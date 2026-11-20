"""LST-36: the Microsoft Entra client secret entered in Administration -> Authentication.

Write-only, encrypted at rest with the deployment credential key (the GMP password mechanism of LST-24), never returned,
logged or audited; the server secret (ORION_OIDC_CLIENT_SECRET) stays the fallback. Unit tests use a temporary key and an
in-memory settings table; the API tests run against the test stack, which has no credential key on purpose.
"""
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import SecretStr

SECRET = "Ex4mple~only.Secret_value-123"
TENANT = "11111111-2222-3333-4444-555555555555"


class FakeDb:
    """The two calls the code makes on a session: get(model, key, ...) and add(row)."""

    def __init__(self):
        self.rows: dict = {}

    def get(self, _model, key, **_kwargs):
        return self.rows.get(key)

    def add(self, row):
        self.rows[row.key] = row

    def commit(self):
        pass


def settings(tmp_path, server_secret="", key=True):
    key_file = tmp_path / "credential_key"
    if key:
        key_file.write_text("cd" * 32)
    return SimpleNamespace(
        environment="test", public_base_url="https://orion.example", greenbone_credential_key_file=str(key_file) if key else "",
        oidc_client_secret=server_secret, google_client_secret="", ldap_bind_password="", oidc_issuer="", oidc_client_id="",
        oidc_provider="", sso_auto_provision=None, oidc_default_role="USER", graph_login_url="https://login.microsoftonline.com",
        google_issuer="")


def request(s):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=s)))


@pytest.fixture
def route(monkeypatch):
    from orion_app.api import admin_auth
    events = []
    monkeypatch.setattr(admin_auth.audit, "record", lambda *_a, **kw: events.append(kw))
    admin_auth.recorded = events
    return admin_auth


def body(route, secret="", confirm=None, provider="entra"):
    value = {"provider": provider, "entra": {"tenant_id": TENANT, "client_id": "app-id", "issuer": ""}}
    return route.AuthBody(value=value, entra_client_secret=SecretStr(secret), entra_client_secret_confirm=SecretStr(secret if confirm is None else confirm))


def test_stored_encrypted_and_used_by_the_sign_in_never_returned(tmp_path, route):
    from orion_app.services import auth_config, auth_secrets
    s, db = settings(tmp_path, server_secret="server-side-secret"), FakeDb()
    result = route.put_auth(body(route, SECRET), request(s), db, None)
    token = db.rows[auth_secrets.SETTING_KEY].value[auth_secrets.ENTRA_FIELD]
    assert SECRET not in token and SECRET not in json.dumps(db.rows["auth"].value)          # encrypted, apart from the auth settings
    assert SECRET not in json.dumps(result) and token not in json.dumps(result)            # neither the value nor the ciphertext
    assert result["secrets"]["entra_client_secret"] == {"configured": True, "source": "webui", "unreadable": False, "stored": True}
    assert auth_config.effective(db, s).client_secret == SECRET                              # takes precedence over the server secret
    assert SECRET not in json.dumps(route.recorded, default=str)                            # audit without the value
    assert any(event.get("detail") == {"stored": "encrypted"} for event in route.recorded)


def test_empty_keeps_the_current_secret_and_replacement_rotates_it(tmp_path, route):
    from orion_app.services import auth_secrets
    s, db = settings(tmp_path), FakeDb()
    route.put_auth(body(route, SECRET), request(s), db, None)
    route.put_auth(body(route, ""), request(s), db, None)
    assert auth_secrets.entra_secret(db, s)[0] == SECRET
    route.put_auth(body(route, "Rotated-" + SECRET), request(s), db, None)
    assert auth_secrets.entra_secret(db, s) == ("Rotated-" + SECRET, "webui", False)


@pytest.mark.parametrize(("secret", "confirm", "message"), [
    (SECRET, SECRET + "x", "do not match"), ("", SECRET, "do not match"), (" " + SECRET, None, "spaces"), (SECRET + "\n", None, "control"),
    ("a" * 513, None, "longer than 512"),
])
def test_invalid_input_is_refused_and_nothing_is_stored(tmp_path, route, secret, confirm, message):
    from orion_app.services import auth_secrets
    s, db = settings(tmp_path), FakeDb()
    with pytest.raises(HTTPException) as refused:
        route.put_auth(body(route, secret, confirm), request(s), db, None)
    assert refused.value.status_code == 422 and message in refused.value.detail
    assert SECRET not in refused.value.detail
    assert auth_secrets.SETTING_KEY not in db.rows


def test_without_the_credential_key_the_secret_is_refused_not_stored_in_clear(tmp_path, route):
    from orion_app.services import auth_secrets
    s, db = settings(tmp_path, key=False), FakeDb()
    with pytest.raises(HTTPException) as refused:
        route.put_auth(body(route, SECRET), request(s), db, None)
    assert refused.value.status_code == 503 and "ORION_OIDC_CLIENT_SECRET_FILE" in refused.value.detail
    assert auth_secrets.SETTING_KEY not in db.rows and "auth" not in db.rows


def test_unreadable_stored_secret_falls_back_to_the_server_secret(tmp_path, route, caplog):
    from orion_app.services import auth_config, auth_secrets
    s, db = settings(tmp_path, server_secret="server-side-secret"), FakeDb()
    route.put_auth(body(route, SECRET), request(s), db, None)
    (tmp_path / "credential_key").write_text("ef" * 32)                                     # the key was replaced
    with caplog.at_level(logging.WARNING):
        assert auth_secrets.entra_secret(db, s) == ("server-side-secret", "server", True)
        assert auth_config.effective(db, s).client_secret == "server-side-secret"           # the sign-in keeps working
    assert SECRET not in caplog.text and "server-side-secret" not in caplog.text
    assert route._public(db, request(s))["secrets"]["entra_client_secret"]["unreadable"] is True


def test_removal_never_leaves_the_active_entra_sign_in_without_a_secret(tmp_path, route):
    from orion_app.services import auth_secrets
    s, db = settings(tmp_path), FakeDb()
    route.put_auth(body(route, SECRET), request(s), db, None)
    with pytest.raises(HTTPException) as refused:
        route.remove_entra_secret(request(s), db, None)
    assert refused.value.status_code == 409 and auth_secrets.entra_secret(db, s)[0] == SECRET
    s.oidc_client_secret = "server-side-secret"
    result = route.remove_entra_secret(request(s), db, None)
    assert result["secrets"]["entra_client_secret"] == {"configured": True, "source": "server", "unreadable": False, "stored": False}
    with pytest.raises(HTTPException) as missing:
        route.remove_entra_secret(request(s), db, None)
    assert missing.value.status_code == 404


def test_server_secret_alone_keeps_working_unchanged(tmp_path, route):
    from orion_app.services import auth_config
    s, db = settings(tmp_path, server_secret="server-side-secret"), FakeDb()
    route.put_auth(body(route, ""), request(s), db, None)
    assert auth_config.effective(db, s).client_secret == "server-side-secret"
    assert route._public(db, request(s))["secrets"]["entra_client_secret"]["source"] == "server"


# ---------- API, on the test stack (no credential key there) ----------
def test_only_an_administrator_can_set_or_remove_it(operator, auditor):
    for who in (operator, auditor):
        put = who.put("/api/admin/auth", json={"value": {"provider": ""}, "entra_client_secret": SECRET, "entra_client_secret_confirm": SECRET})
        assert put.status_code == 403 and SECRET not in put.text
        assert who.delete("/api/admin/auth/entra-secret").status_code == 403
        assert who.get("/api/admin/auth").status_code == 403


def test_api_refuses_without_key_and_never_echoes_the_secret(admin):
    before = admin.get("/api/admin/auth").json()
    put = admin.put("/api/admin/auth", json={"value": before["stored"], "entra_client_secret": SECRET, "entra_client_secret_confirm": SECRET})
    assert put.status_code == 503 and SECRET not in put.text
    after = admin.get("/api/admin/auth")
    assert SECRET not in after.text and after.json()["secrets"]["entra_client_secret"]["stored"] is False
    audit = admin.get("/api/admin/audit", params={"action": "auth."}).text
    assert SECRET not in audit


@pytest.mark.parametrize("wrong_type", [["Leak-Me-123"], {"value": "Leak-Me-123"}, 123456789])
def test_a_wrongly_typed_secret_is_refused_without_being_echoed(tmp_path, route, wrong_type):
    from orion_app.services import auth_secrets
    s, db = settings(tmp_path), FakeDb()
    parsed = route.AuthBody.model_validate({"value": {"provider": "entra"}, "entra_client_secret": wrong_type, "entra_client_secret_confirm": wrong_type})
    assert "Leak-Me" not in repr(parsed) and "123456789" not in repr(parsed)
    with pytest.raises(HTTPException) as refused:
        route.put_auth(parsed, request(s), db, None)
    assert refused.value.status_code == 422
    assert "Leak-Me" not in refused.value.detail and "123456789" not in refused.value.detail
    assert auth_secrets.SETTING_KEY not in db.rows
