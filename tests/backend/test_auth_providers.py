"""Entra ID and Google Workspace sign-in against the mock OIDC provider, the creation policy and the safety rules.

MOCK ONLY: nothing here proves a real Entra tenant or Google Workspace works (see docs/admin/authentication.md for the optional real test).
"""
from __future__ import annotations

import json
import uuid

import httpx
import pytest

from conftest import API

TENANT = "11111111-2222-3333-4444-555555555555"
MOCK = "http://mock-oidc:8080"


def entra(**over):
    return {"provider": "entra", "entra": {"tenant_id": TENANT, "client_id": "tls-scan-test", "issuer": MOCK}, "auto_provision": True, **over}


def google(domains=("corp.example",), **over):
    return {"provider": "google", "google": {"client_id": "tls-scan-test", "allowed_domains": list(domains)}, "auto_provision": True, **over}


@pytest.fixture(autouse=True)
def restore(admin):
    yield
    assert admin.put("/api/admin/auth", json={"value": {"provider": "", "auto_provision": True}}).status_code == 200


def configure(admin, value):
    r = admin.put("/api/admin/auth", json={"value": value})
    assert r.status_code == 200, r.text
    return r.json()


def attempt(email: str, claims: dict | None = None, tamper_state: bool = False) -> tuple[httpx.Client, httpx.Response]:
    client = httpx.Client(base_url=API, follow_redirects=False)
    r = client.get("/api/auth/sso/login")
    assert r.status_code == 302, r.text
    hint = "&login_hint=" + email + (("&claims=" + json.dumps(claims)) if claims else "")
    r2 = httpx.get(r.headers["location"] + hint, follow_redirects=False)
    params = dict(httpx.URL(r2.headers["location"]).params)
    if tamper_state:
        params["state"] = "tampered"
    return client, client.get("/api/auth/sso/callback", params=params)


def me(client: httpx.Client) -> dict:
    return client.get("/api/auth/me").json()["user"]


def email_of(prefix="p") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}@corp.example"


def audit_codes(admin, action="auth.sso_login") -> list[str]:
    return [(e.get("detail") or {}).get("code") for e in admin.get("/api/admin/audit", params={"action": action, "limit": 20}).json()]


# ----------------------------------------------------------------------------------- configuration and secrets
def test_the_environment_provider_keeps_working_and_no_secret_is_ever_returned(admin):
    data = admin.get("/api/admin/auth").json()
    assert data["effective"]["provider"] == "generic" and data["effective"]["source"] == "environment"
    assert data["secrets"] == {"oidc_client_secret": True, "google_client_secret": True, "ldap_bind_password": True}
    text = json.dumps(data)
    assert "crashtest-only" not in text and "ldap-test-admin-pw" not in text
    assert httpx.get(f"{API}/api/auth/providers").json()["sso"] == {"enabled": True, "provider": "generic"}


def test_only_an_administrator_reads_or_changes_the_authentication(operator, user):
    for api in (operator, user):
        assert api.get("/api/admin/auth").status_code == 403
        assert api.put("/api/admin/auth", json={"value": {"provider": "none"}}).status_code == 403
        assert api.post("/api/admin/auth/test/entra", json={}).status_code == 403


def test_a_multi_tenant_endpoint_cannot_replace_the_tenant_restriction(admin):
    for tenant in ("common", "organizations", "consumers"):
        r = admin.put("/api/admin/auth", json={"value": entra(entra={"tenant_id": tenant, "client_id": "x", "issuer": ""})})
        assert r.status_code == 422, tenant
    r = admin.put("/api/admin/auth", json={"value": entra(entra={"tenant_id": TENANT, "client_id": "x", "issuer": "https://login.microsoftonline.com/common/v2.0"})})
    assert r.status_code == 422
    r = admin.put("/api/admin/auth", json={"value": entra(entra={"tenant_id": TENANT, "client_id": "x", "issuer": "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"})})
    assert r.status_code == 422  # the issuer authority cannot silently target another tenant
    from tls_scan_app.services.auth_config import validate
    with pytest.raises(ValueError, match="issuer"):
        validate(entra(entra={"tenant_id": TENANT, "client_id": "x", "issuer": "http://localhost/tenant/v2.0"}), allow_http=False)
    assert admin.put("/api/admin/auth", json={"value": {"provider": "google", "google": {"client_id": "x", "allowed_domains": ["not a domain"]}}}).status_code == 422
    assert admin.put("/api/admin/auth", json={"value": {"provider": "nonsense"}}).status_code == 422
    assert admin.put("/api/admin/auth", json={"value": {"provider": "none", "default_role": "ADMIN"}}).status_code == 422   # an external identity never starts as administrator


def test_switching_the_provider_off_and_back(admin):
    configure(admin, {"provider": "none", "auto_provision": True})
    assert httpx.get(f"{API}/api/auth/providers").json()["sso"] == {"enabled": False}
    assert httpx.Client(base_url=API).get("/api/auth/sso/login").status_code == 404
    configure(admin, entra())
    assert httpx.get(f"{API}/api/auth/providers").json()["sso"] == {"enabled": True, "provider": "entra"}


# ----------------------------------------------------------------------------------- Entra ID
def test_entra_valid_sign_in_keeps_the_role_across_sign_ins(admin):
    configure(admin, entra())
    mail = email_of("entra")
    client, r = attempt(mail, {"tid": TENANT})
    assert r.status_code == 302, r.text
    user = me(client)
    assert user["role"] == "USER" and user["local_account"] is False
    assert admin.put(f"/api/admin/users/{user['id']}", json={"role": "OPERATOR"}).status_code == 200
    again, r = attempt(mail, {"tid": TENANT})                    # re-authentication
    assert r.status_code == 302 and me(again)["role"] == "OPERATOR" and me(again)["id"] == user["id"]
    listed = next(u for u in admin.get("/api/admin/users").json() if u["id"] == user["id"])
    assert listed["source"] == "entra" or listed["source"] == "sso"            # the mock issuer is not a Microsoft one


@pytest.mark.parametrize("claims", [{"tid": "99999999-2222-3333-4444-555555555555"}, {}, {"tid": TENANT, "aud": "someone-else"},
                                    {"tid": TENANT, "nonce": "not-the-one"}, {"tid": TENANT, "iss": "http://evil"}, {"tid": TENANT, "exp": 1}])
def test_entra_refuses_other_tenants_and_invalid_tokens(admin, claims):
    configure(admin, entra())
    _, r = attempt(email_of("bad"), claims)
    assert r.status_code == 400 and "tid" not in r.text and "tenant" not in r.text.lower()      # nothing about the provider leaks to the browser


def test_entra_state_is_validated_and_a_replayed_callback_fails(admin):
    configure(admin, entra())
    _, r = attempt(email_of("st"), {"tid": TENANT}, tamper_state=True)
    assert r.status_code == 400
    client = httpx.Client(base_url=API)
    r = client.get("/api/auth/sso/login")
    r2 = httpx.get(r.headers["location"] + "&login_hint=" + email_of("rp") + "&claims=" + json.dumps({"tid": TENANT}), follow_redirects=False)
    params = dict(httpx.URL(r2.headers["location"]).params)
    assert client.get("/api/auth/sso/callback", params=params).status_code == 302
    assert client.get("/api/auth/sso/callback", params=params).status_code == 400          # the code is single use


def test_entra_failures_are_explained_to_the_administrator_only(admin):
    configure(admin, entra())
    attempt(email_of("diag"), {"tid": "99999999-2222-3333-4444-555555555555"})
    diag = admin.get("/api/admin/auth/diagnostics").json()
    assert diag and diag[0]["action"] == "auth.sso_login" and diag[0]["code"] == "tenant_mismatch" and "tenant" in diag[0]["explanation"].lower()
    assert "crashtest-only" not in json.dumps(diag)


def test_entra_configuration_test_steps_are_honest(admin):
    configure(admin, entra())
    steps = admin.post("/api/admin/auth/test/entra", json={}).json()
    by = {s["step"]: s for s in steps}
    assert by["configuration"]["status"] == "ok" and by["client secret"]["status"] == "ok" and by["issuer reachable"]["status"] == "ok"
    assert by["signing keys (JWKS)"]["status"] == "ok" and by["tenant restriction"]["status"] == "ok"
    assert steps[-1]["step"] == "interactive sign-in" and steps[-1]["status"] == "info"      # technical checks are not a real sign-in
    assert admin.post("/api/admin/auth/test/google", json={}).json()[0]["status"] == "fail"    # not the active provider
    configure(admin, entra(entra={"tenant_id": TENANT, "client_id": "tls-scan-test", "issuer": "http://mock-oidc:9"}))
    assert any(s["status"] == "fail" for s in admin.post("/api/admin/auth/test/entra", json={}).json())


# ----------------------------------------------------------------------------------- Google Workspace
def test_google_workspace_sign_in_needs_the_signed_domain_claim(admin):
    configure(admin, google())
    assert httpx.get(f"{API}/api/auth/providers").json()["sso"] == {"enabled": True, "provider": "google"}
    mail = email_of("g")
    client, r = attempt(mail, {"hd": "corp.example", "email_verified": True})
    assert r.status_code == 302 and me(client)["email"] == mail
    uid = me(client)["id"]
    assert admin.put(f"/api/admin/users/{uid}", json={"role": "OPERATOR"}).status_code == 200
    again, r = attempt(mail, {"hd": "corp.example", "email_verified": True})
    assert r.status_code == 302 and me(again)["role"] == "OPERATOR"                              # existing user reused, role kept


@pytest.mark.parametrize("claims", [{}, {"email_verified": True}, {"hd": "other.example", "email_verified": True},
                                    {"hd": "corp.example", "email_verified": False}, {"hd": "corp.example"}, {"hd": "CORP.example.evil.com", "email_verified": True}])
def test_google_refuses_personal_accounts_other_domains_and_unverified_mail(admin, claims):
    configure(admin, google())
    # the e-mail suffix looks right, only the signed claim decides
    _, r = attempt(email_of("g-bad"), claims)
    assert r.status_code == 400


def test_google_without_an_allowed_domain_is_not_offered(admin):
    configure(admin, google(domains=()))
    assert httpx.get(f"{API}/api/auth/providers").json()["sso"] == {"enabled": False}


def test_google_invalid_token_is_refused(admin):
    configure(admin, google())
    _, r = attempt(email_of("g-aud"), {"hd": "corp.example", "email_verified": True, "aud": "another-client"})
    assert r.status_code == 400


# ----------------------------------------------------------------------------------- accounts, creation policy, safety
def test_a_provider_never_takes_over_an_existing_account_by_email(admin):
    configure(admin, entra())
    local = f"local-{uuid.uuid4().hex[:6]}@corp.example"
    made = admin.post("/api/admin/users", json={"email": local, "role": "ADMIN"})
    assert made.status_code == 201
    admin.put(f"/api/admin/users/{made.json()['user']['id']}", json={"role": "USER"})      # the account only has to exist: keep the shared administrator count unchanged
    _, r = attempt(local, {"tid": TENANT})
    assert r.status_code == 400                                                  # same e-mail as a local administrator: refused, not merged
    assert "email_conflict" in audit_codes(admin) or "email_conflict" in [(e.get("detail") or {}).get("reason") for e in admin.get("/api/admin/audit", params={"action": "auth.sso_login", "limit": 5}).json()]
    assert sum(1 for u in admin.get("/api/admin/users").json() if u["email"] == local) == 1


def test_without_automatic_creation_only_pre_provisioned_people_enter(admin):
    configure(admin, entra(auto_provision=False))
    mail = email_of("pre")
    _, r = attempt(mail, {"tid": TENANT})
    assert r.status_code == 400                                                  # nobody created them
    assert admin.post("/api/admin/directory/provision", json={"email": mail, "role": "AUDITOR"}).status_code == 201
    client, r = attempt(mail, {"tid": TENANT})
    assert r.status_code == 302 and me(client)["role"] == "AUDITOR"              # adopted with the role the administrator chose
    row = next(u for u in admin.get("/api/admin/users").json() if u["email"] == mail)
    assert row["issuer"] != "directory:pending"


def test_a_disabled_account_is_refused_whatever_the_provider(admin):
    configure(admin, google())
    mail = email_of("off")
    client, _ = attempt(mail, {"hd": "corp.example", "email_verified": True})
    uid = me(client)["id"]
    assert admin.put(f"/api/admin/users/{uid}", json={"role": "USER", "active": False}).status_code == 200
    assert client.get("/api/auth/me").status_code == 401                         # the open session stops working
    _, r = attempt(mail, {"hd": "corp.example", "email_verified": True})
    assert r.status_code == 400


def test_the_last_local_administrator_cannot_be_disabled_by_a_provider_change(admin):
    from conftest import make_user

    configure(admin, entra())
    sso_admin = me(attempt(email_of("sso-admin"), {"tid": TENANT})[0])["id"]
    assert admin.put(f"/api/admin/users/{sso_admin}", json={"role": "ADMIN"}).status_code == 200
    only = make_user(admin, "ADMIN")                                              # a local administrator that will be the only one left
    others = [u for u in admin.get("/api/admin/users").json() if u["role"] == "ADMIN" and u["local_account"] and u["id"] != only.user["id"]]
    try:
        for u in others:                                                           # the shared test administrator is restored in `finally`
            assert only.put(f"/api/admin/users/{u['id']}", json={"role": "USER"}).status_code == 200
        r = only.put(f"/api/admin/users/{only.user['id']}", json={"role": "USER"})
        assert r.status_code == 409 and "local administrator" in r.text          # the emergency access cannot be removed
        assert only.put(f"/api/admin/users/{only.user['id']}", json={"role": "ADMIN", "active": False}).status_code == 409
    finally:
        for u in others:
            only.put(f"/api/admin/users/{u['id']}", json={"role": "ADMIN"})
    assert admin.put(f"/api/admin/users/{sso_admin}", json={"role": "USER"}).status_code == 200
    assert admin.put(f"/api/admin/users/{only.user['id']}", json={"role": "USER"}).status_code == 200      # leave the shared administrator count as it was


def test_local_sign_in_still_works_with_an_external_provider_active(admin):
    configure(admin, entra())
    fresh = httpx.Client(base_url=API)
    from conftest import ADMIN_PASSWORD, ADMIN_USER, STRONG
    r = fresh.post("/api/auth/login", json={"username": ADMIN_USER, "password": STRONG})
    if r.status_code != 200:
        r = fresh.post("/api/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert r.status_code == 200
