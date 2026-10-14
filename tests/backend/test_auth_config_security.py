from __future__ import annotations

import asyncio

import pytest

from tls_scan_app.auth import oidc
from tls_scan_app.connectors import ldap_auth
from tls_scan_app.connectors.registry import build_connector
from tls_scan_app.config import Settings
from tls_scan_app.models import SystemSetting
from tls_scan_app.services.auth_config import validate


TENANT = "11111111-2222-3333-4444-555555555555"


def entra(issuer: str) -> dict:
    return {"provider": "entra", "entra": {"tenant_id": TENANT, "client_id": "client", "issuer": issuer}}


def test_production_auth_config_rejects_http_issuer_and_other_tenants() -> None:
    with pytest.raises(ValueError, match="issuer"):
        validate(entra("http://localhost/tenant/v2.0"), allow_http=False)
    with pytest.raises(ValueError, match="Tenant ID"):
        validate(entra("https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"))


@pytest.mark.parametrize("ldap_url", [
    "ldaps://user:password@directory.example.org",
    "ldaps://directory.example.org/dc=example,dc=org",
    "ldaps://directory.example.org?x=1",
    "ldaps://directory.example.org:70000",
])
def test_ldap_server_url_rejects_embedded_credentials_and_unexpected_parts(ldap_url: str) -> None:
    with pytest.raises(ValueError, match="LDAP URL"):
        validate({"provider": "ldap", "ldap": {"server_url": ldap_url, "base_dn": "dc=example,dc=org"}})


def test_ldap_starttls_must_be_a_boolean() -> None:
    with pytest.raises(ValueError, match="StartTLS"):
        validate({"provider": "ldap", "ldap": {"server_url": "ldap://directory.example.org", "base_dn": "dc=example,dc=org", "starttls": "false"}})


def test_ldap_service_bind_never_falls_back_to_anonymous() -> None:
    cfg = {"server_url": "ldaps://directory.example.org", "base_dn": "dc=example,dc=org", "bind_dn": "cn=service,dc=example,dc=org"}
    with pytest.raises(ldap_auth.LdapAuthError) as error:
        ldap_auth.authenticate(cfg, "", "alice", "user-password")
    assert error.value.code == "ldap_service_bind"


def test_production_directory_connector_forces_certificate_validation() -> None:
    class Db:
        def get(self, _: type, key: str) -> SystemSetting:
            assert key == "directory"
            return SystemSetting(key="directory", value={"kind": "ldap", "ldap": {"server_url": "ldaps://directory.example.org",
                                                                                  "base_dn": "dc=example,dc=org", "tls_verify": False}})

    connector = build_connector(Db(), Settings(environment="production", session_secret="x" * 32))
    assert connector is not None and connector.cfg["tls_verify"] is True


def test_oidc_discovery_cannot_replace_the_configured_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer = "https://idp.example.org"

    class Response:
        status_code = 200

        def json(self) -> dict:
            return {"issuer": "https://other.example.org", "authorization_endpoint": "https://idp.example.org/auth",
                    "token_endpoint": "https://idp.example.org/token", "jwks_uri": "https://idp.example.org/jwks"}

    class Client:
        def __init__(self, **_: object) -> None:
            pass

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, _: str) -> Response:
            return Response()

    monkeypatch.setattr(oidc.httpx, "AsyncClient", Client)
    with pytest.raises(oidc.OidcError, match="does not match"):
        asyncio.run(oidc.discover_provider(issuer))


def test_oidc_discovery_rejects_insecure_provider_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer = "https://idp.example.org"

    class Response:
        status_code = 200

        def json(self) -> dict:
            return {"issuer": issuer, "authorization_endpoint": "https://idp.example.org/auth",
                    "token_endpoint": "http://idp.example.org/token", "jwks_uri": "https://idp.example.org/jwks"}

    class Client:
        def __init__(self, **_: object) -> None:
            pass

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, _: str) -> Response:
            return Response()

    monkeypatch.setattr(oidc.httpx, "AsyncClient", Client)
    with pytest.raises(oidc.OidcError, match="insecure endpoint"):
        asyncio.run(oidc.discover_provider(issuer))


def test_oidc_issuer_credentials_are_rejected_before_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def __init__(self, **_: object) -> None:
            pytest.fail("the issuer must be rejected before any network request")

    monkeypatch.setattr(oidc.httpx, "AsyncClient", Client)
    with pytest.raises(oidc.OidcError, match="issuer URL"):
        asyncio.run(oidc.discover_provider("https://user:secret@idp.example.org"))
