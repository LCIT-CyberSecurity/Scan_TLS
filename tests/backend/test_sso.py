"""SSO against the mock OIDC provider (the real Entra ID test is run separately, see docs/integrations)."""
from __future__ import annotations

import uuid

import httpx

from conftest import API


def sso_login(email: str) -> httpx.Client:
    client = httpx.Client(base_url=API, follow_redirects=False)
    r = client.get("/api/auth/sso/login")
    assert r.status_code == 302
    r2 = httpx.get(r.headers["location"] + "&login_hint=" + email, follow_redirects=False)
    assert r2.status_code == 302
    cb = httpx.URL(r2.headers["location"])
    r3 = client.get("/api/auth/sso/callback", params=dict(cb.params))
    assert r3.status_code == 302, r3.text
    return client


def test_providers_endpoint():
    assert httpx.get(f"{API}/api/auth/providers").json()["sso"]["enabled"] is True


def test_sso_login_provisions_a_user_and_opens_a_session(admin):
    email = f"sso-{uuid.uuid4().hex[:6]}@sso.example.com"
    client = sso_login(email)
    me = client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["user"]["email"] == email
    assert me.json()["user"]["role"] == "USER"  # default role; no privilege from the IdP
    assert me.json()["user"]["local_account"] is False
    # admin can promote; the role persists across the next SSO login
    uid = me.json()["user"]["id"]
    assert admin.put(f"/api/admin/users/{uid}", json={"role": "OPERATOR"}).status_code == 200
    assert sso_login(email).get("/api/auth/me").json()["user"]["role"] == "OPERATOR"


def test_sso_rejects_tampered_state():
    client = httpx.Client(base_url=API)
    assert client.get("/api/auth/sso/callback", params={"code": "x", "state": "y"}).status_code == 400
    client.get("/api/auth/sso/login")
    assert client.get("/api/auth/sso/callback", params={"code": "x", "state": "wrong"}).status_code == 400


def test_disabled_sso_user_is_refused(admin):
    email = f"sso-off-{uuid.uuid4().hex[:6]}@sso.example.com"
    uid = sso_login(email).get("/api/auth/me").json()["user"]["id"]
    assert admin.put(f"/api/admin/users/{uid}", json={"role": "USER", "active": False}).status_code == 200
    client = httpx.Client(base_url=API)
    r = client.get("/api/auth/sso/login")
    cb = httpx.URL(httpx.get(r.headers["location"] + "&login_hint=" + email, follow_redirects=False).headers["location"])
    assert client.get("/api/auth/sso/callback", params=dict(cb.params)).status_code == 400
