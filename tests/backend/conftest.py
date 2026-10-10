"""Black-box tests against the running API/worker/scheduler stack (see ops/dev/run-tests.sh)."""
from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest

API = os.environ.get("TEST_API_URL", "http://localhost:8000")
LAB = os.environ.get("TEST_LAB_HOST", "lab-tls")
ADMIN_USER = os.environ.get("TLS_SCAN_LOCAL_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ["TLS_SCAN_LOCAL_ADMIN_PASSWORD"]
STRONG = "Correct-Horse-Battery-9!"
POLICY = {
    "allowed_versions": ["TLSv1.2", "TLSv1.3"],
    "allowed_cipher_algorithms": ["AES-GCM", "AES-CCM", "CHACHA20-POLY1305"],
    "allowed_signature_hashes": ["SHA-256", "SHA-384", "SHA-512"],
    "minimum_rsa_bits": 2048,
}
PROFILE = {
    "scan": {"ports": "443,8443", "crypto": "standard", "resolve_dns": True, "workers": 2},
    "checks": {"certificate": {"enabled": True, "expires_within_days": 30,
                               "trust": {"enabled": True, "public_store": {"enabled": True}},
                               "revocation": {"enabled": False}}},
}


class Api:
    """A logged-in client carrying the session cookie and the CSRF header."""

    def __init__(self) -> None:
        self.http = httpx.Client(base_url=API, timeout=30)
        self.csrf = ""
        self.user: dict = {}

    def login(self, username: str, password: str, expect: int = 200) -> httpx.Response:
        r = self.http.post("/api/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
            self.user = r.json()["user"]
            self.http.headers["x-csrf-token"] = self.csrf
        assert r.status_code == expect, r.text
        return r

    def __getattr__(self, name):  # get/post/put/delete/patch
        return getattr(self.http, name)


def wait_for(predicate, timeout=240, interval=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("timeout waiting for condition")


def wait_final(api: Api, run_id: str, timeout=240) -> dict:
    def check():
        run = api.get(f"/api/scan-runs/{run_id}").json()
        return run if run["status"] in ("completed", "partial", "failed", "cancelled", "expired") else None

    return wait_for(check, timeout)


@pytest.fixture(scope="session")
def admin() -> Api:
    api = Api()
    api.login(ADMIN_USER, ADMIN_PASSWORD)
    if api.user["must_change_password"]:
        assert api.post("/api/auth/password", json={"current_password": ADMIN_PASSWORD, "new_password": STRONG}).status_code == 200
        api.http.cookies.clear()
        api.login(ADMIN_USER, STRONG)
    return api


def make_user(admin: Api, role: str) -> Api:
    email = f"{role.lower()}-{uuid.uuid4().hex[:6]}@example.com"
    r = admin.post("/api/admin/users", json={"email": email, "display_name": role, "role": role})
    assert r.status_code == 201, r.text
    temp = r.json()["temporary_password"]
    api = Api()
    api.login(email, temp)
    assert api.user["must_change_password"]
    assert api.post("/api/auth/password", json={"current_password": temp, "new_password": STRONG}).status_code == 200
    api.http.cookies.clear()
    api.login(email, STRONG)
    return api


@pytest.fixture(scope="session")
def operator(admin) -> Api:
    return make_user(admin, "OPERATOR")


@pytest.fixture(scope="session")
def user(admin) -> Api:
    return make_user(admin, "USER")


@pytest.fixture(scope="session")
def user2(admin) -> Api:
    return make_user(admin, "USER")


@pytest.fixture(scope="session")
def auditor(admin) -> Api:
    return make_user(admin, "AUDITOR")


@pytest.fixture(scope="session")
def catalog(operator) -> dict:
    """A published policy and profile shared by the tests."""
    policy = operator.post("/api/policies", json={"name": f"anssi-{uuid.uuid4().hex[:5]}", "content": POLICY}).json()
    assert operator.post(f"/api/policies/{policy['id']}/publish").status_code == 200
    profile = operator.post("/api/profiles", json={"name": f"lab-{uuid.uuid4().hex[:5]}", "content": PROFILE}).json()
    assert operator.post(f"/api/profiles/{profile['id']}/publish").status_code == 200
    return {"policy": policy["id"], "profile": profile["id"]}


def make_definition(api: Api, catalog: dict, targets: list[str], name: str | None = None, ports: str = "") -> dict:
    ids = []
    for value in targets:
        r = api.post("/api/targets", json={"value": value, "ports": ports})
        if r.status_code == 409:
            ids.append(next(t["id"] for t in api.get("/api/targets", params={"q": value}).json() if t["value"] == value and t["ports"] == ports))
        else:
            assert r.status_code == 201, r.text
            ids.append(r.json()["id"])
    r = api.post("/api/scan-definitions", json={
        "name": name or f"def-{uuid.uuid4().hex[:6]}", "target_ids": ids, "policy_ids": [catalog["policy"]], "profile_id": catalog["profile"],
    })
    assert r.status_code == 201, r.text
    return r.json()
