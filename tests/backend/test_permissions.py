"""Role matrix enforced by the API (never just hidden in the UI)."""
from __future__ import annotations

import uuid

import httpx
import pytest

from conftest import API, LAB, POLICY, make_definition


def test_unauthenticated_requests_are_refused():
    c = httpx.Client(base_url=API)
    for path in ("/api/targets", "/api/scan-runs", "/api/admin/users", "/api/dashboard"):
        assert c.get(path).status_code == 401, path


def test_csrf_is_required_on_state_changes(user):
    bare = httpx.Client(base_url=API, cookies=user.http.cookies)  # cookie but no CSRF header
    r = bare.post("/api/targets", json={"value": "csrf.example.org"})
    assert r.status_code == 403


def test_auditor_is_read_only(auditor, catalog):
    assert auditor.get("/api/scan-runs").status_code == 200
    assert auditor.get("/api/information-systems").status_code == 200
    assert auditor.post("/api/targets", json={"value": "a.example.org"}).status_code == 403
    assert auditor.post("/api/scan-definitions", json={"name": "x", "policy_ids": [catalog["policy"]], "profile_id": catalog["profile"], "target_ids": []}).status_code == 403
    assert auditor.get("/api/schedules").status_code == 403
    assert auditor.get("/api/policies").status_code == 403


def test_user_cannot_manage_policies_or_admin(user, catalog):
    assert user.post("/api/policies", json={"name": "nope", "content": POLICY}).status_code == 403
    assert user.post("/api/profiles", json={"name": "nope", "content": {}}).status_code == 403
    assert user.get("/api/admin/users").status_code == 403
    assert user.get("/api/admin/audit").status_code == 403
    assert user.get("/api/policies").status_code == 200  # may consult


def test_operator_cannot_administer(operator):
    assert operator.get("/api/admin/users").status_code == 403
    assert operator.get("/api/admin/settings").status_code == 403
    assert operator.get("/api/admin/failed-runs").status_code == 200


def test_owner_rules_on_targets_definitions_and_schedules(user, user2, operator, catalog):
    target = user.post("/api/targets", json={"value": f"{uuid.uuid4().hex[:8]}.example.org"}).json()
    assert user2.put(f"/api/targets/{target['id']}", json={"value": "hijack.example.org"}).status_code == 403
    assert user2.delete(f"/api/targets/{target['id']}").status_code == 403
    assert operator.put(f"/api/targets/{target['id']}", json={"value": target["value"], "description": "op"}).status_code == 200

    definition = make_definition(user, catalog, [f"{uuid.uuid4().hex[:8]}.example.org"])
    body = {**definition, "name": "renamed", "policy_ids": [catalog["policy"]], "profile_id": catalog["profile"]}
    assert user2.put(f"/api/scan-definitions/{definition['id']}", json=body).status_code == 403
    assert operator.put(f"/api/scan-definitions/{definition['id']}", json=body).status_code == 200

    sched = user.post("/api/schedules", json={"definition_id": definition["id"], "kind": "daily", "params": {"time": "03:00"}, "timezone": "Europe/Paris"})
    assert sched.status_code == 201, sched.text
    sid = sched.json()["id"]
    assert user2.put(f"/api/schedules/{sid}", json={"definition_id": definition["id"], "kind": "daily", "params": {"time": "04:00"}}).status_code == 403
    assert user2.delete(f"/api/schedules/{sid}").status_code == 403
    assert sid not in [s["id"] for s in user2.get("/api/schedules").json()]  # USER sees only their own
    assert sid in [s["id"] for s in operator.get("/api/schedules").json()]  # OPERATOR supervises all
    assert user.delete(f"/api/schedules/{sid}").status_code == 204


def test_input_injection_is_rejected(user):
    for bad in ("-oN /tmp/pwn", "host; rm -rf /", "a b", "$(id).example.org", "--script=evil", "1.2.3.4 -iL x"):
        assert user.post("/api/targets", json={"value": bad}).status_code == 422, bad
    assert user.post("/api/targets", json={"value": "ok.example.org", "ports": "443;ls"}).status_code == 422


def test_last_admin_cannot_be_demoted(admin):
    me = admin.user["id"]
    r = admin.put(f"/api/admin/users/{me}", json={"role": "USER"})
    assert r.status_code == 409


def test_password_policy_and_must_change(admin):
    r = admin.post("/api/admin/users", json={"email": f"weak-{uuid.uuid4().hex[:5]}@example.com", "role": "USER"})
    from conftest import Api

    temp, email = r.json()["temporary_password"], r.json()["user"]["email"]
    api = Api()
    api.login(email, temp)
    # blocked from everything except changing the password
    assert api.get("/api/targets").status_code == 403
    assert api.post("/api/auth/password", json={"current_password": temp, "new_password": "password1234"}).status_code == 400
    assert api.post("/api/auth/password", json={"current_password": temp, "new_password": "short"}).status_code == 400


def test_audit_trail_records_business_events(admin, user):
    user.post("/api/targets", json={"value": f"{uuid.uuid4().hex[:8]}.audit.example.org"})
    actions = {e["action"] for e in admin.get("/api/admin/audit", params={"limit": 500}).json()}
    assert {"auth.login", "target.create", "user.create"} <= actions
    dump = str(admin.get("/api/admin/audit", params={"limit": 500}).json()).lower()
    assert "temporary_password" not in dump


def test_wrong_credentials_are_generic(admin):
    from conftest import Api

    api = Api()
    assert api.login("nobody@example.com", "x" * 14, expect=401).json()["detail"] == "Invalid credentials"
