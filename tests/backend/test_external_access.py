"""External REST API v1 and MCP: global switches, per-user authorisation, keys, isolation, read-only, official MCP client."""
from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import httpx2
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy import create_engine, text

from conftest import API, LAB, Api, make_definition, make_user, wait_final
from tls_scan_app.mcp_server import MCP_TOOL_NAMES

NO_RUN = "00000000-0000-4000-8000-000000000000"
engine = create_engine(os.environ["TLS_SCAN_DATABASE_URL"])


def set_service(admin: Api, service: str, on: bool) -> None:
    assert admin.put(f"/api/admin/external-access/{service}", json={"enabled": on}).status_code == 200


def grant(admin: Api, who: Api, **flags: bool) -> None:
    r = admin.put(f"/api/admin/users/{who.user['id']}/access", json=flags)
    assert r.status_code == 200, r.text


def generate(who: Api, service: str) -> str:
    r = who.post(f"/api/me/access/{service}/token")
    assert r.status_code == 201, r.text
    return r.json()["token"]


def rest(token: str) -> httpx.Client:
    return httpx.Client(base_url=API, headers={"Authorization": f"Bearer {token}"}, timeout=30)


@contextlib.asynccontextmanager
async def mcp_session(token: str):
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30) as client:
        async with streamable_http_client(f"{API}/mcp", http_client=client) as streams:
            async with ClientSession(*streams[:2]) as session:
                await session.initialize()
                yield session


@pytest.fixture(autouse=True, scope="module")
def switches_back_off(admin):
    yield
    for service in ("api", "mcp"):
        set_service(admin, service, False)


@pytest.fixture(scope="module")
def run(user, catalog) -> dict:
    definition = make_definition(user, catalog, [LAB], name="external-access")
    return wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])


@pytest.fixture()
def on(admin):
    set_service(admin, "api", True)
    set_service(admin, "mcp", True)


def authorised(admin: Api, role: str = "USER", api: bool = True, mcp: bool = True) -> Api:
    who = make_user(admin, role)
    grant(admin, who, api_access_enabled=api, mcp_access_enabled=mcp)
    return who


# ---------- defaults, switches, authorisations ----------
def test_everything_is_off_by_default(admin):
    state = admin.get("/api/admin/external-access").json()
    assert state == {"api_enabled": False, "mcp_enabled": False}
    assert admin.user["api_access_enabled"] is False and admin.user["mcp_access_enabled"] is False  # not even administrators
    fresh = make_user(admin, "OPERATOR")
    assert fresh.user["api_access_enabled"] is False and fresh.user["mcp_access_enabled"] is False
    me = fresh.get("/api/me/access").json()
    assert me["api"] == {"global_enabled": False, "allowed": False, "key": me["api"]["key"]} and me["api"]["key"]["active"] is False


def test_only_an_administrator_changes_switches_and_authorisations(operator, user, auditor, admin):
    for who in (operator, user, auditor):
        assert who.put("/api/admin/external-access/api", json={"enabled": True}).status_code == 403
        assert who.put(f"/api/admin/users/{who.user['id']}/access", json={"api_access_enabled": True}).status_code == 403
    assert admin.get("/api/admin/external-access").json()["api_enabled"] is False


def test_a_key_needs_both_the_global_switch_and_the_individual_authorisation(admin):
    who = make_user(admin, "USER")
    assert who.post("/api/me/access/api/token").status_code == 403          # off + not authorised
    set_service(admin, "api", True)
    assert who.post("/api/me/access/api/token").status_code == 403          # on, not authorised
    grant(admin, who, api_access_enabled=True)
    set_service(admin, "api", False)
    assert who.post("/api/me/access/api/token").status_code == 403          # authorised, off
    set_service(admin, "api", True)
    r = who.post("/api/me/access/api/token")
    assert r.status_code == 201 and r.json()["token"].startswith("tls_scan_pat_")
    assert who.post("/api/me/access/mcp/token").status_code == 403          # independent: MCP not granted / not enabled
    assert who.post("/api/me/access/other/token").status_code == 404
    state = who.get("/api/me/access").json()["api"]
    assert state["allowed"] and state["global_enabled"] and state["key"]["active"] and r.json()["token"] not in str(state)


def test_an_administrator_cannot_create_a_key_for_someone_else(admin, on):
    who = authorised(admin)
    assert admin.post(f"/api/admin/users/{who.user['id']}/access/api/token").status_code in (404, 405)
    assert who.get("/api/me/access").json()["api"]["key"]["active"] is False


# ---------- key lifecycle ----------
def test_global_switch_applies_immediately_and_suspends_without_revoking(admin, on):
    who = authorised(admin, "OPERATOR")
    c = rest(generate(who, "api"))
    assert c.get("/api/v1/me").status_code == 200
    set_service(admin, "api", False)
    assert c.get("/api/v1/me").status_code == 401                                   # no restart
    assert who.get("/api/me/access").json()["api"]["key"]["active"] is True         # suspended, not revoked
    assert who.post("/api/me/access/api/token").status_code == 403                  # no new key while off
    assert who.delete("/api/me/access/api/token").status_code == 204                # revoking stays possible
    set_service(admin, "api", True)
    assert c.get("/api/v1/me").status_code == 401                                   # revoked meanwhile: stays refused
    other = authorised(admin)
    c2 = rest(generate(other, "api"))
    set_service(admin, "api", False)
    set_service(admin, "api", True)
    assert c2.get("/api/v1/me").status_code == 200                                  # re-enabled: the suspended key works again


def test_withdrawing_the_authorisation_or_deactivating_the_user_revokes_keys(admin, on):
    who = authorised(admin)
    token = generate(who, "api")
    assert rest(token).get("/api/v1/me").status_code == 200
    grant(admin, who, api_access_enabled=False)
    assert rest(token).get("/api/v1/me").status_code == 401
    grant(admin, who, api_access_enabled=True)
    assert rest(token).get("/api/v1/me").status_code == 401                          # revoked for good
    assert who.get("/api/me/access").json()["api"]["key"]["active"] is False
    token = generate(who, "api")
    assert admin.put(f"/api/admin/users/{who.user['id']}", json={"role": "USER", "active": False}).status_code == 200
    assert rest(token).get("/api/v1/me").status_code == 401
    assert admin.put(f"/api/admin/users/{who.user['id']}", json={"role": "USER", "active": True}).status_code == 200
    assert rest(token).get("/api/v1/me").status_code == 401
    with engine.begin() as db:
        assert db.execute(text("select count(*) from access_tokens where user_id = :u and revoked_at is null"), {"u": who.user["id"]}).scalar() == 0


def test_expiry_rotation_revocation_and_admin_revocation(admin, on):
    who = authorised(admin)
    token = generate(who, "api")
    with engine.begin() as db:
        db.execute(text("update access_tokens set expires_at = :t where user_id = :u"), {"t": datetime.now(UTC) - timedelta(seconds=5), "u": who.user["id"]})
    assert rest(token).get("/api/v1/me").status_code == 401
    assert who.get("/api/me/access").json()["api"]["key"]["active"] is False
    first = generate(who, "api")                                                      # a new key after expiry is possible
    second = generate(who, "api")                                                     # regeneration revokes the previous one
    assert rest(first).get("/api/v1/me").status_code == 401 and rest(second).get("/api/v1/me").status_code == 200
    with engine.begin() as db:
        days = db.execute(text("select extract(epoch from (expires_at - created_at))/86400 from access_tokens where user_id=:u and revoked_at is null"), {"u": who.user["id"]}).scalar()
    assert 89.9 < float(days) < 90.1
    assert admin.delete(f"/api/admin/users/{who.user['id']}/access/api/token").status_code == 204
    assert rest(second).get("/api/v1/me").status_code == 401
    assert admin.delete(f"/api/admin/users/{who.user['id']}/access/nope/token").status_code == 404


def test_keys_are_stored_hashed_and_never_returned_again_or_logged(admin, on):
    who = authorised(admin)
    token = generate(who, "api")
    with engine.begin() as db:
        row = db.execute(text("select prefix, token_hash from access_tokens where user_id = :u and revoked_at is null"), {"u": who.user["id"]}).one()
        everything = str(db.execute(text("select * from access_tokens where user_id = :u"), {"u": who.user["id"]}).all())
        audit_dump = str(db.execute(text("select detail, actor_label, resource_id from audit_events order by created_at desc limit 500")).all())
    assert len(row.token_hash) == 64 and row.token_hash != token and token not in everything and token not in audit_dump
    assert token.startswith(row.prefix) and len(row.prefix) < len(token) // 2
    assert token not in str(who.get("/api/me/access").json()) and token not in str(admin.get("/api/admin/users").json())
    assert token not in str(admin.get("/api/admin/audit", params={"action": "external_access"}).json())
    created = admin.get("/api/admin/audit", params={"action": "external_access.api_key_created"}).json()
    assert created and created[0]["detail"]["prefix"] == row.prefix


# ---------- separation of services and surfaces ----------
def test_rest_and_mcp_keys_and_sessions_never_cross(admin, on):
    who = authorised(admin)
    pat, mcp = generate(who, "api"), generate(who, "mcp")
    assert pat.startswith("tls_scan_pat_") and mcp.startswith("tls_scan_mcp_")
    assert rest(pat).get("/api/v1/me").status_code == 200
    assert rest(mcp).get("/api/v1/me").status_code == 401                              # MCP key on REST
    assert httpx.post(f"{API}/mcp", headers={"Authorization": f"Bearer {pat}"}, json={}).status_code == 401   # REST key on MCP
    for token in (pat, mcp):
        for path in ("/api/dashboard", "/api/scan-runs", "/api/admin/users", "/api/results", "/api/me/access", "/api/auth/me"):
            assert rest(token).get(path).status_code == 401, path                        # external keys never open WebUI routes
    assert who.get("/api/v1/me").status_code == 401                                      # a WebUI session is not an external key
    assert httpx.get(f"{API}/api/v1/me").status_code == 401
    assert rest("tls_scan_pat_" + "x" * 40).get("/api/v1/me").status_code == 401


def test_the_webui_and_its_internal_api_are_unaffected_by_the_switches(admin, user):
    for on_ in (False, True):
        set_service(admin, "api", on_)
        set_service(admin, "mcp", on_)
        assert user.get("/api/scan-runs").status_code == 200 and user.get("/api/targets").status_code == 200
    set_service(admin, "api", False)
    set_service(admin, "mcp", False)


# ---------- REST: data, roles, read-only, documentation ----------
def test_rest_reads_scan_results_with_the_role_of_the_account(admin, on, run):
    who = authorised(admin, "AUDITOR")
    c = rest(generate(who, "api"))
    assert c.get("/api/v1/me").json()["role"] == "AUDITOR"
    page = c.get("/api/v1/scans", params={"limit": 5}).json()
    assert page["pagination"]["limit"] == 5 and any(i["id"] == run["id"] for i in c.get("/api/v1/scans", params={"limit": 100}).json()["items"])
    detail = c.get(f"/api/v1/scans/{run['id']}").json()
    assert detail["id"] == run["id"] and "reports" not in detail and "progress" not in detail and "config_snapshot" not in detail
    summary = c.get(f"/api/v1/scans/{run['id']}/summary").json()
    assert summary["id"] == run["id"] and summary["summary"] is not None
    endpoints = c.get(f"/api/v1/scans/{run['id']}/endpoints").json()
    assert endpoints["pagination"]["total"] >= 1
    findings = c.get(f"/api/v1/scans/{run['id']}/findings", params={"limit": 3}).json()
    assert len(findings["items"]) <= 3
    assert c.get(f"/api/v1/scans/{run['id']}/comparison").status_code == 403           # AUDITOR: as in the WebUI
    # the role is read at each request: promote the account, the same key now compares
    assert admin.put(f"/api/admin/users/{who.user['id']}", json={"role": "USER"}).status_code == 200
    assert c.get(f"/api/v1/scans/{run['id']}/comparison").status_code in (200, 404)
    assert admin.put(f"/api/admin/users/{who.user['id']}", json={"role": "AUDITOR"}).status_code == 200
    assert c.get(f"/api/v1/scans/{run['id']}/comparison").status_code == 403


def test_unknown_or_invalid_scans_do_not_leak(admin, on):
    c = rest(generate(authorised(admin), "api"))
    assert c.get(f"/api/v1/scans/{NO_RUN}").status_code == 404
    assert c.get(f"/api/v1/scans/{NO_RUN}/endpoints").status_code == 404
    assert c.get("/api/v1/scans/not-a-uuid").status_code == 422
    assert "traceback" not in c.get("/api/v1/scans/not-a-uuid").text.lower()


def test_pagination_and_filters_are_validated(admin, on, run):
    c = rest(generate(authorised(admin), "api"))
    for params in ({"limit": 0}, {"limit": 101}, {"limit": 1000}, {"offset": -1}, {"status": "bogus"}):
        assert c.get("/api/v1/scans", params=params).status_code == 422, params
    assert len(c.get(f"/api/v1/scans/{run['id']}/endpoints", params={"limit": 1}).json()["items"]) == 1
    assert c.get(f"/api/v1/scans/{run['id']}/findings", params={"severity": "nope"}).status_code == 422


def test_no_business_write_through_the_external_api(admin, on, run):
    c = rest(generate(authorised(admin, "OPERATOR"), "api"))
    before = admin.get("/api/scan-runs").json()
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        for path in ("/api/v1/scans", f"/api/v1/scans/{run['id']}", f"/api/v1/scans/{run['id']}/findings", "/api/v1/me", "/api/v1/targets"):
            assert c.request(method, path, json={}).status_code in (404, 405), (method, path)
    assert admin.get("/api/scan-runs").json() == before


def test_external_documentation_is_scoped_and_depends_on_the_service(admin):
    set_service(admin, "api", False)
    for path in ("/api/v1/docs", "/api/v1/docs/", "/api/v1/openapi.json", "/api/v1/docs/init.js", "/api/v1/docs/swagger-ui-bundle.js"):
        assert httpx.get(f"{API}{path}").status_code == 404, path
    set_service(admin, "api", True)
    schema = httpx.get(f"{API}/api/v1/openapi.json").json()
    assert set(schema["paths"]) == {"/api/v1/me", "/api/v1/scans", "/api/v1/scans/{scan_id}", "/api/v1/scans/{scan_id}/summary",
                                    "/api/v1/scans/{scan_id}/endpoints", "/api/v1/scans/{scan_id}/findings", "/api/v1/scans/{scan_id}/comparison"}
    assert {m for item in schema["paths"].values() for m in item} == {"get"}
    assert schema["components"]["securitySchemes"]["personalApiToken"]["scheme"] == "bearer"
    text_ = str(schema).lower()
    for internal in ("/api/admin", "/api/results", "scan-definitions", "/password", "reports"):
        assert internal not in text_, internal
    page = httpx.get(f"{API}/api/v1/docs")
    assert page.status_code == 200 and "swagger-ui" in page.text and "unpkg" not in page.text and "script-src 'self'" in page.headers["content-security-policy"]
    assert httpx.get(f"{API}/api/v1/docs/swagger-ui-bundle.js").status_code == 200
    set_service(admin, "api", False)


def test_rest_rate_limit_and_audited_failures(admin, on):
    who = authorised(admin)
    c = rest(generate(who, "api"))
    codes = [c.get("/api/v1/me").status_code for _ in range(130)]
    assert codes.count(200) == 120 and codes.count(429) == 10
    assert c.get("/api/v1/me").headers.get("retry-after") == "60"
    httpx.get(f"{API}/api/v1/me", headers={"Authorization": "Bearer tls_scan_pat_bogus"})
    events = admin.get("/api/admin/audit", params={"action": "external_api"}).json()
    assert any(e["action"] == "external_api.auth_failed" for e in events) and any(e["action"] == "external_api.rate_limited" for e in events)
    assert "tls_scan_pat_bogus" not in str(events)


# ---------- MCP ----------
def test_mcp_is_refused_when_off_or_not_authorised_and_checks_host_origin_and_size(admin):
    who = make_user(admin, "USER")
    assert httpx.post(f"{API}/mcp", json={}).status_code == 401
    set_service(admin, "mcp", True)
    assert who.post("/api/me/access/mcp/token").status_code == 403
    grant(admin, who, mcp_access_enabled=True)
    token = generate(who, "mcp")
    headers = {"Authorization": f"Bearer {token}"}
    ok = httpx.post(f"{API}/mcp", headers={**headers, "Accept": "application/json, text/event-stream"}, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert ok.status_code not in (401, 403, 421), ok.text
    assert httpx.post(f"{API}/mcp", headers={**headers, "Origin": "https://attacker.invalid"}, json={}).status_code == 403
    assert httpx.post(f"{API}/mcp", headers={**headers, "Host": "attacker.invalid"}, json={}).status_code in (400, 403, 421)
    assert httpx.post(f"{API}/mcp", headers=headers, content=b"x" * (70 * 1024)).status_code == 413
    set_service(admin, "mcp", False)
    assert httpx.post(f"{API}/mcp", headers=headers, json={}).status_code == 401
    assert httpx.get(f"{API}/mcp-other").status_code == 404


def test_official_mcp_client_lists_a_closed_read_only_tool_list_and_calls_them(admin, on, run):
    who = authorised(admin, "USER")
    token = generate(who, "mcp")
    runs_before = admin.get("/api/scan-runs").json()
    findings_before = httpx.Client(base_url=API, headers={"Authorization": f"Bearer {generate(authorised(admin), 'api')}"}).get(f"/api/v1/scans/{run['id']}/findings", params={"limit": 100}).json()

    async def exercise() -> None:
        async with mcp_session(token) as session:
            tools = await session.list_tools()
            assert sorted(t.name for t in tools.tools) == sorted(MCP_TOOL_NAMES)
            assert not any(w in t.name for t in tools.tools for w in ("run", "delete", "create", "update", "export", "shell", "sql"))
            current = (await session.call_tool("tls_scan_get_current_user", {})).structured_content
            assert current["email"] == who.user["email"] and current["role"] == "USER"
            listed = (await session.call_tool("tls_scan_list_scans", {"limit": 100})).structured_content
            assert any(i["id"] == run["id"] for i in listed["items"])
            summary = (await session.call_tool("tls_scan_get_scan_summary", {"scan_id": run["id"]})).structured_content
            assert summary["id"] == run["id"] and "reports" not in summary
            endpoints = (await session.call_tool("tls_scan_list_endpoints", {"scan_id": run["id"], "limit": 5})).structured_content
            assert endpoints["items"]
            endpoint_id = endpoints["items"][0]["endpoint_id"]
            details = (await session.call_tool("tls_scan_get_endpoint_details", {"scan_id": run["id"], "endpoint_id": endpoint_id})).structured_content
            assert details["endpoint"]["endpoint_id"] == endpoint_id and isinstance(details["findings"], list)
            findings = (await session.call_tool("tls_scan_list_findings", {"scan_id": run["id"], "limit": 100})).structured_content
            assert findings["pagination"]["total"] == findings_before["pagination"]["total"]       # same data as REST
            compliance = (await session.call_tool("tls_scan_get_compliance_summary", {"scan_id": run["id"]})).structured_content
            assert compliance["scan_id"] == run["id"] and compliance["endpoints_by_compliance_status"]
            compared = await session.call_tool("tls_scan_compare_scans", {"scan_id": run["id"]})
            assert compared.is_error or compared.structured_content is not None
            missing = await session.call_tool("tls_scan_get_scan_summary", {"scan_id": NO_RUN})
            assert missing.is_error
            bad = await session.call_tool("tls_scan_list_scans", {"limit": 5000})
            assert bad.is_error
            garbage = await session.call_tool("tls_scan_get_scan_summary", {"scan_id": "x'; drop table users;--"})
            assert garbage.is_error

    asyncio.run(exercise())
    assert admin.get("/api/scan-runs").json() == runs_before                      # nothing created, nothing changed
    audited = admin.get("/api/admin/audit", params={"action": "mcp."}).json()
    assert any(e["action"] == "mcp.tool_called" for e in audited) and token not in str(audited)


def test_mcp_applies_the_current_role_and_the_current_authorisation_on_every_call(admin, on, run):
    who = authorised(admin, "USER")
    token = generate(who, "mcp")

    async def call(name: str, args: dict):
        async with mcp_session(token) as session:
            return await session.call_tool(name, args)

    assert not asyncio.run(call("tls_scan_get_current_user", {})).is_error
    assert admin.put(f"/api/admin/users/{who.user['id']}", json={"role": "AUDITOR"}).status_code == 200
    assert asyncio.run(call("tls_scan_get_current_user", {})).structured_content["role"] == "AUDITOR"
    assert asyncio.run(call("tls_scan_compare_scans", {"scan_id": run["id"]})).is_error            # AUDITOR cannot compare
    grant(admin, who, mcp_access_enabled=False)
    with pytest.raises(Exception):
        asyncio.run(call("tls_scan_get_current_user", {}))                                          # key revoked: no session at all


def test_mcp_rate_limit(admin, on):
    who = authorised(admin)
    token = generate(who, "mcp")

    async def burst() -> list[bool]:
        outcomes = []
        async with mcp_session(token) as session:
            for _ in range(70):
                outcomes.append((await session.call_tool("tls_scan_get_current_user", {})).is_error)
        return outcomes

    try:
        outcomes = asyncio.run(burst())
    except Exception:  # the HTTP-level limit may cut the session first
        return
    assert outcomes.count(True) >= 1
