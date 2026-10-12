"""Read-only results API (/api/results) and its dedicated Swagger UI (/swagger)."""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import httpx
import pytest

from conftest import API, LAB, make_definition, wait_final

NO_RUN = "00000000-0000-4000-8000-000000000000"
ROOT = Path(os.environ.get("TLS_SCAN_STORAGE_ROOT", "/var/lib/tls-scan"))


@pytest.fixture(scope="module")
def run(user, catalog) -> dict:
    definition = make_definition(user, catalog, [LAB], name="results-api")
    return wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])


def test_swagger_both_urls_and_assets_after_login(auditor):
    for path in ("/swagger", "/swagger/"):
        r = auditor.get(path)
        assert r.status_code == 200 and "swagger-ui" in r.text, path
        assert "text/html" in r.headers["content-type"]
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "http" not in csp  # served locally, no CDN
        assert "unpkg" not in r.text and "cdn" not in r.text.lower()
    assert auditor.get("/swagger/swagger-ui-bundle.js").status_code == 200
    assert auditor.get("/swagger/swagger-ui.css").status_code == 200
    assert "openapi.json" in auditor.get("/swagger/init.js").text
    assert auditor.get("/swagger/..%2f..%2fetc%2fpasswd").status_code == 404
    assert auditor.get("/swagger/not-an-asset.js").status_code == 404


def test_swagger_and_schema_require_authentication():
    for path in ("/swagger", "/swagger/", "/swagger/openapi.json", "/swagger/swagger-ui-bundle.js", "/swagger/init.js"):
        assert httpx.get(f"{API}{path}", follow_redirects=False).status_code == 401, path


def test_internal_openapi_is_not_published():
    for path in ("/api/openapi.json", "/api/docs", "/openapi.json", "/docs"):
        assert httpx.get(f"{API}{path}").status_code in (401, 404), path


def test_dedicated_schema_is_read_only_and_describes_only_results(auditor):
    schema = auditor.get("/swagger/openapi.json").json()
    assert schema["openapi"].startswith("3.")
    methods = {m for item in schema["paths"].values() for m in item}
    assert methods == {"get"}, methods
    assert set(schema["paths"]) == {
        "/api/results", "/api/results/{run_id}", "/api/results/{run_id}/endpoints", "/api/results/{run_id}/findings",
        "/api/results/{run_id}/compare", "/api/results/{run_id}/reports", "/api/results/{run_id}/reports/{format}",
    }
    text = str(schema).lower()
    for internal in ("/cancel", "/api/admin", "scan-definitions", "/api/auth", "/api/schedules", "/password"):
        assert internal not in text, internal
    for name in ("Run", "RunDetail", "RunSummary", "Endpoint", "Certificate", "Finding", "Comparison", "ReportInfo", "Pagination"):
        assert name in schema["components"]["schemas"], name
    assert "examples" in schema["components"]["schemas"]["RunDetail"]
    statuses = schema["components"]["schemas"]["Run"]["properties"]["status"]["enum"]
    assert {"completed", "partial", "failed", "cancelled", "queued", "running"} <= set(statuses)


def test_no_write_method_on_results(admin):
    run_id = NO_RUN
    for path in ("/api/results", f"/api/results/{run_id}", f"/api/results/{run_id}/reports/html"):
        for method in ("post", "put", "patch", "delete"):
            assert admin.request(method, path).status_code in (404, 405), (method, path)


def test_results_require_authentication(run):
    for path in ("", f"/{run['id']}", f"/{run['id']}/endpoints", f"/{run['id']}/findings", f"/{run['id']}/compare", f"/{run['id']}/reports",
                 f"/{run['id']}/reports/html"):
        assert httpx.get(f"{API}/api/results{path}").status_code == 401, path


def test_roles(run, auditor, user, operator, admin):
    for api in (auditor, user, operator, admin):
        assert api.get("/api/results").status_code == 200
        assert api.get(f"/api/results/{run['id']}").status_code == 200
        assert api.get(f"/api/results/{run['id']}/reports").status_code == 200
    # comparison needs USER, like the internal route
    assert auditor.get(f"/api/results/{run['id']}/compare").status_code == 403
    assert user.get(f"/api/results/{run['id']}/compare").status_code in (200, 404)  # 404: no earlier comparable run yet


def test_list_pagination_filters_and_order(run, user, auditor):
    page = auditor.get("/api/results", params={"limit": 1}).json()
    assert len(page["items"]) == 1 and page["pagination"]["limit"] == 1 and page["pagination"]["total"] >= 1
    everything = auditor.get("/api/results", params={"limit": 200}).json()["items"]
    queued = [r["queued_at"] for r in everything]
    assert queued == sorted(queued, reverse=True)
    if page["pagination"]["total"] > 1:
        second = auditor.get("/api/results", params={"limit": 1, "offset": 1}).json()["items"]
        assert second[0]["id"] != page["items"][0]["id"]
    for bad in ({"limit": 0}, {"limit": 201}, {"offset": -1}, {"status": "bogus"}, {"definition_id": "nope"}, {"started_after": "yesterday"}):
        assert auditor.get("/api/results", params=bad).status_code == 422, bad
    done = auditor.get("/api/results", params={"status": run["status"], "limit": 200}).json()["items"]
    assert run["id"] in [r["id"] for r in done] and {r["status"] for r in done} == {run["status"]}
    by_def = auditor.get("/api/results", params={"definition_id": run["definition_id"]}).json()["items"]
    assert [r["id"] for r in by_def if r["id"] == run["id"]] and {r["definition"]["id"] for r in by_def} == {run["definition_id"]}
    assert auditor.get("/api/results", params={"definition_id": str(uuid.uuid4())}).json()["pagination"]["total"] == 0
    mine = user.get("/api/results", params={"mine": True, "limit": 200}).json()["items"]
    assert run["id"] in [r["id"] for r in mine]
    assert auditor.get("/api/results", params={"mine": True, "limit": 200}).json()["pagination"]["total"] == 0
    by_user = auditor.get("/api/results", params={"requested_by": user.user["id"], "limit": 200}).json()["items"]
    assert run["id"] in [r["id"] for r in by_user]
    after = auditor.get("/api/results", params={"finished_after": run["finished_at"], "limit": 200}).json()["items"]
    assert run["id"] in [r["id"] for r in after]
    assert auditor.get("/api/results", params={"finished_before": "2000-01-01T00:00:00Z"}).json()["pagination"]["total"] == 0
    assert auditor.get("/api/results", params={"started_after": "2999-01-01T00:00:00Z"}).json()["pagination"]["total"] == 0


def test_tag_and_si_filters(user, operator, auditor, catalog):
    si = operator.post("/api/information-systems", json={"name": f"SI-{uuid.uuid4().hex[:4]}"}).json()
    sub = user.post("/api/information-systems", json={"name": "Web", "parent_id": si["id"]}).json()
    tag = f"tag-{uuid.uuid4().hex[:6]}"
    definition = make_definition(user, catalog, [LAB], name="results-tags", ports="80")
    assert user.put(f"/api/scan-definitions/{definition['id']}", json={
        "name": definition["name"], "target_ids": definition["target_ids"],
        "policy_ids": [catalog["policy"]], "profile_id": catalog["profile"], "tags": [tag], "si_ids": [sub["id"]]}).status_code == 200
    final = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    for params in ({"tag": tag}, {"si": sub["id"]}, {"si": si["id"]}):  # parent SI includes the sub-SI
        ids = [r["id"] for r in auditor.get("/api/results", params=params).json()["items"]]
        assert ids == [final["id"]], params
    item = auditor.get("/api/results", params={"tag": tag}).json()["items"][0]
    assert item["tags"] == [tag] and item["information_systems"] == [sub["id"]]
    assert auditor.get("/api/results", params={"tag": "no-such-tag"}).json()["pagination"]["total"] == 0


def test_run_detail_matches_collected_data(run, auditor):
    d = auditor.get(f"/api/results/{run['id']}").json()
    assert d["id"] == run["id"] and d["status"] == run["status"] and d["name"] == run["name"]
    assert d["definition"]["id"] == run["definition_id"] and d["definition"]["name"]
    assert d["profile"]["name"] and d["profile_version"] is not None
    assert d["policy_versions"] == [{"name": p["name"], "version": p["version"], "version_id": p["version_id"]} for p in run["policy_versions"]]
    for key in ("total_endpoints", "compliant_endpoints", "non_compliant_endpoints", "overall_grade"):
        assert d["summary"][key] == run["summary"][key]
    sev = d["summary"]["findings_by_severity"]
    assert sum(v["unique"] for v in sev.values()) == d["summary"]["unique_findings"] == len(run["findings"])
    assert d["queued_at"].endswith(("Z", "+00:00")) and d["duration_seconds"] == run["duration_seconds"]
    assert {r["format"] for r in d["reports"]} >= {"html", "md", "csv", "cbom"} and all(r["available"] for r in d["reports"])
    assert d["error"] is None or isinstance(d["error"], str)
    assert isinstance(d["untested_checks"], dict) and isinstance(d["endpoint_errors"], dict)


def test_unknown_or_malformed_ids(auditor, run):
    for tail in ("", "/endpoints", "/findings", "/reports", "/reports/html"):
        assert auditor.get(f"/api/results/{NO_RUN}{tail}").status_code == 404, tail
        assert auditor.get(f"/api/results/not-a-uuid{tail}").status_code == 422, tail
    assert auditor.get(f"/api/results/{run['id']}/reports/exe").status_code == 422
    assert auditor.get(f"/api/results/{NO_RUN}/compare").status_code in (403, 404)


def test_endpoints_certificates_and_unexecuted_checks(run, auditor):
    page = auditor.get(f"/api/results/{run['id']}/endpoints").json()
    items = page["items"]
    assert page["pagination"]["total"] == len(items) == len(run["endpoints"]) >= 2
    assert [e["endpoint_id"] for e in items] == sorted(e["endpoint_id"] for e in items)
    internal = {e["endpoint_id"]: e for e in run["endpoints"]}
    for e in items:
        src = internal[e["endpoint_id"]]
        assert e["port"] == int(src["port"]) and e["ip_address"] == src["ip_address"] and e["grade"] == src["grade"]
        assert e["tls_versions"] == src["tls_versions"] and e["compliance_status"] == src["compliance_status"]
        assert e["untested_checks"] == src["untested_checks"] and e["errors"] == src["errors"]
        assert isinstance(e["cipher_suites"], list)
        cert = e["certificate"]
        assert cert is not None and cert["subject"] and cert["issuer"]
        assert cert["valid_until"] and isinstance(cert["key_size"], int) and cert["signature_algorithm"] and cert["fingerprint"]
        assert set(cert) >= {"trust_status", "revocation_status", "chain_validation_status", "self_signed"}
    first = items[0]
    assert [e["endpoint_id"] for e in auditor.get(f"/api/results/{run['id']}/endpoints", params={"limit": 1}).json()["items"]] == [first["endpoint_id"]]
    only = auditor.get(f"/api/results/{run['id']}/endpoints", params={"compliance_status": "no-such"}).json()
    assert only["items"] == [] and only["pagination"]["total"] == 0
    assert auditor.get(f"/api/results/{run['id']}/endpoints", params={"severity": "nope"}).status_code == 422
    q = auditor.get(f"/api/results/{run['id']}/endpoints", params={"q": first["ip_address"]}).json()
    assert first["endpoint_id"] in [e["endpoint_id"] for e in q["items"]]


def test_findings_with_evidence_and_remediation(run, auditor):
    page = auditor.get(f"/api/results/{run['id']}/findings", params={"limit": 200}).json()
    assert run["findings"] and page["pagination"]["total"] == len(run["findings"])
    internal = {f["finding_id"]: f for f in run["findings"]}
    for f in page["items"]:
        src = internal[f["finding_id"]]  # identifiers of the engine are preserved
        assert f["title"] == src["title"] and f["severity"] == src["severity"] and f["affected_endpoint_ids"] == src["affected_endpoint_ids"]
        assert f["evidence"] == (src["evidence"] or None) and f["remediation"] == (src["remediation"] or None)
    assert any(f["evidence"] and f["remediation"] for f in page["items"])
    sev = page["items"][0]["severity"]
    only = auditor.get(f"/api/results/{run['id']}/findings", params={"severity": sev, "limit": 200}).json()["items"]
    assert only and {f["severity"] for f in only} == {sev}
    ep = page["items"][0]["affected_endpoint_ids"][0]
    for f in auditor.get(f"/api/results/{run['id']}/findings", params={"endpoint_id": ep, "limit": 200}).json()["items"]:
        assert ep in f["affected_endpoint_ids"]
    assert auditor.get(f"/api/results/{run['id']}/findings", params={"severity": "nope"}).status_code == 422


def test_compare_matches_internal_and_untested_is_not_fixed(user, catalog, run):
    again = wait_final(user, user.post(f"/api/scan-definitions/{run['definition_id']}/run").json()["run_id"])
    api = user.get(f"/api/results/{again['id']}/compare").json()
    assert api == user.get(f"/api/scan-runs/{again['id']}/compare").json()
    assert api["old_run_id"] == run["id"] and api["counts"]["fixed"] == 0 and api["counts"]["persistent"] > 0
    other = make_definition(user, catalog, [LAB], name="results-compare-other", ports="80")
    empty = wait_final(user, user.post(f"/api/scan-definitions/{other['id']}/run").json()["run_id"])
    cmp = user.get(f"/api/results/{empty['id']}/compare", params={"with_run": run["id"]}).json()
    assert cmp["counts"]["fixed"] == 0 and cmp["counts"]["not_retested"] > 0 and "scope_differs" in cmp["warnings"]
    assert user.get(f"/api/results/{run['id']}/compare", params={"with_run": run["id"]}).status_code == 422
    assert user.get(f"/api/results/{run['id']}/compare", params={"with_run": NO_RUN}).status_code == 404


def test_report_list_and_download_with_protections(run, auditor):
    listed = auditor.get(f"/api/results/{run['id']}/reports").json()["items"]
    assert {r["format"] for r in listed} >= {"html", "md", "csv", "cbom"}
    for r in listed:
        assert r["sha256"] and r["download_url"] == f"/api/results/{run['id']}/reports/{r['format']}" and r["content_type"]
    html = auditor.get(f"/api/results/{run['id']}/reports/html")
    assert html.status_code == 200 and "sandbox" in html.headers["content-security-policy"]
    assert "allow-same-origin" not in html.headers["content-security-policy"] and html.headers["x-content-type-options"] == "nosniff"
    csv = auditor.get(f"/api/results/{run['id']}/reports/csv")
    assert csv.status_code == 200 and hashlib.sha256(csv.content).hexdigest() == next(r["sha256"] for r in listed if r["format"] == "csv")
    assert auditor.get(f"/api/results/{run['id']}/reports/cbom").json()["bomFormat"] == "CycloneDX"
    for fmt in ("..%2f..%2fetc%2fpasswd", "../../etc/passwd", "exe"):
        assert auditor.get(f"/api/results/{run['id']}/reports/{fmt}").status_code in (404, 422)


def test_report_integrity_failure_is_refused(user, auditor, catalog):
    definition = make_definition(user, catalog, [LAB], name="results-integrity", ports="443")
    final = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    expected = next(r["sha256"] for r in final["reports"] if r["format"] == "md")
    path = next(p for p in (ROOT / "reports").rglob("*.md") if hashlib.sha256(p.read_bytes()).hexdigest() == expected)
    original = path.read_bytes()
    assert auditor.get(f"/api/results/{final['id']}/reports/md").status_code == 200
    try:
        path.write_bytes(original + b"\ntampered")
        r = auditor.get(f"/api/results/{final['id']}/reports/md")
        assert r.status_code == 500 and "tampered" not in r.text and str(ROOT) not in r.text
        assert auditor.get(f"/api/scan-runs/{final['id']}/reports/md").status_code == 500
        assert next(x for x in auditor.get(f"/api/results/{final['id']}/reports").json()["items"] if x["format"] == "md")["available"]
    finally:
        path.write_bytes(original)
    assert auditor.get(f"/api/results/{final['id']}/reports/md").status_code == 200


def test_no_secret_leaks_in_results(run, auditor):
    secrets = [os.environ.get(k) for k in ("TLS_SCAN_SESSION_SECRET", "TLS_SCAN_LOCAL_ADMIN_PASSWORD", "TLS_SCAN_DATABASE_URL",
                                           "TLS_SCAN_OIDC_CLIENT_SECRET", "TLS_SCAN_GRAPH_CLIENT_SECRET", "TLS_SCAN_LDAP_BIND_PASSWORD")]
    paths = ["/api/results", f"/api/results/{run['id']}", f"/api/results/{run['id']}/endpoints", f"/api/results/{run['id']}/findings",
             f"/api/results/{run['id']}/reports", "/swagger/openapi.json", f"/api/results/{NO_RUN}", "/api/results?limit=zzz"]
    blob = "".join(auditor.get(p).text for p in paths)
    assert "config_snapshot" not in blob and "worker_id" not in blob and "sha256=" not in blob.lower()
    for secret in filter(None, secrets):
        assert secret not in blob
    assert "access-control-allow-origin" not in httpx.get(f"{API}/api/results", headers={"Origin": "https://evil.example"}).headers


def test_reads_do_not_change_results(run, auditor):
    before = auditor.get(f"/api/results/{run['id']}").json()
    for p in ("", "/endpoints", "/findings", "/reports", "/reports/csv"):
        auditor.get(f"/api/results/{run['id']}{p}")
    assert auditor.get(f"/api/results/{run['id']}").json() == before


def test_internal_apis_still_work(run, user, auditor, operator, admin):
    assert user.get(f"/api/scan-runs/{run['id']}").json()["endpoints"]
    assert auditor.get("/api/scan-runs", params={"limit": 5}).status_code == 200
    assert user.get("/api/scan-runs", params={"mine": True, "status": run["status"]}).status_code == 200
    assert admin.get("/api/dashboard").status_code == 200
    assert auditor.get(f"/api/scan-runs/{run['id']}/reports/html").status_code == 200
    assert user.get("/api/scan-definitions").status_code == 200
    assert auditor.post(f"/api/scan-runs/{run['id']}/cancel").status_code == 403  # write operations keep their rules


NGINX = os.environ.get("TEST_NGINX_URL")


@pytest.mark.skipif(not NGINX, reason="set TEST_NGINX_URL, TEST_NGINX_USER and TEST_NGINX_PASSWORD (HTTPS entry point, e.g. the crashtest stack)")
def test_behind_nginx():
    login = httpx.Client(base_url=NGINX, verify=False, follow_redirects=False)
    assert login.get("/swagger").status_code == 401 and login.get("/swagger/").status_code == 401
    r = login.post("/api/auth/login", json={"username": os.environ["TEST_NGINX_USER"], "password": os.environ["TEST_NGINX_PASSWORD"]})
    assert r.status_code == 200
    for path in ("/swagger", "/swagger/"):
        page = login.get(path)
        assert page.status_code == 200 and "swagger-ui" in page.text and "<title>TLS Scan API" in page.text, path
        assert "strict-transport-security" in page.headers and "script-src 'self'" in page.headers["content-security-policy"]
    assert login.get("/swagger/swagger-ui-bundle.js").status_code == 200
    assert login.get("/swagger/openapi.json").json()["paths"]
    assert login.get("/api/results").status_code == 200 and login.get("/").text.lower().count("<div id=\"root\"") == 1


def test_dashboard_posture_follows_the_scope_of_the_caller(run, user, user2, operator):
    mine = user.get("/api/dashboard").json()
    assert mine["posture"]["basis_run_ids"] and mine["posture"]["endpoints"]["total"] >= 1  # the basis is the latest finished run of each definition
    assert mine["trend"]["points"] and all(p["rate"] is None or 0 <= p["rate"] <= 100 for p in mine["trend"]["points"])
    other = user2.get("/api/dashboard").json()  # a user never sees the results of somebody else's scans
    assert not set(mine["posture"]["basis_run_ids"]) & set(other["posture"]["basis_run_ids"])
    assert not {p["run_id"] for p in mine["trend"]["points"]} & {p["run_id"] for p in other["trend"]["points"]}
    everything = operator.get("/api/dashboard", params={"scope": "all"}).json()
    assert set(mine["posture"]["basis_run_ids"]) <= set(everything["posture"]["basis_run_ids"])
    assert user.get("/api/dashboard", params={"trend_definition": str(uuid.uuid4())}).status_code == 200
