"""Run lifecycle: dedup under concurrency, cancellation, failures, schedules, comparison, SI/tags."""
from __future__ import annotations

import concurrent.futures
import time
import uuid

from conftest import LAB, make_definition, wait_final, wait_for


def test_concurrent_identical_requests_share_one_run(user, user2, catalog):
    definition = make_definition(user, catalog, [LAB], name="dedup")

    def fire(api):
        return api.post(f"/api/scan-definitions/{definition['id']}/run").json()

    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        results = list(pool.map(fire, [user, user2] * 4))
    ids = {r["run_id"] for r in results}
    assert len(ids) == 1, f"expected one shared run, got {ids}"
    assert sum(1 for r in results if not r["deduplicated"]) == 1
    final = wait_final(user, ids.pop())
    assert final["status"] in ("completed", "partial")
    # both users can retrieve the shared run; user2 gets no right on user's definition
    assert user2.get(f"/api/scan-runs/{final['id']}").status_code == 200
    assert final["id"] in [r["id"] for r in user2.get("/api/scan-runs", params={"mine": True}).json()]
    assert user2.delete(f"/api/scan-definitions/{definition['id']}").status_code == 403
    # once finished, a new scan is a new run
    again = user.post(f"/api/scan-definitions/{definition['id']}/run").json()
    assert again["run_id"] != final["id"] and not again["deduplicated"]
    wait_final(user, again["run_id"])


def test_no_tls_service_is_not_an_error_nor_compliant(user, catalog):
    definition = make_definition(user, catalog, [LAB], name="plain-http", ports="80")
    run = user.post(f"/api/scan-definitions/{definition['id']}/run").json()
    final = wait_final(user, run["run_id"])
    assert final["status"] == "completed", final
    assert final["endpoints"] == []
    assert final["summary"]["total_endpoints"] == 0


def test_cancel_stops_run_and_only_owner_or_operator_can(user, user2, operator, catalog):
    # a CIDR over unreachable space keeps nmap busy long enough to cancel
    definition = make_definition(user, catalog, ["10.255.0.0/20"], name="slow")
    run = user.post(f"/api/scan-definitions/{definition['id']}/run").json()
    wait_for(lambda: user.get(f"/api/scan-runs/{run['run_id']}").json()["status"] == "running", 60)
    assert user2.post(f"/api/scan-runs/{run['run_id']}/cancel").status_code == 403
    assert user.post(f"/api/scan-runs/{run['run_id']}/cancel").status_code == 200
    final = wait_final(user, run["run_id"], 90)
    assert final["status"] == "cancelled"
    assert operator.post(f"/api/scan-runs/{run['run_id']}/cancel").status_code == 409  # already final


def test_schedule_once_fires_exactly_once_and_is_traced(user, operator, catalog):
    from datetime import datetime, timedelta, timezone

    definition = make_definition(user, catalog, [LAB], name="scheduled", ports="443")
    at = (datetime.now(timezone.utc) + timedelta(seconds=6)).replace(microsecond=0).isoformat()
    sched = user.post("/api/schedules", json={"definition_id": definition["id"], "kind": "once", "params": {"at": at}, "timezone": "UTC"}).json()
    detail = wait_for(lambda: (d := user.get(f"/api/schedules/{sched['id']}").json())["triggers"] and d, 60)
    assert [t["outcome"] for t in detail["triggers"]] == ["triggered"]
    run_id = detail["triggers"][0]["run_id"]
    final = wait_final(user, run_id)
    assert final["schedule_id"] == sched["id"]
    time.sleep(6)
    after = user.get(f"/api/schedules/{sched['id']}").json()
    assert len(after["triggers"]) == 1 and after["active"] is False


def test_invalid_schedules_are_rejected(user, catalog):
    definition = make_definition(user, catalog, [LAB], name="sched-validation", ports="443")
    for kind, params in (("cron", {"expr": "* * * * *"}), ("cron", {"expr": "nonsense"}), ("daily", {"time": "25:00"}), ("monthly", {"time": "01:00", "day": 31})):
        r = user.post("/api/schedules", json={"definition_id": definition["id"], "kind": kind, "params": params, "timezone": "UTC"})
        assert r.status_code == 422, (kind, params)


def test_compare_two_runs_and_untested_is_not_fixed(user, catalog):
    definition = make_definition(user, catalog, [LAB], name="compare")
    first = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    second = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    cmp = user.get(f"/api/scan-runs/{second['id']}/compare").json()
    assert cmp["old_run_id"] == first["id"]
    assert cmp["counts"]["new"] == 0 and cmp["counts"]["fixed"] == 0 and cmp["counts"]["persistent"] > 0
    # comparing with a run on a different target never reports its findings as fixed
    other = make_definition(user, catalog, [LAB], name="compare-other", ports="80")
    empty = wait_final(user, user.post(f"/api/scan-definitions/{other['id']}/run").json()["run_id"])
    cmp2 = user.get(f"/api/scan-runs/{empty['id']}/compare", params={"with_run": first["id"]}).json()
    assert cmp2["counts"]["fixed"] == 0 and cmp2["counts"]["not_retested"] > 0
    assert "scope_differs" in cmp2["warnings"]


def test_si_tags_filtering_and_no_duplicates(user, operator):
    si = operator.post("/api/information-systems", json={"name": f"SI-{uuid.uuid4().hex[:4]}"}).json()
    sub = user.post("/api/information-systems", json={"name": "Web", "parent_id": si["id"]}).json()
    assert user.post("/api/information-systems", json={"name": "x", "parent_id": sub["id"]}).status_code == 422
    value = f"{uuid.uuid4().hex[:8]}.example.org"
    t = user.post("/api/targets", json={"value": value, "tags": ["Production", "Internet"], "si_ids": [sub["id"]]}).json()
    assert user.post("/api/targets", json={"value": value}).status_code == 409  # no artificial duplicates
    assert [x["id"] for x in user.get("/api/targets", params={"si": si["id"]}).json()] == [t["id"]]  # SI filter includes sub-SI
    assert t["id"] in [x["id"] for x in user.get("/api/targets", params={"tag": "Internet"}).json()]
    assert user.get("/api/targets", params={"tag": "Nope"}).json() == []


def test_policy_versions_are_immutable(operator, catalog):
    from conftest import POLICY

    item = next(p for p in operator.get("/api/policies").json() if p["id"] == catalog["policy"])
    published = [v for v in item["versions"] if v["status"] == "published"][0]
    changed = {**POLICY, "minimum_rsa_bits": 3072}
    r = operator.post(f"/api/policies/{item['id']}/versions", json={"name": item["name"], "content": changed}).json()
    versions = {v["version"]: v for v in r["versions"]}
    assert versions[published["version"]]["content"]["minimum_rsa_bits"] == 2048  # untouched
    assert versions[published["version"] + 1]["status"] == "draft"
    assert operator.post("/api/policies", json={"name": "bad", "content": {"allowed_versions": []}}).status_code == 422


def test_pqc_profile_distinguishes_hybrid_ml_kem_from_classical(operator, user, catalog):
    """Needs OpenSSL >= 3.5 in the worker image (trixie) and the lab's 8447 (X25519MLKEM768) / 8448 (classical)."""
    import uuid

    from conftest import POLICY

    profile = operator.post("/api/profiles", json={"name": f"pqc-{uuid.uuid4().hex[:5]}", "content": {
        "scan": {"ports": "8447,8448", "crypto": "pqc", "workers": 2}, "checks": {"certificate": {"revocation": {"enabled": False}}}}}).json()
    assert operator.post(f"/api/profiles/{profile['id']}/publish").status_code == 200
    definition = make_definition(user, {**catalog, "profile": profile["id"]}, [LAB], name="pqc", ports="")
    final = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    assert final["status"] in ("completed", "partial"), final["error"]
    by_port = {e["port"]: e for e in final["endpoints"]}
    assert {"8447", "8448"} <= set(by_port), by_port.keys()
    def titles(port):
        return {f["title"] for f in final["findings"] if any(a.endswith(f":{port}/tcp") for a in f["affected_endpoint_ids"])}

    assert "Hybrid ML-KEM Group Not Supported" in titles("8448")  # classical-only endpoint is flagged
    assert "Hybrid ML-KEM Group Not Supported" not in titles("8447")  # X25519MLKEM768 endpoint is not


def test_report_template_branding_is_applied_to_the_html_report(operator, user, catalog):
    import base64
    import uuid

    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 64).decode()
    good = {"name": f"brand-{uuid.uuid4().hex[:5]}", "export_formats": ["html", "csv"], "organization_name": "ACME <Sec>", "accent_color": "#0a7f3f", "logo": f"data:image/png;base64,{png}"}
    r = operator.post("/api/report-templates", json=good)
    assert r.status_code == 201, r.text
    tpl = r.json()
    for bad in ({"accent_color": "red"}, {"logo": "data:text/html;base64,PHNjcmlwdD4="}, {"logo": f"data:image/jpeg;base64,{png}"}, {"organization_name": "x" * 200}):
        assert operator.post("/api/report-templates", json={**good, "name": f"bad-{uuid.uuid4().hex[:5]}", **bad}).status_code == 422, bad
    assert user.post("/api/report-templates", json=good).status_code == 403
    ids = []
    for value in (LAB,):
        t = user.post("/api/targets", json={"value": value, "ports": "443"})
        ids = [x["id"] for x in user.get("/api/targets", params={"q": value}).json() if x["ports"] == "443"]
    d = user.post("/api/scan-definitions", json={"name": "branded", "target_ids": ids, "policy_ids": [catalog["policy"]], "profile_id": catalog["profile"], "report_template_id": tpl["id"]}).json()
    final = wait_final(user, user.post(f"/api/scan-definitions/{d['id']}/run").json()["run_id"])
    assert {r["format"] for r in final["reports"]} >= {"html", "csv"} and "md" not in {r["format"] for r in final["reports"]}  # template picks formats
    html = user.get(f"/api/scan-runs/{final['id']}/reports/html").text  # integrity check passes on the branded file
    assert "ACME &lt;Sec&gt;" in html and "--brand-600:#0a7f3f" in html and f"data:image/png;base64,{png}" in html and "<Sec>" not in html


def test_only_operator_and_admin_can_delete_a_scan(user, operator, admin, auditor, catalog):
    definition = make_definition(user, catalog, [LAB], name="delete-rights")
    run_id = user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"]
    wait_final(user, run_id)
    assert user.delete(f"/api/scan-runs/{run_id}").status_code == 403  # the requester cannot delete
    assert auditor.delete(f"/api/scan-runs/{run_id}").status_code == 403  # the auditor only reads
    assert operator.delete(f"/api/scan-runs/{run_id}").status_code == 204
    assert admin.get(f"/api/scan-runs/{run_id}").status_code == 404
    # the admin can delete too (own definition: no run to share with the first one)
    other = make_definition(user, catalog, [LAB], name="delete-rights-admin")
    run_id = user.post(f"/api/scan-definitions/{other['id']}/run").json()["run_id"]
    wait_final(user, run_id)
    assert admin.delete(f"/api/scan-runs/{run_id}").status_code == 204
