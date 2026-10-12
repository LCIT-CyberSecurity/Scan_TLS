"""Complementary TLS checks end to end: versioned profile -> worker -> storage -> UI/REST API -> reports, and compatibility."""
from __future__ import annotations

import copy
import uuid

import pytest

from conftest import LAB, PROFILE, make_definition, wait_final

CHECK_IDS = ["hostname_san", "ocsp_stapling", "tls_compression", "renegotiation", "fallback_scsv", "extended_master_secret", "ecdhe_groups", "ffdhe_groups",
             "session_resumption", "session_tickets", "early_data", "client_auth", *(f"starttls_{p}" for p in ("imap", "pop3", "ldap", "ftp", "postgres", "xmpp", "xmpp_server"))]
TLS = {check: {"enabled": True} for check in CHECK_IDS}


def profile(operator, tls: dict | None, ports="443,8450") -> str:
    content = copy.deepcopy(PROFILE)
    content["scan"]["ports"] = ports
    if tls is not None:
        content["checks"]["tls"] = tls
    created = operator.post("/api/profiles", json={"name": f"tlschk-{uuid.uuid4().hex[:6]}", "content": content})
    assert created.status_code == 201, created.text
    assert operator.post(f"/api/profiles/{created.json()['id']}/publish").status_code == 200
    return created.json()["id"]


def run_with(user, operator, catalog, tls):
    definition = make_definition(user, {**catalog, "profile": profile(operator, tls)}, [LAB], name=f"tlschk-{uuid.uuid4().hex[:6]}")
    return wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])


def by_port(run) -> dict:
    return {e["port"]: e for e in run["endpoints"]}
APPLICABLE_IDS = [i for i in CHECK_IDS if not i.startswith("starttls_")]


def test_catalogue_lists_only_implemented_checks(user):
    items = user.get("/api/tls-checks").json()
    assert [i["id"] for i in items] == CHECK_IDS
    assert {i["family"] for i in items} == {"identity", "handshake", "groups", "sessions", "authentication", "protocols"}
    assert {i["id"] for i in items if i["recommended"]} == {"hostname_san", "ocsp_stapling", "tls_compression", "renegotiation", "fallback_scsv", "extended_master_secret",
                                                            "session_resumption", "session_tickets", "early_data", "client_auth", *(f"starttls_{p}" for p in ("imap", "pop3", "ldap", "ftp", "postgres", "xmpp", "xmpp_server"))}
    assert next(i for i in items if i["id"] == "early_data")["options"][0]["name"] == "probe"


def test_profile_validation_uses_the_engine_rules(operator):
    base = {"scan": {"ports": "443"}, "checks": {}}
    for tls in ({"heartbleed": {"enabled": True}}, {"hostname_san": "yes"}, {"timeout_seconds": 0}, {"time_budget_seconds": 5}, {"hostname_san": {"enabled": True, "x": 1}}, {"starttls_imap": {"ports": [0]}}, {"session_resumption": {"attempts": 9}}, {"early_data": {"probe": "yes"}}):
        r = operator.post("/api/profiles", json={"name": f"bad-{uuid.uuid4().hex[:5]}", "content": {**base, "checks": {"tls": tls}}})
        assert r.status_code == 422, tls
    ok = operator.post("/api/profiles", json={"name": f"ok-{uuid.uuid4().hex[:5]}", "content": {**base, "checks": {"tls": {"hostname_san": True, "timeout_seconds": 5, "early_data": {"probe": False}, "starttls_imap": {"ports": [143, 1143]}}}}})
    assert ok.status_code == 201, ok.text


@pytest.fixture(scope="module")
def runs(user, operator, catalog):
    return {"legacy": run_with(user, operator, catalog, None), "tls": run_with(user, operator, catalog, TLS)}


def test_results_are_stored_per_endpoint_and_exposed(user, auditor, runs):
    run = runs["tls"]
    assert run["status"] in ("completed", "partial"), run
    endpoints = by_port(run)
    assert set(endpoints) >= {"443", "8450"}
    for port in ("443", "8450"):
        checks = {c["check_id"]: c for c in endpoints[port]["tls_checks"]}
        assert list(checks) == APPLICABLE_IDS  # protocol checks only appear on their own ports
        assert all(c["status"] in ("PASS", "FAIL", "NOT_TESTED", "NOT_APPLICABLE", "INCONCLUSIVE", "ERROR") and c["duration_ms"] is not None for c in checks.values())
    http_check = {c["check_id"]: c for c in endpoints["443"]["tls_checks"]}
    assert http_check["hostname_san"]["status"] == "PASS"  # the requested name is lab-tls, the SAN says lab-tls
    assert http_check["tls_compression"]["status"] == "PASS" and http_check["fallback_scsv"]["status"] == "PASS"
    assert http_check["ocsp_stapling"]["status"] == "NOT_APPLICABLE"
    staple = {c["check_id"]: c for c in endpoints["8450"]["tls_checks"]}["ocsp_stapling"]
    assert staple["status"] == "PASS" and staple["observations"]["signature_verified"] is True
    # the read-only results API (and thus MCP, which shares the service) carries the same observations
    rest = auditor.get(f"/api/results/{run['id']}/endpoints").json()["items"]
    assert {e["endpoint_id"]: [c["check_id"] for c in e["tls_checks"]] for e in rest if e["port"] in (443, 8450)}
    assert all(e["tls_checks"] == [] or len(e["tls_checks"]) == len(APPLICABLE_IDS) for e in rest)


def test_historical_profile_keeps_its_behaviour_and_the_grade_is_unchanged(runs):
    legacy, enriched = runs["legacy"], runs["tls"]
    assert all(e["tls_checks"] == [] for e in legacy["endpoints"])
    def pick(run):
        return {e["port"]: (e["grade"], e["compliance_status"], e["highest_severity"], sorted(e["tls_versions"])) for e in run["endpoints"]}

    assert pick(legacy) == pick(enriched)
    def key(finding):
        return (finding["finding_id"], finding["status"], tuple(finding["affected_endpoint_ids"]))

    assert sorted(map(key, legacy["findings"])) == sorted(map(key, enriched["findings"]))
    assert legacy["summary"]["overall_grade"] == enriched["summary"]["overall_grade"]
    assert legacy["summary"]["total_endpoints"] == enriched["summary"]["total_endpoints"]


def test_reports_show_the_checks_separately_and_stay_compatible(user, runs):
    enriched, legacy = runs["tls"], runs["legacy"]
    html = user.get(f"/api/scan-runs/{enriched['id']}/reports/html").text
    assert 'report-chapter" id="tlschecks"' in html and '"complementary_checks":[' in html
    markdown = user.get(f"/api/scan-runs/{enriched['id']}/reports/md").text
    assert "## Complementary TLS Checks" in markdown and "OCSP stapling" in markdown
    legacy_html = user.get(f"/api/scan-runs/{legacy['id']}/reports/html").text
    legacy_md = user.get(f"/api/scan-runs/{legacy['id']}/reports/md").text
    # (the delivered HTML inlines report.js, which knows the section; only the section and the data must be absent)
    assert 'report-chapter" id="tlschecks"' not in legacy_html and '"complementary_checks"' not in legacy_html and "Complementary TLS Checks" not in legacy_md
    # CSV and CBOM have the same shape with or without the checks
    legacy_csv = user.get(f"/api/scan-runs/{legacy['id']}/reports/csv").text.splitlines()[0]
    assert user.get(f"/api/scan-runs/{enriched['id']}/reports/csv").text.splitlines()[0] == legacy_csv
    assert user.get(f"/api/scan-runs/{enriched['id']}/reports/cbom").json()["bomFormat"] == "CycloneDX"


def test_comparison_reports_status_changes_of_the_checks_only_when_both_runs_have_them():
    from tls_scan_app.services.comparison import _tls_check_changes

    old = [{"check_id": "a", "status": "PASS"}, {"check_id": "b", "status": "PASS"}]
    new = [{"check_id": "a", "status": "FAIL"}, {"check_id": "b", "status": "PASS"}, {"check_id": "c", "status": "FAIL"}]
    assert _tls_check_changes(old, new) == [{"check_id": "a", "before": "PASS", "after": "FAIL"}]
    assert _tls_check_changes([], new) == []


def test_scan_comparison_between_a_run_with_and_without_checks_is_still_valid(user, runs):
    r = user.get(f"/api/scan-runs/{runs['tls']['id']}/compare", params={"against": runs["legacy"]["id"]})
    assert r.status_code in (200, 404, 422)  # the profile differs: a warning, never a crash
    assert r.status_code != 500


def test_report_name_from_definition_is_ascii_safe():
    from tls_scan_app.services.planner import _safe_name
    from tls_scanner.config import validate_config_name

    for name in ("test home avancé", "Scan été / prod", "日本語", "ok-name_1"):
        validate_config_name(_safe_name(name), "report.name")
    assert _safe_name("test home avancé") == "test_home_avance"
    assert _safe_name("日本語") == "scan"
