"""Evolution between two dates (dashboard) and the extra sections of the WebUI reports (evolution, scope, trend)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from conftest import LAB, make_definition, wait_final

ACME = "intranet.acme.local"


def launch(api, definition):
    r = api.post(f"/api/scan-definitions/{definition['id']}/run")
    assert r.status_code == 202, r.text
    run = wait_final(api, r.json()["run_id"])
    assert run["status"] in ("completed", "partial"), run
    return run


def dashboard(api, definition_id, date_from, date_to):
    r = api.get("/api/dashboard", params={"trend_definition": definition_id, "evolution_from": date_from, "evolution_to": date_to})
    assert r.status_code == 200, r.text
    return r.json()["evolution"]


def test_the_dashboard_compares_the_scans_of_a_definition_between_two_dates(operator, catalog):
    d = make_definition(operator, catalog, [LAB], name=f"evo-{uuid.uuid4().hex[:6]}")
    today = datetime.now(UTC).date()
    first = launch(operator, d)
    only = dashboard(operator, d["id"], (today - timedelta(days=30)).isoformat(), today.isoformat())
    assert only["status"] == "single_run" and only["to_run"]["run_id"] == first["id"] and only["comparison"] is None
    second = launch(operator, d)
    evo = dashboard(operator, d["id"], (today - timedelta(days=30)).isoformat(), today.isoformat())
    assert evo["status"] == "ok" and evo["definition_id"] == d["id"]
    assert evo["from_run"]["run_id"] == first["id"] and evo["to_run"]["run_id"] == second["id"]
    assert [p["run_id"] for p in evo["series"]] == [first["id"], second["id"]]
    cmp = evo["comparison"]
    assert set(cmp["counts"]) == {"new", "fixed", "persistent", "not_retested"} and cmp["counts"]["new"] == 0 and cmp["counts"]["fixed"] == 0
    assert set(evo["to_run"]["findings"]) == {"critical", "high", "medium", "low"}
    # the same persistent findings in both scans: the per-severity occurrences match
    assert evo["from_run"]["findings"] == evo["to_run"]["findings"]
    # dates drive the choice of the reference scans: a window before any scan has nothing, a reversed one is refused
    assert dashboard(operator, d["id"], "2000-01-01", "2000-01-31")["status"] == "no_runs"
    assert dashboard(operator, d["id"], today.isoformat(), (today - timedelta(days=1)).isoformat())["status"] == "invalid_range"
    # the detailed comparison can be opened against that very scan
    assert operator.get(f"/api/scan-runs/{second['id']}/compare", params={"with_run": first["id"]}).json()["old_run_id"] == first["id"]


def test_evolution_is_private_to_the_scope_of_the_requester(operator, user, catalog):
    d = make_definition(operator, catalog, [LAB], name=f"evo-{uuid.uuid4().hex[:6]}")
    launch(operator, d)
    today = datetime.now(UTC).date().isoformat()
    other = user.get("/api/dashboard", params={"trend_definition": d["id"], "evolution_from": today, "evolution_to": today}).json()["evolution"]
    assert other["status"] == "no_runs" and other["series"] == []        # somebody else's scans do not show up


def test_reports_carry_the_evolution_the_scope_and_the_trend(operator, auditor, catalog):
    d = make_definition(operator, catalog, [LAB, ACME], name=f"rep-{uuid.uuid4().hex[:6]}")
    body = {"name": d["name"], "target_ids": d["target_ids"], "policy_ids": d["policy_ids"], "profile_id": d["profile_id"], "exclusions": [ACME]}
    assert operator.put(f"/api/scan-definitions/{d['id']}", json=body).status_code == 200
    first = launch(operator, d)
    html = auditor.get(f"/api/scan-runs/{first['id']}/reports/html").text
    assert "Evolution since the previous scan" not in html and "Trend over the last" not in html     # a first scan has no past
    assert 'id="scope"' in html and ACME in html and "Exclusions applied to this scan" in html
    second = launch(operator, d)
    html = auditor.get(f"/api/scan-runs/{second['id']}/reports/html").text
    md = auditor.get(f"/api/scan-runs/{second['id']}/reports/md").text
    for text in (html, md):
        assert "Evolution since the previous scan" in text and "not retested" in text and "Trend over the last 2 scans" in text
        assert "Scan scope" in text
    assert html.index('id="evolution"') < html.index('<footer class="report-footer"')            # the extra sections come before the footer
    # the API verifies the stored SHA-256 before serving a report: reaching this point means the modified files were hashed after the change
    assert {r["format"] for r in second["reports"]} >= {"html", "md"}
