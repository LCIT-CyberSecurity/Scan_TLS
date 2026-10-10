from __future__ import annotations

import httpx

from conftest import LAB, make_definition, wait_final, wait_for

SINK = "http://smtp-sink:8025/messages"


def test_smtp_diagnostics_notification_and_preferences(admin, user, operator, catalog):
    # unconfigured connector: explicit conflict, not a fake success
    assert admin.post("/api/admin/notifications/test", json={}).status_code == 409
    cfg = {"connector": "smtp", "smtp": {"host": "smtp-sink", "port": 1025, "starttls": False, "from": "tls-scan@example.com"}}
    assert admin.put("/api/admin/settings/notifications", json={"value": cfg}).status_code == 200
    steps = admin.post("/api/admin/notifications/test", json={"to": "admin-test@example.com"}).json()
    assert [s["status"] for s in steps] == ["ok", "ok", "ok"]
    bad = {"connector": "smtp", "smtp": {"host": "no-such-host.invalid", "port": 25, "from": "x@example.com"}}
    admin.put("/api/admin/settings/notifications", json={"value": bad})
    steps = admin.post("/api/admin/notifications/test", json={}).json()
    assert steps[0]["step"] == "dns" and steps[0]["status"] == "fail" and "resolve" in steps[0]["detail"].lower()
    admin.put("/api/admin/settings/notifications", json={"value": cfg})

    # a finished scan notifies its requester with a summary and a link, without attachments
    definition = make_definition(user, catalog, [LAB], name="notify", ports="443")
    final = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    mails = wait_for(lambda: [m for m in httpx.get(SINK).json() if final["id"] in m["body"]], 60)
    assert mails[0]["to"] == [user.user["email"]] and "notify" in mails[0]["subject"]
    assert "Report:" in mails[0]["body"] and "Content-Disposition" not in str(mails[0]["body"])

    # preferences: opting out of everything stops notifications
    assert user.patch("/api/auth/preferences", json={"notify_events": []}).status_code == 200
    before = len(httpx.get(SINK).json())
    wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    import time

    time.sleep(5)
    assert len(httpx.get(SINK).json()) == before
    assert user.patch("/api/auth/preferences", json={"notify_events": ["bogus"]}).status_code == 422
    user.patch("/api/auth/preferences", json={"notify_events": ["scan_completed", "scan_failed", "scan_cancelled", "new_noncompliance", "certificate_expiring", "schedule_problem"]})  # restore
    assert operator.get("/api/admin/notifications").status_code == 403
    assert any(n["status"] == "sent" for n in admin.get("/api/admin/notifications").json())


def test_retention_settings_validation(admin):
    assert admin.put("/api/admin/settings/retention", json={"value": {"reports_days": 0, "runs_days": 1, "audit_days": 1}}).status_code == 422
    ok = {"reports_days": 90, "runs_days": 365, "audit_days": 730}
    assert admin.put("/api/admin/settings/retention", json={"value": ok}).status_code == 200
    assert admin.get("/api/admin/settings").json()["retention"] == ok


def test_retention_purges_old_report_files_and_audit_but_keeps_recent(admin, user, catalog):
    import os
    from datetime import UTC, datetime, timedelta
    from pathlib import Path

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session

    from tls_scan_app.services import retention

    definition = make_definition(user, catalog, [LAB], name="retention", ports="443")
    old = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    recent = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    assert user.get(f"/api/scan-runs/{old['id']}/reports/csv").status_code == 200
    admin.put("/api/admin/settings/retention", json={"value": {"reports_days": 30, "runs_days": 3650, "audit_days": 3650}})
    engine = create_engine(os.environ["TLS_SCAN_DATABASE_URL"])
    with engine.begin() as db:
        db.execute(text("update scan_runs set finished_at = :t where id = :id"), {"t": datetime.now(UTC) - timedelta(days=90), "id": old["id"]})
    with Session(engine) as db:
        counts = retention.purge(db, Path(os.environ["TLS_SCAN_STORAGE_ROOT"]))
    assert counts["report_files"] >= 1
    assert user.get(f"/api/scan-runs/{old['id']}/reports/csv").status_code == 404  # files purged
    assert user.get(f"/api/scan-runs/{old['id']}").json()["endpoints"]  # structured history kept (runs_days not reached)
    assert user.get(f"/api/scan-runs/{recent['id']}/reports/csv").status_code == 200  # recent report untouched
    actions = {e["action"] for e in admin.get("/api/admin/audit", params={"limit": 50}).json()}
    assert "retention.purge" in actions


def test_graph_connector_diagnostics_and_delivery(admin, user, catalog):
    import httpx

    graph = {"tenant_id": "contoso-test", "client_id": "app-1", "sender": "tls-scan@contoso.example"}
    admin.put("/api/admin/settings/notifications", json={"value": {"connector": "graph", "graph": graph}})
    steps = admin.post("/api/admin/notifications/test", json={"to": "someone@example.com"}).json()
    assert [(s["step"], s["status"]) for s in steps] == [("token", "ok"), ("send", "ok")]
    # permission problem is explained
    admin.put("/api/admin/settings/notifications", json={"value": {"connector": "graph", "graph": {**graph, "sender": "forbidden@contoso.example"}}})
    steps = admin.post("/api/admin/notifications/test", json={"to": "someone@example.com"}).json()
    assert steps[-1]["status"] == "fail" and "Mail.Send" in steps[-1]["detail"]
    # a scan result is delivered through Graph, with a link and no attachment
    admin.put("/api/admin/settings/notifications", json={"value": {"connector": "graph", "graph": graph}})
    definition = make_definition(user, catalog, [LAB], name="graph-notify", ports="443")
    final = wait_final(user, user.post(f"/api/scan-definitions/{definition['id']}/run").json()["run_id"])
    mails = wait_for(lambda: [m for m in httpx.get("http://mock-graph:8080/messages").json() if final["id"] in m["body"]], 60)
    assert mails[0]["to"] == [user.user["email"]] and mails[0]["sender"] == graph["sender"] and "Report:" in mails[0]["body"]
    admin.put("/api/admin/settings/notifications", json={"value": {"connector": "smtp", "smtp": {"host": "smtp-sink", "port": 1025, "starttls": False, "from": "tls-scan@example.com"}}})


def test_certificate_expiry_and_new_noncompliance_events(admin, user, operator, catalog):
    """The lab's 8445 certificate expires in 10 days (< 30-day window); a second scan with an extra port brings new findings."""
    import httpx

    admin.put("/api/admin/settings/notifications", json={"value": {"connector": "smtp", "smtp": {"host": "smtp-sink", "port": 1025, "starttls": False, "from": "tls-scan@example.com"}}})
    assert user.patch("/api/auth/preferences", json={"notify_events": ["certificate_expiring", "new_noncompliance"]}).status_code == 200
    d1 = make_definition(user, catalog, [LAB], name="expiry-a", ports="8445")
    final1 = wait_final(user, user.post(f"/api/scan-definitions/{d1['id']}/run").json()["run_id"])
    try:
        mails = wait_for(lambda: [m for m in httpx.get(SINK).json() if final1["id"] in m["body"] and "expiring" in m["subject"]], 40)
    except AssertionError:
        raise AssertionError(f"no expiry mail; summary={ {k: v for k, v in final1['summary'].items() if 'cert' in k} }; subjects={[m['subject'] for m in httpx.get(SINK).json()]}") from None
    assert "day(s) left" in mails[0]["body"] or "EXPIRED" in mails[0]["body"]
    # same definition re-targeted: add the legacy port -> new findings relative to the previous comparable run
    user.post("/api/targets", json={"value": LAB, "ports": "8443"})  # 409 if it already exists
    ids = [t["id"] for t in user.get("/api/targets", params={"q": LAB}).json() if t["ports"] in ("8445", "8443")]
    assert len(ids) == 2
    body = {**d1, "target_ids": ids, "policy_ids": [catalog["policy"]], "profile_id": catalog["profile"]}
    assert user.put(f"/api/scan-definitions/{d1['id']}", json=body).status_code == 200
    final2 = wait_final(user, user.post(f"/api/scan-definitions/{d1['id']}/run").json()["run_id"])
    try:
        mails = wait_for(lambda: [m for m in httpx.get(SINK).json() if final2["id"] in m["body"] and "new non-compliance" in m["subject"]], 40)
    except AssertionError:
        cmp = user.get(f"/api/scan-runs/{final2['id']}/compare")
        raise AssertionError(f"no mail; compare={cmp.status_code} {str(cmp.json())[:300]}; subjects={[m['subject'] for m in httpx.get(SINK).json() if final2['id'] in m['body']]}") from None
    assert "New since the previous scan" in mails[0]["body"]
    user.patch("/api/auth/preferences", json={"notify_events": ["scan_completed", "scan_failed", "scan_cancelled", "new_noncompliance", "certificate_expiring", "schedule_problem"]})


def test_schedule_problem_event_is_sent(admin, user, catalog):
    import os
    import time
    import uuid
    from datetime import UTC, datetime, timedelta

    import httpx
    from sqlalchemy import create_engine, text

    admin.put("/api/admin/settings/notifications", json={"value": {"connector": "smtp", "smtp": {"host": "smtp-sink", "port": 1025, "starttls": False, "from": "tls-scan@example.com"}}})
    definition = make_definition(user, catalog, [LAB], name="late-schedule", ports="443")
    sched = user.post("/api/schedules", json={"definition_id": definition["id"], "kind": "daily", "params": {"time": "03:00"}, "timezone": "UTC"}).json()
    # simulate downtime: the occurrence was due two hours ago
    engine = create_engine(os.environ["TLS_SCAN_DATABASE_URL"])
    with engine.begin() as db:
        db.execute(text("update scan_schedules set next_run_at = :t where id = :id"), {"t": datetime.now(UTC) - timedelta(hours=2), "id": sched["id"]})
    mails = wait_for(lambda: [m for m in httpx.get(SINK).json() if "schedule problem" in m["subject"] and sched["id"] in m["body"]], 60)
    assert "skipped_late" in mails[0]["subject"]
    triggers = user.get(f"/api/schedules/{sched['id']}").json()["triggers"]
    assert triggers[0]["outcome"] == "skipped_late"
