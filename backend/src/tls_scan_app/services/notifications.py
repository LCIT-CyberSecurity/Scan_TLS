"""Notification queue: enqueue on run completion; delivery (SMTP) is done by the worker loop."""
from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import Notification, ScanRun, ScanRunRequester

EVENT_BY_STATUS = {"completed": "scan_completed", "partial": "scan_completed", "failed": "scan_failed",
                   "cancelled": "scan_cancelled", "expired": "scan_failed"}


def notify_run_finished(db: DbSession, run: ScanRun) -> None:
    event = EVENT_BY_STATUS.get(run.status)
    if event is None:
        return
    summary = run.summary or {}
    body = (
        f"Scan: {run.name}\nStatus: {run.status}\n"
        f"Endpoints: {summary.get('total_endpoints', 0)} (non compliant: {summary.get('non_compliant_endpoints', 0)})\n"
        f"Critical findings: {summary.get('critical_findings', 0)}\nRun: /scans/{run.id}\n"
    )
    for requester in db.query(ScanRunRequester).filter_by(run_id=run.id):
        db.add(Notification(user_id=requester.user_id, event=event, run_id=run.id,
                            subject=f"[TLS Scan] {run.name}: {run.status}", body=body))
