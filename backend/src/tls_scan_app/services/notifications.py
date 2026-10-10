"""Notification queue: enqueue on run completion; delivery (SMTP) is done by the worker loop."""
from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import Notification, RunEndpoint, ScanRun, ScanRunRequester, User

DEFAULT_EVENTS = {"scan_completed", "scan_failed", "scan_cancelled", "new_noncompliance", "certificate_expiring", "schedule_problem"}
EXTRA_EVENTS = {"new_noncompliance", "certificate_expiring", "schedule_problem"}
ALL_EVENTS = DEFAULT_EVENTS | EXTRA_EVENTS

EVENT_BY_STATUS = {"completed": "scan_completed", "partial": "scan_completed", "failed": "scan_failed",
                   "cancelled": "scan_cancelled", "expired": "scan_failed"}


def _recipients(db: DbSession, run: ScanRun, event: str) -> list[User]:
    out = []
    ids = [r.user_id for r in db.query(ScanRunRequester).filter_by(run_id=run.id)]
    for user_id in ids:
        user = db.get(User, user_id)
        wanted = set(user.notify_events.split(",")) if user and user.notify_events is not None else DEFAULT_EVENTS
        if user and user.active and event in wanted:
            out.append(user)
    return out


def _queue(db: DbSession, run: ScanRun, event: str, subject: str, body: str) -> None:
    for user in _recipients(db, run, event):
        db.add(Notification(user_id=user.id, event=event, run_id=run.id, subject=subject, body=body))


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
    _queue(db, run, event, f"[TLS Scan] {run.name}: {run.status}", body)
    if run.status not in ("completed", "partial"):
        return
    # Certificates already expired or expiring within the profile's warning window (per endpoint: the
    # engine's single "certificate status" can be masked by another status such as self-signed).
    window = ((run.config_snapshot.get("checks") or {}).get("certificate") or {}).get("expires_within_days", 30)
    expiring = [(e.endpoint_id, e.certificate.get("remaining_days")) for e in db.query(RunEndpoint).filter_by(run_id=run.id)
                if isinstance(e.certificate.get("remaining_days"), int) and e.certificate["remaining_days"] <= window]
    if expiring:
        lines = "\n".join(f"- {eid}: {'EXPIRED' if days < 0 else f'{days} day(s) left'}" for eid, days in expiring[:15])
        _queue(db, run, "certificate_expiring", f"[TLS Scan] {run.name}: certificates expiring",
               f"Scan: {run.name}\nCertificates expired or expiring within {window} days: {len(expiring)}\n{lines}\nRun: /scans/{run.id}\n")
    # New non-compliance compared with the previous comparable run.
    from tls_scan_app.services import comparison

    previous = comparison.previous_comparable(db, run)
    if previous is not None:
        result = comparison.compare_runs(db, previous, run)
        if result["new"]:
            lines = "\n".join(f"- [{f['severity']}] {f['title']}: {', '.join(f['affected'][:3])}" for f in result["new"][:10])
            _queue(db, run, "new_noncompliance", f"[TLS Scan] {run.name}: {len(result['new'])} new non-compliance(s)",
                   f"Scan: {run.name}\nNew since the previous scan:\n{lines}\nRun: /scans/{run.id}\n")


def notify_schedule_problem(db: DbSession, schedule, outcome: str, reason: str) -> None:
    """Tell the schedule's owner that an occurrence was missed or failed to start."""
    user = db.get(User, schedule.owner_id) if schedule.owner_id else None
    if user is None or not user.active:
        return
    wanted = set(user.notify_events.split(",")) if user.notify_events is not None else DEFAULT_EVENTS
    if "schedule_problem" in wanted:
        db.add(Notification(user_id=user.id, event="schedule_problem", subject=f"[TLS Scan] schedule problem: {outcome}",
                            body=f"A scheduled scan could not run as planned.\nOutcome: {outcome}\nReason: {reason}\nSchedule: {schedule.id}\n"))
