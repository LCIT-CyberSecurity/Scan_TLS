"""Scheduler loop: turns due schedules into queued runs, exactly once per occurrence.

Guarantees:
- exactly-once per (schedule, due_at): UNIQUE(schedule_id, due_at) in schedule_triggers, plus
  `FOR UPDATE SKIP LOCKED` on the schedule row;
- no overlap: an occurrence is recorded `skipped_overlap` if a run of the same schedule is active
  (or the engine deduplicates it onto an equivalent run);
- downtime: occurrences missed by more than the grace period are recorded `skipped_late` (not replayed
  in a burst) and the schedule moves on to its next future occurrence.
"""
from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.config import Settings, get_settings
from tls_scan_app.database import make_engine, make_session_factory
from tls_scan_app.models import ScanDefinition, ScanRun, ScanSchedule, ScheduleTrigger
from tls_scan_app.models.scan import ACTIVE_STATUSES
from tls_scan_app.services import audit, runs
from tls_scan_app.services.logs import configure_logging
from tls_scan_app.services.planner import PlanError, build_snapshot, fingerprint
from tls_scan_app.services.schedule_calc import next_after

logger = logging.getLogger("tls_scan_app.scheduler")
LATE_GRACE = timedelta(minutes=15)


def tick(db: DbSession, settings: Settings, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    fired = 0
    due = db.execute(
        select(ScanSchedule).where(ScanSchedule.active.is_(True), ScanSchedule.next_run_at <= now)
        .with_for_update(skip_locked=True)
    ).scalars().all()
    for schedule in due:
        due_at = schedule.next_run_at
        outcome, reason, run_id = _fire(db, settings, schedule, due_at, now)
        try:
            with db.begin_nested():
                db.add(ScheduleTrigger(schedule_id=schedule.id, due_at=due_at, outcome=outcome, reason=reason, run_id=run_id))
                db.flush()
        except IntegrityError:
            pass  # already handled by another scheduler instance
        schedule.last_run_at = now if outcome == "triggered" else schedule.last_run_at
        nxt = next_after(schedule.kind, schedule.params, schedule.timezone, now)
        schedule.next_run_at = nxt
        if nxt is None:
            schedule.active = False  # one-shot done
        fired += outcome == "triggered"
        db.commit()
    return fired


def _fire(db, settings, schedule, due_at, now):
    if now - due_at > LATE_GRACE:
        return "skipped_late", f"missed by {now - due_at} (service down or delayed)", None
    active = db.execute(select(ScanRun.id).where(ScanRun.schedule_id == schedule.id, ScanRun.status.in_(ACTIVE_STATUSES))).first()
    if active:
        return "skipped_overlap", "previous occurrence still active", None
    definition = db.get(ScanDefinition, schedule.definition_id)
    try:
        snapshot = build_snapshot(db, definition, settings.max_targets_per_scan)  # latest published versions
    except PlanError as error:
        audit.record(db, "schedule.error", actor_label="scheduler", resource_type="schedule", resource_id=schedule.id,
                     outcome="failure", detail={"error": str(error)})
        return "error", str(error), None
    run, dedup = runs.create_run(db, snapshot, fingerprint(snapshot), definition=definition, user=None, schedule_id=schedule.id)
    owner = schedule.owner_id
    if owner:
        runs.add_requester(db, run.id, owner)
    return ("skipped_overlap", "merged into an equivalent active run", run.id) if dedup else ("triggered", "", run.id)


def main() -> None:
    settings = get_settings()
    configure_logging(settings, "scheduler")
    factory = make_session_factory(make_engine(settings.database_url))
    logger.info("scheduler started")
    while True:
        try:
            with factory() as db:
                tick(db, settings)
        except Exception:  # noqa: BLE001
            logger.exception("scheduler tick failed")
        time.sleep(settings.scheduler_poll_seconds)


if __name__ == "__main__":
    main()
