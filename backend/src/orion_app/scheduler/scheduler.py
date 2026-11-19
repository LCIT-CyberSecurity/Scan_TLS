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

from orion_app.config import Settings, get_settings
from orion_app.database import make_engine, make_session_factory
from orion_app.models import (
    DnsDiscovery,
    Role,
    ScanDefinition,
    ScanRun,
    ScanSchedule,
    ScheduleTrigger,
    User,
)
from orion_app.models.scan import ACTIVE_STATUSES
from orion_app.models.user import role_at_least
from orion_app.services import audit, runs
from orion_app.services.logs import configure_logging
from orion_app.services.planner import PlanError, build_snapshot, fingerprint
from orion_app.services.schedule_calc import next_after

logger = logging.getLogger("orion_app.scheduler")
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
        outcome, reason, run_id, discovery_id = _fire(db, settings, schedule, due_at, now)
        try:
            with db.begin_nested():
                db.add(ScheduleTrigger(schedule_id=schedule.id, due_at=due_at, outcome=outcome, reason=reason,
                                       run_id=run_id, discovery_id=discovery_id))
                db.flush()
        except IntegrityError:
            pass  # already handled by another scheduler instance
        schedule.last_run_at = now if outcome == "triggered" else schedule.last_run_at
        nxt = next_after(schedule.kind, schedule.params, schedule.timezone, now)
        schedule.next_run_at = nxt
        if nxt is None:
            schedule.active = False  # one-shot done
        if outcome in ("skipped_late", "error"):
            from orion_app.services.notifications import notify_schedule_problem

            notify_schedule_problem(db, schedule, outcome, reason)
        fired += outcome == "triggered"
        db.commit()
    return fired


def _fire(db, settings, schedule, due_at, now):
    if now - due_at > LATE_GRACE:
        return "skipped_late", f"missed by {now - due_at} (service down or delayed)", None, None
    if schedule.task_type == "dns_discovery":
        return _fire_dns(db, schedule)
    active = db.execute(select(ScanRun.id).where(ScanRun.schedule_id == schedule.id, ScanRun.status.in_(ACTIVE_STATUSES))).first()
    if active:
        return "skipped_overlap", "previous occurrence still active", None, None
    definition = db.get(ScanDefinition, schedule.definition_id)
    if definition is None:
        return "error", "scan definition was deleted", None, None
    try:
        snapshot = build_snapshot(db, definition, settings.max_targets_per_scan)  # latest published versions
    except PlanError as error:
        audit.record(db, "schedule.error", actor_label="scheduler", resource_type="schedule", resource_id=schedule.id,
                     outcome="failure", detail={"error": str(error)})
        return "error", str(error), None, None
    run, dedup = runs.create_run(db, snapshot, fingerprint(snapshot), definition=definition, user=None, schedule_id=schedule.id)
    owner = schedule.owner_id
    if owner:
        runs.add_requester(db, run.id, owner)
    return ("skipped_overlap", "merged into an equivalent active run", run.id, None) if dedup else ("triggered", "", run.id, None)


def _fire_dns(db, schedule):
    config = schedule.task_config or {}
    if not config.get("authorized") or not config.get("domain") or not isinstance(config.get("options"), dict):
        return "error", "scheduled discovery authorization or configuration is missing", None, None
    owner = db.get(User, schedule.owner_id) if schedule.owner_id else None
    if owner is None or not owner.active or not role_at_least(owner.role, Role.OPERATOR):
        return "error", "schedule owner is missing, inactive, or no longer permitted to run discoveries", None, None
    monitor_id = config["options"].get("lookalike_monitor_id")
    if monitor_id:
        from orion_app.models import DnsLookalikeMonitor

        try:
            monitor = db.get(DnsLookalikeMonitor, monitor_id)
        except (TypeError, ValueError):
            monitor = None
        if (monitor is None or monitor.deleted_at is not None or not monitor.enabled
                or monitor.owner_id != owner.id or owner.role != Role.ADMIN):
            return "error", "lookalike monitor is missing, disabled, or no longer authorised", None, None
        if monitor.domain != config["domain"]:
            return "error", "lookalike schedule domain no longer matches its monitor", None, None
        busy = db.scalar(select(DnsDiscovery.id).where(DnsDiscovery.requested_by == owner.id,
                                                       DnsDiscovery.status.in_(("queued", "running"))).limit(1))
        if busy:
            return "skipped_overlap", "a previous DNS discovery for this owner is still active", None, None
        discovery = DnsDiscovery(domain=monitor.domain, requested_by=owner.id,
                                 options={"lookalike_monitor_id": str(monitor.id)})
        db.add(discovery)
        db.flush()
        audit.record(db, "dns.lookalike.scheduled", actor_label="scheduler", resource_type="dns_discovery",
                     resource_id=discovery.id, detail={"domain": monitor.domain, "schedule_id": str(schedule.id),
                                                       "monitor_id": str(monitor.id)})
        return "triggered", "", None, discovery.id
    busy = db.scalar(select(DnsDiscovery.id).where(DnsDiscovery.requested_by == owner.id,
                                                   DnsDiscovery.status.in_(("queued", "running"))).limit(1))
    if busy:
        return "skipped_overlap", "a previous DNS discovery for this owner is still active", None, None
    try:
        # Revalidate the saved request against current administrator scope and limits at every run.
        from orion_app.api.catalog import DiscoverBody, _discovery_options
        from orion_app.services.dns_discovery.policy import load_settings

        body = DiscoverBody(domain=config["domain"], authorized=True, **config["options"])
        from orion_app.services.dns_discovery.policy import normalize_domain

        domain = normalize_domain(body.domain)
        options = _discovery_options(body, load_settings(db))
    except (TypeError, ValueError) as error:
        return "error", f"DNS discovery configuration is no longer valid: {error}", None, None
    discovery = DnsDiscovery(domain=domain, requested_by=owner.id, options=options)
    db.add(discovery)
    db.flush()
    audit.record(db, "target.discover", actor_label="scheduler", resource_type="dns_discovery", resource_id=discovery.id,
                 detail={"domain": domain, "mode": options["mode"], "methods": options["methods"],
                         "resolver": options.get("dns_server") or "system", "scheduled": True, "schedule_id": str(schedule.id)})
    return "triggered", "", None, discovery.id


def main() -> None:
    settings = get_settings()
    configure_logging(settings, "scheduler")
    factory = make_session_factory(make_engine(settings.database_url, settings.database_password_file))
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
