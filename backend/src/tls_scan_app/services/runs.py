"""Scan run lifecycle: creation with de-duplication, queue claiming, cancellation, result persistence."""
from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import RunEndpoint, RunFinding, ScanDefinition, ScanRun, ScanRunRequester, User
from tls_scan_app.models.scan import ACTIVE_STATUSES, CANCELLED, COMPLETED, EXPIRED, FAILED, PARTIAL, QUEUED, RUNNING
from tls_scan_app.services import audit

STALE_HEARTBEAT_SECONDS = 120
CLAIM_LOCK_KEY = 727301  # pg advisory lock serialising queue claims (global concurrency cap)


def add_requester(db: DbSession, run_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Idempotent and race-free: the same user may attach to the same run from several simultaneous requests."""
    db.execute(pg_insert(ScanRunRequester).values(run_id=run_id, user_id=user_id).on_conflict_do_nothing())


def create_run(
    db: DbSession,
    snapshot: dict[str, Any],
    fingerprint: str,
    *,
    definition: ScanDefinition | None,
    user: User | None,
    schedule_id: uuid.UUID | None = None,
) -> tuple[ScanRun, bool]:
    """Queue a run, or attach to an equivalent active one. Returns (run, deduplicated).

    The partial unique index on (fingerprint) for active statuses makes this safe under
    concurrency: of two simultaneous requests one INSERT fails and falls back to attaching.
    """
    existing = _active_run(db, fingerprint)
    if existing is None:
        run = ScanRun(
            id=uuid.uuid4(),
            definition_id=definition.id if definition else None,
            schedule_id=schedule_id,
            name=snapshot["definition"]["name"],
            initiated_by=user.id if user else None,
            status=QUEUED,
            fingerprint=fingerprint,
            config_snapshot=snapshot,
            policy_versions=[{"name": p["name"], "version": p["version"], "version_id": p["version_id"]} for p in snapshot["policies"]],
        )
        try:
            with db.begin_nested():
                db.add(run)
                db.flush()
            existing = None
        except IntegrityError:
            existing = _active_run(db, fingerprint)
            if existing is None:
                raise
    if existing is None:
        if user:
            add_requester(db, run.id, user.id)
        audit.record(db, "scan.queued", actor=user, actor_label="scheduler" if not user else "",
                     resource_type="scan_run", resource_id=run.id, detail={"definition": snapshot["definition"]["name"]})
        db.commit()
        return run, False
    if user:
        add_requester(db, existing.id, user.id)
    audit.record(db, "scan.deduplicated", actor=user, actor_label="scheduler" if not user else "",
                 resource_type="scan_run", resource_id=existing.id)
    db.commit()
    return existing, True


def _active_run(db: DbSession, fingerprint: str) -> ScanRun | None:
    return db.execute(
        select(ScanRun).where(ScanRun.fingerprint == fingerprint, ScanRun.status.in_(ACTIVE_STATUSES))
    ).scalars().first()


def claim_next(db: DbSession, worker_id: str, max_concurrent: int) -> ScanRun | None:
    """Atomically move the oldest queued run to running, honouring the global concurrency cap."""
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CLAIM_LOCK_KEY})
    running = db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.status == RUNNING))
    if running >= max_concurrent:
        db.rollback()
        return None
    run = db.execute(
        select(ScanRun).where(ScanRun.status == QUEUED, ScanRun.cancel_requested.is_(False))
        .order_by(ScanRun.queued_at).limit(1).with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if run is None:
        db.rollback()
        return None
    now = datetime.now(UTC)
    run.status, run.worker_id, run.started_at, run.heartbeat_at, run.phase = RUNNING, worker_id, now, now, "starting"
    db.commit()
    return run


def recover_stale(db: DbSession) -> int:
    """Runs whose worker disappeared (crash / restart) are failed explicitly, never left 'running'."""
    cutoff = datetime.now(UTC) - timedelta(seconds=STALE_HEARTBEAT_SECONDS)
    stale = db.execute(select(ScanRun).where(ScanRun.status == RUNNING, ScanRun.heartbeat_at < cutoff)).scalars().all()
    for run in stale:
        run.status, run.finished_at = FAILED, datetime.now(UTC)
        run.error = "worker lost (no heartbeat); the run was interrupted, relaunch it"
        audit.record(db, "scan.failed", actor_label="worker", resource_type="scan_run", resource_id=run.id, outcome="failure",
                     detail={"reason": "worker_lost"})
    # queued runs flagged for cancellation are finalised without ever starting
    for run in db.execute(select(ScanRun).where(ScanRun.status == QUEUED, ScanRun.cancel_requested.is_(True))).scalars():
        run.status, run.finished_at = CANCELLED, datetime.now(UTC)
    db.commit()
    return len(stale)


def request_cancel(db: DbSession, run: ScanRun, actor: User) -> None:
    run.cancel_requested = True
    if run.status == QUEUED:
        run.status, run.finished_at = CANCELLED, datetime.now(UTC)
    audit.record(db, "scan.cancel_requested", actor=actor, resource_type="scan_run", resource_id=run.id)
    db.commit()


def final_status(outcome: dict[str, Any], cancelled: bool, timed_out: bool) -> str:
    if timed_out:
        return EXPIRED
    if cancelled:
        return CANCELLED
    model = outcome.get("report_model") or {}
    endpoints = model.get("endpoints", [])
    if outcome.get("skipped_hosts") or any(e.get("errors") for e in endpoints):
        return PARTIAL
    return COMPLETED


def persist_results(db: DbSession, run: ScanRun, outcome: dict[str, Any], status: str, storage_root: Path) -> None:
    model = outcome.get("report_model") or {}
    for endpoint in model.get("endpoints", []):
        cert = endpoint.get("certificate") or {}
        db.add(RunEndpoint(
            run_id=run.id, endpoint_id=endpoint["endpoint_id"], hostname=endpoint.get("hostname", ""),
            ip_address=endpoint.get("ip_address", ""), port=str(endpoint.get("port", "")), grade=endpoint.get("overall_grade", ""),
            compliance_status=endpoint.get("compliance_status", ""), highest_severity=endpoint.get("highest_severity", ""),
            supported_tls_versions=list(endpoint.get("supported_tls_versions", [])),
            cipher_suites=[c.get("name") for c in endpoint.get("cipher_suites", [])],
            certificate={k: cert.get(k) for k in ("subject", "issuer", "valid_until", "remaining_days", "key_type", "key_size",
                                                   "signature_algorithm", "fingerprint", "trust_status", "chain_validation_status",
                                                   "revocation_status", "self_signed", "status")},
            errors=list(endpoint.get("errors", [])), untested_checks=list(endpoint.get("untested_checks", [])),
        ))
    for finding in model.get("findings", []):
        db.add(RunFinding(
            run_id=run.id, finding_id=finding["finding_id"], title=finding.get("title", ""), category=finding.get("category", ""),
            severity=finding.get("severity", ""), status=finding.get("status", ""), evidence=finding.get("evidence", ""),
            remediation=finding.get("remediation", ""), affected_endpoint_ids=list(finding.get("affected_endpoint_ids", [])),
        ))
    files = []
    for path_str in outcome.get("written_files", []):
        path = Path(path_str)
        if path.is_file():
            files.append({"format": _format_of(path), "path": str(path.relative_to(storage_root)),
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
    run.report_files = files
    run.summary = model.get("statistics")
    run.scanned_hosts = outcome.get("scanned_hosts", [])
    run.skipped_hosts = outcome.get("skipped_hosts", [])
    run.status = status
    run.finished_at = datetime.now(UTC)
    run.duration_seconds = outcome.get("duration_seconds")
    run.phase = "done"
    audit.record(db, f"scan.{status}", actor_label="worker", resource_type="scan_run", resource_id=run.id)


def _format_of(path: Path) -> str:
    name = path.name
    if name.endswith(".cbom.json"):
        return "cbom"
    if name.endswith("_findings.csv"):
        return "findings_csv"
    if name.endswith(".metadata.json"):
        return "metadata"
    return {".html": "html", ".md": "md", ".csv": "csv"}.get(path.suffix, path.suffix.lstrip("."))
