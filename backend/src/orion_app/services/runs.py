"""Scan run lifecycle: creation with de-duplication, queue claiming, cancellation, result persistence."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from orion_app.models import (
    RunEndpoint,
    RunFinding,
    RunIpsecObservation,
    RunSshObservation,
    ScanDefinition,
    ScanRun,
    ScanRunRequester,
    User,
)
from orion_app.models.scan import (
    ACTIVE_STATUSES,
    CANCELLED,
    COMPLETED,
    EXPIRED,
    FAILED,
    PARTIAL,
    QUEUED,
    RUNNING,
)
from orion_app.services import (
    audit,
    contextual_risk,
    report_addendum,
    report_branding,
)
from orion_app.services.mail_security import attach_smtp_observations

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
            policy_versions=[{"name": p["name"], "version": p["version"], "version_id": p["version_id"]}
                             for p in [*snapshot.get("policies", []), *((snapshot.get("ipsec") or {}).get("policies", [])), *((snapshot.get("ssh") or {}).get("policies", []))]],
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
    risk_rows = contextual_risk.report_rows(model, run.config_snapshot or {})
    risk_by_finding: dict[str, dict[str, Any]] = {}
    for row in risk_rows:
        risk_by_finding.setdefault(row["finding_id"], {})[row["endpoint_id"]] = {
            key: value for key, value in contextual_risk.assess(row["intrinsic_severity"],
                    contextual_risk.exposure_for_endpoint(next((item for item in model.get("endpoints", []) if item.get("endpoint_id") == row["endpoint_id"]), {}), run.config_snapshot or {})).items()}
    for observation in outcome.get("ipsec_observations", []):
        db.add(RunIpsecObservation(
            run_id=run.id, target=observation["target"], port=int(observation["port"]), status=observation["status"],
            ike_version=observation.get("ike_version", ""), exchange=observation.get("exchange", ""),
            proposal=observation.get("proposal") or {}, verdict=observation.get("verdict", "indeterminate"),
            evidence=observation.get("evidence") or {},
        ))
    for observation in outcome.get("ssh_observations", []):
        db.add(RunSshObservation(
            run_id=run.id, target=observation["target"], port=int(observation["port"]), status=observation["status"],
            verdict=observation.get("verdict", "indeterminate"), banner=observation.get("banner", ""),
            algorithms=observation.get("algorithms") or {}, host_keys=observation.get("host_keys") or [],
            fingerprints=observation.get("fingerprints") or {}, evidence=observation.get("evidence") or {},
        ))
    for endpoint in model.get("endpoints", []):
        cert = endpoint.get("certificate") or {}
        exposure = contextual_risk.exposure_for_endpoint(endpoint, run.config_snapshot or {}) or {
            "protocol": "tls", "state": "unknown", "validated": False, "reason": "no endpoint-specific evidence was recorded"}
        risk_summary = {"matrix_version": contextual_risk.MATRIX_VERSION, "exposure": exposure,
                        "crypto_grade": endpoint.get("overall_grade", "")}
        db.add(RunEndpoint(
            run_id=run.id, endpoint_id=endpoint["endpoint_id"], hostname=endpoint.get("hostname", ""),
            ip_address=endpoint.get("ip_address", ""), port=str(endpoint.get("port", "")), grade=endpoint.get("overall_grade", ""),
            compliance_status=endpoint.get("compliance_status", ""), highest_severity=endpoint.get("highest_severity", ""),
            supported_tls_versions=list(endpoint.get("supported_tls_versions", [])),
            cipher_suites=[c.get("name") for c in endpoint.get("cipher_suites", [])],
            certificate={k: cert.get(k) for k in ("subject", "issuer", "valid_until", "remaining_days", "key_type", "key_size",
                                                   "signature_algorithm", "fingerprint", "trust_status", "chain_validation_status",
                                                   "revocation_status", "self_signed", "status", "trust_classification", "trusted_by",
                                                   "trust_anchor", "trust_store_results", "hostname_validation_status",
                                                   "san_validation_status", "ocsp_status", "crl_status")},
            errors=list(endpoint.get("errors", [])), untested_checks=list(endpoint.get("untested_checks", [])),
            tls_checks=list(endpoint.get("complementary_checks", [])),
            exposure_snapshot=exposure, contextual_risk=risk_summary,
        ))
    for finding in model.get("findings", []):
        db.add(RunFinding(
            run_id=run.id, finding_id=finding["finding_id"], title=finding.get("title", ""), category=finding.get("category", ""),
            severity=finding.get("severity", ""), status=finding.get("status", ""), evidence=finding.get("evidence", ""),
            remediation=finding.get("remediation", ""), affected_endpoint_ids=list(finding.get("affected_endpoint_ids", [])),
            contextual_risk_by_endpoint=risk_by_finding.get(finding.get("finding_id", ""), {}),
        ))
    files = []
    branding = run.config_snapshot.get("branding")
    # what the previous scans bring to this report (evolution, renewals, trend, scope): needs this run's rows and end state
    run.scanned_hosts, run.skipped_hosts = outcome.get("scanned_hosts", []), outcome.get("skipped_hosts", [])
    run.mail_security_results = outcome.get("mail_security_results") or None
    run.service_observations = outcome.get("service_observations") or None
    run.quic_observations = outcome.get("quic_observations") or None
    if run.mail_security_results:
        attach_smtp_observations(run.mail_security_results, model.get("endpoints", []))
    run.summary, run.status, run.finished_at = model.get("statistics"), status, datetime.now(UTC)
    db.flush()
    if (run.config_snapshot or {}).get("control_type") in {"ipsec", "ssh"}:
        addendum = None  # TLS-only evolution/finding addenda must not be mixed into IKE reports.
    else:
        try:
            addendum = report_addendum.build(db, run)
        except Exception:  # a report extra must never make a finished scan fail
            addendum = None
    for path_str in outcome.get("written_files", []):
        path = Path(path_str)
        if path.suffix == ".html":
            report_branding.apply_to_html(path, branding)  # before hashing: the stored SHA-256 is of the delivered file
            if addendum and not path.name.startswith("ipsec-results."):
                report_addendum.apply_to_html(path, addendum)
            if not path.name.startswith(("ipsec-results.", "ssh-results.")):
                contextual_risk.append_html(path, risk_rows)
        elif path.suffix == ".md" and addendum:
            report_addendum.apply_to_markdown(path, addendum)
        if path.suffix == ".md" and not path.name.startswith(("ipsec-results.", "ssh-results.")):
            contextual_risk.append_markdown(path, risk_rows)
        if path.is_file():
            files.append({"format": _format_of(path, run), "path": str(path.relative_to(storage_root)),
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
    if risk_rows and "csv" in (run.config_snapshot.get("export_formats") or []):
        contextual_path = storage_root / "reports" / str(run.id) / "contextual-risk.csv"
        contextual_risk.write_csv(contextual_path, risk_rows)
        files.append({"format": "contextual_risk_csv", "path": str(contextual_path.relative_to(storage_root)),
                      "sha256": hashlib.sha256(contextual_path.read_bytes()).hexdigest(), "size": contextual_path.stat().st_size})
    if run.mail_security_results and "csv" in (run.config_snapshot.get("export_formats") or []):
        import csv
        import io
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=("domain", "check", "status", "message", "records", "details", "provenance"))
        writer.writeheader()
        for domain in run.mail_security_results:
            for check in domain.get("checks", []):
                writer.writerow({"domain": domain.get("domain", ""), **check,
                                 "records": " | ".join(check.get("records") or []),
                                 "details": json.dumps(check.get("details") or {}, sort_keys=True)})
            for observation in domain.get("smtp_starttls", []):
                writer.writerow({"domain": domain.get("domain", ""), "check": "smtp_starttls", "status": observation.get("status"),
                                 "message": observation.get("message", ""), "records": "", "details": json.dumps(observation, sort_keys=True),
                                 "provenance": "existing scan endpoint observation"})
        csv_path = storage_root / "reports" / str(run.id) / "mail-security.csv"
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.write_text(stream.getvalue(), encoding="utf-8")
        files.append({"format": "mail_security_csv", "path": str(csv_path.relative_to(storage_root)),
                      "sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(), "size": csv_path.stat().st_size})
    run.report_files = files
    run.summary = model.get("statistics")
    run.scanned_hosts = outcome.get("scanned_hosts", [])
    run.skipped_hosts = outcome.get("skipped_hosts", [])
    run.status = status
    run.finished_at = datetime.now(UTC)
    run.duration_seconds = outcome.get("duration_seconds")
    run.phase = "done"
    audit.record(db, f"scan.{status}", actor_label="worker", resource_type="scan_run", resource_id=run.id)


def _format_of(path: Path, run: ScanRun | None = None) -> str:
    controls = (run.config_snapshot or {}).get("enabled_controls", []) if run else []
    if path.name.startswith("ipsec-results.") and "tls" in controls and "ipsec" in controls:
        return f"ipsec_{path.suffix.lstrip('.')}"
    if path.name.startswith("ssh-results."):
        return f"ssh_{path.suffix.lstrip('.')}"
    name = path.name
    if name.endswith(".cbom.json"):
        return "cbom"
    if name.endswith("_findings.csv"):
        return "findings_csv"
    if name == "mail-security.csv":
        return "mail_security_csv"
    if name == "service-identification.csv":
        return "service_csv"
    if name == "quic-results.csv":
        return "quic_csv"
    if name.endswith(".metadata.json"):
        return "metadata"
    return {".html": "html", ".md": "md", ".csv": "csv"}.get(path.suffix, path.suffix.lstrip("."))
