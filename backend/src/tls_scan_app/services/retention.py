"""Retention: purge old runs (and their report files) and old audit events, per admin settings."""
from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.models import AuditEvent, ScanRun, SystemSetting
from tls_scan_app.models.scan import FINAL_STATUSES
from tls_scan_app.services import audit

DEFAULTS = {"reports_days": 365, "runs_days": 730, "audit_days": 1095}


def purge(db: DbSession, storage_root: Path, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(UTC)
    row = db.get(SystemSetting, "retention")
    cfg = {**DEFAULTS, **(row.value if row else {})}
    counts = {"report_files": 0, "runs": 0, "audit": 0}
    for run in db.execute(select(ScanRun).where(ScanRun.status.in_(FINAL_STATUSES), ScanRun.finished_at < now - timedelta(days=cfg["reports_days"]),
                                                  ScanRun.report_files.is_not(None))).scalars():
        if run.report_files:
            parts = Path(run.report_files[0]["path"]).parts
            if len(parts) >= 2 and parts[0] == "reports":
                shutil.rmtree((storage_root / parts[0] / parts[1]).resolve(), ignore_errors=True)
            run.report_files = []
            counts["report_files"] += 1
    old_runs = db.execute(select(ScanRun).where(ScanRun.status.in_(FINAL_STATUSES), ScanRun.finished_at < now - timedelta(days=cfg["runs_days"]))).scalars().all()
    for run in old_runs:
        db.delete(run)
    counts["runs"] = len(old_runs)
    counts["audit"] = db.execute(delete(AuditEvent).where(AuditEvent.created_at < now - timedelta(days=cfg["audit_days"]))).rowcount
    if any(counts.values()):
        audit.record(db, "retention.purge", actor_label="system", detail=counts)
    db.commit()
    return counts
