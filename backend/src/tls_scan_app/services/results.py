"""Read-side helpers shared by the internal `/api/scan-runs` routes and the read-only `/api/results` API."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Select, or_, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.common import classification_of, ids_matching_filter
from tls_scan_app.models import RunEndpoint, RunFinding, ScanRun, ScanRunRequester, Target, User


def filter_runs(stmt: Select, db: DbSession, *, mine_of: User | None = None, requested_by: uuid.UUID | None = None, status: str | None = None,
                definition_id: uuid.UUID | None = None, tag: str | None = None, si: uuid.UUID | None = None,
                started_after: datetime | None = None, started_before: datetime | None = None,
                finished_after: datetime | None = None, finished_before: datetime | None = None) -> Select:
    """Filters of the runs list (WebUI and API). `mine_of` restricts to runs initiated by / attached to that user."""
    def requested(user_id: uuid.UUID):
        return or_(ScanRun.initiated_by == user_id, ScanRun.id.in_(select(ScanRunRequester.run_id).where(ScanRunRequester.user_id == user_id)))

    if mine_of is not None:
        stmt = stmt.where(requested(mine_of.id))
    if requested_by is not None:
        stmt = stmt.where(requested(requested_by))
    if status:
        stmt = stmt.where(ScanRun.status == status)
    if definition_id:
        stmt = stmt.where(ScanRun.definition_id == definition_id)
    allowed = ids_matching_filter(db, "definition", tag, si)
    if allowed is not None:
        stmt = stmt.where(ScanRun.definition_id.in_(allowed))
    for column, op, value in ((ScanRun.started_at, "ge", started_after), (ScanRun.started_at, "le", started_before),
                              (ScanRun.finished_at, "ge", finished_after), (ScanRun.finished_at, "le", finished_before)):
        if value is not None:
            stmt = stmt.where(column >= value if op == "ge" else column <= value)
    return stmt


def endpoint_tags(db: DbSession, endpoints: list[RunEndpoint]) -> dict[str, set[str]]:
    """Tags are read live from the matching target(s): same value as the endpoint's hostname or address."""
    values = {v for e in endpoints for v in (e.hostname, e.ip_address) if v}
    by_value: dict[str, set[str]] = {}
    if values:
        matched = db.execute(select(Target.id, Target.value).where(Target.value.in_(values))).all()
        classes = classification_of(db, "target", [tid for tid, _ in matched])
        for tid, value in matched:
            by_value.setdefault(value, set()).update(classes[tid]["tags"])
    return by_value


def endpoint_out(e: RunEndpoint, by_value: dict[str, set[str]]) -> dict[str, Any]:
    return {"endpoint_id": e.endpoint_id, "hostname": e.hostname, "ip_address": e.ip_address, "port": e.port, "grade": e.grade,
            "compliance_status": e.compliance_status, "highest_severity": e.highest_severity, "tls_versions": e.supported_tls_versions,
            "certificate": e.certificate, "errors": e.errors, "untested_checks": e.untested_checks,
            "tls_checks": e.tls_checks or [],
            "tags": sorted(by_value.get(e.hostname, set()) | by_value.get(e.ip_address, set()))}


def finding_out(f: RunFinding) -> dict[str, Any]:
    return {"finding_id": f.finding_id, "title": f.title, "severity": f.severity, "status": f.status, "category": f.category,
            "evidence": f.evidence, "remediation": f.remediation, "affected_endpoint_ids": f.affected_endpoint_ids}
