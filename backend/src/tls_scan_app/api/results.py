"""Read-only results API (V1): consult scans, TLS endpoints, findings, comparisons and reports.

GET only, authenticated by the existing session, with the existing RBAC. Business logic lives in the existing
services (`services.results`, `services.comparison`) and in the internal report download, which is reused as is.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession, defer

from tls_scan_app.api import runs as internal
from tls_scan_app.api.common import classification_of, get_or_404
from tls_scan_app.api.results_schemas import (
    Comparison, EndpointPage, ErrorBody, FindingPage, ReportFormat, ReportInfo, ReportList, Run, RunDetail, RunPage, RunStatus, Severity,
)
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import Role, RunEndpoint, RunFinding, ScanDefinition, ScanProfile, ScanRun, User
from tls_scan_app.services import comparison, results

router = APIRouter(prefix="/api/results", tags=["Results"])
auditor = require_role(Role.AUDITOR)
user_only = require_role(Role.USER)

ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorBody, "description": "Not authenticated (no session, expired or revoked)."},
    403: {"model": ErrorBody, "description": "Insufficient role, or the user must change their password first."},
    404: {"model": ErrorBody, "description": "Scan, comparable scan or report not found."},
}
Limit = Annotated[int, Query(ge=1, le=200, description="Page size (1-200).")]
Offset = Annotated[int, Query(ge=0, le=1_000_000, description="Number of items to skip.")]


def _blank(data: dict) -> dict:
    """Empty strings stored for 'not collected' are exposed as null, never as a misleading value."""
    return {k: (None if v == "" else v) for k, v in data.items()}


def _endpoint(e: RunEndpoint, tags: dict[str, set[str]]) -> dict:
    out = _blank(results.endpoint_out(e, tags))
    out["port"] = int(e.port) if e.port.isdigit() else None
    out["cipher_suites"] = [c for c in (e.cipher_suites or []) if c]
    cert = {k: v for k, v in (e.certificate or {}).items() if v is not None}
    out["certificate"] = _blank(cert) if cert else None
    return out


def _reports(r: ScanRun, root: Path) -> list[dict]:
    root = root.resolve()
    out = []
    for f in r.report_files or []:
        path = (root / f["path"]).resolve()
        out.append({"format": f["format"], "size": f.get("size"), "sha256": f["sha256"],
                    "content_type": internal.MEDIA.get(f["format"], "application/octet-stream"),
                    "available": path.is_relative_to(root) and path.is_file(), "download_url": f"/api/results/{r.id}/reports/{f['format']}"})
    return out


def _run_items(db: DbSession, runs_: list[ScanRun]) -> list[dict]:
    def_ids = [r.definition_id for r in runs_ if r.definition_id]
    names = dict(db.execute(select(ScanDefinition.id, ScanDefinition.name).where(ScanDefinition.id.in_(def_ids))).all()) if def_ids else {}
    classes = classification_of(db, "definition", list(set(def_ids)))
    items = []
    for r in runs_:
        cls = classes.get(r.definition_id, {"tags": [], "si": []}) if r.definition_id else {"tags": [], "si": []}
        items.append({
            "id": r.id, "name": r.name, "status": r.status, "phase": r.phase or None,
            "definition": {"id": r.definition_id, "name": names.get(r.definition_id)} if r.definition_id else None,
            "initiated_by": r.initiated_by, "queued_at": r.queued_at, "started_at": r.started_at, "finished_at": r.finished_at,
            "duration_seconds": r.duration_seconds, "tags": sorted(cls["tags"]), "information_systems": cls["si"], "summary": r.summary,
        })
    return items


@router.get("", response_model=RunPage, responses={k: ERRORS[k] for k in (401, 403)}, summary="List scans",
            description="Scans, most recent first (`queued_at` desc, then `id`). Same visibility as the WebUI: every role from AUDITOR sees all scans; "
                        "`mine` restricts to the caller's own. Requires role **AUDITOR** or higher.")
def list_results(
    status: Annotated[RunStatus | None, Query(description="Scan status.")] = None,
    definition_id: Annotated[uuid.UUID | None, Query(description="Scan definition.")] = None,
    si: Annotated[uuid.UUID | None, Query(description="Information system; includes its sub-SI.")] = None,
    tag: Annotated[str | None, Query(max_length=60, description="Tag of the scan definition.")] = None,
    mine: Annotated[bool, Query(description="Only scans requested by the authenticated user.")] = False,
    requested_by: Annotated[uuid.UUID | None, Query(description="Only scans requested by this user id.")] = None,
    started_after: Annotated[datetime | None, Query(description="Start date >= (ISO 8601).")] = None,
    started_before: Annotated[datetime | None, Query(description="Start date <= (ISO 8601).")] = None,
    finished_after: Annotated[datetime | None, Query(description="End date >= (ISO 8601).")] = None,
    finished_before: Annotated[datetime | None, Query(description="End date <= (ISO 8601).")] = None,
    limit: Limit = 50, offset: Offset = 0,
    db: DbSession = Depends(get_db), user: User = Depends(auditor),
) -> dict:
    base = results.filter_runs(select(ScanRun), db, mine_of=user if mine else None, requested_by=requested_by, status=status,
                               definition_id=definition_id, tag=tag, si=si, started_after=started_after, started_before=started_before,
                               finished_after=finished_after, finished_before=finished_before)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    page = db.execute(base.options(defer(ScanRun.config_snapshot), defer(ScanRun.scanned_hosts), defer(ScanRun.skipped_hosts))
                      .order_by(ScanRun.queued_at.desc(), ScanRun.id).limit(limit).offset(offset)).scalars().all()
    return {"items": _run_items(db, list(page)), "pagination": {"total": total, "limit": limit, "offset": offset}}


@router.get("/{run_id}", response_model=RunDetail, responses={k: ERRORS[k] for k in (401, 403, 404)}, summary="Scan detail",
            description="A scan with its summary, profile and policy versions, execution errors, checks not performed and available reports. "
                        "Counts come from the engine's statistics; they are null while the scan has produced none. Role **AUDITOR** or higher.")
def get_result(run_id: uuid.UUID, request: Request, db: DbSession = Depends(get_db), user: User = Depends(auditor)) -> dict:
    r = get_or_404(db, ScanRun, run_id, "Scan")
    out = _run_items(db, [r])[0]
    snap = r.config_snapshot or {}
    profile = snap.get("profile") or {}
    profile_id = uuid.UUID(profile["id"]) if profile.get("id") else None
    out |= {
        "profile": {"id": profile_id, "name": db.scalar(select(ScanProfile.name).where(ScanProfile.id == profile_id))} if profile_id else None,
        "profile_version": profile.get("version"),
        "policy_versions": r.policy_versions or [], "progress": r.progress, "error": r.error or None,
        "skipped_hosts": r.skipped_hosts or [], "reports": _reports(r, Path(request.app.state.settings.storage_root)),
    }
    rows = db.execute(select(RunEndpoint.endpoint_id, RunEndpoint.errors, RunEndpoint.untested_checks).where(RunEndpoint.run_id == r.id)
                      .order_by(RunEndpoint.endpoint_id)).all()
    out["endpoint_errors"] = {eid: errors for eid, errors, _ in rows if errors}
    out["untested_checks"] = {eid: untested for eid, _, untested in rows if untested}
    return out


@router.get("/{run_id}/endpoints", response_model=EndpointPage, responses={k: ERRORS[k] for k in (401, 403, 404)}, summary="TLS endpoints of a scan",
            description="Analysed TLS services: versions, cipher suites, grade, compliance, certificate, errors and checks not performed. "
                        "Ordered by `endpoint_id`. Role **AUDITOR** or higher.")
def list_endpoints(
    run_id: uuid.UUID,
    compliance_status: Annotated[str | None, Query(max_length=40, description="compliant, non_compliant, error or not_tested.")] = None,
    severity: Annotated[Severity | None, Query(description="Highest severity of the endpoint.")] = None,
    q: Annotated[str | None, Query(max_length=255, description="Substring of the FQDN or IP address.")] = None,
    limit: Limit = 50, offset: Offset = 0,
    db: DbSession = Depends(get_db), user: User = Depends(auditor),
) -> dict:
    get_or_404(db, ScanRun, run_id, "Scan")
    stmt = select(RunEndpoint).where(RunEndpoint.run_id == run_id)
    if compliance_status:
        stmt = stmt.where(RunEndpoint.compliance_status == compliance_status)
    if severity:
        stmt = stmt.where(RunEndpoint.highest_severity == severity)
    if q:
        like = f"%{q.replace('%', '').replace('_', '')}%"
        stmt = stmt.where(or_(RunEndpoint.hostname.ilike(like), RunEndpoint.ip_address.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(stmt.order_by(RunEndpoint.endpoint_id).limit(limit).offset(offset)).scalars().all()
    tags = results.endpoint_tags(db, list(rows))
    return {"items": [_endpoint(e, tags) for e in rows], "pagination": {"total": total, "limit": limit, "offset": offset}}


@router.get("/{run_id}/findings", response_model=FindingPage, responses={k: ERRORS[k] for k in (401, 403, 404)}, summary="Findings of a scan",
            description="Security findings as produced by the TLS engine, with evidence, remediation and affected endpoints. "
                        "Ordered by `finding_id`. Role **AUDITOR** or higher.")
def list_findings(
    run_id: uuid.UUID,
    severity: Annotated[Severity | None, Query(description="Finding severity.")] = None,
    category: Annotated[str | None, Query(max_length=80, description="Exact category.")] = None,
    status: Annotated[str | None, Query(max_length=40, description="Finding status.")] = None,
    endpoint_id: Annotated[str | None, Query(max_length=120, description="Only findings affecting this endpoint id.")] = None,
    limit: Limit = 50, offset: Offset = 0,
    db: DbSession = Depends(get_db), user: User = Depends(auditor),
) -> dict:
    get_or_404(db, ScanRun, run_id, "Scan")
    stmt = select(RunFinding).where(RunFinding.run_id == run_id)
    if severity:
        stmt = stmt.where(RunFinding.severity == severity)
    if category:
        stmt = stmt.where(RunFinding.category == category)
    if status:
        stmt = stmt.where(RunFinding.status == status)
    rows = db.execute(stmt.order_by(RunFinding.finding_id, RunFinding.id)).scalars().all()
    if endpoint_id:  # affected_endpoint_ids is a JSON list: filtered in Python to stay portable across SQL dialects
        rows = [f for f in rows if endpoint_id in (f.affected_endpoint_ids or [])]
    page = rows[offset:offset + limit]
    return {"items": [_blank(results.finding_out(f)) for f in page], "pagination": {"total": len(rows), "limit": limit, "offset": offset}}


@router.get("/{run_id}/compare", response_model=Comparison, responses={k: ERRORS[k] for k in (401, 403, 404)}, summary="Compare two scans",
            description="Findings new / fixed / persistent / not retested, endpoints added or removed and TLS or certificate changes. "
                        "Compares with `with_run`, otherwise with the previous comparable scan. A finding on an endpoint that was not tested "
                        "again is `not_retested`, never `fixed`. Requires role **USER** or higher (AUDITOR is refused, as in the WebUI).")
def compare_results(run_id: uuid.UUID, with_run: Annotated[uuid.UUID | None, Query(description="Scan to compare with.")] = None,
                    db: DbSession = Depends(get_db), user: User = Depends(user_only)) -> dict:
    if with_run == run_id:
        raise HTTPException(422, "Choose a different scan to compare with")
    return internal.compare(run_id, with_run, db, user)


@router.get("/{run_id}/reports", response_model=ReportList, responses={k: ERRORS[k] for k in (401, 403, 404)}, summary="List the reports of a scan",
            description="Report files generated for the scan, with the SHA-256 recorded at generation. Role **AUDITOR** or higher.")
def list_reports(run_id: uuid.UUID, request: Request, db: DbSession = Depends(get_db), user: User = Depends(auditor)) -> dict:
    r = get_or_404(db, ScanRun, run_id, "Scan")
    return {"items": _reports(r, Path(request.app.state.settings.storage_root))}


@router.get("/{run_id}/reports/{format}", summary="Download a report",
            description="Downloads the report after verifying its SHA-256 (500 if it was altered). HTML reports are served with a sandboxing CSP. "
                        "The download is recorded in the audit trail. Role **AUDITOR** or higher.",
            responses={200: {"description": "The report file.", "content": {
                "text/html": {"schema": {"type": "string"}}, "text/markdown": {"schema": {"type": "string"}}, "text/csv": {"schema": {"type": "string"}},
                "application/json": {"schema": {"type": "object"}}}},
                **{k: ERRORS[k] for k in (401, 403, 404)}, 500: {"model": ErrorBody, "description": "Integrity check failed."}})
def download_result_report(run_id: uuid.UUID, format: ReportFormat, request: Request, inline: Annotated[bool, Query(description="Display HTML instead of downloading it.")] = False,
                           db: DbSession = Depends(get_db), user: User = Depends(auditor)) -> Response:
    return internal.download_report(run_id, format, request, inline, db, user)
