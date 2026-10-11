"""External REST API v1 (`/api/v1`): read-only access to scan results with a Personal API Token.

Separate from the internal `/api/*` routes used by the WebUI: it accepts only `Authorization: Bearer tls_scan_pat_...`
(never a session cookie, never an MCP key) and the WebUI routes never accept these keys. Every request re-checks the
global switch, the key, the user and the user's current role in the database. Data and visibility rules are those of the
WebUI (and of `/api/results`): the handlers of the results API are reused, filtered through explicit output schemas.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api import results
from tls_scan_app.api.results_schemas import (
    Comparison, Endpoint, ErrorBody, Finding, NamedRef, Pagination, PolicyVersionRef, RunStatus, RunSummary, Severity,
)
from tls_scan_app.api.swagger import ASSETS, CSP, STATIC
from tls_scan_app.deps import client_ip, get_db
from tls_scan_app.models import Role, User
from tls_scan_app.models.user import role_at_least
from tls_scan_app.services import audit, external_access
from tls_scan_app.services.external_access import AccessError, Principal

PER_KEY_PER_MINUTE = 120
FAILURES_PER_IP_PER_MINUTE = 30
router = APIRouter(prefix="/api/v1", tags=["External API v1"])
docs = APIRouter(include_in_schema=False)

Limit = Annotated[int, Query(ge=1, le=100, description="Page size (1-100).")]
Offset = Annotated[int, Query(ge=0, le=100_000, description="Number of items to skip.")]
UNAUTHORIZED = {"model": ErrorBody, "description": "Missing, invalid, expired or revoked key, service disabled, or account not authorised."}
ERRORS: dict[int | str, dict[str, Any]] = {401: UNAUTHORIZED, 404: {"model": ErrorBody, "description": "Scan not found."},
                                           429: {"model": ErrorBody, "description": "Too many requests."}}


# ---- output schemas (explicit: nothing internal leaks through them) ----
class Me(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    role: str = Field(description="Current role; it decides what the key may read, and changes apply immediately.")
    key_prefix: str = Field(description="Beginning of the key used for this request.")


class ExtScan(BaseModel):
    id: uuid.UUID
    name: str
    status: RunStatus
    definition: NamedRef | None = None
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    tags: list[str] = []
    information_systems: list[uuid.UUID] = []
    summary: RunSummary | None = None


class ExtScanDetail(ExtScan):
    profile: NamedRef | None = None
    profile_version: int | str | None = None
    policy_versions: list[PolicyVersionRef] = []
    error: str | None = None
    endpoint_errors: dict[str, list[str]] = Field({}, description="Errors per endpoint_id (endpoints without error are omitted).")
    untested_checks: dict[str, list[str]] = Field({}, description="Checks not performed, per endpoint_id.")


class ExtScanPage(BaseModel):
    items: list[ExtScan]
    pagination: Pagination


class ExtEndpointPage(BaseModel):
    items: list[Endpoint]
    pagination: Pagination


class ExtFindingPage(BaseModel):
    items: list[Finding]
    pagination: Pagination


class ScanSummary(BaseModel):
    id: uuid.UUID
    name: str
    status: RunStatus
    finished_at: datetime | None = None
    summary: RunSummary | None = Field(None, description="Engine statistics; null while the scan has produced none.")
    endpoints_with_errors_count: int
    endpoints_not_fully_tested_count: int


# ---- authentication ----
def _deny(request: Request, db: DbSession, reason: str) -> HTTPException:
    """Every failure is the same 401 for the caller; the reason is only audited (and the audit itself is throttled)."""
    ip = client_ip(request)
    limiter = request.app.state.limiter
    if limiter.allow(f"v1-audit:{ip}", FAILURES_PER_IP_PER_MINUTE, 60):
        audit.record(db, "external_api.auth_failed", actor_label="external-api", outcome="failure", ip_address=ip,
                     request_id=getattr(request.state, "request_id", ""), detail={"reason": reason, "path": request.url.path[:120]})
        db.commit()
    return HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})


def principal(request: Request, db: DbSession = Depends(get_db)) -> Principal:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise _deny(request, db, "no bearer")
    try:
        who = external_access.authenticate(db, header[7:].strip(), "api")
    except AccessError as error:
        raise _deny(request, db, str(error)) from None
    if not request.app.state.limiter.allow(f"v1:{who.prefix}", PER_KEY_PER_MINUTE, 60):
        audit.record(db, "external_api.rate_limited", actor=who.user, outcome="failure", ip_address=client_ip(request),
                     request_id=getattr(request.state, "request_id", ""), detail={"prefix": who.prefix})
        db.commit()
        raise HTTPException(429, "Too many requests", headers={"Retry-After": "60"})
    return who


def _log(request: Request, db: DbSession, who: Principal, action: str, resource: str) -> None:
    audit.record(db, f"external_api.{action}", actor=who.user, resource_type="scan_run", resource_id=resource, ip_address=client_ip(request),
                 request_id=getattr(request.state, "request_id", ""), detail={"prefix": who.prefix})
    db.commit()


# ---- endpoints ----
@router.get("/me", response_model=Me, responses={k: ERRORS[k] for k in (401, 429)}, summary="Who am I",
            description="The account behind the key and its current role.")
def me(who: Principal = Depends(principal)) -> dict:
    u: User = who.user
    return {"id": u.id, "email": u.email, "display_name": u.display_name, "role": str(u.role), "key_prefix": who.prefix}


@router.get("/scans", response_model=ExtScanPage, responses={k: ERRORS[k] for k in (401, 429)}, summary="List scans",
            description="Scans, most recent first. Same visibility as the WebUI for the account's current role.")
def list_scans(
    status: Annotated[RunStatus | None, Query(description="Scan status.")] = None,
    definition_id: Annotated[uuid.UUID | None, Query(description="Scan definition.")] = None,
    si: Annotated[uuid.UUID | None, Query(description="Information system (includes its sub-SI).")] = None,
    tag: Annotated[str | None, Query(max_length=60, description="Tag of the scan definition.")] = None,
    mine: Annotated[bool, Query(description="Only the scans requested by the key's owner.")] = False,
    started_after: Annotated[datetime | None, Query(description="Start date >= (ISO 8601).")] = None,
    started_before: Annotated[datetime | None, Query(description="Start date <= (ISO 8601).")] = None,
    limit: Limit = 25, offset: Offset = 0,
    who: Principal = Depends(principal), db: DbSession = Depends(get_db),
) -> dict:
    return results.list_results(status=status, definition_id=definition_id, si=si, tag=tag, mine=mine, requested_by=None,
                                started_after=started_after, started_before=started_before, finished_after=None, finished_before=None,
                                limit=limit, offset=offset, db=db, user=who.user)


@router.get("/scans/{scan_id}", response_model=ExtScanDetail, responses={k: ERRORS[k] for k in (401, 404, 429)}, summary="Scan detail",
            description="A scan with its engine summary, profile and policy versions, execution errors and checks not performed.")
def get_scan(scan_id: uuid.UUID, request: Request, who: Principal = Depends(principal), db: DbSession = Depends(get_db)) -> dict:
    out = results.get_result(scan_id, request, db, who.user)
    _log(request, db, who, "scan_read", str(scan_id))
    return out


@router.get("/scans/{scan_id}/summary", response_model=ScanSummary, responses={k: ERRORS[k] for k in (401, 404, 429)}, summary="Scan summary",
            description="The engine statistics of a scan (counts of endpoints, compliance, findings by severity) in a compact form.")
def scan_summary(scan_id: uuid.UUID, request: Request, who: Principal = Depends(principal), db: DbSession = Depends(get_db)) -> dict:
    detail = results.get_result(scan_id, request, db, who.user)
    summary = detail.get("summary") or {}
    return {"id": detail["id"], "name": detail["name"], "status": detail["status"], "finished_at": detail["finished_at"], "summary": detail.get("summary"),
            "endpoints_with_errors_count": summary.get("endpoints_with_errors") or len(detail.get("endpoint_errors") or {}),
            "endpoints_not_fully_tested_count": summary.get("endpoints_not_fully_tested") or len(detail.get("untested_checks") or {})}


@router.get("/scans/{scan_id}/endpoints", response_model=ExtEndpointPage, responses={k: ERRORS[k] for k in (401, 404, 429)}, summary="TLS endpoints of a scan",
            description="Analysed TLS services: versions, cipher suites, grade, compliance, certificate, errors and checks not performed.")
def scan_endpoints(
    scan_id: uuid.UUID, request: Request,
    compliance_status: Annotated[str | None, Query(max_length=40, description="compliant, non_compliant, error or not_tested.")] = None,
    severity: Annotated[Severity | None, Query(description="Highest severity of the endpoint.")] = None,
    q: Annotated[str | None, Query(max_length=255, description="Substring of the FQDN or IP address.")] = None,
    limit: Limit = 25, offset: Offset = 0,
    who: Principal = Depends(principal), db: DbSession = Depends(get_db),
) -> dict:
    out = results.list_endpoints(scan_id, compliance_status, severity, q, limit, offset, db, who.user)
    _log(request, db, who, "endpoints_read", str(scan_id))
    return out


@router.get("/scans/{scan_id}/findings", response_model=ExtFindingPage, responses={k: ERRORS[k] for k in (401, 404, 429)}, summary="Findings of a scan",
            description="Security findings as produced by the TLS engine, with evidence, remediation and affected endpoints.")
def scan_findings(
    scan_id: uuid.UUID, request: Request,
    severity: Annotated[Severity | None, Query(description="Finding severity.")] = None,
    category: Annotated[str | None, Query(max_length=80, description="Exact category.")] = None,
    status: Annotated[str | None, Query(max_length=40, description="Finding status.")] = None,
    endpoint_id: Annotated[str | None, Query(max_length=120, description="Only findings affecting this endpoint id.")] = None,
    limit: Limit = 25, offset: Offset = 0,
    who: Principal = Depends(principal), db: DbSession = Depends(get_db),
) -> dict:
    out = results.list_findings(scan_id, severity, category, status, endpoint_id, limit, offset, db, who.user)
    _log(request, db, who, "findings_read", str(scan_id))
    return out


@router.get("/scans/{scan_id}/comparison", response_model=Comparison, responses={k: ERRORS[k] for k in (401, 404, 429)}, summary="Compare two scans",
            description="New / fixed / persistent / not-retested findings and endpoint changes, against `with_scan` or the previous comparable scan. "
                        "Requires the role USER or higher, as in the WebUI (an AUDITOR key gets 403).")
def scan_comparison(scan_id: uuid.UUID, request: Request, with_scan: Annotated[uuid.UUID | None, Query(description="Scan to compare with.")] = None,
                    who: Principal = Depends(principal), db: DbSession = Depends(get_db)) -> dict:
    if not role_at_least(who.user.role, Role.USER):
        raise HTTPException(403, "Insufficient role")
    out = results.compare_results(scan_id, with_scan, db, who.user)
    _log(request, db, who, "comparison_read", str(scan_id))
    return out


# ---- documentation: local Swagger UI and the OpenAPI document of this router only, available only while the API is enabled ----
DESCRIPTION = """Read-only access to TLS Scan results with a **Personal API Token**.

Send `Authorization: Bearer tls_scan_pat_...` on every request (use *Authorize* below). Keys are created by their owner in
*Preferences → API and MCP access*, are valid 90 days and can be revoked at any time. The service is off unless the administrator
enabled it and authorised your account. The key sees what your role sees in the WebUI; changes of role apply immediately.
Only GET operations exist. Lists are paginated (`limit`, `offset`). Use HTTPS."""


def build_openapi(app_version: str = "1.0.0") -> dict:
    schema = get_openapi(title="TLS Scan - External API v1", version=app_version, description=DESCRIPTION, routes=router.routes, servers=[{"url": "/"}])
    schema.setdefault("components", {})["securitySchemes"] = {"personalApiToken": {"type": "http", "scheme": "bearer", "bearerFormat": "tls_scan_pat_...",
                                                                                      "description": "Personal API Token (prefix tls_scan_pat_)."}}
    schema["security"] = [{"personalApiToken": []}]
    return schema


def _enabled(request: Request, db: DbSession = Depends(get_db)) -> None:
    if not external_access.service_enabled(db, "api"):
        raise HTTPException(404, "Not found")


INDEX = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TLS Scan - External API v1</title><link rel="stylesheet" href="/api/v1/docs/swagger-ui.css"><link rel="icon" href="/api/v1/docs/favicon-32x32.png"></head>
<body><div id="swagger-ui"></div><script src="/api/v1/docs/swagger-ui-bundle.js"></script><script src="/api/v1/docs/init.js"></script></body></html>
"""
INIT_JS = """window.ui = SwaggerUIBundle({ url: "/api/v1/openapi.json", dom_id: "#swagger-ui", deepLinking: true, tryItOutEnabled: true,
  supportedSubmitMethods: ["get"] });
"""


@docs.get("/api/v1/docs")
@docs.get("/api/v1/docs/")
def swagger_ui(_: None = Depends(_enabled)) -> HTMLResponse:
    return HTMLResponse(INDEX, headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store"})


@docs.get("/api/v1/openapi.json")
def openapi_document(request: Request, _: None = Depends(_enabled)) -> JSONResponse:
    if not hasattr(request.app.state, "external_openapi"):
        request.app.state.external_openapi = build_openapi()
    return JSONResponse(request.app.state.external_openapi, headers={"Cache-Control": "no-store"})


@docs.get("/api/v1/docs/init.js")
def swagger_init(_: None = Depends(_enabled)) -> HTMLResponse:
    return HTMLResponse(INIT_JS, media_type="application/javascript", headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store"})


@docs.get("/api/v1/docs/{asset}")
def swagger_asset(asset: str, _: None = Depends(_enabled)) -> FileResponse:
    if asset not in ASSETS:
        raise HTTPException(404, "Not found")
    return FileResponse(STATIC / asset, media_type=ASSETS[asset], headers={"Cache-Control": "private, max-age=3600"})
