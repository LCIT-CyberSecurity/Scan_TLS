"""MCP server (`/mcp`, Streamable HTTP, official Python SDK): read-only access to TLS scan results.

Same data, same rules and same output schemas as the external REST API v1; a closed list of tools; no write, no scan launch, no
export, no file, SQL, shell or HTTP access. Authenticated by a dedicated key (`tls_scan_mcp_...`): a REST key is refused here, an MCP
key is refused everywhere else. Every HTTP request AND every tool call re-validates the global switch, the key, the user, their
individual authorisation and their current role in the database.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from types import SimpleNamespace
from typing import Any, Callable
from urllib.parse import urlparse

from fastapi.encoders import jsonable_encoder
from sqlalchemy import func, select

try:
    from mcp.server.mcpserver import Context, MCPServer
    from mcp.server.transport_security import RequestBodyLimitMiddleware, TransportSecuritySettings
except ModuleNotFoundError:  # pragma: no cover - the MCP SDK is an application dependency
    Context = Any  # type: ignore[misc,assignment]
    MCPServer = None  # type: ignore[assignment]
    TransportSecuritySettings = None  # type: ignore[assignment]
    RequestBodyLimitMiddleware = None  # type: ignore[assignment]

from tls_scan_app.api import external, results
from tls_scan_app.models import Role, RunEndpoint
from tls_scan_app.models.user import role_at_least
from tls_scan_app.services import audit, external_access
from tls_scan_app.services import results as results_service
from tls_scan_app.services.external_access import AccessError

MCP_TOOL_NAMES = (
    "tls_scan_get_current_user",
    "tls_scan_list_scans",
    "tls_scan_get_scan_summary",
    "tls_scan_list_endpoints",
    "tls_scan_get_endpoint_details",
    "tls_scan_list_findings",
    "tls_scan_get_compliance_summary",
    "tls_scan_compare_scans",
)
MAX_BODY_BYTES = 64 * 1024
HTTP_PER_KEY_PER_MINUTE = 240
TOOLS_PER_KEY_PER_MINUTE = 60
TOOL_TIMEOUT_SECONDS = 25
MAX_PAGE = 100


def _header(headers: Any, name: str) -> str | None:
    if not headers:
        return None
    for key, value in (headers.items() if hasattr(headers, "items") else headers):
        k = key.decode("latin-1") if isinstance(key, bytes) else str(key)
        if k.casefold() == name.casefold():
            return value.decode("latin-1") if isinstance(value, bytes) else str(value)
    return None


def _bearer(headers: Any) -> str | None:
    value = _header(headers, "authorization")
    return value[7:].strip() if value and value.lower().startswith("bearer ") else None


def _page(limit: int, offset: int) -> tuple[int, int]:
    if not 1 <= int(limit) <= MAX_PAGE or not 0 <= int(offset) <= 100_000:
        raise ValueError(f"limit must be 1-{MAX_PAGE} and offset 0-100000")
    return int(limit), int(offset)


def _uuid(value: str | None, name: str) -> uuid.UUID | None:
    if value in (None, ""):
        return None
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise ValueError(f"{name} must be a scan identifier") from None


def allowed_hosts(public_base_url: str) -> list[str]:
    configured = [i.strip() for i in os.getenv("TLS_SCAN_MCP_ALLOWED_HOSTS", "").split(",") if i.strip()]
    hosts = ["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*", "[::1]", "[::1]:*", "api", "api:*"]
    public = urlparse(public_base_url)
    if public.hostname:
        hosts += [public.hostname, f"{public.hostname}:*"]
    return configured or hosts


def allowed_origins(public_base_url: str) -> list[str]:
    configured = [i.strip() for i in os.getenv("TLS_SCAN_MCP_ALLOWED_ORIGINS", "").split(",") if i.strip()]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*", "https://localhost:*"]
    public = urlparse(public_base_url)
    if public.scheme and public.hostname:
        origins += [f"{public.scheme}://{public.hostname}", f"{public.scheme}://{public.hostname}:*"]
    return configured or origins


class McpAuthMiddleware:
    """HTTP gate in front of the SDK: exact path, MCP key, rate limit. Failures are uniform 401s and audited (throttled)."""

    def __init__(self, app: Any, state: Any) -> None:
        self.app, self.state = app, state

    async def _respond(self, send: Any, status: int, body: bytes, extra: list[tuple[bytes, bytes]] | None = None) -> None:
        headers = [(b"content-type", b"text/plain"), (b"content-length", str(len(body)).encode()), (b"cache-control", b"no-store")] + (extra or [])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope.get("type") != "http" or scope.get("path") != "/mcp":
            await self._respond(send, 404, b"Not found")
            return
        headers = dict(scope.get("headers", []))
        token = _bearer(headers)
        client = (scope.get("client") or ("", 0))[0]
        outcome = await asyncio.to_thread(self._check, token, client)
        if outcome[0] == "ok":
            await self.app(scope, receive, send)
        elif outcome[0] == "rate":
            await self._respond(send, 429, b"Too many requests", [(b"retry-after", b"60")])
        else:
            await self._respond(send, 401, b"MCP authentication required", [(b"www-authenticate", b"Bearer")])

    def _check(self, token: str | None, client: str) -> tuple[str, str]:
        with self.state.session_factory() as db:
            try:
                if not token:
                    raise AccessError("no bearer")
                who = external_access.authenticate(db, token, "mcp")
            except AccessError as error:
                if self.state.limiter.allow(f"mcp-audit:{client}", external.FAILURES_PER_IP_PER_MINUTE, 60):
                    audit.record(db, "mcp.auth_failed", actor_label="mcp", outcome="failure", ip_address=client, detail={"reason": str(error)})
                    db.commit()
                return "denied", str(error)
            if not self.state.limiter.allow(f"mcp-http:{who.prefix}", HTTP_PER_KEY_PER_MINUTE, 60):
                return "rate", ""
            return "ok", ""


def build_mcp_asgi(state: Any) -> tuple[Any, Any]:
    """`state` is the FastAPI app state: settings, session_factory, limiter."""
    if MCPServer is None or TransportSecuritySettings is None:
        raise RuntimeError("The MCP SDK is required; install the application dependencies")
    settings = state.settings
    server = MCPServer(name="TLS Scan MCP", version="1.0.0",
                       instructions="TLS Scan MCP V1 is authenticated, read-only and limited to the results of TLS scans.")
    fake_request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))

    def execute(ctx: Context, tool: str, scan_id: str | None, operation: Callable[..., dict]) -> dict:
        """Runs one tool call in a worker thread: re-authenticates, rate-limits, audits, and projects the result."""
        token = _bearer(ctx.headers)
        started = time.monotonic()
        with state.session_factory() as db:
            try:
                if not token:
                    raise AccessError("no bearer")
                who = external_access.authenticate(db, token, "mcp")
            except AccessError as error:
                if state.limiter.allow("mcp-audit:tool", external.FAILURES_PER_IP_PER_MINUTE, 60):
                    audit.record(db, "mcp.tool_denied", actor_label="mcp", outcome="failure", resource_type="mcp_tool", resource_id=tool,
                                 detail={"reason": str(error)})
                    db.commit()
                raise PermissionError("MCP authentication required") from None
            if not state.limiter.allow(f"mcp-tool:{who.prefix}", TOOLS_PER_KEY_PER_MINUTE, 60):
                audit.record(db, "mcp.rate_limited", actor=who.user, outcome="failure", resource_type="mcp_tool", resource_id=tool)
                db.commit()
                raise PermissionError("Too many requests, retry in a minute")
            try:
                result = jsonable_encoder(operation(db, who.user))
                count = result.get("pagination", {}).get("total") if isinstance(result, dict) and isinstance(result.get("pagination"), dict) else 1
                audit.record(db, "mcp.tool_called", actor=who.user, resource_type="mcp_tool", resource_id=tool,
                             detail={"scan_id": scan_id, "result_count": count, "duration_ms": round((time.monotonic() - started) * 1000), "prefix": who.prefix})
                db.commit()
                return result
            except Exception as error:  # noqa: BLE001
                db.rollback()
                denied = isinstance(error, (PermissionError, ValueError)) or getattr(error, "status_code", 500) in (403, 404, 422)
                audit.record(db, "mcp.tool_denied" if denied else "mcp.tool_failed", actor=who.user, outcome="failure", resource_type="mcp_tool",
                             resource_id=tool, detail={"scan_id": scan_id, "prefix": who.prefix})
                db.commit()
                if getattr(error, "status_code", None) in (403, 404):
                    raise PermissionError("not found or not allowed") from None
                if isinstance(error, (PermissionError, ValueError)):
                    raise
                if getattr(error, "status_code", None) == 422:
                    raise ValueError(str(getattr(error, "detail", "invalid request"))) from None
                raise RuntimeError("internal error") from None

    async def call(ctx: Context, tool: str, scan_id: str | None, operation: Callable[..., dict]) -> dict:
        try:
            return await asyncio.wait_for(asyncio.to_thread(execute, ctx, tool, scan_id, operation), TOOL_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            raise RuntimeError("the request took too long") from None

    @server.tool(name="tls_scan_get_current_user", structured_output=True)
    async def get_current_user(ctx: Context) -> dict[str, object]:
        """The account behind the key and its current role."""
        return await call(ctx, "tls_scan_get_current_user", None, lambda db, u: {"id": u.id, "email": u.email, "display_name": u.display_name, "role": str(u.role)})

    @server.tool(name="tls_scan_list_scans", structured_output=True)
    async def list_scans(ctx: Context, limit: int = 25, offset: int = 0, status: str | None = None, mine: bool = False) -> dict[str, object]:
        """Scans, most recent first (limit 1-100). status: queued, running, completed, partial, failed, cancelled, expired."""
        def op(db, u):
            lim, off = _page(limit, offset)
            data = results.list_results(status=status, definition_id=None, si=None, tag=None, mine=mine, requested_by=None, started_after=None,
                                        started_before=None, finished_after=None, finished_before=None, limit=lim, offset=off, db=db, user=u)
            return external.ExtScanPage.model_validate(data).model_dump(mode="json")
        return await call(ctx, "tls_scan_list_scans", None, op)

    @server.tool(name="tls_scan_get_scan_summary", structured_output=True)
    async def get_scan_summary(ctx: Context, scan_id: str) -> dict[str, object]:
        """Detail and engine statistics of one scan."""
        def op(db, u):
            data = results.get_result(_uuid(scan_id, "scan_id"), fake_request, db, u)
            return external.ExtScanDetail.model_validate(data).model_dump(mode="json")
        return await call(ctx, "tls_scan_get_scan_summary", scan_id, op)

    @server.tool(name="tls_scan_list_endpoints", structured_output=True)
    async def list_endpoints(ctx: Context, scan_id: str, limit: int = 25, offset: int = 0, compliance_status: str | None = None,
                             severity: str | None = None, q: str | None = None) -> dict[str, object]:
        """TLS endpoints of a scan. compliance_status: compliant, non_compliant, error, not_tested. severity: critical..informational."""
        def op(db, u):
            lim, off = _page(limit, offset)
            data = results.list_endpoints(_uuid(scan_id, "scan_id"), compliance_status, severity, (q or None) and q[:255], lim, off, db, u)
            return external.ExtEndpointPage.model_validate(data).model_dump(mode="json")
        return await call(ctx, "tls_scan_list_endpoints", scan_id, op)

    @server.tool(name="tls_scan_get_endpoint_details", structured_output=True)
    async def get_endpoint_details(ctx: Context, scan_id: str, endpoint_id: str) -> dict[str, object]:
        """One endpoint of a scan with its certificate, cipher suites and the findings that affect it."""
        def op(db, u):
            run_id = _uuid(scan_id, "scan_id")
            results.get_result(run_id, fake_request, db, u)  # existence / visibility, same rules as the scan
            row = db.execute(select(RunEndpoint).where(RunEndpoint.run_id == run_id, RunEndpoint.endpoint_id == endpoint_id[:120])).scalar_one_or_none()
            if row is None:
                raise ValueError("endpoint not found")
            endpoint = external.ExtEndpointPage.model_validate({"items": [results._endpoint(row, results_service.endpoint_tags(db, [row]))],
                                                                 "pagination": {"total": 1, "limit": 1, "offset": 0}}).model_dump(mode="json")["items"][0]
            findings = results.list_findings(run_id, None, None, None, row.endpoint_id, MAX_PAGE, 0, db, u)
            return {"endpoint": endpoint, "findings": external.ExtFindingPage.model_validate(findings).model_dump(mode="json")["items"]}
        return await call(ctx, "tls_scan_get_endpoint_details", scan_id, op)

    @server.tool(name="tls_scan_list_findings", structured_output=True)
    async def list_findings(ctx: Context, scan_id: str, limit: int = 25, offset: int = 0, severity: str | None = None, category: str | None = None,
                            status: str | None = None, endpoint_id: str | None = None) -> dict[str, object]:
        """Security findings of a scan with evidence, remediation and affected endpoints."""
        def op(db, u):
            lim, off = _page(limit, offset)
            data = results.list_findings(_uuid(scan_id, "scan_id"), severity, category, status, endpoint_id, lim, off, db, u)
            return external.ExtFindingPage.model_validate(data).model_dump(mode="json")
        return await call(ctx, "tls_scan_list_findings", scan_id, op)

    @server.tool(name="tls_scan_get_compliance_summary", structured_output=True)
    async def get_compliance_summary(ctx: Context, scan_id: str) -> dict[str, object]:
        """Compliance statistics of a scan: engine summary and endpoint counts by compliance status and by highest severity."""
        def op(db, u):
            run_id = _uuid(scan_id, "scan_id")
            detail = external.ExtScanDetail.model_validate(results.get_result(run_id, fake_request, db, u)).model_dump(mode="json")
            by_status = dict(db.execute(select(RunEndpoint.compliance_status, func.count()).where(RunEndpoint.run_id == run_id).group_by(RunEndpoint.compliance_status)).all())
            by_severity = dict(db.execute(select(RunEndpoint.highest_severity, func.count()).where(RunEndpoint.run_id == run_id).group_by(RunEndpoint.highest_severity)).all())
            return {"scan_id": detail["id"], "status": detail["status"], "summary": detail["summary"],
                    "endpoints_by_compliance_status": {str(k or "unknown"): v for k, v in by_status.items()},
                    "endpoints_by_highest_severity": {str(k or "none"): v for k, v in by_severity.items()}}
        return await call(ctx, "tls_scan_get_compliance_summary", scan_id, op)

    @server.tool(name="tls_scan_compare_scans", structured_output=True)
    async def compare_scans(ctx: Context, scan_id: str, with_scan_id: str | None = None) -> dict[str, object]:
        """New / fixed / persistent / not-retested findings and endpoint changes against with_scan_id or the previous comparable scan. Role USER or higher."""
        def op(db, u):
            if not role_at_least(u.role, Role.USER):
                raise PermissionError("insufficient role")
            run_id, other = _uuid(scan_id, "scan_id"), _uuid(with_scan_id, "with_scan_id")
            if other == run_id:
                raise ValueError("choose a different scan to compare with")
            return external.Comparison.model_validate(results.compare_results(run_id, other, db, u)).model_dump(mode="json")
        return await call(ctx, "tls_scan_compare_scans", scan_id, op)

    security = TransportSecuritySettings(allowed_hosts=allowed_hosts(settings.public_base_url), allowed_origins=allowed_origins(settings.public_base_url),
                                         enable_dns_rebinding_protection=True)
    app = server.streamable_http_app(streamable_http_path="/mcp", stateless_http=False, transport_security=security)
    if RequestBodyLimitMiddleware is not None:
        app = RequestBodyLimitMiddleware(app, MAX_BODY_BYTES)
    return server, McpAuthMiddleware(app, state)
