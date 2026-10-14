"""Administration -> Authentication: which external sign-in is active, its non-secret settings, tests and recent diagnostics.

Secrets (client secrets, the LDAP service password) are read from the environment or protected files only; the API tells
whether they are set, never what they are.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.sso import redirect_uri
from tls_scan_app.auth.diagnostics import explain
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import AuditEvent, Role, SystemSetting, User
from tls_scan_app.services import audit, auth_config, auth_selftest

router = APIRouter(prefix="/api/admin/auth", tags=["admin"])
admin_only = require_role(Role.ADMIN)
AUTH_ACTIONS = ("auth.sso_login", "auth.ldap_login", "auth.test", "auth.config_update")


def _public(db: DbSession, request: Request) -> dict[str, Any]:
    s = request.app.state.settings
    cfg = auth_config.effective(db, s)
    stored = auth_config.stored(db)
    return {
        "stored": stored,
        "effective": {"provider": cfg.provider, "source": cfg.source, "issuer": cfg.issuer, "client_id": cfg.client_id, "default_role": cfg.default_role,
                      "auto_provision": cfg.auto_provision, "complete": cfg.oidc or cfg.ldap_enabled},
        "redirect_uri": redirect_uri(request),
        "secrets": {"oidc_client_secret": bool(s.oidc_client_secret), "google_client_secret": bool(s.google_client_secret), "ldap_bind_password": bool(s.ldap_bind_password)},
        "environment": {"oidc_configured": bool(s.oidc_issuer and s.oidc_client_id), "oidc_provider": s.oidc_provider, "auto_provision": s.sso_auto_provision},
        "providers": list(auth_config.PROVIDERS),
    }


@router.get("")
def get_auth(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    return _public(db, request)


class AuthBody(BaseModel):
    value: dict = Field(default_factory=dict)


@router.put("")
def put_auth(body: AuthBody, request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    try:
        value = auth_config.validate(body.value, allow_http=request.app.state.settings.environment != "production")
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    previous = auth_config.stored(db)
    if value["auto_provision"] is None:   # the page may omit it: never silently change the creation policy
        value["auto_provision"] = previous["auto_provision"]
    row = db.get(SystemSetting, "auth") or SystemSetting(key="auth", value={})
    row.value = value
    db.add(row)
    audit.record(db, "auth.config_update", actor=actor, resource_type="settings", resource_id="auth",
                 detail={"provider": value["provider"], "from": previous["provider"], "auto_provision": value["auto_provision"], "default_role": value["default_role"]})
    db.commit()
    return _public(db, request)


class TestBody(BaseModel):
    username: str = ""
    password: str = ""   # LDAP only, explicitly entered for this test, never stored nor logged


@router.post("/test/{provider}")
def test_auth(provider: str, body: TestBody, request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> list[dict]:
    if provider not in ("entra", "google", "generic", "ldap"):
        raise HTTPException(404, "Unknown provider")
    steps = auth_selftest.run(db, request.app.state.settings, provider, redirect_uri(request), body.model_dump())
    failed = [s for s in steps if s["status"] == "fail"]
    audit.record(db, "auth.test", actor=actor, resource_type="settings", resource_id="auth", outcome="failure" if failed else "success",
                 detail={"provider": provider, "failed": [s["step"] for s in failed]})
    db.commit()
    return steps


@router.get("/diagnostics")
def diagnostics(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    """The latest sign-in failures and configuration tests, each with its explanation."""
    rows = db.execute(select(AuditEvent).where(AuditEvent.action.in_(AUTH_ACTIONS), AuditEvent.outcome != "success")
                      .order_by(AuditEvent.created_at.desc()).limit(30)).scalars()
    out = []
    for e in rows:
        d = e.detail or {}
        info = explain(f"{d.get('code', '')} {d.get('reason', '')} {d.get('detail', '')}", redirect=redirect_uri(request)) if e.action != "auth.test" else {"code": "test", "explanation": f"Failed steps: {', '.join(d.get('failed', []))}"}
        out.append({"at": e.created_at, "action": e.action, "who": e.actor_label, "outcome": e.outcome, "ip": e.ip_address, "reason": d.get("reason", ""),
                    "code": d.get("code") or info["code"], "explanation": info["explanation"]})
    return out
