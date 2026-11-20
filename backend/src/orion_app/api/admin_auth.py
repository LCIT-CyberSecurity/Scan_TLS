"""Administration -> Authentication: which external sign-in is active, its non-secret settings, tests and recent diagnostics.

Secrets (client secrets, the LDAP service password) are read from the environment or protected files; the Entra client secret
may also be entered here, write-only, and is then stored encrypted (services/auth_secrets.py). The API tells whether a
secret is set and where it comes from, never what it is.
"""
from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from orion_app.api.sso import redirect_uri
from orion_app.auth.diagnostics import explain
from orion_app.deps import get_db, require_role
from orion_app.models import AuditEvent, Role, SystemSetting, User
from orion_app.services import audit, auth_config, auth_secrets, auth_selftest

router = APIRouter(prefix="/api/admin/auth", tags=["admin"])
admin_only = require_role(Role.ADMIN)
AUTH_ACTIONS = ("auth.sso_login", "auth.ldap_login", "auth.test", "auth.config_update")


def _public(db: DbSession, request: Request) -> dict[str, Any]:
    s = request.app.state.settings
    cfg = auth_config.effective(db, s)
    stored = auth_config.stored(db)
    entra = auth_secrets.entra_status(db, s)
    return {
        "stored": stored,
        "effective": {"provider": cfg.provider, "source": cfg.source, "issuer": cfg.issuer, "client_id": cfg.client_id, "default_role": cfg.default_role,
                      "auto_provision": cfg.auto_provision, "complete": cfg.oidc or cfg.ldap_enabled},
        "redirect_uri": redirect_uri(request),
        "secrets": {"oidc_client_secret": entra["configured"] if stored["provider"] == "entra" else bool(s.oidc_client_secret),
                    "google_client_secret": bool(s.google_client_secret), "ldap_bind_password": bool(s.ldap_bind_password),
                    "entra_client_secret": {k: entra[k] for k in ("configured", "source", "unreadable", "stored")}},
        "environment": {"oidc_configured": bool(s.oidc_issuer and s.oidc_client_id), "oidc_provider": s.oidc_provider, "auto_provision": s.sso_auto_provision},
        "providers": list(auth_config.PROVIDERS),
    }


@router.get("")
def get_auth(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    return _public(db, request)


class AuthBody(BaseModel):
    value: dict = Field(default_factory=dict)
    # Write-only: empty keeps the current Entra client secret. Both fields must match (a typo would break the sign-in).
    entra_client_secret: SecretStr = SecretStr("")
    entra_client_secret_confirm: SecretStr = SecretStr("")

    @field_validator("entra_client_secret", "entra_client_secret_confirm", mode="before")
    @classmethod
    def _never_echo(cls, value: Any) -> Any:
        """A validation error would echo the input back: a value of the wrong type becomes an invalid marker instead, refused
        later with a neutral message."""
        if value is None:
            return ""
        return value if isinstance(value, (str, SecretStr)) else "\x00"


@router.put("")
def put_auth(body: AuthBody, request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    try:
        value = auth_config.validate(body.value, allow_http=request.app.state.settings.environment != "production")
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    previous = auth_config.stored(db)
    secret = body.entra_client_secret.get_secret_value()
    if secret or body.entra_client_secret_confirm.get_secret_value():
        if not hmac.compare_digest(secret.encode(), body.entra_client_secret_confirm.get_secret_value().encode()):
            raise HTTPException(422, "The two client secret fields do not match")
        try:
            auth_secrets.store_entra(db, request.app.state.settings, secret)
        except auth_secrets.KeyUnavailable as error:
            raise HTTPException(503, str(error)) from None
        except auth_secrets.SecretError as error:
            raise HTTPException(422, str(error)) from None
        audit.record(db, "auth.entra_secret.replace", actor=actor, resource_type="settings", resource_id="auth",
                     detail={"stored": "encrypted"})
    if value["auto_provision"] is None:   # the page may omit it: never silently change the creation policy
        value["auto_provision"] = previous["auto_provision"]
    row = db.get(SystemSetting, "auth") or SystemSetting(key="auth", value={})
    row.value = value
    db.add(row)
    audit.record(db, "auth.config_update", actor=actor, resource_type="settings", resource_id="auth",
                 detail={"provider": value["provider"], "from": previous["provider"], "auto_provision": value["auto_provision"], "default_role": value["default_role"]})
    db.commit()
    return _public(db, request)


@router.delete("/entra-secret")
def remove_entra_secret(request: Request, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    """Forget the secret entered in the WebUI; the server secret (ORION_OIDC_CLIENT_SECRET) takes over again. Refused when the
    active Entra sign-in would be left without any secret."""
    s = request.app.state.settings
    if not auth_secrets.entra_status(db, s)["stored"]:
        raise HTTPException(404, "No client secret is stored in Orion")
    if auth_config.stored(db)["provider"] == "entra" and not s.oidc_client_secret:
        raise HTTPException(409, "The active Entra sign-in would have no client secret left: enter a new one, or set "
                                 "ORION_OIDC_CLIENT_SECRET on the server, before removing this one")
    auth_secrets.remove_entra(db)
    audit.record(db, "auth.entra_secret.remove", actor=actor, resource_type="settings", resource_id="auth",
                 detail={"fallback": "server" if s.oidc_client_secret else "none"})
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
