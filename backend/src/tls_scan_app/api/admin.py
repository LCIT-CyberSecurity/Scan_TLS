"""Administration: users and roles, audit log, system settings, diagnostics."""
from __future__ import annotations

import secrets
import shutil
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.api.auth import user_payload
from tls_scan_app.api.common import get_or_404
from tls_scan_app.auth.passwords import hash_password
from tls_scan_app.database import database_is_ready
from tls_scan_app.deps import get_db, require_role
from tls_scan_app.models import AuditEvent, Role, ScanRun, Session, SystemSetting, User
from tls_scan_app.models.scan import ACTIVE_STATUSES
from tls_scan_app.services import audit

router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_only = require_role(Role.ADMIN)

DEFAULT_SETTINGS = {
    "retention": {"reports_days": 365, "runs_days": 730, "audit_days": 1095},
    "notifications": {"connector": "none", "smtp": {"host": "", "port": 587, "starttls": True, "username": "", "from": ""}},
}


class UserBody(BaseModel):
    email: EmailStr
    display_name: str = ""
    role: Role = Role.USER


class RoleBody(BaseModel):
    role: Role
    active: bool | None = None


@router.get("/users")
def list_users(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    return [user_payload(u) | {"active": u.active, "issuer": u.issuer, "last_login_at": u.last_login_at}
            for u in db.execute(select(User).order_by(User.email)).scalars()]


@router.post("/users", status_code=201)
def create_user(body: UserBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    """Create a local account with a one-time password (shown once); the user must change it at first login."""
    email = body.email.lower()
    if db.execute(select(User).where(func.lower(User.email) == email)).first():
        raise HTTPException(409, "A user with this e-mail already exists")
    temp = secrets.token_urlsafe(15)
    user = User(issuer="local:user", subject=email, email=email, display_name=body.display_name or email,
                password_hash=hash_password(temp), must_change_password=True, role=body.role)
    db.add(user)
    db.flush()
    audit.record(db, "user.create", actor=actor, resource_type="user", resource_id=user.id, detail={"email": email, "role": str(body.role)})
    db.commit()
    return {"user": user_payload(user), "temporary_password": temp}


@router.put("/users/{user_id}")
def update_user(user_id: uuid.UUID, body: RoleBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    user = get_or_404(db, User, user_id, "User")
    admins = db.scalar(select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.active.is_(True)))
    demoting = user.role == Role.ADMIN and (body.role != Role.ADMIN or body.active is False)
    if demoting and admins <= 1:
        raise HTTPException(409, "At least one active administrator is required")
    previous = str(user.role)
    user.role = body.role
    if body.active is not None:
        user.active = body.active
        if not body.active:
            for s in db.execute(select(Session).where(Session.user_id == user.id, Session.revoked_at.is_(None))).scalars():
                s.revoked_at = datetime.now().astimezone()
    audit.record(db, "user.role_change", actor=actor, resource_type="user", resource_id=user.id,
                 detail={"from": previous, "to": str(body.role), "active": user.active})
    db.commit()
    return user_payload(user)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: uuid.UUID, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    user = get_or_404(db, User, user_id, "User")
    if user.password_hash is None:
        raise HTTPException(409, "This account signs in through SSO")
    temp = secrets.token_urlsafe(15)
    user.password_hash, user.must_change_password = hash_password(temp), True
    audit.record(db, "user.password_reset", actor=actor, resource_type="user", resource_id=user.id)
    db.commit()
    return {"temporary_password": temp}


@router.get("/audit")
def audit_log(action: str | None = None, actor: str | None = None, limit: int = 200, offset: int = 0,
              db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> list[dict]:
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(min(limit, 1000)).offset(offset)
    if action:
        stmt = stmt.where(AuditEvent.action.like(f"{action}%"))
    if actor:
        stmt = stmt.where(AuditEvent.actor_label.ilike(f"%{actor}%"))
    return [{"id": str(e.id), "created_at": e.created_at, "actor": e.actor_label, "action": e.action, "resource_type": e.resource_type,
             "resource_id": e.resource_id, "outcome": e.outcome, "detail": e.detail, "ip_address": e.ip_address}
            for e in db.execute(stmt).scalars()]


@router.get("/settings")
def get_settings_(db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    stored = {s.key: s.value for s in db.execute(select(SystemSetting)).scalars()}
    return {k: stored.get(k, v) for k, v in DEFAULT_SETTINGS.items()}


class SettingBody(BaseModel):
    value: dict = Field(default_factory=dict)


@router.put("/settings/{key}")
def put_setting(key: str, body: SettingBody, db: DbSession = Depends(get_db), actor: User = Depends(admin_only)) -> dict:
    if key not in DEFAULT_SETTINGS:
        raise HTTPException(404, "Unknown setting")
    if key == "retention":
        for field in DEFAULT_SETTINGS["retention"]:
            v = body.value.get(field)
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise HTTPException(422, f"{field} must be a positive number of days")
    row = db.get(SystemSetting, key) or SystemSetting(key=key, value={})
    row.value = body.value
    db.add(row)
    audit.record(db, "settings.update", actor=actor, resource_type="settings", resource_id=key)
    db.commit()
    return {key: row.value}


@router.get("/diagnostics")
def diagnostics(request: Request, db: DbSession = Depends(get_db), _: User = Depends(admin_only)) -> dict:
    settings = request.app.state.settings
    usage = shutil.disk_usage(settings.storage_root) if __import__("os").path.isdir(settings.storage_root) else None
    return {
        "database": database_is_ready(request.app.state.engine),
        "nmap": shutil.which("nmap") is not None,
        "openssl": shutil.which("openssl") is not None,
        "storage_free_gb": round(usage.free / 1e9, 1) if usage else None,
        "active_runs": db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.status.in_(ACTIVE_STATUSES))),
        "limits": {"max_concurrent_scans": settings.max_concurrent_scans, "max_scan_duration_seconds": settings.max_scan_duration_seconds,
                   "max_addresses_per_scan": settings.max_targets_per_scan},
        "sso_configured": bool(settings.oidc_issuer),
        "environment": settings.environment,
    }


@router.get("/failed-runs")
def failed_runs(db: DbSession = Depends(get_db), _: User = Depends(require_role(Role.OPERATOR))) -> list[dict]:
    """Execution errors, for OPERATOR+ troubleshooting."""
    rows = db.execute(select(ScanRun).where(ScanRun.status.in_(("failed", "expired", "partial"))).order_by(ScanRun.queued_at.desc()).limit(100)).scalars()
    return [{"id": str(r.id), "name": r.name, "status": r.status, "error": r.error, "phase": r.phase, "queued_at": r.queued_at} for r in rows]
