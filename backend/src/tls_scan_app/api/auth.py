from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.auth.passwords import hash_password, is_acceptable_for_production, verify_password
from tls_scan_app.auth.tokens import SESSION_COOKIE, new_csrf_token, new_session_token
from tls_scan_app.deps import client_ip, get_current_session, get_current_user, get_db
from tls_scan_app.models import Session, User
from tls_scan_app.services import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


class PasswordBody(BaseModel):
    current_password: str
    new_password: str


def user_payload(user: User) -> dict:
    return {
        "id": str(user.id), "email": user.email, "display_name": user.display_name, "role": str(user.role),
        "must_change_password": user.must_change_password, "locale": user.locale, "theme": user.theme,
        "palette": user.palette, "notify_events": (user.notify_events.split(",") if user.notify_events else []) if user.notify_events is not None else None, "local_account": user.password_hash is not None,
    }


def open_session(db: DbSession, request: Request, response: Response, user: User) -> Session:
    settings = request.app.state.settings
    raw, token_hash = new_session_token()
    session = Session(
        session_token_hash=token_hash, csrf_token=new_csrf_token(), user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=settings.session_absolute_timeout_hours),
    )
    db.add(session)
    user.last_login_at = datetime.now(UTC)
    response.set_cookie(
        SESSION_COOKIE, raw, httponly=True, secure=settings.cookie_secure, samesite="lax",
        max_age=settings.session_absolute_timeout_hours * 3600, path="/",
    )
    return session


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response, db: DbSession = Depends(get_db)) -> dict:
    limiter, settings, ip = request.app.state.limiter, request.app.state.settings, client_ip(request)
    name = body.username.strip().lower()
    # Only FAILED attempts count towards the limit: a legitimate user signing in often is never locked out.
    if settings.rate_limit_enabled and (limiter.count(f"login:ip:{ip}", 300) >= 20 or limiter.count(f"login:user:{name}", 300) >= 5):
        audit.record(db, "auth.login", actor_label=name, outcome="blocked", ip_address=ip)
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try again later")
    user = db.execute(
        select(User).where(func.lower(User.email) == name, User.password_hash.is_not(None))
    ).scalars().first() or db.execute(
        select(User).where(User.subject == name, User.issuer == "builtin:local")
    ).scalars().first()
    ok = verify_password(body.password, user.password_hash if user else None)  # always one verification
    if not (user and user.active and ok):
        limiter.hit(f"login:ip:{ip}")
        limiter.hit(f"login:user:{name}")
        audit.record(db, "auth.login", actor_label=name, outcome="failure", ip_address=ip)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    limiter.reset(f"login:user:{name}")
    session = open_session(db, request, response, user)
    audit.record(db, "auth.login", actor=user, ip_address=ip)
    db.commit()
    return {"user": user_payload(user), "csrf_token": session.csrf_token}


@router.post("/logout")
def logout(session: Session = Depends(get_current_session), user: User = Depends(get_current_user),
           response: Response = None, db: DbSession = Depends(get_db)) -> dict:
    session.revoked_at = datetime.now(UTC)
    audit.record(db, "auth.logout", actor=user)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user), session: Session = Depends(get_current_session)) -> dict:
    return {"user": user_payload(user), "csrf_token": session.csrf_token}


@router.post("/password")
def change_password(body: PasswordBody, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)) -> dict:
    if not user.password_hash or not verify_password(body.current_password, user.password_hash):
        audit.record(db, "auth.password_change", actor=user, outcome="failure")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The new password must differ from the current one")
    problem = is_acceptable_for_production(body.new_password)
    if problem:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Password refused: {problem}")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    audit.record(db, "auth.password_change", actor=user)
    db.commit()
    return {"ok": True}


class PreferencesBody(BaseModel):
    locale: str | None = None
    theme: str | None = None
    palette: str | None = None
    notify_events: list[str] | None = None


@router.patch("/preferences")
def preferences(body: PreferencesBody, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)) -> dict:
    if body.locale is not None:
        if body.locale not in ("fr", "en", "de", ""):
            raise HTTPException(422, "Unsupported language")
        user.locale = body.locale or None
    if body.theme is not None:
        if body.theme not in ("light", "dark", "system"):
            raise HTTPException(422, "Unsupported theme")
        user.theme = body.theme
    if body.notify_events is not None:
        from tls_scan_app.services.notifications import ALL_EVENTS

        if set(body.notify_events) - ALL_EVENTS:
            raise HTTPException(422, "Unknown notification event")
        user.notify_events = ",".join(sorted(body.notify_events))
    if body.palette is not None:
        user.palette = body.palette[:20]
    db.commit()
    return {"user": user_payload(user)}
