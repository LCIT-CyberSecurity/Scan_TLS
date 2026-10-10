from __future__ import annotations

from collections.abc import Callable, Generator
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from tls_scan_app.auth.tokens import CSRF_HEADER, SESSION_COOKIE, hash_session_token
from tls_scan_app.config import Settings
from tls_scan_app.models import Role, Session, User
from tls_scan_app.models.user import role_at_least

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def ensure_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def get_db(request: Request) -> Generator[DbSession]:
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def get_current_session(request: Request, db: DbSession = Depends(get_db)) -> Session:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    session = db.execute(select(Session).where(Session.session_token_hash == hash_session_token(raw))).scalar_one_or_none()
    settings: Settings = request.app.state.settings
    now = datetime.now(UTC)
    if (
        session is None
        or session.revoked_at is not None
        or ensure_utc(session.expires_at) < now
        or ensure_utc(session.last_activity_at) < now - timedelta(minutes=settings.session_idle_timeout_minutes)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired or invalid")
    # CSRF: the cookie is SameSite=Lax; state-changing requests must also echo the per-session token.
    if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != session.csrf_token:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")
    session.last_activity_at = now
    db.commit()
    return session


def get_current_user(session: Session = Depends(get_current_session), db: DbSession = Depends(get_db)) -> User:
    user = db.get(User, session.user_id)
    if user is None or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user


def require_role(minimum: Role) -> Callable[..., User]:
    """Backend-enforced RBAC: deny unless the user's role is at least `minimum`.

    A user who must still change their initial password cannot do anything else.
    """

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.must_change_password:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Password change required")
        if not role_at_least(user.role, minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return dependency


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""
