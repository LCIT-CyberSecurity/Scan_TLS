from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from tls_scan_app.database import Base


class Role(enum.StrEnum):
    """Global roles (no per-SI scoping). Linear hierarchy: each role holds the rights of the previous."""

    AUDITOR = "AUDITOR"
    USER = "USER"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


ROLE_RANK = {Role.AUDITOR: 1, Role.USER: 2, Role.OPERATOR: 3, Role.ADMIN: 4}


def role_at_least(role: Role | str, minimum: Role) -> bool:
    return ROLE_RANK[Role(role)] >= ROLE_RANK[minimum]


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_users_issuer_subject"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str | None] = mapped_column(String(255))
    must_change_password: Mapped[bool] = mapped_column(default=False)
    role: Mapped[Role] = mapped_column(String(20), default=Role.USER)
    active: Mapped[bool] = mapped_column(default=True)
    # Preferences (language wins over browser detection once set; null = follow the browser).
    locale: Mapped[str | None] = mapped_column(String(5))
    theme: Mapped[str] = mapped_column(String(10), default="system")
    palette: Mapped[str] = mapped_column(String(20), default="default")
    notify_events: Mapped[str | None] = mapped_column(String(255))  # comma list; null = defaults
    # External access (independent of the role, off for everyone including administrators until granted).
    api_access_enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    mcp_access_enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Session(Base):
    """Server-side session; only the SHA-256 of the opaque token is stored."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AccessToken(Base):
    """Personal API token (service "api", prefix tls_scan_pat_) or MCP key (service "mcp", prefix tls_scan_mcp_).

    Only the SHA-256 of the secret is stored. One non-revoked key per user and service (partial unique index).
    """

    __tablename__ = "access_tokens"
    __table_args__ = (
        Index("uq_access_tokens_active", "user_id", "service", unique=True, postgresql_where=text("revoked_at IS NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    service: Mapped[str] = mapped_column(String(3))  # api | mcp
    prefix: Mapped[str] = mapped_column(String(20))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
