"""Administered trust stores (private PKI). Versions are immutable: a scan snapshot references the exact version.

Only public certificates are ever stored. Certificate content lives in PostgreSQL (no file path is ever
accepted from a user, and the worker receives the content through the run snapshot).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from tls_scan_app.database import Base, JsonType

ROLE_ANCHOR, ROLE_INTERMEDIATE = "anchor", "intermediate"


class TrustStore(Base):
    __tablename__ = "trust_stores"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)  # the immutable technical identifier
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TrustStoreVersion(Base):
    __tablename__ = "trust_store_versions"
    __table_args__ = (UniqueConstraint("store_id", "version", name="uq_trust_store_version"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    store_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("trust_stores.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    content_sha256: Mapped[str] = mapped_column(String(64))  # over the sorted (role, fingerprint) pairs
    comment: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TrustStoreCertificate(Base):
    __tablename__ = "trust_store_certificates"
    __table_args__ = (UniqueConstraint("version_id", "fingerprint_sha256", name="uq_trust_store_cert"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("trust_store_versions.id", ondelete="CASCADE"), index=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(12))  # anchor | intermediate
    pem: Mapped[str] = mapped_column(Text)  # public certificate only
    details: Mapped[dict] = mapped_column(JsonType)  # subject, issuer, serial, validity, key, signature, constraints, key usage
