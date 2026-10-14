from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from tls_scan_app.database import Base, JsonType


class NetworkZone(Base):
    """User-declared network classification; it is not a discovered network boundary."""

    __tablename__ = "network_zones"
    __table_args__ = (
        UniqueConstraint("parent_zone_id", "name", name="uq_network_zone_parent_name"),
        CheckConstraint("parent_zone_id IS NULL OR parent_zone_id != id", name="ck_network_zone_not_own_parent"),
        Index("uq_network_zone_root_name", "name", unique=True, postgresql_where=text("parent_zone_id IS NULL"), sqlite_where=text("parent_zone_id IS NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    zone_type: Mapped[str] = mapped_column(String(40), default="custom")
    parent_zone_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("network_zones.id", ondelete="SET NULL"), index=True)
    cidr: Mapped[str | None] = mapped_column(String(64))
    presentation: Mapped[dict | None] = mapped_column(JsonType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class NetworkZoneSystem(Base):
    __tablename__ = "network_zone_systems"

    zone_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("network_zones.id", ondelete="CASCADE"), primary_key=True)
    si_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("information_systems.id", ondelete="CASCADE"), primary_key=True)


class NetworkZoneTarget(Base):
    __tablename__ = "network_zone_targets"

    zone_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("network_zones.id", ondelete="CASCADE"), primary_key=True)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True)
    primary_placement: Mapped[bool] = mapped_column(default=False, server_default="false")


class NetworkDevice(Base):
    __tablename__ = "network_devices"
    __table_args__ = (
        Index("ix_network_devices_zone", "zone_id"),
        CheckConstraint("provenance IN ('DECLARED', 'OBSERVED', 'INFERRED')", name="ck_network_device_provenance"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_network_device_confidence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160))
    device_type: Mapped[str] = mapped_column(String(40), default="generic")
    zone_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("network_zones.id", ondelete="SET NULL"))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"))
    provenance: Mapped[str] = mapped_column(String(12), default="DECLARED")
    source: Mapped[str] = mapped_column(String(255), default="")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confidence: Mapped[float | None]
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JsonType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class NetworkLink(Base):
    """Explicit device-to-device link with source and confidence; no connectivity is inferred by the scanner."""

    __tablename__ = "network_links"
    __table_args__ = (
        UniqueConstraint("source_device_id", "target_device_id", "link_type", name="uq_network_link_devices_type"),
        Index("ix_network_links_target", "target_device_id"),
        CheckConstraint("source_device_id != target_device_id", name="ck_network_link_distinct_devices"),
        CheckConstraint("provenance IN ('DECLARED', 'OBSERVED', 'INFERRED')", name="ck_network_link_provenance"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_network_link_confidence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    target_device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"))
    link_type: Mapped[str] = mapped_column(String(40), default="network")
    provenance: Mapped[str] = mapped_column(String(12), default="DECLARED")
    source: Mapped[str] = mapped_column(String(255), default="")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confidence: Mapped[float | None]
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
