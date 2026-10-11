"""Organisation, SI / sub-SI, tags, targets and target groups.

SI, sub-SI and tags are classification only (no access control). They attach to targets, groups and
scan definitions through the polymorphic `resource_tags` / `resource_si` tables, so one target
can belong to several groupings without duplication.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from tls_scan_app.database import Base, JsonType


class Organization(Base):
    __tablename__ = "organization"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)  # single row per installation
    name: Mapped[str] = mapped_column(String(255), default="My organization")


class InformationSystem(Base):
    """An SI, or a sub-SI when parent_id is set (one level)."""

    __tablename__ = "information_systems"
    __table_args__ = (UniqueConstraint("parent_id", "name", name="uq_si_parent_name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    parent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("information_systems.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(60), unique=True)
    color: Mapped[str] = mapped_column(String(9), default="")


class ResourceTag(Base):
    __tablename__ = "resource_tags"
    __table_args__ = (Index("ix_resource_tags_resource", "resource_type", "resource_id"),)

    resource_type: Mapped[str] = mapped_column(String(20), primary_key=True)  # target|group|definition
    resource_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tag_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)


class ResourceSI(Base):
    __tablename__ = "resource_si"
    __table_args__ = (Index("ix_resource_si_resource", "resource_type", "resource_id"),)

    resource_type: Mapped[str] = mapped_column(String(20), primary_key=True)
    resource_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    si_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("information_systems.id", ondelete="CASCADE"), primary_key=True
    )


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("value", "ports", name="uq_target_value_ports"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160), default="", server_default="")  # display label; the value stays the identity
    value: Mapped[str] = mapped_column(String(255))  # fqdn, ip or cidr (normalised lower-case)
    kind: Mapped[str] = mapped_column(String(10))  # fqdn | ip | cidr
    ports: Mapped[str] = mapped_column(String(120), default="")  # "" = use the profile's ports
    description: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TargetGroup(Base):
    __tablename__ = "target_groups"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TargetGroupMember(Base):
    __tablename__ = "target_group_members"

    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("target_groups.id", ondelete="CASCADE"), primary_key=True)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True)


class DnsDiscovery(Base):
    """A DNS discovery request for one domain (name-server lookup + zone-transfer attempt), run by the worker.

    The result is a suggestion list: nothing becomes a target until the user adds it.
    """

    __tablename__ = "dns_discoveries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    domain: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(10), default="queued", index=True)  # queued | running | done | failed
    result: Mapped[dict | None] = mapped_column(JsonType)
    error: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
