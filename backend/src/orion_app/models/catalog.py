"""Organisation, SI / sub-SI, tags, targets and target groups.

SI, sub-SI and tags are classification only (no access control). They attach to targets, groups and
scan definitions through the polymorphic `resource_tags` / `resource_si` tables, so one target
can belong to several groupings without duplication.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from orion_app.database import Base, JsonType


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


class EndpointExposure(Base):
    """Evidence-backed Internet reachability context for a target protocol and port."""

    __tablename__ = "endpoint_exposures"
    __table_args__ = (UniqueConstraint("target_id", "protocol", "port", "sni", name="uq_endpoint_exposure_target_protocol_port_sni"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(12))  # tls | ipsec | ssh
    port: Mapped[int] = mapped_column(Integer)
    sni: Mapped[str] = mapped_column(String(255), default="")
    state: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown")
    zone_context: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown")
    evidence_method: Mapped[str] = mapped_column(String(40), default="")
    source: Mapped[str] = mapped_column(String(255), default="")
    justification: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(12), default="unknown", server_default="unknown")
    validated: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    recorded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


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
    # V2: what was asked (methods, resolver, dictionary...), live progress, liveness and cancellation. All nullable: historical rows are untouched.
    options: Mapped[dict | None] = mapped_column(JsonType)
    progress: Mapped[dict | None] = mapped_column(JsonType)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested: Mapped[bool] = mapped_column(default=False, server_default="false")


class DnsLookalikeMonitor(Base):
    """Explicitly enabled, per-domain lookalike monitoring; disabled and silent by default."""

    __tablename__ = "dns_lookalike_monitors"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    domain: Mapped[str] = mapped_column(String(253), index=True)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    enabled: Mapped[bool] = mapped_column(default=False, server_default="false", index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    options: Mapped[dict] = mapped_column(JsonType, default=dict)
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_schedules.id", ondelete="SET NULL"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TargetDnsObservation(Base):
    """What DNS discoveries observed about a target's FQDN. Technical, additive and bounded; never edits the target's own (manual) fields."""

    __tablename__ = "target_dns_observations"

    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True)
    ips: Mapped[list] = mapped_column(JsonType, default=list)        # [{ip, first_seen, last_seen}]
    cnames: Mapped[list] = mapped_column(JsonType, default=list)     # [{name, first_seen, last_seen}]
    sources: Mapped[list] = mapped_column(JsonType, default=list)    # [{method, zone, discovery_id, at, detail}]
    last_discovery_id: Mapped[uuid.UUID | None] = mapped_column()
    created_discovery_id: Mapped[uuid.UUID | None] = mapped_column()  # set only when a discovery created the target (not when it enriched it)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class GreenboneImport(Base):
    """A bounded import snapshot and its user-visible processing history."""

    __tablename__ = "greenbone_imports"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)
    mode: Mapped[str] = mapped_column(String(8))  # gmp | xml
    source_name: Mapped[str] = mapped_column(String(160), default="")
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    snapshot: Mapped[dict | None] = mapped_column(JsonType)
    result: Mapped[dict | None] = mapped_column(JsonType)
    progress: Mapped[dict | None] = mapped_column(JsonType)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class GreenboneObjectLink(Base):
    """Stable source-to-Orion mapping; tags are presentation, never provenance."""

    __tablename__ = "greenbone_object_links"
    __table_args__ = (UniqueConstraint("source_id", "object_type", "external_id", name="uq_greenbone_source_object"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_id: Mapped[str] = mapped_column(String(255))
    object_type: Mapped[str] = mapped_column(String(24))
    external_id: Mapped[str] = mapped_column(String(128))
    tls_id: Mapped[str] = mapped_column(String(128))
    mode: Mapped[str] = mapped_column(String(8))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
