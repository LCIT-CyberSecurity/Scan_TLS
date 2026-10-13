"""Scan definitions, schedules and runs (+ structured results)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from tls_scan_app.database import Base, JsonType

# Run statuses
SCHEDULED, QUEUED, RUNNING = "scheduled", "queued", "running"
COMPLETED, PARTIAL, FAILED, CANCELLED, EXPIRED = "completed", "partial", "failed", "cancelled", "expired"
ACTIVE_STATUSES = (QUEUED, RUNNING)
FINAL_STATUSES = (COMPLETED, PARTIAL, FAILED, CANCELLED, EXPIRED)


class ScanDefinition(Base):
    __tablename__ = "scan_definitions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_profiles.id"))
    report_template_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("report_templates.id", ondelete="SET NULL"))
    policy_mode: Mapped[str] = mapped_column(String(20), default="strict_all")
    exclusions: Mapped[list | None] = mapped_column(JsonType)  # hosts, networks and names this scan never touches (IP, CIDR, FQDN, *.domain)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class DefinitionTarget(Base):
    __tablename__ = "definition_targets"

    definition_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_definitions.id", ondelete="CASCADE"), primary_key=True)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id"), primary_key=True)


class DefinitionGroup(Base):
    __tablename__ = "definition_groups"

    definition_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_definitions.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("target_groups.id"), primary_key=True)


class DefinitionPolicy(Base):
    """Policies applied by a definition; the latest published version is resolved at run time."""

    __tablename__ = "definition_policies"

    definition_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_definitions.id", ondelete="CASCADE"), primary_key=True)
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("policies.id"), primary_key=True)


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    definition_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_definitions.id", ondelete="CASCADE"), index=True)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(10))  # once | daily | weekly | monthly | cron
    # once: {at}; daily: {time}; weekly: {time, weekday 0-6}; monthly: {time, day 1-28}; cron: {expr}
    params: Mapped[dict] = mapped_column(JsonType)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    active: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScheduleTrigger(Base):
    """History of every due occurrence: triggered, skipped (overlap) or missed (downtime)."""

    __tablename__ = "schedule_triggers"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    schedule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_schedules.id", ondelete="CASCADE"), index=True)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    outcome: Mapped[str] = mapped_column(String(20))  # triggered | skipped_overlap | skipped_late | error
    reason: Mapped[str] = mapped_column(Text, default="")
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"))
    __table_args__ = (UniqueConstraint("schedule_id", "due_at", name="uq_trigger_schedule_due"),)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        # At most one active (queued/running) run per fingerprint: the DB enforces dedup under concurrency.
        Index(
            "uq_scan_runs_active_fingerprint",
            "fingerprint",
            unique=True,
            postgresql_where=text("status IN ('queued','running')"),
            sqlite_where=text("status IN ('queued','running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    definition_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_definitions.id", ondelete="SET NULL"), index=True)
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_schedules.id", ondelete="SET NULL"), index=True)
    name: Mapped[str] = mapped_column(String(160), default="")
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    status: Mapped[str] = mapped_column(String(12), default=QUEUED, index=True)
    phase: Mapped[str] = mapped_column(String(30), default="")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    # Exact configuration used (targets, ports, profile content+version, policy contents+versions).
    config_snapshot: Mapped[dict] = mapped_column(JsonType)
    policy_versions: Mapped[list] = mapped_column(JsonType, default=list)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    cancel_requested: Mapped[bool] = mapped_column(default=False)
    worker_id: Mapped[str | None] = mapped_column(String(80))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[dict | None] = mapped_column(JsonType)  # ReportStatistics
    progress: Mapped[dict | None] = mapped_column(JsonType)  # hosts done / total (only when reliable)
    scanned_hosts: Mapped[list | None] = mapped_column(JsonType)
    skipped_hosts: Mapped[list | None] = mapped_column(JsonType)
    report_dir: Mapped[str] = mapped_column(String(500), default="")
    report_files: Mapped[list | None] = mapped_column(JsonType)  # [{format,path,sha256,size}]


class ScanRunRequester(Base):
    """Everybody who asked for (or was attached to) a run, including deduplicated requests."""

    __tablename__ = "scan_run_requesters"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class RunEndpoint(Base):
    __tablename__ = "run_endpoints"
    __table_args__ = (UniqueConstraint("run_id", "endpoint_id", name="uq_run_endpoint"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[str] = mapped_column(String(120))  # ip:port/tcp
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[str] = mapped_column(String(10), default="")
    grade: Mapped[str] = mapped_column(String(4), default="")
    compliance_status: Mapped[str] = mapped_column(String(40), default="")
    highest_severity: Mapped[str] = mapped_column(String(20), default="")
    supported_tls_versions: Mapped[list] = mapped_column(JsonType, default=list)
    cipher_suites: Mapped[list] = mapped_column(JsonType, default=list)
    certificate: Mapped[dict] = mapped_column(JsonType, default=dict)
    errors: Mapped[list] = mapped_column(JsonType, default=list)
    untested_checks: Mapped[list] = mapped_column(JsonType, default=list)
    # complementary TLS checks (tls_scanner.checks): [{check_id, status, message, observations, evidence, duration_ms}]
    tls_checks: Mapped[list] = mapped_column(JsonType, default=list)


class RunFinding(Base):
    __tablename__ = "run_findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(160))
    title: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(80), default="")
    severity: Mapped[str] = mapped_column(String(20), default="")
    status: Mapped[str] = mapped_column(String(40), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    affected_endpoint_ids: Mapped[list] = mapped_column(JsonType, default=list)
