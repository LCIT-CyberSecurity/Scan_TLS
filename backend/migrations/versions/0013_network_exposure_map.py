"""Declared network map zones, devices and links.

Revision ID: 0013
Revises: 0012
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "network_zones",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("zone_type", sa.String(40), nullable=False),
        sa.Column("parent_zone_id", sa.Uuid(), sa.ForeignKey("network_zones.id", ondelete="SET NULL")),
        sa.Column("cidr", sa.String(64)),
        sa.Column("presentation", JSON),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("parent_zone_id", "name", name="uq_network_zone_parent_name"),
        sa.CheckConstraint("parent_zone_id IS NULL OR parent_zone_id != id", name="ck_network_zone_not_own_parent"),
    )
    op.create_index("ix_network_zones_parent_zone_id", "network_zones", ["parent_zone_id"])
    op.create_index("uq_network_zone_root_name", "network_zones", ["name"], unique=True, postgresql_where=sa.text("parent_zone_id IS NULL"), sqlite_where=sa.text("parent_zone_id IS NULL"))
    op.create_table(
        "network_zone_systems",
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("network_zones.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("si_id", sa.Uuid(), sa.ForeignKey("information_systems.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "network_zone_targets",
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("network_zones.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("primary_placement", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "network_devices",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("device_type", sa.String(40), nullable=False),
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("network_zones.id", ondelete="SET NULL")),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id", ondelete="SET NULL")),
        sa.Column("provenance", sa.String(12), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("confidence", sa.Float()),
        sa.Column("metadata", JSON),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("provenance IN ('DECLARED', 'OBSERVED', 'INFERRED')", name="ck_network_device_provenance"),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_network_device_confidence"),
    )
    op.create_index("ix_network_devices_zone", "network_devices", ["zone_id"])
    op.create_table(
        "network_links",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("source_device_id", sa.Uuid(), sa.ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_device_id", sa.Uuid(), sa.ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("link_type", sa.String(40), nullable=False),
        sa.Column("provenance", sa.String(12), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("confidence", sa.Float()),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("source_device_id", "target_device_id", "link_type", name="uq_network_link_devices_type"),
        sa.CheckConstraint("source_device_id != target_device_id", name="ck_network_link_distinct_devices"),
        sa.CheckConstraint("provenance IN ('DECLARED', 'OBSERVED', 'INFERRED')", name="ck_network_link_provenance"),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_network_link_confidence"),
    )
    op.create_index("ix_network_links_target", "network_links", ["target_device_id"])


def downgrade() -> None:
    op.drop_table("network_links")
    op.drop_index("ix_network_devices_zone", table_name="network_devices")
    op.drop_table("network_devices")
    op.drop_table("network_zone_targets")
    op.drop_table("network_zone_systems")
    op.drop_index("ix_network_zones_parent_zone_id", table_name="network_zones")
    op.drop_index("uq_network_zone_root_name", table_name="network_zones")
    op.drop_table("network_zones")
