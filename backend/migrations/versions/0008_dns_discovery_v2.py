"""DNS discovery V2: options, progress, cancellation, and the DNS observations kept per target

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("dns_discoveries", sa.Column("options", JSON, nullable=True))
    op.add_column("dns_discoveries", sa.Column("progress", JSON, nullable=True))
    op.add_column("dns_discoveries", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("dns_discoveries", sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "target_dns_observations",
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("ips", JSON, nullable=False),
        sa.Column("cnames", JSON, nullable=False),
        sa.Column("sources", JSON, nullable=False),
        sa.Column("last_discovery_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("target_dns_observations")
    for column in ("cancel_requested", "heartbeat_at", "progress", "options"):
        op.drop_column("dns_discoveries", column)
