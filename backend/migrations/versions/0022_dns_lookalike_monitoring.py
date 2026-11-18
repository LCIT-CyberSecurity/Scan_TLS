"""Add explicitly disabled, per-domain DNS lookalike monitors."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0022_dns_lookalike_monitoring"
down_revision = "0021_quic_observations"
branch_labels = None
depends_on = None
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "dns_lookalike_monitors",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("options", JSON, nullable=False),
        sa.Column("schedule_id", sa.Uuid(), sa.ForeignKey("scan_schedules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_dns_lookalike_monitors_domain", "dns_lookalike_monitors", ["domain"])
    op.create_index("ix_dns_lookalike_monitors_owner_id", "dns_lookalike_monitors", ["owner_id"])
    op.create_index("ix_dns_lookalike_monitors_enabled", "dns_lookalike_monitors", ["enabled"])
    op.create_index("ix_dns_lookalike_monitors_schedule_id", "dns_lookalike_monitors", ["schedule_id"])


def downgrade() -> None:
    op.drop_index("ix_dns_lookalike_monitors_schedule_id", table_name="dns_lookalike_monitors")
    op.drop_index("ix_dns_lookalike_monitors_enabled", table_name="dns_lookalike_monitors")
    op.drop_index("ix_dns_lookalike_monitors_owner_id", table_name="dns_lookalike_monitors")
    op.drop_index("ix_dns_lookalike_monitors_domain", table_name="dns_lookalike_monitors")
    op.drop_table("dns_lookalike_monitors")
