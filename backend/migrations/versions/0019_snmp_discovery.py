"""Persist SNMP discovery previews before explicit cartography enrichment."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0019_snmp_discovery"
down_revision = "0018_ssh_audit"
branch_labels = None
depends_on = None
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "snmp_discoveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("requested_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("target_ids", JSON, nullable=False),
        sa.Column("options", JSON, nullable=False),
        sa.Column("result", JSON),
        sa.Column("status", sa.String(12), nullable=False, server_default="queued"),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_snmp_discoveries_status", "snmp_discoveries", ["status"])


def downgrade() -> None:
    op.drop_index("ix_snmp_discoveries_status", table_name="snmp_discoveries")
    op.drop_table("snmp_discoveries")
