"""DNS discovery requests (name servers + zone-transfer attempt)

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dns_discoveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="queued"),
        sa.Column("result", sa.JSON().with_variant(postgresql.JSONB(), "postgresql")),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("requested_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_dns_discoveries_status", "dns_discoveries", ["status"])


def downgrade() -> None:
    op.drop_index("ix_dns_discoveries_status", table_name="dns_discoveries")
    op.drop_table("dns_discoveries")
