"""Greenbone import history and stable source mappings.

Revision ID: 0012
Revises: 0011
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "greenbone_imports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("source_name", sa.String(160), nullable=False),
        sa.Column("requested_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("snapshot", JSON),
        sa.Column("result", JSON),
        sa.Column("progress", JSON),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_greenbone_imports_status", "greenbone_imports", ["status"])
    op.create_table(
        "greenbone_object_links",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("source_id", sa.String(255), nullable=False),
        sa.Column("object_type", sa.String(24), nullable=False),
        sa.Column("external_id", sa.String(128), nullable=False),
        sa.Column("tls_id", sa.String(128), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("source_id", "object_type", "external_id", name="uq_greenbone_source_object"),
    )


def downgrade() -> None:
    op.drop_table("greenbone_object_links")
    op.drop_index("ix_greenbone_imports_status", table_name="greenbone_imports")
    op.drop_table("greenbone_imports")
