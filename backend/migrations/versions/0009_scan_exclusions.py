"""Exclusions on scan definitions

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # nullable: existing definitions simply have no exclusion (their scans are unchanged)
    op.add_column("scan_definitions", sa.Column("exclusions", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_definitions", "exclusions")
