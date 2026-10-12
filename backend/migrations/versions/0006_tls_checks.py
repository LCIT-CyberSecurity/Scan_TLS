"""Complementary TLS checks stored per endpoint

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # nullable: endpoints stored by earlier scans simply have no complementary check (never requalified)
    op.add_column("run_endpoints", sa.Column("tls_checks", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True))


def downgrade() -> None:
    op.drop_column("run_endpoints", "tls_checks")
