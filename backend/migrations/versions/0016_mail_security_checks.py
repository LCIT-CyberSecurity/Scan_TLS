"""Add optional mail-security controls and immutable results to TLS scan definitions/runs.

Revision ID: 0016_mail_security_checks
Revises: 0015
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0016_mail_security_checks"
down_revision = "0015"
branch_labels = None
depends_on = None


def _json_type():
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade():
    op.add_column("scan_definitions", sa.Column("mail_security", _json_type(), nullable=True))
    op.add_column("scan_runs", sa.Column("mail_security_results", _json_type(), nullable=True))


def downgrade():
    op.drop_column("scan_runs", "mail_security_results")
    op.drop_column("scan_definitions", "mail_security")
