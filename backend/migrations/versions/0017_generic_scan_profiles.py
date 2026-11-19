"""Enable generic multi-technology profiles without changing legacy definitions.

Revision ID: 0017_generic_scan_profiles
Revises: 0016_mail_security_checks
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

revision = "0017_generic_scan_profiles"
down_revision = "0016_mail_security_checks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_scan_profiles_technology", "scan_profiles", type_="check")
    op.create_check_constraint("ck_scan_profiles_technology", "scan_profiles", "technology IN ('tls', 'ipsec', 'generic')")
    op.add_column("scan_definitions", sa.Column("enabled_controls", JSON, nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM scan_profiles WHERE technology = 'generic'")).scalar_one():
        raise RuntimeError("Cannot downgrade while generic scan profiles exist")
    if bind.execute(sa.text("SELECT COUNT(*) FROM scan_definitions WHERE enabled_controls IS NOT NULL")).scalar_one():
        raise RuntimeError("Cannot downgrade while multi-control scan definitions exist")
    op.drop_column("scan_definitions", "enabled_controls")
    op.drop_constraint("ck_scan_profiles_technology", "scan_profiles", type_="check")
    op.create_check_constraint("ck_scan_profiles_technology", "scan_profiles", "technology IN ('tls', 'ipsec')")
