"""Separate TLS and IPsec profiles, policies, definitions and evidence.

Revision ID: 0014
Revises: 0013
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("policies", sa.Column("technology", sa.String(12), server_default="tls", nullable=False))
    op.add_column("scan_profiles", sa.Column("technology", sa.String(12), server_default="tls", nullable=False))
    op.add_column("scan_definitions", sa.Column("control_type", sa.String(12), server_default="tls", nullable=False))
    op.create_check_constraint("ck_policies_technology", "policies", "technology IN ('tls', 'ipsec')")
    op.create_check_constraint("ck_scan_profiles_technology", "scan_profiles", "technology IN ('tls', 'ipsec')")
    op.create_check_constraint("ck_scan_definitions_control_type", "scan_definitions", "control_type IN ('tls', 'ipsec')")
    op.create_table(
        "run_ipsec_observations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("ike_version", sa.String(8), nullable=False, server_default=""),
        sa.Column("exchange", sa.String(32), nullable=False, server_default=""),
        sa.Column("proposal", JSON, nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False, server_default="indeterminate"),
        sa.Column("evidence", JSON, nullable=False),
        sa.CheckConstraint("status IN ('observed','indeterminate','timeout','filtered','error')", name="ck_ipsec_observation_status"),
        sa.CheckConstraint("verdict IN ('compliant','non_compliant','indeterminate')", name="ck_ipsec_observation_verdict"),
    )
    op.create_index("ix_run_ipsec_observations_run_id", "run_ipsec_observations", ["run_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM policies WHERE technology = 'ipsec'")).scalar_one() \
            or bind.execute(sa.text("SELECT COUNT(*) FROM scan_profiles WHERE technology = 'ipsec'")).scalar_one() \
            or bind.execute(sa.text("SELECT COUNT(*) FROM scan_definitions WHERE control_type = 'ipsec'")).scalar_one() \
            or bind.execute(sa.text("SELECT COUNT(*) FROM run_ipsec_observations")).scalar_one():
        raise RuntimeError("Cannot downgrade while IPsec profiles, policies, definitions or observations exist")
    op.drop_index("ix_run_ipsec_observations_run_id", table_name="run_ipsec_observations")
    op.drop_table("run_ipsec_observations")
    op.drop_constraint("ck_scan_definitions_control_type", "scan_definitions", type_="check")
    op.drop_constraint("ck_scan_profiles_technology", "scan_profiles", type_="check")
    op.drop_constraint("ck_policies_technology", "policies", type_="check")
    op.drop_column("scan_definitions", "control_type")
    op.drop_column("scan_profiles", "technology")
    op.drop_column("policies", "technology")
