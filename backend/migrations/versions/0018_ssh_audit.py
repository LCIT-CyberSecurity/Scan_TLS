"""Add SSH audit and extend generic profiles/policies to SSH.

Revision ID: 0018_ssh_audit
Revises: 0017_generic_scan_profiles
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
revision = "0018_ssh_audit"
down_revision = "0017_generic_scan_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_policies_technology", "policies", type_="check")
    op.create_check_constraint("ck_policies_technology", "policies", "technology IN ('tls', 'ipsec', 'ssh')")
    op.drop_constraint("ck_scan_profiles_technology", "scan_profiles", type_="check")
    op.create_check_constraint("ck_scan_profiles_technology", "scan_profiles", "technology IN ('tls', 'ipsec', 'generic')")
    op.create_table(
        "run_ssh_observations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False, server_default="indeterminate"),
        sa.Column("banner", sa.String(255), nullable=False, server_default=""),
        sa.Column("algorithms", JSON, nullable=False),
        sa.Column("host_keys", JSON, nullable=False),
        sa.Column("fingerprints", JSON, nullable=False),
        sa.Column("evidence", JSON, nullable=False),
        sa.CheckConstraint("status IN ('observed','timeout','filtered','error')", name="ck_ssh_observation_status"),
        sa.CheckConstraint("verdict IN ('compliant','non_compliant','indeterminate')", name="ck_ssh_observation_verdict"),
    )
    op.create_index("ix_run_ssh_observations_run_id", "run_ssh_observations", ["run_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM policies WHERE technology = 'ssh'")).scalar_one() \
            or bind.execute(sa.text("SELECT COUNT(*) FROM run_ssh_observations")).scalar_one():
        raise RuntimeError("Cannot downgrade while SSH policies or observations exist")
    op.drop_index("ix_run_ssh_observations_run_id", table_name="run_ssh_observations")
    op.drop_table("run_ssh_observations")
    op.drop_constraint("ck_policies_technology", "policies", type_="check")
    op.create_check_constraint("ck_policies_technology", "policies", "technology IN ('tls', 'ipsec')")
    op.drop_constraint("ck_scan_profiles_technology", "scan_profiles", type_="check")
    op.create_check_constraint("ck_scan_profiles_technology", "scan_profiles", "technology IN ('tls', 'ipsec', 'generic')")
