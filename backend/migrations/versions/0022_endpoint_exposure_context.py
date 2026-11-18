"""Store evidence-backed endpoint exposure and per-run risk snapshots."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0022_endpoint_exposure_context"
down_revision = "0021_quic_observations"
branch_labels = None
depends_on = None
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "endpoint_exposures",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("protocol", sa.String(12), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("sni", sa.String(255), server_default="", nullable=False),
        sa.Column("state", sa.String(32), server_default="unknown", nullable=False),
        sa.Column("zone_context", sa.String(32), server_default="unknown", nullable=False),
        sa.Column("evidence_method", sa.String(40), server_default="", nullable=False),
        sa.Column("source", sa.String(255), server_default="", nullable=False),
        sa.Column("justification", sa.Text(), server_default="", nullable=False),
        sa.Column("confidence", sa.String(12), server_default="unknown", nullable=False),
        sa.Column("validated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("recorded_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("validated_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("target_id", "protocol", "port", "sni", name="uq_endpoint_exposure_target_protocol_port_sni"),
    )
    op.create_index("ix_endpoint_exposures_target_id", "endpoint_exposures", ["target_id"])
    with op.batch_alter_table("run_endpoints") as batch:
        batch.add_column(sa.Column("exposure_snapshot", JSON, nullable=False, server_default=sa.text("'{}'")))
        batch.add_column(sa.Column("contextual_risk", JSON, nullable=False, server_default=sa.text("'{}'")))
    with op.batch_alter_table("run_findings") as batch:
        batch.add_column(sa.Column("contextual_risk_by_endpoint", JSON, nullable=False, server_default=sa.text("'{}'")))


def downgrade() -> None:
    with op.batch_alter_table("run_findings") as batch:
        batch.drop_column("contextual_risk_by_endpoint")
    with op.batch_alter_table("run_endpoints") as batch:
        batch.drop_column("contextual_risk")
        batch.drop_column("exposure_snapshot")
    op.drop_index("ix_endpoint_exposures_target_id", table_name="endpoint_exposures")
    op.drop_table("endpoint_exposures")
