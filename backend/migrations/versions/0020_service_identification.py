"""Store opt-in service identification settings and results."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0020_service_identification"
down_revision = "0019_snmp_discovery"
branch_labels = None
depends_on = None
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("scan_definitions", sa.Column("service_identification_enabled", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("scan_runs", sa.Column("service_observations", JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("scan_runs", "service_observations")
    op.drop_column("scan_definitions", "service_identification_enabled")
