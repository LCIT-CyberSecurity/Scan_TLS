"""Store opt-in QUIC handshake observations and per-scan profile override."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0021_quic_observations"
down_revision = "0020_service_identification"
branch_labels = None
depends_on = None
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("scan_definitions", sa.Column("quic_enabled", sa.Boolean(), nullable=True))
    op.add_column("scan_runs", sa.Column("quic_observations", JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("scan_runs", "quic_observations")
    op.drop_column("scan_definitions", "quic_enabled")
