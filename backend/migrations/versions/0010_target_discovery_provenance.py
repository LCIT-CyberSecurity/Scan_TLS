"""Which discovery created a target (provenance shown in the Targets list)

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # nullable: targets created by hand, or enriched by a discovery, simply have none
    op.add_column("target_dns_observations", sa.Column("created_discovery_id", sa.Uuid(), nullable=True))


def downgrade() -> None:
    op.drop_column("target_dns_observations", "created_discovery_id")
