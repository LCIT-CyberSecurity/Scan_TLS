"""External REST API and MCP: per-user authorisations (off) and access keys (hashed)

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Non-destructive: existing users keep everything and start with both accesses refused.
    op.add_column("users", sa.Column("api_access_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("mcp_access_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "access_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service", sa.String(3), nullable=False),
        sa.Column("prefix", sa.String(20), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_access_tokens_user_id", "access_tokens", ["user_id"])
    op.create_index("uq_access_tokens_active", "access_tokens", ["user_id", "service"], unique=True, postgresql_where=sa.text("revoked_at IS NULL"))
    # The global switches live in system_settings (key "external_access"); absent = both disabled.


def downgrade() -> None:
    op.drop_table("access_tokens")
    op.drop_column("users", "mcp_access_enabled")
    op.drop_column("users", "api_access_enabled")
