"""Keep automatic creation of SSO accounts on for installations that already use external sign-in

Revision ID: 0011
Revises: 0010
"""
import os

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Until now every first SSO sign-in created an account (default role). Installations that rely on it keep that behaviour;
    # a new installation has no row and starts restrictive (pre-provisioning), unless TLS_SCAN_SSO_AUTO_PROVISION says otherwise.
    bind = op.get_bind()
    sso_users = bind.execute(sa.text("SELECT count(*) FROM users WHERE issuer NOT IN ('builtin:local', 'local:user', 'directory:pending')")).scalar() or 0
    if sso_users or os.environ.get("TLS_SCAN_OIDC_ISSUER"):
        bind.execute(sa.text("DELETE FROM system_settings WHERE key = 'auth'"))
        bind.execute(sa.text("INSERT INTO system_settings (key, value, updated_at) VALUES ('auth', CAST(:v AS jsonb), now())"),
                     {"v": '{"provider": "", "auto_provision": true}'})


def downgrade() -> None:
    pass
