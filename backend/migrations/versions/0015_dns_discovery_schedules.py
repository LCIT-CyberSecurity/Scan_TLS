"""Allow the existing schedule engine to trigger DNS discovery jobs.

Revision ID: 0015
Revises: 0014
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.alter_column("scan_schedules", "definition_id", existing_type=sa.Uuid(), nullable=True)
    op.add_column("scan_schedules", sa.Column("task_type", sa.String(24), server_default="tls", nullable=False))
    op.add_column("scan_schedules", sa.Column("task_config", JSON, nullable=True))
    op.create_check_constraint("ck_scan_schedule_task_definition", "scan_schedules",
                                "(task_type = 'tls' AND definition_id IS NOT NULL) OR (task_type = 'dns_discovery' AND definition_id IS NULL)")
    op.add_column("schedule_triggers", sa.Column("discovery_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("fk_schedule_triggers_discovery_id", "schedule_triggers", "dns_discoveries", ["discovery_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_scan_schedules_task_type", "scan_schedules", ["task_type"])


def downgrade() -> None:
    if op.get_bind().execute(sa.text("SELECT 1 FROM scan_schedules WHERE task_type = 'dns_discovery' LIMIT 1")).first():
        raise RuntimeError("Remove DNS schedules before downgrading revision 0014; their task configuration cannot be represented by the TLS-only schema.")
    op.drop_index("ix_scan_schedules_task_type", table_name="scan_schedules")
    op.drop_constraint("fk_schedule_triggers_discovery_id", "schedule_triggers", type_="foreignkey")
    op.drop_column("schedule_triggers", "discovery_id")
    op.drop_column("scan_schedules", "task_config")
    op.drop_constraint("ck_scan_schedule_task_definition", "scan_schedules", type_="check")
    op.drop_column("scan_schedules", "task_type")
    op.alter_column("scan_schedules", "definition_id", existing_type=sa.Uuid(), nullable=False)
