"""Device OS patch status (latest, one row per device): pending updates by severity, reboot-pending, last-patched."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_patch_status",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("pending_total", sa.Integer(), nullable=True),
        sa.Column("pending_critical", sa.Integer(), nullable=True),
        sa.Column("pending_important", sa.Integer(), nullable=True),
        sa.Column("reboot_pending", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_patched", sa.String(64), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_device_patch_status_device_id", "device_patch_status", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_device_patch_status_device_id", table_name="device_patch_status")
    op.drop_table("device_patch_status")
