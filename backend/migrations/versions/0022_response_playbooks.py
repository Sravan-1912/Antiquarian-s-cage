"""Automated-response playbooks (SOAR): alert trigger -> actions."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "response_playbooks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("match_rule_keys", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("match_min_severity", sa.String(12), nullable=False, server_default="high"),
        sa.Column("match_kinds", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("actions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("response_playbooks")
