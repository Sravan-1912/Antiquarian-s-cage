"""Chat alert channels (Slack/Teams/Discord/generic webhook) + their durable delivery outbox."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chat_webhooks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("platform", sa.String(12), nullable=False),
        sa.Column("url_enc", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("min_severity", sa.String(12), nullable=False, server_default="high"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.UniqueConstraint("organization_id", "platform", name="uq_chat_org_platform"),
    )
    op.create_table(
        "chat_deliveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("webhook_id", sa.Uuid(), sa.ForeignKey("chat_webhooks.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_chat_deliv_status_next", "chat_deliveries", ["status", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("ix_chat_deliv_status_next", table_name="chat_deliveries")
    op.drop_table("chat_deliveries")
    op.drop_table("chat_webhooks")
