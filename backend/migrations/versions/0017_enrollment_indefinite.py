"""Allow indefinite (never-expiring) enrollment tokens: make enrollment_tokens.expires_at nullable.

A NULL expires_at means the token never expires (see services/devices.token_state)."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("enrollment_tokens") as batch:
        batch.alter_column("expires_at", existing_type=sa.DateTime(), nullable=True)


def downgrade() -> None:
    # Backfill any indefinite tokens to a concrete timestamp before restoring NOT NULL.
    op.execute("UPDATE enrollment_tokens SET expires_at = created_at WHERE expires_at IS NULL")
    with op.batch_alter_table("enrollment_tokens") as batch:
        batch.alter_column("expires_at", existing_type=sa.DateTime(), nullable=False)
