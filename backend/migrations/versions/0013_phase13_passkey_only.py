"""phase13 passkey-only auth: drop password and TOTP columns

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

COLUMNS = ("password_hash", "mfa_enabled", "mfa_secret_enc", "mfa_pending_secret_enc",
           "mfa_last_used_step", "password_changed_at")


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as b:
        for col in COLUMNS:
            b.drop_column(col)


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as b:
        b.add_column(sa.Column("password_hash", sa.String(length=255), nullable=True))
        b.add_column(sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        b.add_column(sa.Column("mfa_secret_enc", sa.Text(), nullable=True))
        b.add_column(sa.Column("mfa_pending_secret_enc", sa.Text(), nullable=True))
        b.add_column(sa.Column("mfa_last_used_step", sa.Integer(), nullable=True))
        b.add_column(sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
