"""password auth: add password_hash and must_change_password to users

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as b:
        b.add_column(sa.Column("password_hash", sa.String(length=255), nullable=True))
        b.add_column(sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as b:
        b.drop_column("must_change_password")
        b.drop_column("password_hash")
