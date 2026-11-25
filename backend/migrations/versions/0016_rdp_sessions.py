"""remote sessions: add mode (assist|rdp) and connection (host:port for RDP)

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("remote_sessions", schema=None) as b:
        b.add_column(sa.Column("mode", sa.String(length=16), nullable=False, server_default="assist"))
        b.add_column(sa.Column("connection", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remote_sessions", schema=None) as b:
        b.drop_column("connection")
        b.drop_column("mode")
