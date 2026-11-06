"""phase7 audit anchors

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-06
"""
from alembic import op
import sqlalchemy as sa
import app.core.database

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_anchors',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('seq', sa.BigInteger(), nullable=False),
    sa.Column('hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', app.core.database.UTCDateTime(timezone=True), nullable=False),
    sa.Column('key_id', sa.String(length=40), nullable=False),
    sa.Column('signature', sa.String(length=128), nullable=False),
    sa.Column('external_written', sa.Boolean(), nullable=False),
    sa.Column('external_error', sa.String(length=300), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_audit_anchors_organization_id_organizations')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_anchors')),
    sa.UniqueConstraint('organization_id', 'seq', name=op.f('uq_audit_anchors_organization_id_seq'))
    )
    if op.get_bind().dialect.name == "postgresql":
        # Same append-only guarantee as audit_logs (function created in 0001).
        op.execute("""
            CREATE TRIGGER audit_anchors_no_update_delete
            BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_anchors
            FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_block_mutation();
        """)
        # Default privileges would give the application role UPDATE/DELETE; it only ever needs to append and read.
        op.execute("""
            DO $$ BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cage_app') THEN
                REVOKE UPDATE, DELETE, TRUNCATE ON audit_anchors FROM cage_app;
                GRANT SELECT, INSERT ON audit_anchors TO cage_app;
              END IF;
            END $$;
        """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_anchors_no_update_delete ON audit_anchors")
    op.drop_table('audit_anchors')
