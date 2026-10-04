"""add devices table

Revision ID: c4f8a2d6e1b7
Revises: b3e7f9c1a4d8
Create Date: 2026-08-31 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c4f8a2d6e1b7'
down_revision: Union[str, Sequence[str], None] = 'b3e7f9c1a4d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    New table only (Multi-Device Identity, Phase 16) -- no existing
    table, column, or row touched. Records the PUBLIC half of a
    device's cryptographic identity and its authorization state; no
    private-key column exists here, and none ever will (see database/
    models/device.py's own docstring).
    """
    op.create_table(
        'devices',
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_name', sa.String(length=128), nullable=True),
        sa.Column('platform', sa.String(length=128), nullable=True),
        sa.Column('kem_public_key', sa.Text(), nullable=False),
        sa.Column('ml_dsa_public_key', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(length=128), nullable=False),
        sa.Column('state', sa.String(length=16), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('authorized_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('authorized_by_device_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['authorized_by_device_id'], ['devices.device_id'], ondelete='SET NULL'
        ),
        sa.PrimaryKeyConstraint('device_id'),
    )
    op.create_index(op.f('ix_devices_user_id'), 'devices', ['user_id'], unique=False)
    op.create_index(op.f('ix_devices_fingerprint'), 'devices', ['fingerprint'], unique=False)


def downgrade() -> None:
    """Downgrade schema.

    Clean drop -- nothing outside this phase's own new code depends on
    this table.
    """
    op.drop_index(op.f('ix_devices_fingerprint'), table_name='devices')
    op.drop_index(op.f('ix_devices_user_id'), table_name='devices')
    op.drop_table('devices')
