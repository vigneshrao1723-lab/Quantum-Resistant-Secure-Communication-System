"""add blocked_users table (Block User)

Revision ID: 98be0391f12d
Revises: a7d3e5f8c9b2
Create Date: 2026-09-19 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = '98be0391f12d'
down_revision: Union[str, Sequence[str], None] = 'a7d3e5f8c9b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Brand-new table, nothing existing altered/dropped/renamed --
    see database/models/blocked_user.py for the full rationale."""

    op.create_table(
        'blocked_users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            'blocker_id', postgresql.UUID(as_uuid=True),
            sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False,
        ),
        sa.Column(
            'blocked_id', postgresql.UUID(as_uuid=True),
            sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False,
        ),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            'blocker_id', 'blocked_id', name='uq_blocked_users_blocker_id_blocked_id',
        ),
    )
    op.create_index('ix_blocked_users_blocker_id', 'blocked_users', ['blocker_id'])
    op.create_index('ix_blocked_users_blocked_id', 'blocked_users', ['blocked_id'])


def downgrade() -> None:
    op.drop_index('ix_blocked_users_blocked_id', table_name='blocked_users')
    op.drop_index('ix_blocked_users_blocker_id', table_name='blocked_users')
    op.drop_table('blocked_users')
