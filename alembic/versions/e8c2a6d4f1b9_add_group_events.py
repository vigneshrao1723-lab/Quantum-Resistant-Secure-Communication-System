"""group membership events

Revision ID: e8c2a6d4f1b9
Revises: d3f7b9c2e5a1
Create Date: 2026-10-21 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = 'e8c2a6d4f1b9'
down_revision: Union[str, Sequence[str], None] = 'd3f7b9c2e5a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Expand step: one new table, nothing existing is touched (see
    database/models/group_event.py). Existing groups simply have no events yet; membership
    changes made from now on are recorded."""

    op.create_table(
        'group_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('conversation_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.String(length=32), nullable=False),
        sa.Column('actor_user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('subject_user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('actor_username', sa.String(length=255), nullable=True),
        sa.Column('subject_username', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['subject_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_group_events_conversation_id', 'group_events', ['conversation_id'])
    op.create_index('ix_group_events_created_at', 'group_events', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_group_events_created_at', table_name='group_events')
    op.drop_index('ix_group_events_conversation_id', table_name='group_events')
    op.drop_table('group_events')
