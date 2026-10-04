"""add inbox notifications table

Revision ID: d8a3f6c2b9e4
Revises: c4f8a2d6e1b7
Create Date: 2026-09-04 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd8a3f6c2b9e4'
down_revision: Union[str, Sequence[str], None] = 'c4f8a2d6e1b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    New table only (Phase 19.13 -- User Manual Feedback
    Implementation) -- no existing table, column, or row touched.
    Backs the inbox/verification-request/group-add-approval
    workflows; see database/models/inbox_notification.py's own
    docstring.
    """
    op.create_table(
        'inbox_notifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('recipient_user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('requester_user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('conversation_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('candidate_user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['recipient_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['requester_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['candidate_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_inbox_notifications_recipient_user_id'),
        'inbox_notifications', ['recipient_user_id'], unique=False,
    )
    op.create_index(
        op.f('ix_inbox_notifications_requester_user_id'),
        'inbox_notifications', ['requester_user_id'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean drop -- nothing outside this phase's own new code depends on
    this table.
    """
    op.drop_index(op.f('ix_inbox_notifications_requester_user_id'), table_name='inbox_notifications')
    op.drop_index(op.f('ix_inbox_notifications_recipient_user_id'), table_name='inbox_notifications')
    op.drop_table('inbox_notifications')
