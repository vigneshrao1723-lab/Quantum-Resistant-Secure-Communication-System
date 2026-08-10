"""add group messaging foundation

Revision ID: d4b8f1a9c3e2
Revises: c9a4f2e6b1d7
Create Date: 2026-08-08 09:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd4b8f1a9c3e2'
down_revision: Union[str, Sequence[str], None] = 'c9a4f2e6b1d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Expand step (Architecture Blueprint v2, Phase 4 -- Secure Group
    Messaging Foundation): purely additive. Adds a nullable
    conversations.name column (meaningful only for TYPE_GROUP), and a
    new message_recipients table for per-recipient delivery state.

    messages.receiver_id is deliberately NOT touched -- it remains
    NOT NULL with its existing meaning intact for every direct
    message; group messages populate it with the sender's own id as a
    documented legacy placeholder (see server/client_handler.py) and
    rely on conversation_id + message_recipients as the authoritative
    addressing/delivery mechanism instead. No existing row, column,
    or constraint on messages is altered by this migration.
    """
    op.add_column(
        'conversations',
        sa.Column('name', sa.String(length=128), nullable=True),
    )

    op.create_table(
        'message_recipients',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('message_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('recipient_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['recipient_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'message_id', 'recipient_id',
            name='uq_message_recipients_message_id_recipient_id',
        ),
    )
    op.create_index(
        op.f('ix_message_recipients_message_id'),
        'message_recipients', ['message_id'], unique=False,
    )
    op.create_index(
        op.f('ix_message_recipients_recipient_id'),
        'message_recipients', ['recipient_id'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean, unconditional drop -- safe regardless of whether group
    messages have been sent, since receiver_id was never touched and
    nothing outside this phase's own new files depends on name or
    message_recipients.
    """
    op.drop_index(op.f('ix_message_recipients_recipient_id'), table_name='message_recipients')
    op.drop_index(op.f('ix_message_recipients_message_id'), table_name='message_recipients')
    op.drop_table('message_recipients')

    op.drop_column('conversations', 'name')
