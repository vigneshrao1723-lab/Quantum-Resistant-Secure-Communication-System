"""add conversations foundation

Revision ID: b7e2f4a1c8d5
Revises: a2dd4e553e79
Create Date: 2026-08-07 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b7e2f4a1c8d5'
down_revision: Union[str, Sequence[str], None] = 'a2dd4e553e79'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Expand step of an expand-and-contract migration (Architecture
    Blueprint v2, Phase 1): creates the conversations and
    conversation_members tables, and adds a nullable conversation_id
    column to messages. No existing column, row, or constraint on
    messages is touched -- receiver_id remains required and
    authoritative. Backfilling historical rows and dropping
    receiver_id are explicitly deferred to whichever future phase
    first needs to read through conversation_id.
    """
    op.create_table(
        'conversations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('type', sa.String(length=16), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("type IN ('direct', 'group')", name='ck_conversations_type'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'conversation_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('conversation_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('joined_at', sa.DateTime(), nullable=False),
        sa.Column('left_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'conversation_id', 'user_id',
            name='uq_conversation_members_conversation_id_user_id',
        ),
    )
    op.create_index(
        op.f('ix_conversation_members_conversation_id'),
        'conversation_members', ['conversation_id'], unique=False,
    )
    op.create_index(
        op.f('ix_conversation_members_user_id'),
        'conversation_members', ['user_id'], unique=False,
    )

    op.add_column(
        'messages',
        sa.Column('conversation_id', postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        'fk_messages_conversation_id_conversations',
        'messages', 'conversations',
        ['conversation_id'], ['id'],
        ondelete='CASCADE',
    )
    op.create_index(
        op.f('ix_messages_conversation_id'),
        'messages', ['conversation_id'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean drop -- safe in both directions since no code outside this
    phase's own new files depends on conversation_id or the new
    tables; receiver_id-based data is untouched throughout.
    """
    op.drop_index(op.f('ix_messages_conversation_id'), table_name='messages')
    op.drop_constraint(
        'fk_messages_conversation_id_conversations', 'messages', type_='foreignkey'
    )
    op.drop_column('messages', 'conversation_id')

    op.drop_index(op.f('ix_conversation_members_user_id'), table_name='conversation_members')
    op.drop_index(
        op.f('ix_conversation_members_conversation_id'), table_name='conversation_members'
    )
    op.drop_table('conversation_members')

    op.drop_table('conversations')
