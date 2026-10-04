"""message lifecycle events (reply/edit/delete/reactions/idempotency)

Revision ID: f4a8c2e6b1d7
Revises: d8a3f6c2b9e4
Create Date: 2026-09-14 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f4a8c2e6b1d7'
down_revision: Union[str, Sequence[str], None] = 'd8a3f6c2b9e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Expand step of an expand-and-contract migration (Phase 19.24 --
    Message Lifecycle Events): every new column on ``messages`` is
    nullable/additive, and the two new tables are brand new -- nothing
    existing is altered, dropped, or renamed. See database/models/
    message.py, message_reaction.py, message_hidden_for_user.py for
    the full rationale behind each field.
    """

    op.add_column(
        'messages',
        sa.Column('reply_to_message_id', postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        'fk_messages_reply_to_message_id',
        'messages', 'messages',
        ['reply_to_message_id'], ['id'],
        ondelete='SET NULL',
    )
    op.create_index(
        'ix_messages_reply_to_message_id', 'messages', ['reply_to_message_id'],
    )

    op.add_column('messages', sa.Column('edited_at', sa.DateTime(), nullable=True))
    op.add_column(
        'messages',
        sa.Column('edit_version', sa.Integer(), nullable=False, server_default='0'),
    )

    op.add_column('messages', sa.Column('deleted_at', sa.DateTime(), nullable=True))
    op.add_column(
        'messages',
        sa.Column('deleted_by', postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        'fk_messages_deleted_by', 'messages', 'users',
        ['deleted_by'], ['id'],
        ondelete='SET NULL',
    )

    op.add_column(
        'messages',
        sa.Column('client_message_id', sa.String(length=36), nullable=True),
    )
    op.create_unique_constraint(
        'uq_messages_client_message_id', 'messages', ['client_message_id'],
    )

    op.create_table(
        'message_reactions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            'message_id', postgresql.UUID(as_uuid=True),
            sa.ForeignKey('messages.id', ondelete='CASCADE'), nullable=False,
        ),
        sa.Column(
            'user_id', postgresql.UUID(as_uuid=True),
            sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False,
        ),
        sa.Column('ciphertext', sa.Text(), nullable=False),
        sa.Column('epoch', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            'message_id', 'user_id', name='uq_message_reactions_message_id_user_id',
        ),
    )
    op.create_index('ix_message_reactions_message_id', 'message_reactions', ['message_id'])
    op.create_index('ix_message_reactions_user_id', 'message_reactions', ['user_id'])

    op.create_table(
        'message_hidden_for_user',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            'message_id', postgresql.UUID(as_uuid=True),
            sa.ForeignKey('messages.id', ondelete='CASCADE'), nullable=False,
        ),
        sa.Column(
            'user_id', postgresql.UUID(as_uuid=True),
            sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False,
        ),
        sa.Column('hidden_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            'message_id', 'user_id', name='uq_message_hidden_for_user_message_id_user_id',
        ),
    )
    op.create_index(
        'ix_message_hidden_for_user_message_id', 'message_hidden_for_user', ['message_id'],
    )
    op.create_index(
        'ix_message_hidden_for_user_user_id', 'message_hidden_for_user', ['user_id'],
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean drop, in reverse dependency order -- nothing outside this
    phase's own new code depends on any of this.
    """

    op.drop_index('ix_message_hidden_for_user_user_id', table_name='message_hidden_for_user')
    op.drop_index('ix_message_hidden_for_user_message_id', table_name='message_hidden_for_user')
    op.drop_table('message_hidden_for_user')

    op.drop_index('ix_message_reactions_user_id', table_name='message_reactions')
    op.drop_index('ix_message_reactions_message_id', table_name='message_reactions')
    op.drop_table('message_reactions')

    op.drop_constraint('uq_messages_client_message_id', 'messages', type_='unique')
    op.drop_column('messages', 'client_message_id')

    op.drop_constraint('fk_messages_deleted_by', 'messages', type_='foreignkey')
    op.drop_column('messages', 'deleted_by')
    op.drop_column('messages', 'deleted_at')

    op.drop_column('messages', 'edit_version')
    op.drop_column('messages', 'edited_at')

    op.drop_index('ix_messages_reply_to_message_id', table_name='messages')
    op.drop_constraint('fk_messages_reply_to_message_id', 'messages', type_='foreignkey')
    op.drop_column('messages', 'reply_to_message_id')
