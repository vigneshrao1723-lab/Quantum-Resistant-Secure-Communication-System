"""add group key epoch

Revision ID: f4b8e2c6a1d9
Revises: e6f1a3b9d2c4
Create Date: 2026-08-11 09:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f4b8e2c6a1d9'
down_revision: Union[str, Sequence[str], None] = 'e6f1a3b9d2c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Expand step of an expand-and-contract migration (Architecture
    Blueprint v2, Phase 7 -- Group Membership Management): three
    purely additive columns, no existing column, row, or constraint
    touched.

    messages.epoch (nullable): which group-key epoch encrypted a
    row's ciphertext. NULL on every existing row -- correctly, since
    no rotation mechanism existed before this migration, every prior
    message really was encrypted under what this phase calls epoch 1.
    Application code treats NULL as 1 when reading; new rows populate
    it explicitly going forward.

    conversations.current_key_epoch / confirmed_key_epoch (NOT NULL,
    default 1): the server's authoritative bookkeeping for group-key
    rotation. Defaulting every existing conversation to 1/1 is simply
    true -- no group has ever rotated its key before this phase.
    """
    op.add_column(
        'messages',
        sa.Column('epoch', sa.Integer(), nullable=True),
    )
    op.add_column(
        'conversations',
        sa.Column(
            'current_key_epoch', sa.Integer(), nullable=False, server_default='1'
        ),
    )
    op.add_column(
        'conversations',
        sa.Column(
            'confirmed_key_epoch', sa.Integer(), nullable=False, server_default='1'
        ),
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean drop of all three columns -- safe regardless of whether any
    group has rotated, since nothing outside this phase's own new
    code depends on them.
    """
    op.drop_column('conversations', 'confirmed_key_epoch')
    op.drop_column('conversations', 'current_key_epoch')
    op.drop_column('messages', 'epoch')
