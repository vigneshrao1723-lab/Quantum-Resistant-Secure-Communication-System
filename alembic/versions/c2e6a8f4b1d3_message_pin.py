"""message pin (pinned_at/pinned_by)

Revision ID: c2e6a8f4b1d3
Revises: 98be0391f12d
Create Date: 2026-09-19 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = 'c2e6a8f4b1d3'
down_revision: Union[str, Sequence[str], None] = '98be0391f12d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Expand step: two purely additive, nullable columns -- see
    database/models/message.py::pinned_at/pinned_by's own docstring.
    No content, so no ciphertext/epoch/signature columns are needed
    here, unlike message_reactions -- pin state carries no data of its
    own to protect."""

    op.add_column('messages', sa.Column('pinned_at', sa.DateTime(), nullable=True))
    op.add_column(
        'messages',
        sa.Column('pinned_by', postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        'fk_messages_pinned_by_users',
        'messages', 'users',
        ['pinned_by'], ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint('fk_messages_pinned_by_users', 'messages', type_='foreignkey')
    op.drop_column('messages', 'pinned_by')
    op.drop_column('messages', 'pinned_at')
