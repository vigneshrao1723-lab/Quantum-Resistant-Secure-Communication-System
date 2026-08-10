"""add payload fields to messages

Revision ID: c9a4f2e6b1d7
Revises: b7e2f4a1c8d5
Create Date: 2026-08-07 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c9a4f2e6b1d7'
down_revision: Union[str, Sequence[str], None] = 'b7e2f4a1c8d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Expand step of an expand-and-contract migration (Architecture
    Blueprint v2, Phase 3 -- Universal Secure Payload Architecture):
    adds two nullable columns to messages. No existing column, row,
    or constraint is touched -- ciphertext/algorithm/timestamp remain
    exactly as they are. No backfill: historical rows keep
    payload_type/content_metadata NULL; persist_message() populates
    them for every message going forward.

    content_metadata is JSONB, not TEXT: it always holds structured
    key/value descriptors (filename, mime type, duration, ...), never
    free text, so storing it as JSONB lets SQLAlchemy bind/read a
    Python dict directly (no manual json.dumps/json.loads at the
    application boundary) and makes the column queryable/indexable if
    a future phase ever needs that.
    """
    op.add_column(
        'messages',
        sa.Column('payload_type', sa.String(length=32), nullable=True),
    )
    op.add_column(
        'messages',
        sa.Column('content_metadata', postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean drop -- safe in both directions since no code outside this
    phase's own new files depends on either column; ciphertext-based
    data is untouched throughout.
    """
    op.drop_column('messages', 'content_metadata')
    op.drop_column('messages', 'payload_type')
