"""reaction message_signature (receiver-side verification)

Revision ID: a7d3e5f8c9b2
Revises: f4a8c2e6b1d7
Create Date: 2026-09-15 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = 'a7d3e5f8c9b2'
down_revision: Union[str, Sequence[str], None] = 'f4a8c2e6b1d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Expand step: one purely additive, nullable column -- see
    database/models/message_reaction.py::message_signature's own
    docstring. Lets a client verify a reaction's ML-DSA origin
    independently of trusting the server, both live and on history
    recovery."""

    op.add_column(
        'message_reactions',
        sa.Column('message_signature', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('message_reactions', 'message_signature')
