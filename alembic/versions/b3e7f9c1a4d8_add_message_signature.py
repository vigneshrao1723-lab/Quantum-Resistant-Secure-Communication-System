"""add message signature

Revision ID: b3e7f9c1a4d8
Revises: a1c7d5e9f2b3
Create Date: 2026-08-30 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b3e7f9c1a4d8'
down_revision: Union[str, Sequence[str], None] = 'a1c7d5e9f2b3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Expand step of an expand-and-contract migration (Message-Level
    ML-DSA Origin Authentication): one purely additive, nullable
    column -- no existing column, row, or constraint touched.

    messages.message_signature: the base64-encoded ML-DSA-65 signature
    over crypto/message_protocol.py::canonical_message_payload() for
    this row's ciphertext, carried alongside it into offline storage
    so a signature produced at send time survives being queued and
    later delivered through history loading -- see client/session.py::
    _decrypt_history_message()'s verification of this column. NULL on
    every existing row (correctly: no message signed before this
    phase ever had one) and on any future row from a sender that, for
    whatever reason, produced none -- application code treats a NULL
    value as "unsigned, reject" when verifying, exactly like a missing
    "message_signature" field on the live "chat" packet already does.
    Text, not a fixed-length type: base64 of a fixed 3309-byte ML-DSA
    signature is a fixed-length string in practice, but this column
    imposes no assumption about signature size going forward.
    """
    op.add_column(
        'messages',
        sa.Column('message_signature', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean drop -- nothing outside this phase's own new verification
    code depends on this column.
    """
    op.drop_column('messages', 'message_signature')
