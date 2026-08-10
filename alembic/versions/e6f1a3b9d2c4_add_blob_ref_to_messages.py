"""add blob_ref to messages

Revision ID: e6f1a3b9d2c4
Revises: d4b8f1a9c3e2
Create Date: 2026-08-09 10:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e6f1a3b9d2c4'
down_revision: Union[str, Sequence[str], None] = 'd4b8f1a9c3e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Expand step of an expand-and-contract migration (Architecture
    Blueprint v2, Phase 6 -- Secure File & Image Transfer
    Infrastructure): relaxes messages.ciphertext to nullable and adds
    a new, additive messages.blob_ref column.

    ciphertext's relaxation only ever applies to a new message whose
    content is routed to blob storage (PayloadType.FILE/IMAGE,
    persist_message() in server/client_handler.py) -- every existing
    row keeps its ciphertext value unchanged, and every text message
    going forward continues to populate it exactly as before.
    blob_ref is new and nullable, so no existing row or query is
    affected.
    """
    op.alter_column(
        'messages', 'ciphertext',
        existing_type=sa.Text(),
        nullable=True,
    )
    op.add_column(
        'messages',
        sa.Column('blob_ref', sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema.

    Clean drop of blob_ref -- safe regardless of whether any blob-
    stored message exists, since nothing outside this phase's own new
    files depends on it. Restoring ciphertext's NOT NULL constraint is
    only safe if no blob-stored (ciphertext IS NULL) row exists; left
    as a manual step for whoever downgrades, consistent with this
    being an expand-and-contract migration's expand half.
    """
    op.drop_column('messages', 'blob_ref')
    op.alter_column(
        'messages', 'ciphertext',
        existing_type=sa.Text(),
        nullable=False,
    )
