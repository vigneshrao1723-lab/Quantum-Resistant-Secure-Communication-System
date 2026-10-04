"""user last_seen_at

Revision ID: d3f7b9c2e5a1
Revises: c2e6a8f4b1d3
Create Date: 2026-09-20 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = 'd3f7b9c2e5a1'
down_revision: Union[str, Sequence[str], None] = 'c2e6a8f4b1d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Expand step: one purely additive, nullable column -- see
    database/models/user.py::last_seen_at's own docstring. A single
    overwritten timestamp, not a history log."""

    op.add_column('users', sa.Column('last_seen_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'last_seen_at')
