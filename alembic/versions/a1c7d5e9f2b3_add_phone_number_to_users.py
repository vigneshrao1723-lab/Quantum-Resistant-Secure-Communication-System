"""add phone number to users

Revision ID: a1c7d5e9f2b3
Revises: f4b8e2c6a1d9
Create Date: 2026-08-18 22:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a1c7d5e9f2b3'
down_revision: Union[str, Sequence[str], None] = 'f4b8e2c6a1d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Adds users.phone_number -- the user-facing discovery identifier
    (BUG 7). users.id remains the internal UUID primary key; nothing
    about identity, foreign keys, or authentication moves onto this
    column.

    NOT NULL and UNIQUE, because both are load-bearing: discovery is
    only useful if every account has a number, and only correct if a
    number identifies exactly one account. The value is stored already
    normalised by security/phone_number.py, which is what makes the
    unique constraint mean what it should -- "+91 98765 43210" and
    "+919876543210" are the same number and must collide.

    Adding a NOT NULL column with no server default fails on a table
    that already has rows, and there is deliberately no backfill here:
    inventing placeholder numbers would create rows that satisfy the
    constraint while being false, and a placeholder that is unique per
    row is indistinguishable from a real registration. This project's
    database holds development and test data only, so the accepted
    procedure is to recreate it:

        alembic downgrade base && alembic upgrade head

    That is a deliberate, documented choice for a project with no
    production data, not an oversight.
    """

    op.add_column(
        "users",
        sa.Column("phone_number", sa.String(length=20), nullable=False),
    )

    op.create_index(
        op.f("ix_users_phone_number"), "users", ["phone_number"], unique=False
    )

    op.create_unique_constraint("uq_users_phone_number", "users", ["phone_number"])


def downgrade() -> None:
    """Downgrade schema.

    Drops the constraint, the index, then the column -- the exact
    reverse of upgrade(). No other table references phone_number, so
    nothing else needs unwinding.
    """

    op.drop_constraint("uq_users_phone_number", "users", type_="unique")

    op.drop_index(op.f("ix_users_phone_number"), table_name="users")

    op.drop_column("users", "phone_number")
