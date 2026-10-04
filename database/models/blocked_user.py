"""
Block User (Phase 19.24 -- Block User).

Unlike Mute/Archive (storage/secure_key_store.py -- local-only, never
server-enforced, since neither one is a security control), a block
MUST be server-enforced to mean anything: a local-only block that the
server never consults would still let the blocked party message,
verify, and see the presence of the blocker from a second device or a
freshly-reinstalled client. This table is the single source of truth
every enforcement point (server/client_handler.py's direct-message
relay, verification-request handling, presence/typing broadcast
filtering, and user search) consults.

Directional and asymmetric by design: a row means exactly "blocker_id
has blocked blocked_id" -- it says nothing about the reverse
direction, mirroring every mainstream messaging app's own block model
(the blocked party is never notified and is not blocked back merely
because they were blocked).

Deliberately does NOT touch group messaging: blocking is a DM/
presence/verification/search control, not a retroactive split of
messages already flowing through a shared group thread that has its
own membership and admin model -- no mainstream messaging app makes a
1:1 block do that either. See server/client_handler.py::handle_group_
create()/handle_group_add_members() for the one place blocking DOES
apply to groups: it refuses to let a blocking relationship (in either
direction) be reflected in a BRAND NEW group's membership.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime -- see database/models/
    message.py's identical helper for the full rationale."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class BlockedUser(Base):
    """One directional block: blocker_id has blocked blocked_id."""

    __tablename__ = "blocked_users"
    __table_args__ = (
        UniqueConstraint(
            "blocker_id",
            "blocked_id",
            name="uq_blocked_users_blocker_id_blocked_id",
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    blocker_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    blocked_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    created_at = Column(DateTime, nullable=False, default=_utc_now)

    def __repr__(self):
        return f"<BlockedUser(blocker_id={self.blocker_id}, blocked_id={self.blocked_id})>"
