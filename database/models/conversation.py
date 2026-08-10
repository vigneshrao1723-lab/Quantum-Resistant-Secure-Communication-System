"""
Conversation model.

The addressing unit for messaging (Architecture Blueprint v2, S01). A
"direct" conversation has exactly two members -- today's private
chat, re-addressed through this model in Phase 1. A "group"
conversation will have more, once Group Chat is implemented.

Both type values are valid at the schema level from the start so a
later phase can begin creating "group" conversations without a
migration -- see database/repositories/conversation_repository.py,
which is the only place conversations are actually created, and which
in Phase 1 only ever passes TYPE_DIRECT.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Conversation(Base):
    """Represents a conversation: the addressing unit for messaging."""

    TYPE_DIRECT = "direct"
    TYPE_GROUP = "group"

    __tablename__ = "conversations"
    __table_args__ = (
        CheckConstraint(
            "type IN ('direct', 'group')",
            name="ck_conversations_type",
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    type = Column(String(16), nullable=False, default=TYPE_DIRECT)

    # Additive (Phase 4 -- Secure Group Messaging Foundation): nullable,
    # meaningful only for TYPE_GROUP. Direct conversations never set it.
    name = Column(String(128), nullable=True)

    # Additive (Phase 7 -- Group Membership Management), meaningful
    # only for TYPE_GROUP -- direct conversations stay at epoch 1
    # forever, since nothing ever rotates them. Together these two
    # counters are the server's authoritative, race-free bookkeeping
    # for group-key rotation (see server/client_handler.py's leave/
    # rotation handlers); the server tracks *which epoch number* is
    # current/confirmed as plain coordination metadata -- it never
    # sees the epoch's actual key material.
    #
    # current_key_epoch: the highest epoch *reserved* so far --
    # incremented by exactly one every time a member leaves.
    #
    # confirmed_key_epoch: the highest epoch a rotation initiator has
    # confirmed finishing distribution for (group_key_rotation_complete).
    # "A rotation is owed" is the derived condition
    # confirmed_key_epoch < current_key_epoch -- not a separate flag --
    # so an arbitrary backlog of un-rotated epochs (multiple leaves
    # before an earlier rotation finishes) is representable and can be
    # caught up one epoch at a time, in order, never skipped.
    #
    # Both default to 1: every conversation that predates this phase
    # has, in fact, never rotated -- 1 is the true current and
    # confirmed epoch for all of them, not a placeholder.
    current_key_epoch = Column(Integer, nullable=False, default=1)
    confirmed_key_epoch = Column(Integer, nullable=False, default=1)

    created_at = Column(DateTime, nullable=False, default=_utc_now)

    def __repr__(self):
        return f"<Conversation(id={self.id}, type={self.type})>"
