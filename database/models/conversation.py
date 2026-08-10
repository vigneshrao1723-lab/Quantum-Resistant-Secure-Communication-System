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

from sqlalchemy import CheckConstraint, Column, DateTime, String
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

    created_at = Column(DateTime, nullable=False, default=_utc_now)

    def __repr__(self):
        return f"<Conversation(id={self.id}, type={self.type})>"
