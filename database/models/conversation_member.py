"""
Conversation membership model.

Links a user to a conversation. The same shape serves both a direct
conversation's two members today and a group conversation's members
once Group Chat is implemented -- no schema change is expected when
that phase lands. ``role`` is included now for that reason but carries
no behavior in Phase 1: every membership created today is TYPE_DIRECT
and gets the default ROLE_MEMBER.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ConversationMember(Base):
    """Represents one user's membership in one conversation."""

    ROLE_MEMBER = "member"

    __tablename__ = "conversation_members"
    __table_args__ = (
        UniqueConstraint(
            "conversation_id",
            "user_id",
            name="uq_conversation_members_conversation_id_user_id",
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    conversation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    role = Column(String(32), nullable=False, default=ROLE_MEMBER)

    joined_at = Column(DateTime, nullable=False, default=_utc_now)
    left_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return (
            f"<ConversationMember(conversation_id={self.conversation_id}, "
            f"user_id={self.user_id}, role={self.role})>"
        )
