"""
Message model for persisted private chat messages.

Stores ciphertext only -- the server never has access to plaintext,
consistent with the existing end-to-end encryption architecture (see
crypto/aes.py, crypto/key_manager.py). A row is only ever written
after a private message has been successfully routed to its
recipient; failed deliveries are never persisted.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Message(Base):
    """Represents a persisted, successfully delivered private message."""

    __tablename__ = "messages"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    sender_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    receiver_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    ciphertext = Column(Text, nullable=False)
    algorithm = Column(String(32), nullable=False)

    timestamp = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=_utc_now)

    def __repr__(self):
        return (
            f"<Message(id={self.id}, sender_id={self.sender_id}, "
            f"receiver_id={self.receiver_id}, algorithm={self.algorithm})>"
        )
