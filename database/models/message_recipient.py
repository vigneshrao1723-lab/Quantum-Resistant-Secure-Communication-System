"""
Message recipient model.

Per-recipient delivery state for a message, kept separate from the
message's content (database/models/message.py) so delivery tracking
(today: QUEUED/DELIVERED) and future read receipts (READ) extend this
table additively -- see domain/message_delivery_status.py.

Only ever populated for group messages (Phase 4 -- Secure Group
Messaging Foundation). Direct messages have no rows here:
messages.receiver_id already fully captures their single-recipient
delivery target, and that column's meaning is deliberately left
untouched -- see database/models/message.py.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID

from database.models.base import Base
from domain.message_delivery_status import MessageDeliveryStatus


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class MessageRecipient(Base):
    """Represents one recipient's delivery state for one message."""

    __tablename__ = "message_recipients"
    __table_args__ = (
        UniqueConstraint(
            "message_id",
            "recipient_id",
            name="uq_message_recipients_message_id_recipient_id",
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    message_id = Column(
        UUID(as_uuid=True),
        ForeignKey("messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    recipient_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status = Column(
        String(16),
        nullable=False,
        default=MessageDeliveryStatus.QUEUED,
    )

    updated_at = Column(
        DateTime,
        nullable=False,
        default=_utc_now,
        onupdate=_utc_now,
    )

    created_at = Column(DateTime, nullable=False, default=_utc_now)

    def __repr__(self):
        return (
            f"<MessageRecipient(message_id={self.message_id}, "
            f"recipient_id={self.recipient_id}, status={self.status})>"
        )
