"""
Per-user "delete for me" suppression list (Phase 19.24 -- Message
Lifecycle Events).

Deliberately NOT a mutation of the Message row itself: "delete for me"
is a per-viewer preference, not a fact about the message -- every
other participant (and every other of THIS user's authorized devices
that hasn't yet learned about it) must still see it completely
unaffected. A row here means "user_id no longer wants message_id
returned to them by history/search" -- server/client_handler.py::
handle_message_history_request() filters these out for the requesting
user, and this table is exactly what lets that preference survive
logout/login and synchronize to the user's OTHER authorized devices on
their next reconnect/history-reload (Phase 19.24 mandate: "must
synchronize correctly across the user's authorized devices").

The server never needs to know WHY a user hid a message, only that
they did -- this table carries no content, ciphertext, or reason, only
the fact of suppression and when it happened.
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


class MessageHiddenForUser(Base):
    """One user's "delete for me" suppression of one message."""

    __tablename__ = "message_hidden_for_user"
    __table_args__ = (
        UniqueConstraint(
            "message_id",
            "user_id",
            name="uq_message_hidden_for_user_message_id_user_id",
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

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    hidden_at = Column(DateTime, nullable=False, default=_utc_now)

    def __repr__(self):
        return (
            f"<MessageHiddenForUser(message_id={self.message_id}, "
            f"user_id={self.user_id})>"
        )
