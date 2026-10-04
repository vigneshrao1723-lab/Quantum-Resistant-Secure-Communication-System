"""
Message reaction model (Phase 19.24 -- Message Lifecycle Events).

One row per (message, user) -- a user has at most one active reaction
on a given message at a time (adding a new one REPLACES the old one in
place, mirroring the "add/remove" singular semantics of the
reaction_add/reaction_remove protocol events; there is no concept of
one user stacking multiple simultaneous reactions on the same
message).

``ciphertext`` holds the small (a few bytes of JSON, e.g. {"reaction":
"\U0001F44D"}) AES-256-GCM payload produced by payload/reaction_adapter.py,
encrypted under the SAME per-conversation epoch key every other message
in this conversation already uses (crypto/key_manager.py) -- the server
never learns which emoji was chosen, only who reacted to what and when.
This is deliberately NOT a plain string column: reactions get the exact
same E2E treatment as message content, with no special-cased exception
for being "just metadata" (Phase 19.24 mandate: "Protect the event
using the existing secure protocol architecture").

epoch records which conversation-key epoch the ciphertext is encrypted
under, the same way messages.epoch does, so a client can always find
the right decryption key regardless of any later key rotation.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime -- see database/models/
    message.py's identical helper for the full rationale."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class MessageReaction(Base):
    """One user's current reaction on one message."""

    __tablename__ = "message_reactions"
    __table_args__ = (
        UniqueConstraint(
            "message_id",
            "user_id",
            name="uq_message_reactions_message_id_user_id",
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

    ciphertext = Column(Text, nullable=False)
    epoch = Column(Integer, nullable=False)

    # Phase 19.24 (continued) -- receiver-side verification. Base64
    # ML-DSA-65 signature over crypto/message_protocol.py::
    # canonical_message_payload(..., purpose=REACTION_PAYLOAD_PURPOSE),
    # persisted alongside the ciphertext so a client that reconnects
    # later and recovers this reaction via history can verify its
    # origin exactly like a live reaction_updated notification already
    # can -- not just at the moment it first arrived. Nullable only for
    # a reaction that predates this column (there are none in practice,
    # since this ships in the same phase as reactions themselves).
    message_signature = Column(Text, nullable=True)

    created_at = Column(DateTime, nullable=False, default=_utc_now)
    updated_at = Column(
        DateTime, nullable=False, default=_utc_now, onupdate=_utc_now
    )

    def __repr__(self):
        return (
            f"<MessageReaction(message_id={self.message_id}, "
            f"user_id={self.user_id})>"
        )
