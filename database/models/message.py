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
from sqlalchemy.dialects.postgresql import JSONB, UUID

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

    # Expand step of an expand-and-contract migration (Architecture
    # Blueprint v2, Phase 1): nullable and unread by every existing
    # query. receiver_id remains the required, authoritative field.
    # New messages populate this via ConversationRepository; historical
    # rows are left NULL until a later phase needs to read through it.
    conversation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Expand step of an expand-and-contract migration (Architecture
    # Blueprint v2, Phase 6 -- Secure File & Image Transfer
    # Infrastructure): nullable. A row's ciphertext is NULL exactly
    # when blob_ref is set -- content too large to store inline
    # (currently: PayloadType.FILE/IMAGE, see
    # domain/payload_type.py's BLOB_STORAGE_PAYLOAD_TYPES) lives in
    # blob_ref's referenced storage instead. Every text message,
    # historical or new, is entirely unaffected: ciphertext keeps
    # holding the value directly, exactly as before.
    ciphertext = Column(Text, nullable=True)

    # Opaque reference into storage/encrypted_blob_store.py, set only
    # for messages whose ciphertext was too large to store inline
    # (see the ciphertext column above). Deliberately a plain nullable
    # string, not a foreign key to another table: a blob reference is
    # a single optional pointer with no independent relational data of
    # its own, so a dedicated table would add structure without a
    # reason to.
    #
    # This column is intentionally an implementation detail of the
    # *current* storage backend (a UUID4 filename under
    # FILE_STORAGE_ROOT) rather than a generic abstraction of its own.
    # If a future phase introduces additional storage backends (cloud
    # object storage, distributed storage, a different inline
    # strategy, ...), this field can evolve into a generic payload
    # reference (e.g. gaining a backend discriminator) without any
    # change to the cryptographic or payload architecture above it --
    # PayloadType, content_metadata, and PayloadAdapter are already the
    # only things that differentiate payload kinds, and none of them
    # need to know how or where blob_ref's target is actually stored.
    blob_ref = Column(String(64), nullable=True)

    algorithm = Column(String(32), nullable=False)

    # Expand step of an expand-and-contract migration (Architecture
    # Blueprint v2, Phase 3 -- Universal Secure Payload Architecture):
    # nullable and additive. New messages populate payload_type via
    # persist_message(); historical rows (and, for now, every payload
    # type other than "text") leave content_metadata NULL. Storing
    # ciphertext-and-metadata-only here is unchanged -- the server
    # still never has plaintext. content_metadata is JSONB (structured
    # key/value descriptors, never free text) so SQLAlchemy binds/reads
    # a plain Python dict directly, no manual JSON (de)serialization.
    payload_type = Column(String(32), nullable=True)
    content_metadata = Column(JSONB, nullable=True)

    timestamp = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=_utc_now)

    def __repr__(self):
        return (
            f"<Message(id={self.id}, sender_id={self.sender_id}, "
            f"receiver_id={self.receiver_id}, algorithm={self.algorithm})>"
        )
