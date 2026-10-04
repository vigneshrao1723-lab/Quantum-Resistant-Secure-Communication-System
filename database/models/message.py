"""
Message model for persisted private chat messages.

Stores ciphertext only -- the server never has access to plaintext.
Encryption and decryption happen entirely on the clients (see
crypto/aes.py, crypto/key_manager.py); no key material is stored in
this table, or anywhere else server-side.

A row is written when a private message is accepted, whether or not
the recipient was connected at the time (C1 -- Offline Direct-Message
Persistence). A message addressed to a real, registered user who is
simply offline is persisted exactly like a live-relayed one; the two
differ only in delivery state, never in content or storage.

Delivery state deliberately lives in a separate table
(database/models/message_recipient.py), not in a column here: QUEUED
means persisted but not yet relayed, DELIVERED means actually relayed
to the recipient, and READ extends the same row further. Keeping it
separate is what lets this table stay a pure record of content, and
lets one message carry per-recipient state.

Nothing is persisted when there is no real recipient to persist under
-- receiver_id is a required foreign key -- so a message to a
username that was never registered is still stored nowhere at all.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
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

    # Expand step of an expand-and-contract migration (Architecture
    # Blueprint v2, Phase 7 -- Group Membership Management): nullable.
    # Which group-key epoch (crypto/key_manager.py) encrypted this
    # row's ciphertext -- NULL on every historical row, interpreted as
    # 1 everywhere it's read (no rotation mechanism existed before
    # this phase, so every prior message really was epoch 1; NULL->1
    # is a true statement about the past, not a convenient default).
    # Direct messages are always epoch 1 and never change. A group
    # conversation that has rotated has messages at multiple epochs in
    # the same conversation_id -- this column is what lets history
    # loading pick the correct historical key per message instead of
    # decrypting everything with whatever key is current "now".
    epoch = Column(Integer, nullable=True)

    # Expand step of an expand-and-contract migration (Message-Level
    # ML-DSA Origin Authentication): nullable. Base64-encoded ML-DSA-65
    # signature over crypto/message_protocol.py::
    # canonical_message_payload() for this row -- carried alongside the
    # ciphertext into offline storage so a signature produced at send
    # time survives being queued and later delivered through history
    # loading (client/session.py::_decrypt_history_message() verifies
    # it). NULL on every row from before this phase, and treated
    # identically to a missing "message_signature" field on the live
    # "chat" packet: unsigned, reject.
    message_signature = Column(Text, nullable=True)

    timestamp = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=_utc_now)

    # Phase 19.24 -- Message Lifecycle Events. Expand step, purely
    # additive and nullable, following the exact same expand-and-
    # contract convention every column above documents.

    # REPLY: the logical message this one is a reply to, or NULL for
    # an ordinary message. A real foreign key (not a content_metadata
    # field) deliberately -- it is structural addressing, not a
    # payload-specific descriptor, and a real FK lets ON DELETE SET
    # NULL do the right thing automatically the moment a replied-to
    # message is later deleted-for-everyone (server/client_handler.py::
    # handle_message_delete_for_everyone() also nulls the referenced
    # row's OWN ciphertext, so a reply's local "quoted preview" cache
    # is what a client must fall back to -- see docs/architecture/
    # messaging_event_architecture.md's Reply section). Self-referential
    # FK on the same table, same ondelete semantics as every other FK
    # in this file.
    reply_to_message_id = Column(
        UUID(as_uuid=True),
        ForeignKey("messages.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # EDIT: NULL until the first edit; set (and re-set) by
    # handle_message_edit() every time the ORIGINAL SENDER (re-derived
    # server-side, never trusted from the packet -- see that handler's
    # own docstring) submits a new ciphertext for this SAME message_id.
    # edit_version starts at 0 and increments on every accepted edit --
    # it is this row's own optimistic-concurrency/out-of-order guard:
    # an edit_edit packet naming an edit_version older than what is
    # already stored is a stale/duplicate/replayed event and is
    # rejected, never silently applied out of order (see
    # handle_message_edit()).
    edited_at = Column(DateTime, nullable=True)
    edit_version = Column(Integer, nullable=False, default=0)

    # DELETE FOR EVERYONE: NULL until deleted. Deletion is REAL data
    # minimization, not a soft UI flag -- handle_message_delete_for_
    # everyone() also NULLs ciphertext/blob_ref/content_metadata/
    # message_signature on this same row (and removes the referenced
    # encrypted_blob_store blob, for FILE/IMAGE payloads) at the same
    # time it sets these two columns, so the plaintext-producing
    # ciphertext genuinely no longer exists server-side after this --
    # not merely hidden from normal queries. deleted_by is the
    # authenticated actor who performed it (always the original
    # sender -- see that handler's docstring for why no broader
    # "admin can delete" policy was added), kept for audit/UI
    # attribution ("You deleted this message" vs "This message was
    # deleted"), itself surviving even though the content it refers to
    # does not.
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # PIN: NULL until pinned. Unlike EDIT/DELETE above, there is no
    # ciphertext-bearing content here to protect -- pin/unpin carries
    # no message content of its own (just "this existing message is
    # currently pinned"), so it needs no AES-256-GCM envelope and no
    # per-event ML-DSA signature, exactly like deleted_at/deleted_by
    # above carry no signature of their own: the actor is always the
    # server-derived authenticated connection (server/client_handler.py
    # ::handle_message_pin()), never a client-supplied field, and that
    # is the same trust boundary this whole table already rests on.
    # Authorization is "an ACTIVE member of this message's conversation"
    # -- deliberately broader than EDIT/DELETE's sender-only rule (see
    # handle_message_pin()'s own docstring for the full trust-model
    # rationale) -- any participant may pin/unpin, mirroring ordinary
    # messenger conventions, not just the original sender.
    pinned_at = Column(DateTime, nullable=True)
    pinned_by = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # RETRY IDEMPOTENCY: an optional client-generated UUID (v4, as a
    # string) a sender attaches to a live "chat" packet so a retried
    # send after an ambiguous network failure (the client never learned
    # whether the original attempt was actually persisted) cannot
    # create a second, duplicate message -- persist_message() treats a
    # UNIQUE-constraint collision on this column as "already persisted,
    # return the existing row" rather than an error (see server/
    # client_handler.py::persist_message()'s own docstring). NULL for
    # any client/message that predates this phase or does not supply
    # one -- retry-safety is additive, never required.
    client_message_id = Column(String(36), nullable=True, unique=True)

    def __repr__(self):
        return (
            f"<Message(id={self.id}, sender_id={self.sender_id}, "
            f"receiver_id={self.receiver_id}, algorithm={self.algorithm})>"
        )
