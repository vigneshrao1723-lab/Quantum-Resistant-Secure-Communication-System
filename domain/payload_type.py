"""
Payload type enum.

The single source of truth for every payload_type value used across
the payload pipeline (Payload, PayloadEnvelope, PayloadAdapter,
packets, and persisted messages) -- replaces raw string literals so a
typo or drift between layers is a type error, not a silent runtime
mismatch. A future payload type adds a member here, which every layer
that compares or defaults on payload_type immediately benefits from.

A StrEnum (not a plain Enum): its members ARE str instances, so they
serialize over JSON (packets) and bind into a String database column
exactly like a plain string, with no extra (de)serialization step
anywhere in the pipeline.
"""

from enum import StrEnum


class PayloadType(StrEnum):
    TEXT = "text"
    FILE = "file"
    IMAGE = "image"


# Which payload types store their ciphertext externally (via
# storage/encrypted_blob_store.py) rather than inline in
# messages.ciphertext (Phase 6 -- Secure File & Image Transfer
# Infrastructure). Colocated with the type definitions themselves so a
# future binary payload type (voice, video, ...) opts in with the same
# one-line edit that adds its enum member -- neither
# server/client_handler.py nor the storage backend ever need to change
# again. TEXT is deliberately not just "everything but TEXT": a future
# payload type with no reason to leave the database (e.g. a small
# reaction/read-receipt marker) should not be silently routed to blob
# storage just because it isn't TEXT.
BLOB_STORAGE_PAYLOAD_TYPES = frozenset({PayloadType.FILE, PayloadType.IMAGE})
