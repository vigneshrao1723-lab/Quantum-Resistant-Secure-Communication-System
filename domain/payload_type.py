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

import mimetypes
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


def classify_attachment(filename: str) -> PayloadType:
    """
    Classify a local file by name into PayloadType.IMAGE or
    PayloadType.FILE (Phase 8 -- File & Image Transfer), by MIME type
    via the standard library's extension table -- not a hand-rolled
    extension whitelist. Anything not recognized as an "image/*" MIME
    type (including an unrecognized or missing extension) is a plain
    FILE; there is no third bucket at attach time, and the caller never
    asks the user to choose manually.
    """

    mime_type, _ = mimetypes.guess_type(filename)

    if mime_type and mime_type.startswith("image/"):
        return PayloadType.IMAGE

    return PayloadType.FILE
