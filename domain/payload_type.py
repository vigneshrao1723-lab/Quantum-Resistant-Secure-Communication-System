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
    # Phase 19.24 -- Message Lifecycle Events: exactly the "small
    # reaction/read-receipt marker" this module's own comment (below)
    # already anticipated. Never routed to blob storage (see
    # BLOB_STORAGE_PAYLOAD_TYPES below) -- a few bytes of JSON, always
    # stored inline in message_reactions.ciphertext, never in
    # messages.ciphertext (reactions are not Message rows at all; see
    # database/models/message_reaction.py).
    REACTION = "reaction"
    # Phase 19.24 -- Voice/Video Messages. Deliberately NOT a new
    # protocol/crypto path: a recorded clip is read into memory exactly
    # like any other local file and pushed through the SAME send_
    # attachment()/AES-256-GCM/ML-DSA/blob-storage pipeline FILE/IMAGE
    # already use (see BLOB_STORAGE_PAYLOAD_TYPES below and client/
    # session.py::send_attachment()'s own docstring) -- these two
    # members exist only so a receiver renders a play control instead
    # of a generic file/download link; they carry no new security
    # properties of their own to reason about.
    VOICE = "voice"
    VIDEO = "video"


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
BLOB_STORAGE_PAYLOAD_TYPES = frozenset({
    PayloadType.FILE, PayloadType.IMAGE, PayloadType.VOICE, PayloadType.VIDEO,
})


def classify_attachment(filename: str) -> PayloadType:
    """
    Classify a local file by name into PayloadType.IMAGE, PayloadType.
    VOICE, PayloadType.VIDEO, or PayloadType.FILE (Phase 8 -- File &
    Image Transfer; Phase 19.24 -- Voice/Video), by MIME type via the
    standard library's extension table -- not a hand-rolled extension
    whitelist. Anything not recognized as an "image/*", "audio/*" or
    "video/*" MIME type (including an unrecognized or missing
    extension) is a plain FILE; the caller never asks the user to
    choose manually.

    A caller that RECORDED the bytes itself (gui/chat_window.py's
    voice/video recorder dialogs) still goes through this exact same
    function -- it writes the recording to a temp file with a real
    extension (.m4a/.mp4) first, precisely so classification never
    needs a second, recording-specific code path.
    """

    # strict=False: the standard library's strict table omits some
    # real, common image types (.webp being the concrete one found in
    # Phase 19.17C -- an Android-picked .webp photo was silently
    # misclassified as PayloadType.FILE at the sender, before it ever
    # reached the wire, making every receiving client's otherwise-
    # correct payload_type check show a generic file/download instead
    # of the image). strict=False adds mimetypes.common_types on top
    # of the strict table without removing anything from it.
    mime_type, _ = mimetypes.guess_type(filename, strict=False)

    if mime_type and mime_type.startswith("image/"):
        return PayloadType.IMAGE

    if mime_type and mime_type.startswith("audio/"):
        return PayloadType.VOICE

    if mime_type and mime_type.startswith("video/"):
        return PayloadType.VIDEO

    return PayloadType.FILE
