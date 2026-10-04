"""
Payload serialization.

Converts a Payload's native content into bytes for encryption, and
raw bytes back into native content after decryption. Independent of
networking (no packet/socket knowledge here) and independent of
encryption (no crypto/ import here, and nothing here touches
AESCipher or any adapter) -- these two functions are the one place
payload_type branches into an actual encoding.

TEXT encodes/decodes as UTF-8. FILE, IMAGE, VOICE and VIDEO (Phase 6
-- Secure File & Image Transfer Infrastructure; Phase 19.24 -- Voice/
Video Messages) are already raw bytes by the time they reach here --
a passthrough, not an encoding -- since the "content" of a binary
payload IS the bytes to encrypt. Voice/video need no encoding of their
own precisely because they are just recorded bytes, exactly like any
other binary attachment.
"""

from domain.payload_type import PayloadType

_BINARY_PASSTHROUGH_TYPES = frozenset({
    PayloadType.FILE, PayloadType.IMAGE, PayloadType.VOICE, PayloadType.VIDEO,
})


def serialize_payload(payload) -> bytes:
    """Payload -> bytes, ready for encryption."""

    # Phase 19.24: a reaction's "content" is a short string (e.g. a
    # single emoji) -- UTF-8 text, the same encoding TEXT already uses,
    # not a distinct format needing its own branch.
    if payload.payload_type in (PayloadType.TEXT, PayloadType.REACTION):
        return payload.content.encode("utf-8")

    if payload.payload_type in _BINARY_PASSTHROUGH_TYPES:
        return payload.content

    raise ValueError(
        f"Unsupported payload_type for serialization: {payload.payload_type!r}"
    )


def deserialize_payload(payload_type, data: bytes):
    """bytes -> native content, after decryption."""

    if payload_type in (PayloadType.TEXT, PayloadType.REACTION):
        return data.decode("utf-8")

    if payload_type in _BINARY_PASSTHROUGH_TYPES:
        return data

    raise ValueError(
        f"Unsupported payload_type for deserialization: {payload_type!r}"
    )
