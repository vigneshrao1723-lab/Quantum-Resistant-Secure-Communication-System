"""
Payload serialization.

Converts a Payload's native content into bytes for encryption, and
raw bytes back into native content after decryption. Independent of
networking (no packet/socket knowledge here) and independent of
encryption (no crypto/ import here, and nothing here touches
AESCipher or any adapter) -- these two functions are the one place
payload_type branches into an actual encoding.

TEXT encodes/decodes as UTF-8. FILE and IMAGE (Phase 6 -- Secure File
& Image Transfer Infrastructure) are already raw bytes by the time
they reach here -- a passthrough, not an encoding -- since the
"content" of a binary payload IS the bytes to encrypt. This is still
the extension point a future voice or video payload type adds a
branch to, should it ever need something other than a raw passthrough.
"""

from domain.payload_type import PayloadType

_BINARY_PASSTHROUGH_TYPES = frozenset({PayloadType.FILE, PayloadType.IMAGE})


def serialize_payload(payload) -> bytes:
    """Payload -> bytes, ready for encryption."""

    if payload.payload_type == PayloadType.TEXT:
        return payload.content.encode("utf-8")

    if payload.payload_type in _BINARY_PASSTHROUGH_TYPES:
        return payload.content

    raise ValueError(
        f"Unsupported payload_type for serialization: {payload.payload_type!r}"
    )


def deserialize_payload(payload_type, data: bytes):
    """bytes -> native content, after decryption."""

    if payload_type == PayloadType.TEXT:
        return data.decode("utf-8")

    if payload_type in _BINARY_PASSTHROUGH_TYPES:
        return data

    raise ValueError(
        f"Unsupported payload_type for deserialization: {payload_type!r}"
    )
