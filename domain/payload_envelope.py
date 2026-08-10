"""
Payload envelope domain model.

Framework-free (no Qt, no SQLAlchemy, no network dependency). The
wire/storage shape from Architecture Blueprint v2 (S02 Payload
Pipeline): what a packet carries and what persist_message() stores --
already-encrypted content plus the bookkeeping needed to route and
render it, never plaintext.
"""

from dataclasses import dataclass, field
from typing import Any

from domain.payload_type import PayloadType


@dataclass
class PayloadEnvelope:
    """One payload's wire/storage representation, post-encryption.

    ``payload_type`` is only ever PayloadType.TEXT today. ``ciphertext``
    is whatever AESCipher.encrypt() (or a payload-type-specific
    adapter/cipher built on it) produced -- opaque to every layer
    above Encryption. ``content_metadata`` is unused until a future
    payload type needs to carry non-secret descriptors (filename,
    mime type, duration, ...).
    """

    payload_type: PayloadType
    ciphertext: str
    content_metadata: dict[str, Any] = field(default_factory=dict)
