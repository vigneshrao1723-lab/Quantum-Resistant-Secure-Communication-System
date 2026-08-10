"""
File Payload Adapter.

Implements PayloadAdapter (payload/adapter.py) for binary payload
types (Phase 6 -- Secure File & Image Transfer Infrastructure):
PayloadType.FILE and PayloadType.IMAGE. Unlike TextPayloadAdapter,
there is no legacy wire format to preserve here, so this adapter
delegates directly to crypto/payload_cipher.py's generic, base64-based
encrypt_payload()/decrypt_payload() -- exactly the reuse that module
was built anticipating.

One class, not two: FILE and IMAGE differ only in which PayloadType
they carry (and, at the caller, in content_metadata) -- their
encryption strategy is identical, so client/session.py registers this
same adapter twice, once per payload_type, rather than duplicating an
otherwise-identical class body.
"""

from typing import Any

from crypto.payload_cipher import decrypt_payload, encrypt_payload
from domain.payload import Payload
from domain.payload_envelope import PayloadEnvelope


class FilePayloadAdapter:
    """PayloadAdapter implementation for a binary payload_type."""

    def __init__(self, payload_type):
        self.payload_type = payload_type

    def encrypt(
        self,
        content,
        aes,
        content_metadata: dict[str, Any] | None = None,
    ) -> PayloadEnvelope:

        payload = Payload(
            payload_type=self.payload_type,
            content=content,
            content_metadata=content_metadata or {},
        )

        return encrypt_payload(payload, aes)

    def decrypt(self, envelope: PayloadEnvelope, aes):
        return decrypt_payload(envelope, aes)
