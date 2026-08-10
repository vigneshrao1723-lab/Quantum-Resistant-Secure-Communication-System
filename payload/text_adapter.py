"""
Text Payload Adapter.

Implements PayloadAdapter (payload/adapter.py) for payload_type
"text" -- the compatibility layer between the pre-existing
text-messaging code path and the universal payload pipeline
(Payload -> Serialization -> Encryption -> Packet -> Network).

Deliberately does NOT use crypto/payload_cipher.py's generic,
base64-based encrypt_payload()/decrypt_payload() -- that would change
the ciphertext bytes produced for text compared to what has always
been produced (a direct AESCipher.encrypt(str) call, no base64),
making every message persisted before this pipeline existed
undecryptable. This adapter performs the exact same operation
instead, expressed through the Payload/PayloadEnvelope vocabulary:

    data = payload.content.encode("utf-8")   # serialize_payload()
    ciphertext = aes.encrypt(data.decode("utf-8"))   # a lossless
    # round trip of the same bytes -- byte-for-byte identical to
    # aes.encrypt(payload.content) directly.

So:
  - New text messages sent through this adapter produce byte-for-byte
    identical ciphertext to the pre-existing code path.
  - Historical ciphertext (encrypted before this pipeline existed)
    decrypts through this same adapter without any migration, because
    the decrypt operation is unchanged.
  - The result is still a proper PayloadEnvelope, so it flows through
    create_payload_packet()/persist_message() exactly like any other
    payload type would.
"""

from typing import Any

from domain.payload import Payload
from domain.payload_envelope import PayloadEnvelope
from domain.payload_serializer import deserialize_payload, serialize_payload
from domain.payload_type import PayloadType
from payload.adapter import PayloadAdapter


class TextPayloadAdapter(PayloadAdapter):
    """PayloadAdapter implementation for PayloadType.TEXT."""

    payload_type = PayloadType.TEXT

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

        data = serialize_payload(payload)

        ciphertext = aes.encrypt(data.decode("utf-8"))

        return PayloadEnvelope(
            payload_type=payload.payload_type,
            ciphertext=ciphertext,
            content_metadata=payload.content_metadata,
        )

    def decrypt(self, envelope: PayloadEnvelope, aes):

        data = aes.decrypt(envelope.ciphertext).encode("utf-8")

        return deserialize_payload(self.payload_type, data)
