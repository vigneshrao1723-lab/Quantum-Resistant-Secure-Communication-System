"""
Reaction Payload Adapter (Phase 19.24 -- Message Lifecycle Events).

Implements PayloadAdapter (payload/adapter.py) for payload_type
"reaction" -- a reaction string (e.g. a single emoji) gets the exact
same E2E treatment as a text message: AES-256-GCM under the
conversation's current epoch key, a fresh random nonce per encryption
(crypto/aes.py::AESCipher._generate_nonce()), the server never seeing
plaintext. Mirrors payload/text_adapter.py exactly -- content is a
plain string, encoded/decoded identically -- because domain/
payload_serializer.py treats PayloadType.REACTION as UTF-8 text, the
same as PayloadType.TEXT (see that module's own comment).

Deliberately its own adapter (not "just reuse TextPayloadAdapter
directly") so payload_type is correctly stamped PayloadType.REACTION
on the resulting envelope -- what routes a reaction's ciphertext into
message_reactions.ciphertext instead of being mistaken for an ordinary
chat message.
"""

from typing import Any

from domain.payload import Payload
from domain.payload_envelope import PayloadEnvelope
from domain.payload_serializer import deserialize_payload, serialize_payload
from domain.payload_type import PayloadType
from payload.adapter import PayloadAdapter


class ReactionPayloadAdapter(PayloadAdapter):
    """PayloadAdapter implementation for PayloadType.REACTION."""

    payload_type = PayloadType.REACTION

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
