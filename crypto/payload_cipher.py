"""
Payload encryption (generic).

The pipeline's Encryption stage for any payload type with no legacy
wire format to preserve: turns serialized payload bytes into a
wire-ready PayloadEnvelope, and back. Operates purely on bytes --
never branches on payload_type (that already happened one layer up,
in domain/payload_serializer.py) and never touches packet or network
code (utils/protocol.py, one layer down). AESCipher (crypto/aes.py)
is unmodified and stays str-based; arbitrary bytes are base64-encoded
into a string at this boundary so any future binary payload can flow
through it unchanged.

"text" does NOT use this module in practice -- see
payload/text_adapter.py for why (byte-compatibility with ciphertext
already persisted before this pipeline existed). This module is the
strategy a future binary payload type (file, image, voice, video)
uses directly, with no such legacy constraint to work around.
"""

import base64

from domain.payload_envelope import PayloadEnvelope
from domain.payload_serializer import deserialize_payload, serialize_payload


def encrypt_payload(payload, aes) -> PayloadEnvelope:
    """Serialize + encrypt a Payload into a wire-ready PayloadEnvelope."""

    data = serialize_payload(payload)

    ciphertext = aes.encrypt(base64.b64encode(data).decode("ascii"))

    return PayloadEnvelope(
        payload_type=payload.payload_type,
        ciphertext=ciphertext,
        content_metadata=payload.content_metadata,
    )


def decrypt_payload(envelope, aes):
    """Decrypt + deserialize a PayloadEnvelope back into native content."""

    data = base64.b64decode(aes.decrypt(envelope.ciphertext))

    return deserialize_payload(envelope.payload_type, data)
