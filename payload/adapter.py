"""
Payload Adapter interface.

The common structural contract every payload type's encryption
adapter satisfies: turn native content into a wire-ready
PayloadEnvelope, and recover native content from one.
TextPayloadAdapter (payload/text_adapter.py) is the only
implementation today; a future Image/File/Voice/Video adapter
implements the same two methods without requiring any change here or
in any of this interface's callers (client/session.py,
server/client_handler.py).

A typing.Protocol rather than an ABC: structural, not nominal --
anything with a matching payload_type attribute and encrypt()/
decrypt() methods satisfies this interface, with or without
explicitly inheriting from it.

An adapter is free to implement encrypt()/decrypt() however its
payload_type requires. A payload type with no legacy wire format to
preserve would typically delegate to crypto/payload_cipher.py's
generic, base64-based encrypt_payload()/decrypt_payload(); a payload
type that predates this interface (text) implements its own
compatibility-preserving strategy instead -- the interface itself
takes no position on which.
"""

from typing import Any, Protocol, runtime_checkable

from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType


@runtime_checkable
class PayloadAdapter(Protocol):
    """Encrypts/decrypts one payload_type's content into/out of a PayloadEnvelope."""

    payload_type: PayloadType

    def encrypt(
        self,
        content,
        aes,
        content_metadata: dict[str, Any] | None = None,
    ) -> PayloadEnvelope:
        """
        Encrypt native content (this adapter's payload_type) into a
        PayloadEnvelope, ready for create_payload_packet().
        """
        ...

    def decrypt(self, envelope: PayloadEnvelope, aes):
        """
        Decrypt a PayloadEnvelope back into native content for this
        adapter's payload_type.
        """
        ...
