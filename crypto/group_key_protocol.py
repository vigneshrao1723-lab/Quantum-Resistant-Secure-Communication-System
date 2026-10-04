"""
Group-Key-Distribution ML-DSA Origin Authentication

Phase 11/12A authenticated the public identity/key-distribution
ANNOUNCEMENT packet. Phase 12B authenticated application MESSAGES.
Neither touched "group_key_distribution" -- the packet that delivers
one member's wrapped copy of a group's shared AES key (client/
session.py::_distribute_group_key()/handle_group_key_distribution()).
That packet had ZERO origin authentication: ClientSession.
handle_group_key_distribution()'s own (pre-existing) docstring says
outright "Uses only this client's own private key material; nothing
from the sender is needed beyond the packet's opaque fields" -- i.e.
ANYONE holding the recipient's PUBLIC ML-KEM key (broadcast to every
connected client by design) can independently encapsulate a fresh
shared secret and AES-GCM-wrap an ARBITRARY key of their own choosing;
the recipient's decapsulation succeeds regardless of who produced it.
ML-KEM-then-DEM gives CONFIDENTIALITY (only the intended recipient's
private key can ever recover the wrapped key) -- it gives no
AUTHENTICITY at all (see this module's own docstring below, and this
phase's final report, Part 7, for the fuller confidentiality-vs-
authenticity distinction). This module closes that gap.

Mirrors crypto/identity_protocol.py's and crypto/message_protocol.py's
exact shape (canonical encoding function + thin sign/verify wrappers
around crypto/ml_dsa.py::MLDSASigner -- no second ML-DSA
implementation) for a third, structurally distinct signed-payload
purpose. Kept as its own module, with its own fixed domain-separation
purpose, for the same reason the other two are separate: a signature
valid for one purpose must never be mistakable for another, even
though all three ultimately use the same per-user MLDSASigner.

CRITICAL TRUST RULE (see client/session.py::
handle_group_key_distribution()'s own docstring for the enforcement):
verify_group_key_payload() takes the verification key as a parameter
-- it is the CALLER's responsibility to resolve that key from the
receiver's own, already-established (and, for group-key distribution
specifically, VERIFIED) peer identity state, never from anything
inside the group_key_distribution packet. That packet carries no
ML-DSA public-key field at all; there is nothing here for a malicious
sender/server to substitute their own key into.
"""

import struct

from crypto.identity_protocol import _coerce_to_bytes
from crypto.ml_dsa import MLDSASigner

# Fixed, non-secret domain-separation prefix for this signed-payload
# purpose (a group-key-distribution delivery). Distinct from
# crypto/identity_protocol.py's IDENTITY_PAYLOAD_PURPOSE, crypto/
# message_protocol.py's MESSAGE_PAYLOAD_PURPOSE, and crypto/ml_dsa.py's
# own fixed _CONTEXT -- see this module's docstring. Never transmitted
# on the wire; both sides already know it.
GROUP_KEY_PAYLOAD_PURPOSE = b"qrscs-group-key-v1"


def canonical_group_key_payload(
    sender,
    conversation_id,
    recipient,
    encapsulation,
    wrapped_key,
    epoch,
    purpose=GROUP_KEY_PAYLOAD_PURPOSE,
):
    """
    ONE canonical, deterministic byte encoding of a group-key-
    distribution delivery -- the exact bytes signed by the sender
    (client/session.py::_distribute_group_key()) and reconstructed and
    verified by the receiver (handle_group_key_distribution()). Both
    call this SAME function; neither reimplements the encoding.

    Binds (each as a 4-byte unsigned big-endian length prefix followed
    by its raw bytes, exactly crypto/identity_protocol.py's and
    crypto/message_protocol.py's established convention):

        purpose
      + sender
      + conversation_id
      + recipient
      + encapsulation   (empty string in RSA mode -- see below)
      + wrapped_key
      + epoch            (4-byte unsigned big-endian integer)

    This packet is inherently per-recipient (create_group_key_
    distribution_packet() sends one packet per member, each with its
    own encapsulation/wrapped_key) -- ``recipient`` is bound so an
    attacker cannot take a genuinely-signed delivery addressed to one
    member and re-address it to another, even though the wrapped key
    material itself would fail to decapsulate under a different
    member's private key anyway (defense in depth, and what actually
    stops a signature-swap attempt from silently no-op'ing instead of
    being caught explicitly).

    ``encapsulation`` is None in RSA mode (crypto/key_manager.py::
    wrap_key_for_member()'s own documented return shape: "encapsulation
    is the Kyber ciphertext in KYBER mode, or None in RSA mode") --
    coerced to an empty string here, the same treatment crypto/
    message_protocol.py already gives an absent receiver/
    conversation_id.

    ``epoch`` identifies which group-key epoch (crypto/key_manager.py)
    this delivery establishes -- security-relevant (KeyManager.
    store_key() addresses conversation history by exactly this value,
    and server/client_handler.py::handle_group_key_distribution()
    already bounds it against the server's own reserved epoch) and
    bound here so an attacker cannot replay/relabel a genuine delivery
    under a different epoch number. Normalized to 1 if falsy (None/0),
    matching every other epoch-handling call site in this codebase's
    "epoch or 1" convention -- though every real caller of this
    function always passes an explicit epoch >= 1.
    """

    sender = _coerce_to_bytes("sender", sender)
    conversation_id = _coerce_to_bytes("conversation_id", conversation_id)
    recipient = _coerce_to_bytes("recipient", recipient)
    encapsulation = _coerce_to_bytes("encapsulation", encapsulation or "")
    wrapped_key = _coerce_to_bytes("wrapped_key", wrapped_key)

    if not isinstance(purpose, (bytes, bytearray)):
        raise TypeError(
            f"purpose must be bytes-like, not {type(purpose).__name__}."
        )

    epoch_value = int(epoch) if epoch else 1

    def _framed(value):
        return struct.pack(">I", len(value)) + value

    return (
        bytes(purpose)
        + _framed(sender)
        + _framed(conversation_id)
        + _framed(recipient)
        + _framed(encapsulation)
        + _framed(wrapped_key)
        + struct.pack(">I", epoch_value)
    )


def sign_group_key_payload(
    ml_dsa_signer, sender, conversation_id, recipient, encapsulation, wrapped_key, epoch
):
    """
    Sign the canonical group-key-distribution payload with
    ``ml_dsa_signer``'s private key -- a crypto.ml_dsa.MLDSASigner
    instance already holding a private key (crypto/key_manager.py::
    KeyManager.ml_dsa, the same persistent signer already used for
    identity announcements and messages). The private key never leaves
    that object; this function only ever calls its .sign() method and
    returns the resulting signature bytes.
    """

    payload = canonical_group_key_payload(
        sender, conversation_id, recipient, encapsulation, wrapped_key, epoch,
    )

    return ml_dsa_signer.sign(payload)


def verify_group_key_payload(
    sender, conversation_id, recipient, encapsulation, wrapped_key, epoch,
    signature, signing_public_key,
):
    """
    Verify that ``signature`` is a valid ML-DSA-65 signature, under
    ``signing_public_key``, over the canonical group-key-distribution
    payload for exactly these fields.

    ``signing_public_key`` MUST be resolved by the caller from the
    receiver's own, already-established (and VERIFIED -- see this
    module's docstring's CRITICAL TRUST RULE and client/session.py::
    handle_group_key_distribution()'s own enforcement) peer identity
    state. This function has no way to look that up itself and does
    not try to; it verifies against exactly the key it is given.

    Returns:
        True  -- valid signature for exactly these fields, under this
                 key.
        False -- well-formed input, but the signature does not verify.

    Raises:
        TypeError/ValueError -- any field is malformed, mirroring
        MLDSASigner.verify()'s fail-closed convention exactly. A
        caller receiving untrusted network input should treat both
        this exception case and a False return the same way: reject
        the packet.
    """

    payload = canonical_group_key_payload(
        sender, conversation_id, recipient, encapsulation, wrapped_key, epoch,
    )

    return MLDSASigner.verify(payload, signature, signing_public_key)
