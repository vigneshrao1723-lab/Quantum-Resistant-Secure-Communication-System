"""
Message-Level ML-DSA Origin Authentication

Phase 11/12A gave the public identity/key-distribution ANNOUNCEMENT
packet (client/session.py::send_public_key()/handle_public_key()) a
cryptographic proof of origin. That proves who CONTROLS a given
(KEM, signing) identity -- it says nothing about who actually produced
any individual encrypted MESSAGE sent later. This module closes that
second gap: a canonical, signable envelope binding an already-encrypted
chat/attachment message to the sender who produced it, verifiable by
the receiver using that sender's already-established (Phase 7/8/11)
ML-DSA identity -- never a key embedded in the message packet itself.

Mirrors crypto/identity_protocol.py's exact shape (canonical encoding
function + thin sign/verify wrappers around crypto/ml_dsa.py::
MLDSASigner -- no second ML-DSA implementation) for a structurally
different payload: a MESSAGE, not an identity announcement. Kept as a
separate module rather than added to identity_protocol.py because the
two are different signed-payload PURPOSES with different bound fields
-- exactly the kind of confusion IDENTITY_PAYLOAD_PURPOSE/
MESSAGE_PAYLOAD_PURPOSE's domain separation exists to make impossible
even if a signature from one were replayed against the other.

What gets encrypted (AES-256-GCM, crypto/aes.py) and how a conversation
key is established (ML-KEM/RSA, crypto/key_manager.py) are both
completely unchanged -- this module only signs the envelope AFTER
encryption already produced its ciphertext, and only verifies it BEFORE
that ciphertext is ever decrypted. See client/session.py::
_send_encrypted_payload()/handle_chat() for exactly where each step is
wired into the real send/receive pipeline.

CRITICAL TRUST RULE (see client/session.py::handle_chat()'s own
docstring for the enforcement): verify_message_payload() takes the
verification key as a parameter -- it is the CALLER's responsibility to
resolve that key from the receiver's own, already-established peer
identity state (never from anything inside the message packet). A
message packet carries no ML-DSA public key field at all; there is
nothing here for a malicious sender to substitute their own key into.
"""

import json
import struct

from crypto.identity_protocol import _coerce_to_bytes
from crypto.ml_dsa import MLDSASigner

# Fixed, non-secret domain-separation prefix for this signed-payload
# purpose (an authenticated application message). Distinct from
# crypto/identity_protocol.py's IDENTITY_PAYLOAD_PURPOSE and from
# crypto/ml_dsa.py's own fixed _CONTEXT -- see this module's docstring.
# Never transmitted on the wire; both sides already know it.
MESSAGE_PAYLOAD_PURPOSE = b"qrscs-message-v1"

# Phase 19.24 (continued) -- Message Lifecycle Events receiver-side
# verification. Distinct purpose tags for EDIT and REACTION signatures
# -- canonical_message_payload()'s byte encoding is otherwise IDENTICAL
# in shape to an ordinary chat message's, so without a distinct purpose
# a legitimately-signed edit/reaction could canonicalize to the exact
# same bytes as some ordinary chat message with matching fields (or
# vice versa), which would let one be replayed as the other. Each
# purpose is used ONLY for its own event type, both at sign time
# (ClientSession.edit_message()/add_reaction()) and at verify time
# (handle_message_edited()/handle_reaction_updated()) -- never mixed.
EDIT_PAYLOAD_PURPOSE = b"qrscs-edit-v1"
REACTION_PAYLOAD_PURPOSE = b"qrscs-reaction-v1"


def _canonical_content_metadata(content_metadata):
    """
    Deterministic byte encoding of a message's content_metadata dict
    (filename/mime_type/size_bytes for an attachment; empty for text --
    see domain/payload_envelope.py). JSON with sorted keys and no
    incidental whitespace is deterministic for the plain str/int values
    this dict ever actually holds (never floats, never nested
    structures) -- the same reasoning storage/secure_key_store.py
    already relies on for its own JSON persistence layer. ``None`` is
    treated identically to ``{}`` (create_payload_packet() puts None on
    the wire for an empty metadata dict; PayloadEnvelope.content_metadata
    defaults to {} on the receiving side -- both must canonicalize
    identically, or a genuine message would fail its own signature
    check purely from that representational difference).
    """

    return json.dumps(
        content_metadata or {}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def canonical_message_payload(
    sender,
    receiver,
    conversation_id,
    payload_type,
    ciphertext,
    content_metadata,
    epoch,
    purpose=MESSAGE_PAYLOAD_PURPOSE,
):
    """
    ONE canonical, deterministic byte encoding of an authenticated
    application message -- the exact bytes signed by the sender
    (client/session.py::_send_encrypted_payload()) and reconstructed
    and verified by the receiver (handle_chat()). Both call this SAME
    function; neither reimplements the encoding.

    Binds (each as a 4-byte unsigned big-endian length prefix followed
    by its raw bytes, exactly crypto/identity_protocol.py::
    canonical_identity_payload()'s established convention):

        purpose
      + sender
      + receiver          (empty string if this is a group message)
      + conversation_id   (empty string if this is a direct message)
      + payload_type
      + ciphertext
      + canonical_content_metadata
      + epoch             (4-byte unsigned big-endian integer)

    ``receiver`` and ``conversation_id`` are bound as TWO separate
    fields -- never collapsed into "whichever one is set" -- so a
    direct message addressed to a username can never canonicalize to
    the same bytes as a group message addressed to a conversation_id
    that happens to equal that same string; create_payload_packet()
    already guarantees exactly one of the two is ever meaningful for a
    given packet, and this mirrors that shape exactly rather than
    inventing a new addressing convention.

    ``epoch`` identifies which conversation-key epoch (crypto/
    key_manager.py) encrypted this ciphertext -- already
    security-relevant (handle_chat() decrypts under exactly the epoch
    the packet claims, never "whatever key is current") and bound here
    for the same reason: an attacker must not be able to replay a
    genuine ciphertext+signature under a different epoch number.
    ``epoch`` is normalized to 1 if falsy (None/0), matching handle_
    chat()'s/create_payload_packet()'s own existing "epoch or 1"/
    "epoch: None" -> 1 convention exactly, so a sender that omits it
    and a receiver that defaults it always agree on what was signed.

    No message-identifier field exists in the current protocol (no
    message_id/UUID on this packet type) and none is invented here --
    see this phase's own report for why. ``timestamp`` is deliberately
    NOT bound: it is display-only, not used to look up encryption
    material or route the message, and binding it would make a
    perfectly genuine message's signature invalid the moment a
    resend/retry legitimately changed only the timestamp.
    """

    sender = _coerce_to_bytes("sender", sender)
    receiver = _coerce_to_bytes("receiver", receiver or "")
    conversation_id = _coerce_to_bytes("conversation_id", conversation_id or "")
    payload_type = _coerce_to_bytes("payload_type", payload_type)
    ciphertext = _coerce_to_bytes("ciphertext", ciphertext)

    if not isinstance(purpose, (bytes, bytearray)):
        raise TypeError(
            f"purpose must be bytes-like, not {type(purpose).__name__}."
        )

    metadata_bytes = _canonical_content_metadata(content_metadata)
    epoch_value = int(epoch) if epoch else 1

    def _framed(value):
        return struct.pack(">I", len(value)) + value

    return (
        bytes(purpose)
        + _framed(sender)
        + _framed(receiver)
        + _framed(conversation_id)
        + _framed(payload_type)
        + _framed(ciphertext)
        + _framed(metadata_bytes)
        + struct.pack(">I", epoch_value)
    )


def sign_message_payload(
    ml_dsa_signer,
    sender,
    receiver,
    conversation_id,
    payload_type,
    ciphertext,
    content_metadata,
    epoch,
    purpose=MESSAGE_PAYLOAD_PURPOSE,
):
    """
    Sign the canonical message payload with ``ml_dsa_signer``'s private
    key -- a crypto.ml_dsa.MLDSASigner instance already holding a
    private key (crypto/key_manager.py::KeyManager.ml_dsa, the same
    persistent signer Phase 11 already uses for identity announcements).
    The private key never leaves that object; this function only ever
    calls its .sign() method and returns the resulting signature bytes.

    ``purpose`` (continued Phase 19.24 -- Message Lifecycle Events
    receiver-side verification): defaults to the original, ordinary-
    chat-message purpose -- every pre-existing caller is unaffected.
    A caller signing a DIFFERENT event type over the same field shape
    (an edit, a reaction) passes EDIT_PAYLOAD_PURPOSE/REACTION_PAYLOAD_
    PURPOSE instead, so the two can never be confused with each other
    or with an ordinary chat message at verification time.
    """

    payload = canonical_message_payload(
        sender, receiver, conversation_id, payload_type, ciphertext,
        content_metadata, epoch, purpose=purpose,
    )

    return ml_dsa_signer.sign(payload)


def verify_message_payload(
    sender,
    receiver,
    conversation_id,
    payload_type,
    ciphertext,
    content_metadata,
    epoch,
    signature,
    signing_public_key,
    purpose=MESSAGE_PAYLOAD_PURPOSE,
):
    """
    Verify that ``signature`` is a valid ML-DSA-65 signature, under
    ``signing_public_key``, over the canonical message payload for
    exactly these fields.

    ``signing_public_key`` MUST be resolved by the caller from the
    receiver's own, already-established peer identity state -- see this
    module's docstring's CRITICAL TRUST RULE. This function has no way
    to look that up itself and does not try to; it verifies against
    exactly the key it is given.

    Returns:
        True  -- valid signature for exactly these fields, under this
                 key.
        False -- well-formed input, but the signature does not verify.

    Raises:
        TypeError/ValueError -- any field is malformed, mirroring
        MLDSASigner.verify()'s fail-closed convention exactly. A caller
        receiving untrusted network input should treat both this
        exception case and a False return the same way: reject the
        message.
    """

    payload = canonical_message_payload(
        sender, receiver, conversation_id, payload_type, ciphertext,
        content_metadata, epoch, purpose=purpose,
    )

    return MLDSASigner.verify(payload, signature, signing_public_key)
