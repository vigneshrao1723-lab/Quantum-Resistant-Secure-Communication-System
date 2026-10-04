"""
RSA Direct-Session-Key ML-DSA Origin Authentication (Phase 13.6)

Phase 13 added ML-DSA origin authentication to KYBER-mode key
establishment (group-key distribution AND, because
create_group_key_distribution_packet()/handle_group_key_distribution()
are shared, KYBER-mode direct session-key establishment too). RSA-mode
direct session-key establishment (client/session.py::
establish_session_key()'s RSA branch -> utils/protocol.py::
create_session_key_packet() -> client/session.py::handle_session_key())
was never touched by that phase and carried no signature of any kind.

Phase 13.5's independent audit proved this empirically: RSA-OAEP is
true public-key encryption -- ANYONE holding a recipient's PUBLIC RSA
key (broadcast to every connected client by design, exactly like the
ML-KEM public key) can encrypt an arbitrary session key of their own
choosing and address it to that recipient. handle_session_key() had no
way to tell a genuine sender from a forger; it only checked that the
packet's own ``algorithm`` label matched this client's configured
algorithm (crypto/session_key_protocol.py's the origin-authenticity
piece; that label check is orthogonal and unchanged -- see client/
session.py::handle_session_key()'s own docstring). This module closes
that gap.

Mirrors crypto/group_key_protocol.py's/crypto/message_protocol.py's/
crypto/identity_protocol.py's exact shape (canonical encoding function
+ thin sign/verify wrappers around crypto/ml_dsa.py::MLDSASigner -- no
second ML-DSA implementation, no duplicated canonicalization helper)
for a FOURTH, structurally distinct signed-payload purpose. Kept as
its own module rather than folded into group_key_protocol.py: an RSA
session-key delivery is a different wire shape (no ``encapsulation``
field at all -- RSA-OAEP is direct public-key encryption, not KEM-
then-DEM) addressed with different field names (``receiver``, not
``recipient``) for a conceptually different operation (one client's
own direct 1:1 session key, never a shared group secret). Reusing
GROUP_KEY_PAYLOAD_PURPOSE here would already have been Phase 13.5's
own flagged "shared purpose for two different operations" design wart
made worse, not better -- see this phase's final report, Part 2.

CRITICAL TRUST RULE (see client/session.py::handle_session_key()'s own
docstring for the enforcement): verify_rsa_session_key_payload() takes
the verification key as a parameter -- it is the CALLER's
responsibility to resolve that key from the receiver's own, already-
established (and VERIFIED -- symmetric with the KYBER/group-key rule,
see this phase's final report Part 3) peer identity state, never from
anything inside the session_key packet. That packet carries no ML-DSA
public-key field at all; there is nothing here for a malicious
sender/server to substitute their own key into.
"""

import struct

from crypto.identity_protocol import _coerce_to_bytes
from crypto.ml_dsa import MLDSASigner

# Fixed, non-secret domain-separation prefix for this signed-payload
# purpose (an RSA-mode direct session-key delivery). Distinct from
# crypto/identity_protocol.py's IDENTITY_PAYLOAD_PURPOSE, crypto/
# message_protocol.py's MESSAGE_PAYLOAD_PURPOSE, crypto/
# group_key_protocol.py's GROUP_KEY_PAYLOAD_PURPOSE, and crypto/
# ml_dsa.py's own fixed _CONTEXT -- see this module's docstring. Never
# transmitted on the wire; both sides already know it.
RSA_SESSION_KEY_PAYLOAD_PURPOSE = b"qrscs-rsa-session-key-v1"


def canonical_rsa_session_key_payload(
    sender,
    receiver,
    conversation_id,
    algorithm,
    encrypted_key,
    epoch,
    purpose=RSA_SESSION_KEY_PAYLOAD_PURPOSE,
):
    """
    ONE canonical, deterministic byte encoding of an RSA-mode direct
    session-key delivery -- the exact bytes signed by the sender
    (client/session.py::establish_session_key()'s RSA branch) and
    reconstructed and verified by the receiver (handle_session_key()).
    Both call this SAME function; neither reimplements the encoding.
    Never a JSON string: JSON field order/whitespace is incidental
    serialization detail, not something a signature should ever depend
    on -- see this phase's final report, Part 4.

    Binds (each as a 4-byte unsigned big-endian length prefix followed
    by its raw bytes, exactly crypto/group_key_protocol.py's/crypto/
    message_protocol.py's/crypto/identity_protocol.py's established
    convention):

        purpose
      + sender
      + receiver
      + conversation_id
      + algorithm
      + encrypted_key
      + epoch             (4-byte unsigned big-endian integer)

    ``algorithm`` is bound so a forged packet cannot claim a different
    key-establishment algorithm than the one the sender actually used
    to produce ``encrypted_key`` -- independent of, and in addition
    to, handle_session_key()'s own pre-existing, unrelated defense (a
    receiver-local check that the packet's algorithm label matches
    this client's own configured algorithm, which protects against a
    KYBER-vs-RSA decrypt-routine confusion, not against origin
    forgery).

    ``conversation_id`` is the sender's own, locally-resolved direct-
    conversation id (client/session.py::establish_session_key()'s
    ``self.current_conversation_id``) -- bound here so a malicious
    relay cannot take a genuinely-signed delivery and relabel it under
    a different conversation. server/client_handler.py's own,
    independent D3.1 hardening still overwrites ``conversation_id`` on
    the wire with its own server-side resolution before relay (never
    trusting a client-supplied value there either) -- binding the
    sender's value here means the two must agree, or verification
    fails closed; it does not weaken or replace that server-side
    check, it adds a second, independent one the server itself cannot
    satisfy by lying.

    ``epoch`` identifies which server-reserved key epoch (crypto/
    key_manager.py) this session key belongs to -- security-relevant
    (KeyManager.store_key() addresses conversation history by exactly
    this value) and bound here so an attacker cannot replay/relabel a
    genuine delivery under a different epoch number. Normalized to 1
    if falsy (None/0), matching every other epoch-handling call site
    in this codebase's "epoch or 1" convention -- though every real
    caller of this function always passes an explicit epoch >= 1.
    """

    sender = _coerce_to_bytes("sender", sender)
    receiver = _coerce_to_bytes("receiver", receiver)
    conversation_id = _coerce_to_bytes("conversation_id", conversation_id or "")
    algorithm = _coerce_to_bytes("algorithm", algorithm)
    encrypted_key = _coerce_to_bytes("encrypted_key", encrypted_key)

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
        + _framed(receiver)
        + _framed(conversation_id)
        + _framed(algorithm)
        + _framed(encrypted_key)
        + struct.pack(">I", epoch_value)
    )


def sign_rsa_session_key_payload(
    ml_dsa_signer, sender, receiver, conversation_id, algorithm, encrypted_key, epoch
):
    """
    Sign the canonical RSA session-key payload with ``ml_dsa_signer``'s
    private key -- a crypto.ml_dsa.MLDSASigner instance already
    holding a private key (crypto/key_manager.py::KeyManager.ml_dsa,
    the same persistent signer already used for identity announcements,
    messages, and group-key distribution). The private key never
    leaves that object; this function only ever calls its .sign()
    method and returns the resulting signature bytes.
    """

    payload = canonical_rsa_session_key_payload(
        sender, receiver, conversation_id, algorithm, encrypted_key, epoch,
    )

    return ml_dsa_signer.sign(payload)


def verify_rsa_session_key_payload(
    sender, receiver, conversation_id, algorithm, encrypted_key, epoch,
    signature, signing_public_key,
):
    """
    Verify that ``signature`` is a valid ML-DSA-65 signature, under
    ``signing_public_key``, over the canonical RSA session-key payload
    for exactly these fields.

    ``signing_public_key`` MUST be resolved by the caller from the
    receiver's own, already-established (and VERIFIED -- see this
    module's docstring's CRITICAL TRUST RULE and client/session.py::
    handle_session_key()'s own enforcement) peer identity state. This
    function has no way to look that up itself and does not try to; it
    verifies against exactly the key it is given.

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

    payload = canonical_rsa_session_key_payload(
        sender, receiver, conversation_id, algorithm, encrypted_key, epoch,
    )

    return MLDSASigner.verify(payload, signature, signing_public_key)
