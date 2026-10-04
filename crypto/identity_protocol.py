"""
Protocol-Level ML-DSA Origin Authentication

The ML-DSA identity/key-persistence foundation phase gave each peer a
persistent (ML-KEM, ML-DSA) combined identity and a fingerprint/trust-
state machine for it (crypto/key_manager.py::
fingerprint_combined_identity(), client/session.py::
observe_peer_identity()) -- but nothing yet proved that a public-key/
key-distribution packet carrying that identity actually originated
from the party who controls the advertised ML-DSA private key. A
malicious relay/server could still fabricate a packet asserting
arbitrary (KEM, signing) material for any username, and the receiver
had no cryptographic way to tell.

This module closes that gap for exactly one thing: the public
identity/key-distribution ANNOUNCEMENT packet (client/session.py::
send_public_key() / handle_public_key()). It does not sign chat
messages, and it does not sign group-key-distribution material -- see
this phase's own final report for that explicit scope boundary.

Two pieces:

  canonical_identity_payload() -- ONE deterministic, length-prefixed
  byte encoding of "who is announcing which (KEM, signing) identity",
  called by both the sender (to sign) and the receiver (to verify) --
  never reimplemented independently on either side.

  sign_identity_payload() / verify_identity_payload() -- thin
  wrappers around crypto/ml_dsa.py::MLDSASigner (no second ML-DSA
  implementation; the real signing/verification is entirely
  MLDSASigner.sign()/.verify()'s own job).

Security notes:

  * The private ML-DSA seed never appears here or crosses this
    module's boundary -- sign_identity_payload() takes an already-
    constructed MLDSASigner (holding the private key in memory only)
    and returns bytes; nothing here ever serializes private material.

  * A valid signature proves POSSESSION of the private key matching
    the advertised ML-DSA public key. It does NOT establish that the
    advertised public key belongs to the claimed human identity -- an
    attacker who generates their own fresh ML-DSA keypair can validly
    sign a payload asserting THEIR OWN public key under any username
    string they like. That is exactly why verify_identity_payload()
    success does not, by itself, ever grant PEER_STATE_VERIFIED --
    the caller (client/session.py) must still route a successfully
    verified identity through observe_peer_identity(), which keeps
    first contact at UNVERIFIED and requires an explicit human
    confirm_combined_peer_verification() call, exactly as before this
    phase. This module answers ONLY "did the party who sent this
    packet control the signing key it advertises", never "is this the
    human I think it is".
"""

import struct

from crypto.ml_dsa import MLDSASigner

# Fixed, non-secret domain-separation prefix for this ONE signed-
# payload purpose (a public identity/key-distribution announcement).
# Distinct from crypto/ml_dsa.py's own fixed _CONTEXT (a library-level
# ML-DSA context string applied to every signature this application
# ever produces, regardless of purpose): this is an application-level
# binding baked directly into the signed BYTES, so that if a future
# phase ever introduces a second kind of ML-DSA-signed payload sharing
# the same per-user signing key, a signature produced for THAT purpose
# can never be replayed here, and vice versa, even though both would
# still share ml_dsa.py's one _CONTEXT. Never transmitted on the wire
# -- both sides already know it, exactly like _CONTEXT itself.
IDENTITY_PAYLOAD_PURPOSE = b"qrscs-public-identity-v1"


def _coerce_to_bytes(name, value):
    if isinstance(value, str):
        value = value.encode("utf-8")

    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(
            f"{name} must be bytes-like or str, not {type(value).__name__}."
        )

    return bytes(value)


def canonical_identity_payload(
    username, kem_public_key, signing_public_key, purpose=IDENTITY_PAYLOAD_PURPOSE
):
    """
    ONE canonical, deterministic byte encoding binding a public
    identity/key-distribution announcement's purpose, sender username,
    ML-KEM public key, and ML-DSA public key together -- the exact
    bytes that get signed and, independently, reconstructed and
    verified. Both client/session.py::send_public_key() (signing) and
    client/session.py::handle_public_key() (verifying) call this SAME
    function; neither reimplements the encoding.

    Construction (fixed purpose prefix, then each field as a 4-byte
    unsigned big-endian length prefix followed by its raw bytes -- the
    same length-prefixed convention crypto/key_manager.py::
    fingerprint_combined_identity() already established for combining
    two variable-length keys unambiguously):

        purpose
      + pack(">I", len(username))            + username
      + pack(">I", len(kem_public_key))       + kem_public_key
      + pack(">I", len(signing_public_key))   + signing_public_key

    The length prefixes make the boundary between fields unambiguous
    by construction -- exactly the same reasoning
    fingerprint_combined_identity() documents for why a bare
    concatenation is unsafe. ``purpose`` is fixed for every real
    caller (IDENTITY_PAYLOAD_PURPOSE); the parameter exists only so
    tests can construct a deliberately WRONG-purpose payload to prove
    cross-purpose domain separation, never something a real sender or
    receiver chooses.

    ``username``, ``kem_public_key``, and ``signing_public_key`` each
    accept str or bytes-like, coerced the same way
    fingerprint_public_key()/fingerprint_combined_identity() already
    do. ``purpose`` must already be bytes.

    Raises TypeError if any field is not bytes-like or str.
    """

    username = _coerce_to_bytes("username", username)
    kem_public_key = _coerce_to_bytes("kem_public_key", kem_public_key)
    signing_public_key = _coerce_to_bytes("signing_public_key", signing_public_key)

    if not isinstance(purpose, (bytes, bytearray)):
        raise TypeError(
            f"purpose must be bytes-like, not {type(purpose).__name__}."
        )

    return (
        bytes(purpose)
        + struct.pack(">I", len(username)) + username
        + struct.pack(">I", len(kem_public_key)) + kem_public_key
        + struct.pack(">I", len(signing_public_key)) + signing_public_key
    )


def sign_identity_payload(ml_dsa_signer, username, kem_public_key, signing_public_key):
    """
    Sign the canonical identity payload for (username, kem_public_key,
    signing_public_key) with ``ml_dsa_signer``'s private key.

    ``ml_dsa_signer`` is a crypto.ml_dsa.MLDSASigner instance already
    holding a private key (crypto/key_manager.py::KeyManager.ml_dsa,
    persistent across restarts since the identity/key-persistence
    foundation phase) -- never raw private bytes. The private key
    never leaves that object; this function only ever calls its
    .sign() method and returns the resulting signature bytes.

    Returns raw signature bytes (ML_DSA_65_SIGNATURE_BYTES long).

    Raises TypeError/ValueError exactly as MLDSASigner.sign() and
    canonical_identity_payload() do, for malformed input or a signer
    with no private key loaded.
    """

    payload = canonical_identity_payload(username, kem_public_key, signing_public_key)

    return ml_dsa_signer.sign(payload)


def verify_identity_payload(username, kem_public_key, signing_public_key, signature):
    """
    Verify that ``signature`` is a valid ML-DSA-65 signature, under
    ``signing_public_key``, over the canonical identity payload for
    exactly (username, kem_public_key, signing_public_key).

    The receiver's counterpart to sign_identity_payload() -- called
    with the packet's OWN advertised fields (never anything cached
    from a previous, different observation), so any field an attacker
    changes after the fact (username, either key) changes the
    reconstructed payload and the signature no longer matches.

    Returns:
        True  -- the signature is valid for exactly this
                 (username, kem_public_key, signing_public_key) triple.
        False -- well-formed input, but the signature does not verify
                 (wrong key, wrong payload, tampered signature).

    Raises:
        TypeError/ValueError -- any field is malformed (wrong type,
        or -- for signing_public_key/signature -- wrong length or not
        a well-formed ML-DSA-65 value), mirroring MLDSASigner.verify()'s
        own fail-closed convention exactly. A caller receiving
        untrusted network input should treat both this exception case
        and a False return the same way: reject the packet.
    """

    payload = canonical_identity_payload(username, kem_public_key, signing_public_key)

    return MLDSASigner.verify(payload, signature, signing_public_key)
