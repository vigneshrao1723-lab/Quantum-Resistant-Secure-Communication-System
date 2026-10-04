"""
Device Management ML-DSA Origin Authentication (Phase 16 -- Multi-
Device Identity).

Three canonical, deterministic byte encodings -- one per device-
management operation (enrollment, authorization, revocation) -- each
under its own fixed suffix appended to the shared purpose prefix, so a
signature produced for one operation can never be replayed as valid
for another, even though all three share the same domain-separation
purpose constant. Mirrors crypto/identity_protocol.py's
_coerce_to_bytes/length-prefix convention exactly; no new encoding
scheme invented.

Security notes (identical in shape to crypto/identity_protocol.py's
own, since this is the same kind of claim):

  * A valid ENROLLMENT self-signature proves only that the requester
    holds the private key matching the device's own advertised public
    keys -- it is not, by itself, authorization. See client/session.py
    /server/device_handler.py for how PENDING vs AUTHORIZED is
    actually decided.

  * A valid AUTHORIZATION signature must be verified by the caller
    against the AUTHORIZING device's OWN already-AUTHORIZED public
    key on file -- never against anything carried in the packet being
    verified. This module only builds/checks the canonical bytes; it
    has no opinion about which key is "trusted" for a given caller,
    exactly like crypto/group_key_protocol.py's own division of
    responsibility.
"""

import struct

from crypto.identity_protocol import _coerce_to_bytes
from crypto.ml_dsa import MLDSASigner

# Fixed, non-secret domain-separation prefix for every device-
# management payload (Phase 16). Distinct from every other purpose
# constant in this codebase (crypto/identity_protocol.py's
# IDENTITY_PAYLOAD_PURPOSE, crypto/message_protocol.py's
# MESSAGE_PAYLOAD_PURPOSE, crypto/group_key_protocol.py's
# GROUP_KEY_PAYLOAD_PURPOSE, crypto/session_key_protocol.py's
# RSA_SESSION_KEY_PAYLOAD_PURPOSE) -- verified non-colliding by
# construction (all are distinct fixed byte strings). Never
# transmitted on the wire; every party already knows it.
DEVICE_PAYLOAD_PURPOSE = b"qrscs-device-v1"

# Phase 16C -- Cross-Device Key Synchronization: a genuinely SEPARATE
# top-level purpose from DEVICE_PAYLOAD_PURPOSE above (not another
# per-operation suffix under it) -- enrollment/authorization/
# revocation are ACCOUNT-MANAGEMENT operations; this is a
# CRYPTOGRAPHIC KEY DELIVERY operation carrying real conversation key
# material (wrapped, never plaintext) between two of the same
# account's own devices. Keeping the two purposes distinct means a
# signature over one can never be replayed as valid for the other,
# even though both are signed by the same per-device ML-DSA key.
DEVICE_KEY_SYNC_PAYLOAD_PURPOSE = b"qrscs-device-key-sync-v1"

# Per-operation suffixes appended AFTER the shared purpose prefix --
# see this module's own docstring for why: without this, a genuine
# enrollment self-signature (which an attacker can always obtain by
# simply generating their own keypair and enrolling it) could
# otherwise be replayed as if it were an authorization or revocation
# signature for the SAME (username, device_id) fields, since the
# purpose prefix alone would not distinguish them.
_OP_ENROLL = b"enroll"
_OP_AUTHORIZE = b"authorize"
_OP_REVOKE = b"revoke"
_OP_SESSION_BIND = b"session_bind"


def _framed(value):
    return struct.pack(">I", len(value)) + value


def canonical_device_enrollment_payload(username, device_id, kem_public_key, ml_dsa_public_key, device_name, platform):
    """
    Canonical payload for a device's own, self-signed enrollment
    request -- signed with the NEW device's own private ML-DSA key,
    proving it holds the private key matching the public keys it is
    advertising for itself. Binds every field that determines what the
    device becomes known as: the account it claims to belong to
    (server-side, the caller still independently checks this against
    the authenticated JWT -- see server/device_handler.py -- this
    signature alone never grants that), the device's own self-chosen
    device_id, both of its public keys, and its own claimed
    name/platform.
    """

    username = _coerce_to_bytes("username", username)
    device_id = _coerce_to_bytes("device_id", device_id)
    kem_public_key = _coerce_to_bytes("kem_public_key", kem_public_key)
    ml_dsa_public_key = _coerce_to_bytes("ml_dsa_public_key", ml_dsa_public_key)
    device_name = _coerce_to_bytes("device_name", device_name or "")
    platform = _coerce_to_bytes("platform", platform or "")

    return (
        DEVICE_PAYLOAD_PURPOSE
        + _OP_ENROLL
        + _framed(username)
        + _framed(device_id)
        + _framed(kem_public_key)
        + _framed(ml_dsa_public_key)
        + _framed(device_name)
        + _framed(platform)
    )


def canonical_device_authorization_payload(username, target_device_id, target_fingerprint, authorizer_device_id):
    """
    Canonical payload for an existing, AUTHORIZED device vouching for
    a PENDING device -- signed with the AUTHORIZING device's own
    private ML-DSA key. Binds the target device's fingerprint (not
    just its ID) so the signature is over WHAT was actually verified
    by the human comparing fingerprints, not merely an opaque
    identifier an attacker-controlled server could have silently
    pointed at a different device.
    """

    username = _coerce_to_bytes("username", username)
    target_device_id = _coerce_to_bytes("target_device_id", target_device_id)
    target_fingerprint = _coerce_to_bytes("target_fingerprint", target_fingerprint)
    authorizer_device_id = _coerce_to_bytes("authorizer_device_id", authorizer_device_id)

    return (
        DEVICE_PAYLOAD_PURPOSE
        + _OP_AUTHORIZE
        + _framed(username)
        + _framed(target_device_id)
        + _framed(target_fingerprint)
        + _framed(authorizer_device_id)
    )


def canonical_device_revocation_payload(username, target_device_id, revoker_device_id):
    """
    Canonical payload for an existing, AUTHORIZED device revoking
    another device (possibly itself, e.g. "I lost this laptop") --
    signed with the REVOKING device's own private ML-DSA key.
    """

    username = _coerce_to_bytes("username", username)
    target_device_id = _coerce_to_bytes("target_device_id", target_device_id)
    revoker_device_id = _coerce_to_bytes("revoker_device_id", revoker_device_id)

    return (
        DEVICE_PAYLOAD_PURPOSE
        + _OP_REVOKE
        + _framed(username)
        + _framed(target_device_id)
        + _framed(revoker_device_id)
    )


def canonical_device_session_binding_payload(username, device_id, session_nonce):
    """
    Canonical payload proving THIS connection is operated by the party
    holding the private ML-DSA key for ``device_id`` (Phase 16B --
    Device Authentication Binding). Signed with the connecting
    device's own private key. ``session_nonce`` is a fresh, client-
    generated random value (see ClientSession.bind_device_session()) --
    a single request/response round trip rather than a full server-
    issued-challenge handshake; this connection is already TLS-
    protected and JWT-authenticated before this step is ever reached,
    so the realistic threat this narrows is a stale, accidentally-
    resent binding signature, not a network attacker (who cannot
    observe this exchange at all) -- see docs/architecture/
    multi_device_identity.md's own note on this tradeoff.
    """

    username = _coerce_to_bytes("username", username)
    device_id = _coerce_to_bytes("device_id", device_id)
    session_nonce = _coerce_to_bytes("session_nonce", session_nonce)

    return (
        DEVICE_PAYLOAD_PURPOSE
        + _OP_SESSION_BIND
        + _framed(username)
        + _framed(device_id)
        + _framed(session_nonce)
    )


def canonical_device_key_sync_payload(
    username, source_device_id, target_device_id, target_fingerprint,
    conversation_id, epoch, package_type, encapsulation, wrapped_key,
):
    """
    Canonical payload for one device delivering wrapped conversation/
    group key material to another of the SAME account's own devices
    (Phase 16C). Signed with the SOURCE device's own private ML-DSA
    key. Binds every field that determines what gets installed and
    where -- including the wrapped key material itself
    (``encapsulation``/``wrapped_key``, both already opaque: KEM
    ciphertext + AES-256-GCM ciphertext, never plaintext) -- so
    tampering any one of them, or replaying a genuine package against
    a different device/conversation/epoch, invalidates the signature.

    ``package_type`` distinguishes what kind of key this is (e.g.
    "direct" vs "group") -- bound into the signature so a package
    cannot be reinterpreted as a different kind after the fact.
    ``protocol version`` is DEVICE_KEY_SYNC_PAYLOAD_PURPOSE's own
    "-v1" suffix; no separate field is needed for it.
    """

    username = _coerce_to_bytes("username", username)
    source_device_id = _coerce_to_bytes("source_device_id", source_device_id)
    target_device_id = _coerce_to_bytes("target_device_id", target_device_id)
    target_fingerprint = _coerce_to_bytes("target_fingerprint", target_fingerprint)
    conversation_id = _coerce_to_bytes("conversation_id", conversation_id)
    package_type = _coerce_to_bytes("package_type", package_type)
    encapsulation = _coerce_to_bytes("encapsulation", encapsulation or "")
    wrapped_key = _coerce_to_bytes("wrapped_key", wrapped_key)

    epoch_value = int(epoch) if epoch else 1

    return (
        DEVICE_KEY_SYNC_PAYLOAD_PURPOSE
        + _framed(username)
        + _framed(source_device_id)
        + _framed(target_device_id)
        + _framed(target_fingerprint)
        + _framed(conversation_id)
        + struct.pack(">I", epoch_value)
        + _framed(package_type)
        + _framed(encapsulation)
        + _framed(wrapped_key)
    )


def sign_device_payload(ml_dsa_signer, payload_bytes):
    """
    Sign an already-built canonical device payload with
    ``ml_dsa_signer``'s private key -- a crypto.ml_dsa.MLDSASigner
    instance already holding a private key. The private key never
    leaves that object; this function only ever calls its .sign()
    method and returns the resulting signature bytes. Deliberately
    takes already-canonicalized bytes (unlike crypto/identity_
    protocol.py's sign_identity_payload()) since this module has
    three different canonical constructions rather than one -- the
    caller picks which canonical_device_*_payload() to build first.
    """

    return ml_dsa_signer.sign(payload_bytes)


def verify_device_payload(payload_bytes, signature, signing_public_key):
    """
    Verify ``signature`` is a valid ML-DSA-65 signature over
    ``payload_bytes`` under ``signing_public_key``. Thin wrapper
    around MLDSASigner.verify() -- no independent verification logic.
    The caller is responsible for resolving ``signing_public_key`` from
    its own trusted state (the requesting device's own advertised key
    for a self-signed enrollment; the AUTHORIZING device's already-
    on-file key for an authorization/revocation) -- never from a field
    inside the packet being verified, mirroring every other *_protocol.py
    module's identical division of responsibility.
    """

    return MLDSASigner.verify(payload_bytes, signature, signing_public_key)
