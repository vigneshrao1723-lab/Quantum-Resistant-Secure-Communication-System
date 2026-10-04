"""
Phase 12A -- Security Audit of Phase 11 (Protocol-Level ML-DSA Origin
Authentication): downgrade attack, first-contact invariant, VERIFIED-
identity protection, and replay.

AUDIT FINDING (documented, then closed): before this phase,
ClientSession.handle_public_key() routed a packet to the AUTHENTICATED
combined-identity path only when "signing_public_key" was present in
the packet; a packet with that field simply absent fell through to the
pre-Phase-11 legacy code, which happily installed a brand-new,
never-before-seen peer's KEM key and recorded them as UNVERIFIED with
NO cryptographic proof of origin at all. Since a malicious server (this
project's entire threat model -- see every "Server-Untrusted Identity
Verification" stage before this one) fully controls what it relays, it
could trivially strip "signing_public_key"/"identity_signature" from
any packet -- whether by never signing anything in the first place, or
by taking a genuinely signed packet and deleting the two fields before
relaying it -- and thereby completely neutralize Phase 11's protection
for any peer it chose to target. This defeated Phase 11's entire stated
purpose (crypto-proof-of-origin before any observation) with zero
effort and zero detectability by the receiver.

The fix (client/session.py::handle_public_key(), see its own updated
docstring): an unsigned packet may now ONLY be evaluated as a mismatch
against an ALREADY-VERIFIED record (unchanged defense-in-depth) or
silently ignored when it matches one exactly (harmless no-op); it can
never again create a new peer-identity record or update an UNVERIFIED
one. This file proves the downgrade is closed, and separately proves
the surrounding first-contact/VERIFIED/replay invariants the audit
was asked to establish.

Run with:
    pytest tests/test_phase12a_downgrade_audit.py -v
"""

import base64
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from client.session import ClientSession, PEER_KEY_STATE_CHANGED
from crypto.identity_protocol import sign_identity_payload
from crypto.key_manager import fingerprint_combined_identity
from crypto.kyber import KyberKEM
from crypto.ml_dsa import MLDSASigner
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED, SecureKeyStore

PASSWORD = "Str0ng!Passw0rd"


def _identity():
    """A fresh, real (KEM wire string, ML-DSA signer, ML-DSA public
    key bytes) tuple."""

    kem = KyberKEM()
    kem.generate_keys()
    kem_wire = kem.export_public_key()

    signer = MLDSASigner()
    signer.generate_keys()

    return kem_wire, signer, signer.export_public_key()


def _signed_packet(username, kem_wire, signer, signing_public_key):
    """A real, genuinely signed "public_key" packet -- exactly the
    shape ClientSession.send_public_key() produces."""

    signature = sign_identity_payload(signer, username, kem_wire, signing_public_key)

    return {
        "type": "key_exchange",
        "operation": "public_key",
        "algorithm": "KYBER",
        "username": username,
        "public_key": kem_wire,
        "signing_public_key": base64.b64encode(signing_public_key).decode("ascii"),
        "identity_signature": base64.b64encode(signature).decode("ascii"),
    }


def _bare_session_with_store(username, tmp_path):
    """A real, unconnected ClientSession -- no server, no socket --
    with a real, unlocked, isolated SecureKeyStore attached, mirroring
    tests/test_peer_identity_state_transitions.py's established
    pattern for this."""

    session = ClientSession()
    session.username = username

    store = SecureKeyStore(f"{username}-user-id", storage_dir=tmp_path / username)
    store.unlock(PASSWORD)
    session.key_store = store

    return session


# ========================================================================
# Audit Question 1 -- downgrade attack: stripping the signature fields
# ========================================================================


def test_downgrade_stripping_signature_fields_from_a_real_signed_packet_is_rejected(
    tmp_path,
):
    """The literal attack: take a genuinely, correctly signed identity
    packet and strip signing_public_key/identity_signature before it
    reaches the receiver -- exactly what a malicious relay server (the
    only entity in a position to do this) could do. Must be rejected
    outright: no identity record created, no KEM key installed."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    genuine_packet = _signed_packet("bob", kem_wire, signer, signing_public_key)

    stripped_packet = dict(genuine_packet)
    del stripped_packet["signing_public_key"]
    del stripped_packet["identity_signature"]

    alice.handle_public_key(stripped_packet)

    assert alice.get_peer_verification_state("bob") is None
    assert alice.key_store.get_peer_verification("bob") is None
    assert alice.key_manager.get_public_key("bob") is None


def test_downgrade_stripping_only_the_signature_and_keeping_the_signing_key_is_rejected(
    tmp_path,
):
    """A partial-strip variant: the attacker leaves signing_public_key
    in place (so the packet still LOOKS like it declares itself
    authenticated) but removes only identity_signature. handle_public_
    key() routes this to _handle_signed_public_key() (since the field
    check is presence of "signing_public_key"), which must reject it
    for a missing signature -- there is no silent fallback to treating
    it as unsigned either."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    genuine_packet = _signed_packet("bob", kem_wire, signer, signing_public_key)
    del genuine_packet["identity_signature"]

    alice.handle_public_key(genuine_packet)

    assert alice.get_peer_verification_state("bob") is None
    assert alice.key_manager.get_public_key("bob") is None


def test_downgrade_cannot_silently_promote_an_unverified_legacy_observation(tmp_path):
    """Even for a peer with an EXISTING but still-UNVERIFIED record
    (e.g. from an earlier legitimate signed observation), a later
    stripped/unsigned packet advertising a DIFFERENT key must not be
    able to silently overwrite that observation with unproven material
    -- it must be flatly ignored, leaving the earlier (still-UNVERIFIED,
    still cryptographically-proven) observation exactly as it was."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire_1, signer_1, signing_public_key_1 = _identity()

    genuine_packet = _signed_packet("bob", kem_wire_1, signer_1, signing_public_key_1)
    alice.handle_public_key(genuine_packet)
    assert alice.get_peer_verification_state("bob") == PEER_STATE_UNVERIFIED
    original_entry = alice.key_store.get_peer_verification("bob")

    kem_2 = KyberKEM()
    kem_2.generate_keys()
    forged_packet = {
        "type": "key_exchange",
        "operation": "public_key",
        "algorithm": "KYBER",
        "username": "bob",
        "public_key": kem_2.export_public_key(),
    }
    alice.handle_public_key(forged_packet)

    assert alice.get_peer_verification_state("bob") == PEER_STATE_UNVERIFIED
    assert alice.key_store.get_peer_verification("bob") == original_entry
    # KeyManager still holds SOME key for bob (installed by the
    # genuine first packet) -- not the forged one, which was never
    # even validated/imported (add_public_key() is never reached for
    # a rejected legacy packet).
    assert alice.key_manager.get_public_key("bob") is not None


# ========================================================================
# Audit Question 4 -- first contact
# ========================================================================


def test_first_contact_unsigned_packet_is_rejected(tmp_path):
    alice = _bare_session_with_store("alice", tmp_path)
    kem = KyberKEM()
    kem.generate_keys()

    unsigned_packet = {
        "type": "key_exchange",
        "operation": "public_key",
        "algorithm": "KYBER",
        "username": "bob",
        "public_key": kem.export_public_key(),
    }
    alice.handle_public_key(unsigned_packet)

    assert alice.get_peer_verification_state("bob") is None
    assert alice.key_manager.get_public_key("bob") is None


def test_first_contact_invalidly_signed_packet_is_rejected(tmp_path):
    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    packet = _signed_packet("bob", kem_wire, signer, signing_public_key)
    # Corrupt the signature after the fact -- a well-formed-length but
    # invalid signature, the case a malicious relay could produce by
    # bit-flipping in transit without possessing any real key.
    corrupted = bytearray(base64.b64decode(packet["identity_signature"]))
    corrupted[0] ^= 0xFF
    packet["identity_signature"] = base64.b64encode(bytes(corrupted)).decode("ascii")

    alice.handle_public_key(packet)

    assert alice.get_peer_verification_state("bob") is None
    assert alice.key_manager.get_public_key("bob") is None


def test_first_contact_valid_signature_is_accepted_but_remains_unverified(tmp_path):
    """The positive case: cryptographic origin proof is necessary but
    not sufficient for trust -- a validly signed first-contact identity
    is recorded (unlike the two rejected cases above) but MUST NOT be
    auto-promoted to VERIFIED. Possession of a private ML-DSA key proves
    only that -- never that the key belongs to the claimed human peer."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    packet = _signed_packet("bob", kem_wire, signer, signing_public_key)
    alice.handle_public_key(packet)

    assert alice.get_peer_verification_state("bob") == PEER_STATE_UNVERIFIED
    assert alice.get_peer_verification_state("bob") != PEER_STATE_VERIFIED
    assert alice.key_manager.get_public_key("bob") is not None

    expected_fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    assert alice.key_store.get_peer_verification("bob") == {
        "fingerprint": expected_fingerprint,
        "state": PEER_STATE_UNVERIFIED,
    }


# ========================================================================
# Audit Question 5 -- VERIFIED identity protection
# ========================================================================


def test_verified_plus_same_signed_identity_remains_verified(tmp_path):
    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    packet = _signed_packet("bob", kem_wire, signer, signing_public_key)
    alice.handle_public_key(packet)
    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    alice.confirm_combined_peer_verification("bob", fingerprint)
    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED

    alice.handle_public_key(_signed_packet("bob", kem_wire, signer, signing_public_key))

    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED
    assert alice.key_store.get_peer_verification("bob")["fingerprint"] == fingerprint


def test_verified_plus_changed_signed_identity_becomes_key_changed(tmp_path):
    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    packet = _signed_packet("bob", kem_wire, signer, signing_public_key)
    alice.handle_public_key(packet)
    original_fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    alice.confirm_combined_peer_verification("bob", original_fingerprint)
    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED

    new_kem_wire, new_signer, new_signing_public_key = _identity()
    changed_packet = _signed_packet("bob", new_kem_wire, new_signer, new_signing_public_key)
    alice.handle_public_key(changed_packet)

    assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED
    persisted = alice.key_store.get_peer_verification("bob")
    assert persisted["state"] == PEER_STATE_VERIFIED
    assert persisted["fingerprint"] == original_fingerprint


def test_verified_plus_forged_unsigned_identity_leaves_verified_untouched(tmp_path):
    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    packet = _signed_packet("bob", kem_wire, signer, signing_public_key)
    alice.handle_public_key(packet)
    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    alice.confirm_combined_peer_verification("bob", fingerprint)

    attacker_kem = KyberKEM()
    attacker_kem.generate_keys()
    forged_unsigned = {
        "type": "key_exchange",
        "operation": "public_key",
        "algorithm": "KYBER",
        "username": "bob",
        "public_key": attacker_kem.export_public_key(),
    }
    alice.handle_public_key(forged_unsigned)

    # Defense in depth: still flagged KEY_CHANGED (mismatch detected),
    # but the persisted VERIFIED record is untouched either way.
    assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED
    persisted = alice.key_store.get_peer_verification("bob")
    assert persisted["state"] == PEER_STATE_VERIFIED
    assert persisted["fingerprint"] == fingerprint

    # And the real KEM key alice already trusts for Bob is still
    # cached and usable -- the forged, unsigned packet's key was
    # never validated or installed anywhere.
    assert alice.key_manager.get_public_key("bob") is not None


def test_verified_plus_forged_invalidly_signed_identity_leaves_verified_untouched(
    tmp_path,
):
    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    packet = _signed_packet("bob", kem_wire, signer, signing_public_key)
    alice.handle_public_key(packet)
    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    alice.confirm_combined_peer_verification("bob", fingerprint)

    attacker_kem, attacker_signer, attacker_signing_key = _identity()
    forged_packet = _signed_packet("bob", attacker_kem, attacker_signer, attacker_signing_key)
    # Corrupt the otherwise-self-consistent forged signature.
    corrupted = bytearray(base64.b64decode(forged_packet["identity_signature"]))
    corrupted[0] ^= 0xFF
    forged_packet["identity_signature"] = base64.b64encode(bytes(corrupted)).decode("ascii")

    alice.handle_public_key(forged_packet)

    # Invalid signature -> the whole packet is rejected before it ever
    # reaches the identity-observation logic at all: no KEY_CHANGED
    # flag, no mismatch recorded, nothing but a dropped packet.
    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED
    persisted = alice.key_store.get_peer_verification("bob")
    assert persisted["state"] == PEER_STATE_VERIFIED
    assert persisted["fingerprint"] == fingerprint


# ========================================================================
# Audit Question 6 -- replay
# ========================================================================


def test_replay_of_an_identical_valid_signed_packet_is_harmless(tmp_path):
    """This packet type is a static identity ANNOUNCEMENT, not a
    one-time credential or a state-mutating command -- it always
    asserts exactly "this username currently holds this (KEM, signing)
    key pair", a fact that is either still true (replay is a true
    no-op) or has been superseded by a newer, different announcement
    (already covered by the KEY_CHANGED tests above). There is no
    notion of a "used" identity packet to exhaust, and no action a
    replay could trigger beyond re-asserting the same fact -- so no
    nonce or sequence-number machinery is added here; replaying the
    exact same bytes an arbitrary number of times is proven harmless
    directly instead."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem_wire, signer, signing_public_key = _identity()

    packet = _signed_packet("bob", kem_wire, signer, signing_public_key)

    for _ in range(5):
        alice.handle_public_key(dict(packet))

    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    assert alice.get_peer_verification_state("bob") == PEER_STATE_UNVERIFIED
    assert alice.key_store.get_peer_verification("bob") == {
        "fingerprint": fingerprint,
        "state": PEER_STATE_UNVERIFIED,
    }

    # Replay after VERIFIED: still harmless, no escalation, no
    # signal of any kind beyond "still true".
    alice.confirm_combined_peer_verification("bob", fingerprint)
    for _ in range(5):
        alice.handle_public_key(dict(packet))

    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED
    assert alice.key_store.get_peer_verification("bob") == {
        "fingerprint": fingerprint,
        "state": PEER_STATE_VERIFIED,
    }
