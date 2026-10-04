"""
ML-DSA identity/key-persistence foundation phase -- combined
(ML-KEM + ML-DSA) peer identity state machine.

Proves the exact state-transition table this phase's design requires
(first contact, verified contact, changed KEM, changed ML-DSA, changed
both -- Phase 8), the key-change security properties that make the
combined identity meaningful at all (Phase 9, tests A-I), and the one
scenario this entire feature exists to defeat: a server that keeps a
peer's KEM key intact but substitutes a different ML-DSA signing key
(Phase 10).

Exercises client/session.py::ClientSession.observe_peer_identity() /
confirm_combined_peer_verification() directly -- a real, unconnected
ClientSession (no server, no socket) with a real, unlocked
SecureKeyStore, mirroring the established pattern in
tests/test_key_distribution_origin_authentication.py (`_bare_session`)
and tests/test_peer_key_verification.py (real SecureKeyStore, since
the mechanism under test lives entirely inside it). No network packet
signing exists yet -- these methods are not wired to any packet
handler this phase; that is explicitly out of scope (Phase 11).

Run with:
    pytest tests/test_peer_identity_state_transitions.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from client.session import (
    PEER_KEY_STATE_CHANGED,
    ClientSession,
    PeerVerificationMismatchError,
)
from crypto.key_manager import fingerprint_combined_identity, fingerprint_public_key
from crypto.kyber import KyberKEM
from crypto.ml_dsa import MLDSASigner
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED, SecureKeyStore


def _identity():
    """A fresh, real (KEM public key, signing public key) pair."""

    kem = KyberKEM()
    kem.generate_keys()

    signer = MLDSASigner()
    signer.generate_keys()

    return kem.export_public_key().encode("utf-8"), signer.export_public_key()


def _bare_session_with_store(username, tmp_path):
    """A real, unconnected ClientSession with a real, unlocked,
    isolated SecureKeyStore attached directly -- bypassing
    _unlock_key_store()'s full login flow (real server/DB/password
    round trip), since the state machine under test only needs
    self.key_store to be a genuine, unlocked SecureKeyStore, not a
    specific path to get there. Mirrors _bare_session() in
    tests/test_key_distribution_origin_authentication.py, extended
    with a store."""

    session = ClientSession()
    session.username = username

    store = SecureKeyStore(f"{username}-user-id", storage_dir=tmp_path / username)
    store.unlock("Str0ng!Passw0rd")
    session.key_store = store

    return session


# ========================================================================
# Phase 8 -- exact state transitions
# ========================================================================


def test_first_contact_stores_observed_identity_as_unverified(tmp_path):
    """FIRST CONTACT: no identity -> receive KEM+ML-DSA -> store
    observed -> UNVERIFIED. Must NOT auto-VERIFY."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem, signing = _identity()

    assert alice.key_store.get_peer_verification("bob") is None

    alice.observe_peer_identity("bob", kem, signing)

    entry = alice.key_store.get_peer_verification("bob")
    assert entry is not None
    assert entry["state"] == PEER_STATE_UNVERIFIED
    assert entry["fingerprint"] == fingerprint_combined_identity(kem, signing)
    assert alice.get_peer_verification_state("bob") == PEER_STATE_UNVERIFIED


def test_verified_contact_with_identical_keys_remains_verified(tmp_path):
    """VERIFIED CONTACT: same keys observed again -> remain VERIFIED,
    no spurious KEY_CHANGED."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem, signing = _identity()

    alice.observe_peer_identity("bob", kem, signing)
    fingerprint = fingerprint_combined_identity(kem, signing)
    alice.confirm_combined_peer_verification("bob", fingerprint)
    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED

    # The exact same identity observed again -- e.g. Bob reconnecting.
    alice.observe_peer_identity("bob", kem, signing)

    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED
    assert alice.key_store.get_peer_verification("bob")["fingerprint"] == fingerprint


def test_changed_kem_only_transitions_to_key_changed(tmp_path):
    """CHANGED KEM: KEM key substituted, ML-DSA key unchanged ->
    KEY_CHANGED."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem1, signing = _identity()
    kem2, _ = _identity()

    alice.observe_peer_identity("bob", kem1, signing)
    fingerprint = fingerprint_combined_identity(kem1, signing)
    alice.confirm_combined_peer_verification("bob", fingerprint)

    alice.observe_peer_identity("bob", kem2, signing)  # KEM substituted

    assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED


def test_changed_signing_only_transitions_to_key_changed(tmp_path):
    """CHANGED ML-DSA: ML-DSA key substituted, KEM key unchanged ->
    KEY_CHANGED. The property this entire feature exists to provide --
    without it, a server substituting only the signing key would be
    invisible."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem, signing1 = _identity()
    _, signing2 = _identity()

    alice.observe_peer_identity("bob", kem, signing1)
    fingerprint = fingerprint_combined_identity(kem, signing1)
    alice.confirm_combined_peer_verification("bob", fingerprint)

    alice.observe_peer_identity("bob", kem, signing2)  # ML-DSA substituted

    assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED


def test_changed_both_keys_transitions_to_key_changed(tmp_path):
    """CHANGED BOTH: both keys substituted -> KEY_CHANGED."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem1, signing1 = _identity()
    kem2, signing2 = _identity()

    alice.observe_peer_identity("bob", kem1, signing1)
    fingerprint = fingerprint_combined_identity(kem1, signing1)
    alice.confirm_combined_peer_verification("bob", fingerprint)

    alice.observe_peer_identity("bob", kem2, signing2)  # both substituted

    assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED


# ========================================================================
# Phase 9 -- key-change security tests (A-I)
# ========================================================================


def test_A_verified_plus_same_keys_remains_verified(tmp_path):
    """A: VERIFIED + same keys observed -> remains VERIFIED."""

    test_verified_contact_with_identical_keys_remains_verified(tmp_path)


def test_B_verified_plus_changed_kem_becomes_key_changed(tmp_path):
    """B: VERIFIED + changed KEM -> KEY_CHANGED."""

    test_changed_kem_only_transitions_to_key_changed(tmp_path)


def test_C_verified_plus_changed_signing_becomes_key_changed(tmp_path):
    """C: VERIFIED + changed ML-DSA -> KEY_CHANGED."""

    test_changed_signing_only_transitions_to_key_changed(tmp_path)


def test_D_verified_plus_both_changed_becomes_key_changed(tmp_path):
    """D: VERIFIED + both keys changed -> KEY_CHANGED."""

    test_changed_both_keys_transitions_to_key_changed(tmp_path)


def test_E_key_changed_does_not_silently_replace_the_verified_identity(tmp_path):
    """E: a KEY_CHANGED observation must NOT overwrite the persisted
    VERIFIED record -- the original trusted identity stays intact and
    recoverable in SecureKeyStore, even though the session-local state
    reports KEY_CHANGED."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem1, signing1 = _identity()
    kem2, signing2 = _identity()

    alice.observe_peer_identity("bob", kem1, signing1)
    original_fingerprint = fingerprint_combined_identity(kem1, signing1)
    alice.confirm_combined_peer_verification("bob", original_fingerprint)

    alice.observe_peer_identity("bob", kem2, signing2)  # forged substitution

    # Session-local view: KEY_CHANGED.
    assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED

    # SecureKeyStore's persisted record: UNTOUCHED -- still the
    # original VERIFIED identity, not silently overwritten.
    persisted = alice.key_store.get_peer_verification("bob")
    assert persisted["state"] == PEER_STATE_VERIFIED
    assert persisted["fingerprint"] == original_fingerprint


def test_F_first_identity_with_no_verification_action_remains_unverified(tmp_path):
    """F: a first-observed identity, never explicitly verified, stays
    UNVERIFIED -- including across repeated observations of the exact
    same identity (e.g. multiple reconnects before the user ever
    verifies)."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem, signing = _identity()

    alice.observe_peer_identity("bob", kem, signing)
    assert alice.get_peer_verification_state("bob") == PEER_STATE_UNVERIFIED

    alice.observe_peer_identity("bob", kem, signing)
    alice.observe_peer_identity("bob", kem, signing)

    assert alice.get_peer_verification_state("bob") == PEER_STATE_UNVERIFIED


def test_G_malicious_server_cannot_reach_verified_by_supplying_a_new_signing_key(
    tmp_path,
):
    """G: after a VERIFIED identity's signing key is substituted, the
    new identity must never become VERIFIED merely by being observed,
    supplied, or repeatedly presented -- only an explicit,
    independently-checked confirm_combined_peer_verification() call can
    ever do that, and it refuses unless the caller supplies the
    correct, independently-re-derived fingerprint (never trusting a
    caller-supplied string, exactly like confirm_peer_verification()'s
    existing hardening)."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem, signing1 = _identity()
    _, signing2 = _identity()

    alice.observe_peer_identity("bob", kem, signing1)
    alice.confirm_combined_peer_verification(
        "bob", fingerprint_combined_identity(kem, signing1)
    )

    # Server substitutes the signing key, repeatedly.
    for _ in range(3):
        alice.observe_peer_identity("bob", kem, signing2)
        assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED

    # A forged confirmation attempt using a fabricated fingerprint
    # string (not independently re-derived) must be refused.
    with pytest.raises(PeerVerificationMismatchError):
        alice.confirm_combined_peer_verification("bob", "FAKE FING ERPR INT0")

    # The persisted record must still be the ORIGINAL VERIFIED
    # identity -- the substitution never became VERIFIED at any point.
    persisted = alice.key_store.get_peer_verification("bob")
    assert persisted["state"] == PEER_STATE_VERIFIED
    assert persisted["fingerprint"] == fingerprint_combined_identity(kem, signing1)


def test_H_explicit_human_verification_is_the_only_path_to_verified(tmp_path):
    """H: the ONLY way a combined identity ever becomes VERIFIED is an
    explicit confirm_combined_peer_verification() call with the
    correct, independently-re-derived fingerprint -- proven by
    confirming a genuine KEY_CHANGED substitution WITH the correct
    fingerprint, and observing state move to VERIFIED only then, never
    before."""

    alice = _bare_session_with_store("alice", tmp_path)
    kem, signing1 = _identity()
    _, signing2 = _identity()

    alice.observe_peer_identity("bob", kem, signing1)
    alice.confirm_combined_peer_verification(
        "bob", fingerprint_combined_identity(kem, signing1)
    )

    alice.observe_peer_identity("bob", kem, signing2)
    assert alice.get_peer_verification_state("bob") == PEER_KEY_STATE_CHANGED

    new_fingerprint = fingerprint_combined_identity(kem, signing2)
    alice.confirm_combined_peer_verification("bob", new_fingerprint)

    # Only NOW, after the explicit, correctly-matched human action,
    # does the new identity become VERIFIED.
    assert alice.get_peer_verification_state("bob") == PEER_STATE_VERIFIED
    assert alice.key_store.get_peer_verification("bob")["fingerprint"] == new_fingerprint


def test_I_legacy_single_key_path_no_longer_bootstraps_first_contact(tmp_path):
    """I (superseded by the Phase 12A security audit -- see client/
    session.py::handle_public_key()'s own docstring for the traced
    downgrade attack this closes): an UNSIGNED "key_exchange"/
    "public_key" packet -- exactly this test's original packet, built
    with no "signing_public_key" field, exactly as a malicious relay
    could still trivially construct after stripping Phase 11's two new
    fields -- must NOT be able to bootstrap a brand-new peer identity
    any more. Before the audit, this test proved the opposite (that the
    legacy path still worked standalone for first contact); that was
    itself the vulnerability -- a server-controlled downgrade could
    silently defeat 100% of Phase 11's cryptographic-origin proof for
    any never-before-seen peer. Uses a DIFFERENT peer than the
    combined-identity tests above, for the same isolation reason as
    before: the two mechanisms still share one SecureKeyStore._peers
    slot per username."""

    alice = _bare_session_with_store("alice", tmp_path)

    kem = KyberKEM()
    kem.generate_keys()
    packet = {"type": "key_exchange", "username": "carol", "algorithm": "KYBER", "public_key": kem.export_public_key()}

    alice.handle_public_key(packet)

    # Nothing was recorded at all -- not even UNVERIFIED -- and the KEM
    # key was never installed into KeyManager.
    assert alice.get_peer_verification_state("carol") is None
    assert alice.key_store.get_peer_verification("carol") is None
    assert alice.key_manager.get_public_key("carol") is None


def test_I_legacy_single_key_path_still_protects_an_existing_verified_baseline(tmp_path):
    """The defense-in-depth half of the same fix: an unsigned packet
    may no longer CREATE trust, but detecting a MISMATCH against an
    already-VERIFIED legacy-format record -- and flagging KEY_CHANGED
    without overwriting it -- is still intact and still valuable, since
    a pre-Phase-11 VERIFIED record (or one seeded directly, as here)
    has no signing key to upgrade to the combined path on its own."""

    alice = _bare_session_with_store("alice", tmp_path)

    kem1 = KyberKEM()
    kem1.generate_keys()
    legacy_fingerprint = fingerprint_public_key(kem1.export_public_key())
    alice.key_store.verify_peer_fingerprint("carol", legacy_fingerprint)
    assert alice.get_peer_verification_state("carol") == PEER_STATE_VERIFIED

    kem2 = KyberKEM()
    kem2.generate_keys()
    forged_packet = {
        "type": "key_exchange",
        "username": "carol",
        "algorithm": "KYBER",
        "public_key": kem2.export_public_key(),
    }
    alice.handle_public_key(forged_packet)

    assert alice.get_peer_verification_state("carol") == PEER_KEY_STATE_CHANGED
    assert alice.key_store.get_peer_verification("carol") == {
        "fingerprint": legacy_fingerprint,
        "state": PEER_STATE_VERIFIED,
    }


# ========================================================================
# Phase 10 -- critical signing-key substitution test
# ========================================================================


def test_signing_key_substitution_with_unchanged_kem_key_is_detected_and_rejected(
    tmp_path,
):
    """THE scenario this entire feature exists to defeat.

    Alice is genuine: KEM=K1, ML-DSA=D1, combined fingerprint=F1,
    state=VERIFIED.

    A malicious server (or any attacker controlling relay/broadcast)
    attempts to substitute ONLY the signing key -- KEM=K1 (unchanged,
    so any KEM-only check would see nothing wrong), ML-DSA=D2
    (fingerprint=F2). Expected: KEY_CHANGED, NOT VERIFIED, and the
    substitution is NOT silently recorded as the new observed
    identity.

    Then Alice's genuine identity (K1+D1) is received again (e.g. she
    reconnects, or the legitimate broadcast reasserts itself). Expected:
    recognized as the SAME already-trusted identity -- fingerprint F1
    again -- and state remains VERIFIED, not reset to UNVERIFIED and
    not stuck at KEY_CHANGED.

    Without ML-DSA, a KEM-only fingerprint scheme would see K1
    unchanged and never detect this substitution at all -- proving the
    combined fingerprint is doing real work here, not merely
    duplicating what the KEM-only check already provided.
    """

    bob = _bare_session_with_store("bob", tmp_path)

    k1, d1 = _identity()
    _, d2 = _identity()  # attacker's own signing keypair; K1 is reused unchanged

    f1 = fingerprint_combined_identity(k1, d1)
    f2 = fingerprint_combined_identity(k1, d2)
    assert f1 != f2  # sanity: the KEM half alone would never show this

    # --- Alice's genuine identity, explicitly VERIFIED ---
    bob.observe_peer_identity("alice", k1, d1)
    bob.confirm_combined_peer_verification("alice", f1)
    assert bob.get_peer_verification_state("alice") == PEER_STATE_VERIFIED

    # --- Malicious server attempts K1 + D2 ---
    bob.observe_peer_identity("alice", k1, d2)

    assert bob.get_peer_verification_state("alice") == PEER_KEY_STATE_CHANGED
    assert bob.get_peer_verification_state("alice") != PEER_STATE_VERIFIED

    # The persisted record must still be F1 (VERIFIED), not silently
    # replaced by F2.
    persisted = bob.key_store.get_peer_verification("alice")
    assert persisted["state"] == PEER_STATE_VERIFIED
    assert persisted["fingerprint"] == f1
    assert persisted["fingerprint"] != f2

    # An attempt to confirm the forged identity as VERIFIED, even with
    # its own correctly-derived fingerprint, must not be silently
    # accepted as continuity with the original trust -- it IS accepted
    # as ITS OWN explicit verification if a human genuinely does that
    # (H already proves the mechanism permits explicit re-verification
    # after KEY_CHANGED), but it is never automatic. Demonstrated here
    # by confirming that NO action other than an explicit confirm_
    # combined_peer_verification() call moved the state -- observe_
    # peer_identity() alone (already called above) did not.

    # --- Alice's genuine identity (K1 + D1) received again ---
    bob.observe_peer_identity("alice", k1, d1)

    assert bob.get_peer_verification_state("alice") == PEER_STATE_VERIFIED
    assert bob.key_store.get_peer_verification("alice")["fingerprint"] == f1
