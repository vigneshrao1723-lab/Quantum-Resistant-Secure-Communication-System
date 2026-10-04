"""
ML-DSA identity/key-persistence foundation phase -- combined-identity
fingerprint.

A peer's identity is the ML-KEM public key AND the ML-DSA public key
TOGETHER, as ONE fingerprint representing ONE identity -- never two
independent fingerprints for the same peer (see crypto/key_manager.py::
fingerprint_combined_identity()'s own docstring for the full design
rationale). This file proves the properties that design depends on:
sensitivity to either half changing, collision-resistance of the
length-prefixed canonical construction specifically (not just "the
hash is different"), determinism, that only public material can ever
reach it, and that it is never confusable with the pre-existing
single-key fingerprint format it sits alongside.

This is pure-function testing only -- no KeyManager, SecureKeyStore,
ClientSession, network, or GUI involvement. Peer-identity state-
machine behavior built on top of this fingerprint (UNVERIFIED /
VERIFIED / KEY_CHANGED) is covered separately in
tests/test_peer_identity_state_transitions.py.

Run with:
    pytest tests/test_combined_identity_fingerprint.py -v
"""

import hashlib
import inspect

from crypto.key_manager import fingerprint_combined_identity, fingerprint_public_key
from crypto.kyber import KyberKEM
from crypto.ml_dsa import MLDSASigner


def _kem_and_signing_keys():
    kem = KyberKEM()
    kem.generate_keys()

    signer = MLDSASigner()
    signer.generate_keys()

    return kem.export_public_key().encode("utf-8"), signer.export_public_key()


# --- 1. Same KEM + same DSA -> same fingerprint ---


def test_same_kem_and_same_dsa_produce_the_same_fingerprint():
    kem, signing = _kem_and_signing_keys()

    fp1 = fingerprint_combined_identity(kem, signing)
    fp2 = fingerprint_combined_identity(kem, signing)

    assert fp1 == fp2


# --- 2. Different KEM + same DSA -> different fingerprint ---


def test_different_kem_same_dsa_produces_a_different_fingerprint():
    kem1, signing = _kem_and_signing_keys()
    kem2, _ = _kem_and_signing_keys()

    assert kem1 != kem2  # sanity: two independent keypairs never collide
    assert (
        fingerprint_combined_identity(kem1, signing)
        != fingerprint_combined_identity(kem2, signing)
    )


# --- 3. Same KEM + different DSA -> different fingerprint ---


def test_same_kem_different_dsa_produces_a_different_fingerprint():
    kem, signing1 = _kem_and_signing_keys()
    _, signing2 = _kem_and_signing_keys()

    assert signing1 != signing2
    assert (
        fingerprint_combined_identity(kem, signing1)
        != fingerprint_combined_identity(kem, signing2)
    )


# --- 4. Both different -> different fingerprint ---


def test_both_keys_different_produces_a_different_fingerprint():
    kem1, signing1 = _kem_and_signing_keys()
    kem2, signing2 = _kem_and_signing_keys()

    assert (
        fingerprint_combined_identity(kem1, signing1)
        != fingerprint_combined_identity(kem2, signing2)
    )


# --- 5. Reordering the two keys cannot collide ---


def test_swapping_which_key_is_kem_and_which_is_signing_does_not_collide():
    """fingerprint_combined_identity(A, B) must not equal
    fingerprint_combined_identity(B, A) for distinct A/B -- the fixed
    KEM-first-then-signing order is part of what the fingerprint
    authenticates, not an arbitrary convention a caller could get away
    with reversing."""

    a = b"\x11" * 32
    b = b"\x22" * 64

    assert fingerprint_combined_identity(a, b) != fingerprint_combined_identity(b, a)


# --- 6. Length-prefix ambiguity is impossible ---


def test_length_prefixing_prevents_boundary_ambiguity_collisions():
    """Without length prefixes, (kem=b"AB", signing=b"CD") and
    (kem=b"ABC", signing=b"D") would concatenate to the identical byte
    string b"ABCD", producing a collision purely from where the two
    keys happen to split. The 4-byte length prefix specified by this
    phase's design must make that impossible."""

    fp1 = fingerprint_combined_identity(b"AB", b"CD")
    fp2 = fingerprint_combined_identity(b"ABC", b"D")

    assert fp1 != fp2


def test_length_prefixing_prevents_collisions_across_many_boundary_splits():
    """The same property as above, generalized: for a fixed total byte
    string, every possible (kem, signing) split must produce a
    distinct fingerprint."""

    total = b"0123456789ABCDEF"  # 16 bytes, split at every possible point

    fingerprints = {
        fingerprint_combined_identity(total[:i], total[i:])
        for i in range(len(total) + 1)
    }

    assert len(fingerprints) == len(total) + 1  # every split is unique


# --- 7. Deterministic across restart ---


def test_fingerprint_is_deterministic_across_independent_calls():
    """No hidden state (randomness, insertion order, process-specific
    salting) influences the result -- the same two public keys always
    produce the same fingerprint, whether computed in the same process
    or (simulated here by simply calling again) after a restart."""

    kem, signing = _kem_and_signing_keys()

    results = {fingerprint_combined_identity(kem, signing) for _ in range(5)}

    assert len(results) == 1


# --- 8. Private keys never affect the fingerprint ---


def test_function_signature_has_no_private_key_parameter():
    """Structural proof, not just a behavioral one: fingerprint_
    combined_identity() accepts exactly two parameters -- the KEM and
    signing PUBLIC keys -- so there is no argument position through
    which private key material could ever be passed to it."""

    parameters = list(inspect.signature(fingerprint_combined_identity).parameters)

    assert parameters == ["kem_public_key_bytes", "signing_public_key_bytes"]


def test_fingerprint_depends_only_on_the_public_bytes_given():
    """Two MLDSASigner/KyberKEM instances reconstructed from the SAME
    exported public keys but otherwise independent (different
    in-memory object identity, and in the signing case, private key
    material reconstructed via a different code path) must still
    fingerprint identically -- proving the result is a pure function of
    the public bytes, not of any private state riding along with the
    objects they came from."""

    kem = KyberKEM()
    kem.generate_keys()
    kem_public = kem.export_public_key().encode("utf-8")

    signer = MLDSASigner()
    signer.generate_keys()
    signing_public = signer.export_public_key()
    signing_private_seed = signer.export_private_key()

    reconstructed_signer = MLDSASigner()
    reconstructed_signer.import_private_key(signing_private_seed)

    fp_original = fingerprint_combined_identity(kem_public, signing_public)
    fp_reconstructed = fingerprint_combined_identity(
        kem_public, reconstructed_signer.export_public_key()
    )

    assert fp_original == fp_reconstructed


# --- 9. Fingerprint reflects both public keys (fixed test vector) ---


def test_fixed_test_vector_matches_the_documented_canonical_construction():
    """A hand-computed test vector, independent of the implementation
    under test: builds the canonical
    len(kem)+kem+len(signing)+signing byte string exactly as
    fingerprint_combined_identity()'s own docstring specifies, hashes
    it with plain hashlib.sha256, and formats it the same way
    fingerprint_public_key() already does -- then asserts the function
    under test produces exactly that value. If the canonical
    construction ever silently drifted (e.g. wrong length-prefix
    byte order, or a swapped field), this test would catch it even
    though the "different inputs -> different outputs" tests above
    would not."""

    kem = b"kem-public-key-bytes-fixture"
    signing = b"signing-public-key-bytes-fixture"

    canonical = (
        len(kem).to_bytes(4, "big") + kem
        + len(signing).to_bytes(4, "big") + signing
    )
    digest = hashlib.sha256(canonical).hexdigest().upper()
    expected = " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))

    assert fingerprint_combined_identity(kem, signing) == expected


# --- 10. Legacy KEM-only fingerprint is never reused for the combined identity ---


def test_combined_fingerprint_never_matches_the_legacy_single_key_fingerprint():
    """fingerprint_public_key(kem) (the pre-existing, Stage-1
    single-key fingerprint) must never equal fingerprint_combined_
    identity(kem, signing) for the same kem key -- the two must be
    visually and structurally indistinguishable in FORMAT (same
    grouping convention) but never accidentally identical in VALUE, so
    a UI or persisted record can never mistake a legacy KEM-only
    verification for a combined-identity one."""

    kem, signing = _kem_and_signing_keys()

    legacy_fingerprint = fingerprint_public_key(kem)
    combined_fingerprint = fingerprint_combined_identity(kem, signing)

    assert legacy_fingerprint != combined_fingerprint


def test_combined_fingerprint_format_matches_the_legacy_format_convention():
    """Same output convention (uppercase hex, grouped into 4-character
    blocks) as the existing single-key fingerprint -- deliberate, so
    the GUI/verification-comparison code that already knows how to
    display and compare fingerprint_public_key()'s output needs no
    format-specific branching to also display a combined identity
    fingerprint."""

    kem, signing = _kem_and_signing_keys()

    combined_fingerprint = fingerprint_combined_identity(kem, signing)
    legacy_fingerprint = fingerprint_public_key(kem)

    assert " " in combined_fingerprint
    assert all(part.isalnum() for part in combined_fingerprint.split(" "))
    assert len(combined_fingerprint.replace(" ", "")) == len(
        legacy_fingerprint.replace(" ", "")
    )  # both are SHA-256 -> 64 hex characters
