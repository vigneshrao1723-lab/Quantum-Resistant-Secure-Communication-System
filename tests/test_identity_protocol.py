"""
Protocol-level ML-DSA origin authentication -- crypto/identity_protocol.py.

Pure crypto/canonicalization-level tests: no ClientSession, no
network, no server. Proves canonical_identity_payload()'s length-
prefixed construction is unambiguous and collision-resistant (mirroring
tests/test_combined_identity_fingerprint.py's equivalent proofs for
fingerprint_combined_identity()), that sign_identity_payload()/
verify_identity_payload() correctly bind purpose + username + both
keys together, and that every one of this phase's required tamper
scenarios (attacker changes any one bound field) is independently
detected.

End-to-end wire-level attacks (a real ClientSession/server relay) are
covered separately in tests/test_public_key_signature_authentication.py.

Run with:
    pytest tests/test_identity_protocol.py -v
"""

import struct

import pytest

from crypto.identity_protocol import (
    IDENTITY_PAYLOAD_PURPOSE,
    canonical_identity_payload,
    sign_identity_payload,
    verify_identity_payload,
)
from crypto.kyber import KyberKEM
from crypto.ml_dsa import ML_DSA_65_SIGNATURE_BYTES, MLDSASigner


def _identity(username="alice"):
    kem = KyberKEM()
    kem.generate_keys()

    signer = MLDSASigner()
    signer.generate_keys()

    kem_public_key = kem.export_public_key().encode("utf-8")
    signing_public_key = signer.export_public_key()

    return username, kem_public_key, signing_public_key, signer


# ========================================================================
# Canonicalization
# ========================================================================


def test_fixed_test_vector_matches_the_documented_construction():
    """Hand-computed, independent of the implementation under test --
    if the canonical construction ever silently drifted, this would
    catch it even though "different inputs -> different outputs" would
    not."""

    username = b"alice"
    kem_public_key = b"kem-fixture-bytes"
    signing_public_key = b"signing-fixture-bytes"

    expected = (
        IDENTITY_PAYLOAD_PURPOSE
        + struct.pack(">I", len(username)) + username
        + struct.pack(">I", len(kem_public_key)) + kem_public_key
        + struct.pack(">I", len(signing_public_key)) + signing_public_key
    )

    assert (
        canonical_identity_payload(username, kem_public_key, signing_public_key)
        == expected
    )


def test_accepts_str_inputs_matching_utf8_encoded_bytes():
    assert canonical_identity_payload(
        "alice", b"kem", b"signing"
    ) == canonical_identity_payload(b"alice", b"kem", b"signing")


def test_length_prefixing_prevents_boundary_ambiguity_across_all_three_fields():
    """Without length prefixes, (username=b"AB", kem=b"CD", signing=b"E")
    and (username=b"A", kem=b"BC", signing=b"DE") could both concatenate
    to related byte strings purely from where fields happen to split.
    The canonical payload must remain distinct in this and other
    boundary-shifted cases."""

    assert canonical_identity_payload(
        b"AB", b"CD", b"E"
    ) != canonical_identity_payload(b"A", b"BC", b"DE")


def test_reordering_the_three_fields_cannot_collide():
    a, b, c = b"\x11" * 8, b"\x22" * 16, b"\x33" * 24

    assert (
        canonical_identity_payload(a, b, c)
        != canonical_identity_payload(c, b, a)
    )


def test_different_purpose_produces_a_different_payload():
    """Domain separation: a payload produced for some OTHER purpose
    (a hypothetical future signed-packet type sharing the same
    per-user ML-DSA key) must be byte-distinct from this phase's
    public-identity payload, even for identical username/keys."""

    username, kem_public_key, signing_public_key, _ = _identity()

    real = canonical_identity_payload(username, kem_public_key, signing_public_key)
    other_purpose = canonical_identity_payload(
        username, kem_public_key, signing_public_key, purpose=b"some-other-purpose-v1"
    )

    assert real != other_purpose


def test_canonicalization_rejects_non_bytes_non_str_fields():
    with pytest.raises(TypeError):
        canonical_identity_payload(12345, b"kem", b"signing")

    with pytest.raises(TypeError):
        canonical_identity_payload("alice", 12345, b"signing")

    with pytest.raises(TypeError):
        canonical_identity_payload("alice", b"kem", 12345)


# ========================================================================
# Sign / verify round trip
# ========================================================================


def test_sign_then_verify_round_trip_succeeds():
    username, kem_public_key, signing_public_key, signer = _identity()

    signature = sign_identity_payload(signer, username, kem_public_key, signing_public_key)

    assert isinstance(signature, bytes)
    assert len(signature) == ML_DSA_65_SIGNATURE_BYTES
    assert verify_identity_payload(
        username, kem_public_key, signing_public_key, signature
    ) is True


def test_signature_is_deterministic_in_its_verification_result():
    """Verifying the same (payload, signature, key) triple repeatedly
    always agrees -- no hidden state affects the outcome."""

    username, kem_public_key, signing_public_key, signer = _identity()
    signature = sign_identity_payload(signer, username, kem_public_key, signing_public_key)

    results = {
        verify_identity_payload(username, kem_public_key, signing_public_key, signature)
        for _ in range(5)
    }

    assert results == {True}


# ========================================================================
# Tamper detection -- one test per bound field (Phase 11 attacks C-F)
# ========================================================================


def test_attack_C_changed_kem_key_fails_verification():
    username, kem_public_key_1, signing_public_key, signer = _identity()
    signature = sign_identity_payload(
        signer, username, kem_public_key_1, signing_public_key
    )

    kem_public_key_2 = KyberKEM()
    kem_public_key_2.generate_keys()
    forged_kem = kem_public_key_2.export_public_key().encode("utf-8")

    assert verify_identity_payload(
        username, forged_kem, signing_public_key, signature
    ) is False


def test_attack_D_changed_signing_public_key_fails_verification():
    username, kem_public_key, signing_public_key_1, signer = _identity()
    signature = sign_identity_payload(
        signer, username, kem_public_key, signing_public_key_1
    )

    other_signer = MLDSASigner()
    other_signer.generate_keys()
    signing_public_key_2 = other_signer.export_public_key()

    assert verify_identity_payload(
        username, kem_public_key, signing_public_key_2, signature
    ) is False


def test_attack_E_changed_username_fails_verification():
    username, kem_public_key, signing_public_key, signer = _identity("alice")
    signature = sign_identity_payload(
        signer, username, kem_public_key, signing_public_key
    )

    assert verify_identity_payload(
        "mallory", kem_public_key, signing_public_key, signature
    ) is False


def test_attack_F_changed_purpose_fails_verification():
    """Simulates a cross-purpose signature replay: a signature genuinely
    produced under a DIFFERENT purpose prefix (see
    test_different_purpose_produces_a_different_payload) must not
    verify against this phase's real IDENTITY_PAYLOAD_PURPOSE, and vice
    versa -- reaches beneath verify_identity_payload() (which always
    uses the real, fixed purpose) directly at the MLDSASigner level to
    prove this, exactly like tests/test_ml_dsa.py's own context-string
    domain-separation test does."""

    username, kem_public_key, signing_public_key, signer = _identity()

    wrong_purpose_payload = canonical_identity_payload(
        username, kem_public_key, signing_public_key, purpose=b"some-other-purpose-v1"
    )
    signature_over_wrong_purpose = signer.sign(wrong_purpose_payload)

    assert verify_identity_payload(
        username, kem_public_key, signing_public_key, signature_over_wrong_purpose
    ) is False


def test_attack_G_signature_by_the_wrong_signer_never_verifies_the_substituted_key():
    """A packet signed by the LEGITIMATE D1 but advertising a
    substituted D2 must fail -- the attacker cannot produce a valid
    signature for an identity it does not hold the private key for."""

    username, kem_public_key, signing_public_key_1, signer_1 = _identity()

    signer_2 = MLDSASigner()
    signer_2.generate_keys()
    signing_public_key_2 = signer_2.export_public_key()

    # Attacker takes D1's genuine signature (over D1) and relabels the
    # packet as advertising D2 instead.
    genuine_signature = sign_identity_payload(
        signer_1, username, kem_public_key, signing_public_key_1
    )

    assert verify_identity_payload(
        username, kem_public_key, signing_public_key_2, genuine_signature
    ) is False

    # Nor can the attacker sign D2's own advertisement with D1's key --
    # that only verifies against D1, not D2.
    signature_by_d1_over_d2 = sign_identity_payload(
        signer_1, username, kem_public_key, signing_public_key_2
    )
    assert verify_identity_payload(
        username, kem_public_key, signing_public_key_2, signature_by_d1_over_d2
    ) is False


def test_attack_A_legitimate_identity_signed_by_an_independent_attacker_key_fails():
    """Phase 12A audit, attack A: a legitimate (KEM, ML-DSA public key)
    pair, but the signature was produced by an ATTACKER's own,
    completely independent ML-DSA keypair -- never derived from, or
    related to, the legitimate signer_1 above. Verifying against the
    ADVERTISED (legitimate) signing_public_key must fail, since that
    key never produced this signature at all."""

    username, kem_public_key, signing_public_key, _legit_signer = _identity()

    attacker_signer = MLDSASigner()
    attacker_signer.generate_keys()

    forged_signature = sign_identity_payload(
        attacker_signer, username, kem_public_key, signing_public_key
    )

    assert verify_identity_payload(
        username, kem_public_key, signing_public_key, forged_signature
    ) is False


# ========================================================================
# Malformed input -- fail closed (attacks A/B)
# ========================================================================


def test_attack_B_random_garbage_signature_of_correct_length_fails_verification():
    username, kem_public_key, signing_public_key, _ = _identity()

    garbage_signature = b"\x00" * ML_DSA_65_SIGNATURE_BYTES

    assert verify_identity_payload(
        username, kem_public_key, signing_public_key, garbage_signature
    ) is False


def test_malformed_wrong_length_signature_raises_rather_than_silently_failing():
    username, kem_public_key, signing_public_key, _ = _identity()

    with pytest.raises(ValueError):
        verify_identity_payload(username, kem_public_key, signing_public_key, b"too short")


def test_malformed_signing_public_key_raises():
    username, kem_public_key, _, signer = _identity()
    signature = sign_identity_payload(signer, username, kem_public_key, b"x" * 1952)

    with pytest.raises(ValueError):
        verify_identity_payload(username, kem_public_key, b"not a real key", signature)


def test_non_bytes_signature_raises_typeerror():
    username, kem_public_key, signing_public_key, _ = _identity()

    with pytest.raises(TypeError):
        verify_identity_payload(username, kem_public_key, signing_public_key, "not bytes")


# ========================================================================
# Phase 12A audit: attacks G (truncated) / H (extra bytes) / I (wrong-
# length ML-DSA public key) / J (wrong-length KEM public key)
# ========================================================================


def test_attack_G_truncated_signature_of_a_real_signature_raises():
    """A genuinely truncated real signature (not just arbitrary short
    garbage) must be rejected as malformed, not silently mis-verified."""

    username, kem_public_key, signing_public_key, signer = _identity()
    real_signature = sign_identity_payload(
        signer, username, kem_public_key, signing_public_key
    )

    truncated = real_signature[:-1]
    assert len(truncated) != ML_DSA_65_SIGNATURE_BYTES

    with pytest.raises(ValueError):
        verify_identity_payload(username, kem_public_key, signing_public_key, truncated)


def test_attack_H_extra_bytes_appended_to_signature_raises():
    """Extra bytes appended to an otherwise-real signature change its
    length away from the fixed ML-DSA-65 size -- must be rejected the
    same way truncation is, not silently accepted or silently
    truncated back down by some lenient parser."""

    username, kem_public_key, signing_public_key, signer = _identity()
    real_signature = sign_identity_payload(
        signer, username, kem_public_key, signing_public_key
    )

    padded = real_signature + b"\x00" * 16
    assert len(padded) != ML_DSA_65_SIGNATURE_BYTES

    with pytest.raises(ValueError):
        verify_identity_payload(username, kem_public_key, signing_public_key, padded)


def test_attack_I_wrong_length_ml_dsa_public_key_raises():
    """A signing_public_key that is not exactly ML_DSA_65_PUBLIC_KEY_BYTES
    long must be rejected as malformed input, never treated as "just a
    key that doesn't verify"."""

    username, kem_public_key, _, signer = _identity()
    real_signature = sign_identity_payload(
        signer, username, kem_public_key, b"x" * 1952
    )

    too_short_key = b"x" * 100
    with pytest.raises(ValueError):
        verify_identity_payload(username, kem_public_key, too_short_key, real_signature)

    too_long_key = b"x" * 3000
    with pytest.raises(ValueError):
        verify_identity_payload(username, kem_public_key, too_long_key, real_signature)


def test_attack_J_wrong_length_kem_public_key_fails_closed_not_silently():
    """The KEM public key is opaque to this module (crypto/
    identity_protocol.py never validates ML-KEM key material itself --
    that remains crypto/kyber.py's job, downstream in KeyManager.
    add_public_key()). A wrong-length/malformed KEM key therefore does
    NOT raise here -- it simply produces a DIFFERENT canonical payload
    than whatever a genuine sender actually signed, so verification
    against any real signature fails closed (returns False) rather
    than crashing or silently succeeding. Documented explicitly so this
    behavior is a deliberate, tested contract, not an accident."""

    username, real_kem_public_key, signing_public_key, signer = _identity()
    real_signature = sign_identity_payload(
        signer, username, real_kem_public_key, signing_public_key
    )

    wrong_length_kem_key = b"short"
    assert verify_identity_payload(
        username, wrong_length_kem_key, signing_public_key, real_signature
    ) is False
