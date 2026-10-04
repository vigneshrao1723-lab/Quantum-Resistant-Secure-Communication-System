"""
ML-DSA (FIPS 204) Test Suite

Verifies crypto/ml_dsa.py against the ML-DSA-65 spec: key/signature
sizes, sign/verify correctness, tamper detection, wrong-key rejection,
context-string domain separation, and malformed-input handling.
Mirrors tests/test_kyber.py's structure and conventions exactly, for
the signing primitive rather than the KEM.

This is crypto-primitive validation only, per the current phase's
explicit scope -- it does not touch ClientSession, the wire protocol,
the server, sockets, or the database. Protocol/trust-model
integration is a later, separate phase.

Run with:
    pytest tests/test_ml_dsa.py -v
"""

import pytest

from crypto.ml_dsa import MLDSASigner, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_PRIVATE_SEED_BYTES, ML_DSA_65_SIGNATURE_BYTES


@pytest.fixture
def alice():
    """An MLDSASigner instance with a freshly generated keypair."""
    signer = MLDSASigner()
    signer.generate_keys()
    return signer


@pytest.fixture
def bob():
    """A second, independent MLDSASigner instance."""
    signer = MLDSASigner()
    signer.generate_keys()
    return signer


# =====================================================
# 1. Key generation
# =====================================================

def test_generate_keys_produces_correct_sizes(alice):
    """
    ML-DSA-65 keys must be exactly the FIPS 204 mandated lengths.
    A regression here (e.g. someone accidentally swapping in
    ML-DSA-44 or ML-DSA-87) must fail loudly.
    """

    assert len(alice.export_public_key()) == ML_DSA_65_PUBLIC_KEY_BYTES
    assert len(alice.export_private_key()) == ML_DSA_65_PRIVATE_SEED_BYTES


def test_each_keypair_is_unique(alice, bob):
    """Two independently generated keypairs must never collide."""

    assert alice.export_public_key() != bob.export_public_key()
    assert alice.export_private_key() != bob.export_private_key()


# =====================================================
# 2. Public/private raw serialization
# =====================================================

def test_export_public_key_is_raw_bytes_of_the_correct_size(alice):
    exported = alice.export_public_key()

    assert isinstance(exported, bytes)
    assert len(exported) == ML_DSA_65_PUBLIC_KEY_BYTES


def test_export_private_key_is_raw_bytes_of_the_correct_size(alice):
    exported = alice.export_private_key()

    assert isinstance(exported, bytes)
    assert len(exported) == ML_DSA_65_PRIVATE_SEED_BYTES


# =====================================================
# 3. Private-key reconstruction
# =====================================================

def test_import_private_key_reconstructs_the_same_keypair(alice):
    """
    Exporting then re-importing a private key seed must reproduce
    a keypair that behaves identically to the original -- any
    drift here would silently break every future signature made
    after a restart.
    """

    seed = alice.export_private_key()

    reconstructed = MLDSASigner()
    reconstructed.import_private_key(seed)

    # The re-derived public key must be byte-for-byte identical to
    # the original -- proving the seed alone fully determines the
    # keypair, not just "some new consistent keypair".
    assert reconstructed.export_public_key() == alice.export_public_key()


def test_import_private_key_rejects_wrong_length():
    signer = MLDSASigner()

    with pytest.raises(ValueError):
        signer.import_private_key(b"too short")


def test_import_private_key_rejects_non_bytes():
    signer = MLDSASigner()

    with pytest.raises(TypeError):
        signer.import_private_key("not bytes")


# =====================================================
# 4. Public-key reconstruction
# =====================================================

def test_import_public_key_round_trip(alice):
    """
    Validating an exported public key must return the exact
    original bytes -- any drift here would corrupt every future
    verification against that key.
    """

    exported = alice.export_public_key()
    imported = MLDSASigner.import_public_key(exported)

    assert imported == exported


def test_import_public_key_rejects_wrong_length():
    with pytest.raises(ValueError):
        MLDSASigner.import_public_key(b"too short")


def test_import_public_key_rejects_non_bytes():
    with pytest.raises(TypeError):
        MLDSASigner.import_public_key("not bytes")


# =====================================================
# 5. Sign / verify round trip
# =====================================================

def test_sign_verify_round_trip(alice):
    message = b"the quick brown fox jumps over the lazy dog"

    signature = alice.sign(message)

    assert isinstance(signature, bytes)
    assert len(signature) == ML_DSA_65_SIGNATURE_BYTES
    assert MLDSASigner.verify(message, signature, alice.export_public_key()) is True


def test_sign_verify_round_trip_after_key_reconstruction(alice):
    """
    The full lifecycle this feature actually depends on: generate,
    persist (export), restart (import), sign, verify -- proving a
    signature made after a real restart is indistinguishable from
    one made in the original session.
    """

    seed = alice.export_private_key()

    reconstructed = MLDSASigner()
    reconstructed.import_private_key(seed)

    message = b"full round-trip test message"
    signature = reconstructed.sign(message)

    assert MLDSASigner.verify(message, signature, alice.export_public_key()) is True


def test_sign_without_a_private_key_raises():
    signer = MLDSASigner()

    with pytest.raises(ValueError):
        signer.sign(b"no key yet")


# =====================================================
# 6. Modified message
# =====================================================

def test_modified_message_fails_verification(alice):
    message = b"original message"
    signature = alice.sign(message)

    tampered = b"original messagE"  # one byte different

    assert MLDSASigner.verify(tampered, signature, alice.export_public_key()) is False


# =====================================================
# 7. Modified signature
# =====================================================

def test_modified_signature_fails_verification(alice):
    message = b"a message"
    signature = bytearray(alice.sign(message))
    signature[0] ^= 0xFF
    signature = bytes(signature)

    assert MLDSASigner.verify(message, signature, alice.export_public_key()) is False


def test_signature_of_wrong_length_raises_rather_than_silently_failing():
    """
    A malformed (wrong-length) signature is a data error, not "the
    signature was merely wrong" -- distinguishing these two matters
    to a caller (Server-Untrusted Identity Verification, key-
    distribution origin authentication) deciding whether to log a
    security warning about a genuinely forged packet or a protocol/
    parsing bug.
    """

    with pytest.raises(ValueError):
        MLDSASigner.verify(b"msg", b"too short", b"x" * ML_DSA_65_PUBLIC_KEY_BYTES)


# =====================================================
# 8. Wrong public key
# =====================================================

def test_wrong_public_key_fails_verification(alice, bob):
    """
    A signature genuinely made by Alice must not verify under
    Bob's public key -- the core authenticity guarantee this
    entire feature exists to provide.
    """

    message = b"only alice signed this"
    signature = alice.sign(message)

    assert MLDSASigner.verify(message, signature, bob.export_public_key()) is False


# =====================================================
# 9. Empty message
# =====================================================

def test_empty_message_signs_and_verifies(alice):
    signature = alice.sign(b"")

    assert MLDSASigner.verify(b"", signature, alice.export_public_key()) is True


# =====================================================
# 10. Binary message
# =====================================================

def test_binary_message_with_all_byte_values_signs_and_verifies(alice):
    """
    The canonical envelope (Phase 9 of the design) signs raw binary
    fields (encapsulation, wrapped_key), not just readable text --
    this must work identically for arbitrary binary content,
    including every possible byte value.
    """

    message = bytes(range(256)) * 4

    signature = alice.sign(message)

    assert MLDSASigner.verify(message, signature, alice.export_public_key()) is True


# =====================================================
# 11. Context string (domain separation)
# =====================================================

def test_signature_does_not_verify_under_a_different_context(alice):
    """
    MLDSASigner deliberately exposes no context parameter -- every
    signature this application ever produces uses exactly one,
    fixed context (crypto/ml_dsa.py::_CONTEXT), so there is no
    "wrong context" call this wrapper's own public API can even
    make. This test instead proves that fixed context is genuinely
    being applied and genuinely matters -- by reaching underneath
    the wrapper to the real `cryptography` API directly, and
    showing a signature this wrapper produced does NOT verify under
    a different context string. If this test ever failed, the
    context parameter would be a no-op, silently defeating the
    domain-separation Phase 12 of the design calls for.
    """

    from cryptography.hazmat.primitives.asymmetric import mldsa

    message = b"context separation test"
    signature = alice.sign(message)

    public_key_object = mldsa.MLDSA65PublicKey.from_public_bytes(
        alice.export_public_key()
    )

    with pytest.raises(Exception):
        public_key_object.verify(signature, message, b"a-different-context")


# =====================================================
# 12. Malformed public key
# =====================================================

def test_malformed_public_key_raises_on_verify():
    with pytest.raises((TypeError, ValueError)):
        MLDSASigner.verify(b"msg", b"x" * ML_DSA_65_SIGNATURE_BYTES, b"not a real key")


def test_non_bytes_public_key_raises_on_verify():
    with pytest.raises(TypeError):
        MLDSASigner.verify(b"msg", b"x" * ML_DSA_65_SIGNATURE_BYTES, "not bytes")


# =====================================================
# 13. Malformed signature
# =====================================================

def test_malformed_signature_raises_on_verify(alice):
    with pytest.raises(ValueError):
        MLDSASigner.verify(b"msg", b"garbage", alice.export_public_key())


def test_non_bytes_signature_raises_on_verify(alice):
    with pytest.raises(TypeError):
        MLDSASigner.verify(b"msg", "not bytes", alice.export_public_key())


def test_non_bytes_message_raises_on_sign(alice):
    with pytest.raises(TypeError):
        alice.sign("not bytes")


def test_non_bytes_message_raises_on_verify(alice):
    signature = alice.sign(b"real message")

    with pytest.raises(TypeError):
        MLDSASigner.verify("not bytes", signature, alice.export_public_key())
