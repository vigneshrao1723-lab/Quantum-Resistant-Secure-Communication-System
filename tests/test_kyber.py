"""
Kyber (ML-KEM-768) Test Suite

Verifies crypto/kyber.py against the FIPS 203 ML-KEM-768 spec:
key sizes, encapsulation/decapsulation correctness, randomization,
and the KEM's implicit-rejection behavior on tampered ciphertext
or a wrong private key.

Run with:
    pytest tests/test_kyber.py -v
"""

import base64

import pytest

from crypto.kyber import KyberKEM
from crypto.aes import AESCipher


# ML-KEM-768 (FIPS 203) fixed sizes in bytes.
ENCAPSULATION_KEY_SIZE = 1184  # public key
DECAPSULATION_KEY_SIZE = 2400  # private key
CIPHERTEXT_SIZE = 1088
SHARED_SECRET_SIZE = 32


@pytest.fixture
def alice():
    """A KyberKEM instance with a freshly generated keypair."""
    kem = KyberKEM()
    kem.generate_keys()
    return kem


@pytest.fixture
def bob():
    """A second, independent KyberKEM instance."""
    kem = KyberKEM()
    kem.generate_keys()
    return kem


# =====================================================
# Key generation
# =====================================================

def test_generate_keys_produces_correct_sizes(alice):
    """
    ML-KEM-768 keys must be exactly the FIPS 203 mandated
    lengths. A regression here (e.g. someone accidentally
    swapping in ML-KEM-512 or ML-KEM-1024) must fail loudly.
    """

    assert len(alice.encapsulation_key) == ENCAPSULATION_KEY_SIZE
    assert len(alice.decapsulation_key) == DECAPSULATION_KEY_SIZE


def test_each_keypair_is_unique(alice, bob):
    """
    Two independently generated keypairs must never collide.
    """

    assert alice.encapsulation_key != bob.encapsulation_key
    assert alice.decapsulation_key != bob.decapsulation_key


# =====================================================
# Public key export / import
# =====================================================

def test_export_public_key_is_base64_string(alice):
    exported = alice.export_public_key()

    assert isinstance(exported, str)
    # Must round-trip through base64 without error.
    base64.b64decode(exported)


def test_import_public_key_round_trip(alice):
    """
    Exporting then importing a public key must reproduce the
    exact original bytes -- any drift here would corrupt every
    future encapsulation against that key.
    """

    exported = alice.export_public_key()
    imported = KyberKEM.import_public_key(exported)

    assert imported == alice.encapsulation_key


def test_import_public_key_accepts_utf8_encoded_base64_bytes(alice):
    """
    import_public_key must also accept the UTF-8-encoded bytes of
    a base64 string (not raw decoded key bytes) -- this is the
    exact form KeyManager.add_public_key() passes through when a
    public key arrives as bytes rather than str.
    """

    exported_b64_str = alice.export_public_key()
    ascii_bytes_of_b64_string = exported_b64_str.encode("utf-8")

    imported = KyberKEM.import_public_key(ascii_bytes_of_b64_string)

    assert imported == alice.encapsulation_key


# =====================================================
# Encapsulation / Decapsulation correctness
# =====================================================

def test_encapsulate_returns_expected_shapes(alice, bob):
    ciphertext_b64, shared_secret = bob.encapsulate(
        alice.encapsulation_key
    )

    assert isinstance(ciphertext_b64, str)
    assert isinstance(shared_secret, bytes)
    assert len(shared_secret) == SHARED_SECRET_SIZE
    assert len(base64.b64decode(ciphertext_b64)) == CIPHERTEXT_SIZE


def test_decapsulate_recovers_matching_shared_secret(alice, bob):
    """
    The core KEM guarantee: the secret Bob derived while
    encapsulating against Alice's public key must exactly equal
    the secret Alice recovers by decapsulating with her private
    key.
    """

    ciphertext_b64, bob_secret = bob.encapsulate(
        alice.encapsulation_key
    )

    alice_secret = alice.decapsulate(ciphertext_b64)

    assert alice_secret == bob_secret
    assert len(alice_secret) == SHARED_SECRET_SIZE


def test_decapsulate_accepts_raw_ciphertext_bytes(alice, bob):
    """
    decapsulate must also accept already-decoded ciphertext
    bytes, not only base64 strings.
    """

    ciphertext_b64, bob_secret = bob.encapsulate(
        alice.encapsulation_key
    )

    ciphertext_raw = base64.b64decode(ciphertext_b64)
    alice_secret = alice.decapsulate(ciphertext_raw)

    assert alice_secret == bob_secret


def test_encapsulation_is_randomized(alice, bob):
    """
    Encapsulating twice against the same public key must produce
    a different ciphertext and a different shared secret each
    time. Without this, a passive observer could correlate
    sessions or an active attacker could replay old key material.
    """

    ct1, ss1 = bob.encapsulate(alice.encapsulation_key)
    ct2, ss2 = bob.encapsulate(alice.encapsulation_key)

    assert ct1 != ct2
    assert ss1 != ss2


# =====================================================
# Implicit rejection (FIPS 203 security property)
# =====================================================
#
# ML-KEM does NOT raise an exception on a tampered ciphertext or
# a mismatched private key. By design (FIPS 203 "implicit
# rejection"), decapsulate() always returns a syntactically valid
# 32-byte secret -- but if the ciphertext was tampered with, or
# decapsulated with the wrong private key, that secret will be
# wrong and will not match what the real sender derived.
#
# This is why AES-GCM (an AEAD cipher) matters for the session
# layer: if two peers silently end up with different Kyber
# secrets, plain AES-CBC would either throw an unrelated padding
# error or -- worse -- decrypt to garbage. AES-GCM's authentication
# tag check turns that into a clean, detectable failure instead.
# =====================================================

def test_tampered_ciphertext_does_not_raise_but_yields_wrong_secret(
    alice, bob
):
    ciphertext_b64, bob_secret = bob.encapsulate(
        alice.encapsulation_key
    )

    tampered = bytearray(base64.b64decode(ciphertext_b64))
    tampered[0] ^= 0xFF
    tampered_b64 = base64.b64encode(bytes(tampered)).decode("utf-8")

    # Must not raise (implicit rejection, not an exception).
    recovered_secret = alice.decapsulate(tampered_b64)

    assert len(recovered_secret) == SHARED_SECRET_SIZE
    assert recovered_secret != bob_secret


def test_wrong_private_key_does_not_raise_but_yields_wrong_secret(
    alice, bob
):
    """
    If a ciphertext meant for Alice is decapsulated by a third
    party (Eve) using Eve's own private key, no exception is
    raised, but Eve's recovered "secret" must not match the
    real shared secret Bob and Alice agreed on.
    """

    eve = KyberKEM()
    eve.generate_keys()

    ciphertext_b64, bob_secret = bob.encapsulate(
        alice.encapsulation_key
    )

    eve_secret = eve.decapsulate(ciphertext_b64)

    assert len(eve_secret) == SHARED_SECRET_SIZE
    assert eve_secret != bob_secret


# =====================================================
# Integration: Kyber shared secret used directly as an
# AES-256-GCM key (mirrors the real session.py flow).
# =====================================================

def test_kyber_shared_secret_works_as_aes_gcm_key(alice, bob):
    """
    End-to-end proof that a Kyber-derived shared secret is a
    valid, directly-usable AES-256 key, and that both sides of
    the key exchange can decrypt what the other side encrypted.
    """

    ciphertext_b64, bob_secret = bob.encapsulate(
        alice.encapsulation_key
    )

    alice_secret = alice.decapsulate(ciphertext_b64)

    assert alice_secret == bob_secret

    aes_bob = AESCipher(bob_secret)
    aes_alice = AESCipher(alice_secret)

    message = "Hello Alice! This message is quantum-safe."

    encrypted = aes_bob.encrypt(message)
    decrypted = aes_alice.decrypt(encrypted)

    assert decrypted == message


def test_mismatched_kyber_secrets_cause_aes_gcm_to_reject(alice, bob):
    """
    If decapsulation happened with the wrong private key (secrets
    silently diverge, per implicit rejection above), AES-GCM must
    turn that into a clean, detectable authentication failure
    rather than returning garbage plaintext.
    """

    eve = KyberKEM()
    eve.generate_keys()

    ciphertext_b64, bob_secret = bob.encapsulate(
        alice.encapsulation_key
    )

    wrong_secret = eve.decapsulate(ciphertext_b64)

    aes_bob = AESCipher(bob_secret)
    aes_eve = AESCipher(wrong_secret)

    encrypted = aes_bob.encrypt("Hello Alice!")

    with pytest.raises(ValueError):
        aes_eve.decrypt(encrypted)