"""
AES-256-GCM Test Suite

Verifies crypto/aes.py: round-trip correctness, key validation,
authentication-tag enforcement (tamper/wrong-key rejection), nonce
uniqueness, and wire-format edge cases.

Run with:
    pytest tests/test_aes.py -v
"""

import base64

import pytest

from crypto.aes import AESCipher


VALID_KEY = b"A" * 32
OTHER_KEY = b"B" * 32


# =====================================================
# Construction / key validation
# =====================================================

def test_default_key_is_used_when_none_provided():
    """
    Only for standalone testing of this module -- the real
    client/server flow always supplies a Kyber/RSA-derived key.
    """

    cipher = AESCipher()

    assert cipher.key == b"12345678901234567890123456789012"


def test_rejects_non_bytes_key():
    with pytest.raises(TypeError):
        AESCipher(key="not bytes, a string")


def test_rejects_key_of_wrong_length():
    with pytest.raises(ValueError):
        AESCipher(key=b"too_short")


def test_accepts_valid_32_byte_key():
    cipher = AESCipher(key=VALID_KEY)

    assert cipher.key == VALID_KEY


# =====================================================
# Round trip
# =====================================================

def test_encrypt_decrypt_round_trip():
    cipher = AESCipher(VALID_KEY)
    message = "Hello Vignesh! Welcome to AES-256-GCM Encryption."

    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == message


def test_round_trip_handles_unicode():
    cipher = AESCipher(VALID_KEY)
    message = "Quantum-safe chat: héllo wörld 你好 🔐"

    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == message


def test_round_trip_handles_empty_string():
    cipher = AESCipher(VALID_KEY)

    encrypted = cipher.encrypt("")
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == ""


def test_encrypted_output_is_base64_string():
    cipher = AESCipher(VALID_KEY)
    encrypted = cipher.encrypt("test message")

    assert isinstance(encrypted, str)
    # Must decode as valid base64 without error.
    base64.b64decode(encrypted)


# =====================================================
# Wire format
# =====================================================

def test_encrypted_payload_contains_nonce_tag_and_ciphertext():
    cipher = AESCipher(VALID_KEY)
    message = "test message"
    encrypted = cipher.encrypt(message)

    raw = base64.b64decode(encrypted)

    # nonce(12) + tag(16) + ciphertext(len(message) as UTF-8, GCM is
    # a stream cipher mode so ciphertext length == plaintext length)
    expected_len = (
        AESCipher.NONCE_SIZE
        + AESCipher.TAG_SIZE
        + len(message.encode("utf-8"))
    )

    assert len(raw) == expected_len


def test_decrypt_rejects_payload_shorter_than_nonce_plus_tag():
    cipher = AESCipher(VALID_KEY)

    too_short = base64.b64encode(b"\x00" * 10).decode("utf-8")

    with pytest.raises(ValueError):
        cipher.decrypt(too_short)


# =====================================================
# Authentication (the whole point of GCM over CBC)
# =====================================================

def test_decrypt_with_wrong_key_raises():
    encrypted = AESCipher(VALID_KEY).encrypt("secret message")

    with pytest.raises(ValueError):
        AESCipher(OTHER_KEY).decrypt(encrypted)


def test_tampered_ciphertext_byte_raises():
    cipher = AESCipher(VALID_KEY)
    encrypted = cipher.encrypt("secret message")

    raw = bytearray(base64.b64decode(encrypted))
    raw[-1] ^= 0xFF  # flip a bit in the ciphertext
    tampered = base64.b64encode(bytes(raw)).decode("utf-8")

    with pytest.raises(ValueError):
        cipher.decrypt(tampered)


def test_tampered_tag_raises():
    cipher = AESCipher(VALID_KEY)
    encrypted = cipher.encrypt("secret message")

    raw = bytearray(base64.b64decode(encrypted))
    # Tag occupies bytes [NONCE_SIZE : NONCE_SIZE + TAG_SIZE].
    raw[AESCipher.NONCE_SIZE] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode("utf-8")

    with pytest.raises(ValueError):
        cipher.decrypt(tampered)


def test_tampered_nonce_raises():
    cipher = AESCipher(VALID_KEY)
    encrypted = cipher.encrypt("secret message")

    raw = bytearray(base64.b64decode(encrypted))
    raw[0] ^= 0xFF  # flip a bit in the nonce
    tampered = base64.b64encode(bytes(raw)).decode("utf-8")

    with pytest.raises(ValueError):
        cipher.decrypt(tampered)


def test_truncated_ciphertext_raises():
    cipher = AESCipher(VALID_KEY)
    encrypted = cipher.encrypt("a reasonably long secret message")

    raw = base64.b64decode(encrypted)
    truncated = base64.b64encode(raw[:-5]).decode("utf-8")

    with pytest.raises(ValueError):
        cipher.decrypt(truncated)


# =====================================================
# Nonce uniqueness (critical for GCM security -- nonce
# reuse under the same key breaks confidentiality AND
# authenticity)
# =====================================================

def test_repeated_encryption_of_same_message_yields_different_ciphertexts():
    cipher = AESCipher(VALID_KEY)
    message = "identical plaintext, encrypted twice"

    encrypted_1 = cipher.encrypt(message)
    encrypted_2 = cipher.encrypt(message)

    assert encrypted_1 != encrypted_2

    # But both must still independently decrypt correctly.
    assert cipher.decrypt(encrypted_1) == message
    assert cipher.decrypt(encrypted_2) == message


def test_nonces_are_unique_across_many_encryptions():
    cipher = AESCipher(VALID_KEY)
    nonces = set()

    for _ in range(200):
        encrypted = cipher.encrypt("x")
        raw = base64.b64decode(encrypted)
        nonce = raw[: AESCipher.NONCE_SIZE]
        nonces.add(nonce)

    assert len(nonces) == 200