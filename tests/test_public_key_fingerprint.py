"""
Tests for crypto/key_manager.py::fingerprint_public_key() (Server-
Untrusted Identity Verification, Stage 1).

This function is deliberately a pure, standalone helper -- no
KeyManager instance, no network I/O, no GUI dependency -- so these
tests exercise it directly, with no server, no ClientSession, and no
real Kyber/RSA key generation required. It does not alter ML-KEM/RSA
behavior in any way; these tests prove exactly that (input bytes are
left untouched) alongside determinism and collision-avoidance.

Run with:
    pytest tests/test_public_key_fingerprint.py -v
"""

import pytest

from crypto.key_manager import fingerprint_public_key


# ----------------------------------------------------------------------
# A -- deterministic
# ----------------------------------------------------------------------


def test_fingerprint_is_deterministic():
    key_bytes = b"a completely arbitrary public key payload"

    first = fingerprint_public_key(key_bytes)
    second = fingerprint_public_key(key_bytes)

    assert first == second


def test_fingerprint_is_deterministic_across_many_calls():
    key_bytes = bytes(range(200))

    results = {fingerprint_public_key(key_bytes) for _ in range(20)}

    assert len(results) == 1


# ----------------------------------------------------------------------
# B -- different keys, different fingerprints
# ----------------------------------------------------------------------


def test_different_public_keys_produce_different_fingerprints():
    fingerprint_one = fingerprint_public_key(b"public key belonging to alice")
    fingerprint_two = fingerprint_public_key(b"public key belonging to bob")

    assert fingerprint_one != fingerprint_two


def test_a_single_changed_byte_produces_a_different_fingerprint():
    """The avalanche property SHA-256 already guarantees -- proven
    here at the level this helper actually exposes, not assumed from
    the underlying hash function's own reputation."""

    original = bytearray(b"0" * 1184)  # ML-KEM-768 public-key length
    changed = bytearray(original)
    changed[0] ^= 0x01

    assert fingerprint_public_key(bytes(original)) != fingerprint_public_key(bytes(changed))


# ----------------------------------------------------------------------
# C -- does not modify input bytes
# ----------------------------------------------------------------------


def test_fingerprint_does_not_modify_input_bytes():
    original = b"public key bytes that must remain exactly as given"
    copy_for_comparison = bytes(original)

    fingerprint_public_key(original)

    assert original == copy_for_comparison


def test_fingerprint_accepts_a_bytearray_without_mutating_it():
    key_bytes = bytearray(b"mutable key material")
    snapshot = bytes(key_bytes)

    fingerprint_public_key(key_bytes)

    assert bytes(key_bytes) == snapshot


# ----------------------------------------------------------------------
# Representation -- suitable for later human verification
# ----------------------------------------------------------------------


def test_fingerprint_is_a_grouped_uppercase_hex_string():
    result = fingerprint_public_key(b"any key bytes at all")

    assert result == result.upper()
    # SHA-256 = 64 hex characters, grouped into 4s -> 16 groups joined
    # by single spaces: 64 hex chars + 15 separators = 79 characters.
    assert len(result.replace(" ", "")) == 64
    for group in result.split(" "):
        assert len(group) == 4
        assert all(char in "0123456789ABCDEF" for char in group)


def test_fingerprint_accepts_str_input_matching_utf8_encoded_bytes():
    """KyberKEM.export_public_key() returns a base64 str, not bytes --
    this must work directly on that, without every caller having to
    remember to .encode() first."""

    text = "a base64-looking public key string"

    assert fingerprint_public_key(text) == fingerprint_public_key(text.encode("utf-8"))


def test_fingerprint_rejects_non_bytes_non_str_input():
    with pytest.raises(TypeError):
        fingerprint_public_key(12345)
