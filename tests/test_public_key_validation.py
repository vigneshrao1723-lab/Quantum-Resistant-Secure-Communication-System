"""
D6.5 -- Public-Key Input Validation.

Malformed public keys must be rejected at the boundary where untrusted
remote key material first enters the process, not silently cached and
left to fail much later during key wrapping.

Measured behavior of the PREVIOUS implementation (crypto/kyber.py's
import_public_key() was a bare base64.b64decode()):

    "!!!!"                 -> accepted,    0 bytes
    ""                     -> accepted,    0 bytes
    "AAAA"                 -> accepted,    3 bytes
    truncated valid key    -> accepted,   75 bytes

b64decode() defaults to validate=False, so characters outside the
Base64 alphabet are discarded rather than reported. Every one of those
was cached by handle_public_key() as though it were a real key, and
only failed inside ML_KEM_768.encaps() during group key distribution --
where, before D6.4, it also aborted delivery to unrelated members.

RSA was already sound against malformed PEM (load_pem_public_key raises
ValueError for garbage, empty, and truncated input) but had a distinct
gap of its own: a structurally valid PEM carrying a NON-RSA key (EC,
for instance) loaded successfully and only failed later inside
encrypt(), as an AttributeError -- which _distribute_group_key()
deliberately does not catch, because AttributeError is the signature of
a programming error. That wrong-type key is now rejected at import as
the ValueError it actually is.

Run with:
    pytest tests/test_public_key_validation.py -v
"""

import base64
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_backend

from crypto.key_manager import KeyManager
from crypto.kyber import ML_KEM_768_PUBLIC_KEY_BYTES, KyberKEM
from crypto.rsa import RSA_MINIMUM_KEY_SIZE_BITS, RSAEncryption


@pytest.fixture(scope="module")
def valid_kyber_public_key():
    kyber = KyberKEM()
    kyber.generate_keys()
    return kyber.export_public_key()


@pytest.fixture(scope="module")
def valid_rsa_public_key_pem():
    rsa_helper = RSAEncryption()
    rsa_helper.generate_keys()
    return rsa_helper.export_public_key()


# ----------------------------------------------------------------------
# Valid keys must behave exactly as before
# ----------------------------------------------------------------------

def test_valid_kyber_key_round_trips_unchanged(valid_kyber_public_key):
    imported = KyberKEM.import_public_key(valid_kyber_public_key)

    assert isinstance(imported, bytes)
    assert len(imported) == ML_KEM_768_PUBLIC_KEY_BYTES
    assert imported == base64.b64decode(valid_kyber_public_key)


def test_valid_kyber_key_still_accepted_as_bytes(valid_kyber_public_key):
    """export_public_key() returns str; the wire path may hand back its
    UTF-8 bytes. Both forms were supported before D6.5 and still are."""

    as_bytes = valid_kyber_public_key.encode("utf-8")

    assert KyberKEM.import_public_key(as_bytes) == KyberKEM.import_public_key(
        valid_kyber_public_key
    )


def test_valid_kyber_key_still_encapsulates(valid_kyber_public_key):
    """The end that matters: a validated key is still usable."""

    kyber = KyberKEM()
    kyber.generate_keys()

    imported = KyberKEM.import_public_key(valid_kyber_public_key)
    ciphertext, shared_secret = kyber.encapsulate(imported)

    assert ciphertext
    assert len(shared_secret) == 32


def test_valid_rsa_key_round_trips_unchanged(valid_rsa_public_key_pem):
    imported = RSAEncryption.import_public_key(valid_rsa_public_key_pem)

    assert isinstance(imported, rsa_backend.RSAPublicKey)
    assert imported.key_size == 2048


# ----------------------------------------------------------------------
# Kyber: malformed input must be rejected
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("invalid base64 (all non-alphabet)", "!!!!"),
        ("invalid base64 (embedded spaces)", "AA AA AA AA"),
        ("invalid base64 (punctuation)", "not base64 @@@"),
        ("empty string", ""),
        ("empty bytes", b""),
        ("wrong length (3 bytes)", "AAAA"),
        ("wrong length (single byte)", base64.b64encode(b"x").decode("ascii")),
    ],
)
def test_malformed_kyber_key_is_rejected(label, value):
    with pytest.raises(ValueError):
        KyberKEM.import_public_key(value)


def test_truncated_kyber_key_is_rejected(valid_kyber_public_key):
    truncated = valid_kyber_public_key[:100]

    with pytest.raises(ValueError):
        KyberKEM.import_public_key(truncated)


def test_oversized_kyber_key_is_rejected(valid_kyber_public_key):
    oversized = base64.b64encode(
        os.urandom(ML_KEM_768_PUBLIC_KEY_BYTES + 1)
    ).decode("ascii")

    with pytest.raises(ValueError):
        KyberKEM.import_public_key(oversized)


@pytest.mark.parametrize("value", [None, 12345, 3.14, [], {}])
def test_non_string_kyber_key_is_rejected_as_type_error(value):
    with pytest.raises(TypeError):
        KyberKEM.import_public_key(value)


def test_right_length_key_passes_validation_but_fails_at_encapsulation():
    """
    Documents the exact limit of D6.5: length validation is not
    completeness validation. A right-length random key is accepted at
    import and only rejected by ML-KEM's own modulus check.

    This is why ClientSession._distribute_group_key()'s per-recipient
    ValueError guard (D6.4) is still load-bearing after D6.5.
    """

    plausible = base64.b64encode(
        os.urandom(ML_KEM_768_PUBLIC_KEY_BYTES)
    ).decode("ascii")

    imported = KyberKEM.import_public_key(plausible)  # must NOT raise
    assert len(imported) == ML_KEM_768_PUBLIC_KEY_BYTES

    kyber = KyberKEM()
    kyber.generate_keys()

    with pytest.raises(ValueError):
        kyber.encapsulate(imported)


# ----------------------------------------------------------------------
# RSA: malformed and wrong-type input must be rejected
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("garbage bytes", b"not-a-pem"),
        ("empty", b""),
        ("plausible header only", b"-----BEGIN PUBLIC KEY-----\n"),
    ],
)
def test_malformed_rsa_pem_is_rejected(label, value):
    with pytest.raises(ValueError):
        RSAEncryption.import_public_key(value)


def test_truncated_rsa_pem_is_rejected(valid_rsa_public_key_pem):
    with pytest.raises(ValueError):
        RSAEncryption.import_public_key(valid_rsa_public_key_pem[:80])


def test_valid_pem_holding_a_non_rsa_key_is_rejected():
    """
    The RSA-specific gap D6.5 closes: a structurally valid PEM carrying
    an EC key used to import cleanly and only fail later, inside
    encrypt(), as an AttributeError -- a failure class
    _distribute_group_key() intentionally does not catch.
    """

    ec_pem = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    with pytest.raises(ValueError, match="RSA"):
        RSAEncryption.import_public_key(ec_pem)


def _rsa_public_pem(key_size):
    return (
        rsa_backend.generate_private_key(public_exponent=65537, key_size=key_size)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_rsa_key_below_the_minimum_is_rejected():
    """
    RSA-1024 is well-formed but weaker than the level this project
    states for its RSA mode (config.py documents "classical RSA-2048",
    and generate_keys() hardcodes 2048). A conforming client cannot
    produce it, so accepting it would silently weaken session-key
    wrapping.
    """

    with pytest.raises(ValueError, match="at least"):
        RSAEncryption.import_public_key(_rsa_public_pem(1024))


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_rsa_keys_at_or_above_the_minimum_are_accepted(key_size):
    """A minimum, not an equality check -- stronger keys must still
    import, and must remain usable for OAEP/SHA-256 wrapping."""

    imported = RSAEncryption.import_public_key(_rsa_public_pem(key_size))

    assert isinstance(imported, rsa_backend.RSAPublicKey)
    assert imported.key_size == key_size

    # Still usable for the actual operation RSA mode performs: wrapping
    # a 32-byte AES session key.
    rsa_helper = RSAEncryption()
    assert rsa_helper.encrypt(b"x" * 32, imported)


def test_minimum_matches_the_size_this_project_generates():
    """Guards against the floor and generate_keys() drifting apart."""

    rsa_helper = RSAEncryption()
    rsa_helper.generate_keys()

    assert rsa_helper.public_key.key_size == RSA_MINIMUM_KEY_SIZE_BITS

    # A freshly generated key must always pass its own import check.
    assert RSAEncryption.import_public_key(rsa_helper.export_public_key())


def test_rejecting_non_rsa_key_prevents_the_later_attribute_error():
    """Proves the rejection above is what keeps an AttributeError out of
    the key-wrapping path, rather than merely being tidier."""

    ec_public = ec.generate_private_key(ec.SECP256R1()).public_key()

    rsa_helper = RSAEncryption()
    rsa_helper.generate_keys()

    # This is what WOULD have happened had the wrong-type key been stored.
    with pytest.raises(AttributeError):
        rsa_helper.encrypt(b"x" * 32, ec_public)


# ----------------------------------------------------------------------
# Storage behavior: malformed rejected, valid stored
# ----------------------------------------------------------------------

def test_malformed_key_is_not_stored_by_key_manager():
    key_manager = KeyManager()

    if key_manager.algorithm != "KYBER":
        pytest.skip("configured key exchange algorithm is not KYBER")

    with pytest.raises(ValueError):
        key_manager.add_public_key("attacker", "!!!!")

    assert key_manager.get_public_key("attacker") is None, (
        "a rejected key must leave no cached state behind"
    )


def test_valid_key_is_stored_normally(valid_kyber_public_key):
    key_manager = KeyManager()

    if key_manager.algorithm != "KYBER":
        pytest.skip("configured key exchange algorithm is not KYBER")

    key_manager.add_public_key("peer", valid_kyber_public_key)

    stored = key_manager.get_public_key("peer")

    assert stored is not None
    assert stored == base64.b64decode(valid_kyber_public_key)


def test_rejected_key_does_not_overwrite_an_existing_valid_key(
    valid_kyber_public_key,
):
    """
    A malformed key must not be able to destroy key material that is
    already cached and working -- otherwise rejecting it would still
    hand an attacker a denial-of-service against an established peer.
    """

    key_manager = KeyManager()

    if key_manager.algorithm != "KYBER":
        pytest.skip("configured key exchange algorithm is not KYBER")

    key_manager.add_public_key("peer", valid_kyber_public_key)
    original = key_manager.get_public_key("peer")

    with pytest.raises(ValueError):
        key_manager.add_public_key("peer", "!!!!")

    assert key_manager.get_public_key("peer") == original
