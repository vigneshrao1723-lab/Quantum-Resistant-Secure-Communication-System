"""
Tests for KeyManager's group-key wrapping (Phase 4 -- Secure Group
Messaging Foundation): wrap_key_for_member() / unwrap_received_key().

These compose only the existing primitives (crypto/kyber.py,
crypto/rsa.py, crypto/aes.py) -- no new cryptography. Runs under
whichever KEY_EXCHANGE_ALGORITHM is configured (KYBER by default; see
config.py), proving the composition is correct for that mode.

Run with:
    pytest tests/test_key_manager_group_keys.py -v
"""

import os

from crypto.key_manager import KeyManager


def _peers():
    """Two independent KeyManagers, each aware of the other's public key --
    mirrors the public-key exchange every connected client already performs."""
    creator = KeyManager()
    member = KeyManager()

    creator.add_public_key("member", member.public_key)
    member.add_public_key("creator", creator.public_key)

    return creator, member


def test_wrap_and_unwrap_recovers_the_exact_group_key():
    creator, member = _peers()

    group_key = os.urandom(32)

    encapsulation, wrapped_key = creator.wrap_key_for_member("member", group_key)
    recovered = member.unwrap_received_key(encapsulation, wrapped_key)

    assert recovered == group_key


def test_wrap_uses_a_key_the_caller_chose_not_one_kyber_generated():
    """The whole point of wrap_key_for_member(): the recovered key is
    exactly the caller's pre-chosen bytes, not whatever a bare
    encapsulate() call would have produced on its own."""
    creator, member = _peers()

    chosen_key = b"G" * 32

    encapsulation, wrapped_key = creator.wrap_key_for_member("member", chosen_key)
    recovered = member.unwrap_received_key(encapsulation, wrapped_key)

    assert recovered == chosen_key
    assert len(recovered) == 32


def test_wrap_raises_without_a_known_public_key():
    creator = KeyManager()

    try:
        creator.wrap_key_for_member("stranger", os.urandom(32))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_different_members_get_independently_wrapped_keys():
    """Two members receiving the same group key must get distinct
    wrapped payloads (fresh Kyber encapsulation / fresh AES nonce each
    time) -- proving no key material is reused across members."""
    creator = KeyManager()
    member_a = KeyManager()
    member_b = KeyManager()

    creator.add_public_key("a", member_a.public_key)
    creator.add_public_key("b", member_b.public_key)
    member_a.add_public_key("creator", creator.public_key)
    member_b.add_public_key("creator", creator.public_key)

    group_key = os.urandom(32)

    encapsulation_a, wrapped_a = creator.wrap_key_for_member("a", group_key)
    encapsulation_b, wrapped_b = creator.wrap_key_for_member("b", group_key)

    assert wrapped_a != wrapped_b

    assert member_a.unwrap_received_key(encapsulation_a, wrapped_a) == group_key
    assert member_b.unwrap_received_key(encapsulation_b, wrapped_b) == group_key
