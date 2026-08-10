"""
Tests for KeyManager's conversation-based key storage (Phase 5 --
Secure Group Key Distribution): store_key()/get_key()/has_key()/
remove_key(). Every conversation, direct or group, is addressed the
same way -- this suite proves the API itself is generic (any unique
string identifier works identically), independent of what that
identifier represents.

See tests/test_key_manager_group_keys.py for the group-key wrap/unwrap
composition (Phase 4), unaffected by this rename.

Run with:
    pytest tests/test_key_manager.py -v
"""

from crypto.key_manager import KeyManager


def test_store_and_get_key_round_trip():
    manager = KeyManager()

    manager.store_key("conversation-1", b"K" * 32)

    assert manager.get_key("conversation-1") == b"K" * 32


def test_get_key_returns_none_when_absent():
    manager = KeyManager()

    assert manager.get_key("no-such-conversation") is None


def test_has_key_reflects_presence():
    manager = KeyManager()

    assert manager.has_key("conversation-1") is False

    manager.store_key("conversation-1", b"K" * 32)

    assert manager.has_key("conversation-1") is True


def test_remove_key_clears_it():
    manager = KeyManager()

    manager.store_key("conversation-1", b"K" * 32)
    manager.remove_key("conversation-1")

    assert manager.has_key("conversation-1") is False
    assert manager.get_key("conversation-1") is None


def test_remove_key_is_a_no_op_when_absent():
    manager = KeyManager()

    manager.remove_key("no-such-conversation")  # must not raise


def test_multiple_conversations_are_independent():
    """A direct conversation's key and a group conversation's key
    coexist under different identifiers with no special-casing --
    KeyManager has no notion of "direct" or "group" at all."""
    manager = KeyManager()

    direct_key = b"D" * 32
    group_key = b"G" * 32

    manager.store_key("some-username", direct_key)
    manager.store_key("a-real-conversation-uuid", group_key)

    assert manager.get_key("some-username") == direct_key
    assert manager.get_key("a-real-conversation-uuid") == group_key


def test_no_direct_or_group_specific_api_exists():
    """Guards the explicit architectural requirement: no
    get_direct_key()/get_group_key()-style methods."""
    manager = KeyManager()

    for forbidden in (
        "get_direct_key",
        "get_group_key",
        "store_direct_key",
        "store_group_key",
    ):
        assert not hasattr(manager, forbidden)
