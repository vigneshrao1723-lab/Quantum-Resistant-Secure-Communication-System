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


# ----------------------------------------------------------------------
# Phase 7 -- Group Membership Management: epoch-aware key storage
# ----------------------------------------------------------------------


def test_store_and_get_key_default_to_epoch_1():
    """Every pre-Phase-7 call site (store_key(id, key), get_key(id))
    keeps working unchanged: no epoch argument means epoch 1."""
    manager = KeyManager()

    manager.store_key("conversation-1", b"K" * 32)

    assert manager.get_key("conversation-1") == b"K" * 32
    assert manager.get_key("conversation-1", epoch=1) == b"K" * 32


def test_get_key_with_explicit_epoch_returns_exactly_that_epoch():
    manager = KeyManager()

    manager.store_key("conversation-1", b"1" * 32, epoch=1)
    manager.store_key("conversation-1", b"2" * 32, epoch=2)

    assert manager.get_key("conversation-1", epoch=1) == b"1" * 32
    assert manager.get_key("conversation-1", epoch=2) == b"2" * 32


def test_get_key_with_no_epoch_returns_current_epoch():
    """epoch=None (the default) always means "whatever is current now",
    not "epoch 1" -- essential for encrypting/decrypting a live
    message after a rotation."""
    manager = KeyManager()

    manager.store_key("conversation-1", b"1" * 32, epoch=1)
    manager.store_key("conversation-1", b"2" * 32, epoch=2)

    assert manager.get_key("conversation-1") == b"2" * 32


def test_get_key_for_missing_epoch_returns_none_not_a_different_epoch():
    """A client that never received epoch 2 must get None for it, even
    though it has epoch 1 -- never a silent substitution."""
    manager = KeyManager()

    manager.store_key("conversation-1", b"1" * 32, epoch=1)

    assert manager.get_key("conversation-1", epoch=2) is None
    assert manager.get_key("conversation-1", epoch=1) == b"1" * 32


def test_has_key_is_epoch_aware():
    manager = KeyManager()

    manager.store_key("conversation-1", b"1" * 32, epoch=1)

    assert manager.has_key("conversation-1", epoch=1) is True
    assert manager.has_key("conversation-1", epoch=2) is False


def test_store_key_never_overwrites_an_existing_epoch():
    """The rotation-recovery contract: an initiator asked to
    (re)distribute an epoch it already generated must reuse the exact
    same key, never silently replace it with a second, different one
    under the same epoch number."""
    manager = KeyManager()

    manager.store_key("conversation-1", b"original-32-bytes-of-key-material", epoch=2)
    manager.store_key("conversation-1", b"different-32-bytes-of-key-materia", epoch=2)

    assert manager.get_key("conversation-1", epoch=2) == b"original-32-bytes-of-key-material"


def test_current_epoch_reflects_the_highest_epoch_stored():
    manager = KeyManager()

    manager.store_key("conversation-1", b"1" * 32, epoch=1)
    assert manager.current_epoch("conversation-1") == 1

    manager.store_key("conversation-1", b"2" * 32, epoch=2)
    assert manager.current_epoch("conversation-1") == 2


def test_current_epoch_is_none_when_never_stored():
    manager = KeyManager()

    assert manager.current_epoch("no-such-conversation") is None


def test_current_epoch_never_moves_backwards_on_out_of_order_store():
    """A late-arriving group_key_distribution packet for an older
    epoch (delivery reordering) must not regress "current"."""
    manager = KeyManager()

    manager.store_key("conversation-1", b"2" * 32, epoch=2)
    manager.store_key("conversation-1", b"1" * 32, epoch=1)

    assert manager.current_epoch("conversation-1") == 2
    assert manager.get_key("conversation-1") == b"2" * 32


def test_remove_key_clears_every_epoch():
    manager = KeyManager()

    manager.store_key("conversation-1", b"1" * 32, epoch=1)
    manager.store_key("conversation-1", b"2" * 32, epoch=2)

    manager.remove_key("conversation-1")

    assert manager.get_key("conversation-1", epoch=1) is None
    assert manager.get_key("conversation-1", epoch=2) is None
    assert manager.current_epoch("conversation-1") is None


def test_multiple_epochs_coexist_for_historical_decryption():
    """The core Phase 7 guarantee: rotating to a new epoch never
    deletes an older one -- a group's message history spanning
    multiple epochs must remain fully decryptable."""
    manager = KeyManager()

    manager.store_key("conversation-1", b"epoch-1-key-32-bytes-of-material", epoch=1)
    manager.store_key("conversation-1", b"epoch-2-key-32-bytes-of-material", epoch=2)
    manager.store_key("conversation-1", b"epoch-3-key-32-bytes-of-materia1", epoch=3)

    assert manager.get_key("conversation-1", epoch=1) == b"epoch-1-key-32-bytes-of-material"
    assert manager.get_key("conversation-1", epoch=2) == b"epoch-2-key-32-bytes-of-material"
    assert manager.get_key("conversation-1", epoch=3) == b"epoch-3-key-32-bytes-of-materia1"
    assert manager.current_epoch("conversation-1") == 3
