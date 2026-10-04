"""
Phase 19.24 -- Mute: Desktop UI wiring and local persistence.

Mute affects notifications, never delivery: a muted conversation's
messages still arrive, decrypt, and accumulate a real unread count
exactly as before (get_unread_count() stays honest) -- what changes is
purely the one notification surface this desktop client actually has,
the sidebar's unread badge (there is no OS toast/sound system in this
codebase to suppress). These tests drive the REAL gui.chat_window.
ChatWindow/gui.conversation_list_widget.ConversationListWidget code a
real right-click "Mute"/"Unmute" selection actually runs (bypassing
only the modal QMenu.exec() call itself, exactly like this suite's
existing bubble-context-menu tests bypass only their own QMenu.exec())
against a REAL running server, REAL ClientSessions, and the REAL
storage/secure_key_store.py persistence layer.

Run with:
    pytest tests/test_phase19_24_desktop_mute.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt

from storage.secure_key_store import SecureKeyStore
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _direct_summary,
    _KEEP_ALIVE,
    _two_windows,
    _verify_each_other,
    _wait_for,
    accounts,
    connect,
    running_server,
)


def _row_for(conversation_list, key):
    for i in range(conversation_list.count()):
        item = conversation_list.item(i)
        summary = item.data(Qt.UserRole)
        if summary is not None and summary.key == key:
            return conversation_list.itemWidget(item)
    return None


def test_mute_suppresses_the_badge_but_not_the_real_unread_count(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    bob_username = bob_payload["username"]

    # Real right-click "Mute -> For 1 hour" -- the exact handler a real
    # QMenu selection invokes, bypassing only the modal exec() itself.
    alice_window._handle_mute_action(_direct_summary(bob_username), "mute_1h")
    assert alice_window.session.is_conversation_muted(bob_username)

    # Switch away from bob so his next message is a genuine unread
    # arrival, not one immediately marked read by an open conversation.
    alice_window.open_conversation(_direct_summary(carol_payload["username"]))

    unread_before = alice_window.session.get_unread_count(bob_username)
    bob_window.send_message("while you were muted")
    assert _wait_for(
        lambda: alice_window.session.get_unread_count(bob_username) > unread_before
    )

    alice_window.render_conversations()
    row = _row_for(alice_window.conversation_list, bob_username)
    assert row is not None
    assert row.mute_icon.isVisible()
    assert not row.unread_badge.isVisible()
    # The real count is still tracked honestly underneath the muted
    # badge -- mute never touches delivery/read-state.
    assert alice_window.session.get_unread_count(bob_username) > 0


def test_unmuting_reveals_the_accumulated_badge(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    bob_username = bob_payload["username"]

    alice_window._handle_mute_action(_direct_summary(bob_username), "mute_forever")
    alice_window.open_conversation(_direct_summary(carol_payload["username"]))

    bob_window.send_message("hello while muted")
    assert _wait_for(lambda: alice_window.session.get_unread_count(bob_username) > 0)

    alice_window.render_conversations()
    muted_row = _row_for(alice_window.conversation_list, bob_username)
    assert not muted_row.unread_badge.isVisible()

    alice_window._handle_mute_action(_direct_summary(bob_username), "unmute")
    assert not alice_window.session.is_conversation_muted(bob_username)

    unmuted_row = _row_for(alice_window.conversation_list, bob_username)
    assert not unmuted_row.mute_icon.isVisible()
    assert unmuted_row.unread_badge.isVisible()
    assert unmuted_row.unread_badge.text() == str(
        alice_window.session.get_unread_count(bob_username)
    )


def test_mute_state_persists_across_a_key_store_reload(tmp_path, connect, accounts):
    """Mirrors tests/test_key_store_persistence.py's own convention:
    a fresh SecureKeyStore instance pointed at the same file/password,
    simulating a real app restart -- mute must survive it, since a
    per-session-only mute would silently un-mute on every relogin."""

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    bob_username = bob_payload["username"]

    alice_window._handle_mute_action(_direct_summary(bob_username), "mute_1w")
    assert alice_window.session.is_conversation_muted(bob_username)

    reopened = SecureKeyStore(
        alice_window.session.key_store._user_id,
        storage_dir=str(alice_window.session.key_store._dir),
    )
    reopened.unlock("Str0ng!Passw0rd")

    assert reopened.is_conversation_muted(bob_username)
    assert reopened.get_conversation_muted_until(bob_username) is not None


def test_unmute_when_never_muted_is_a_safe_noop(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    bob_username = bob_payload["username"]

    assert not alice_window.session.is_conversation_muted(bob_username)
    alice_window._handle_mute_action(_direct_summary(bob_username), "unmute")  # must not raise
    assert not alice_window.session.is_conversation_muted(bob_username)


def test_an_already_expired_timed_mute_reads_as_unmuted(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    bob_username = bob_payload["username"]

    # A timestamp in the past -- set directly through the store, since
    # mute_conversation() only ever computes a FUTURE deadline; this
    # proves is_conversation_muted() itself treats an expired mute as
    # over, not merely that a caller always passes a sane duration.
    alice_window.session.key_store.set_conversation_muted_until(
        bob_username, "2000-01-01T00:00:00+00:00"
    )

    assert not alice_window.session.is_conversation_muted(bob_username)
