"""
Phase 19.24 -- Archive: Desktop UI wiring and local persistence.

Archive retains history -- it never deletes or hides anything server-
side, purely a local "don't show this in my main sidebar list"
preference, exactly like Mute (see tests/test_phase19_24_desktop_
mute.py's own docstring for the shared reasoning and harness this file
reuses rather than reimplementing). Drives the REAL gui.chat_window.
ChatWindow/gui.conversation_list_widget.ConversationListWidget code a
real Archived-toggle click and a real right-click "Archive"/"Unarchive"
selection actually run (bypassing only the modal QMenu.exec() call
itself) against a REAL running server, REAL ClientSessions, and the
REAL storage/secure_key_store.py persistence layer.

Run with:
    pytest tests/test_phase19_24_desktop_archive.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from storage.secure_key_store import SecureKeyStore
from tests.test_phase19_24_desktop_mute import _row_for  # noqa: F401
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _direct_summary,
    _KEEP_ALIVE,
    _send_and_get_bubble,
    _two_windows,
    _verify_each_other,
    _wait_for,
    accounts,
    connect,
    running_server,
)


def test_archiving_removes_the_row_from_the_main_list(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    # ConversationStore only carries a conversation once it has had at
    # least one message -- merely opening it (which _two_windows()
    # already did) is not enough for a row to exist to archive.
    _send_and_get_bubble(alice_window, bob_window, "seed the conversation")

    alice_window.render_conversations()
    assert _row_for(alice_window.conversation_list, bob_username) is not None

    # Real right-click "Archive" -- the exact handler a real QMenu
    # selection invokes, bypassing only the modal exec() itself.
    alice_window._handle_mute_action(_direct_summary(bob_username), "archive")
    assert alice_window.session.is_conversation_archived(bob_username)

    alice_window.render_conversations()
    assert _row_for(alice_window.conversation_list, bob_username) is None


def test_the_archived_toggle_shows_only_archived_conversations(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]
    _send_and_get_bubble(alice_window, bob_window, "seed bob's conversation")

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)
    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)
    alice_window.open_conversation(_direct_summary(carol_payload["username"]))
    alice_window.send_message("seed carol's conversation")
    alice_window.open_conversation(_direct_summary(bob_username))

    alice_window._handle_mute_action(_direct_summary(bob_username), "archive")

    # Main (non-archived) list: bob is gone, carol remains.
    alice_window.render_conversations()
    assert _row_for(alice_window.conversation_list, bob_username) is None
    assert _row_for(alice_window.conversation_list, carol_payload["username"]) is not None

    # A real click on the real Archived toggle button.
    alice_window.archived_toggle_button.setChecked(True)

    assert _row_for(alice_window.conversation_list, bob_username) is not None
    assert _row_for(alice_window.conversation_list, carol_payload["username"]) is None
    assert alice_window.archived_toggle_button.text() == "Back to Chats"

    # Toggling back restores the main list view.
    alice_window.archived_toggle_button.setChecked(False)
    assert _row_for(alice_window.conversation_list, bob_username) is None
    assert _row_for(alice_window.conversation_list, carol_payload["username"]) is not None


def test_unarchiving_restores_the_row_to_the_main_list(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]
    _send_and_get_bubble(alice_window, bob_window, "seed the conversation")

    alice_window._handle_mute_action(_direct_summary(bob_username), "archive")
    alice_window._handle_mute_action(_direct_summary(bob_username), "unarchive")

    assert not alice_window.session.is_conversation_archived(bob_username)
    alice_window.render_conversations()
    assert _row_for(alice_window.conversation_list, bob_username) is not None


def test_archive_state_persists_across_a_key_store_reload(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    alice_window._handle_mute_action(_direct_summary(bob_username), "archive")

    reopened = SecureKeyStore(
        alice_window.session.key_store._user_id,
        storage_dir=str(alice_window.session.key_store._dir),
    )
    reopened.unlock("Str0ng!Passw0rd")

    assert reopened.is_conversation_archived(bob_username)


def test_archiving_does_not_affect_a_separate_mute_state(tmp_path, connect, accounts):
    """Archive and Mute share one conversation_prefs entry -- setting
    one must never silently erase the other."""

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    alice_window._handle_mute_action(_direct_summary(bob_username), "mute_forever")
    alice_window._handle_mute_action(_direct_summary(bob_username), "archive")

    assert alice_window.session.is_conversation_muted(bob_username)
    assert alice_window.session.is_conversation_archived(bob_username)

    alice_window._handle_mute_action(_direct_summary(bob_username), "unarchive")

    # Unarchiving must not have silently unmuted.
    assert alice_window.session.is_conversation_muted(bob_username)
    assert not alice_window.session.is_conversation_archived(bob_username)
