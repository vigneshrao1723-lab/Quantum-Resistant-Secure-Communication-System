"""
Phase 19.24 -- Mute: mobile ChatScreen UI wiring and local persistence.

Reuses tests/test_phase19_24_mobile_drafts.py's ChatScreen harness
(_StubApp/_new_mobile_session/_mutual_verify) rather than
reimplementing it -- this is the SAME class of test (a real
mobile/app.py ChatScreen against a real MobileClientSession and a real
running server), just exercising the chat-list screen (show_chats_
list()) instead of an open conversation. Drives the REAL _build_mute_
button()/_apply_mute_action()/_add_chat_row() methods a real tap on
the row's bell icon and a real popup selection actually run --
bypassing only the popup's own on-screen rendering (Kivy Popup.open()
adds it as an overlay that only actually dispatches touches once a
real event loop is ticking, which these tests, like every other Kivy
widget test in this codebase, do not run -- see test_phase19_24_
mobile_drafts.py's own docstring for the identical reasoning behind
its ChatScreen harness).

Run with:
    pytest tests/test_phase19_24_mobile_mute.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from PySide6.QtWidgets import QApplication

from mobile.app import ChatScreen, GhostButton, RowCard
from storage.secure_key_store import SecureKeyStore
from tests.test_phase19_24_mobile_drafts import (  # noqa: F401
    _new_mobile_session,
    _StubApp,
    _three_mobile_sessions,
)
from tests.test_device_key_sync import _delete, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def _row_for_name(screen, name):
    """Searches by the row's own displayed name Label rather than
    assuming exactly one row exists -- _three_mobile_sessions's own
    mutual verification with a third party (carol) gives ChatScreen a
    second, real, legitimate conversation entry for her too, not a bug
    these tests are about."""

    for widget in screen.content_area.walk():
        if isinstance(widget, RowCard):
            for child in widget.walk():
                if isinstance(child, Label) and child.text == name:
                    return widget
    return None


def _mute_button_text(row):
    for widget in row.walk():
        if isinstance(widget, GhostButton) and widget.text in ("\U0001F514", "\U0001F515"):
            return widget.text
    return None


def _has_unread_badge(row, count):
    for widget in row.walk():
        if isinstance(widget, FloatLayout):
            for child in widget.walk():
                if isinstance(child, Label) and child.text == str(count):
                    return True
    return False


def test_mute_hides_the_unread_badge_and_shows_the_muted_icon(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mmutea"
    )
    try:
        screen = ChatScreen(alice)
        screen._touch_preview(bob.username, "hi", incoming=True, name=bob.username)
        assert screen.conversations[bob.username]["unread"] == 1

        screen._apply_mute_action(bob.username, "mute_1h")
        assert alice.is_conversation_muted(bob.username)

        screen.show_chats_list()
        row = _row_for_name(screen, bob.username)
        assert row is not None
        assert _mute_button_text(row) == "\U0001F515"  # 🔕
        assert not _has_unread_badge(row, 1)

        # The real count is untouched underneath the muted badge.
        assert screen.conversations[bob.username]["unread"] == 1
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_unmuting_reveals_the_badge_again(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mmuteb"
    )
    try:
        screen = ChatScreen(alice)
        screen._touch_preview(bob.username, "hi", incoming=True, name=bob.username)
        screen._apply_mute_action(bob.username, "mute_forever")

        screen.show_chats_list()
        muted_row = _row_for_name(screen, bob.username)
        assert not _has_unread_badge(muted_row, 1)

        screen._apply_mute_action(bob.username, "unmute")
        assert not alice.is_conversation_muted(bob.username)

        screen.show_chats_list()
        unmuted_row = _row_for_name(screen, bob.username)
        assert _mute_button_text(unmuted_row) == "\U0001F514"  # 🔔
        assert _has_unread_badge(unmuted_row, 1)
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_mute_state_persists_across_a_key_store_reload(
    running_server, monkeypatch, tmp_path
):
    """Mirrors tests/test_key_store_persistence.py's own convention: a
    fresh SecureKeyStore instance pointed at the same file/password,
    simulating a real app restart -- mute must survive it."""

    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mmutec"
    )
    try:
        alice.mute_conversation(bob.username, "1w")
        assert alice.is_conversation_muted(bob.username)

        reopened = SecureKeyStore(
            alice.key_store._user_id, storage_dir=str(alice.key_store._dir)
        )
        reopened.unlock("Str0ng!Passw0rd")

        assert reopened.is_conversation_muted(bob.username)
        assert reopened.get_conversation_muted_until(bob.username) is not None
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_unmute_when_never_muted_is_a_safe_noop(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mmuted"
    )
    try:
        assert not alice.is_conversation_muted(bob.username)
        alice.unmute_conversation(bob.username)  # must not raise
        assert not alice.is_conversation_muted(bob.username)
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_an_already_expired_timed_mute_reads_as_unmuted(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mmutee"
    )
    try:
        alice.key_store.set_conversation_muted_until(
            bob.username, "2000-01-01T00:00:00+00:00"
        )
        assert not alice.is_conversation_muted(bob.username)
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
