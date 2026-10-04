"""
Phase 19.24 -- Archive: mobile ChatScreen UI wiring and local
persistence.

Reuses tests/test_phase19_24_mobile_drafts.py's ChatScreen harness
rather than reimplementing it -- see that file's own docstring for the
full reasoning. Drives the REAL show_chats_list()/show_groups_list()/
_apply_mute_action()/_toggle_archived_chats() methods a real tap on
the row's popup and a real tap on the Archived toggle button actually
run, against a REAL running server, REAL MobileClientSession, and the
REAL storage/secure_key_store.py persistence layer.

Run with:
    pytest tests/test_phase19_24_mobile_archive.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from kivy.uix.label import Label
from PySide6.QtWidgets import QApplication

from mobile.app import ChatScreen, RowCard
from storage.secure_key_store import SecureKeyStore
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def _row_for_name(screen, name):
    """Unlike Desktop's ConversationRow, a mobile RowCard carries no
    identity_key attribute of its own -- this searches by the row's
    own displayed name Label instead. Needed (rather than the simpler
    "is there any row at all" a single-peer scenario could get away
    with) because _three_mobile_sessions's own mutual verification
    with a third party gives ChatScreen a second, real, legitimate
    conversation entry for that party too -- not a bug this file is
    testing, just a reason more than one row can legitimately exist."""

    for widget in screen.content_area.walk():
        if isinstance(widget, RowCard):
            for child in widget.walk():
                if isinstance(child, Label) and child.text == name:
                    return widget
    return None


def test_archiving_removes_the_row_from_the_chats_list(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "marcha"
    )
    try:
        screen = ChatScreen(alice)
        screen._touch_preview(bob.username, "hi", incoming=True, name=bob.username)

        screen.show_chats_list()
        assert _row_for_name(screen, bob.username) is not None

        screen._apply_mute_action(bob.username, "archive")
        assert alice.is_conversation_archived(bob.username)

        screen.show_chats_list()
        assert _row_for_name(screen, bob.username) is None
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_the_archived_toggle_shows_archived_chats(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "marchb"
    )
    try:
        screen = ChatScreen(alice)
        screen._touch_preview(bob.username, "hi", incoming=True, name=bob.username)
        screen._apply_mute_action(bob.username, "archive")

        screen.show_chats_list()
        assert _row_for_name(screen, bob.username) is None  # main list: bob is hidden

        screen._toggle_archived_chats()
        assert screen._show_archived is True
        assert _row_for_name(screen, bob.username) is not None  # archived list: bob is shown

        screen._toggle_archived_chats()
        assert screen._show_archived is False
        assert _row_for_name(screen, bob.username) is None
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_unarchiving_restores_the_row_to_the_chats_list(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "marchc"
    )
    try:
        screen = ChatScreen(alice)
        screen._touch_preview(bob.username, "hi", incoming=True, name=bob.username)
        screen._apply_mute_action(bob.username, "archive")
        screen._apply_mute_action(bob.username, "unarchive")

        assert not alice.is_conversation_archived(bob.username)
        screen.show_chats_list()
        assert _row_for_name(screen, bob.username) is not None
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_archive_state_persists_across_a_key_store_reload(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "marchd"
    )
    try:
        alice.archive_conversation(bob.username)
        assert alice.is_conversation_archived(bob.username)

        reopened = SecureKeyStore(
            alice.key_store._user_id, storage_dir=str(alice.key_store._dir)
        )
        reopened.unlock("Str0ng!Passw0rd")

        assert reopened.is_conversation_archived(bob.username)
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_archiving_does_not_affect_a_separate_mute_state(
    running_server, monkeypatch, tmp_path
):
    """Archive and Mute share one conversation_prefs entry -- setting
    one must never silently erase the other."""

    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "marche"
    )
    try:
        alice.mute_conversation(bob.username, "1w")
        alice.archive_conversation(bob.username)

        assert alice.is_conversation_muted(bob.username)
        assert alice.is_conversation_archived(bob.username)

        alice.unarchive_conversation(bob.username)

        assert alice.is_conversation_muted(bob.username)
        assert not alice.is_conversation_archived(bob.username)
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
