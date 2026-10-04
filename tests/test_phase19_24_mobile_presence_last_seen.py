"""
Phase 19.24 -- Presence/Last Seen: mobile ChatScreen UI wiring.

Real, server-recorded state (database/models/user.py::last_seen_at,
server/client_handler.py::handle_last_seen_request()) -- NOT a fake
local-only label. Reuses tests/test_phase19_24_mobile_drafts.py's
ChatScreen harness. Drives the REAL _set_presence_label()/_on_users_
updated() code a real header presence line actually runs.

Run with:
    pytest tests/test_phase19_24_mobile_presence_last_seen.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from kivy.clock import Clock

from mobile.app import ChatScreen
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def _ticking(predicate):
    """Wrap a _wait_for() predicate so every poll also drains Kivy's
    Clock -- mobile/app.py's _on_users_updated() (like every other
    incoming-packet signal handler in that file) marshals onto the
    main thread via Clock.schedule_once(), which nothing in this test
    process otherwise drains (see tests/test_phase19_24_mobile_pinned_
    messages.py's own identical helper/docstring for the full reason)."""

    def _check():
        Clock.tick()
        return predicate()

    return _check


def test_presence_label_shows_online_then_last_seen_after_peer_disconnects(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mseen"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        assert "Online" in screen._active_presence_label.text

        bob.disconnect()

        assert _wait_for(_ticking(lambda: "Last seen" in screen._active_presence_label.text))
    finally:
        alice.disconnect()
        try:
            bob.disconnect()
        except Exception:  # noqa: BLE001 -- already disconnected above
            pass
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_presence_label_none_for_a_peer_that_never_disconnected(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mseenb"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        assert "Online" in screen._active_presence_label.text
        assert alice.fetch_last_seen(bob.username) is None
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_group_chat_never_sets_an_active_presence_label(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mseenc"
    )
    try:
        created = {}
        alice.group_created.connect(
            lambda conversation_id, name, members: created.update(conversation_id=conversation_id)
        )
        alice.create_group("mseenc group", [bob.username, carol.username])
        assert _wait_for(lambda: "conversation_id" in created)
        conversation_id = created["conversation_id"]

        screen = ChatScreen(alice)
        screen.open_chat(conversation_id)

        assert screen._active_presence_label is None
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
