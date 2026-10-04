"""
Phase 19.24 -- Pinned Messages: mobile ChatScreen UI wiring.

Real, server-synchronized state (database/models/message.py::
pinned_at/pinned_by, server/client_handler.py::handle_message_pin()/
handle_message_unpin()) -- NOT a fake local-only button. Reuses tests/
test_phase19_24_mobile_drafts.py's ChatScreen harness. Drives the REAL
_handle_bubble_context_action()("pin"/"unpin")/_pinned_bubbles()/
_open_pinned_messages_panel() code a real long-press menu selection and
a real header-button panel actually run, against a REAL running server
and REAL MobileClientSession.

Every incoming-packet signal handler that touches a widget (mobile/
app.py's own documented threading model) is marshalled onto the main
thread via kivy.clock.Clock.schedule_once() -- nothing in this test
process ever runs Kivy's own App.run() event loop to drain that queue,
so every wait below that depends on one of those handlers having run
(a received bubble appearing, a bubble's real message_id resolving, a
live pin/unpin notification applying) must pump Clock.tick() itself
while polling, or the condition would never become true no matter how
long _wait_for() waited. See _ticking() below.

Run with:
    pytest tests/test_phase19_24_mobile_pinned_messages.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from kivy.clock import Clock

from mobile.app import ChatScreen, _bubble_context_actions
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def _ticking(predicate):
    """Wrap a _wait_for() predicate so every poll also drains Kivy's
    Clock -- see this module's own docstring for why that is required
    here and nowhere else in this project's existing mobile tests."""

    def _check():
        Clock.tick()
        return predicate()

    return _check


def test_pinning_via_context_action_updates_both_sides(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mpina"
    )
    try:
        alice_screen = ChatScreen(alice)
        alice_screen.open_chat(bob.username)
        bob_screen = ChatScreen(bob)
        bob_screen.open_chat(alice.username)

        alice_screen._send_text(bob.username, False, "pin me please")
        assert _wait_for(_ticking(lambda: len(bob_screen._bubbles_by_message_id) == 1))
        assert _wait_for(_ticking(lambda: len(alice_screen._bubbles_by_message_id) == 1))

        bubble = list(alice_screen._bubbles_by_message_id.values())[0]
        alice_screen._handle_bubble_context_action("pin", bubble)

        assert bubble.is_pinned is True

        bob_bubble_id = list(bob_screen._bubbles_by_message_id.keys())[0]
        assert _wait_for(_ticking(
            lambda: bob_screen._bubbles_by_message_id[bob_bubble_id].is_pinned
        )), "recipient's bubble was never marked pinned"
        assert bob_screen._bubbles_by_message_id[bob_bubble_id].pinned_by == alice.username
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_any_member_can_pin_not_only_the_sender(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mpinb"
    )
    try:
        alice_screen = ChatScreen(alice)
        alice_screen.open_chat(bob.username)
        bob_screen = ChatScreen(bob)
        bob_screen.open_chat(alice.username)

        alice_screen._send_text(bob.username, False, "bob will pin this")
        assert _wait_for(_ticking(lambda: len(bob_screen._bubbles_by_message_id) == 1))
        assert _wait_for(_ticking(lambda: len(alice_screen._bubbles_by_message_id) == 1))

        bob_bubble = list(bob_screen._bubbles_by_message_id.values())[0]
        assert bob_bubble.kind == "received"

        bob_screen._handle_bubble_context_action("pin", bob_bubble)

        assert bob_bubble.is_pinned is True

        alice_bubble = list(alice_screen._bubbles_by_message_id.values())[0]
        assert _wait_for(_ticking(lambda: alice_bubble.is_pinned is True))
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_unpinning_via_context_action_clears_both_sides(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mpinc"
    )
    try:
        alice_screen = ChatScreen(alice)
        alice_screen.open_chat(bob.username)
        bob_screen = ChatScreen(bob)
        bob_screen.open_chat(alice.username)

        alice_screen._send_text(bob.username, False, "pin then unpin")
        assert _wait_for(_ticking(lambda: len(bob_screen._bubbles_by_message_id) == 1))
        assert _wait_for(_ticking(lambda: len(alice_screen._bubbles_by_message_id) == 1))

        bubble = list(alice_screen._bubbles_by_message_id.values())[0]
        bob_bubble_id = list(bob_screen._bubbles_by_message_id.keys())[0]

        alice_screen._handle_bubble_context_action("pin", bubble)
        assert _wait_for(_ticking(
            lambda: bob_screen._bubbles_by_message_id[bob_bubble_id].is_pinned
        ))

        alice_screen._handle_bubble_context_action("unpin", bubble)
        assert bubble.is_pinned is False

        assert _wait_for(_ticking(
            lambda: bob_screen._bubbles_by_message_id[bob_bubble_id].is_pinned is False
        ))
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_pinned_panel_lists_and_navigates_to_a_pinned_bubble(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mpind"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "not pinned")
        screen._send_text(bob.username, False, "this one is pinned")
        assert _wait_for(_ticking(lambda: len(screen._bubbles_by_message_id) == 2))

        assert screen._pinned_bubbles(bob.username) == []

        target_bubble = list(screen._pending_send_status[bob.username])[-1]
        assert target_bubble.message_id is not None
        screen._handle_bubble_context_action("pin", target_bubble)
        assert target_bubble.is_pinned is True

        pinned = screen._pinned_bubbles(bob.username)
        assert len(pinned) == 1
        assert pinned[0] is target_bubble

        screen._highlight_search_match(target_bubble)
        assert screen._search_highlighted_bubble is target_bubble
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_deleting_a_pinned_message_removes_it_from_the_panel(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mpine"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "pinned then deleted")
        bubble = list(screen._pending_send_status[bob.username])[-1]
        assert _wait_for(_ticking(lambda: bubble.message_id is not None))

        screen._handle_bubble_context_action("pin", bubble)
        assert len(screen._pinned_bubbles(bob.username)) == 1

        screen._do_delete_for_everyone(bubble)
        assert _wait_for(_ticking(lambda: bubble.is_deleted is True))

        assert screen._pinned_bubbles(bob.username) == []
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_context_menu_offers_pin_then_unpin_toggle(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mpinf"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "toggle check")
        bubble = list(screen._pending_send_status[bob.username])[-1]
        assert _wait_for(_ticking(lambda: bubble.message_id is not None))

        actions = dict(_bubble_context_actions(bubble))
        assert actions.get("pin") == "Pin"
        assert "unpin" not in actions

        bubble.set_pinned(True, "alice")

        actions = dict(_bubble_context_actions(bubble))
        assert actions.get("unpin") == "Unpin"
        assert "pin" not in actions
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
