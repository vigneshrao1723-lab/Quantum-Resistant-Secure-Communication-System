"""
Phase 19.24 -- Message Search: mobile ChatScreen UI wiring.

Mirrors gui/message_widget.py::MessageWidget.find_matches()'s exact
contract on the Kivy side: searches only the already-decrypted bubbles
currently rendered for the open conversation (mobile/app.py::
ChatScreen._search_matching_bubbles()) -- no network call, no second
history fetch, the query text itself never leaves this device.

Reuses tests/test_phase19_24_mobile_drafts.py's ChatScreen harness.
Drives the REAL _toggle_search_bar()/_handle_search_query_changed()/
_search_next()/_search_previous() code a real header search button +
real text field input actually run, against a REAL running server and
REAL MobileClientSession.

Run with:
    pytest tests/test_phase19_24_mobile_message_search.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mobile.app import BG, ChatScreen, SEARCH_HIGHLIGHT
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def test_search_finds_matching_messages_case_insensitively(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "msearcha"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "Hello world")
        screen._send_text(bob.username, False, "Goodbye now")
        screen._send_text(bob.username, False, "WORLD peace")

        matches = screen._search_matching_bubbles(bob.username, "world")

        assert [b.message_text for b in matches] == ["Hello world", "WORLD peace"]
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_search_with_no_matches_or_empty_query_returns_empty_list(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "msearchb"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "nothing relevant here")

        assert screen._search_matching_bubbles(bob.username, "xyzzy-not-present") == []
        assert screen._search_matching_bubbles(bob.username, "") == []
        assert screen._search_matching_bubbles(bob.username, "   ") == []
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_deleted_messages_are_excluded_from_search(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "msearchc"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "erase this secret")
        screen._send_text(bob.username, False, "keep this secret")

        assert len(screen._search_matching_bubbles(bob.username, "secret")) == 2

        bubble_to_delete = screen._pending_send_status[bob.username][0]
        screen._handle_bubble_context_action("delete_me", bubble_to_delete)

        remaining = screen._search_matching_bubbles(bob.username, "secret")
        assert len(remaining) == 1
        assert remaining[0].message_text == "keep this secret"
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_highlighting_a_match_repaints_its_bubble_and_clearing_restores_it(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "msearchd"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "outline me please")
        matches = screen._search_matching_bubbles(bob.username, "outline")
        bubble = matches[0]
        original_bg = bubble._normal_bg

        screen._highlight_search_match(bubble)
        assert tuple(bubble._bg_color.rgba) == SEARCH_HIGHLIGHT
        assert screen._search_highlighted_bubble is bubble

        screen._clear_search_highlight()
        assert screen._search_highlighted_bubble is None
        assert tuple(bubble._bg_color.rgba) == original_bg
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_real_search_bar_ui_toggles_and_navigates_between_matches(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "msearche"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_text(bob.username, False, "apple one")
        screen._send_text(bob.username, False, "banana")
        screen._send_text(bob.username, False, "apple two")

        assert screen._search_bar.height == 0

        screen._toggle_search_bar(bob.username)
        assert screen._search_bar.height > 0

        # The real text field's own bound handler.
        screen._search_input.text = "apple"
        assert screen._search_result_label.text == "1 of 2"

        screen._search_next()
        assert screen._search_result_label.text == "2 of 2"

        # Wraps back around to the first match.
        screen._search_next()
        assert screen._search_result_label.text == "1 of 2"

        screen._search_previous()
        assert screen._search_result_label.text == "2 of 2"

        screen._close_search_bar()
        assert screen._search_bar.height == 0
        assert screen._search_input.text == ""
        assert screen._search_highlighted_bubble is None
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_search_bar_resets_when_switching_conversations(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "msearchf"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)
        screen._send_text(bob.username, False, "findable text")

        screen._toggle_search_bar(bob.username)
        screen._search_input.text = "findable"
        assert screen._search_result_label.text == "1 of 1"

        screen.open_chat(carol.username)

        assert screen._search_bar.height == 0
        assert screen._search_matches == []
        assert screen._search_match_index == -1
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
