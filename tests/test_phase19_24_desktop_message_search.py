"""
Phase 19.24 -- Message Search: Desktop UI wiring.

Operates ONLY on messages already decrypted and rendered by gui/
message_widget.py::MessageWidget -- the search text is never sent to
the server, and there is no second history fetch (see MessageWidget.
find_matches()'s own docstring). Drives the REAL gui.chat_window.
ChatWindow.handle_toggle_search_bar()/handle_search_next()/handle_
search_previous() and the real QLineEdit the header search button
actually reveals -- exactly like this suite's existing Mute/Archive/
Block/Wallpaper tests, nothing here is faked or bypassed except (where
noted) message delivery being driven directly instead of through a
real socket a second time.

Run with:
    pytest tests/test_phase19_24_desktop_message_search.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _KEEP_ALIVE,
    _send_and_get_bubble,
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)


def test_search_finds_matching_messages_case_insensitively(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    _send_and_get_bubble(alice_window, bob_window, "Hello world")
    _send_and_get_bubble(alice_window, bob_window, "Goodbye now")
    _send_and_get_bubble(alice_window, bob_window, "WORLD peace")

    matches = alice_window.messages.find_matches("world")

    assert len(matches) == 2
    texts = [
        alice_window.messages.itemWidget(alice_window.messages.item(row)).message_text
        for row in matches
    ]
    assert texts == ["Hello world", "WORLD peace"]


def test_search_with_no_matches_returns_empty_list(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    _send_and_get_bubble(alice_window, bob_window, "nothing relevant here")

    assert alice_window.messages.find_matches("xyzzy-not-present") == []
    assert alice_window.messages.find_matches("") == []
    assert alice_window.messages.find_matches("   ") == []


def test_deleted_messages_are_excluded_from_search(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, _ = _send_and_get_bubble(alice_window, bob_window, "erase this secret")
    _send_and_get_bubble(alice_window, bob_window, "keep this secret")

    assert len(alice_window.messages.find_matches("secret")) == 2

    alice_window._handle_bubble_context_action("delete_me", bubble)

    matches = alice_window.messages.find_matches("secret")
    assert len(matches) == 1
    remaining = alice_window.messages.itemWidget(
        alice_window.messages.item(matches[0])
    )
    assert remaining.message_text == "keep this secret"


def test_highlight_row_outlines_the_bubble_and_clear_highlight_restores_it(
    tmp_path, connect, accounts
):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    _send_and_get_bubble(alice_window, bob_window, "outline me please")

    matches = alice_window.messages.find_matches("outline")
    assert len(matches) == 1

    alice_window.messages.highlight_row(matches[0])
    bubble = alice_window.messages._highlighted_bubble
    assert bubble is not None
    assert "border: 2px solid" in bubble._bubble.styleSheet()

    alice_window.messages.clear_highlight()
    assert alice_window.messages._highlighted_bubble is None
    assert "border: 2px solid" not in bubble._bubble.styleSheet()


def test_real_search_bar_ui_toggles_and_navigates_between_matches(
    tmp_path, connect, accounts
):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    _send_and_get_bubble(alice_window, bob_window, "apple one")
    _send_and_get_bubble(alice_window, bob_window, "banana")
    _send_and_get_bubble(alice_window, bob_window, "apple two")

    assert alice_window.search_bar.isVisible() is False

    alice_window.handle_toggle_search_bar()
    assert alice_window.search_bar.isVisible() is True

    alice_window.search_input.setText("apple")
    assert alice_window.search_result_label.text() == "1 of 2"

    alice_window.handle_search_next()
    assert alice_window.search_result_label.text() == "2 of 2"

    # Wraps back around to the first match.
    alice_window.handle_search_next()
    assert alice_window.search_result_label.text() == "1 of 2"

    alice_window.handle_search_previous()
    assert alice_window.search_result_label.text() == "2 of 2"

    alice_window.handle_close_search_bar()
    assert alice_window.search_bar.isVisible() is False
    assert alice_window.search_input.text() == ""
    assert alice_window.messages._highlighted_bubble is None


def test_search_bar_resets_when_switching_conversations(tmp_path, connect, accounts):
    from tests.test_phase19_24_desktop_ui_wiring import _direct_summary, _verify_each_other

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    _send_and_get_bubble(alice_window, bob_window, "findable text")

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)
    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    alice_window.handle_toggle_search_bar()
    alice_window.search_input.setText("findable")
    assert alice_window.search_result_label.text() == "1 of 1"

    alice_window.open_conversation(_direct_summary(carol_payload["username"]))

    assert alice_window.search_bar.isVisible() is False
    assert alice_window.search_input.text() == ""
