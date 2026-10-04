"""
Phase 19.24 -- Pinned Messages: Desktop UI wiring.

Real, server-synchronized state (database/models/message.py::
pinned_at/pinned_by, server/client_handler.py::handle_message_pin()/
handle_message_unpin()) -- NOT a fake local-only button. Drives the
REAL gui.chat_window.ChatWindow._handle_bubble_context_action()
("pin"/"unpin") and gui.message_widget.MessageWidget.apply_pin_to_
message()/get_pinned_bubbles()/scroll_to_bubble() code a real context-
menu selection and a real header-button panel actually run (bypassing
only the modal QMenu.exec() calls themselves, exactly like this
suite's existing Mute/Archive/Block/Wallpaper/Search tests).

Run with:
    pytest tests/test_phase19_24_desktop_pinned_messages.py -v
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


def test_pinning_via_context_action_updates_both_sides_and_persists_across_reload(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "pin me please")

    alice_window._handle_bubble_context_action("pin", bubble)

    # Optimistic local update, immediately, on the actor's own side.
    assert bubble.is_pinned is True

    # Real server broadcast reaches the OTHER side too.
    assert _wait_for(
        lambda: (bob_window.messages.get_bubble(message_id) or None) is not None
        and bob_window.messages.get_bubble(message_id).is_pinned
    ), "recipient's bubble was never marked pinned"
    assert bob_window.messages.get_bubble(message_id).pinned_by == alice_payload["username"]

    # Pin state survives a fresh history reload (server-side, not
    # merely this session's in-memory bubble) -- reopening the SAME
    # conversation re-runs open_conversation()'s history-load path,
    # which re-applies pinned_at/pinned_by exactly like edit/delete/
    # reactions already do.
    from tests.test_phase19_24_desktop_ui_wiring import _direct_summary

    bob_username = bob_window.session.username
    alice_window.open_conversation(_direct_summary(bob_username))
    reloaded = alice_window.messages.get_bubble(message_id)
    assert reloaded is not None
    assert reloaded.is_pinned is True


def test_any_member_can_pin_not_only_the_sender(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "bob will pin this")

    bob_bubble = bob_window.messages.get_bubble(message_id)
    assert bob_bubble is not None
    assert bob_bubble.kind == "received"

    bob_window._handle_bubble_context_action("pin", bob_bubble)

    assert bob_bubble.is_pinned is True
    assert _wait_for(lambda: bubble.is_pinned is True), "sender's own bubble never updated"


def test_unpinning_via_context_action_clears_both_sides(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "pin then unpin")

    alice_window._handle_bubble_context_action("pin", bubble)
    assert _wait_for(
        lambda: (bob_window.messages.get_bubble(message_id) or None) is not None
        and bob_window.messages.get_bubble(message_id).is_pinned
    )

    alice_window._handle_bubble_context_action("unpin", bubble)
    assert bubble.is_pinned is False

    assert _wait_for(
        lambda: bob_window.messages.get_bubble(message_id).is_pinned is False
    ), "recipient's bubble was never unmarked pinned"


def test_pinned_messages_panel_lists_and_navigates_to_a_pinned_bubble(
    tmp_path, connect, accounts
):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    _send_and_get_bubble(alice_window, bob_window, "not pinned")
    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "this one is pinned")

    assert alice_window.messages.get_pinned_bubbles() == []

    alice_window._handle_bubble_context_action("pin", bubble)

    pinned = alice_window.messages.get_pinned_bubbles()
    assert len(pinned) == 1
    assert pinned[0] is bubble

    assert alice_window.messages.scroll_to_bubble(bubble) is True
    assert alice_window.messages._highlighted_bubble is bubble


def test_deleting_a_pinned_message_removes_it_from_the_panel(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "pinned then deleted")

    alice_window._handle_bubble_context_action("pin", bubble)
    assert len(alice_window.messages.get_pinned_bubbles()) == 1

    alice_window._do_delete_for_everyone(bubble)
    assert _wait_for(lambda: bubble.is_deleted is True)

    assert alice_window.messages.get_pinned_bubbles() == []


def test_context_menu_offers_pin_then_unpin_toggle(tmp_path, connect, accounts):
    from gui.message_widget import _build_message_context_menu

    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, _ = _send_and_get_bubble(alice_window, bob_window, "toggle check")

    menu = _build_message_context_menu(bubble, alice_window)
    actions = {a.data(): a.text() for a in menu.actions()}
    assert actions.get("pin") == "Pin"
    assert "unpin" not in actions

    bubble.set_pinned(True, "alice")

    menu = _build_message_context_menu(bubble, alice_window)
    actions = {a.data(): a.text() for a in menu.actions()}
    assert actions.get("unpin") == "Unpin"
    assert "pin" not in actions
