"""
Desktop: group membership events appear in the open group as one fixed sentence, once, in order.

Real ChatWindows on real sessions over the real server. The sentence is built from the
server-recorded actor and subject and the display names -- never from text a peer typed.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from gui.message_widget import MessageBubble
from tests.test_desktop_chat_settings import _group_windows  # noqa: F401 -- helper reused
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401 -- fixtures reused
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])


@pytest.fixture()
def pair(connect, accounts, tmp_path):
    return _two_windows(connect, accounts, tmp_path)


def _system_lines(window):
    lines = []
    for row in range(window.messages.count()):
        widget = window.messages.itemWidget(window.messages.item(row))
        if isinstance(widget, MessageBubble) and widget.kind == "system":
            lines.append(widget.message_text)
    return lines


def _event(kind, actor, subject, event_id="e1"):
    return {"event_id": event_id, "event_type": kind, "actor": actor, "subject": subject, "timestamp": None}


def test_the_sentence_reads_correctly_from_every_point_of_view(pair):
    alice_window, bob_window, alice_payload, bob_payload = pair
    alice, bob = alice_payload["username"], bob_payload["username"]
    window = alice_window                                    # this account is "alice"
    window.name_for = lambda handle: {"carol": "Carol", bob: "Bob"}.get(handle, handle)

    assert window.group_event_text(_event("member_added", alice, "carol")) == "You added Carol"
    assert window.group_event_text(_event("member_added", bob, alice)) == "Bob added you"
    assert window.group_event_text(_event("member_added", bob, "carol")) == "Bob added Carol"
    assert window.group_event_text(_event("member_added", None, "carol")) == "Carol was added to the group"
    assert window.group_event_text(_event("member_removed", alice, "carol")) == "You removed Carol"
    assert window.group_event_text(_event("member_removed", bob, alice)) == "Bob removed you"
    assert window.group_event_text(_event("member_removed", bob, "carol")) == "Bob removed Carol"
    assert window.group_event_text(_event("member_left", "carol", "carol")) == "Carol left the group"
    assert window.group_event_text(_event("member_left", alice, alice)) == "You left the group"


def test_a_member_leaving_shows_up_live_in_the_open_group(pair):
    alice_window, bob_window, alice_payload, bob_payload = _group_windows(pair)
    assert _system_lines(alice_window)[-1].startswith("Group:")      # the open group, nothing else yet

    bob_window.session.leave_group_conversation(bob_window.session.get_current_chat())

    assert _wait_for(lambda: any(line.endswith("left the group") for line in _system_lines(alice_window)))
    line = next(l for l in _system_lines(alice_window) if l.endswith("left the group"))
    assert line == f"{alice_window.name_for(bob_payload['username'])} left the group"


def test_an_admin_removal_names_the_admin_and_the_event_is_shown_once_even_after_a_reload(pair):
    alice_window, bob_window, alice_payload, bob_payload = _group_windows(pair)
    conversation_id = alice_window.session.get_current_chat()

    assert alice_window.session.remove_group_member(conversation_id, bob_payload["username"]).get("success")

    assert _wait_for(lambda: any(l.startswith("You removed") for l in _system_lines(alice_window)))
    live = [l for l in _system_lines(alice_window) if l.startswith("You removed")]
    # (Both accounts share a display name here, so the handle tells them apart.)
    assert len(live) == 1
    assert live[0].startswith(f"You removed {alice_window.name_for(bob_payload['username'])}")
    assert live[0].endswith(f"(@{bob_payload['username']})")

    # Reopening the group reloads history: the same event (same id) is shown once, not twice.
    alice_window.open_conversation(alice_window.session.conversation_store.get(conversation_id))
    assert _wait_for(lambda: any(l.startswith("You removed") for l in _system_lines(alice_window)))
    again = [l for l in _system_lines(alice_window) if l.startswith("You removed")]
    assert len(again) == 1

    # And the person removed no longer has the group at all, so nothing is shown to them.
    assert _wait_for(lambda: bob_window.session.conversation_store.get(conversation_id) is None)
    assert not any("removed" in line for line in _system_lines(bob_window))


def test_history_places_events_in_order_among_the_messages(pair):
    alice_window, bob_window, alice_payload, bob_payload = _group_windows(pair)
    conversation_id = alice_window.session.get_current_chat()
    session = alice_window.session

    alice_window.send_message("before")
    assert _wait_for(lambda: any(isinstance(alice_window.messages.itemWidget(alice_window.messages.item(i)), MessageBubble)
                                 and alice_window.messages.itemWidget(alice_window.messages.item(i)).message_text == "before"
                                 for i in range(alice_window.messages.count())))
    assert session.remove_group_member(conversation_id, bob_payload["username"]).get("success")
    assert _wait_for(lambda: any(l.startswith("You removed") for l in _system_lines(alice_window)))
    alice_window.send_message("after")

    def order():
        sequence = []
        for row in range(alice_window.messages.count()):
            widget = alice_window.messages.itemWidget(alice_window.messages.item(row))
            if isinstance(widget, MessageBubble):
                sequence.append(widget.message_text)
        return [s for s in sequence if s in ("before", "after") or s.startswith("You removed")]

    assert _wait_for(lambda: len(order()) == 3)
    live_order = order()
    assert live_order[0] == "before" and live_order[1].startswith("You removed") and live_order[2] == "after"

    # Reloaded from the server: the same order.
    alice_window.open_conversation(session.conversation_store.get(conversation_id))
    assert _wait_for(lambda: len(order()) == 3)
    assert order() == live_order
