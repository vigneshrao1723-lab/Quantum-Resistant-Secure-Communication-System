"""
GUI-level tests for C2 (Read Receipts).

Follows the established offscreen-QApplication pattern (see
tests/test_chat_window_connection_status.py). A full ChatWindow is
never constructed, for the same reason that file gives: it requires a
fully authenticated session, a live socket, and a real database
connection just to build. The first two sections instead exercise the
real pieces ChatWindow.handle_read_receipt_updated() wires together --
MessageWidget's bubble tracking/status display, and ClientSession's
read_receipt_updated signal -- directly.

The final section calls ChatWindow.handle_read_receipt_updated()
itself -- the real, unmodified production method, not a
reimplementation of its logic -- against a minimal stand-in object
carrying exactly the three attributes it reads/writes (session,
messages, _read_receipt_readers). session and messages are always real
production objects (a bare ClientSession, a real MessageWidget); only
ChatWindow's own construction is stood in for, exactly matching this
file's and test_chat_window_connection_status.py's established reason
for avoiding it.

Run with:
    pytest tests/test_read_receipts_gui.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from types import SimpleNamespace

from PySide6.QtWidgets import QApplication

from client.session import ClientSession
from gui.chat_window import ChatWindow
from gui.message_widget import FileMessageBubble, MessageBubble, MessageWidget

_app = QApplication.instance() or QApplication([])


# ----------------------------------------------------------------------
# Bubble-level: check-mark glyph rendering
# ----------------------------------------------------------------------


def test_sent_bubble_with_none_status_shows_no_glyph():
    bubble = MessageBubble("hello", kind="sent", timestamp="10:00", read_status=None)
    assert bubble.time_label.text() == "10:00"


def test_sent_bubble_with_false_status_shows_single_check():
    bubble = MessageBubble("hello", kind="sent", timestamp="10:00", read_status=False)
    assert "10:00" in bubble.time_label.text()
    assert "✓✓" not in bubble.time_label.text()
    assert "✓" in bubble.time_label.text()


def test_sent_bubble_with_true_status_shows_double_check():
    bubble = MessageBubble("hello", kind="sent", timestamp="10:00", read_status=True)
    assert "✓✓" in bubble.time_label.text()


def test_received_bubble_never_shows_a_status_glyph_even_if_passed():
    """Structural guard, not just a default: even if a caller
    mistakenly passed read_status for a received bubble, it must not
    render -- received messages never show a receipt indicator."""
    bubble = MessageBubble(
        "hi", kind="received", sender="alice", timestamp="10:00", read_status=True
    )
    assert "✓" not in bubble.time_label.text()


def test_set_read_status_updates_sent_bubble_in_place():
    bubble = MessageBubble("hello", kind="sent", timestamp="10:00", read_status=False)
    assert "✓✓" not in bubble.time_label.text()

    bubble.set_read_status(True)

    assert "✓✓" in bubble.time_label.text()
    assert bubble.time_label.text().startswith("10:00")


def test_set_read_status_is_a_no_op_for_received_bubble():
    bubble = MessageBubble("hi", kind="received", sender="alice", timestamp="10:00")
    original = bubble.time_label.text()

    bubble.set_read_status(True)

    assert bubble.time_label.text() == original


def test_file_bubble_read_status_glyph_matches_text_bubble_behavior():
    bubble = FileMessageBubble(
        b"content", {"filename": "a.txt"}, kind="sent", timestamp="10:00", read_status=False
    )
    assert "✓" in bubble.time_label.text()

    bubble.set_read_status(True)
    assert "✓✓" in bubble.time_label.text()


# ----------------------------------------------------------------------
# MessageWidget-level: bubble tracking + mark_all_sent_read()
# ----------------------------------------------------------------------


def test_sent_message_with_message_id_is_tracked():
    widget = MessageWidget()
    widget.add_sent_message("hi", message_id="msg-1", read_status=False)

    assert "msg-1" in widget._sent_bubbles_by_message_id


def test_sent_message_without_message_id_is_still_tracked():
    """BUG 2: a message sent live this session has no database id on
    this client (the id is assigned server-side and never sent back),
    and it used to be left unregistered -- which is exactly why a
    sender watching the conversation saw no double tick when the other
    party read it, and why the tick only appeared after a logout/login
    re-rendered the message from history.

    This test previously asserted the opposite. It was inverted only
    after the behaviour was proven wrong end to end: the receipt does
    reach the sender's ClientSession and the signal does fire, so the
    sole reason nothing changed on screen was that no bubble had been
    registered to flip.
    """

    widget = MessageWidget()
    widget.add_sent_message("hi")

    assert len(widget._sent_bubbles_by_message_id) == 1

    widget.mark_all_sent_read()

    bubble = next(iter(widget._sent_bubbles_by_message_id.values()))
    assert "✓✓" in bubble.time_label.text()


def test_live_sent_bubbles_get_distinct_keys():
    """Two live messages must both be reachable -- one must not
    overwrite the other in the registry."""

    widget = MessageWidget()
    widget.add_sent_message("first")
    widget.add_sent_message("second")

    assert len(widget._sent_bubbles_by_message_id) == 2


def test_real_message_ids_are_still_used_as_keys():
    """The synthetic key is only a fallback: a known database id must
    still key its bubble, so a future per-message receipt can address
    exactly one bubble."""

    widget = MessageWidget()
    widget.add_sent_message("live one")
    widget.add_sent_message("from history", message_id="msg-1", read_status=False)

    assert "msg-1" in widget._sent_bubbles_by_message_id
    assert len(widget._sent_bubbles_by_message_id) == 2


def test_received_message_is_never_tracked():
    """Only SENT bubbles are registered -- a received bubble never
    shows a receipt glyph, so tracking it would only waste memory.
    Unchanged by BUG 2, and deliberately re-asserted here: the fix
    widened registration to every sent bubble, not to every bubble."""

    widget = MessageWidget()
    widget.add_received_message("bob", "hi")

    assert widget._sent_bubbles_by_message_id == {}


def test_mark_all_sent_read_flips_every_tracked_bubble():
    widget = MessageWidget()
    widget.add_sent_message("first", message_id="m1", read_status=False)
    widget.add_sent_message("second", message_id="m2", read_status=False)

    widget.mark_all_sent_read()

    for bubble in widget._sent_bubbles_by_message_id.values():
        assert "✓✓" in bubble.time_label.text()


def test_mark_all_sent_read_does_not_affect_received_bubbles():
    widget = MessageWidget()
    widget.add_received_message("bob", "hi there")
    widget.add_sent_message("reply", message_id="m1", read_status=False)

    widget.mark_all_sent_read()

    # The received bubble is item 0; assert it never gained a glyph.
    received_bubble = widget.itemWidget(widget.item(0))
    assert "✓" not in received_bubble.time_label.text()


def test_clear_messages_resets_sent_bubble_tracking():
    widget = MessageWidget()
    widget.add_sent_message("hi", message_id="m1", read_status=False)
    widget.add_sent_message("live one")
    assert widget._sent_bubbles_by_message_id != {}

    widget.clear_messages()

    assert widget._sent_bubbles_by_message_id == {}

    # The synthetic-key counter resets too, so a reopened conversation
    # starts from a clean slate rather than accumulating keys forever.
    assert widget._live_bubble_sequence == 0


# ----------------------------------------------------------------------
# ClientSession-level: read_receipt_updated signal wiring
# ----------------------------------------------------------------------


def test_handle_read_receipt_notification_emits_signal_with_fields():
    session = ClientSession()

    received = []
    session.read_receipt_updated.connect(
        lambda conversation_id, reader: received.append((conversation_id, reader))
    )

    session.handle_read_receipt_notification(
        {
            "type": "read_receipt_notification",
            "conversation_id": "conv-123",
            "reader": "bob",
        }
    )

    assert received == [("conv-123", "bob")]


def test_handle_read_receipt_notification_ignores_malformed_packet():
    session = ClientSession()

    received = []
    session.read_receipt_updated.connect(
        lambda conversation_id, reader: received.append((conversation_id, reader))
    )

    session.handle_read_receipt_notification({"type": "read_receipt_notification"})

    assert received == []


def test_mark_conversation_read_is_a_no_op_without_a_conversation_id():
    """Must not raise or attempt a send when there's nothing to mark
    (e.g. a direct partner never messaged, so no conversation_id
    exists yet)."""
    session = ClientSession()

    # No socket connection exists on a bare ClientSession -- if this
    # attempted to send anything, it would raise (client_socket is a
    # fresh, unconnected socket object). Reaching the assertion below
    # without an exception is the proof it returned early.
    session.mark_conversation_read(None)

    assert True


# ----------------------------------------------------------------------
# ChatWindow-level: handle_read_receipt_updated() itself
# ----------------------------------------------------------------------


def _make_window(session, messages):
    """A minimal stand-in for ChatWindow -- see module docstring for
    why a real one isn't constructed. Carries exactly the three
    attributes handle_read_receipt_updated() reads/writes; the method
    called against it below is the real, unmodified one from
    gui/chat_window.py, not a reimplementation."""
    return SimpleNamespace(
        session=session,
        messages=messages,
        _read_receipt_readers=set(),
    )


def _direct_session(conversation_id, username="alice"):
    session = ClientSession()
    session.username = username
    session.current_conversation_id = conversation_id
    session.current_chat_is_group = False
    return session


def _group_session(conversation_id, participants, username="alice"):
    """participants excludes ``username`` itself, exactly like
    ClientSession.handle_group_create()/handle_group_members_added()
    already populate conversation_store for a real group."""
    session = ClientSession()
    session.username = username
    session.current_conversation_id = conversation_id
    session.current_chat_is_group = True
    session.conversation_store.add_or_update_group(
        conversation_id, "Test Group", participants
    )
    return session


def test_read_receipt_updated_ignores_notification_for_a_different_conversation():
    session = _direct_session("conv-a")
    messages = MessageWidget()
    messages.add_sent_message("hi", message_id="m1", read_status=False)
    window = _make_window(session, messages)

    ChatWindow.handle_read_receipt_updated(window, "conv-b", "bob")

    bubble = messages._sent_bubbles_by_message_id["m1"]
    assert "✓✓" not in bubble.time_label.text()
    assert window._read_receipt_readers == set()


def test_read_receipt_updated_flips_direct_conversation_immediately():
    session = _direct_session("conv-a")
    messages = MessageWidget()
    messages.add_sent_message("hi", message_id="m1", read_status=False)
    window = _make_window(session, messages)

    ChatWindow.handle_read_receipt_updated(window, "conv-a", "bob")

    bubble = messages._sent_bubbles_by_message_id["m1"]
    assert "✓✓" in bubble.time_label.text()


def test_read_receipt_updated_group_partial_readers_does_not_flip():
    session = _group_session("conv-g", ["bob", "charlie"])
    messages = MessageWidget()
    messages.add_sent_message("hi", message_id="m1", read_status=False)
    window = _make_window(session, messages)

    ChatWindow.handle_read_receipt_updated(window, "conv-g", "bob")

    bubble = messages._sent_bubbles_by_message_id["m1"]
    assert "✓✓" not in bubble.time_label.text()
    assert window._read_receipt_readers == {"bob"}


def test_read_receipt_updated_group_flips_once_every_active_reader_present():
    session = _group_session("conv-g", ["bob", "charlie"])
    messages = MessageWidget()
    messages.add_sent_message("hi", message_id="m1", read_status=False)
    window = _make_window(session, messages)

    ChatWindow.handle_read_receipt_updated(window, "conv-g", "bob")
    assert "✓✓" not in messages._sent_bubbles_by_message_id["m1"].time_label.text()

    ChatWindow.handle_read_receipt_updated(window, "conv-g", "charlie")

    bubble = messages._sent_bubbles_by_message_id["m1"]
    assert "✓✓" in bubble.time_label.text()


def test_read_receipt_updated_duplicate_notification_for_same_reader_is_harmless():
    """A redundant notification for a reader already accounted for
    must not do anything surprising -- readers is a set, so re-adding
    the same one changes nothing."""
    session = _group_session("conv-g", ["bob", "charlie"])
    messages = MessageWidget()
    messages.add_sent_message("hi", message_id="m1", read_status=False)
    window = _make_window(session, messages)

    ChatWindow.handle_read_receipt_updated(window, "conv-g", "bob")
    ChatWindow.handle_read_receipt_updated(window, "conv-g", "bob")

    assert window._read_receipt_readers == {"bob"}
    assert "✓✓" not in messages._sent_bubbles_by_message_id["m1"].time_label.text()


def test_read_receipt_updated_reader_state_resets_when_switching_conversations():
    """Mirrors exactly what gui/chat_window.py::open_conversation()
    does on every conversation switch (_read_receipt_readers = set(),
    then a fresh render): proves stale accumulation from a previously
    open group cannot leak into a freshly opened one and cause a
    premature flip."""
    session = _group_session("conv-g1", ["bob", "charlie"])
    messages = MessageWidget()
    window = _make_window(session, messages)

    ChatWindow.handle_read_receipt_updated(window, "conv-g1", "bob")
    assert window._read_receipt_readers == {"bob"}

    # The exact reset open_conversation() performs before every fresh
    # history load, immediately followed by switching to a second,
    # unrelated group.
    window._read_receipt_readers = set()
    session.current_conversation_id = "conv-g2"
    session.conversation_store.add_or_update_group(
        "conv-g2", "Second Group", ["dave", "erin"]
    )
    messages.clear_messages()
    messages.add_sent_message("hi again", message_id="m2", read_status=False)

    # bob's earlier read of conv-g1 must not count toward conv-g2.
    ChatWindow.handle_read_receipt_updated(window, "conv-g2", "dave")

    bubble = messages._sent_bubbles_by_message_id["m2"]
    assert "✓✓" not in bubble.time_label.text()
    assert window._read_receipt_readers == {"dave"}
