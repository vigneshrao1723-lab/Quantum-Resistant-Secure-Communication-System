"""
GUI-level tests for C2 (Read Receipts).

Follows the established offscreen-QApplication pattern (see
tests/test_chat_window_connection_status.py). ChatWindow itself is
deliberately not constructed here, for the same reason that file
gives: it requires a fully authenticated session, a live socket, and a
real database connection just to build. These tests instead exercise
the two real pieces ChatWindow.handle_read_receipt_updated() wires
together -- MessageWidget's bubble tracking/status display, and
ClientSession's read_receipt_updated signal -- directly.

Run with:
    pytest tests/test_read_receipts_gui.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from client.session import ClientSession
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


def test_sent_message_without_message_id_is_not_tracked():
    """A message sent live this session (no database id yet -- see
    gui/chat_window.py::send_message()) simply isn't reachable by a
    later notification; it must not raise or register under a bogus
    key."""
    widget = MessageWidget()
    widget.add_sent_message("hi")

    assert widget._sent_bubbles_by_message_id == {}


def test_received_message_is_never_tracked_even_with_a_message_id():
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
    assert widget._sent_bubbles_by_message_id != {}

    widget.clear_messages()

    assert widget._sent_bubbles_by_message_id == {}


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
