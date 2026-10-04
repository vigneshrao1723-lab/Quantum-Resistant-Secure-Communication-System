"""
Task 2 -- sender-side delivery status indicators.

Each state must be driven by a real event. The tests below pin that
down in both directions: the glyph a status renders, and -- more
importantly -- the states that must NOT appear (a fabricated read,
a fabricated delivered).
"""

import pytest
from PySide6.QtWidgets import QApplication

from gui.message_widget import (
    STATUS_DELIVERED,
    STATUS_FAILED,
    MessageBubble,
    MessageWidget,
    _read_status_suffix,
)
from gui.styles import COLOR_READ_RECEIPT, COLOR_SEND_FAILED


@pytest.fixture(scope="module", autouse=True)
def _app():
    return QApplication.instance() or QApplication([])


# Bubbles are held for the module's lifetime on purpose: a bubble
# built inline in an expression is garbage-collected before the
# assertion reads it, and PySide6 then raises "Internal C++ object
# already deleted" on the QLabel.
_KEEP_ALIVE = []


def _sent(read_status):
    bubble = MessageBubble(
        "hello", kind="sent", timestamp="10:00", read_status=read_status
    )
    _KEEP_ALIVE.append(bubble)
    return bubble


# ----------------------------------------------------------------------
# Glyph per status
# ----------------------------------------------------------------------


def test_unknown_status_renders_nothing_at_all():
    """None means "no receipt data", which must not be dressed up as
    any positive claim."""

    bubble = _sent(None)

    assert bubble.time_label.text() == "10:00"


def test_sent_renders_a_single_check():
    bubble = _sent(False)
    text = bubble.time_label.text()

    assert "✓" in text
    assert "✓✓" not in text


def test_read_renders_a_blue_double_check():
    bubble = _sent(True)
    text = bubble.time_label.text()

    assert "✓✓" in text
    assert COLOR_READ_RECEIPT in text


def test_failed_renders_a_warning_and_no_check_at_all():
    bubble = _sent(STATUS_FAILED)
    text = bubble.time_label.text()

    assert "⚠" in text
    assert COLOR_SEND_FAILED in text
    assert "✓" not in text


def test_failed_bubble_is_visually_distinct_from_a_sent_one():
    """Red is not legible on the blue sent bubble, so the failure is
    carried by the bubble itself -- see COLOR_BUBBLE_FAILED."""

    from gui.styles import COLOR_BUBBLE_FAILED, COLOR_BUBBLE_SENT

    failed = _sent(STATUS_FAILED)
    ok = _sent(False)

    assert COLOR_BUBBLE_FAILED in failed._bubble.styleSheet()
    assert COLOR_BUBBLE_SENT in ok._bubble.styleSheet()


def test_timestamp_always_comes_first():
    for status in (None, False, True, STATUS_FAILED):
        bubble = _sent(status)
        assert bubble.time_label.text().startswith("10:00")


# ----------------------------------------------------------------------
# States that must never be fabricated
# ----------------------------------------------------------------------


def test_none_false_and_failed_never_render_a_double_check():
    """None/False/STATUS_FAILED must never claim a stronger state than
    they represent -- the only ways to get a double check are the real
    STATUS_DELIVERED (Phase 19.23) and True (read)."""

    for status in (None, False, STATUS_FAILED):
        text = _read_status_suffix(status)
        assert "✓✓" not in text

    assert COLOR_READ_RECEIPT in _read_status_suffix(True)


def test_delivered_renders_a_grey_double_check():
    """Phase 19.23 -- Issue 3: server/client_handler.py now sends this
    client a real message_delivered packet (Phase 19.14) AND a real
    history delivery_status field (_delivery_status_for_own_message()),
    so DELIVERED is a genuine, server-derived event, not a guess. Grey,
    not blue -- deliberately the SAME colour as a plain "Sent" ✓ (no
    inline colour span at all), so DELIVERED and READ differ by tick
    count, exactly like WhatsApp's own convention."""

    bubble = _sent(STATUS_DELIVERED)
    text = bubble.time_label.text()

    assert "✓✓" in text
    assert COLOR_READ_RECEIPT not in text


def test_delivered_is_stronger_than_sent_but_weaker_than_read():
    """set_read_status() must let Sent -> Delivered -> Read progress
    forward, and must never let Read regress back to Delivered."""

    bubble = _sent(False)
    assert "✓✓" not in bubble.time_label.text()

    bubble.set_read_status(STATUS_DELIVERED)
    assert "✓✓" in bubble.time_label.text()
    assert COLOR_READ_RECEIPT not in bubble.time_label.text()

    bubble.set_read_status(True)
    assert COLOR_READ_RECEIPT in bubble.time_label.text()

    # A stray/duplicate message_delivered ack after a read receipt
    # must never downgrade an already-read bubble back to grey.
    bubble.set_read_status(STATUS_DELIVERED)
    assert COLOR_READ_RECEIPT in bubble.time_label.text()


def test_tick_suffix_uses_single_space_not_double():
    """Phase 19.23 -- Issue 5: "✓        ✓"-style over-wide spacing --
    the fix here is one space between the timestamp and the tick
    glyph(s), not two, and the two check marks within "✓✓" itself are
    already adjacent characters in one string, never two separately
    spaced glyphs."""

    assert _read_status_suffix(False) == " ✓"
    assert _read_status_suffix(STATUS_DELIVERED) == " ✓✓"
    assert "✓  ✓" not in _read_status_suffix(True)
    assert "✓  ✓" not in _read_status_suffix(STATUS_DELIVERED)


def test_a_failed_send_is_never_promoted_to_read():
    """mark_all_sent_read() sweeps every tracked sent bubble by design.
    A message whose send call raised never reached the server, so it
    can never have been read."""

    widget = MessageWidget()
    widget.add_sent_message("delivered fine", read_status=False)
    widget.add_sent_message("never left", read_status=STATUS_FAILED)

    widget.mark_all_sent_read()

    texts = [b.time_label.text() for b in widget._sent_bubbles_by_message_id.values()]

    assert any("✓✓" in t for t in texts)
    assert any("⚠" in t for t in texts)
    assert not any("✓✓" in t and "⚠" in t for t in texts)


def test_mark_oldest_undelivered_sent_resolves_in_send_order():
    """Phase 19.23 -- Issue 3: a live-sent bubble has no server message_
    id yet (it is tracked under a "live-N" placeholder until the next
    history reload), so a message_delivered packet's real id cannot be
    matched directly -- the oldest still-plain-"Sent" bubble is, by
    construction, the one it is for."""

    widget = MessageWidget()
    widget.add_sent_message("first", read_status=False)
    widget.add_sent_message("second", read_status=False)

    bubbles = list(widget._sent_bubbles_by_message_id.values())
    assert all("✓✓" not in b.time_label.text() for b in bubbles)

    widget.mark_oldest_undelivered_sent()

    assert "✓✓" in bubbles[0].time_label.text()
    assert "✓✓" not in bubbles[1].time_label.text()

    widget.mark_oldest_undelivered_sent()

    assert "✓✓" in bubbles[1].time_label.text()

    # Nothing left in plain "Sent" -- a further ack is a safe no-op.
    widget.mark_oldest_undelivered_sent()


def test_failed_status_survives_a_direct_set_read_status_call():
    bubble = _sent(STATUS_FAILED)

    bubble.set_read_status(True)

    assert "⚠" in bubble.time_label.text()
    assert "✓✓" not in bubble.time_label.text()


def test_a_received_bubble_never_shows_any_delivery_status():
    bubble = MessageBubble(
        "hi", kind="received", sender="alice", timestamp="10:00",
        read_status=STATUS_FAILED,
    )

    assert bubble.time_label.text() == "10:00"


def test_system_bubble_tolerates_a_status_update():
    bubble = MessageBubble("alice joined", kind="system")

    bubble.set_read_status(True)  # must not raise


# ----------------------------------------------------------------------
# Retry on a failed send
# ----------------------------------------------------------------------


def test_a_successful_send_has_no_retry_control():
    """The control exists only where there is something to recover."""

    assert _sent(False).retry_button is None
    assert _sent(True).retry_button is None
    assert _sent(None).retry_button is None


def test_a_failed_bubble_without_a_callback_has_no_retry_control():
    """A history-loaded failure has nothing to resend through."""

    assert _sent(STATUS_FAILED).retry_button is None


def test_a_failed_bubble_offers_retry_and_keeps_the_text():
    bubble = MessageBubble(
        "the message that never left",
        kind="sent",
        timestamp="10:00",
        read_status=STATUS_FAILED,
        on_retry=lambda b: None,
    )
    _KEEP_ALIVE.append(bubble)

    assert bubble.retry_button is not None
    assert bubble.retry_button.text() == "Retry"
    assert bubble.message_text == "the message that never left"


def test_clicking_retry_hands_the_bubble_back_to_the_owner():
    seen = []

    bubble = MessageBubble(
        "resend me",
        kind="sent",
        timestamp="10:00",
        read_status=STATUS_FAILED,
        on_retry=seen.append,
    )
    _KEEP_ALIVE.append(bubble)

    bubble.retry_button.click()

    assert seen == [bubble]


def test_a_retry_that_fails_leaves_the_message_failed():
    """The bubble must never claim success the owner did not report.
    A failing retry leaves the failure visible and the button usable
    again."""

    def explode(_bubble):
        raise RuntimeError("still disconnected")

    bubble = MessageBubble(
        "x", kind="sent", timestamp="10:00",
        read_status=STATUS_FAILED, on_retry=explode,
    )
    _KEEP_ALIVE.append(bubble)

    with pytest.raises(RuntimeError):
        bubble._handle_retry()

    assert "⚠" in bubble.time_label.text()
    assert "✓" not in bubble.time_label.text()
    assert bubble.retry_button.isEnabled()
    assert bubble.retry_button.text() == "Retry"


def test_a_successful_retry_clears_the_failure_and_removes_the_control():
    bubble = MessageBubble(
        "y", kind="sent", timestamp="10:00",
        read_status=STATUS_FAILED,
        on_retry=lambda b: b.mark_retry_succeeded(),
    )
    _KEEP_ALIVE.append(bubble)

    bubble.retry_button.click()

    text = bubble.time_label.text()

    assert "✓" in text
    assert "⚠" not in text
    assert "✓✓" not in text, "a resend is SENT, not read"
    assert bubble.retry_button is None


def test_a_recovered_bubble_can_then_be_marked_read_normally():
    """Once a retry has succeeded the message is an ordinary sent
    message again, so a genuine read receipt must still promote it."""

    bubble = MessageBubble(
        "z", kind="sent", timestamp="10:00",
        read_status=STATUS_FAILED,
        on_retry=lambda b: b.mark_retry_succeeded(),
    )
    _KEEP_ALIVE.append(bubble)

    bubble.retry_button.click()
    bubble.set_read_status(True)

    assert "✓✓" in bubble.time_label.text()


def test_mark_retry_succeeded_is_a_no_op_for_a_received_bubble():
    bubble = MessageBubble("hi", kind="received", sender="a", timestamp="10:00")
    _KEEP_ALIVE.append(bubble)

    bubble.mark_retry_succeeded()

    assert bubble.time_label.text() == "10:00"


def test_the_read_sweep_still_cannot_promote_a_failed_bubble_with_retry():
    """Adding a retry path must not weaken the terminal-failed rule
    that protects mark_all_sent_read()."""

    widget = MessageWidget()
    _KEEP_ALIVE.append(widget)

    widget.add_sent_message("fine", read_status=False)
    widget.add_sent_message(
        "broken", read_status=STATUS_FAILED, on_retry=lambda b: None
    )

    widget.mark_all_sent_read()

    texts = [b.time_label.text() for b in widget._sent_bubbles_by_message_id.values()]

    assert any("✓✓" in t for t in texts)
    assert any("⚠" in t for t in texts)
