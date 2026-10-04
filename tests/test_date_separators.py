"""
UI Finalization Decision 4 -- message-timeline date separators
(Today / Yesterday / a full date), replacing the removed static
"Chatting with <user>" header text.

Follows the established offscreen-QApplication + _KEEP_ALIVE pattern
from tests/test_message_status_indicators.py (a bubble built inline in
an expression is garbage-collected before the assertion reads it,
raising "Internal C++ object already deleted").
"""

from datetime import date, timedelta

import pytest
from PySide6.QtWidgets import QApplication

from gui.message_widget import DateSeparatorBubble, MessageWidget, _date_separator_text


@pytest.fixture(scope="module", autouse=True)
def _app():
    return QApplication.instance() or QApplication([])


_KEEP_ALIVE = []


def _widget():
    w = MessageWidget()
    _KEEP_ALIVE.append(w)
    return w


def _separator_texts(widget):
    """Every DateSeparatorBubble's rendered text, in list order.
    DateSeparatorBubble has no public text accessor, so this reads its
    one QLabel child directly off the layout (index 1: stretch, label,
    stretch)."""

    return [
        widget.itemWidget(widget.item(i)).layout().itemAt(1).widget().text()
        for i in range(widget.count())
        if isinstance(widget.itemWidget(widget.item(i)), DateSeparatorBubble)
    ]


def _row_kinds(widget):
    """'separator' or the underlying bubble's `kind` for every row, in order."""

    kinds = []
    for i in range(widget.count()):
        item_widget = widget.itemWidget(widget.item(i))
        if isinstance(item_widget, DateSeparatorBubble):
            kinds.append("separator")
        else:
            kinds.append(item_widget.kind)
    return kinds


# ----------------------------------------------------------------------
# _date_separator_text() -- Today / Yesterday / older
# ----------------------------------------------------------------------


def test_todays_date_renders_as_today():
    assert _date_separator_text(date.today()) == "Today"


def test_yesterdays_date_renders_as_yesterday():
    assert _date_separator_text(date.today() - timedelta(days=1)) == "Yesterday"


def test_an_older_date_renders_as_a_full_date():
    """A fixed calendar date would coincide with 'today' on the one
    day a year it's actually run, so this is computed relative to the
    real current date instead -- guaranteed neither today nor
    yesterday, whenever the test executes."""
    older = date.today() - timedelta(days=10)
    text = _date_separator_text(older)
    assert text != "Today"
    assert text != "Yesterday"
    assert str(older.year) in text


def test_date_calculation_uses_the_actual_current_date_not_a_fixed_one():
    """Regression guard against a hardcoded reference date: exactly
    one day before the REAL today must always be 'Yesterday', whatever
    day the test happens to run on."""

    real_today = date.today()
    assert _date_separator_text(real_today - timedelta(days=1)) == "Yesterday"
    assert _date_separator_text(real_today) == "Today"


# ----------------------------------------------------------------------
# MessageWidget -- one separator per calendar date, not per message
# ----------------------------------------------------------------------


def test_same_day_messages_get_exactly_one_separator():
    widget = _widget()
    today = date.today()

    widget.add_received_message("bob", "hi", message_date=today)
    widget.add_sent_message("hello", message_date=today)
    widget.add_received_message("bob", "how are you", message_date=today)

    assert _row_kinds(widget) == ["separator", "received", "sent", "received"]


def test_multiple_dates_show_separators_in_chronological_order():
    widget = _widget()
    day1 = date(2026, 8, 20)
    day2 = date(2026, 8, 21)
    day3 = date(2026, 8, 22)

    widget.add_received_message("bob", "day one", message_date=day1)
    widget.add_sent_message("still day one", message_date=day1)
    widget.add_received_message("bob", "day two", message_date=day2)
    widget.add_sent_message("day three", message_date=day3)

    assert _row_kinds(widget) == [
        "separator", "received", "sent",
        "separator", "received",
        "separator", "sent",
    ]


def test_today_and_yesterday_labels_appear_for_a_two_day_history():
    widget = _widget()
    today = date.today()
    yesterday = today - timedelta(days=1)

    widget.add_received_message("bob", "yesterday's message", message_date=yesterday)
    widget.add_sent_message("today's message", message_date=today)

    assert _separator_texts(widget) == ["Yesterday", "Today"]


def test_older_date_label_appears_correctly():
    """A single-digit day renders without a leading zero (e.g. "1
    January 2026", not "01 January 2026") -- more natural to read,
    and matches _date_separator_text()'s own lstrip("0")."""
    widget = _widget()
    older = date(2026, 1, 1)

    widget.add_received_message("bob", "new year", message_date=older)

    assert _separator_texts(widget) == ["1 January 2026"]


def test_system_message_does_not_trigger_or_break_a_separator():
    """A system notice between two same-day messages must not itself
    cause an extra separator, and must not prevent the real one."""
    widget = _widget()
    today = date.today()

    widget.add_received_message("bob", "hi", message_date=today)
    widget.add_system_message("bob left the chat")
    widget.add_sent_message("bye", message_date=today)

    assert _row_kinds(widget) == ["separator", "received", "system", "sent"]


def test_live_message_crossing_midnight_inserts_a_new_separator_without_reload():
    """The live-session case: a conversation open across midnight must
    get a new separator the moment a message with a later date is
    added -- no clear_messages()/reload involved."""
    widget = _widget()
    day1 = date(2026, 8, 24)
    day2 = date(2026, 8, 25)

    widget.add_received_message("bob", "before midnight", message_date=day1)
    widget.add_sent_message("after midnight", message_date=day2)

    assert _row_kinds(widget) == ["separator", "received", "separator", "sent"]
    assert _separator_texts(widget) == [
        _date_separator_text(day1), _date_separator_text(day2)
    ]


def test_clear_messages_resets_separator_state_for_a_fresh_render():
    """Reopening/reloading a conversation must not inherit the
    previous conversation's 'last separator date' -- otherwise the
    first message of a freshly-loaded history could be silently
    missing its separator if it happens to share a date with whatever
    was last shown before clear_messages()."""
    widget = _widget()
    today = date.today()

    widget.add_received_message("bob", "hi", message_date=today)
    widget.clear_messages()
    widget.add_received_message("carol", "hi again", message_date=today)

    assert _row_kinds(widget) == ["separator", "received"]


def test_no_date_given_does_not_insert_a_separator():
    """message_date=None (the default) must remain a safe no-op --
    every pre-existing caller that never passes it keeps working
    exactly as before this feature existed."""
    widget = _widget()

    widget.add_received_message("bob", "hi")
    widget.add_sent_message("hello")

    assert _row_kinds(widget) == ["received", "sent"]
