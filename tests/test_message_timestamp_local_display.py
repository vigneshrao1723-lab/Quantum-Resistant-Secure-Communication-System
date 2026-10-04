"""
Timestamp/timezone display bug.

Root cause: every stored/relayed timestamp in this app is naive UTC
by convention (client/session.py::_parse_incoming_timestamp(),
server/client_handler.py::_parse_message_timestamp()) -- deliberately
unchanged by this fix. gui/chat_window.py::load_history() and
gui/conversation_list_widget.py::ConversationRow used to format that
naive-UTC value directly with strftime("%H:%M"), displaying the raw
UTC hour. A message added live this session never went through that
path at all -- MessageBubble falls back to datetime.now() (genuinely
local) when no explicit timestamp is given -- so a freshly-sent
message and a history-loaded one showed two different timezones side
by side, which is what was reported as "the times don't look right".

The fix is gui/message_widget.py::to_local_time(): tag the naive value
as UTC, then call .astimezone() with no argument, which asks the OS
for its own configured local timezone -- never a hardcoded offset, so
these tests must never hardcode one either. Every expected value below
is computed with the exact same to_local_time() the production code
uses, applied to a controlled, known UTC input -- correct on whatever
machine/timezone actually runs this suite.

Run with:
    pytest tests/test_message_timestamp_local_display.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QApplication

from domain.conversation_summary import ConversationSummary, MessagePreview
from domain.payload_type import PayloadType
from gui.chat_window import ChatWindow
from gui.conversation_list_widget import ConversationRow
from gui.message_widget import to_local_time

_app = QApplication.instance() or QApplication([])

_KEEP_ALIVE = []

# A fixed, arbitrary UTC instant -- not "now", so the test is not
# coupled to whatever moment it happens to run.
_KNOWN_UTC = datetime(2026, 1, 15, 9, 6, 0, tzinfo=timezone.utc)
_KNOWN_UTC_NAIVE = _KNOWN_UTC.replace(tzinfo=None)


def _expected_local_hhmm(utc_naive):
    """The correct answer, computed the same way to_local_time() does
    -- this is a controlled reference value, not a duplicate
    implementation: to_local_time() is imported and exercised
    directly, this just gives the parametrized tests something to
    compare its output against without hardcoding a timezone."""
    return to_local_time(utc_naive).strftime("%H:%M")


# ----------------------------------------------------------------------
# to_local_time() itself
# ----------------------------------------------------------------------


def test_to_local_time_applies_the_machines_actual_utc_offset():
    """No hardcoded offset: the expected value is derived from the
    SAME mechanism (datetime.now().astimezone()) the fix itself uses,
    so this is correct on any machine, in any timezone."""

    actual_offset = datetime.now().astimezone().utcoffset()

    result = to_local_time(_KNOWN_UTC_NAIVE)

    assert result.utcoffset() == actual_offset
    assert result.replace(tzinfo=None) == _KNOWN_UTC_NAIVE + actual_offset


def test_to_local_time_is_correct_at_a_day_boundary():
    """A UTC instant late enough in the day to roll into the next
    local calendar date in any positive-offset timezone, and to stay
    on the earlier date in any negative-offset one -- either way,
    to_local_time()'s own .date() must agree with manually applying
    the machine's real offset, not a hardcoded one."""

    late_utc = datetime(2026, 1, 15, 23, 45, 0, tzinfo=timezone.utc)
    actual_offset = datetime.now().astimezone().utcoffset()

    result = to_local_time(late_utc.replace(tzinfo=None))

    assert result.replace(tzinfo=None) == late_utc.replace(tzinfo=None) + actual_offset


def test_to_local_time_never_returns_the_raw_utc_wall_clock_unless_offset_is_zero():
    """The actual regression this whole bug was: naive UTC formatted
    directly, with no conversion at all -- i.e. the WALL-CLOCK hour/
    minute shown to the user staying identical to the raw UTC one.
    (Comparing the datetime objects themselves with != would not catch
    this: two aware datetimes compare by absolute instant, and a
    correct conversion is of course still the same instant -- 14:36
    IST really is 09:06 UTC -- only the displayed wall-clock text
    differs.) Skipped on a machine actually configured for UTC, where
    "converted" and "raw" display identically by coincidence -- there
    is nothing to distinguish there."""

    offset = datetime.now().astimezone().utcoffset()

    if offset == timedelta(0):
        pytest.skip("local machine's timezone is UTC -- nothing to distinguish")

    assert to_local_time(_KNOWN_UTC_NAIVE).strftime("%H:%M") != _KNOWN_UTC_NAIVE.strftime(
        "%H:%M"
    )


# ----------------------------------------------------------------------
# gui/chat_window.py::load_history() -- the transcript
# ----------------------------------------------------------------------


def _make_session_with_history(history_entry):
    session = MagicMock()
    session.key_manager.algorithm = "Kyber"
    session.get_username.return_value = "me"
    session.phone_number = "+919876543210"
    session.get_online_users.return_value = []
    session.conversation_store.get_all.return_value = []
    session.get_unread_count.return_value = 0
    session.load_conversation_history.return_value = [history_entry]
    session.current_conversation_id = "conv-1"
    return session


def _history_entry(is_own, sender="ramya", text="hi"):
    return {
        "sender": sender,
        "text": text,
        "timestamp": _KNOWN_UTC_NAIVE,
        "is_own": is_own,
        "message_id": "m1",
        "read_status": True if is_own else None,
        "payload_type": PayloadType.TEXT,
        "content": None,
        "content_metadata": {},
    }


@pytest.mark.parametrize("is_own", [True, False])
def test_load_history_displays_local_time_not_raw_utc(is_own):
    session = _make_session_with_history(_history_entry(is_own))
    window = ChatWindow(session)
    _KEEP_ALIVE.append(window)

    window.load_history("ramya", is_group=False)

    bubble_item = window.messages.item(window.messages.count() - 1)
    bubble = window.messages.itemWidget(bubble_item)

    assert bubble.time_label.text().startswith(_expected_local_hhmm(_KNOWN_UTC_NAIVE))


def test_load_history_date_separator_uses_the_local_calendar_date():
    """A message timestamped late enough in UTC to be a different
    local calendar date must anchor its date separator to the LOCAL
    date, not the UTC one."""

    late_utc_naive = datetime(2026, 1, 15, 23, 45, 0)
    entry = _history_entry(is_own=False)
    entry["timestamp"] = late_utc_naive

    session = _make_session_with_history(entry)
    window = ChatWindow(session)
    _KEEP_ALIVE.append(window)

    window.load_history("ramya", is_group=False)

    from gui.message_widget import DateSeparatorBubble

    separator_widgets = [
        window.messages.itemWidget(window.messages.item(i))
        for i in range(window.messages.count())
    ]
    separators = [w for w in separator_widgets if isinstance(w, DateSeparatorBubble)]

    assert len(separators) == 1
    assert separators[0].separator_date == to_local_time(late_utc_naive).date()


# ----------------------------------------------------------------------
# gui/conversation_list_widget.py -- the sidebar preview
# ----------------------------------------------------------------------


def test_conversation_row_preview_displays_local_time_not_raw_utc():
    summary = ConversationSummary(
        conversation_id=1,
        username="Ramya",
        is_online=True,
        latest_message=MessagePreview(
            payload_type=PayloadType.TEXT, text="hey", timestamp=_KNOWN_UTC_NAIVE
        ),
    )
    row = ConversationRow(summary)
    _KEEP_ALIVE.append(row)

    from PySide6.QtWidgets import QLabel

    labels = [label.text() for label in row.findChildren(QLabel)]

    assert any(
        text.startswith(_expected_local_hhmm(_KNOWN_UTC_NAIVE)) for text in labels
    ), f"no label showed the expected local time; labels were {labels}"
