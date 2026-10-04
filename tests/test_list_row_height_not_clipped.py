"""
Regression coverage for the "lowercase y renders as V" bug (UI
Finalization).

Root cause: gui/styles.py's global ``QListWidget::item`` rule declares
a top+bottom margin (``LIST_ITEM_VERTICAL_MARGIN``). Qt carves that
margin OUT OF the same rect a ``setItemWidget()`` widget is then given
on top of its own ``sizeHint()`` -- so a ``QListWidgetItem`` sized via
``item.setSizeHint(widget.sizeHint())`` alone silently grants the
embedded widget less height than it asked for. That was invisible for
cap-height glyphs (Y, V, digits), but cropped exactly the last few
pixels of vertical space -- a lowercase descender -- off characters
like "y"/"g"/"j"/"p"/"q". A "y" missing its tail reads as an unrelated
letter, which is what was reported as "lowercase y renders as V".

Deliberately NOT a QLabel.text()-based test: the underlying string was
always correct end-to-end (see
tests/test_composer_to_bubble_character_fidelity.py) -- the defect was
purely in how much vertical space the embedded widget is actually
granted on screen, which QLabel.text() cannot observe. These tests
check the actual geometry relationship that was wrong: a list row's
stored sizeHint versus its embedded widget's own sizeHint, for every
row type affected (message bubbles, date separators, conversation
sidebar rows).

Run with:
    pytest tests/test_list_row_height_not_clipped.py -v
"""

from datetime import date

import pytest
from PySide6.QtWidgets import QApplication

from domain.conversation_summary import ConversationSummary, MessagePreview
from domain.payload_type import PayloadType
from gui.conversation_list_widget import ConversationListWidget
from gui.message_widget import DateSeparatorBubble, MessageWidget, _row_size_hint
from gui.styles import LIST_ITEM_VERTICAL_MARGIN


@pytest.fixture(scope="module", autouse=True)
def _app():
    return QApplication.instance() or QApplication([])


_KEEP_ALIVE = []


def test_list_item_vertical_margin_is_positive():
    """Sanity: the margin this whole fix compensates for is non-zero.
    If gui/styles.py's QListWidget::item margin is ever removed
    entirely, LIST_ITEM_VERTICAL_MARGIN must be updated to match --
    not silently keep padding rows for a margin that no longer
    exists."""

    assert LIST_ITEM_VERTICAL_MARGIN > 0


def test_row_size_hint_adds_the_margin_back():
    widget = MessageWidget()
    _KEEP_ALIVE.append(widget)

    hint = _row_size_hint(widget)

    assert hint.height() == widget.sizeHint().height() + LIST_ITEM_VERTICAL_MARGIN
    assert hint.width() == widget.sizeHint().width()


@pytest.mark.parametrize("kind", ["sent", "received"])
def test_message_bubble_row_is_not_shorter_than_its_widget_plus_margin(kind):
    """The actual bug scenario: add a real "y" bubble through the real
    production method (add_sent_message/add_received_message), then
    check the row was granted at least as much height as the embedded
    widget needs plus the margin the stylesheet carves out of it."""

    widget = MessageWidget()
    _KEEP_ALIVE.append(widget)

    if kind == "sent":
        widget.add_sent_message("y", timestamp="10:00", read_status=False)
    else:
        widget.add_received_message("Ramya", "y", timestamp="10:00")

    item = widget.item(0)
    embedded = widget.itemWidget(item)

    assert item.sizeHint().height() == embedded.sizeHint().height() + LIST_ITEM_VERTICAL_MARGIN


def test_date_separator_row_is_not_shorter_than_its_widget_plus_margin():
    """"January" has a descender too -- the date separator is built by
    the same _maybe_insert_date_separator() path and must not clip
    it."""

    widget = MessageWidget()
    _KEEP_ALIVE.append(widget)

    widget.add_sent_message(
        "hey", timestamp="10:00", read_status=False, message_date=date(2026, 1, 23)
    )

    separator_item = widget.item(0)
    separator_widget = widget.itemWidget(separator_item)
    assert isinstance(separator_widget, DateSeparatorBubble)

    assert (
        separator_item.sizeHint().height()
        == separator_widget.sizeHint().height() + LIST_ITEM_VERTICAL_MARGIN
    )


def test_conversation_preview_row_is_not_shorter_than_its_widget_plus_margin():
    convo_list = ConversationListWidget()
    _KEEP_ALIVE.append(convo_list)

    summary = ConversationSummary(
        conversation_id=1,
        username="Ramya",
        is_online=True,
        latest_message=MessagePreview(
            payload_type=PayloadType.TEXT, text="hey, are you free today?"
        ),
    )
    convo_list.render([summary])

    item = convo_list.item(0)
    embedded = convo_list.itemWidget(item)

    assert item.sizeHint().height() == embedded.sizeHint().height() + LIST_ITEM_VERTICAL_MARGIN
