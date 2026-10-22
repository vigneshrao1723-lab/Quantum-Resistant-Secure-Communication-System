"""
Desktop message rows must be readable by assistive technology.

A message row is a ``setItemWidget()`` widget, which screen readers and UI
automation cannot look inside; the row's accessible text is what they read. It
must describe exactly what the bubble shows and stay in step with edits and
deletions.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from datetime import date

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from gui.message_widget import MessageWidget

_app = QApplication.instance() or QApplication([])


def _texts(widget):
    return [widget.item(i).data(Qt.AccessibleTextRole) for i in range(widget.count())]


def test_sent_and_received_rows_expose_who_what_and_when():
    widget = MessageWidget()
    widget.add_received_message("bob", "hello there", timestamp="10:15", message_date=date(2026, 10, 20))
    widget.add_sent_message("hi bob", timestamp="10:16", message_date=date(2026, 10, 20))

    texts = _texts(widget)
    assert texts[0] == "20 October 2026"  # the date separator
    assert texts[1] == "bob, hello there, 10:15"
    assert texts[2] == "You, hi bob, 10:16"


def test_system_messages_are_exposed_as_their_text():
    widget = MessageWidget()
    widget.add_system_message("You are now verified")

    assert _texts(widget) == ["You are now verified"]


def test_an_edit_updates_the_accessible_text():
    widget = MessageWidget()
    bubble = widget.add_sent_message("first draft", timestamp="09:00")

    bubble.apply_edit("final text", 1)

    assert _texts(widget)[-1] == "You, final text (edited), 09:00"


def test_a_deleted_message_no_longer_exposes_its_content():
    widget = MessageWidget()
    bubble = widget.add_received_message("bob", "secret plan", timestamp="09:30")

    bubble.mark_deleted()

    text = _texts(widget)[-1]
    assert "secret plan" not in text
    assert text == "bob, Message deleted, 09:30"


def test_conversation_rows_expose_name_preview_and_unread_count():
    from domain.conversation_summary import ConversationSummary, MessagePreview
    from domain.payload_type import PayloadType
    from gui.conversation_list_widget import ConversationListWidget

    direct = ConversationSummary(
        conversation_id="c1", username="bob", is_online=True,
        latest_message=MessagePreview(payload_type=PayloadType.TEXT, text="see you at nine"),
    )
    group = ConversationSummary(
        conversation_id="g1", username=None, is_online=False, is_group=True, group_name="Project team",
        latest_message=None,
    )
    widget = ConversationListWidget()
    widget.render([direct, group])

    assert widget.item(0).data(Qt.AccessibleTextRole) == "bob, see you at nine"
    assert widget.item(1).data(Qt.AccessibleTextRole) == "Group Project team, No messages yet"

    widget.set_unread_count(direct.key, 3)

    assert widget.item(0).data(Qt.AccessibleTextRole) == "bob, see you at nine, 3 unread"
