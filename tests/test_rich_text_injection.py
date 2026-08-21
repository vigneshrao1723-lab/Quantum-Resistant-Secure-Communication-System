"""
D8 / L-1 -- rich-text injection regression tests.

Every QLabel in this project used to sit on Qt's ``AutoText`` default,
which auto-detects markup and PARSES it. Message bodies, sender names,
attachment filenames and sidebar previews are all attacker-controlled
strings, so a sender could inject HTML into the recipient's window.

The proof that motivated this file: a message containing
``<img src="file:///...">`` caused the recipient's label to read that
file from disk and draw it. ``test_img_tag_cannot_load_a_local_file``
below reproduces exactly that and fails against the old behaviour.

These tests assert two different things on purpose:

  * BEHAVIOUR -- markup arrives as literal characters, and an <img>
    reference draws nothing.
  * STRUCTURE -- ``_assert_all_labels_plain()`` walks a constructed
    widget and fails if ANY label is left parsing markup, so a label
    added later cannot silently reopen the hole.

The one deliberate exception is documented in ``RICH_TEXT_LABELS``.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from datetime import datetime

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPixmap
from PySide6.QtWidgets import QApplication, QLabel

from domain.conversation_summary import ConversationSummary, MessagePreview
from domain.payload_type import PayloadType
from gui.conversation_list_widget import ConversationListWidget, ConversationRow
from gui.message_widget import (
    STATUS_FAILED,
    FileMessageBubble,
    ImageMessageBubble,
    MessageBubble,
    MessageWidget,
)
from gui.online_users_widget import OnlineUsersWidget
from gui.status_bar import StatusBarWidget

_app = QApplication.instance() or QApplication([])

# Widgets are kept alive for the module's lifetime: a widget built
# inline in an expression is garbage-collected before the assertion
# reads it, and PySide6 then raises "Internal C++ object already
# deleted" on its labels.
_KEEP_ALIVE = []


def _keep(widget):
    _KEEP_ALIVE.append(widget)
    return widget


# ----------------------------------------------------------------------
# Payloads
# ----------------------------------------------------------------------

HTML_PAYLOADS = [
    "<b>bold</b>",
    '<a href="http://evil.example">click</a>',
    '<span style="color:#C9F0FF">  \u2713\u2713</span>',
    "<script>alert(1)</script>",
    '<img src="http://evil.example/pixel.png">',
    '<img src="file:///C:/Windows/win.ini">',
    "<h1>huge</h1>",
    "&lt;not-a-tag&gt;",
    "<table><tr><td>cell</td></tr></table>",
]


# ----------------------------------------------------------------------
# Structural guard
# ----------------------------------------------------------------------

# The ONLY labels allowed to parse markup, by object name. Anything
# else that renders rich text is a bug -- see the module docstring.
#
# time_label is app-generated and escaped: gui/message_widget.py::
# _time_label_html() html.escape()s the timestamp and appends this
# module's own constant colour markup for the read/failed glyph.
RICH_TEXT_LABELS = {"TimestampLabel"}


def _assert_all_labels_plain(widget, context):
    """Fail if any label under ``widget`` would parse markup."""

    offenders = []

    for label in widget.findChildren(QLabel):

        if label.objectName() in RICH_TEXT_LABELS:
            assert label.textFormat() == Qt.RichText, (
                f"{context}: {label.objectName()} is whitelisted as rich "
                f"text but is set to {label.textFormat()}"
            )
            continue

        if label.textFormat() != Qt.PlainText:
            offenders.append(
                f"{label.objectName() or '<unnamed>'}"
                f"(text={label.text()[:40]!r}, format={label.textFormat()})"
            )

    assert not offenders, (
        f"{context}: label(s) not pinned to PlainText -- attacker-controlled "
        f"text rendered here would be parsed as markup: {offenders}"
    )


# ----------------------------------------------------------------------
# The original exploit
# ----------------------------------------------------------------------


def _body_label(bubble, needle):
    for label in bubble.findChildren(QLabel):
        if needle in label.text():
            return label
    raise AssertionError(f"no label containing {needle!r}")


def test_img_tag_cannot_load_a_local_file(tmp_path):
    """The exact proof-of-concept from the D8 audit.

    Before the fix this rendered the referenced file: 4800 pixels of
    the 120x40 probe image were drawn into the recipient's chat
    window from their own disk.
    """

    probe = tmp_path / "probe.png"
    image = QImage(120, 40, QImage.Format_RGB32)
    image.fill(QColor(255, 0, 255))
    assert image.save(str(probe), "PNG")

    url = "file:///" + str(probe).replace("\\", "/")

    bubble = _keep(
        MessageBubble(
            f'A<img src="{url}">B',
            kind="received",
            sender="mallory",
            timestamp="10:00",
        )
    )

    label = _body_label(bubble, "A<img")
    label.resize(label.sizeHint())

    # Pre-filled, NOT a bare QPixmap(size). A fresh QPixmap is
    # uninitialised memory and the label's own background is
    # transparent, so leftover frames from other tests show
    # through and get counted. Measured: 1518 "magenta" pixels
    # appeared this way for an <img> whose file does not even
    # exist. Filling first makes every counted pixel one this
    # label actually drew.
    pixmap = QPixmap(label.size())
    pixmap.fill(QColor(0, 0, 0))
    label.render(pixmap)
    rendered = pixmap.toImage()

    magenta = sum(
        1
        for y in range(rendered.height())
        for x in range(rendered.width())
        if (
            rendered.pixelColor(x, y).red() > 200
            and rendered.pixelColor(x, y).blue() > 200
            and rendered.pixelColor(x, y).green() < 60
        )
    )

    assert magenta == 0, (
        f"{magenta} pixels of the referenced local file were drawn -- the "
        f"message body is loading file:// resources"
    )
    assert label.textFormat() == Qt.PlainText
    assert label.text().startswith("A<img src="), (
        "the markup must survive as literal characters"
    )


@pytest.mark.parametrize("payload", HTML_PAYLOADS)
def test_message_body_renders_markup_literally(payload):
    bubble = _keep(
        MessageBubble(payload, kind="received", sender="mallory", timestamp="10:00")
    )

    label = _body_label(bubble, payload[:8])

    assert label.text() == payload
    assert label.textFormat() == Qt.PlainText


def test_markup_occupies_space_instead_of_being_consumed():
    """A width comparison, independent of textFormat(): if Qt were
    parsing the tags they would collapse to nothing and both labels
    would measure the same."""

    tagged = _keep(
        MessageBubble(
            '<b>BOLD</b><a href="http://evil">link</a>',
            kind="received",
            sender="m",
            timestamp="10:00",
        )
    )
    plain = _keep(
        MessageBubble("BOLDlink", kind="received", sender="m", timestamp="10:00")
    )

    tagged_width = _body_label(tagged, "BOLD").sizeHint().width()
    plain_width = _body_label(plain, "BOLD").sizeHint().width()

    assert tagged_width > plain_width, (
        f"tagged={tagged_width} plain={plain_width} -- identical widths mean "
        f"the markup was parsed away rather than displayed"
    )


def test_sender_name_renders_markup_literally():
    hostile = '<b>admin</b><img src="file:///etc/passwd">'

    bubble = _keep(
        MessageBubble("hi", kind="received", sender=hostile, timestamp="10:00")
    )

    label = _body_label(bubble, "<b>admin")

    assert label.text() == hostile
    assert label.textFormat() == Qt.PlainText


def test_system_message_renders_markup_literally():
    hostile = '<img src="file:///etc/passwd">joined'

    bubble = _keep(MessageBubble(hostile, kind="system"))

    label = _body_label(bubble, "<img")

    assert label.text() == hostile
    assert label.textFormat() == Qt.PlainText


def test_attachment_filename_renders_markup_literally():
    """The filename arrives inside content_metadata, chosen by the
    sender."""

    bubble = _keep(
        FileMessageBubble(
            b"data",
            {"filename": '<img src="file:///etc/passwd">.txt', "size": 4},
            kind="received",
            sender="mallory",
            timestamp="10:00",
        )
    )

    _assert_all_labels_plain(bubble, "FileMessageBubble")


def test_conversation_row_renders_markup_literally():
    summary = ConversationSummary(
        conversation_id=None,
        username='<b>alice</b><img src="file:///etc/passwd">',
        is_online=True,
        latest_message=MessagePreview(
            payload_type=PayloadType.TEXT,
            text='<a href="http://evil">preview</a>',
            timestamp=datetime(2026, 1, 1, 10, 0),
        ),
    )

    row = _keep(ConversationRow(summary))

    _assert_all_labels_plain(row, "ConversationRow")


# ----------------------------------------------------------------------
# Structural sweeps
# ----------------------------------------------------------------------


def test_every_label_in_a_populated_transcript_is_plain_text():
    widget = _keep(MessageWidget())

    widget.add_system_message("<b>system</b>")
    widget.add_received_message("mallory", '<img src="file:///x">')
    widget.add_sent_message("<b>mine</b>", read_status=False)
    widget.add_sent_message("failed", read_status=STATUS_FAILED)
    widget.add_received_file(
        "mallory", b"data", {"filename": "<b>x</b>.txt", "size": 4}
    )

    for index in range(widget.count()):
        bubble = widget.itemWidget(widget.item(index))
        if bubble is not None:
            _assert_all_labels_plain(bubble, f"transcript row {index}")


def test_every_label_in_the_sidebar_is_plain_text():
    summaries = [
        ConversationSummary(
            conversation_id=None,
            username="<b>alice</b>",
            is_online=True,
            latest_message=MessagePreview(
                payload_type=PayloadType.TEXT, text="<i>hi</i>"
            ),
        ),
        ConversationSummary(
            conversation_id="c1",
            username=None,
            is_online=False,
            latest_message=None,
            is_group=True,
            group_name='<img src="file:///x">',
        ),
    ]

    widget = _keep(ConversationListWidget())
    widget.render(summaries)

    for index in range(widget.count()):
        row = widget.itemWidget(widget.item(index))
        if row is not None:
            _assert_all_labels_plain(row, f"sidebar row {index}")


def test_status_bar_labels_are_plain_text():
    bar = _keep(StatusBarWidget())

    bar.set_username('<b>root</b>')
    bar.set_phone_number('<img src="file:///x">')

    _assert_all_labels_plain(bar, "StatusBarWidget")


def test_online_users_widget_labels_are_plain_text():
    """Unused in the current UI but kept for rollback safety -- it
    must not be a way back in."""

    widget = _keep(OnlineUsersWidget())
    widget.update_users(["<b>alice</b>"])

    for index in range(widget.count()):
        row = widget.itemWidget(widget.item(index))
        if row is not None:
            _assert_all_labels_plain(row, f"online row {index}")


def test_image_bubble_labels_are_plain_text():
    bubble = _keep(
        ImageMessageBubble(
            b"not-an-image",
            kind="received",
            sender="<b>mallory</b>",
            timestamp="10:00",
            content_metadata={"filename": "<b>x</b>.png"},
        )
    )

    _assert_all_labels_plain(bubble, "ImageMessageBubble")


# ----------------------------------------------------------------------
# The deliberate exception must keep working
# ----------------------------------------------------------------------


def test_trusted_status_glyph_still_renders_as_rich_text():
    bubble = _keep(
        MessageBubble("ok", kind="sent", timestamp="10:00", read_status=True)
    )

    assert bubble.time_label.textFormat() == Qt.RichText
    assert "\u2713\u2713" in bubble.time_label.text()
    assert "<span" in bubble.time_label.text()


def test_timestamp_half_of_the_rich_label_is_escaped():
    """The status suffix is trusted markup; the timestamp it is
    concatenated onto is escaped so the label cannot become an
    injection point if a caller ever passes something unexpected."""

    bubble = _keep(
        MessageBubble(
            "ok",
            kind="sent",
            timestamp='<img src="file:///x">',
            read_status=True,
        )
    )

    text = bubble.time_label.text()

    assert "&lt;img" in text
    assert "<img" not in text
