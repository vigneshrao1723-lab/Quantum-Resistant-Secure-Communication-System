"""
Character-fidelity regression coverage for the "lowercase y renders as
V" investigation (UI Finalization).

The investigation traced this end to end and found no reproducible
data or rendering defect anywhere in the codebase: real synthesized
Qt keystrokes (QTest.keyClicks -- the actual input pipeline, not
.setText()/copy-paste) into the real InputBar composer, the real
AES-256-GCM round trip, and the real MessageBubble/ConversationRow
widgets all preserved every character correctly, including a direct
pixel-level render comparison of the actual glyphs (done manually with
the real "Segoe UI" font via the real Qt "windows" platform -- not
committed here as an automated test, since this suite has no existing
infrastructure for image/pixel comparison and forcing non-offscreen
rendering would make CI runs depend on a real display).

What IS committed here is the CI-safe half: end-to-end TEXT-content
fidelity from real keystrokes through to the rendered widgets' own
QLabel.text(), for the exact characters in question (y/Y/v/V) plus the
original ten-character set the investigation started from. This is a
genuine regression guard for the data layer even though it cannot, by
itself, catch a pure glyph/font-rendering defect -- see the module
docstring above for how that half was actually checked.

Run with:
    pytest tests/test_composer_to_bubble_character_fidelity.py -v
"""

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel

from domain.conversation_summary import ConversationSummary, MessagePreview
from domain.payload_type import PayloadType
from gui.conversation_list_widget import ConversationRow
from gui.input_bar import InputBar
from gui.message_widget import MessageBubble


@pytest.fixture(scope="module", autouse=True)
def _app():
    return QApplication.instance() or QApplication([])


_KEEP_ALIVE = []

CHARS = ["y", "Y", "v", "V", "A", "Z", "0", "1", "?", "!"]


def _type_and_send(bar, text):
    """Real synthesized keystrokes into the real composer widget --
    QTest.keyClicks drives the actual Qt key-event pipeline, not
    .setText()."""

    bar.message_input.clear()
    captured = []
    bar.message_sent.connect(lambda msg, c=captured: c.append(msg))
    QTest.keyClicks(bar.message_input, text)
    composer_text = bar.message_input.text()
    QTest.keyClick(bar.message_input, Qt.Key_Return)
    bar.message_sent.disconnect()
    return composer_text, (captured[0] if captured else None)


@pytest.mark.parametrize("ch", CHARS)
def test_composer_preserves_the_typed_character(ch):
    bar = InputBar()
    _KEEP_ALIVE.append(bar)

    composer_text, sent_text = _type_and_send(bar, ch)

    assert composer_text == ch
    assert sent_text == ch


@pytest.mark.parametrize("ch", CHARS)
def test_sent_and_received_bubbles_render_the_exact_character(ch):
    sent = MessageBubble(ch, kind="sent", timestamp="10:00", read_status=False)
    _KEEP_ALIVE.append(sent)
    # Phase 19.24 (continued): a sent bubble now also carries a reply-
    # preview label and a reactions label (both present but empty/
    # hidden here) alongside the actual message-text label -- matching
    # the "received" case just below, this checks that SOME label
    # renders the exact character, rather than assuming the message
    # text is specifically the first non-timestamp QLabel found.
    sent_labels = [
        label for label in sent.findChildren(QLabel) if label.objectName() != "TimestampLabel"
    ]
    assert any(label.text() == ch for label in sent_labels)

    received = MessageBubble(ch, kind="received", sender="Ramya", timestamp="10:01")
    _KEEP_ALIVE.append(received)
    received_labels = [
        label for label in received.findChildren(QLabel) if label.objectName() != "TimestampLabel"
    ]
    # received bubbles have a sender-name label too; the message body
    # is whichever one actually holds the tested character.
    assert any(label.text() == ch for label in received_labels)


@pytest.mark.parametrize("ch", CHARS)
def test_conversation_preview_row_renders_the_exact_character(ch):
    summary = ConversationSummary(
        conversation_id=None,
        username="Ramya",
        is_online=True,
        latest_message=MessagePreview(payload_type=PayloadType.TEXT, text=ch),
    )
    row = ConversationRow(summary)
    _KEEP_ALIVE.append(row)

    labels = row.findChildren(QLabel)
    assert any(label.text() == ch for label in labels)
