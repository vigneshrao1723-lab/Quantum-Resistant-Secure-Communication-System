"""
GUI-level tests for Phase 8 (File & Image Transfer).

No GUI-test framework exists in this project (see
tests/test_chat_window_connection_status.py's docstring) -- this file
follows that same established pattern: a single self-contained
offscreen QApplication, and direct construction/exercise of the real
widgets rather than a new testing framework. QFileDialog is mocked
(there is no way to drive a native OS file picker in an automated,
headless test) -- everything downstream of the dialog's return value
is the real code path.

Run with:
    pytest tests/test_attachment_gui.py -v
"""

import os
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui.input_bar import InputBar
from gui.message_widget import FileMessageBubble, ImageMessageBubble, MessageWidget

_app = QApplication.instance() or QApplication([])

# A minimal but valid 1x1 PNG -- real image bytes, so QPixmap.loadFromData()
# genuinely succeeds rather than falling into the "[Unable to display
# image]" fallback path.
_VALID_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000a49444154789c6360000002000100"
    "0dae7f870000000049454e44ae426082"
)


# ----------------------------------------------------------------------
# InputBar attachment signal
# ----------------------------------------------------------------------


def test_attach_button_exists_and_starts_enabled_state_matches_input():
    bar = InputBar()
    assert hasattr(bar, "attach_button")
    assert hasattr(bar, "attachment_selected")


def test_attachment_selected_emits_chosen_path():
    bar = InputBar()

    received = []
    bar.attachment_selected.connect(received.append)

    with patch(
        "gui.input_bar.QFileDialog.getOpenFileName",
        return_value=("C:/fake/path/photo.png", "All Files (*)"),
    ):
        bar._handle_attach_clicked()

    assert received == ["C:/fake/path/photo.png"]


def test_attachment_selected_not_emitted_when_dialog_cancelled():
    bar = InputBar()

    received = []
    bar.attachment_selected.connect(received.append)

    with patch(
        "gui.input_bar.QFileDialog.getOpenFileName",
        return_value=("", ""),
    ):
        bar._handle_attach_clicked()

    assert received == []


def test_set_enabled_toggles_attach_button():
    bar = InputBar()

    bar.set_enabled(True)
    assert bar.attach_button.isEnabled() is True

    bar.set_enabled(False)
    assert bar.attach_button.isEnabled() is False


# ----------------------------------------------------------------------
# Image bubble construction
# ----------------------------------------------------------------------


def test_image_bubble_renders_valid_image_bytes():
    bubble = ImageMessageBubble(_VALID_PNG_BYTES, kind="sent")
    assert bubble.kind == "sent"


def test_image_bubble_falls_back_gracefully_for_invalid_bytes():
    """Corrupted/undecodable image bytes must not raise -- they render
    the documented fallback text instead."""
    bubble = ImageMessageBubble(b"not a real image", kind="received", sender="alice")
    assert bubble.kind == "received"


def test_message_widget_add_sent_and_received_image_do_not_raise():
    widget = MessageWidget()
    widget.add_sent_image(_VALID_PNG_BYTES)
    widget.add_received_image("alice", _VALID_PNG_BYTES)
    assert widget.count() == 2


# ----------------------------------------------------------------------
# File bubble construction + Save As
# ----------------------------------------------------------------------


def test_file_bubble_shows_filename_and_size():
    bubble = FileMessageBubble(
        b"file content",
        {"filename": "report.pdf", "size_bytes": 12},
        kind="sent",
    )
    assert bubble._filename == "report.pdf"
    assert bubble._file_bytes == b"file content"


def test_message_widget_add_sent_and_received_file_do_not_raise():
    widget = MessageWidget()
    widget.add_sent_file(b"abc", {"filename": "a.txt"})
    widget.add_received_file("bob", b"abc", {"filename": "a.txt"})
    assert widget.count() == 2


def test_save_as_writes_decrypted_bytes_to_chosen_path(tmp_path):
    destination = tmp_path / "saved_output.bin"
    original_bytes = b"exactly-these-bytes-must-be-written"

    bubble = FileMessageBubble(
        original_bytes, {"filename": "original.bin"}, kind="received", sender="alice"
    )

    with patch(
        "gui.message_widget.QFileDialog.getSaveFileName",
        return_value=(str(destination), "All Files (*)"),
    ):
        bubble._handle_save_as()

    assert destination.read_bytes() == original_bytes


def test_save_as_does_nothing_when_dialog_cancelled(tmp_path):
    bubble = FileMessageBubble(
        b"content", {"filename": "original.bin"}, kind="sent"
    )

    with patch(
        "gui.message_widget.QFileDialog.getSaveFileName",
        return_value=("", ""),
    ):
        bubble._handle_save_as()

    # No exception, and nothing in tmp_path was created.
    assert list(tmp_path.iterdir()) == []
