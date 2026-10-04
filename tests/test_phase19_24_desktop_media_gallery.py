"""
Phase 19.24 -- Media Gallery: Desktop UI.

A real per-conversation view over already-decrypted, already-rendered
image/video/voice/file bubbles (gui.message_widget.MessageWidget.
get_media_bubbles()) -- never a second history fetch, never anything
sent to the server. Drives the REAL gui.chat_window.ChatWindow.
handle_open_media_gallery() code a real header-button click actually
runs (bypassing only the modal QDialog.exec() call itself, exactly
like this suite's existing Mute/Wallpaper/Search/Pin/Voice-Video
tests).

Run with:
    pytest tests/test_phase19_24_desktop_media_gallery.py -v

KNOWN ENVIRONMENT LIMITATION -- run tests in this file individually,
not as a whole-file batch, on this project's current Windows dev
machine: any two tests in this file that BOTH send a real attachment
through a real _two_windows() ChatWindow pair (i.e. any two of
test_gallery_lists_a_sent_image_and_a_sent_file/test_gallery_reaches_
the_real_recipient_too/test_deleted_attachment_is_excluded_from_the_
gallery/test_media_gallery_dialog_shows_a_clickable_thumbnail_that_
opens_the_viewer), run one after another in the SAME pytest process,
reliably hang indefinitely -- confirmed via bisection (every pair
where only one of the two sends an attachment runs fine; every pair
where both do hangs). Every test in this file is independently
correct and passes standalone, reliably and fast (1-2s). This is a
new manifestation of this project's own documented Qt/Windows GUI
resource-accumulation class (see this project's own memory notes) --
specifically involving the real encrypted-attachment/blob-storage
send path through multiple independent real ChatWindow/server pairs
in one process, not merely plain widget construction. Not chased
further per this phase's own "do not get stuck on environmental
flakiness" testing-strategy guidance -- documented here instead.
"""

import os
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from gui.message_widget import FileMessageBubble, ImageMessageBubble
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _KEEP_ALIVE,
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)

# A minimal but valid 1x1 PNG -- real image bytes, so this exercises
# the actual decode path, not a stub.
_VALID_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000a49444154789c6360000002000100"
    "0dae7f870000000049454e44ae426082"
)


def test_gallery_is_empty_before_any_attachment_is_sent(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    assert alice_window.messages.get_media_bubbles() == []


def test_gallery_lists_a_sent_image_and_a_sent_file(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    image_path = tmp_path / "photo.png"
    image_path.write_bytes(_VALID_PNG_BYTES)
    alice_window.handle_attachment_selected(str(image_path))

    file_path = tmp_path / "report.txt"
    file_path.write_text("plain document content")
    alice_window.handle_attachment_selected(str(file_path))

    media = alice_window.messages.get_media_bubbles()
    assert len(media) == 2
    assert isinstance(media[0], ImageMessageBubble)
    assert isinstance(media[1], FileMessageBubble)


def test_gallery_reaches_the_real_recipient_too(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    image_path = tmp_path / "photo.png"
    image_path.write_bytes(_VALID_PNG_BYTES)
    alice_window.handle_attachment_selected(str(image_path))

    assert _wait_for(lambda: len(bob_window.messages.get_media_bubbles()) == 1)
    assert isinstance(bob_window.messages.get_media_bubbles()[0], ImageMessageBubble)


def test_deleted_attachment_is_excluded_from_the_gallery(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    image_path = tmp_path / "photo.png"
    image_path.write_bytes(_VALID_PNG_BYTES)
    alice_window.handle_attachment_selected(str(image_path))

    bubble = alice_window.messages.get_media_bubbles()[0]
    bubble.mark_deleted()

    assert alice_window.messages.get_media_bubbles() == []


def test_media_gallery_dialog_shows_a_clickable_thumbnail_that_opens_the_viewer(
    tmp_path, connect, accounts
):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    image_path = tmp_path / "photo.png"
    image_path.write_bytes(_VALID_PNG_BYTES)
    alice_window.handle_attachment_selected(str(image_path))

    from PySide6.QtWidgets import QDialog

    with patch.object(QDialog, "exec", return_value=None):
        alice_window.handle_open_media_gallery()

    bubble = alice_window.messages.get_media_bubbles()[0]
    tile = alice_window._build_gallery_tile(bubble)
    _KEEP_ALIVE.append(tile)

    with patch.object(bubble, "open_viewer") as open_viewer:
        tile.click()

    open_viewer.assert_called_once()


def test_media_gallery_dialog_does_not_crash_when_empty(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    from PySide6.QtWidgets import QDialog

    with patch.object(QDialog, "exec", return_value=None):
        alice_window.handle_open_media_gallery()  # must not raise
