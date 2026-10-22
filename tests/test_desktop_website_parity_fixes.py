"""
Desktop, matched to the Website after the owner's manual acceptance (2026-10-22):

* the chat header's gear opens a dropdown menu with the Website's entries, in the Website's order;
* the media gallery is the Website's card (title + close, "Photos & videos", "Voice messages &
  files" rows that jump to the message);
* file and voice cards: the file tile with its type, name over size, round download button; the
  voice card titled "Voice message" with a rounded player pill, volume and mute;
* the picture editor: the circle that people will see, the Website's wording, keyboard control,
  the Website's file checks (type, size, dimensions) before the editor opens.

Real windows, real server, real sessions (the same fixtures as the other Desktop chat tests).
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor, QImage, QKeyEvent
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QMenu, QPushButton, QToolButton

from domain.payload_type import PayloadType
from gui.image_crop_dialog import ImageCropDialog
from gui.message_widget import FileMessageBubble
from gui.profile_picture_dialog import check_picture_file
from tests.image_fixtures import solid_png
from tests.test_desktop_chat_settings import _group_windows, pair  # noqa: F401 -- fixture and helper reused
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _KEEP_ALIVE,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])


def _entries(menu):
    """Top-level entries as text ("" for a separator), submenus included by title."""
    return [("" if a.isSeparator() else a.text()) for a in menu.actions()]


# ------------------------------------------------------------------ the Chat settings menu


def test_a_direct_chats_settings_menu_has_the_websites_entries_in_its_order(pair):
    alice_window, *_ = pair
    key = alice_window.session.get_current_chat()

    menu = alice_window._build_chat_settings_menu(key)
    _KEEP_ALIVE.append(menu)

    assert _entries(menu) == [
        "Contact info", "Search in conversation", "Pinned messages", "Media gallery", "Chat wallpaper",
        "", "Mute or archive…",
    ]
    manage = next(a for a in menu.actions() if a.text() == "Mute or archive…").menu()
    texts = _entries(manage)
    assert "Archive chat" in texts and "Block" in texts
    assert any(t.startswith("Mute for") for t in texts)
    assert "Leave group" not in _entries(menu)


def test_a_groups_settings_menu_has_group_details_and_leave_but_no_block(pair):
    alice_window, *_ = _group_windows(pair)
    key = alice_window.session.get_current_chat()

    menu = alice_window._build_chat_settings_menu(key)
    _KEEP_ALIVE.append(menu)

    entries = _entries(menu)
    assert entries[0] == "Group details"
    assert entries[-1] == "Leave group"
    manage = next(a for a in menu.actions() if a.text() == "Mute or archive…").menu()
    assert "Block" not in _entries(manage)


def test_every_menu_entry_runs_the_existing_handler(pair, monkeypatch):
    alice_window, *_ = pair
    called = []
    for name in (
        "handle_open_chat_details", "handle_toggle_search_bar", "handle_open_pinned_messages_panel",
        "handle_open_media_gallery", "handle_open_wallpaper_picker",
    ):
        monkeypatch.setattr(alice_window, name, lambda n=name: called.append(n))
    menu = alice_window._build_chat_settings_menu(alice_window.session.get_current_chat())
    _KEEP_ALIVE.append(menu)

    for action in menu.actions():
        if action.text() in ("Contact info", "Search in conversation", "Pinned messages", "Media gallery", "Chat wallpaper"):
            action.trigger()

    assert called == [
        "handle_open_chat_details", "handle_toggle_search_bar", "handle_open_pinned_messages_panel",
        "handle_open_media_gallery", "handle_open_wallpaper_picker",
    ]


def test_the_gear_opens_the_dropdown_not_a_window(pair, monkeypatch):
    alice_window, *_ = pair
    shown = []
    real_build = alice_window._build_chat_settings_menu

    class _Shown:
        """Stands in for the menu only at the moment it would block on screen."""

        def __init__(self, menu):
            self.menu = menu

        def exec(self, position):
            shown.append((self.menu.objectName(), position))

    monkeypatch.setattr(alice_window, "_build_chat_settings_menu", lambda key: _Shown(real_build(key)))

    alice_window.chat_settings_button.click()

    assert [name for name, _position in shown] == ["ChatSettingsMenu"]


# ------------------------------------------------------------------ the media gallery


def _open_gallery(window, monkeypatch):
    captured = {}

    def fake_exec(self):
        captured["dialog"] = self
        _KEEP_ALIVE.append(self)
        return QDialog.Rejected

    monkeypatch.setattr(QDialog, "exec", fake_exec)
    window.handle_open_media_gallery()
    return captured["dialog"]


def test_the_gallery_is_the_websites_card_and_a_row_jumps_to_its_message(pair, monkeypatch, tmp_path):
    alice_window, *_ = pair
    document = tmp_path / "report.pdf"
    document.write_bytes(b"%PDF-1.7 " + b"x" * 200)
    alice_window.handle_attachment_selected(str(document))
    assert _wait_for(lambda: len(alice_window.messages.get_media_bubbles()) == 1)

    dialog = _open_gallery(alice_window, monkeypatch)

    assert dialog.objectName() == "MediaGalleryDialog"
    headings = [l.text() for l in dialog.findChildren(QLabel) if l.objectName() == "GalleryHeading"]
    assert headings == ["VOICE MESSAGES & FILES"]
    assert any(l.text() == "Media Gallery" for l in dialog.findChildren(QLabel))
    assert dialog.findChild(QToolButton).accessibleName() == "Close"
    rows = [b for b in dialog.findChildren(QPushButton) if b.objectName() == "GalleryFileRow"]
    assert [r.text() for r in rows] == ["report.pdf"]

    jumped = []
    monkeypatch.setattr(alice_window.messages, "scroll_to_bubble", lambda bubble: jumped.append(bubble))
    rows[0].click()
    assert jumped == [alice_window.messages.get_media_bubbles()[0]]


def test_an_empty_gallery_says_so(pair, monkeypatch):
    alice_window, *_ = pair

    dialog = _open_gallery(alice_window, monkeypatch)

    assert any(l.text() == "No media in this conversation yet." for l in dialog.findChildren(QLabel))


# ------------------------------------------------------------------ file and voice cards


def _bubble(kind="received", payload_type=None, name="7th Sem - COE (2026-27).pdf", size=919_000, mime="application/pdf",
            data=None, duration=None):
    metadata = {"filename": name, "size_bytes": size, "mime_type": mime}
    if duration:
        metadata["duration_seconds"] = duration
    bubble = FileMessageBubble(data if data is not None else b"x" * 64, metadata, kind, sender="Ramya", payload_type=payload_type)
    _KEEP_ALIVE.append(bubble)
    return bubble


def test_a_file_card_has_a_type_tile_name_over_size_and_a_round_download_button():
    bubble = _bubble()

    assert bubble._extension_label.text() == "PDF"
    assert bubble._title_label.text() == "7th Sem - COE (2026-27).pdf"
    assert bubble._size_label.text() and not bubble._size_label.isHidden()
    button = bubble._save_button
    assert isinstance(button, QToolButton) and button.objectName() == "FileDownloadButton"
    assert button.accessibleName() == "Save 7th Sem - COE (2026-27).pdf"
    assert button in bubble._action_buttons


def test_the_download_button_still_saves_the_files_bytes(tmp_path, monkeypatch):
    bubble = _bubble(data=b"%PDF-1.7 content", name="doc.pdf")
    target = tmp_path / "saved.pdf"
    monkeypatch.setattr(
        "gui.message_widget.QFileDialog.getSaveFileName", staticmethod(lambda *a, **k: (str(target), ""))
    )

    bubble._save_button.click()

    assert target.read_bytes() == b"%PDF-1.7 content"


def test_a_voice_card_is_titled_voice_message_with_a_player_pill_and_no_size_line():
    bubble = _bubble(payload_type=PayloadType.VOICE, name="voice-message.m4a", mime="audio/mp4", duration=75)

    assert bubble._title_label.text() == "Voice message"
    assert bubble._size_label.isHidden()
    assert bubble._icon_label.isHidden()
    assert bubble._media_pill.objectName() == "MediaPill"
    assert bubble._voice_duration_label.text() == "1:15"
    assert bubble._media_card.volume_button.accessibleName() == "Mute"


def test_the_volume_controls_change_what_the_player_outputs():
    bubble = _bubble(payload_type=PayloadType.VOICE, name="v.m4a", mime="audio/mp4", duration=3)
    card = bubble._media_card
    card._ensure_player()

    card.volume_slider.setValue(40)
    assert card._audio_output.volume() == pytest.approx(0.4, abs=0.01)
    card.toggle_mute()
    assert card._audio_output.isMuted() and card.volume_button.accessibleName() == "Unmute"
    card.toggle_mute()
    assert not card._audio_output.isMuted()


# ------------------------------------------------------------------ the picture editor


def _pixmap(width=400, height=300, color="#2E7D32"):
    image = QImage(width, height, QImage.Format_RGB32)
    image.fill(QColor(color))
    from PySide6.QtGui import QPixmap

    return QPixmap.fromImage(image)


def test_the_editor_uses_the_websites_wording_and_shows_the_circle():
    dialog = ImageCropDialog(_pixmap())
    _KEEP_ALIVE.append(dialog)

    texts = [l.text() for l in dialog.findChildren(QLabel)]
    assert "Adjust your picture" in texts
    assert "Drag to position it, and use the slider to zoom. The circle is what people will see." in texts
    assert [b.text() for b in dialog.findChildren(QPushButton)] == ["Cancel", "Save picture"]

    # The preview is dimmed outside the circle: a corner is darker than the centre.
    preview = dialog.canvas.grab().toImage()
    centre, corner = preview.pixelColor(140, 140), preview.pixelColor(3, 3)
    assert corner.lightness() < centre.lightness() - 20


def test_the_saved_picture_is_the_clean_square_not_the_dimmed_preview():
    dialog = ImageCropDialog(_pixmap())
    _KEEP_ALIVE.append(dialog)

    dialog._handle_save()
    result = dialog.get_result().toImage()

    for x, y in ((0, 0), (result.width() - 1, result.height() - 1), (result.width() // 2, result.height() // 2)):
        pixel = result.pixelColor(x, y)
        assert (pixel.red(), pixel.green(), pixel.blue()) == (0x2E, 0x7D, 0x32)


def test_the_editor_is_keyboard_operable():
    dialog = ImageCropDialog(_pixmap(800, 400))
    _KEEP_ALIVE.append(dialog)
    canvas = dialog.canvas
    zoom_before = dialog.zoom_slider.value()

    canvas.keyPressEvent(QKeyEvent(QEvent.KeyPress, Qt.Key_Plus, Qt.NoModifier))
    assert dialog.zoom_slider.value() > zoom_before

    start = canvas.offset.x()
    canvas.keyPressEvent(QKeyEvent(QEvent.KeyPress, Qt.Key_Right, Qt.NoModifier))
    assert canvas.offset.x() > start
    assert canvas.focusPolicy() == Qt.StrongFocus


def _write(tmp_path, name, width, height, fmt="PNG"):
    image = QImage(width, height, QImage.Format_RGB32)
    image.fill(QColor("#3D6291"))
    path = tmp_path / name
    assert image.save(str(path), fmt)
    return str(path)


def test_picture_files_are_checked_like_the_website_checks_them(tmp_path):
    assert check_picture_file(_write(tmp_path, "ok.png", 300, 200)) is None
    assert check_picture_file(_write(tmp_path, "tiny.png", 40, 40)) == "That image is too small. Use one at least 64 × 64 pixels."
    assert check_picture_file(_write(tmp_path, "wide.png", 9000, 70)) == (
        "That image is too large. Use one no bigger than 8192 × 8192 pixels."
    )
    assert check_picture_file(_write(tmp_path, "pic.bmp", 100, 100, "BMP")) == "Choose a PNG, JPEG, WebP or GIF image."

    # A document is refused with the Website's wording for a wrong type.
    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(b"%PDF-1.7 not an image")
    assert check_picture_file(str(pdf)) == "Choose a PNG, JPEG, WebP or GIF image."
    # Something that is not an image at all, whatever it is called, is never opened by the editor.
    not_an_image = tmp_path / "notes"
    not_an_image.write_bytes(b"this is not an image")
    assert check_picture_file(str(not_an_image)) == "Could not read this image file."

    huge = tmp_path / "huge.png"
    huge.write_bytes(solid_png(64, 64) + b"\x00" * (10 * 1024 * 1024 + 1))
    assert check_picture_file(str(huge)).startswith("That image is too large (")
    assert check_picture_file(str(tmp_path / "missing.png")) == "Could not read this image file."
