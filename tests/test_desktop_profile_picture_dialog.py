"""
Desktop profile picture: choose a file, crop it, upload it.

Runs the real ProfilePictureDialog, the real ImageCropDialog canvas and the
real server with two real ClientSessions. Only the two things a headless run
cannot do are stubbed: the operating-system file picker, and the modal
``exec()`` of the crop dialog (it is made to press its own Save button, so the
crop result is produced by the real canvas).
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtGui import QColor, QImage
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QPushButton

from gui.image_crop_dialog import OUTPUT_SIZE, ImageCropDialog
from gui.profile_picture_dialog import ProfilePictureDialog
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _KEEP_ALIVE,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])


def _image_file(tmp_path, width, height, name="source.png"):
    image = QImage(width, height, QImage.Format_RGB32)
    image.fill(QColor("#3D6291"))
    path = tmp_path / name
    assert image.save(str(path), "PNG")
    return str(path)


def _decode(png_bytes):
    image = QImage()
    assert image.loadFromData(png_bytes)
    return image


@pytest.fixture()
def pick(monkeypatch):
    """Make the OS file picker return a chosen path (or cancel with "")."""

    def _pick(path):
        monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (path, "")))

    return _pick


@pytest.fixture()
def crop_accepts(monkeypatch):
    """The crop dialog "opens", the user presses Save, the real canvas crops."""

    def _exec(self):
        self._handle_save()
        return QDialog.Accepted

    monkeypatch.setattr(ImageCropDialog, "exec", _exec)


def _dialog(session):
    dialog = ProfilePictureDialog(session)
    _KEEP_ALIVE.append(dialog)
    return dialog


def test_choosing_and_cropping_a_picture_uploads_a_square_png_other_users_can_fetch(
    tmp_path, connect, accounts, pick, crop_accepts
):
    alice_payload, bob_payload = accounts("alice_"), accounts("bob_")
    alice, bob = connect(alice_payload), connect(bob_payload)
    dialog = _dialog(alice)
    assert dialog.preview_label.text() == "No picture set"

    pick(_image_file(tmp_path, 640, 360))  # deliberately NOT square
    dialog._handle_change()

    stored = bob.fetch_profile_picture(alice_payload["username"])
    assert stored is not None
    image = _decode(stored)
    assert image.width() == image.height() == OUTPUT_SIZE  # the crop made it square
    assert dialog.status_label.text() == ""
    assert dialog.preview_label.pixmap() is not None and not dialog.preview_label.pixmap().isNull()
    # What the dialog shows is what was stored.
    assert alice.fetch_profile_picture(alice_payload["username"]) == stored


def test_cancelling_the_file_picker_changes_nothing(tmp_path, connect, accounts, pick, crop_accepts):
    payload = accounts("alice_")
    alice = connect(payload)
    dialog = _dialog(alice)

    pick("")
    dialog._handle_change()

    assert alice.fetch_profile_picture(payload["username"]) is None
    assert dialog.preview_label.text() == "No picture set"


def test_cancelling_the_crop_uploads_nothing(tmp_path, connect, accounts, pick, monkeypatch):
    payload = accounts("alice_")
    alice = connect(payload)
    dialog = _dialog(alice)
    monkeypatch.setattr(ImageCropDialog, "exec", lambda self: QDialog.Rejected)

    pick(_image_file(tmp_path, 300, 300))
    dialog._handle_change()

    assert alice.fetch_profile_picture(payload["username"]) is None
    assert dialog.preview_label.text() == "No picture set"


def test_an_unreadable_file_is_reported_and_nothing_is_uploaded(tmp_path, connect, accounts, pick, crop_accepts):
    payload = accounts("alice_")
    alice = connect(payload)
    dialog = _dialog(alice)
    not_an_image = tmp_path / "notes.png"
    not_an_image.write_bytes(b"this is not an image")

    pick(str(not_an_image))
    dialog._handle_change()

    assert dialog.status_label.text() == "Could not read this image file."
    assert alice.fetch_profile_picture(payload["username"]) is None


def test_a_server_refusal_is_shown_and_the_old_picture_stays(tmp_path, connect, accounts, pick, crop_accepts, monkeypatch):
    payload = accounts("alice_")
    alice = connect(payload)
    dialog = _dialog(alice)
    pick(_image_file(tmp_path, 200, 200, "first.png"))
    dialog._handle_change()
    first = alice.fetch_profile_picture(payload["username"])
    assert first is not None

    monkeypatch.setattr(
        alice, "upload_profile_picture",
        lambda *a, **k: {"success": False, "error": "Image must be under 2 MB."},
    )
    other = QImage(200, 200, QImage.Format_RGB32)
    other.fill(QColor("#8A593B"))
    second_path = tmp_path / "second.png"
    other.save(str(second_path), "PNG")
    pick(str(second_path))
    dialog._handle_change()

    assert dialog.status_label.text() == "Image must be under 2 MB."
    assert alice.fetch_profile_picture(payload["username"]) == first


def test_a_peers_picture_dialog_offers_no_change_button(tmp_path, connect, accounts, pick, crop_accepts):
    alice_payload, bob_payload = accounts("alice_"), accounts("bob_")
    alice, bob = connect(alice_payload), connect(bob_payload)
    pick(_image_file(tmp_path, 200, 200))
    _dialog(alice)._handle_change()

    viewer = ProfilePictureDialog(bob, target_username=alice_payload["username"])
    _KEEP_ALIVE.append(viewer)

    assert not viewer.is_own
    assert "Change" not in [b.text() for b in viewer.findChildren(QPushButton)]
    assert viewer.preview_label.pixmap() is not None and not viewer.preview_label.pixmap().isNull()
