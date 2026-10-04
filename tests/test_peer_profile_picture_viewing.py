"""
Phase 19.19 -- Desktop peer profile-picture viewing.

ClientSession.fetch_profile_picture(username) already accepted an
arbitrary target; gui/profile_picture_dialog.py::ProfilePictureDialog
never called it for anyone but the account's own username. Drives the
REAL dialog (constructed directly, not clicked-through) against a REAL
server and two REAL ClientSession accounts.

Run with:
    pytest tests/test_peer_profile_picture_viewing.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtGui import QColor, QImage
from PySide6.QtWidgets import QApplication, QPushButton

import client.session as client_session_module
from client.session import ClientSession
from gui.profile_picture_dialog import ProfilePictureDialog
from tests.test_device_identity import PASSWORD, _delete, _register  # noqa: F401 -- reused, not re-implemented
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


def _new_device_session(running_server, monkeypatch, payload, key_store_dir):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", key_store_dir)

    session = ClientSession()
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _real_png_bytes():
    """A genuinely decodable 8x8 PNG -- not just a magic-number prefix
    -- so this test proves the dialog actually rendered the peer's
    real picture, not merely that bytes moved."""

    image = QImage(8, 8, QImage.Format_RGB32)
    image.fill(QColor(120, 92, 242))
    from PySide6.QtCore import QBuffer, QIODevice

    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(buffer.data())


def test_view_peer_profile_picture_shows_real_uploaded_image(running_server, monkeypatch, tmp_path):
    alice_payload = _register("ppv_alice_")
    bob_payload = _register("ppv_bob_")
    alice = _new_device_session(running_server, monkeypatch, alice_payload, tmp_path / "alice")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    try:
        image_bytes = _real_png_bytes()
        upload_result = alice.upload_profile_picture(image_bytes, content_type="image/png")
        assert upload_result["success"], upload_result

        dialog = ProfilePictureDialog(bob, target_username=alice.username)
        try:
            assert dialog.is_own is False
            assert dialog.windowTitle() == f"{alice.username}'s Profile Picture"

            # Read-only: no Change button reachable at all for a peer
            # -- Close is the only button in the whole dialog.
            buttons = dialog.findChildren(QPushButton)
            assert len(buttons) == 1
            assert buttons[0].text() == "Close"

            # The real image was actually rendered, not just fetched.
            pixmap = dialog.preview_label.pixmap()
            assert pixmap is not None
            assert not pixmap.isNull()
        finally:
            dialog.close()
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_view_peer_profile_picture_gracefully_handles_no_picture_set(running_server, monkeypatch, tmp_path):
    alice_payload = _register("ppvnp_alice_")
    bob_payload = _register("ppvnp_bob_")
    alice = _new_device_session(running_server, monkeypatch, alice_payload, tmp_path / "alice")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    try:
        dialog = ProfilePictureDialog(bob, target_username=alice.username)
        try:
            assert dialog.preview_label.text() == "No picture set"
            assert dialog.status_label.text() == ""
        finally:
            dialog.close()
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_own_profile_picture_dialog_unaffected_by_target_username_addition(running_server, monkeypatch, tmp_path):
    """The pre-existing "my own picture, view + change" behavior must
    remain byte-for-byte unchanged -- omitting target_username entirely
    still resolves to the account's own username, and Change is still
    offered."""

    payload = _register("ppvown_")
    session = _new_device_session(running_server, monkeypatch, payload, tmp_path / "solo")
    try:
        dialog = ProfilePictureDialog(session)
        try:
            assert dialog.is_own is True
            assert dialog.windowTitle() == "Profile Picture"
            assert any(btn.text() == "Change" for btn in dialog.findChildren(QPushButton))
        finally:
            dialog.close()
    finally:
        session.disconnect()
        _delete(payload["username"])
