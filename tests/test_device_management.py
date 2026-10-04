"""
Phase 19.19 -- Desktop Device Management UI.

Drives the REAL gui/device_management_dialog.py::DeviceManagementDialog
against a REAL server and REAL ClientSession instances -- constructing
the dialog itself (not clicking through a mocked one) is what exercises
its lazy self-enrollment (__init__ -> _ensure_this_device_enrolled())
and its action handlers (_handle_authorize()/_handle_revoke()), which
are themselves nothing more than thin wrappers around ClientSession.
enroll_device()/list_devices()/authorize_device()/revoke_device() --
already-tested (tests/test_device_identity.py), unmodified methods.

Run with:
    pytest tests/test_device_management.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from client.session import ClientSession
from gui.device_management_dialog import DeviceManagementDialog
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


def test_device_management_dialog_enrolls_this_device_on_first_open(running_server, monkeypatch, tmp_path):
    """Desktop never called enroll_device() anywhere before this
    phase -- opening the dialog for a session that has never enrolled
    is what activates it, as the account's bootstrap (first-ever,
    auto-AUTHORIZED) device."""

    payload = _register("dm_solo_")
    session = _new_device_session(running_server, monkeypatch, payload, tmp_path / "solo")
    try:
        assert session.device_id is None

        dialog = DeviceManagementDialog(session)
        try:
            assert session.device_id is not None

            devices = session.list_devices()
            assert len(devices) == 1
            assert devices[0]["device_id"] == session.device_id
            assert devices[0]["state"] == "AUTHORIZED"

            # The dialog's own rendered rows agree with the session's
            # own authoritative list -- not a separate, divergent view.
            assert dialog._device_list.count() == 1
        finally:
            dialog.close()
    finally:
        session.disconnect()
        _delete(payload["username"])


def test_device_management_dialog_authorizes_pending_device(running_server, monkeypatch, tmp_path):
    """Two devices of the same account: the first (bootstrap-
    AUTHORIZED) device's dialog sees the second (PENDING) device and
    can authorize it -- the same server-authoritative check
    tests/test_device_identity.py already proves, exercised here
    through the actual dialog action handler."""

    payload = _register("dm_auth_")
    first = _new_device_session(running_server, monkeypatch, payload, tmp_path / "first")
    second = _new_device_session(running_server, monkeypatch, payload, tmp_path / "second")
    try:
        first_dialog = DeviceManagementDialog(first)
        second_dialog = DeviceManagementDialog(second)
        try:
            assert first.device_id is not None
            assert second.device_id is not None

            first_dialog._refresh()
            devices = first.list_devices()
            pending = next(d for d in devices if d["device_id"] == second.device_id)
            assert pending["state"] == "PENDING"

            first_dialog._handle_authorize(pending)

            assert "Authorized" in first_dialog._status_label.text()

            refreshed = first.list_devices()
            second_row = next(d for d in refreshed if d["device_id"] == second.device_id)
            assert second_row["state"] == "AUTHORIZED"
        finally:
            first_dialog.close()
            second_dialog.close()
    finally:
        first.disconnect()
        second.disconnect()
        _delete(payload["username"])


def test_device_management_dialog_revokes_authorized_device(running_server, monkeypatch, tmp_path):
    """An AUTHORIZED device can be revoked through the dialog's own
    Revoke action -- and a non-admin/non-authorized viewer never even
    sees the button in the first place (own_state gating in
    _refresh()), though the server would reject the call regardless."""

    payload = _register("dm_revoke_")
    first = _new_device_session(running_server, monkeypatch, payload, tmp_path / "first")
    second = _new_device_session(running_server, monkeypatch, payload, tmp_path / "second")
    try:
        first_dialog = DeviceManagementDialog(first)
        DeviceManagementDialog(second)  # second self-enrolls as PENDING; not otherwise used here

        devices = first.list_devices()
        pending = next(d for d in devices if d["device_id"] == second.device_id)
        first_dialog._handle_authorize(pending)

        authorized_row = next(d for d in first.list_devices() if d["device_id"] == second.device_id)
        assert authorized_row["state"] == "AUTHORIZED"

        first_dialog._handle_revoke(authorized_row)
        assert "Revoked" in first_dialog._status_label.text()

        revoked_row = next(d for d in first.list_devices() if d["device_id"] == second.device_id)
        assert revoked_row["state"] == "REVOKED"
    finally:
        first.disconnect()
        second.disconnect()
        _delete(payload["username"])


def test_device_management_dialog_hides_actions_for_unauthorized_viewer(running_server, monkeypatch, tmp_path):
    """A PENDING device's own dialog (not yet authorized by anyone)
    must not offer Authorize/Revoke buttons at all -- the server would
    reject the call anyway, but the UI should not invite an action that
    can only ever fail (mandate Section 5: "clear success/error
    messages", not a button that is silently doomed)."""

    payload = _register("dm_gate_")
    first = _new_device_session(running_server, monkeypatch, payload, tmp_path / "first")
    second = _new_device_session(running_server, monkeypatch, payload, tmp_path / "second")
    try:
        DeviceManagementDialog(first)  # bootstrap-AUTHORIZED
        second_dialog = DeviceManagementDialog(second)  # PENDING -- not yet authorized by anyone

        assert second_dialog._device_list.count() == 2

        # This session's own device_id is PENDING, so
        # viewer_is_authorized is False for the whole render pass --
        # no row (including its own) should offer an action button.
        from PySide6.QtWidgets import QPushButton
        buttons = second_dialog._device_list.findChildren(QPushButton)
        assert len(buttons) == 0
    finally:
        first.disconnect()
        second.disconnect()
        _delete(payload["username"])
