"""
Desktop Settings (Phase 19.18 -- L-5/Desktop-parity closure):
change_username, change_password.

Mirrors tests/test_mobile_settings.py exactly (same real-server, real-
ClientSession pattern), proving Desktop's newly-added
ClientSession.change_username()/change_password() round-trip through
the SAME already-existing, already-tested server-side handlers Mobile
already used -- not a second, weaker implementation.

Run with:
    pytest tests/test_desktop_settings.py -v
"""

import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Desktop Settings Test", "username": f"dsettings_{hint}{suffix}",
            "email": f"dsettings_{hint}{suffix}@example.com", "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        return payload
    finally:
        db.close()


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


def _new_session(running_server, monkeypatch, hint, tmp_path):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", tmp_path / hint / "keystore")

    payload = _register(hint)
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
    return session, payload


def test_desktop_change_username_success_and_relogin(running_server, monkeypatch, tmp_path):
    session, payload = _new_session(running_server, monkeypatch, "u1", tmp_path)
    new_username = f"renamed_{uuid.uuid4().hex[:10]}"
    try:
        response = session.change_username(new_username)
        assert response["success"], response
        assert session.username == new_username

        relogin = ClientSession()
        result = relogin.authenticate_credentials(payload["phone_number"], PASSWORD)
        assert result.success, result.message
        assert result.username == new_username
    finally:
        session.disconnect()


def test_desktop_change_username_rejects_collision(running_server, monkeypatch, tmp_path):
    session_a, _ = _new_session(running_server, monkeypatch, "collide_a", tmp_path)
    session_b, payload_b = _new_session(running_server, monkeypatch, "collide_b", tmp_path)
    try:
        response = session_a.change_username(payload_b["username"])
        assert not response["success"]
        assert response["error"]
    finally:
        session_a.disconnect()
        session_b.disconnect()


def test_desktop_change_password_success_and_wrong_current_rejected(running_server, monkeypatch, tmp_path):
    session, payload = _new_session(running_server, monkeypatch, "p1", tmp_path)
    new_password = "N3w!StrongerPassw0rd"
    try:
        bad = session.change_password("definitely-not-the-current-password", new_password, new_password)
        assert not bad["success"]
        assert bad["error"]

        ok = session.change_password(PASSWORD, new_password, new_password)
        assert ok["success"], ok

        # The OLD password must no longer work, and the NEW one must --
        # a real server-side hash change, not a client-local flag.
        stale = ClientSession()
        stale_result = stale.authenticate_credentials(payload["phone_number"], PASSWORD)
        assert not stale_result.success

        fresh = ClientSession()
        fresh_result = fresh.authenticate_credentials(payload["phone_number"], new_password)
        assert fresh_result.success, fresh_result.message
    finally:
        session.disconnect()


def test_desktop_change_password_rejects_policy_violation(running_server, monkeypatch, tmp_path):
    session, _ = _new_session(running_server, monkeypatch, "p2", tmp_path)
    try:
        response = session.change_password(PASSWORD, "short", "short")
        assert not response["success"]
        assert response["error"]
    finally:
        session.disconnect()


def test_desktop_bio_round_trip(running_server, monkeypatch, tmp_path):
    """
    Phase 19.22 -- Settings: User.bio has existed on the model since
    the initial migration but had no wire format/handler/client method
    at all until now. Proves a real server round trip persists it (not
    a client-local value), and that a peer can fetch it by username.
    """

    session, payload = _new_session(running_server, monkeypatch, "bio1", tmp_path)
    viewer, _ = _new_session(running_server, monkeypatch, "bio_viewer", tmp_path)
    try:
        assert session.fetch_bio(payload["username"]) == ""

        response = session.change_bio("Quantum-safe and proud of it.")
        assert response["success"], response

        assert session.fetch_bio(payload["username"]) == "Quantum-safe and proud of it."
        # A real server-persisted value, not a client-local one: a
        # COMPLETELY SEPARATE account, which never called change_bio()
        # itself, independently fetches the same value by username.
        assert viewer.fetch_bio(payload["username"]) == "Quantum-safe and proud of it."
    finally:
        session.disconnect()
        viewer.disconnect()


def test_desktop_bio_rejects_over_length(running_server, monkeypatch, tmp_path):
    session, _ = _new_session(running_server, monkeypatch, "bio2", tmp_path)
    try:
        response = session.change_bio("x" * 257)
        assert not response["success"]
        assert response["error"]
    finally:
        session.disconnect()


def test_desktop_bio_fetch_for_unknown_user_is_not_found(running_server, monkeypatch, tmp_path):
    session, _ = _new_session(running_server, monkeypatch, "bio3", tmp_path)
    try:
        assert session.fetch_bio("no_such_user_at_all_12345") == ""
    finally:
        session.disconnect()
