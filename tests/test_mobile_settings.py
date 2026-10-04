"""
Settings (Phase 19.14) -- change_username, change_password, profile
picture upload/fetch.

Proves, against a real TLS test server and a real MobileClientSession
(the same established pattern as test_group_admin_and_inbox.py /
test_verify_late_key_recovery.py), that these three account-mutation
endpoints:

- Actually round-trip through the real server/database, not a local
  UI-only flag (change_username/change_password persist and can be
  logged in with afterward; a wrong current password is rejected
  server-side, not client-side).
- Enforce the same password policy and username-collision rules the
  rest of the codebase already relies on (AuthenticationService),
  never a second, weaker rule.
- Never fake a profile picture locally: upload is a real store_blob()
  write, and fetch returns the byte-exact original, with `found=False`
  returned identically for "no such user" and "user has no picture"
  (see handle_profile_picture_request()'s own docstring on why).

Run with:
    pytest tests/test_mobile_settings.py -v
"""

import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

import mobile.session as mobile_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from database.connection import SessionLocal
from mobile.session import MobileClientSession
from tests.tls_test_support import start_test_server

PASSWORD = "Str0ng!Passw0rd"


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Settings Test", "username": f"settings_{hint}{suffix}",
            "email": f"settings_{hint}{suffix}@example.com", "password": PASSWORD,
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
    monkeypatch.setattr(mobile_session_module, "SERVER_PORT", port)

    payload = _register(hint)
    session = MobileClientSession(storage_dir=str(tmp_path / hint))
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


def test_change_username_success_and_relogin(running_server, monkeypatch, tmp_path):
    session, payload = _new_session(running_server, monkeypatch, "u1", tmp_path)
    new_username = f"renamed_{uuid.uuid4().hex[:10]}"

    response = session.change_username(new_username)

    assert response["success"], response
    assert session.username == new_username

    # A fresh session, logging in with the SAME phone/password used at
    # registration, must see the rename reflected server-side (not
    # merely echoed back on this one connection).
    relogin = MobileClientSession(storage_dir=str(tmp_path / "u1_relogin"))
    result = relogin.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    assert result.username == new_username


def test_change_username_rejects_collision(running_server, monkeypatch, tmp_path):
    session_a, _ = _new_session(running_server, monkeypatch, "collide_a", tmp_path)
    session_b, payload_b = _new_session(running_server, monkeypatch, "collide_b", tmp_path)

    response = session_a.change_username(payload_b["username"])

    assert not response["success"]
    assert response["error"]


def test_change_password_success_and_wrong_current_rejected(running_server, monkeypatch, tmp_path):
    session, payload = _new_session(running_server, monkeypatch, "p1", tmp_path)
    new_password = "N3w!StrongerPassw0rd"

    bad = session.change_password("definitely-not-the-current-password", new_password, new_password)
    assert not bad["success"]
    assert bad["error"]

    ok = session.change_password(PASSWORD, new_password, new_password)
    assert ok["success"], ok

    # The OLD password must no longer work, and the NEW one must,
    # proving this was a real server-side hash change, not a
    # client-local flag.
    stale = MobileClientSession(storage_dir=str(tmp_path / "p1_stale"))
    stale_result = stale.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert not stale_result.success

    fresh = MobileClientSession(storage_dir=str(tmp_path / "p1_fresh"))
    fresh_result = fresh.authenticate_credentials(payload["phone_number"], new_password)
    assert fresh_result.success, fresh_result.message


def test_change_password_rejects_policy_violation(running_server, monkeypatch, tmp_path):
    session, _ = _new_session(running_server, monkeypatch, "p2", tmp_path)

    response = session.change_password(PASSWORD, "short", "short")

    assert not response["success"]
    assert response["error"]


def test_profile_picture_upload_fetch_roundtrip_and_privacy(running_server, monkeypatch, tmp_path):
    uploader, payload = _new_session(running_server, monkeypatch, "pic1", tmp_path)
    viewer, _ = _new_session(running_server, monkeypatch, "pic2", tmp_path)

    # No picture set yet -- must report found=False, not raise or
    # return placeholder bytes.
    assert viewer.fetch_profile_picture(payload["username"]) is None

    image_bytes = b"\x89PNG\r\n\x1a\n" + os.urandom(256)
    upload_response = uploader.upload_profile_picture(image_bytes, content_type="image/png")
    assert upload_response["success"], upload_response

    fetched = viewer.fetch_profile_picture(payload["username"])
    assert fetched == image_bytes

    # Nonexistent user and "no picture set" are indistinguishable by
    # design (enumeration hardening) -- both must come back as None.
    assert viewer.fetch_profile_picture(f"no-such-user-{uuid.uuid4().hex}") is None


def test_bio_round_trip(running_server, monkeypatch, tmp_path):
    """Phase 19.22 -- Part F: User.bio has existed on the model since
    the initial migration but had no wire format/handler/client method
    at all until now. Mirrors test_desktop_bio_round_trip() exactly --
    proves a real server round trip, not a client-local value."""

    session, payload = _new_session(running_server, monkeypatch, "bio1", tmp_path)
    viewer, _ = _new_session(running_server, monkeypatch, "bio_viewer", tmp_path)

    assert session.fetch_bio(payload["username"]) == ""

    response = session.change_bio("Quantum-safe and proud of it.")
    assert response["success"], response

    assert session.fetch_bio(payload["username"]) == "Quantum-safe and proud of it."
    # A real server-persisted value, not a client-local one: a
    # completely separate account, which never called change_bio()
    # itself, independently fetches the same value by username.
    assert viewer.fetch_bio(payload["username"]) == "Quantum-safe and proud of it."


def test_bio_rejects_over_length(running_server, monkeypatch, tmp_path):
    session, _ = _new_session(running_server, monkeypatch, "bio2", tmp_path)

    response = session.change_bio("x" * 257)

    assert not response["success"]
    assert response["error"]


def test_bio_fetch_for_unknown_user_is_not_found(running_server, monkeypatch, tmp_path):
    session, _ = _new_session(running_server, monkeypatch, "bio3", tmp_path)

    assert session.fetch_bio(f"no-such-user-{uuid.uuid4().hex}") == ""
