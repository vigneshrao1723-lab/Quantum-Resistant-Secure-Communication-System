"""
Tests for the login/logout migration (D2 -- Server-Side API /
Authentication Migration, final slice): gui/main_window.py and
client/client.py no longer talk to PostgreSQL directly through a local
AuthenticationService for either operation -- login now sends a
login_request and reads the response synchronously (see
client.session.ClientSession.authenticate_credentials() and
server/client_handler.py::handle_login_request()), and logout sends a
logout_request through D1's send_request() on the already-authenticated
connection (see ClientSession.logout() and handle_logout_request()).

Login is pre-authentication -- like register_request, it is handled
directly from authenticate_connection(), before any JWT exists, on a
connection that is always closed again afterward (see
authenticate_credentials()'s docstring for why this can't use D1's
send_request()). Logout runs on the existing authenticated connection,
so it uses the same authenticated request/response path
user_lookup_request/read_receipt already use.

The functional tests below exercise the real thing end to end: a
genuine ClientSession against a real running TLS server (the same
harness pattern every other integration suite in this codebase uses).
The protocol/security tests use a raw TLS-wrapped socket to prove the
server-side behavior -- including that session_id for logout is never
taken from the client -- independent of what the real client would
ever actually send.

Run with:
    pytest tests/test_login_logout_integration.py -v
"""

import json
import socket
import struct
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.network import send_message
from utils.protocol import create_auth_packet, create_public_key_packet


def _send(sock, message):
    data = json.dumps(message).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recvall(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _recv(sock, timeout=3):
    sock.settimeout(timeout)
    header = _recvall(sock, 4)
    if not header:
        return None
    length = struct.unpack("!I", header)[0]
    data = _recvall(sock, length)
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        return data.decode("utf-8")


def _recv_until(sock, predicate, attempts=40, per_attempt_timeout=0.3):
    """Read packets until one matches ``predicate``, skipping anything
    else (e.g. the user_list broadcast a public_key exchange triggers)
    -- mirrors tests/test_user_id_search.py's identical helper."""
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except (TimeoutError, OSError):
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


def _delete_user(username):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(username)
        if user is not None:
            for session in SessionRepository(db).get_active_sessions_for_user(user.id):
                db.delete(session)
            db.delete(user)
            db.commit()
    finally:
        db.close()


def _committed_user(suffix_hint=""):
    """A genuinely committed user, visible to the server's own DB
    connection."""
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Login Logout Test",
            "username": f"authll_{suffix_hint}{suffix}",
            "email": f"authll_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        return payload
    finally:
        db.close()


def _login_locally(payload):
    """Direct, local AuthenticationService login -- used only as test
    SETUP (to obtain a token/session_id to test *logout* against), the
    same convention test_user_id_search.py/test_server_auth_integration.py
    already use. Never used to test the login_request flow itself --
    that's exercised for real via ClientSession.authenticate_credentials()
    below."""
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        result = auth_service.authenticate_user(
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result
    finally:
        db.close()


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


def _raw_tls_connect(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    return wrap_client_socket(sock)


def _real_connected_session(port, payload, monkeypatch):
    """A genuine, fully-connected, fully-authenticated ClientSession --
    connect() (real TLS), login() (real JWT exchange), send_public_key()
    (required before the server's dispatch loop reads anything else),
    and start_receiver() (the real background thread). Required
    because ClientSession.logout() uses send_request(), which can only
    ever be resolved by a running receiver thread reading real socket
    data."""
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    session = ClientSession()
    session.user_id = payload["user_id"]
    session.username = payload["username"]
    session.session_id = payload["session_id"]
    session.access_token = payload["access_token"]

    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()

    return session


# ----------------------------------------------------------------------
# LOGIN -- functional: real ClientSession.authenticate_credentials(),
# real server, real round trip
# ----------------------------------------------------------------------


def test_login_valid_credentials_returns_success_and_tokens(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    user = _committed_user("valid_")

    session = ClientSession()
    try:
        result = session.authenticate_credentials(user["username"], user["password"])

        assert result.success is True
        assert result.errors is None
        assert result.user_id
        assert result.username == user["username"]
        assert result.session_id
        assert result.token_pair is not None
        assert result.token_pair.access_token
        assert result.token_pair.refresh_token
        assert result.token_pair.expires_in

        # Real PostgreSQL round trip: the session this produced is a
        # genuine, committed row the server's own DB connection sees.
        db = SessionLocal()
        try:
            db_session = SessionRepository(db).get_by_session_id(result.session_id)
            assert db_session is not None
            assert str(db_session.user_id) == result.user_id
            assert db_session.revoked is False
            assert db_session.is_active is True
        finally:
            db.close()
    finally:
        _delete_user(user["username"])


def test_login_invalid_password_is_rejected(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    user = _committed_user("badpw_")

    session = ClientSession()
    try:
        result = session.authenticate_credentials(user["username"], "WrongPassword!123")

        assert result.success is False
        assert result.errors and "password" in result.errors
        assert result.token_pair is None
    finally:
        _delete_user(user["username"])


def test_login_unknown_identifier_is_rejected(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    session = ClientSession()
    result = session.authenticate_credentials(f"no-such-user-{uuid.uuid4().hex[:8]}", "whatever")

    assert result.success is False
    assert result.errors and "identifier" in result.errors
    assert result.token_pair is None


def test_login_inactive_user_is_rejected(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    user = _committed_user("inactive_")

    db = SessionLocal()
    try:
        db_user = UserRepository(db).get_by_username(user["username"])
        db_user.is_active = False
        db.commit()
    finally:
        db.close()

    session = ClientSession()
    try:
        result = session.authenticate_credentials(user["username"], user["password"])

        assert result.success is False
        assert result.errors["status"] == "Account is inactive."
    finally:
        _delete_user(user["username"])


def test_login_locked_user_is_rejected(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    user = _committed_user("locked_")

    db = SessionLocal()
    try:
        db_user = UserRepository(db).get_by_username(user["username"])
        db_user.status = "locked"
        db.commit()
    finally:
        db.close()

    session = ClientSession()
    try:
        result = session.authenticate_credentials(user["username"], user["password"])

        assert result.success is False
        assert result.errors["status"] == "Account is locked."
    finally:
        _delete_user(user["username"])


def test_login_returned_token_authenticates_through_existing_server(running_server, monkeypatch):
    """The token authenticate_credentials() returns must be a genuine,
    usable JWT -- proven by opening a brand-new connection and sending
    it through the pre-existing, unmodified "auth" path."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    user = _committed_user("usable_")

    session = ClientSession()
    try:
        result = session.authenticate_credentials(user["username"], user["password"])
        assert result.success is True

        sock = _raw_tls_connect(port)
        try:
            _send(sock, create_auth_packet(result.token_pair.access_token))
            response = _recv(sock)

            assert response["type"] == "auth_result"
            assert response["success"] is True
            assert response["username"] == user["username"]
        finally:
            sock.close()
    finally:
        _delete_user(user["username"])


# ----------------------------------------------------------------------
# LOGIN -- protocol / security: raw TLS socket
# ----------------------------------------------------------------------


def test_login_request_requires_no_prior_authentication(running_server):
    _state, port = running_server
    user = _committed_user("rawlogin_")

    sock = _raw_tls_connect(port)
    try:
        packet = {
            "type": "login_request",
            "identifier": user["username"],
            "password": user["password"],
            "request_id": str(uuid.uuid4()),
        }
        _send(sock, packet)

        response = _recv(sock)

        assert response["type"] == "login_result"
        assert response["request_id"] == packet["request_id"]
        assert response["success"] is True
        assert response["access_token"]
        assert response["refresh_token"]
    finally:
        sock.close()
        _delete_user(user["username"])


def test_login_result_never_contains_password_hash_or_extra_fields(running_server):
    _state, port = running_server
    user = _committed_user("noleak_")

    sock = _raw_tls_connect(port)
    try:
        packet = {
            "type": "login_request",
            "identifier": user["username"],
            "password": user["password"],
            "request_id": str(uuid.uuid4()),
        }
        _send(sock, packet)

        response = _recv(sock)

        assert response["success"] is True
        assert set(response.keys()) == {
            "type", "request_id", "success", "message", "user_id", "username",
            "role", "session_id", "access_token", "refresh_token", "expires_in",
            "token_type", "errors",
        }
    finally:
        sock.close()
        _delete_user(user["username"])


def test_existing_auth_path_is_unaffected_by_the_new_login_branch(running_server):
    """Regression guard: adding the login_request branch to
    authenticate_connection() must not change the pre-existing "auth"
    packet behavior at all."""
    _state, port = running_server

    sock = _raw_tls_connect(port)
    try:
        _send(sock, create_auth_packet("not-a-real-token"))
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False
    finally:
        sock.close()


def test_unrecognized_first_packet_is_still_rejected_as_before(running_server):
    _state, port = running_server

    sock = _raw_tls_connect(port)
    try:
        _send(sock, {"type": "chat", "sender": "x", "receiver": "y", "message": "z"})
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False
    finally:
        sock.close()


def test_login_request_missing_request_id_is_silently_ignored(running_server):
    _state, port = running_server
    user = _committed_user("noid_")

    sock = _raw_tls_connect(port)
    try:
        packet = {
            "type": "login_request",
            "identifier": user["username"],
            "password": user["password"],
        }
        # Deliberately no request_id -- mirrors
        # handle_register_request()'s identical guard.
        _send(sock, packet)

        # authenticate_connection() returns None either way, so the
        # connection is closed by handle_client()'s teardown -- a
        # graceful EOF, not a timeout.
        assert _recv(sock, timeout=2) is None
    finally:
        sock.close()
        _delete_user(user["username"])


# ----------------------------------------------------------------------
# LOGOUT -- functional: real ClientSession.logout(), real server,
# real round trip
# ----------------------------------------------------------------------


def test_authenticated_client_can_logout(running_server, monkeypatch):
    _state, port = running_server
    user = _committed_user("logout_")
    login_result = _login_locally(user)
    payload = {
        **user,
        "user_id": login_result.user_id,
        "session_id": login_result.session_id,
        "access_token": login_result.token_pair.access_token,
    }

    session = _real_connected_session(port, payload, monkeypatch)
    try:
        assert session.logout() is True
    finally:
        session.disconnect()
        _delete_user(user["username"])


def test_logout_revokes_the_session_in_the_database(running_server, monkeypatch):
    _state, port = running_server
    user = _committed_user("revoke_")
    login_result = _login_locally(user)
    payload = {
        **user,
        "user_id": login_result.user_id,
        "session_id": login_result.session_id,
        "access_token": login_result.token_pair.access_token,
    }

    session = _real_connected_session(port, payload, monkeypatch)
    try:
        assert session.logout() is True

        db = SessionLocal()
        try:
            db_session = SessionRepository(db).get_by_session_id(login_result.session_id)
            assert db_session is not None
            assert db_session.revoked is True
            assert db_session.is_active is False
            assert db_session.logout_time is not None
        finally:
            db.close()
    finally:
        session.disconnect()
        _delete_user(user["username"])


def test_logout_causes_previously_issued_token_to_be_rejected(running_server, monkeypatch):
    """Regression coverage for the same property
    test_server_auth_integration.py::test_logged_out_session_token_is_rejected
    proves -- but here the revocation itself is triggered through the
    new logout_request wire path instead of a direct
    AuthenticationService.logout() call."""
    _state, port = running_server
    user = _committed_user("tokenreject_")
    login_result = _login_locally(user)
    payload = {
        **user,
        "user_id": login_result.user_id,
        "session_id": login_result.session_id,
        "access_token": login_result.token_pair.access_token,
    }

    session = _real_connected_session(port, payload, monkeypatch)
    try:
        assert session.logout() is True
    finally:
        session.disconnect()

    try:
        sock = _raw_tls_connect(port)
        try:
            _send(sock, create_auth_packet(login_result.token_pair.access_token))
            response = _recv(sock)

            assert response["type"] == "auth_result"
            assert response["success"] is False
        finally:
            sock.close()
    finally:
        _delete_user(user["username"])


def test_client_cannot_choose_another_users_session_id(running_server):
    """Security requirement: the server must derive the session to
    revoke from its own authenticated connection state, never from a
    client-supplied field. A forged session_id in the packet must be
    silently ignored -- the caller's OWN session is revoked, and the
    named victim's session is left untouched."""
    _state, port = running_server
    user_a = _committed_user("victim_a_")
    user_b = _committed_user("victim_b_")

    try:
        login_a = _login_locally(user_a)
        login_b = _login_locally(user_b)

        sock = _raw_tls_connect(port)
        try:
            _send(sock, create_auth_packet(login_a.token_pair.access_token))
            auth_response = _recv(sock)
            assert auth_response["success"] is True

            _send(
                sock,
                create_public_key_packet(
                    username=user_a["username"],
                    algorithm="KYBER",
                    public_key="test-public-key-a",
                ),
            )

            forged_packet = {
                "type": "logout_request",
                "request_id": str(uuid.uuid4()),
                # Forged: this is NOT the authenticated connection's
                # own session -- it belongs to user_b.
                "session_id": login_b.session_id,
            }
            _send(sock, forged_packet)

            # The public_key exchange above triggers an incidental
            # user_list broadcast back to this same socket -- skip
            # past it to the actual logout_result.
            response = _recv_until(sock, lambda p: p.get("type") == "logout_result")
            assert response is not None
            assert response["request_id"] == forged_packet["request_id"]
            # The request still succeeds -- but against the caller's
            # OWN session (user_a's), never the forged one.
            assert response["success"] is True
        finally:
            sock.close()

        db = SessionLocal()
        try:
            session_repo = SessionRepository(db)

            db_session_a = session_repo.get_by_session_id(login_a.session_id)
            assert db_session_a.revoked is True

            db_session_b = session_repo.get_by_session_id(login_b.session_id)
            assert db_session_b.revoked is False
            assert db_session_b.is_active is True
        finally:
            db.close()
    finally:
        _delete_user(user_a["username"])
        _delete_user(user_b["username"])


def test_logout_request_missing_request_id_is_silently_ignored_and_connection_survives(
    running_server, monkeypatch
):
    """Unlike login/register (pre-auth, connection torn down on a
    missing request_id), logout_request is dispatched inside the
    authenticated loop -- a missing request_id must be ignored without
    killing the connection, which is still needed for further packets."""
    _state, port = running_server
    user = _committed_user("logoutnoid_")
    login_result = _login_locally(user)
    payload = {
        **user,
        "user_id": login_result.user_id,
        "session_id": login_result.session_id,
        "access_token": login_result.token_pair.access_token,
    }

    session = _real_connected_session(port, payload, monkeypatch)
    try:
        malformed = {"type": "logout_request"}  # no request_id
        send_message(session.client_socket, malformed)

        # The connection must still be alive and dispatching normally
        # afterward -- a real, well-formed logout_request now succeeds.
        assert session.logout() is True
    finally:
        session.disconnect()
        _delete_user(user["username"])
