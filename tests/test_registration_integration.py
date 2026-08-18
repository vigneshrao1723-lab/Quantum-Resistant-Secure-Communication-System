"""
Tests for the registration migration (D2 -- Server-Side API /
Authentication Migration, second slice): gui/main_window.py's
registration path no longer talks to PostgreSQL directly through a
local AuthenticationService -- it now sends a register_request and
blocks on the response (see client.session.ClientSession.register()
and server/client_handler.py::handle_register_request()).

Unlike user_lookup_request (D2's first slice), a registering client
has no JWT yet -- there is no authenticated session to hang this off
of. handle_register_request() is therefore invoked directly from
authenticate_connection(), before its existing "auth" packet check,
on a connection that never becomes authenticated. The functional tests
below exercise the real thing end to end: a genuine
ClientSession.register() against a real running TLS server (the same
harness pattern every other integration suite in this codebase uses).
The protocol/security tests use a raw TLS-wrapped socket to prove the
server-side behavior -- including that the pre-existing "auth" packet
path is completely unaffected -- independent of what the real client
would ever actually send.

Run with:
    pytest tests/test_registration_integration.py -v
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
from utils.protocol import create_auth_packet, create_register_request_packet


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
    connection -- used where a test needs a pre-existing account
    (e.g. to exercise the duplicate-username/email rejection)."""
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Registration Test",
            "username": f"reg_{suffix_hint}{suffix}",
            "email": f"reg_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        return payload
    finally:
        db.close()


def _login_and_get_token(payload):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        result = auth_service.authenticate_user(
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
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


# ----------------------------------------------------------------------
# Functional: real ClientSession.register(), real server, real round trip
# ----------------------------------------------------------------------


def test_register_creates_a_real_account(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    suffix = uuid.uuid4().hex[:10]
    username = f"reg_new_{suffix}"
    email = f"reg_new_{suffix}@example.com"

    session = ClientSession()
    try:
        result = session.register(
            full_name="Newly Registered",
            username=username,
            email=email,
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
        )

        assert result.success is True
        assert result.errors is None
        assert result.user_id

        db = SessionLocal()
        try:
            user = UserRepository(db).get_by_username(username)
            assert user is not None
            assert str(user.id) == result.user_id
            assert user.email == email
        finally:
            db.close()
    finally:
        _delete_user(username)


def test_register_duplicate_username_is_rejected(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    existing = _committed_user("dup_")

    session = ClientSession()
    try:
        result = session.register(
            full_name="Someone Else",
            username=existing["username"],
            email=f"different_{uuid.uuid4().hex[:10]}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
        )

        assert result.success is False
        assert result.errors and "username" in result.errors
    finally:
        _delete_user(existing["username"])


def test_register_password_mismatch_is_rejected(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    suffix = uuid.uuid4().hex[:10]
    username = f"reg_mismatch_{suffix}"

    session = ClientSession()
    try:
        result = session.register(
            full_name="Mismatch Case",
            username=username,
            email=f"{username}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="SomethingElse!1",
        )

        assert result.success is False
        assert result.errors and "confirm_password" in result.errors

        db = SessionLocal()
        try:
            assert UserRepository(db).get_by_username(username) is None
        finally:
            db.close()
    finally:
        _delete_user(username)


def test_register_does_not_add_the_connection_to_server_state(running_server, monkeypatch):
    """Registration must never authenticate the connection it runs
    on -- state.clients should stay empty for it, exactly like every
    other pre-authentication rejection path in authenticate_connection()."""
    state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    suffix = uuid.uuid4().hex[:10]
    username = f"reg_notrust_{suffix}"

    session = ClientSession()
    try:
        result = session.register(
            full_name="Not Trusted Yet",
            username=username,
            email=f"{username}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
        )

        assert result.success is True
        assert len(state.clients) == 0
        assert session.client_socket is None
    finally:
        _delete_user(username)


def test_register_then_login_on_the_same_session_object(running_server, monkeypatch):
    """gui/main_window.py reuses one ClientSession across a
    register -> login cycle. register() must leave the session object
    clean enough for a completely independent, later connect()/login()
    to succeed -- proving this migration cannot break login (untouched
    by this slice) even indirectly through shared session state."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    suffix = uuid.uuid4().hex[:10]
    username = f"reg_then_login_{suffix}"
    password = "Str0ng!Passw0rd"

    session = ClientSession()
    try:
        result = session.register(
            full_name="Register Then Login",
            username=username,
            email=f"{username}@example.com",
            password=password,
            confirm_password=password,
        )
        assert result.success is True

        session.access_token = _login_and_get_token(
            {"username": username, "password": password}
        )

        session.connect()
        session.login(username)

        assert session.username == username
    finally:
        session.disconnect()
        _delete_user(username)


# ----------------------------------------------------------------------
# Protocol / security: raw TLS socket, independent of ClientSession
# ----------------------------------------------------------------------


def test_register_request_requires_no_prior_authentication(running_server):
    """The entire point of this migration: a register_request is the
    very first packet on a brand-new, never-authenticated connection,
    and still succeeds."""
    _state, port = running_server

    suffix = uuid.uuid4().hex[:10]
    username = f"reg_raw_{suffix}"

    sock = _raw_tls_connect(port)
    try:
        packet = create_register_request_packet(
            full_name="Raw Socket",
            username=username,
            email=f"{username}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
        )
        packet["request_id"] = str(uuid.uuid4())
        _send(sock, packet)

        response = _recv(sock)

        assert response["type"] == "register_result"
        assert response["request_id"] == packet["request_id"]
        assert response["success"] is True
        assert response["user_id"]
        # Only the RegistrationResult-shaped fields -- never a
        # password hash or any other internal User field.
        assert set(response.keys()) == {
            "type", "request_id", "success", "message", "user_id", "errors"
        }
    finally:
        sock.close()
        _delete_user(username)


def test_existing_auth_path_is_unaffected_by_the_new_register_branch(running_server):
    """Regression guard: adding the register_request branch to
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
    """Regression guard for the fallback "Authentication required."
    rejection -- still reached for any packet type that is neither
    "auth" nor "register_request"."""
    _state, port = running_server

    sock = _raw_tls_connect(port)
    try:
        _send(sock, {"type": "chat", "sender": "x", "receiver": "y", "message": "z"})
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False
    finally:
        sock.close()


def test_register_request_missing_request_id_is_silently_ignored(running_server):
    _state, port = running_server

    suffix = uuid.uuid4().hex[:10]
    username = f"reg_noid_{suffix}"

    sock = _raw_tls_connect(port)
    try:
        packet = create_register_request_packet(
            full_name="No Request Id",
            username=username,
            email=f"{username}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
        )
        # Deliberately no request_id -- mirrors
        # handle_user_lookup()'s identical guard.

        _send(sock, packet)

        # handle_register_request() silently no-ops on a missing
        # request_id, so authenticate_connection() returns None and
        # handle_client()'s teardown closes the connection -- the
        # client observes a graceful EOF, not a timeout.
        assert _recv(sock, timeout=2) is None

        db = SessionLocal()
        try:
            assert UserRepository(db).get_by_username(username) is None
        finally:
            db.close()
    finally:
        sock.close()


def test_register_request_weak_password_is_rejected_end_to_end(running_server):
    _state, port = running_server

    suffix = uuid.uuid4().hex[:10]
    username = f"reg_weak_{suffix}"

    sock = _raw_tls_connect(port)
    try:
        packet = create_register_request_packet(
            full_name="Weak Password",
            username=username,
            email=f"{username}@example.com",
            password="weak",
            confirm_password="weak",
        )
        packet["request_id"] = str(uuid.uuid4())
        _send(sock, packet)

        response = _recv(sock)

        assert response["type"] == "register_result"
        assert response["success"] is False
        assert response["errors"] and "password" in response["errors"]

        db = SessionLocal()
        try:
            assert UserRepository(db).get_by_username(username) is None
        finally:
            db.close()
    finally:
        sock.close()
