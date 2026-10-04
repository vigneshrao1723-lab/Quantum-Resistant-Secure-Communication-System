"""
Integration tests for the JWT-gated server connection handshake
(server/client_handler.py's authenticate_connection() + the
"auth"/"auth_result" packets in utils/protocol.py).

Unlike the rest of the auth test suite, these tests cannot use the
transactional db_session fixture (see conftest.py): the server runs
the real accept loop in its own thread and opens its own independent
database connection via SessionLocal(), which must be able to see the
test's user through a genuine commit, not a same-connection SAVEPOINT
that only conftest.py's own connection can see. So these tests create
real rows and clean them up manually, similar to a live smoke test.

Run with:
    pytest tests/test_server_auth_integration.py -v
"""

import base64
import json
import socket
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from config_server import JWT_ALGORITHM, JWT_AUDIENCE, JWT_ISSUER, JWT_SECRET_KEY
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from server.client_handler import handle_client
from tests.tls_test_support import start_test_server
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


@pytest.fixture()
def running_server():
    """Runs the real handle_client accept loop against an ephemeral port.

    Deliberately NOT TLS-wrapped: this suite's clients connect with
    plain socket.create_connection(), so the accepted socket is handed
    to handle_client() directly. That is why it overrides
    start_test_server()'s default connection handler rather than using
    the TLS one every other socket suite uses.
    """

    def _serve_plain(state, _context, client_socket, address):
        handle_client(state, client_socket, address)

    harness = start_test_server(_serve_plain)

    yield harness

    harness.shutdown()


@pytest.fixture()
def committed_user():
    """A genuinely committed user, visible to the server's own DB connection."""
    db = SessionLocal()
    auth_service = AuthenticationService(db)
    suffix = uuid.uuid4().hex[:10]
    payload = {
        "full_name": "Integration Test",
        "username": f"itest_{suffix}",
        "email": f"itest_{suffix}@example.com",
        "password": "Str0ng!Passw0rd",
        "confirm_password": "Str0ng!Passw0rd",
        "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
    }
    result = auth_service.register_user(RegisterRequest(**payload))
    assert result.success, result.errors
    db.close()

    yield payload

    cleanup_db = SessionLocal()
    user = UserRepository(cleanup_db).get_by_username(payload["username"])
    if user is not None:
        for session in SessionRepository(cleanup_db).get_active_sessions_for_user(
            user.id
        ):
            cleanup_db.delete(session)
        cleanup_db.delete(user)
        cleanup_db.commit()
    cleanup_db.close()


def _register_user(suffix_hint=""):
    """Register and return a second (or third...) genuinely committed
    user, independent of the committed_user fixture, for tests that
    need more than one authenticated identity at once."""
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Integration Test",
            "username": f"itest_{suffix_hint}{suffix}",
            "email": f"itest_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        return payload
    finally:
        db.close()


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


def _login_and_get_token(payload):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        result = auth_service.authenticate_user(
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def test_valid_jwt_is_accepted_and_registers_client(running_server, committed_user):
    state, port = running_server
    token = _login_and_get_token(committed_user)

    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, create_auth_packet(token))
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is True
        assert response["username"] == committed_user["username"]

        for _ in range(40):
            if any(
                c["username"] == committed_user["username"]
                for c in state.clients.values()
            ):
                break
            time.sleep(0.05)

        clients = list(state.clients.values())
        matching = [c for c in clients if c["username"] == committed_user["username"]]
        assert matching
        assert matching[0]["user_id"] is not None
        assert matching[0]["session_id"] is not None
    finally:
        sock.close()


def test_invalid_token_is_rejected_and_not_registered(running_server):
    state, port = running_server

    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, create_auth_packet("not-a-real-token"))
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False

        time.sleep(0.2)
        assert len(state.clients) == 0
    finally:
        sock.close()


def test_missing_auth_packet_is_rejected(running_server):
    _state, port = running_server

    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, {"type": "chat", "sender": "x", "receiver": "y", "message": "z"})
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False
    finally:
        sock.close()


def test_expired_token_is_rejected(running_server, committed_user):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(committed_user["username"])
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        expired_payload = {
            "sub": str(user.id),
            "session_id": "irrelevant-session-id",
            "username": user.username,
            "role": user.role,
            "jti": "expired-integration-jti",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now - timedelta(minutes=30),
            "exp": now - timedelta(minutes=15),
            "type": "access",
        }
        expired_token = pyjwt.encode(
            expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM
        )
    finally:
        db.close()

    _state, port = running_server
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, create_auth_packet(expired_token))
        response = _recv(sock)

        assert response["success"] is False
        assert "expired" in response["message"].lower()
    finally:
        sock.close()


def test_locked_user_token_is_rejected(running_server, committed_user):
    token = _login_and_get_token(committed_user)

    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(committed_user["username"])
        user.status = "locked"
        db.commit()
    finally:
        db.close()

    _state, port = running_server
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, create_auth_packet(token))
        response = _recv(sock)

        assert response["success"] is False
    finally:
        sock.close()


def test_inactive_user_token_is_rejected(running_server, committed_user):
    token = _login_and_get_token(committed_user)

    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(committed_user["username"])
        user.is_active = False
        db.commit()
    finally:
        db.close()

    _state, port = running_server
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, create_auth_packet(token))
        response = _recv(sock)

        assert response["success"] is False
    finally:
        sock.close()


def test_logged_out_session_token_is_rejected(running_server, committed_user):
    """Regression test for the logout feature: once
    AuthenticationService.logout() revokes a session, its still
    unexpired, still validly-signed access token must no longer be
    able to authenticate a new connection.
    """
    token = _login_and_get_token(committed_user)

    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        claims = auth_service.jwt_handler.decode_token(token)
        assert auth_service.logout(claims["session_id"]) is True
    finally:
        db.close()

    _state, port = running_server
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, create_auth_packet(token))
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False
    finally:
        sock.close()


def test_tampered_token_is_rejected(running_server, committed_user):
    """A validly-issued token with a corrupted signature segment must
    fail signature verification and be rejected, same as any other
    invalid token."""
    token = _login_and_get_token(committed_user)

    # Flip a bit in the decoded signature *bytes* rather than swapping
    # a base64 character directly -- base64's unused padding bits mean
    # a fixed character substitution can sometimes decode to the same
    # underlying bytes, leaving the signature unchanged (flaky test).
    header, payload, signature = token.split(".")
    padding = "=" * (-len(signature) % 4)
    signature_bytes = bytearray(base64.urlsafe_b64decode(signature + padding))
    signature_bytes[-1] ^= 0xFF
    tampered_signature = (
        base64.urlsafe_b64encode(bytes(signature_bytes)).decode("ascii").rstrip("=")
    )
    tampered_token = f"{header}.{payload}.{tampered_signature}"

    _state, port = running_server
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(sock, create_auth_packet(tampered_token))
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False
    finally:
        sock.close()


def test_multiple_authenticated_users_can_connect_simultaneously(running_server):
    """Two distinct authenticated identities must both be able to join
    and both be tracked with their own user_id/session_id."""
    state, port = running_server

    user_a = _register_user("multi_a_")
    user_b = _register_user("multi_b_")

    try:
        token_a = _login_and_get_token(user_a)
        token_b = _login_and_get_token(user_b)

        sock_a = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock_b = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            _send(sock_a, create_auth_packet(token_a))
            response_a = _recv(sock_a)
            _send(sock_b, create_auth_packet(token_b))
            response_b = _recv(sock_b)

            assert response_a["success"] is True
            assert response_a["username"] == user_a["username"]
            assert response_b["success"] is True
            assert response_b["username"] == user_b["username"]

            for _ in range(40):
                usernames = {c["username"] for c in state.clients.values()}
                if user_a["username"] in usernames and user_b["username"] in usernames:
                    break
                time.sleep(0.05)

            clients = list(state.clients.values())
            usernames = {c["username"] for c in clients}
            assert user_a["username"] in usernames
            assert user_b["username"] in usernames

            user_ids = {c["user_id"] for c in clients}
            assert len(user_ids) == len(clients)
        finally:
            sock_a.close()
            sock_b.close()
    finally:
        _delete_user(user_a["username"])
        _delete_user(user_b["username"])


def test_simultaneous_authenticated_chat_between_two_users(running_server):
    """Two authenticated clients exchange a chat packet; the server
    routes it by the authenticated (server-confirmed) usernames, and
    only after both ends completed the JWT handshake."""
    state, port = running_server

    user_a = _register_user("chat_a_")
    user_b = _register_user("chat_b_")

    try:
        token_a = _login_and_get_token(user_a)
        token_b = _login_and_get_token(user_b)

        sock_a = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock_b = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            _send(sock_a, create_auth_packet(token_a))
            assert _recv(sock_a)["success"] is True
            _send(sock_b, create_auth_packet(token_b))
            assert _recv(sock_b)["success"] is True

            # handle_client() unconditionally reads one more message
            # after auth as the public-key exchange slot before it
            # will enter the chat-forwarding loop -- mirror what a
            # real client always sends there next.
            _send(
                sock_a,
                create_public_key_packet(
                    username=user_a["username"],
                    algorithm="KYBER",
                    public_key="test-public-key-a",
                ),
            )
            _send(
                sock_b,
                create_public_key_packet(
                    username=user_b["username"],
                    algorithm="KYBER",
                    public_key="test-public-key-b",
                ),
            )

            for _ in range(40):
                usernames = {c["username"] for c in state.clients.values()}
                if user_a["username"] in usernames and user_b["username"] in usernames:
                    break
                time.sleep(0.05)

            chat_packet = {
                "type": "chat",
                "sender": user_a["username"],
                "receiver": user_b["username"],
                "message": "hello-from-a",
            }
            _send(sock_a, chat_packet)

            received = None
            for _ in range(20):
                try:
                    candidate = _recv(sock_b, timeout=0.3)
                except TimeoutError:
                    candidate = None
                if candidate and candidate.get("type") == "chat":
                    received = candidate
                    break

            assert received is not None
            assert received["sender"] == user_a["username"]
            assert received["message"] == "hello-from-a"
        finally:
            sock_a.close()
            sock_b.close()
    finally:
        _delete_user(user_a["username"])
        _delete_user(user_b["username"])
