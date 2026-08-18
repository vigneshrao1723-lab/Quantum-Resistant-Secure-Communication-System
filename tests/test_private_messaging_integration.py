"""
Integration tests for Milestone 1: private one-to-one message routing.

Verifies, against the real server.client_handler.handle_client accept
loop (same pattern as test_server_auth_integration.py):
  - a private message reaches only its intended, connected recipient
  - other connected clients never receive it
  - an offline/unknown recipient produces a delivery_failure response
    to the sender instead of the message being silently dropped

These tests exercise routing only, not encryption correctness -- AES
and Kyber/RSA are already covered by test_chat_encryption_integration.py.
The "message" field here is an opaque placeholder string, exactly as
the server treats it (it never inspects or decrypts it).

Run with:
    pytest tests/test_private_messaging_integration.py -v
"""

import json
import socket
import struct
import uuid

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_public_key_packet,
)


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
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except TimeoutError:
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


def _assert_no_chat_packet_received(sock, attempts=15, per_attempt_timeout=0.2):
    """Drains everything that arrives within the window (join/leave/
    user_list broadcast noise is expected and ignored); fails only if
    an actual "chat" packet shows up."""
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except TimeoutError:
            candidate = None
        if candidate is not None and candidate.get("type") == "chat":
            raise AssertionError(
                f"Bystander unexpectedly received a private chat packet: {candidate}"
            )


@pytest.fixture()
def running_server():
    """
    TLS Transport Security: every accepted socket is wrapped via
    tests/tls_test_support.py's serve_tls_client() -- the same context
    builder (security.tls.build_server_context()) and wrap_socket()
    call server/server.py's real accept loop uses -- before
    handle_client() ever sees it.

    Yields a ServerHarness (``.state``, ``.port``, and the two
    shutdown phases) rather than a bare (state, port) tuple, so a
    dependent fixture can sequence its own socket teardown against the
    server's -- see tests/tls_test_support.py's ServerHarness for why
    that ordering matters.
    """
    harness = start_test_server()

    yield harness

    harness.shutdown()


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Private Messaging Test",
            "username": f"pmtest_{suffix_hint}{suffix}",
            "email": f"pmtest_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
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
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _connect_and_authenticate(port, user_payload):
    """Complete the auth + public-key-announce handshake steps
    handle_client() requires before it will route chat packets. These
    tests focus on routing, not real Kyber/RSA key material, so the
    public key sent is an inert placeholder."""
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))
    token = _login_and_get_token(user_payload)

    _send(sock, create_auth_packet(token))
    auth_result = _recv(sock)
    assert auth_result["success"] is True, auth_result
    username = auth_result["username"]

    _send(
        sock,
        create_public_key_packet(
            username=username, algorithm="KYBER", public_key="dummy-public-key"
        ),
    )

    return sock, username


@pytest.fixture()
def three_users(running_server):
    """Three authenticated, connected clients: sender, recipient, and
    an uninvolved bystander who must never see the private message."""
    port = running_server.port

    sender_payload = _register_user("sender_")
    recipient_payload = _register_user("recipient_")
    bystander_payload = _register_user("bystander_")

    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)
    recipient_sock, recipient_name = _connect_and_authenticate(port, recipient_payload)
    bystander_sock, bystander_name = _connect_and_authenticate(port, bystander_payload)

    yield {
        "sender": (sender_sock, sender_name),
        "recipient": (recipient_sock, recipient_name),
        "bystander": (bystander_sock, bystander_name),
    }

    # Teardown order matters here -- see ServerHarness in
    # tests/tls_test_support.py. This fixture
    # owns the client sockets and tears down BEFORE running_server, so
    # it must drive the whole sequence rather than closing sockets
    # underneath a server that is still accepting and handling.
    #
    #   1. stop accepting  -- listening socket closed, accept thread joined
    #   2. close clients   -- handler threads' peers disappear
    #   3. join handlers   -- every server-side SSL teardown completed
    #   4. clean up users  -- no handler can still be touching them
    running_server.stop_accepting()

    sender_sock.close()
    recipient_sock.close()
    bystander_sock.close()

    running_server.join_handlers()

    _delete_user(sender_payload["username"])
    _delete_user(recipient_payload["username"])
    _delete_user(bystander_payload["username"])


def test_recipient_receives_private_message(three_users):
    sender_sock, sender_name = three_users["sender"]
    recipient_sock, recipient_name = three_users["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="opaque-ciphertext",
            timestamp="2026-01-01T00:00:00+00:00",
        ),
    )

    received = _recv_until(recipient_sock, lambda p: p.get("type") == "chat")
    assert received is not None
    assert received["sender"] == sender_name
    assert received["receiver"] == recipient_name
    assert received["message"] == "opaque-ciphertext"
    assert received["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_bystander_does_not_receive_private_message(three_users):
    sender_sock, sender_name = three_users["sender"]
    _recipient_sock, recipient_name = three_users["recipient"]
    bystander_sock, _bystander_name = three_users["bystander"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="opaque-ciphertext",
            timestamp="2026-01-01T00:00:00+00:00",
        ),
    )

    # Sanity check the message was actually routed to the real
    # recipient at all, before asserting the bystander got nothing.
    received = _recv_until(_recipient_sock, lambda p: p.get("type") == "chat")
    assert received is not None

    _assert_no_chat_packet_received(bystander_sock)


def test_offline_recipient_returns_delivery_failure(running_server):
    port = running_server.port

    sender_payload = _register_user("offsend_")
    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)

    try:
        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_name,
                receiver="no-such-connected-user",
                message="opaque-ciphertext",
                timestamp="2026-01-01T00:00:00+00:00",
            ),
        )

        response = _recv_until(
            sender_sock, lambda p: p.get("type") == "delivery_failure"
        )
        assert response is not None
        assert response["receiver"] == "no-such-connected-user"
        assert response["reason"]
    finally:
        # Same ordering as the three_users fixture -- see
        # ServerHarness. Stop the server before closing the client so
        # the two ends of the TLS connection are never torn down
        # concurrently.
        running_server.stop_accepting()
        sender_sock.close()
        running_server.join_handlers()
        _delete_user(sender_payload["username"])


def test_offline_recipient_message_is_not_silently_discarded(running_server):
    """The sender must be told delivery failed -- not receive nothing
    and have to guess whether the message went through."""
    port = running_server.port

    sender_payload = _register_user("nosw_")
    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)

    try:
        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_name,
                receiver="definitely-not-online",
                message="opaque-ciphertext",
            ),
        )

        # Not a raw single _recv(): a "user_list" broadcast from this
        # client's own connection setup may already be queued ahead
        # of the delivery_failure response.
        response = _recv_until(
            sender_sock, lambda p: p.get("type") == "delivery_failure"
        )
        assert response is not None
        assert response.get("type") == "delivery_failure"
    finally:
        # Same ordering as above -- see ServerHarness.
        running_server.stop_accepting()
        sender_sock.close()
        running_server.join_handlers()
        _delete_user(sender_payload["username"])
