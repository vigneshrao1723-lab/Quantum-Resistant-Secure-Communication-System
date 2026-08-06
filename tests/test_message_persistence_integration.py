"""
Integration tests for Milestone 2: database message persistence.

Verifies, against the real server.client_handler.handle_client accept
loop (same pattern as test_private_messaging_integration.py), that a
successfully routed private message is persisted to the messages
table with the correct sender, receiver, ciphertext, algorithm, and
timestamp -- and that a failed delivery (offline recipient) never
creates a database record.

This suite only checks persistence; message routing itself is already
covered by test_private_messaging_integration.py, and encryption
correctness by test_chat_encryption_integration.py.

Run with:
    pytest tests/test_message_persistence_integration.py -v
"""

import json
import socket
import struct
import threading
import time
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from database.connection import SessionLocal
from database.models.message import Message
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from server.client_handler import handle_client
from server.server_state import ServerState
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


@pytest.fixture()
def running_server():
    state = ServerState()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    port = server_socket.getsockname()[1]

    stop = threading.Event()

    def accept_loop():
        server_socket.settimeout(0.2)
        while not stop.is_set():
            try:
                client_socket, addr = server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(
                target=handle_client, args=(state, client_socket, addr), daemon=True
            ).start()

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()

    yield state, port

    stop.set()
    server_socket.close()
    accept_thread.join(timeout=2)


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Message Persistence Test",
            "username": f"mptest_{suffix_hint}{suffix}",
            "email": f"mptest_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
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


def _connect_and_authenticate(port, user_payload, algorithm="KYBER"):
    """Complete the auth + public-key-announce handshake steps
    handle_client() requires before it will route (and persist) chat
    packets. The public key sent is an inert placeholder -- these
    tests focus on persistence, not real Kyber/RSA key material."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    token = _login_and_get_token(user_payload)

    _send(sock, create_auth_packet(token))
    auth_result = _recv(sock)
    assert auth_result["success"] is True, auth_result
    username = auth_result["username"]

    _send(
        sock,
        create_public_key_packet(
            username=username, algorithm=algorithm, public_key="dummy-public-key"
        ),
    )

    return sock, username


def _get_conversation(sender_user_id, receiver_user_id):
    db = SessionLocal()
    try:
        return MessageRepository(db).get_conversation(sender_user_id, receiver_user_id)
    finally:
        db.close()


def _wait_for_persisted_message(sender_user_id, receiver_user_id, attempts=40):
    """Persistence happens on the server thread right after
    send_to_client() -- poll briefly rather than assuming it's
    already committed and visible the instant the socket read
    returns."""
    for _ in range(attempts):
        conversation = _get_conversation(sender_user_id, receiver_user_id)
        if conversation:
            return conversation[-1]
        time.sleep(0.05)
    return None


@pytest.fixture()
def sender_and_recipient(running_server):
    _state, port = running_server

    sender_payload = _register_user("sender_")
    recipient_payload = _register_user("recipient_")

    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)
    recipient_sock, recipient_name = _connect_and_authenticate(port, recipient_payload)

    yield {
        "sender": (sender_sock, sender_name, sender_payload["user_id"]),
        "recipient": (recipient_sock, recipient_name, recipient_payload["user_id"]),
    }

    sender_sock.close()
    recipient_sock.close()
    _delete_user(sender_payload["username"])
    _delete_user(recipient_payload["username"])


def test_message_persisted_after_successful_delivery(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="ciphertext-blob-1",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(recipient_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None


def test_sender_and_receiver_stored_correctly(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="ciphertext-blob-2",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert str(saved.sender_id) == sender_id
    assert str(saved.receiver_id) == recipient_id


def test_ciphertext_stored_unchanged(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    ciphertext = "opaque-base64-ciphertext-blob-XYZ=="

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message=ciphertext,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.ciphertext == ciphertext


def test_timestamp_stored(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    sent_timestamp = datetime(2026, 3, 15, 12, 30, 45, tzinfo=timezone.utc)

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="ciphertext-blob-3",
            timestamp=sent_timestamp.isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.timestamp == sent_timestamp.replace(tzinfo=None)


def test_algorithm_stored(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="ciphertext-blob-4",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.algorithm == "KYBER"


def test_failed_delivery_does_not_create_database_record(running_server):
    _state, port = running_server

    sender_payload = _register_user("offline_")
    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)

    try:
        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_name,
                receiver="no-such-connected-user",
                message="ciphertext-that-should-never-be-saved",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
        )

        failure = _recv_until(
            sender_sock, lambda p: p.get("type") == "delivery_failure"
        )
        assert failure is not None

        # Give any (incorrect) persistence attempt time to land before
        # asserting its absence.
        time.sleep(0.3)

        db = SessionLocal()
        try:
            sender_uuid = uuid.UUID(sender_payload["user_id"])
            messages_from_sender = db.scalars(
                select(Message).where(Message.sender_id == sender_uuid)
            ).all()
            assert messages_from_sender == []
        finally:
            db.close()
    finally:
        sender_sock.close()
        _delete_user(sender_payload["username"])
