"""
Integration tests for Phase 4 (Secure Group Messaging Foundation).

Verifies, against the real server.client_handler.handle_client accept
loop (same harness pattern as test_message_persistence_integration.py
and test_private_messaging_integration.py):

  - group_create is confirmed to every connected named member,
    including the creator, via group_create_result.
  - A conversation_id-addressed "chat" packet fans out to every other
    connected member and is NOT echoed back to the sender.
  - Persistence stores exactly one Message row per logical group
    message (no per-recipient duplication), with receiver_id set to
    the sender (the documented legacy placeholder) and conversation_id
    set to the group.
  - message_recipients rows are created with the correct
    DELIVERED/QUEUED status for connected/offline members.
  - Direct 1:1 messaging is unaffected by any of the above.

Run with:
    pytest tests/test_group_messaging_integration.py -v
"""

import json
import socket
import struct
import time
import uuid
from datetime import datetime, timezone

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from database.connection import SessionLocal
from database.models.message_recipient import MessageRecipient
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.message_delivery_status import MessageDeliveryStatus
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_group_create_packet,
    create_payload_packet,
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
    harness = start_test_server()

    yield harness

    harness.shutdown()


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Group Messaging Test",
            "username": f"gmtest_{suffix_hint}{suffix}",
            "email": f"gmtest_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
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
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _connect_and_authenticate(port, user_payload, algorithm="KYBER"):
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))
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


@pytest.fixture()
def trio(running_server):
    _state, port = running_server

    payloads = [_register_user(f"m{i}_") for i in range(3)]
    connections = [_connect_and_authenticate(port, p) for p in payloads]

    yield {
        "port": port,
        "members": [
            {"sock": sock, "username": username, "user_id": payload["user_id"]}
            for (sock, username), payload in zip(connections, payloads)
        ],
    }

    for member in connections:
        member[0].close()
    for payload in payloads:
        _delete_user(payload["username"])


def test_group_create_result_sent_to_every_connected_member(trio):
    creator, member_b, member_c = trio["members"]

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name="Trio Chat",
            member_usernames=[member_b["username"], member_c["username"]],
        ),
    )

    creator_result = _recv_until(
        creator["sock"], lambda p: p.get("type") == "group_create_result"
    )
    b_result = _recv_until(
        member_b["sock"], lambda p: p.get("type") == "group_create_result"
    )
    c_result = _recv_until(
        member_c["sock"], lambda p: p.get("type") == "group_create_result"
    )

    assert creator_result is not None
    assert b_result is not None
    assert c_result is not None

    assert creator_result["name"] == "Trio Chat"
    assert creator_result["creator"] == creator["username"]
    assert set(creator_result["members"]) == {
        creator["username"], member_b["username"], member_c["username"]
    }
    assert creator_result["conversation_id"] == b_result["conversation_id"] == (
        c_result["conversation_id"]
    )


def _create_group(trio, name="Trio Chat"):
    creator, member_b, member_c = trio["members"]

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name=name,
            member_usernames=[member_b["username"], member_c["username"]],
        ),
    )

    results = {
        creator["username"]: _recv_until(
            creator["sock"], lambda p: p.get("type") == "group_create_result"
        ),
        member_b["username"]: _recv_until(
            member_b["sock"], lambda p: p.get("type") == "group_create_result"
        ),
        member_c["username"]: _recv_until(
            member_c["sock"], lambda p: p.get("type") == "group_create_result"
        ),
    }

    for result in results.values():
        assert result is not None

    return results[creator["username"]]["conversation_id"]


def test_group_chat_fans_out_but_not_back_to_sender(trio):
    creator, member_b, member_c = trio["members"]

    conversation_id = _create_group(trio)

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext="group-ciphertext-blob",
        content_metadata={},
    )
    packet = create_payload_packet(
        sender=creator["username"],
        envelope=envelope,
        timestamp=datetime.now(timezone.utc).isoformat(),
        conversation_id=conversation_id,
    )

    _send(creator["sock"], packet)

    delivered_b = _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    delivered_c = _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    assert delivered_b is not None
    assert delivered_b["message"] == "group-ciphertext-blob"
    assert delivered_c is not None
    assert delivered_c["message"] == "group-ciphertext-blob"

    # The sender must never receive their own group message echoed back.
    echoed_to_sender = _recv_until(
        creator["sock"], lambda p: p.get("type") == "chat", attempts=5
    )
    assert echoed_to_sender is None


def test_group_message_persisted_once_with_placeholder_receiver_id(trio):
    creator, member_b, member_c = trio["members"]

    conversation_id = _create_group(trio)

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext="persist-me",
        content_metadata={},
    )
    packet = create_payload_packet(
        sender=creator["username"],
        envelope=envelope,
        timestamp=datetime.now(timezone.utc).isoformat(),
        conversation_id=conversation_id,
    )

    _send(creator["sock"], packet)

    _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        messages = None
        # Widened from 40 attempts (2s) after TLS Transport Security:
        # persistence happens on the server thread after relaying, and
        # under heavy concurrent load (many tests' TLS handshakes
        # contending for CPU at once) that occasionally took longer
        # than the pre-TLS budget -- observed once in a combined run.
        # A generous ceiling costs nothing on the common, fast path
        # (the loop still breaks the instant persistence lands).
        for _ in range(100):
            messages = message_repo.get_group_conversation(uuid.UUID(conversation_id))
            if messages:
                break
            time.sleep(0.05)

        assert messages is not None and len(messages) == 1
        message = messages[0]

        assert message.ciphertext == "persist-me"
        assert str(message.receiver_id) == creator["user_id"]
        assert str(message.sender_id) == creator["user_id"]
        assert str(message.conversation_id) == conversation_id

        # Recipient rows are now created QUEUED *before* the fan-out
        # and promoted to DELIVERED afterwards, for only the members
        # the relay actually reached (BUG 2 -- the row must exist
        # before a recipient can send a read receipt for it). So the
        # rows appearing is no longer the end of the story: poll until
        # both have actually reached DELIVERED, rather than until they
        # merely exist. The assertions below are unchanged -- this
        # waits for the correct state instead of sampling a state
        # part-way through the transition.
        status_by_recipient = {}
        for _ in range(100):
            recipients = (
                db.query(MessageRecipient)
                .filter(MessageRecipient.message_id == message.id)
                .all()
            )
            db.expire_all()
            status_by_recipient = {str(r.recipient_id): r.status for r in recipients}
            if (
                status_by_recipient.get(member_b["user_id"])
                == MessageDeliveryStatus.DELIVERED
                and status_by_recipient.get(member_c["user_id"])
                == MessageDeliveryStatus.DELIVERED
            ):
                break
            time.sleep(0.05)

        assert status_by_recipient[member_b["user_id"]] == MessageDeliveryStatus.DELIVERED
        assert status_by_recipient[member_c["user_id"]] == MessageDeliveryStatus.DELIVERED
        assert creator["user_id"] not in status_by_recipient
    finally:
        db.close()


def test_direct_messaging_unaffected_by_group_routing(trio):
    """A plain create_chat_packet() (no conversation_id) must still
    route by username exactly as before -- the new conversation_id
    branch must never intercept a direct message."""
    creator, member_b, _member_c = trio["members"]

    _send(
        creator["sock"],
        create_chat_packet(
            sender=creator["username"],
            receiver=member_b["username"],
            message="still-direct",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")

    assert delivered is not None
    assert delivered["message"] == "still-direct"
    assert delivered.get("conversation_id") is None
