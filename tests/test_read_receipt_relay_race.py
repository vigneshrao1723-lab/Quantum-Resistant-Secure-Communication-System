"""
BUG 2 -- the read-receipt relay/commit race.

The server used to relay a direct message to the recipient BEFORE it
recorded who it relayed to. That left a window in which the recipient
held the message and could legitimately read it, while the
MessageRecipient row a read receipt must update did not exist yet. In
that window MessageRepository.mark_conversation_read() matched
nothing, returned an empty list, and handle_read_receipt() took its
``if not newly_read_message_ids: return`` early exit -- so the receipt
was silently discarded, the row was written as DELIVERED, and nothing
ever moved it to READ.

The ordering is now:

    persist Message + MessageRecipient (QUEUED)
              -> relay
              -> QUEUED -> DELIVERED for those actually reached

so the row always exists before the recipient can possibly send a
receipt, and the post-relay promotion only ever moves QUEUED forward.
READ is terminal with respect to delivery status.

These tests force the orderings deterministically with
threading.Event barriers -- never sleeps, never stress loops. Every
wait is bounded and asserted, so a test can fail but never hang.

Run with:
    pytest tests/test_read_receipt_relay_race.py -v
"""

import json
import socket
import struct
import threading
import time
import uuid

import pytest

import server.client_handler as client_handler
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from database.connection import SessionLocal
from database.models.message import Message
from database.models.message_recipient import MessageRecipient
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.message_delivery_status import MessageDeliveryStatus
from tests.tls_test_support import start_test_server, wrap_client_socket
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_public_key_packet,
    create_read_receipt_packet,
)

BARRIER_TIMEOUT = 10.0


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
    return json.loads(data.decode("utf-8"))


def _recv_until(sock, predicate, attempts=40, per_attempt_timeout=0.3):
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except (TimeoutError, socket.timeout, OSError):
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


def _register_user(hint=""):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Read Receipt Race Test",
            "username": f"rrace_{hint}{suffix}",
            "email": f"rrace_{hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
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
        result = AuthenticationService(db).authenticate_user(
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _connect_and_authenticate(port, payload, algorithm="KYBER"):
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))

    _send(sock, create_auth_packet(_login_and_get_token(payload)))
    auth_result = _recv(sock)
    assert auth_result["success"] is True, auth_result

    _send(
        sock,
        create_public_key_packet(
            username=auth_result["username"],
            algorithm=algorithm,
            public_key="dummy-public-key",
        ),
    )

    return sock, auth_result["username"]


def _recipient_row(conversation_id, recipient_id):
    db = SessionLocal()
    try:
        return (
            db.query(MessageRecipient)
            .join(Message, MessageRecipient.message_id == Message.id)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .filter(MessageRecipient.recipient_id == uuid.UUID(str(recipient_id)))
            .one_or_none()
        )
    finally:
        db.close()


def _status(conversation_id, recipient_id):
    row = _recipient_row(conversation_id, recipient_id)
    return None if row is None else row.status


def _wait_until(predicate, timeout=10.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


def _wait_for_status(conversation_id, recipient_id, expected):
    return _wait_until(
        lambda: _status(conversation_id, recipient_id) == expected
    )


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


@pytest.fixture()
def alice_and_bob(running_server):
    _state, port = running_server

    alice_payload = _register_user("alice_")
    bob_payload = _register_user("bob_")

    alice_sock, alice_name = _connect_and_authenticate(port, alice_payload)
    bob_sock, bob_name = _connect_and_authenticate(port, bob_payload)

    yield {
        "alice": (alice_sock, alice_name, alice_payload["user_id"]),
        "bob": (bob_sock, bob_name, bob_payload["user_id"]),
    }

    alice_sock.close()
    bob_sock.close()
    _delete_user(alice_payload["username"])
    _delete_user(bob_payload["username"])


def _send_chat(alice_sock, alice_name, bob_name, text):
    _send(
        alice_sock,
        create_chat_packet(sender=alice_name, receiver=bob_name, message=text),
    )


def test_recipient_row_exists_before_the_message_is_relayed(alice_and_bob):
    """The ordering guarantee itself: by the time the recipient holds
    the message, the row a read receipt needs is already there.

    This is what closes the race -- everything else follows from it.
    """

    alice_sock, alice_name, _alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    _send_chat(alice_sock, alice_name, bob_name, "the row must already exist")

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None, "the message was never relayed to Bob"

    conversation_id = delivered.get("direct_conversation_id")
    assert conversation_id, "the relayed packet carried no conversation id"

    # No waiting, no polling: the instant Bob has the message, the row
    # must already exist. Under the old relay-first ordering this was
    # None.
    row = _recipient_row(conversation_id, bob_id)

    assert row is not None, (
        "the MessageRecipient row did not exist when the recipient "
        "already had the message -- the relay/commit race is back"
    )
    assert row.status in (
        MessageDeliveryStatus.QUEUED,
        MessageDeliveryStatus.DELIVERED,
    )

    # And it still reaches DELIVERED, since the relay succeeded.
    assert _wait_for_status(
        conversation_id, bob_id, MessageDeliveryStatus.DELIVERED
    ), f"status never reached DELIVERED (is {_status(conversation_id, bob_id)!r})"


def test_read_receipt_immediately_after_delivery_is_honoured(alice_and_bob):
    """The originally reported scenario, with no barrier at all: read
    the message the instant it arrives and the receipt must stick."""

    alice_sock, alice_name, _alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    _send_chat(alice_sock, alice_name, bob_name, "read me the instant you get me")

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None

    conversation_id = delivered.get("direct_conversation_id")
    assert conversation_id

    _send(bob_sock, create_read_receipt_packet(conversation_id=conversation_id))

    assert _wait_for_status(
        conversation_id, bob_id, MessageDeliveryStatus.READ
    ), (
        "read receipt was discarded: status is "
        f"{_status(conversation_id, bob_id)!r}"
    )


def test_read_receipt_before_the_delivery_promotion_is_not_downgraded(
    alice_and_bob, monkeypatch
):
    """The state-machine guarantee, forced deterministically.

    The QUEUED -> DELIVERED promotion runs after the relay, so a read
    receipt can legitimately land in between. This holds the promotion
    at a barrier until the receipt has been processed, then releases
    it -- and the row must still be READ afterwards. An unguarded
    promotion would downgrade READ to DELIVERED here, which would be a
    new bug introduced by the fix rather than the old one.
    """

    alice_sock, alice_name, _alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    release_promotion = threading.Event()
    promotion_finished = threading.Event()
    receipt_processed = threading.Event()

    original_promote = client_handler._mark_recipients_delivered

    def _held_promote(*args, **kwargs):
        assert release_promotion.wait(BARRIER_TIMEOUT), (
            "the test never released the promotion barrier"
        )
        try:
            return original_promote(*args, **kwargs)
        finally:
            promotion_finished.set()

    monkeypatch.setattr(
        client_handler, "_mark_recipients_delivered", _held_promote
    )

    original_mark = MessageRepository.mark_conversation_read

    def _signalling_mark(self, conversation_id, recipient_id):
        result = original_mark(self, conversation_id, recipient_id)
        receipt_processed.set()
        return result

    monkeypatch.setattr(
        MessageRepository, "mark_conversation_read", _signalling_mark
    )

    _send_chat(alice_sock, alice_name, bob_name, "read before promotion")

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    conversation_id = delivered.get("direct_conversation_id")
    assert conversation_id

    # The row exists (QUEUED) even though the promotion is held.
    row = _recipient_row(conversation_id, bob_id)
    assert row is not None
    assert row.status == MessageDeliveryStatus.QUEUED

    # Bob reads it while the promotion is still blocked.
    _send(bob_sock, create_read_receipt_packet(conversation_id=conversation_id))

    assert receipt_processed.wait(BARRIER_TIMEOUT), (
        "the server never processed Bob's read receipt"
    )
    assert _wait_for_status(
        conversation_id, bob_id, MessageDeliveryStatus.READ
    ), f"the receipt was not applied (status {_status(conversation_id, bob_id)!r})"

    # Now let the delivery promotion run against an already-READ row.
    release_promotion.set()
    assert promotion_finished.wait(BARRIER_TIMEOUT), (
        "the delivery promotion never completed"
    )

    assert _status(conversation_id, bob_id) == MessageDeliveryStatus.READ, (
        "READ was downgraded by the post-relay delivery promotion -- "
        "READ must be terminal with respect to delivery status"
    )


def test_duplicate_read_receipts_are_idempotent(alice_and_bob):
    """A second receipt for the same conversation changes nothing and
    must not disturb the status."""

    alice_sock, alice_name, _alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    _send_chat(alice_sock, alice_name, bob_name, "read me twice")

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    conversation_id = delivered.get("direct_conversation_id")
    assert conversation_id

    for _ in range(3):
        _send(bob_sock, create_read_receipt_packet(conversation_id=conversation_id))

    assert _wait_for_status(conversation_id, bob_id, MessageDeliveryStatus.READ)

    row = _recipient_row(conversation_id, bob_id)
    assert row.status == MessageDeliveryStatus.READ


def test_offline_recipient_row_stays_queued(alice_and_bob, running_server):
    """The BUG 4 semantics are unchanged by the reordering: a
    recipient who is not connected is persisted QUEUED and is never
    promoted, because no relay reached them."""

    _state, port = running_server
    alice_sock, alice_name, _alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    # Establish the conversation while Bob is connected.
    _send_chat(alice_sock, alice_name, bob_name, "first, while connected")
    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    conversation_id = delivered.get("direct_conversation_id")
    assert conversation_id
    assert _wait_for_status(
        conversation_id, bob_id, MessageDeliveryStatus.DELIVERED
    )

    # Bob leaves, then Alice sends again.
    bob_sock.close()
    assert _wait_until(
        lambda: all(
            client["username"] != bob_name for client in _state.clients.values()
        )
    ), "the server still lists Bob as connected"

    _send_chat(alice_sock, alice_name, bob_name, "second, while offline")

    queued = _wait_until(
        lambda: [
            row
            for row in _all_rows_for(conversation_id, bob_id)
            if row.status == MessageDeliveryStatus.QUEUED
        ]
    )

    assert queued, "the offline message's recipient row was not QUEUED"


def _all_rows_for(conversation_id, recipient_id):
    db = SessionLocal()
    try:
        return (
            db.query(MessageRecipient)
            .join(Message, MessageRecipient.message_id == Message.id)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .filter(MessageRecipient.recipient_id == uuid.UUID(str(recipient_id)))
            .all()
        )
    finally:
        db.close()
