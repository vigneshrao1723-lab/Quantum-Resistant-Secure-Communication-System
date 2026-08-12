"""
Integration tests for C2 (Read Receipts).

Runs against the real server.client_handler.handle_client accept loop
over TLS -- same harness pattern as every other integration suite in
this codebase. Direct-message tests mirror
test_message_persistence_integration.py's sender_and_recipient
fixture; group tests mirror test_group_messaging_integration.py's
lighter trio fixture (no real Kyber KeyManager -- these tests exercise
persistence/status/authorization, not encryption correctness, so a
placeholder ciphertext string is used throughout, exactly like those
sibling files already do).

Run with:
    pytest tests/test_read_receipts_integration.py -v
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
from client.session import ClientSession
from database.connection import SessionLocal
from database.models.message_recipient import MessageRecipient
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.message_delivery_status import MessageDeliveryStatus
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from server.client_handler import handle_client
from server.server_state import ServerState
from tests.tls_test_support import serve_tls_client, wrap_client_socket
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_group_add_members_packet,
    create_group_create_packet,
    create_group_leave_packet,
    create_payload_packet,
    create_public_key_packet,
    create_read_receipt_packet,
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
        except (TimeoutError, OSError):
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


def _assert_no_packet(sock, predicate, attempts=10, per_attempt_timeout=0.2):
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except (TimeoutError, OSError):
            candidate = None
        if candidate is not None and predicate(candidate):
            raise AssertionError(f"Unexpected matching packet arrived: {candidate}")


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
                target=serve_tls_client,
                args=(handle_client, state, client_socket, addr, state.logger),
                daemon=True,
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
            "full_name": "Read Receipt Test",
            "username": f"rrtest_{suffix_hint}{suffix}",
            "email": f"rrtest_{suffix_hint}{suffix}@example.com",
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


def _connect_and_authenticate(port, user_payload):
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


def _make_session_for(user_id, username):
    """A bare ClientSession standing in for a logged-in user -- see
    test_message_persistence_integration.py's identical helper for
    the full rationale."""
    session = ClientSession()
    session.user_id = user_id
    session.username = username
    return session


def _get_recipient_row(message_id, recipient_id):
    db = SessionLocal()
    try:
        return db.scalar(
            select(MessageRecipient).where(
                MessageRecipient.message_id == message_id,
                MessageRecipient.recipient_id == recipient_id,
            )
        )
    finally:
        db.close()


def _wait_for_recipient_status(message_id, recipient_id, expected_status, attempts=100):
    for _ in range(attempts):
        row = _get_recipient_row(message_id, recipient_id)
        if row is not None and row.status == expected_status:
            return row
        time.sleep(0.05)
    return _get_recipient_row(message_id, recipient_id)


def _get_direct_conversation(user_a_id, user_b_id):
    db = SessionLocal()
    try:
        return MessageRepository(db).get_conversation(user_a_id, user_b_id)
    finally:
        db.close()


def _wait_for_direct_message(user_a_id, user_b_id, attempts=100):
    for _ in range(attempts):
        conversation = _get_direct_conversation(user_a_id, user_b_id)
        if conversation:
            return conversation[-1]
        time.sleep(0.05)
    return None


def _get_group_conversation(conversation_id):
    db = SessionLocal()
    try:
        return MessageRepository(db).get_group_conversation(conversation_id)
    finally:
        db.close()


def _wait_for_group_message(conversation_id, attempts=100):
    for _ in range(attempts):
        messages = _get_group_conversation(conversation_id)
        if messages:
            return messages[-1]
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


@pytest.fixture()
def trio(running_server):
    _state, port = running_server

    payloads = [_register_user(f"m{i}_") for i in range(3)]
    connections = [_connect_and_authenticate(port, p) for p in payloads]

    members = [
        {"sock": sock, "username": username, "user_id": payload["user_id"]}
        for (sock, username), payload in zip(connections, payloads)
    ]

    creator, member_b, member_c = members

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name="Read Receipt Trio",
            member_usernames=[member_b["username"], member_c["username"]],
        ),
    )

    conversation_id = None
    for member in members:
        result = _recv_until(member["sock"], lambda p: p.get("type") == "group_create_result")
        assert result is not None
        conversation_id = result["conversation_id"]

    yield {"port": port, "conversation_id": conversation_id, "members": members}

    for member in members:
        member["sock"].close()
    for payload in payloads:
        _delete_user(payload["username"])


def _send_direct_message(sender_sock, sender_name, receiver_name, ciphertext="direct-ct"):
    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=receiver_name,
            message=ciphertext,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )


def _send_group_message(sender_sock, sender_name, conversation_id, ciphertext="group-ct"):
    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT, ciphertext=ciphertext, content_metadata={}
    )
    _send(
        sender_sock,
        create_payload_packet(
            sender=sender_name,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id=conversation_id,
        ),
    )


# ----------------------------------------------------------------------
# 1-3: Direct message delivery-status creation (B)
# ----------------------------------------------------------------------


def test_direct_connected_message_creates_delivered_recipient(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send_direct_message(sender_sock, sender_name, recipient_name)
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_direct_message(sender_id, recipient_id)
    assert saved is not None

    row = _get_recipient_row(saved.id, uuid.UUID(recipient_id))
    assert row is not None
    assert row.status == MessageDeliveryStatus.DELIVERED


def test_direct_offline_message_creates_queued_recipient(running_server):
    _state, port = running_server

    sender_payload = _register_user("qsender_")
    recipient_payload = _register_user("qrecipient_")

    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)

    # Recipient briefly connects (so they exist as a known user) then
    # disconnects -- the real-user-offline case C1/this phase targets.
    recipient_sock, recipient_name = _connect_and_authenticate(port, recipient_payload)
    recipient_sock.close()
    time.sleep(0.2)

    try:
        _send_direct_message(sender_sock, sender_name, recipient_name)
        _recv_until(sender_sock, lambda p: p.get("type") == "delivery_failure")

        saved = _wait_for_direct_message(
            sender_payload["user_id"], recipient_payload["user_id"]
        )
        assert saved is not None

        row = _get_recipient_row(saved.id, uuid.UUID(recipient_payload["user_id"]))
        assert row is not None
        assert row.status == MessageDeliveryStatus.QUEUED
    finally:
        sender_sock.close()
        _delete_user(sender_payload["username"])
        _delete_user(recipient_payload["username"])


def test_direct_message_not_read_merely_by_reconnecting(running_server):
    _state, port = running_server

    sender_payload = _register_user("nrsender_")
    recipient_payload = _register_user("nrrecipient_")

    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)
    recipient_sock, recipient_name = _connect_and_authenticate(port, recipient_payload)
    recipient_sock.close()
    time.sleep(0.2)

    try:
        _send_direct_message(sender_sock, sender_name, recipient_name)
        _recv_until(sender_sock, lambda p: p.get("type") == "delivery_failure")

        saved = _wait_for_direct_message(
            sender_payload["user_id"], recipient_payload["user_id"]
        )
        assert saved is not None

        # Recipient reconnects -- but never sends a read_receipt.
        reconnect_sock, _name = _connect_and_authenticate(port, recipient_payload)

        try:
            time.sleep(0.3)

            row = _get_recipient_row(saved.id, uuid.UUID(recipient_payload["user_id"]))
            assert row is not None
            assert row.status != MessageDeliveryStatus.READ
        finally:
            reconnect_sock.close()
    finally:
        sender_sock.close()
        _delete_user(sender_payload["username"])
        _delete_user(recipient_payload["username"])


# ----------------------------------------------------------------------
# 4-5: Opening the conversation marks read; survives restart (C, D)
# ----------------------------------------------------------------------


def test_read_receipt_marks_direct_message_read_and_notifies_sender(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send_direct_message(sender_sock, sender_name, recipient_name)
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_direct_message(sender_id, recipient_id)
    assert saved is not None

    _send(
        recipient_sock,
        create_read_receipt_packet(conversation_id=str(saved.conversation_id)),
    )

    notification = _recv_until(
        sender_sock, lambda p: p.get("type") == "read_receipt_notification"
    )
    assert notification is not None
    assert notification["reader"] == recipient_name
    assert notification["conversation_id"] == str(saved.conversation_id)

    row = _wait_for_recipient_status(
        saved.id, uuid.UUID(recipient_id), MessageDeliveryStatus.READ
    )
    assert row is not None
    assert row.status == MessageDeliveryStatus.READ


def test_read_status_survives_fresh_session_restart(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send_direct_message(sender_sock, sender_name, recipient_name)
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_direct_message(sender_id, recipient_id)
    assert saved is not None

    _send(
        recipient_sock,
        create_read_receipt_packet(conversation_id=str(saved.conversation_id)),
    )
    _wait_for_recipient_status(saved.id, uuid.UUID(recipient_id), MessageDeliveryStatus.READ)

    # A brand-new ClientSession standing in for the sender logging
    # back in after a full restart -- read_status must be re-derived
    # from the database, not lost with the old process's memory.
    fresh_sender_view = _make_session_for(sender_id, sender_name)

    history = fresh_sender_view.load_conversation_history(recipient_name)

    assert len(history) == 1
    assert history[0]["is_own"] is True
    assert history[0]["read_status"] is True


# ----------------------------------------------------------------------
# 6: Security -- cannot mark another user's row / non-member (D)
# ----------------------------------------------------------------------


def test_non_member_cannot_mark_direct_conversation_read(sender_and_recipient, running_server):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send_direct_message(sender_sock, sender_name, recipient_name)
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_direct_message(sender_id, recipient_id)
    assert saved is not None

    _state, port = running_server
    outsider_payload = _register_user("outsider_")
    outsider_sock, _outsider_name = _connect_and_authenticate(port, outsider_payload)

    try:
        _send(
            outsider_sock,
            create_read_receipt_packet(conversation_id=str(saved.conversation_id)),
        )

        # No notification should ever be sent as a result of a
        # rejected request.
        _assert_no_packet(
            sender_sock, lambda p: p.get("type") == "read_receipt_notification"
        )

        # The real recipient's row must be completely unaffected.
        row = _get_recipient_row(saved.id, uuid.UUID(recipient_id))
        assert row is not None
        assert row.status != MessageDeliveryStatus.READ
    finally:
        outsider_sock.close()
        _delete_user(outsider_payload["username"])


def test_read_receipt_packet_carries_no_reader_identity_field():
    """Structural proof, not just behavioral: the client -> server
    packet has nothing for a malicious client to forge a reader
    identity into in the first place."""
    packet = create_read_receipt_packet(conversation_id="some-conversation-id")

    assert "reader" not in packet
    assert "recipient_id" not in packet
    assert "user_id" not in packet
    assert set(packet.keys()) == {"type", "conversation_id"}


# ----------------------------------------------------------------------
# 7-8: Group -- non-member rejected; independent per-member state (G)
# ----------------------------------------------------------------------


def test_non_member_cannot_mark_group_conversation_read(trio, running_server):
    creator, member_b, member_c = trio["members"]
    conversation_id = trio["conversation_id"]

    _send_group_message(creator["sock"], creator["username"], conversation_id)
    _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    assert saved is not None

    _state, port = running_server
    outsider_payload = _register_user("goutsider_")
    outsider_sock, _outsider_name = _connect_and_authenticate(port, outsider_payload)

    try:
        _send(
            outsider_sock,
            create_read_receipt_packet(conversation_id=conversation_id),
        )

        _assert_no_packet(
            creator["sock"], lambda p: p.get("type") == "read_receipt_notification"
        )

        row_b = _get_recipient_row(saved.id, uuid.UUID(member_b["user_id"]))
        assert row_b.status != MessageDeliveryStatus.READ
    finally:
        outsider_sock.close()
        _delete_user(outsider_payload["username"])


def test_group_members_have_independent_read_states(trio):
    creator, member_b, member_c = trio["members"]
    conversation_id = trio["conversation_id"]

    _send_group_message(creator["sock"], creator["username"], conversation_id)
    _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    assert saved is not None

    _send(member_b["sock"], create_read_receipt_packet(conversation_id=conversation_id))

    row_b = _wait_for_recipient_status(
        saved.id, uuid.UUID(member_b["user_id"]), MessageDeliveryStatus.READ
    )
    assert row_b.status == MessageDeliveryStatus.READ

    # member_c's row must remain exactly as it was -- unaffected by
    # member_b's own read receipt.
    row_c = _get_recipient_row(saved.id, uuid.UUID(member_c["user_id"]))
    assert row_c.status != MessageDeliveryStatus.READ


# ----------------------------------------------------------------------
# 9-10: Fully-read gating + departed member exclusion (G)
# ----------------------------------------------------------------------


def test_group_message_fully_read_only_when_all_active_recipients_have_read(trio):
    creator, member_b, member_c = trio["members"]
    conversation_id = trio["conversation_id"]

    _send_group_message(creator["sock"], creator["username"], conversation_id)
    _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    _wait_for_group_message(uuid.UUID(conversation_id))

    creator_view = _make_session_for(creator["user_id"], creator["username"])

    history = creator_view.load_conversation_history(conversation_id, is_group=True)
    assert history[-1]["read_status"] is False

    _send(member_b["sock"], create_read_receipt_packet(conversation_id=conversation_id))
    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    _wait_for_recipient_status(
        saved.id, uuid.UUID(member_b["user_id"]), MessageDeliveryStatus.READ
    )

    # Only member_b has read -- member_c hasn't yet.
    history = creator_view.load_conversation_history(conversation_id, is_group=True)
    assert history[-1]["read_status"] is False

    _send(member_c["sock"], create_read_receipt_packet(conversation_id=conversation_id))
    _wait_for_recipient_status(
        saved.id, uuid.UUID(member_c["user_id"]), MessageDeliveryStatus.READ
    )

    # Every active recipient has now read it.
    history = creator_view.load_conversation_history(conversation_id, is_group=True)
    assert history[-1]["read_status"] is True


def test_departed_member_does_not_block_all_read_condition(trio):
    creator, member_b, member_c = trio["members"]
    conversation_id = trio["conversation_id"]

    _send_group_message(creator["sock"], creator["username"], conversation_id)
    _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    assert saved is not None

    # member_c leaves without ever reading the message.
    _send(
        member_c["sock"],
        create_group_leave_packet(
            sender=member_c["username"], conversation_id=conversation_id
        ),
    )
    _recv_until(creator["sock"], lambda p: p.get("type") == "group_member_left")

    # member_b (the only remaining, still-active non-sender member)
    # reads it.
    _send(member_b["sock"], create_read_receipt_packet(conversation_id=conversation_id))
    _wait_for_recipient_status(
        saved.id, uuid.UUID(member_b["user_id"]), MessageDeliveryStatus.READ
    )

    creator_view = _make_session_for(creator["user_id"], creator["username"])
    history = creator_view.load_conversation_history(conversation_id, is_group=True)

    # member_c's row is still whatever it was (never READ) -- but
    # since they're no longer active, that must not block "fully read".
    assert history[-1]["read_status"] is True


# ----------------------------------------------------------------------
# 11: Legacy messages without recipient rows (F)
# ----------------------------------------------------------------------


def test_legacy_message_without_recipient_rows_has_none_read_status(sender_and_recipient):
    _sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    _recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    # Persist a message directly, bypassing the server's C2
    # recipient-row creation entirely -- simulates a row that predates
    # this phase, which genuinely has no MessageRecipient rows at all.
    db = SessionLocal()
    try:
        conversation_repo = ConversationRepository(db)
        message_repo = MessageRepository(db)

        conversation = conversation_repo.get_or_create_direct_conversation(
            uuid.UUID(sender_id), uuid.UUID(recipient_id)
        )

        message_repo.save_message(
            sender_id=uuid.UUID(sender_id),
            receiver_id=uuid.UUID(recipient_id),
            conversation_id=conversation.id,
            ciphertext="legacy-ciphertext",
            blob_ref=None,
            payload_type=PayloadType.TEXT,
            content_metadata=None,
            algorithm="KYBER",
            timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
            epoch=1,
        )

        db.commit()
    finally:
        db.close()

    sender_view = _make_session_for(sender_id, sender_name)
    history = sender_view.load_conversation_history(recipient_name)

    assert len(history) == 1
    assert history[0]["is_own"] is True
    assert history[0]["read_status"] is None


# ----------------------------------------------------------------------
# 12: Group membership timing -- a member added after send is excluded
# from that message's recipients and its read gate (post-commit audit
# gap #2)
# ----------------------------------------------------------------------


def test_member_added_after_send_is_excluded_from_that_messages_recipients_and_read_gate(
    running_server,
):
    """handle_group_chat_delivery() snapshots member_ids via
    get_member_user_ids() fresh at send time, and record_recipients()
    only ever creates rows for that snapshot (see both docstrings) --
    so a member added afterward must have no MessageRecipient row at
    all for a message sent before they joined, and _read_status_for_
    own_message()'s member_ids-intersected filtering must not require
    them for "fully read" either."""
    _state, port = running_server

    alice_payload = _register_user("timing_alice_")
    bob_payload = _register_user("timing_bob_")
    charlie_payload = _register_user("timing_charlie_")

    alice_sock, alice_name = _connect_and_authenticate(port, alice_payload)
    bob_sock, bob_name = _connect_and_authenticate(port, bob_payload)
    charlie_sock, charlie_name = _connect_and_authenticate(port, charlie_payload)

    try:
        _send(
            alice_sock,
            create_group_create_packet(
                sender=alice_name, name="Timing Group", member_usernames=[bob_name]
            ),
        )

        conversation_id = None
        for sock in (alice_sock, bob_sock):
            result = _recv_until(sock, lambda p: p.get("type") == "group_create_result")
            assert result is not None
            conversation_id = result["conversation_id"]

        # Alice sends a message while only Alice + Bob are members.
        _send_group_message(alice_sock, alice_name, conversation_id)
        _recv_until(bob_sock, lambda p: p.get("type") == "chat")

        saved = _wait_for_group_message(uuid.UUID(conversation_id))
        assert saved is not None

        # Charlie joins AFTER that message was already sent/persisted.
        _send(
            alice_sock,
            create_group_add_members_packet(
                sender=alice_name,
                conversation_id=conversation_id,
                member_usernames=[charlie_name],
            ),
        )
        added = _recv_until(
            charlie_sock,
            lambda p: p.get("type") == "group_members_added"
            and p.get("conversation_id") == conversation_id,
        )
        assert added is not None

        # Charlie must have no MessageRecipient row for the old message.
        charlie_row = _get_recipient_row(saved.id, uuid.UUID(charlie_payload["user_id"]))
        assert charlie_row is None

        # Bob -- the message's one real recipient -- reads it, and it
        # must become fully read without Charlie ever reading anything.
        _send(bob_sock, create_read_receipt_packet(conversation_id=conversation_id))
        _wait_for_recipient_status(
            saved.id, uuid.UUID(bob_payload["user_id"]), MessageDeliveryStatus.READ
        )

        alice_view = _make_session_for(alice_payload["user_id"], alice_name)
        history = alice_view.load_conversation_history(conversation_id, is_group=True)
        assert history[-1]["read_status"] is True
    finally:
        alice_sock.close()
        bob_sock.close()
        charlie_sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(charlie_payload["username"])


# ----------------------------------------------------------------------
# 13: Read-receipt spoofing -- forged identity fields are ignored
# (post-commit audit gap #3)
# ----------------------------------------------------------------------


def _forged_read_receipt_packet(conversation_id, forged_user_id, forged_username):
    """A hand-built packet bypassing create_read_receipt_packet()
    entirely, carrying every identity-shaped field a malicious client
    might try -- none of which handle_read_receipt() actually reads
    (it only ever calls packet.get("conversation_id"); see its own
    docstring/implementation in server/client_handler.py)."""
    return {
        "type": "read_receipt",
        "conversation_id": conversation_id,
        "user_id": forged_user_id,
        "reader": forged_username,
        "recipient_id": forged_user_id,
    }


def test_forged_identity_fields_in_read_receipt_packet_are_ignored(trio):
    """member_c sends a packet forging member_b's identity into every
    field a real client never sends. If any of them were consulted,
    this would incorrectly mark member_b's row read and/or notify the
    creator with the wrong reader name -- the reader must always be
    member_c, the real, socket-derived identity."""
    creator, member_b, member_c = trio["members"]
    conversation_id = trio["conversation_id"]

    _send_group_message(creator["sock"], creator["username"], conversation_id)
    _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    assert saved is not None

    _send(
        member_c["sock"],
        _forged_read_receipt_packet(
            conversation_id, member_b["user_id"], member_b["username"]
        ),
    )

    notification = _recv_until(
        creator["sock"], lambda p: p.get("type") == "read_receipt_notification"
    )
    assert notification is not None
    assert notification["reader"] == member_c["username"]

    row_c = _wait_for_recipient_status(
        saved.id, uuid.UUID(member_c["user_id"]), MessageDeliveryStatus.READ
    )
    assert row_c.status == MessageDeliveryStatus.READ

    # member_b's row must be completely untouched by the forgery.
    row_b = _get_recipient_row(saved.id, uuid.UUID(member_b["user_id"]))
    assert row_b.status != MessageDeliveryStatus.READ


def test_non_member_with_forged_identity_cannot_mark_group_conversation_read(
    trio, running_server
):
    """Complements the test above: a complete outsider (never a
    member at all) also cannot use forged identity fields to bypass
    the membership check or affect a real member's row."""
    creator, member_b, member_c = trio["members"]
    conversation_id = trio["conversation_id"]

    _send_group_message(creator["sock"], creator["username"], conversation_id)
    _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    assert saved is not None

    _state, port = running_server
    outsider_payload = _register_user("spoof_outsider_")
    outsider_sock, _outsider_name = _connect_and_authenticate(port, outsider_payload)

    try:
        _send(
            outsider_sock,
            _forged_read_receipt_packet(
                conversation_id, member_b["user_id"], member_b["username"]
            ),
        )

        _assert_no_packet(
            creator["sock"], lambda p: p.get("type") == "read_receipt_notification"
        )

        row_b = _get_recipient_row(saved.id, uuid.UUID(member_b["user_id"]))
        assert row_b.status != MessageDeliveryStatus.READ
    finally:
        outsider_sock.close()
        _delete_user(outsider_payload["username"])
