"""
Security regression tests for server-side message routing hardening.

Verifies, against the real server.client_handler.handle_client accept
loop (same harness pattern as test_message_persistence_integration.py
and test_group_messaging_integration.py), the two fixes from this
hardening phase:

  1. Sender authentication: the server overwrites packet["sender"]
     with the authenticated socket identity before relaying a "chat"
     packet (direct or group) -- a client can no longer spoof who a
     message appears to be from.

  2. Group membership authorization: handle_group_chat_delivery()
     rejects (silently: no relay, no persistence, no MessageRecipient
     rows, server-side log only) a "chat" packet addressed to a
     conversation_id the authenticated sender is not an active member
     of -- including a member who has left.

Run with:
    pytest tests/test_message_routing_security.py -v
"""

import json
import socket
import struct
import threading
import time
import uuid
from datetime import datetime, timezone

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from database.connection import SessionLocal
from database.models.conversation_member import ConversationMember
from database.models.message_recipient import MessageRecipient
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from security.tls import build_server_context
from server.client_handler import handle_client
from server.server_state import ServerState
from tests.tls_test_support import serve_tls_client, wrap_client_socket
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
    state = ServerState()

    # Test-harness hardening: one SSLContext per fixture instance,
    # built once and reused for every connection this fixture's
    # accept loop handles -- mirrors build_server_context()'s own
    # documented contract ("built once... and reused for every
    # accepted connection -- never rebuilt per client"), which
    # server/server.py already follows. Previously each connection's
    # serve_tls_client() call rebuilt a fresh SSLContext (and re-read
    # the cert/key from disk) internally; under a full-suite run that
    # meant hundreds of concurrent, independent SSLContext
    # constructions across many threads -- a load pattern production
    # never exercises -- consistent with the intermittent Windows SSL
    # alert failures observed under heavy concurrent runs.
    tls_context = build_server_context()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    port = server_socket.getsockname()[1]

    stop = threading.Event()
    # Test-harness hardening: previously only accept_thread was
    # joined at teardown -- an in-flight per-connection handler
    # thread (blocked in recv()/the TLS handshake) could keep running
    # into the next test's setup, racing that test's own socket
    # teardown and surfacing as a raw OS-level error (observed:
    # WinError 10038, "operation attempted on something that is not
    # a socket") rather than a clean, isolated failure. Tracked here
    # so every one can be joined below.
    handler_threads = []

    def accept_loop():
        server_socket.settimeout(0.2)
        while not stop.is_set():
            try:
                client_socket, addr = server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            handler_thread = threading.Thread(
                target=serve_tls_client,
                args=(handle_client, state, client_socket, addr, state.logger),
                kwargs={"context": tls_context},
                daemon=True,
            )
            handler_thread.start()
            handler_threads.append(handler_thread)

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()

    yield state, port

    stop.set()
    server_socket.close()
    accept_thread.join(timeout=2)

    for handler_thread in handler_threads:
        handler_thread.join(timeout=2)


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Routing Security Test",
            "username": f"rstest_{suffix_hint}{suffix}",
            "email": f"rstest_{suffix_hint}{suffix}@example.com",
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


def _get_group_message_count(conversation_id):
    db = SessionLocal()
    try:
        return len(
            MessageRepository(db).get_group_conversation(uuid.UUID(conversation_id))
        )
    finally:
        db.close()


def _mark_member_as_left(conversation_id, user_id):
    """Directly set ConversationMember.left_at -- no repository method
    for this exists yet (see test_removed_member_cannot_send_group_message's
    docstring), so the test uses the existing column directly rather
    than adding one."""
    db = SessionLocal()
    try:
        member = (
            db.query(ConversationMember)
            .filter(
                ConversationMember.conversation_id == uuid.UUID(conversation_id),
                ConversationMember.user_id == uuid.UUID(user_id),
            )
            .one()
        )
        member.left_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
    finally:
        db.close()


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


def _create_group(trio, name="Security Test Group"):
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


# ----------------------------------------------------------------------
# A. Direct sender spoofing
# ----------------------------------------------------------------------

def test_direct_sender_spoofing_is_corrected_by_server(alice_and_bob):
    alice_sock, alice_name, alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, _bob_id = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_chat_packet(
            sender="mallory",
            receiver=bob_name,
            message="spoof-attempt-ciphertext",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert delivered["sender"] == alice_name
    assert delivered["sender"] != "mallory"

    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        conversation = None
        for _ in range(100):
            conversation = message_repo.get_conversation(
                uuid.UUID(alice_id), uuid.UUID(_bob_id)
            )
            if conversation:
                break
            time.sleep(0.05)

        assert conversation
        saved = conversation[-1]
        assert str(saved.sender_id) == alice_id
    finally:
        db.close()


# ----------------------------------------------------------------------
# B. Legitimate direct messaging still works
# ----------------------------------------------------------------------

def test_legitimate_direct_messaging_still_works(alice_and_bob):
    alice_sock, alice_name, alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_chat_packet(
            sender=alice_name,
            receiver=bob_name,
            message="normal-direct-message",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert delivered["sender"] == alice_name
    assert delivered["message"] == "normal-direct-message"

    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        conversation = None
        for _ in range(100):
            conversation = message_repo.get_conversation(
                uuid.UUID(alice_id), uuid.UUID(bob_id)
            )
            if conversation:
                break
            time.sleep(0.05)

        assert conversation
        assert str(conversation[-1].sender_id) == alice_id
        assert str(conversation[-1].receiver_id) == bob_id
    finally:
        db.close()


# ----------------------------------------------------------------------
# C. Legitimate group member
# ----------------------------------------------------------------------

def test_legitimate_group_member_can_send(trio):
    creator, member_b, member_c = trio["members"]

    conversation_id = _create_group(trio)

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext="legit-group-message",
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
    assert delivered_b["sender"] == creator["username"]
    assert delivered_c is not None
    assert delivered_c["sender"] == creator["username"]

    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        messages = None
        for _ in range(100):
            messages = message_repo.get_group_conversation(uuid.UUID(conversation_id))
            if messages:
                break
            time.sleep(0.05)

        assert messages and len(messages) == 1
        message = messages[0]
        assert str(message.sender_id) == creator["user_id"]

        recipients = (
            db.query(MessageRecipient)
            .filter(MessageRecipient.message_id == message.id)
            .all()
        )
        recipient_ids = {str(r.recipient_id) for r in recipients}
        assert recipient_ids == {member_b["user_id"], member_c["user_id"]}
    finally:
        db.close()


# ----------------------------------------------------------------------
# D. Group sender spoofing
# ----------------------------------------------------------------------

def test_group_sender_spoofing_is_corrected_by_server(trio):
    creator, member_b, member_c = trio["members"]

    conversation_id = _create_group(trio)

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext="spoofed-group-message",
        content_metadata={},
    )
    packet = create_payload_packet(
        sender="mallory",
        envelope=envelope,
        timestamp=datetime.now(timezone.utc).isoformat(),
        conversation_id=conversation_id,
    )

    _send(creator["sock"], packet)

    delivered_b = _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    delivered_c = _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")

    assert delivered_b is not None
    assert delivered_b["sender"] == creator["username"]
    assert delivered_b["sender"] != "mallory"
    assert delivered_c is not None
    assert delivered_c["sender"] == creator["username"]

    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        messages = None
        for _ in range(100):
            messages = message_repo.get_group_conversation(uuid.UUID(conversation_id))
            if messages:
                break
            time.sleep(0.05)

        assert messages and len(messages) == 1
        assert str(messages[0].sender_id) == creator["user_id"]
    finally:
        db.close()


# ----------------------------------------------------------------------
# E. Unauthorized group injection
# ----------------------------------------------------------------------

def test_non_member_cannot_inject_group_message(trio, running_server):
    _state, port = running_server
    creator, member_b, member_c = trio["members"]

    conversation_id = _create_group(trio)

    outsider_payload = _register_user("outsider_")
    outsider_sock, outsider_name = _connect_and_authenticate(port, outsider_payload)

    try:
        before_count = _get_group_message_count(conversation_id)

        envelope = PayloadEnvelope(
            payload_type=PayloadType.TEXT,
            ciphertext="injected-by-non-member",
            content_metadata={},
        )
        packet = create_payload_packet(
            sender=outsider_name,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id=conversation_id,
        )

        _send(outsider_sock, packet)

        # No member of the group must receive it.
        assert _recv_until(
            creator["sock"], lambda p: p.get("type") == "chat", attempts=5
        ) is None
        assert _recv_until(
            member_b["sock"], lambda p: p.get("type") == "chat", attempts=5
        ) is None
        assert _recv_until(
            member_c["sock"], lambda p: p.get("type") == "chat", attempts=5
        ) is None

        # Give any (incorrect) persistence attempt time to land before
        # asserting its absence.
        time.sleep(0.3)

        after_count = _get_group_message_count(conversation_id)
        assert after_count == before_count

        db = SessionLocal()
        try:
            # _create_group() only creates the conversation -- it never
            # sends a chat message -- so no Message row exists for this
            # conversation at all yet, and therefore no MessageRecipient
            # row can exist for it either. The rejected injection must
            # not have created either.
            messages = MessageRepository(db).get_group_conversation(
                uuid.UUID(conversation_id)
            )
            assert messages == []

            message_ids = [m.id for m in messages]
            recipients = (
                db.query(MessageRecipient)
                .filter(MessageRecipient.message_id.in_(message_ids))
                .all()
            )
            assert recipients == []
        finally:
            db.close()
    finally:
        outsider_sock.close()
        _delete_user(outsider_payload["username"])


# ----------------------------------------------------------------------
# F. Removed member
# ----------------------------------------------------------------------

def test_removed_member_cannot_send_group_message(trio):
    """ConversationRepository has no "leave a conversation" method yet
    (only get_member_user_ids(), which already filters left_at IS
    NULL) -- adding one is unrelated architecture and out of scope for
    this hardening phase. This test instead sets the existing
    ConversationMember.left_at column directly, which is sufficient to
    prove the rejection path: get_member_user_ids() excludes this
    member exactly as it would if a real "leave" feature had done it,
    so handle_group_chat_delivery()'s membership check treats them
    identically to a non-member (test E)."""
    creator, member_b, member_c = trio["members"]

    conversation_id = _create_group(trio)

    _mark_member_as_left(conversation_id, member_b["user_id"])

    before_count = _get_group_message_count(conversation_id)

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext="sent-after-leaving",
        content_metadata={},
    )
    packet = create_payload_packet(
        sender=member_b["username"],
        envelope=envelope,
        timestamp=datetime.now(timezone.utc).isoformat(),
        conversation_id=conversation_id,
    )

    _send(member_b["sock"], packet)

    assert _recv_until(
        creator["sock"], lambda p: p.get("type") == "chat", attempts=5
    ) is None
    assert _recv_until(
        member_c["sock"], lambda p: p.get("type") == "chat", attempts=5
    ) is None

    time.sleep(0.3)

    after_count = _get_group_message_count(conversation_id)
    assert after_count == before_count
