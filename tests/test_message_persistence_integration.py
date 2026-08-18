"""
Integration tests for Milestone 2 (database message persistence) and
Milestone 3 (conversation history retrieval).

Verifies, against the real server.client_handler.handle_client accept
loop (same pattern as test_private_messaging_integration.py), that a
successfully routed private message is persisted to the messages
table with the correct sender, receiver, ciphertext, algorithm, and
timestamp -- that a failed delivery (offline recipient) never creates
a database record -- and that ClientSession.load_conversation_history()
correctly retrieves, orders, attributes, and best-effort decrypts that
persisted history.

This suite only checks persistence and history retrieval; live message
routing itself is covered by test_private_messaging_integration.py,
and encryption correctness by test_chat_encryption_integration.py.

Run with:
    pytest tests/test_message_persistence_integration.py -v
"""

import json
import socket
import struct
import time
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.aes import AESCipher
from database.connection import SessionLocal
from database.models.conversation_member import ConversationMember
from database.models.message import Message
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
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
            "full_name": "Message Persistence Test",
            "username": f"mptest_{suffix_hint}{suffix}",
            "email": f"mptest_{suffix_hint}{suffix}@example.com",
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


def _get_conversation(sender_user_id, receiver_user_id):
    db = SessionLocal()
    try:
        return MessageRepository(db).get_conversation(sender_user_id, receiver_user_id)
    finally:
        db.close()


def _wait_for_persisted_message(sender_user_id, receiver_user_id, attempts=100):
    """Persistence happens on the server thread right after
    send_to_client() -- poll briefly rather than assuming it's
    already committed and visible the instant the socket read
    returns. Widened from 40 attempts (2s) after TLS Transport
    Security: under heavy concurrent load (many tests' TLS handshakes
    contending for CPU at once), persistence occasionally took longer
    than the pre-TLS budget -- a generous ceiling costs nothing on the
    common, fast path, since the loop still breaks the instant
    persistence lands."""
    for _ in range(attempts):
        conversation = _get_conversation(sender_user_id, receiver_user_id)
        if conversation:
            return conversation[-1]
        time.sleep(0.05)
    return None


def _wait_for_conversation_length(user_a_id, user_b_id, expected_length, attempts=100):
    for _ in range(attempts):
        conversation = _get_conversation(user_a_id, user_b_id)
        if len(conversation) >= expected_length:
            return conversation
        time.sleep(0.05)
    return _get_conversation(user_a_id, user_b_id)


def _make_connected_session(payload):
    """Real ClientSession: connect() -> login() -> send_public_key()
    -> start_receiver() -- required because load_conversation_history()
    now uses send_request() (D4.3), which can only be resolved by a
    running receiver thread reading real socket data. Replaces the
    former bare _make_session_for() helper, which stood in for a
    logged-in user without ever needing a real connection -- no longer
    possible once history loading requires a server round trip."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _open_direct_chat(session, partner_username):
    """Mirrors ChatWindow.open_conversation() enough to resolve/create
    the real conversation_id via set_current_chat() (D3.3's server-
    side get-or-create) -- the precondition load_conversation_history()
    now relies on, replacing the former direct
    ConversationStore.ensure_direct_conversation_id() call these tests
    used to make (deleted in D4.3)."""
    summary = ConversationSummary(
        conversation_id=None, username=partner_username, is_online=True, latest_message=None,
    )
    session.set_current_chat(summary)


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
        "sender_payload": sender_payload,
        "recipient_payload": recipient_payload,
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


def test_payload_type_defaults_to_text(sender_and_recipient):
    """Phase 3 (Universal Secure Payload Architecture): a packet built
    by create_chat_packet()'s backward-compatible wrapper carries
    payload_type=PayloadType.TEXT automatically -- persist_message()
    must store it, without requiring the sender to pass anything new."""
    from domain.payload_type import PayloadType

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="ciphertext-blob-payload-type",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.payload_type == PayloadType.TEXT
    assert saved.content_metadata is None


def test_content_metadata_stored_when_present(sender_and_recipient):
    """A packet that does carry content_metadata (built directly via
    create_payload_packet(), the generic packet-layer entry point) is
    persisted into the JSONB column as a plain dict -- proven here
    even though no payload type populates it in real use yet."""
    from domain.payload_envelope import PayloadEnvelope
    from domain.payload_type import PayloadType
    from utils.protocol import create_payload_packet

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext="ciphertext-blob-with-metadata",
        content_metadata={"note": "future payload types populate this"},
    )

    _send(
        sender_sock,
        create_payload_packet(
            sender=sender_name,
            receiver=recipient_name,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.payload_type == PayloadType.TEXT
    assert saved.content_metadata == {
        "note": "future payload types populate this"
    }


def test_conversation_id_populated_with_both_members(sender_and_recipient):
    """Phase 1 (Conversation Foundation): persist_message() must also
    resolve/create a direct conversation and record it on the message,
    alongside the untouched receiver_id, without changing anything
    about delivery or the receiver_id-based read path above."""
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="ciphertext-blob-conversation-id",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.conversation_id is not None

    db = SessionLocal()
    try:
        members = (
            db.query(ConversationMember)
            .filter(ConversationMember.conversation_id == saved.conversation_id)
            .all()
        )
        member_user_ids = {str(member.user_id) for member in members}
        assert member_user_ids == {sender_id, recipient_id}
    finally:
        db.close()


def test_conversation_reused_across_multiple_messages(sender_and_recipient):
    """A second message between the same pair must resolve to the
    same conversation as the first, not create a duplicate one."""
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    for i in range(2):
        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_name,
                receiver=recipient_name,
                message=f"ciphertext-reuse-{i}",
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
        )
        _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    conversation = _wait_for_conversation_length(sender_id, recipient_id, 2)
    assert len(conversation) == 2
    assert conversation[0].conversation_id == conversation[1].conversation_id

    db = SessionLocal()
    try:
        conversation_repo = ConversationRepository(db)
        resolved = conversation_repo.get_or_create_direct_conversation(
            sender_id, recipient_id
        )
        assert str(resolved.id) == str(conversation[0].conversation_id)
    finally:
        db.close()


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


# ----------------------------------------------------------------------
# Milestone 3: conversation history retrieval
# ----------------------------------------------------------------------


def test_get_conversation_returns_chronological_order(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    for i in range(3):
        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_name,
                receiver=recipient_name,
                message=f"ciphertext-{i}",
                timestamp=datetime(
                    2026, 1, 1, 10, i, 0, tzinfo=timezone.utc
                ).isoformat(),
            ),
        )
        _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    conversation = _wait_for_conversation_length(sender_id, recipient_id, 3)
    assert len(conversation) == 3
    assert [m.ciphertext for m in conversation] == [
        "ciphertext-0",
        "ciphertext-1",
        "ciphertext-2",
    ]
    assert (
        conversation[0].timestamp
        < conversation[1].timestamp
        < conversation[2].timestamp
    )


def test_load_conversation_history_marks_incoming_and_outgoing(
    sender_and_recipient, running_server, monkeypatch
):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="from-sender-to-recipient",
            timestamp=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    _send(
        recipient_sock,
        create_chat_packet(
            sender=recipient_name,
            receiver=sender_name,
            message="from-recipient-to-sender",
            timestamp=datetime(2026, 1, 1, 9, 1, 0, tzinfo=timezone.utc).isoformat(),
        ),
    )
    _recv_until(sender_sock, lambda p: p.get("type") == "chat")

    _wait_for_conversation_length(sender_id, recipient_id, 2)

    sender_view = _make_connected_session(sender_and_recipient["sender_payload"])
    try:
        _open_direct_chat(sender_view, recipient_name)
        history_for_sender = sender_view.load_conversation_history(recipient_name)
    finally:
        sender_view.disconnect()

    assert len(history_for_sender) == 2
    assert history_for_sender[0]["is_own"] is True
    assert history_for_sender[0]["sender"] == sender_name
    assert history_for_sender[1]["is_own"] is False
    assert history_for_sender[1]["sender"] == recipient_name

    recipient_view = _make_connected_session(sender_and_recipient["recipient_payload"])
    try:
        _open_direct_chat(recipient_view, sender_name)
        history_for_recipient = recipient_view.load_conversation_history(sender_name)
    finally:
        recipient_view.disconnect()

    assert history_for_recipient[0]["is_own"] is False
    assert history_for_recipient[0]["sender"] == sender_name
    assert history_for_recipient[1]["is_own"] is True
    assert history_for_recipient[1]["sender"] == recipient_name


def test_load_conversation_history_preserves_stored_timestamp(
    sender_and_recipient, running_server, monkeypatch
):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    sent_timestamp = datetime(2026, 3, 15, 12, 30, 45, tzinfo=timezone.utc)

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="timestamped-ciphertext",
            timestamp=sent_timestamp.isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")
    _wait_for_conversation_length(sender_id, recipient_id, 1)

    recipient_view = _make_connected_session(sender_and_recipient["recipient_payload"])
    try:
        _open_direct_chat(recipient_view, sender_name)
        history = recipient_view.load_conversation_history(sender_name)
    finally:
        recipient_view.disconnect()

    assert len(history) == 1
    assert history[0]["timestamp"] == sent_timestamp.replace(tzinfo=None)


def test_load_conversation_history_returns_placeholder_without_session_key(
    sender_and_recipient, running_server, monkeypatch
):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="opaque-ciphertext-no-real-key",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")
    _wait_for_conversation_length(sender_id, recipient_id, 1)

    # Fresh session standing in for a new app run: no session key has
    # ever been cached for this partner.
    recipient_view = _make_connected_session(sender_and_recipient["recipient_payload"])
    try:
        _open_direct_chat(recipient_view, sender_name)
        history = recipient_view.load_conversation_history(sender_name)
    finally:
        recipient_view.disconnect()

    assert len(history) == 1
    assert history[0]["text"] == "Message unavailable (encrypted in a previous session)"


def test_load_conversation_history_decrypts_with_cached_session_key(
    sender_and_recipient, running_server, monkeypatch
):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    session_key = b"K" * 32
    plaintext = "a real decryptable message"

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message=AESCipher(session_key).encrypt(plaintext),
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")
    _wait_for_conversation_length(sender_id, recipient_id, 1)

    recipient_view = _make_connected_session(sender_and_recipient["recipient_payload"])
    try:
        # Phase 5 (Secure Group Key Distribution): KeyManager is
        # addressed by conversation_id only -- resolve it via
        # set_current_chat(), the same path the application itself
        # uses, rather than seeding the key under the partner's
        # username.
        _open_direct_chat(recipient_view, sender_name)
        recipient_view.key_manager.store_key(
            recipient_view.current_conversation_id, session_key
        )

        history = recipient_view.load_conversation_history(sender_name)
    finally:
        recipient_view.disconnect()

    assert len(history) == 1
    assert history[0]["text"] == plaintext


# ----------------------------------------------------------------------
# Phase 6 (Secure File & Image Transfer Infrastructure): blob storage
# routing in persist_message()
# ----------------------------------------------------------------------


def test_file_payload_routed_to_blob_storage(sender_and_recipient):
    from domain.payload_envelope import PayloadEnvelope
    from domain.payload_type import PayloadType
    from storage import encrypted_blob_store
    from utils.protocol import create_payload_packet

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    envelope = PayloadEnvelope(
        payload_type=PayloadType.FILE,
        ciphertext="fake-file-ciphertext-blob",
        content_metadata={"filename": "report.pdf", "mime_type": "application/pdf"},
    )

    _send(
        sender_sock,
        create_payload_packet(
            sender=sender_name,
            receiver=recipient_name,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.payload_type == PayloadType.FILE
    assert saved.ciphertext is None
    assert saved.blob_ref is not None
    assert saved.content_metadata == {
        "filename": "report.pdf", "mime_type": "application/pdf"
    }

    try:
        assert encrypted_blob_store.load_blob(saved.blob_ref) == (
            b"fake-file-ciphertext-blob"
        )
    finally:
        encrypted_blob_store.delete_blob(saved.blob_ref)


def test_image_payload_also_routed_to_blob_storage(sender_and_recipient):
    """Proves FILE isn't special-cased -- IMAGE reuses the exact same
    routing decision and the exact same storage backend call."""
    from domain.payload_envelope import PayloadEnvelope
    from domain.payload_type import PayloadType
    from storage import encrypted_blob_store
    from utils.protocol import create_payload_packet

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    envelope = PayloadEnvelope(
        payload_type=PayloadType.IMAGE,
        ciphertext="fake-image-ciphertext-blob",
        content_metadata={"filename": "photo.png"},
    )

    _send(
        sender_sock,
        create_payload_packet(
            sender=sender_name,
            receiver=recipient_name,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.payload_type == PayloadType.IMAGE
    assert saved.ciphertext is None
    assert saved.blob_ref is not None

    try:
        assert encrypted_blob_store.load_blob(saved.blob_ref) == (
            b"fake-image-ciphertext-blob"
        )
    finally:
        encrypted_blob_store.delete_blob(saved.blob_ref)


def test_text_payload_still_stored_inline_not_as_blob(sender_and_recipient):
    """Regression guard: routing FILE/IMAGE to blob storage must not
    change TEXT's storage at all -- ciphertext stays inline, blob_ref
    stays unset, exactly as before Phase 6."""
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    _send(
        sender_sock,
        create_chat_packet(
            sender=sender_name,
            receiver=recipient_name,
            message="plain-text-ciphertext",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

    saved = _wait_for_persisted_message(sender_id, recipient_id)
    assert saved is not None
    assert saved.ciphertext == "plain-text-ciphertext"
    assert saved.blob_ref is None


# ----------------------------------------------------------------------
# C1: Offline Direct-Message Persistence
#
# Distinct from test_failed_delivery_does_not_create_database_record()
# above: that test's receiver ("no-such-connected-user") never
# resolves to any real, registered user at all -- persistence is
# correctly still skipped for it, unchanged by this fix (no valid
# receiver_id foreign key exists to persist under). The tests below
# instead use a REAL, registered recipient who simply isn't connected
# right now -- the case that was previously silently dropped.
# ----------------------------------------------------------------------


def test_message_to_real_offline_user_is_persisted_and_reports_delivery_failure(
    running_server,
):
    """Requirement A: a real, registered recipient who is currently
    disconnected still gets their message saved. delivery_failure is
    still sent -- its meaning is unchanged (not live-delivered right
    now) -- but unlike before this fix, the message itself is not
    lost."""
    _state, port = running_server

    sender_payload = _register_user("c1a_sender_")
    recipient_payload = _register_user("c1a_recipient_")

    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)

    # Bob briefly connects (so he genuinely exists as a known user)
    # then disconnects before Alice sends anything -- the "real user,
    # currently offline" case this fix targets, distinct from a
    # username that was never registered at all.
    recipient_sock, recipient_name = _connect_and_authenticate(port, recipient_payload)
    recipient_sock.close()
    time.sleep(0.2)

    session_key = b"O" * 32
    plaintext = "a real message sent while bob is offline"
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    try:
        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_name,
                receiver=recipient_name,
                message=ciphertext,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
        )

        failure = _recv_until(
            sender_sock, lambda p: p.get("type") == "delivery_failure"
        )
        assert failure is not None
        assert failure["receiver"] == recipient_name
        assert failure["reason"]

        saved = _wait_for_persisted_message(
            sender_payload["user_id"], recipient_payload["user_id"]
        )
        assert saved is not None
        assert str(saved.sender_id) == sender_payload["user_id"]
        assert str(saved.receiver_id) == recipient_payload["user_id"]
        assert saved.conversation_id is not None
        assert saved.ciphertext == ciphertext
        assert plaintext not in saved.ciphertext

        db = SessionLocal()
        try:
            messages = db.scalars(
                select(Message).where(
                    Message.sender_id == uuid.UUID(sender_payload["user_id"]),
                    Message.receiver_id == uuid.UUID(recipient_payload["user_id"]),
                )
            ).all()
            assert len(messages) == 1
        finally:
            db.close()
    finally:
        sender_sock.close()
        _delete_user(sender_payload["username"])
        _delete_user(recipient_payload["username"])


def test_offline_message_appears_and_decrypts_in_recipient_history_after_reconnect(
    running_server, monkeypatch,
):
    """Requirement B: once Bob is back, load_conversation_history()
    -- the existing method, unmodified in this test's own scope --
    finds and correctly decrypts the message that was sent while he
    was offline."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_payload = _register_user("c1b_sender_")
    recipient_payload = _register_user("c1b_recipient_")

    sender_sock, sender_name = _connect_and_authenticate(port, sender_payload)

    recipient_sock, recipient_name = _connect_and_authenticate(port, recipient_payload)
    recipient_sock.close()
    time.sleep(0.2)

    session_key = b"R" * 32
    plaintext = "waiting for bob to come back online"
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    try:
        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_name,
                receiver=recipient_name,
                message=ciphertext,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
        )
        _recv_until(sender_sock, lambda p: p.get("type") == "delivery_failure")

        saved = _wait_for_persisted_message(
            sender_payload["user_id"], recipient_payload["user_id"]
        )
        assert saved is not None

        # Bob "comes back" -- a fresh, really-reconnected session
        # standing in for a new login, exactly like every other
        # history test in this file (_make_connected_session()).
        recipient_view = _make_connected_session(recipient_payload)
        try:
            _open_direct_chat(recipient_view, sender_name)
            recipient_view.key_manager.store_key(
                recipient_view.current_conversation_id, session_key
            )

            history = recipient_view.load_conversation_history(sender_name)
        finally:
            recipient_view.disconnect()

        assert len(history) == 1
        assert history[0]["text"] == plaintext
        assert history[0]["is_own"] is False
    finally:
        sender_sock.close()
        _delete_user(sender_payload["username"])
        _delete_user(recipient_payload["username"])
