"""
Integration tests for Phase 8 (File & Image Transfer).

Verifies, against the real server.client_handler.handle_client accept
loop (same harness pattern as test_message_persistence_integration.py
and test_group_messaging_integration.py):

  - a FILE/IMAGE payload, encrypted through the real AES-GCM +
    FilePayloadAdapter pipeline (not a fake ciphertext string), routes
    and persists identically for direct and group conversations
  - the persisted row has ciphertext=NULL and blob_ref set
  - the blob on disk, once decrypted, is byte-for-byte identical to
    the original file content
  - ClientSession.load_conversation_history() (the real method, via a
    real, fully connected session -- see
    test_message_persistence_integration.py::_make_connected_session())
    can later retrieve that same original content, via D4.3's
    message_history_request/blob_download_request round trip
  - ClientSession.send_attachment() rejects an oversized file before
    any network or crypto work

Run with:
    pytest tests/test_file_image_transfer_integration.py -v
"""

import json
import socket
import struct
import time
import uuid
from datetime import datetime, timezone

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.aes import AESCipher
from database.connection import SessionLocal
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from payload.file_adapter import FilePayloadAdapter
from storage import encrypted_blob_store
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import (
    create_auth_packet,
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
            "full_name": "File Transfer Test",
            "username": f"fitest_{suffix_hint}{suffix}",
            "email": f"fitest_{suffix_hint}{suffix}@example.com",
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


def _make_connected_session(payload):
    """Real ClientSession: connect() -> login() -> send_public_key()
    -> start_receiver() -- required because load_conversation_history()
    now uses send_request() (D4.3) -- mirrors
    test_message_persistence_integration.py::_make_connected_session()
    exactly (duplicated per this codebase's established per-file
    convention rather than shared)."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _open_direct_chat(session, partner_username):
    summary = ConversationSummary(
        conversation_id=None, username=partner_username, is_online=True, latest_message=None,
    )
    session.set_current_chat(summary)


def _get_message_by_conversation(conversation_id):
    db = SessionLocal()
    try:
        return MessageRepository(db).get_group_conversation(conversation_id)
    finally:
        db.close()


def _wait_for_group_message(conversation_id, attempts=100):
    for _ in range(attempts):
        messages = _get_message_by_conversation(conversation_id)
        if messages:
            return messages[-1]
        time.sleep(0.05)
    return None


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


@pytest.fixture()
def trio(running_server):
    _state, port = running_server

    payloads = [_register_user(f"m{i}_") for i in range(3)]
    connections = [_connect_and_authenticate(port, p) for p in payloads]

    yield {
        "members": [
            {"sock": sock, "username": username, "user_id": payload["user_id"]}
            for (sock, username), payload in zip(connections, payloads)
        ],
    }

    for member in connections:
        member[0].close()
    for payload in payloads:
        _delete_user(payload["username"])


def _create_group(trio_fixture, name="File Transfer Group"):
    creator, member_b, member_c = trio_fixture["members"]

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name=name,
            member_usernames=[member_b["username"], member_c["username"]],
        ),
    )

    results = [
        _recv_until(m["sock"], lambda p: p.get("type") == "group_create_result")
        for m in (creator, member_b, member_c)
    ]
    for result in results:
        assert result is not None

    return results[0]["conversation_id"]


def _encrypt_attachment(payload_type, content, content_metadata, session_key):
    """Real AES-GCM + FilePayloadAdapter round trip -- the exact
    encryption path client/session.py::_send_encrypted_payload() uses
    -- not a fake ciphertext placeholder string, unlike the routing-
    only tests in test_message_persistence_integration.py."""
    adapter = FilePayloadAdapter(payload_type)
    aes = AESCipher(session_key)
    return adapter.encrypt(content, aes, content_metadata=content_metadata)


# ----------------------------------------------------------------------
# Direct file/image transfer: real encryption round trip, routing,
# and blob-storage persistence.
# ----------------------------------------------------------------------


def test_direct_file_transfer_delivers_and_persists(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    session_key = b"K" * 32
    original_bytes = b"%PDF-1.4 fake pdf content \x00\x01\x02 binary bytes"
    content_metadata = {
        "filename": "report.pdf",
        "mime_type": "application/pdf",
        "size_bytes": len(original_bytes),
    }

    envelope = _encrypt_attachment(
        PayloadType.FILE, original_bytes, content_metadata, session_key
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

    delivered = _recv_until(recipient_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert delivered["payload_type"] == PayloadType.FILE
    assert delivered["content_metadata"] == content_metadata

    saved = _wait_for_direct_message(uuid.UUID(sender_id), uuid.UUID(recipient_id))
    assert saved is not None
    assert saved.payload_type == PayloadType.FILE
    assert saved.ciphertext is None
    assert saved.blob_ref is not None

    try:
        stored_ciphertext = encrypted_blob_store.load_blob(saved.blob_ref).decode("utf-8")
        decrypted = FilePayloadAdapter(PayloadType.FILE).decrypt(
            PayloadEnvelope(
                payload_type=PayloadType.FILE,
                ciphertext=stored_ciphertext,
                content_metadata=saved.content_metadata or {},
            ),
            AESCipher(session_key),
        )
        assert decrypted == original_bytes
    finally:
        encrypted_blob_store.delete_blob(saved.blob_ref)


def test_direct_image_transfer_delivers_and_persists(sender_and_recipient):
    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    session_key = b"K" * 32
    # Minimal but valid 1x1 PNG, to prove real binary image bytes
    # survive the round trip unchanged.
    original_bytes = bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000000100000001080600000"
        "01f15c4890000000a49444154789c6360000002000100"
        "0dae7f870000000049454e44ae426082"
    )
    content_metadata = {"filename": "pixel.png", "mime_type": "image/png"}

    envelope = _encrypt_attachment(
        PayloadType.IMAGE, original_bytes, content_metadata, session_key
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

    delivered = _recv_until(recipient_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert delivered["payload_type"] == PayloadType.IMAGE

    saved = _wait_for_direct_message(uuid.UUID(sender_id), uuid.UUID(recipient_id))
    assert saved is not None
    assert saved.payload_type == PayloadType.IMAGE
    assert saved.ciphertext is None
    assert saved.blob_ref is not None

    try:
        stored_ciphertext = encrypted_blob_store.load_blob(saved.blob_ref).decode("utf-8")
        decrypted = FilePayloadAdapter(PayloadType.IMAGE).decrypt(
            PayloadEnvelope(
                payload_type=PayloadType.IMAGE,
                ciphertext=stored_ciphertext,
                content_metadata=saved.content_metadata or {},
            ),
            AESCipher(session_key),
        )
        assert decrypted == original_bytes
    finally:
        encrypted_blob_store.delete_blob(saved.blob_ref)


# ----------------------------------------------------------------------
# Group file/image transfer
# ----------------------------------------------------------------------


def test_group_file_transfer_fans_out_and_persists(trio):
    creator, member_b, member_c = trio["members"]
    conversation_id = _create_group(trio)

    session_key = b"G" * 32
    original_bytes = b"group file content, byte-for-byte"
    content_metadata = {"filename": "notes.txt", "mime_type": "text/plain"}

    envelope = _encrypt_attachment(
        PayloadType.FILE, original_bytes, content_metadata, session_key
    )

    _send(
        creator["sock"],
        create_payload_packet(
            sender=creator["username"],
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id=conversation_id,
        ),
    )

    delivered_b = _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    delivered_c = _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")
    assert delivered_b is not None and delivered_b["payload_type"] == PayloadType.FILE
    assert delivered_c is not None and delivered_c["payload_type"] == PayloadType.FILE

    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    assert saved is not None
    assert saved.ciphertext is None
    assert saved.blob_ref is not None

    try:
        stored_ciphertext = encrypted_blob_store.load_blob(saved.blob_ref).decode("utf-8")
        decrypted = FilePayloadAdapter(PayloadType.FILE).decrypt(
            PayloadEnvelope(
                payload_type=PayloadType.FILE,
                ciphertext=stored_ciphertext,
                content_metadata=saved.content_metadata or {},
            ),
            AESCipher(session_key),
        )
        assert decrypted == original_bytes
    finally:
        encrypted_blob_store.delete_blob(saved.blob_ref)


def test_group_image_transfer_fans_out_and_persists(trio):
    creator, member_b, member_c = trio["members"]
    conversation_id = _create_group(trio, name="Image Group")

    session_key = b"G" * 32
    original_bytes = b"\xff\xd8\xff\xe0 fake jpeg bytes for group image test"
    content_metadata = {"filename": "group-photo.jpg", "mime_type": "image/jpeg"}

    envelope = _encrypt_attachment(
        PayloadType.IMAGE, original_bytes, content_metadata, session_key
    )

    _send(
        creator["sock"],
        create_payload_packet(
            sender=creator["username"],
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id=conversation_id,
        ),
    )

    delivered_b = _recv_until(member_b["sock"], lambda p: p.get("type") == "chat")
    delivered_c = _recv_until(member_c["sock"], lambda p: p.get("type") == "chat")
    assert delivered_b is not None and delivered_b["payload_type"] == PayloadType.IMAGE
    assert delivered_c is not None and delivered_c["payload_type"] == PayloadType.IMAGE

    saved = _wait_for_group_message(uuid.UUID(conversation_id))
    assert saved is not None
    assert saved.ciphertext is None
    assert saved.blob_ref is not None

    encrypted_blob_store.delete_blob(saved.blob_ref)


# ----------------------------------------------------------------------
# History reload: ClientSession.load_conversation_history() retrieving
# original bytes back from blob storage (Phase 8's new code path).
# ----------------------------------------------------------------------


def test_history_reload_retrieves_original_file_bytes(
    sender_and_recipient, running_server, monkeypatch
):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    session_key = b"H" * 32
    original_bytes = b"history round trip content \x00\xff"
    content_metadata = {"filename": "history.bin", "size_bytes": len(original_bytes)}

    envelope = _encrypt_attachment(
        PayloadType.FILE, original_bytes, content_metadata, session_key
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

    saved = _wait_for_direct_message(uuid.UUID(sender_id), uuid.UUID(recipient_id))
    assert saved is not None

    try:
        # Fresh, really-reconnected session standing in for a new app
        # run, exactly like test_message_persistence_integration.py's
        # history tests -- the session key must be seeded (a real
        # client would have received it via the Kyber/RSA key-exchange
        # path) before history can be decrypted. D4.3: the actual
        # attachment bytes are fetched lazily, via a
        # blob_download_request load_conversation_history() issues
        # internally -- not read directly from local blob storage.
        recipient_view = _make_connected_session(sender_and_recipient["recipient_payload"])
        try:
            _open_direct_chat(recipient_view, sender_name)
            recipient_view.key_manager.store_key(
                recipient_view.current_conversation_id, session_key
            )

            history = recipient_view.load_conversation_history(sender_name)
        finally:
            recipient_view.disconnect()

        assert len(history) == 1
        assert history[0]["payload_type"] == PayloadType.FILE
        assert history[0]["content"] == original_bytes
        assert history[0]["content_metadata"]["filename"] == "history.bin"
    finally:
        encrypted_blob_store.delete_blob(saved.blob_ref)


def test_history_without_key_returns_none_content_for_attachment(
    sender_and_recipient, running_server, monkeypatch
):
    """Mirrors test_message_persistence_integration.py's text
    placeholder test, for binary content: a client that never received
    this conversation's key gets None, not a crash or garbage bytes."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_sock, sender_name, sender_id = sender_and_recipient["sender"]
    recipient_sock, recipient_name, recipient_id = sender_and_recipient["recipient"]

    session_key = b"N" * 32
    envelope = _encrypt_attachment(
        PayloadType.FILE, b"unreachable without the key", {"filename": "x.bin"}, session_key
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

    saved = _wait_for_direct_message(uuid.UUID(sender_id), uuid.UUID(recipient_id))
    assert saved is not None

    try:
        recipient_view = _make_connected_session(sender_and_recipient["recipient_payload"])
        try:
            _open_direct_chat(recipient_view, sender_name)
            history = recipient_view.load_conversation_history(sender_name)
        finally:
            recipient_view.disconnect()

        assert len(history) == 1
        assert history[0]["payload_type"] == PayloadType.FILE
        assert history[0]["content"] is None
    finally:
        encrypted_blob_store.delete_blob(saved.blob_ref)


# ----------------------------------------------------------------------
# File-size safety (IMPORTANT FILE-SIZE SAFETY requirement)
# ----------------------------------------------------------------------


def test_oversized_attachment_rejected_before_send(tmp_path, monkeypatch):
    """MAX_ATTACHMENT_SIZE_BYTES is enforced via a stat() call before
    the file is read, before any conversation/socket/crypto state is
    touched -- provable with a bare, disconnected ClientSession."""
    import client.session as client_session_module

    monkeypatch.setattr(client_session_module, "MAX_ATTACHMENT_SIZE_BYTES", 10)

    oversized = tmp_path / "too_big.bin"
    oversized.write_bytes(b"x" * 11)

    session = ClientSession()

    with pytest.raises(ValueError, match="exceeds the maximum attachment size"):
        session.send_attachment(str(oversized))


def test_attachment_within_limit_is_not_rejected_by_size_check(tmp_path, monkeypatch):
    """The inverse of the above -- confirms the check is a real
    boundary, not a check that always fails. No conversation is open,
    so this must fail for the *next* reason (no chat partner), not a
    size rejection."""
    import client.session as client_session_module

    monkeypatch.setattr(client_session_module, "MAX_ATTACHMENT_SIZE_BYTES", 10)

    small = tmp_path / "small.bin"
    small.write_bytes(b"x" * 5)

    session = ClientSession()

    with pytest.raises(ValueError, match="No chat partner selected"):
        session.send_attachment(str(small))
