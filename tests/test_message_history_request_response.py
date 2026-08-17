"""
Tests for D4.3 (Message/History Operations Migration, third and final
slice): message_history_request/result and blob_download_request/
result -- the request/response replacement for ClientSession.
load_conversation_history()'s previous direct, client-side
MessageRepository/ConversationRepository/UserRepository/
storage.encrypted_blob_store reads, the last remaining client-side
database and local-storage access anywhere in this codebase's client.

Option A (lazy blob delivery): message_history_result never embeds
attachment ciphertext, only blob_ref metadata; blob_download_request
is a separate, independently authorized endpoint,
load_conversation_history() calls it automatically per attachment so
the GUI's own contract is unaffected.

The protocol/security tests use a raw TLS socket against the real
server.client_handler.handle_client accept loop -- the same harness
pattern as every other D3/D4 request/response test file -- to prove
the server-side behavior independent of what the real client would
ever actually send. The client-consumption tests use a real, fully
connected ClientSession with a real receiver thread, proving
load_conversation_history() no longer touches PostgreSQL or local
blob storage, and that real encrypted text and attachment history
still decrypt correctly end-to-end.

Run with:
    pytest tests/test_message_history_request_response.py -v
"""

import json
import socket
import struct
import threading
import uuid
from datetime import datetime, timezone
from unittest import mock

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.aes import AESCipher
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.message_delivery_status import MessageDeliveryStatus
from domain.payload_type import PayloadType
from payload.file_adapter import FilePayloadAdapter
from security.tls import build_server_context
from server.client_handler import handle_client
from server.server_state import ServerState
from storage import encrypted_blob_store
from tests.tls_test_support import serve_tls_client, wrap_client_socket
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


def _recv_until(sock, predicate, attempts=40, per_attempt_timeout=0.3):
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except (TimeoutError, OSError):
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


@pytest.fixture()
def running_server():
    state = ServerState()

    tls_context = build_server_context()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    port = server_socket.getsockname()[1]

    stop = threading.Event()
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


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "D4.3 Message History Test",
            "username": f"d43_{suffix_hint}{suffix}",
            "email": f"d43_{suffix_hint}{suffix}@example.com",
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


def _make_connected_session(payload):
    """Real ClientSession: connect() -> login() -> send_public_key()
    -> start_receiver() -- required because load_conversation_history()
    now uses send_request() (D4.3), which can only be resolved by a
    running receiver thread reading real socket data."""
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
    the real conversation_id via ClientSession.set_current_chat() (and
    D3.3's server-side get-or-create) -- the precondition
    load_conversation_history() now relies on."""
    summary = ConversationSummary(
        conversation_id=None, username=partner_username, is_online=True, latest_message=None,
    )
    session.set_current_chat(summary)


def _open_group_chat(session, conversation_id):
    summary = ConversationSummary(
        conversation_id=conversation_id,
        username=None,
        is_online=False,
        latest_message=None,
        is_group=True,
    )
    session.set_current_chat(summary)


def _create_direct_conversation(user_a_id, user_b_id):
    db = SessionLocal()
    try:
        conversation_repo = ConversationRepository(db)
        conversation = conversation_repo.get_or_create_direct_conversation(
            uuid.UUID(user_a_id), uuid.UUID(user_b_id)
        )
        conversation_repo.commit()
        return str(conversation.id)
    finally:
        db.close()


def _create_group_conversation(member_ids, name):
    db = SessionLocal()
    try:
        conversation_repo = ConversationRepository(db)
        conversation = conversation_repo.create_group_conversation(
            [uuid.UUID(member_id) for member_id in member_ids], name
        )
        conversation_repo.commit()
        return str(conversation.id)
    finally:
        db.close()


def _insert_message(
    conversation_id,
    sender_id,
    receiver_id,
    ciphertext=None,
    blob_content=None,
    timestamp=None,
    payload_type=None,
    epoch=None,
    content_metadata=None,
):
    """Test-setup helper: insert a message row directly, exactly as
    persist_message() would -- optionally routing its content to real
    blob storage (blob_content) instead of the ciphertext column,
    matching persist_message()'s own BLOB_STORAGE_PAYLOAD_TYPES
    routing exactly."""
    blob_ref = None
    if blob_content is not None:
        blob_ref = encrypted_blob_store.store_blob(blob_content.encode("utf-8"))
        ciphertext = None

    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        message = message_repo.save_message(
            sender_id=uuid.UUID(sender_id),
            receiver_id=uuid.UUID(receiver_id),
            conversation_id=uuid.UUID(conversation_id),
            ciphertext=ciphertext,
            blob_ref=blob_ref,
            payload_type=payload_type,
            epoch=epoch,
            content_metadata=content_metadata,
            algorithm="KYBER",
            timestamp=timestamp or datetime.now(timezone.utc).replace(tzinfo=None),
        )
        message_repo.commit()
        return str(message.id), blob_ref
    finally:
        db.close()


def _mark_read(message_id, recipient_id):
    db = SessionLocal()
    try:
        from database.models.message_recipient import MessageRecipient

        db.add(
            MessageRecipient(
                message_id=uuid.UUID(message_id),
                recipient_id=uuid.UUID(recipient_id),
                status=MessageDeliveryStatus.READ,
            )
        )
        db.commit()
    finally:
        db.close()


def _add_recipient_row(message_id, recipient_id, status=MessageDeliveryStatus.QUEUED):
    db = SessionLocal()
    try:
        from database.models.message_recipient import MessageRecipient

        db.add(
            MessageRecipient(
                message_id=uuid.UUID(message_id),
                recipient_id=uuid.UUID(recipient_id),
                status=status,
            )
        )
        db.commit()
    finally:
        db.close()


def _request_history(sock, conversation_id, is_group):
    request_id = str(uuid.uuid4())
    _send(
        sock,
        {
            "type": "message_history_request",
            "conversation_id": conversation_id,
            "is_group": is_group,
            "request_id": request_id,
        },
    )
    response = _recv_until(
        sock,
        lambda p: p.get("type") == "message_history_result"
        and p.get("request_id") == request_id,
    )
    assert response is not None
    return response


def _request_blob(sock, message_id):
    request_id = str(uuid.uuid4())
    _send(
        sock,
        {
            "type": "blob_download_request",
            "message_id": message_id,
            "request_id": request_id,
        },
    )
    response = _recv_until(
        sock,
        lambda p: p.get("type") == "blob_download_result"
        and p.get("request_id") == request_id,
    )
    assert response is not None
    return response


# ----------------------------------------------------------------------
# A. Server-side protocol/security: raw TLS socket
# ----------------------------------------------------------------------


def test_message_history_request_direct_conversation_returns_messages(running_server):
    _state, port = running_server
    alice_payload = _register_user("direct_a_")
    bob_payload = _register_user("direct_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _insert_message(
        conversation_id, bob_payload["user_id"], alice_payload["user_id"],
        ciphertext="hello-from-bob", timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=False)
        assert response.get("error") is None
        messages = response["messages"]
        assert len(messages) == 1
        assert messages[0]["ciphertext"] == "hello-from-bob"
        assert messages[0]["sender"] == bob_payload["username"]
        assert messages[0]["is_own"] is False
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_message_history_request_group_conversation_returns_messages(running_server):
    _state, port = running_server
    alice_payload = _register_user("group_a_")
    bob_payload = _register_user("group_b_")
    carol_payload = _register_user("group_c_")

    conversation_id = _create_group_conversation(
        [alice_payload["user_id"], bob_payload["user_id"], carol_payload["user_id"]],
        "D4.3 Group",
    )
    _insert_message(
        conversation_id, carol_payload["user_id"], carol_payload["user_id"],
        ciphertext="group-hello", timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=True)
        assert response.get("error") is None
        messages = response["messages"]
        assert len(messages) == 1
        assert messages[0]["ciphertext"] == "group-hello"
        assert messages[0]["sender"] == carol_payload["username"]
        assert messages[0]["is_own"] is False
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])


def test_message_history_request_non_member_rejected_direct(running_server):
    _state, port = running_server
    alice_payload = _register_user("nonmem_a_")
    bob_payload = _register_user("nonmem_b_")
    eve_payload = _register_user("nonmem_e_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )

    sock, _eve_name = _connect_and_authenticate(port, eve_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=False)
        assert response.get("messages") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(eve_payload["username"])


def test_message_history_request_non_member_rejected_group(running_server):
    _state, port = running_server
    alice_payload = _register_user("gnonmem_a_")
    bob_payload = _register_user("gnonmem_b_")
    eve_payload = _register_user("gnonmem_e_")

    conversation_id = _create_group_conversation(
        [alice_payload["user_id"], bob_payload["user_id"]], "Exclusive Group",
    )

    sock, _eve_name = _connect_and_authenticate(port, eve_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=True)
        assert response.get("messages") is None
        assert response.get("error")

        # Connection must remain usable afterward.
        follow_up = _request_history(sock, conversation_id, is_group=True)
        assert follow_up.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(eve_payload["username"])


def test_message_history_request_missing_conversation_id_returns_error(running_server):
    _state, port = running_server
    alice_payload = _register_user("missing_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {"type": "message_history_request", "is_group": False, "request_id": request_id},
        )
        response = _recv_until(
            sock,
            lambda p: p.get("type") == "message_history_result"
            and p.get("request_id") == request_id,
        )
        assert response is not None
        assert response.get("messages") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_message_history_request_malformed_conversation_id_returns_error(running_server):
    _state, port = running_server
    alice_payload = _register_user("malform_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, "not-a-real-uuid", is_group=False)
        assert response.get("messages") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_message_history_request_missing_request_id_is_silently_ignored(running_server):
    _state, port = running_server
    alice_payload = _register_user("noid_a_")
    bob_payload = _register_user("noid_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        _send(
            sock,
            {
                "type": "message_history_request",
                "conversation_id": conversation_id,
                "is_group": False,
            },
        )
        no_response = _recv_until(
            sock, lambda p: p.get("type") == "message_history_result", attempts=5
        )
        assert no_response is None

        response = _request_history(sock, conversation_id, is_group=False)
        assert response.get("error") is None
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_message_history_request_id_correlation(running_server):
    _state, port = running_server
    alice_payload = _register_user("corr_a_")
    bob_payload = _register_user("corr_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext="ct-1",
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        first = _request_history(sock, conversation_id, is_group=False)
        second = _request_history(sock, conversation_id, is_group=False)
        assert first["messages"] == second["messages"]
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_message_history_request_sender_resolved_correctly(running_server):
    _state, port = running_server
    alice_payload = _register_user("sender_a_")
    bob_payload = _register_user("sender_b_")
    carol_payload = _register_user("sender_c_")

    conversation_id = _create_group_conversation(
        [alice_payload["user_id"], bob_payload["user_id"], carol_payload["user_id"]],
        "Sender Group",
    )
    _insert_message(
        conversation_id, alice_payload["user_id"], alice_payload["user_id"],
        ciphertext="from-alice", timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
    )
    _insert_message(
        conversation_id, carol_payload["user_id"], carol_payload["user_id"],
        ciphertext="from-carol", timestamp=_utc_now().replace(2026, 1, 1, 9, 5, 0),
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=True)
        messages = response["messages"]
        assert messages[0]["sender"] == alice_payload["username"]
        assert messages[0]["is_own"] is True
        assert messages[1]["sender"] == carol_payload["username"]
        assert messages[1]["is_own"] is False
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])


def test_message_history_request_read_status_direct(running_server):
    _state, port = running_server
    alice_payload = _register_user("rstat_a_")
    bob_payload = _register_user("rstat_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )

    unread_id, _ = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext="unread", timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
    )
    _add_recipient_row(unread_id, bob_payload["user_id"], status=MessageDeliveryStatus.QUEUED)

    read_id, _ = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext="read", timestamp=_utc_now().replace(2026, 1, 1, 9, 5, 0),
    )
    _mark_read(read_id, bob_payload["user_id"])

    legacy_id, _ = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext="legacy-no-recipient-row", timestamp=_utc_now().replace(2026, 1, 1, 9, 10, 0),
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=False)
        by_id = {m["message_id"]: m for m in response["messages"]}
        assert by_id[unread_id]["read_status"] is False
        assert by_id[read_id]["read_status"] is True
        assert by_id[legacy_id]["read_status"] is None
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_message_history_request_read_status_group_departed_member_excluded(running_server):
    """Mirrors test_read_receipts_integration.py's departed-member
    coverage: a departed member's un-read row must not block the
    "fully read" state."""
    _state, port = running_server
    alice_payload = _register_user("gdep_a_")
    bob_payload = _register_user("gdep_b_")
    carol_payload = _register_user("gdep_c_")

    conversation_id = _create_group_conversation(
        [alice_payload["user_id"], bob_payload["user_id"], carol_payload["user_id"]],
        "Departure Group",
    )

    message_id, _ = _insert_message(
        conversation_id, alice_payload["user_id"], alice_payload["user_id"],
        ciphertext="group-msg",
    )
    _mark_read(message_id, bob_payload["user_id"])
    _add_recipient_row(message_id, carol_payload["user_id"], status=MessageDeliveryStatus.QUEUED)

    # Carol leaves without ever reading it.
    db = SessionLocal()
    try:
        ConversationRepository(db).leave_conversation(
            uuid.UUID(conversation_id), uuid.UUID(carol_payload["user_id"])
        )
        db.commit()
    finally:
        db.close()

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=True)
        assert response["messages"][0]["read_status"] is True
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])


def test_message_history_request_ordering_matches_repository(running_server):
    _state, port = running_server
    alice_payload = _register_user("order_a_")
    bob_payload = _register_user("order_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext="first", timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
    )
    _insert_message(
        conversation_id, bob_payload["user_id"], alice_payload["user_id"],
        ciphertext="second", timestamp=_utc_now().replace(2026, 1, 1, 9, 5, 0),
    )
    _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext="third", timestamp=_utc_now().replace(2026, 1, 1, 9, 10, 0),
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=False)
        actual_order = [m["ciphertext"] for m in response["messages"]]

        db = SessionLocal()
        try:
            expected_order = [
                m.ciphertext
                for m in MessageRepository(db).get_conversation(
                    uuid.UUID(alice_payload["user_id"]), uuid.UUID(bob_payload["user_id"])
                )
            ]
        finally:
            db.close()

        assert actual_order == expected_order == ["first", "second", "third"]
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_message_history_request_ciphertext_unchanged(running_server):
    _state, port = running_server
    alice_payload = _register_user("ct_a_")
    bob_payload = _register_user("ct_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    original_ciphertext = "opaque-base64-ciphertext-blob-XYZ=="
    _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext=original_ciphertext,
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=False)
        assert response["messages"][0]["ciphertext"] == original_ciphertext
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_message_history_request_attachment_metadata_without_ciphertext(running_server):
    _state, port = running_server
    alice_payload = _register_user("att_a_")
    bob_payload = _register_user("att_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    message_id, blob_ref = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        blob_content="opaque-encrypted-file-bytes",
        payload_type=PayloadType.FILE,
        content_metadata={"filename": "report.pdf"},
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_history(sock, conversation_id, is_group=False)
        entry = response["messages"][0]
        assert entry["message_id"] == message_id
        assert entry["payload_type"] == PayloadType.FILE
        assert entry["blob_ref"] == blob_ref
        assert entry["ciphertext"] is None
        assert entry["content_metadata"]["filename"] == "report.pdf"
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        encrypted_blob_store.delete_blob(blob_ref)


def test_blob_download_request_authorized_member_can_download(running_server):
    _state, port = running_server
    alice_payload = _register_user("dl_a_")
    bob_payload = _register_user("dl_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    message_id, blob_ref = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        blob_content="the-real-encrypted-bytes",
        payload_type=PayloadType.FILE,
    )

    sock, _bob_name = _connect_and_authenticate(port, bob_payload)

    try:
        response = _request_blob(sock, message_id)
        assert response.get("error") is None
        assert response["ciphertext"] == "the-real-encrypted-bytes"
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        encrypted_blob_store.delete_blob(blob_ref)


def test_blob_download_request_unauthorized_member_rejected(running_server):
    _state, port = running_server
    alice_payload = _register_user("noauth_a_")
    bob_payload = _register_user("noauth_b_")
    eve_payload = _register_user("noauth_e_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    message_id, blob_ref = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        blob_content="secret-bytes", payload_type=PayloadType.FILE,
    )

    sock, _eve_name = _connect_and_authenticate(port, eve_payload)

    try:
        response = _request_blob(sock, message_id)
        assert response.get("ciphertext") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(eve_payload["username"])
        encrypted_blob_store.delete_blob(blob_ref)


def test_blob_download_request_unknown_message_id_rejected(running_server):
    _state, port = running_server
    alice_payload = _register_user("unknown_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_blob(sock, str(uuid.uuid4()))
        assert response.get("ciphertext") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_blob_download_request_missing_blob_ref_rejected(running_server):
    """A TEXT message (no attachment) requested through the blob
    endpoint must be rejected distinctly -- authorization already
    succeeded (the caller IS a member), it simply isn't a blob
    message."""
    _state, port = running_server
    alice_payload = _register_user("noblob_a_")
    bob_payload = _register_user("noblob_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    message_id, _ = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        ciphertext="plain-text-message",
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_blob(sock, message_id)
        assert response.get("ciphertext") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_blob_download_request_missing_request_id_is_silently_ignored(running_server):
    _state, port = running_server
    alice_payload = _register_user("bnoid_a_")
    bob_payload = _register_user("bnoid_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    message_id, blob_ref = _insert_message(
        conversation_id, alice_payload["user_id"], bob_payload["user_id"],
        blob_content="bytes", payload_type=PayloadType.FILE,
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        _send(sock, {"type": "blob_download_request", "message_id": message_id})
        no_response = _recv_until(
            sock, lambda p: p.get("type") == "blob_download_result", attempts=5
        )
        assert no_response is None

        response = _request_blob(sock, message_id)
        assert response.get("error") is None
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        encrypted_blob_store.delete_blob(blob_ref)


# ----------------------------------------------------------------------
# B. Client consumption: real ClientSession, real receiver thread
# ----------------------------------------------------------------------


def test_load_conversation_history_direct_end_to_end(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("e2e_a_")
    bob_payload = _register_user("e2e_b_")

    session_key = b"K" * 32
    plaintext = "a real decryptable message"
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _insert_message(
        conversation_id, bob_payload["user_id"], alice_payload["user_id"],
        ciphertext=ciphertext,
    )

    alice = _make_connected_session(alice_payload)

    try:
        _open_direct_chat(alice, bob_payload["username"])
        alice.key_manager.store_key(alice.current_conversation_id, session_key)

        history = alice.load_conversation_history(bob_payload["username"])

        assert len(history) == 1
        assert history[0]["text"] == plaintext
        assert history[0]["is_own"] is False
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_load_conversation_history_returns_placeholder_without_session_key(
    running_server, monkeypatch
):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("noplace_a_")
    bob_payload = _register_user("noplace_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _insert_message(
        conversation_id, bob_payload["user_id"], alice_payload["user_id"],
        ciphertext="opaque-ciphertext-no-real-key",
    )

    alice = _make_connected_session(alice_payload)

    try:
        _open_direct_chat(alice, bob_payload["username"])

        history = alice.load_conversation_history(bob_payload["username"])

        assert len(history) == 1
        assert history[0]["text"] == "Message unavailable (encrypted in a previous session)"
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_load_conversation_history_group_end_to_end(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("ge2e_a_")
    bob_payload = _register_user("ge2e_b_")

    session_key = b"G" * 32
    plaintext = "group plaintext"
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    conversation_id = _create_group_conversation(
        [alice_payload["user_id"], bob_payload["user_id"]], "E2E Group",
    )
    _insert_message(
        conversation_id, bob_payload["user_id"], bob_payload["user_id"],
        ciphertext=ciphertext,
    )

    alice = _make_connected_session(alice_payload)

    try:
        alice.key_manager.store_key(conversation_id, session_key)
        _open_group_chat(alice, conversation_id)

        history = alice.load_conversation_history(conversation_id, is_group=True)

        assert len(history) == 1
        assert history[0]["text"] == plaintext
        assert history[0]["sender"] == bob_payload["username"]
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_load_conversation_history_attachment_through_history_and_blob_request(
    running_server, monkeypatch
):
    """The full Option A round trip: history carries only blob_ref,
    load_conversation_history() fetches the actual bytes via a
    separate blob_download_request internally, and the result decrypts
    correctly -- exactly like a real file attachment."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("fatt_a_")
    bob_payload = _register_user("fatt_b_")

    session_key = b"F" * 32
    original_bytes = b"history round trip content \x00\xff"
    content_metadata = {"filename": "history.bin", "size_bytes": len(original_bytes)}

    envelope = FilePayloadAdapter(PayloadType.FILE).encrypt(
        original_bytes, AESCipher(session_key), content_metadata=content_metadata
    )

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _message_id, blob_ref = _insert_message(
        conversation_id, bob_payload["user_id"], alice_payload["user_id"],
        blob_content=envelope.ciphertext,
        payload_type=PayloadType.FILE,
        content_metadata=content_metadata,
    )

    alice = _make_connected_session(alice_payload)

    try:
        _open_direct_chat(alice, bob_payload["username"])
        alice.key_manager.store_key(alice.current_conversation_id, session_key)

        history = alice.load_conversation_history(bob_payload["username"])

        assert len(history) == 1
        assert history[0]["payload_type"] == PayloadType.FILE
        assert history[0]["content"] == original_bytes
        assert history[0]["content_metadata"]["filename"] == "history.bin"
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        encrypted_blob_store.delete_blob(blob_ref)


def test_load_conversation_history_returns_empty_when_current_conversation_id_is_none(
    running_server, monkeypatch
):
    """A conversation that was never opened via set_current_chat()
    has no current_conversation_id -- load_conversation_history() must
    return [] without sending any request at all."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("noconv_a_")
    alice = _make_connected_session(alice_payload)

    try:
        assert alice.current_conversation_id is None

        with mock.patch.object(
            ClientSession,
            "send_request",
            side_effect=AssertionError(
                "load_conversation_history() must not send any request when "
                "current_conversation_id is None"
            ),
        ):
            history = alice.load_conversation_history("someone")

        assert history == []
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])


def test_client_session_module_has_no_database_or_storage_imports():
    """Static proof that client.session no longer imports any
    database/storage access point at all (D4.3 -- the last remaining
    client-side database and local-storage access, removed). Not a
    mock/patch proof: SessionLocal, ConversationRepository,
    MessageRepository, UserRepository, and encrypted_blob_store are
    all still real, importable names elsewhere (the server legitimately
    needs every one of them, running in-process on a background thread
    throughout this test file) -- patching them globally would break
    the server's own handlers, not prove anything about the client.
    The only correct proof left is that client.session's own module
    namespace simply never bound these names in the first place."""

    for name in (
        "SessionLocal",
        "ConversationRepository",
        "MessageRepository",
        "UserRepository",
        "encrypted_blob_store",
        "Conversation",
    ):
        assert not hasattr(client_session_module, name), (
            f"client.session must not import {name} (D4.3)"
        )


def test_load_conversation_history_full_round_trip_needs_no_local_access(
    running_server, monkeypatch
):
    """Behavioral companion to the static import-absence proof above:
    a real conversation mixing a TEXT message and a FILE attachment --
    exercising both message_history_request and blob_download_request
    -- loads and decrypts correctly end-to-end through nothing but the
    real server and real network, on a session that never had local
    database or blob-storage access available to it in the first
    place (see the static proof test)."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("nodb_a_")
    bob_payload = _register_user("nodb_b_")

    session_key = b"N" * 32
    plaintext = "a real text message needing no database access"
    original_bytes = b"no database access needed for this"
    envelope = FilePayloadAdapter(PayloadType.FILE).encrypt(
        original_bytes, AESCipher(session_key), content_metadata={"filename": "n.bin"}
    )

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _insert_message(
        conversation_id, bob_payload["user_id"], alice_payload["user_id"],
        ciphertext=AESCipher(session_key).encrypt(plaintext),
        timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
    )
    _message_id, blob_ref = _insert_message(
        conversation_id, bob_payload["user_id"], alice_payload["user_id"],
        blob_content=envelope.ciphertext,
        payload_type=PayloadType.FILE,
        content_metadata={"filename": "n.bin"},
        timestamp=_utc_now().replace(2026, 1, 1, 9, 5, 0),
    )

    alice = _make_connected_session(alice_payload)

    try:
        _open_direct_chat(alice, bob_payload["username"])
        alice.key_manager.store_key(alice.current_conversation_id, session_key)

        history = alice.load_conversation_history(bob_payload["username"])

        assert len(history) == 2
        assert history[0]["text"] == plaintext
        assert history[1]["content"] == original_bytes
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        encrypted_blob_store.delete_blob(blob_ref)
