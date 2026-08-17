"""
Tests for D4.2 (Message/History Operations Migration, second slice):
conversation_list_request/conversation_list_result -- the request/
response replacement for ClientSession.load_conversations()'s
previous direct, client-side ConversationRepository.
get_conversation_previews_for_user() call, the last remaining client-
side database read for the sidebar's initial population.

The protocol/security tests use a raw TLS socket against the real
server.client_handler.handle_client accept loop -- the same harness
pattern as test_direct_conversation_request_response.py and
test_epoch_reservation_request_response.py -- to prove the server-side
behavior (identity scoping, request/response correlation, exact data
preserved) independent of what the real client would ever actually
send. The client-consumption tests use a real, fully connected
ClientSession with a real receiver thread, proving load_conversations()
no longer touches the database and that the resulting
ConversationStore/ConversationSummary/MessagePreview data is unchanged
from what the old direct-DB implementation produced.

Run with:
    pytest tests/test_conversation_list_request_response.py -v
"""

import json
import socket
import struct
import threading
import uuid
from datetime import datetime, timezone

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
from security.tls import build_server_context
from server.client_handler import handle_client
from server.server_state import ServerState
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
            "full_name": "D4.2 Conversation List Test",
            "username": f"d42_{suffix_hint}{suffix}",
            "email": f"d42_{suffix_hint}{suffix}@example.com",
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
    -> start_receiver() -- required because load_conversations() now
    uses send_request() (D4.2), which can only be resolved by a
    running receiver thread reading real socket data. Mirrors
    gui/main_window.py::start_chat_session()'s now-corrected sequence
    (D4.2 also fixed that ordering -- see gui/main_window.py)."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


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
    ciphertext,
    timestamp=None,
    payload_type=None,
    epoch=None,
    content_metadata=None,
):
    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        message = message_repo.save_message(
            sender_id=uuid.UUID(sender_id),
            receiver_id=uuid.UUID(receiver_id),
            conversation_id=uuid.UUID(conversation_id),
            ciphertext=ciphertext,
            algorithm="KYBER",
            timestamp=timestamp or datetime.now(timezone.utc).replace(tzinfo=None),
            payload_type=payload_type,
            epoch=epoch,
            content_metadata=content_metadata,
        )
        message_repo.commit()
        return message.id
    finally:
        db.close()


def _request_conversation_list(sock):
    request_id = str(uuid.uuid4())
    _send(
        sock,
        {"type": "conversation_list_request", "request_id": request_id},
    )
    response = _recv_until(
        sock,
        lambda p: p.get("type") == "conversation_list_result"
        and p.get("request_id") == request_id,
    )
    assert response is not None
    return response


# ----------------------------------------------------------------------
# A. Server-side protocol/security: raw TLS socket
# ----------------------------------------------------------------------


def test_conversation_list_request_empty_for_new_user(running_server):
    _state, port = running_server
    alice_payload = _register_user("empty_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_conversation_list(sock)
        assert response["conversations"] == []
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_conversation_list_request_returns_only_own_conversations(running_server):
    _state, port = running_server
    alice_payload = _register_user("own_a_")
    bob_payload = _register_user("own_b_")
    carol_payload = _register_user("own_c_")
    dave_payload = _register_user("own_d_")

    # alice belongs to a conversation with bob; carol+dave's
    # conversation has nothing to do with alice at all.
    alice_bob_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    _create_direct_conversation(carol_payload["user_id"], dave_payload["user_id"])

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_conversation_list(sock)
        conversation_ids = {c["conversation_id"] for c in response["conversations"]}
        assert conversation_ids == {alice_bob_id}
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])
        _delete_user(dave_payload["username"])


def test_conversation_list_request_ignores_client_supplied_user_id(running_server):
    """Security: the request carries no legitimate identity field at
    all (create_conversation_list_request_packet() sends only
    {type, request_id}), but a malicious/modified client could still
    inject an arbitrary "user_id" field into the raw packet. The
    server must derive the caller entirely from the authenticated
    connection (user.id) and ignore any such field -- alice must never
    be able to see bob's conversations this way."""
    _state, port = running_server
    alice_payload = _register_user("forge_a_")
    bob_payload = _register_user("forge_b_")
    eve_payload = _register_user("forge_e_")

    bob_eve_id = _create_direct_conversation(
        bob_payload["user_id"], eve_payload["user_id"]
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "conversation_list_request",
                "request_id": request_id,
                # forged field -- must be silently ignored
                "user_id": bob_payload["user_id"],
            },
        )
        response = _recv_until(
            sock,
            lambda p: p.get("type") == "conversation_list_result"
            and p.get("request_id") == request_id,
        )
        assert response is not None

        conversation_ids = {c["conversation_id"] for c in response["conversations"]}
        # alice has no conversations of her own, and specifically does
        # NOT see bob and eve's conversation despite supplying bob's
        # user_id in the packet.
        assert conversation_ids == set()
        assert bob_eve_id not in conversation_ids
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(eve_payload["username"])


def test_conversation_list_request_direct_conversation_shape_is_correct(running_server):
    _state, port = running_server
    alice_payload = _register_user("shape_a_")
    bob_payload = _register_user("shape_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_conversation_list(sock)
        assert len(response["conversations"]) == 1

        entry = response["conversations"][0]
        assert entry["conversation_id"] == conversation_id
        assert entry["is_group"] is False
        assert entry["participants"] == [bob_payload["username"]]
        assert entry["latest_message"] is None
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_conversation_list_request_group_conversation_shape_is_correct(running_server):
    _state, port = running_server
    alice_payload = _register_user("grp_a_")
    bob_payload = _register_user("grp_b_")
    carol_payload = _register_user("grp_c_")

    conversation_id = _create_group_conversation(
        [alice_payload["user_id"], bob_payload["user_id"], carol_payload["user_id"]],
        "D4.2 Test Group",
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_conversation_list(sock)
        assert len(response["conversations"]) == 1

        entry = response["conversations"][0]
        assert entry["conversation_id"] == conversation_id
        assert entry["is_group"] is True
        assert entry["group_name"] == "D4.2 Test Group"
        assert sorted(entry["participants"]) == sorted(
            [bob_payload["username"], carol_payload["username"]]
        )
        assert entry["latest_message"] is None
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])


def test_conversation_list_request_preserves_latest_message_data(running_server):
    _state, port = running_server
    alice_payload = _register_user("msg_a_")
    bob_payload = _register_user("msg_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )

    timestamp = _utc_now().replace(2026, 1, 1, 10, 30, 0)

    _insert_message(
        conversation_id,
        sender_id=bob_payload["user_id"],
        receiver_id=alice_payload["user_id"],
        ciphertext="opaque-ciphertext-blob",
        timestamp=timestamp,
        payload_type="text",
        epoch=3,
        content_metadata={"note": "irrelevant-but-present"},
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_conversation_list(sock)
        entry = response["conversations"][0]
        latest_message = entry["latest_message"]

        assert latest_message is not None
        assert latest_message["ciphertext"] == "opaque-ciphertext-blob"
        assert latest_message["payload_type"] == "text"
        assert latest_message["epoch"] == 3
        assert latest_message["content_metadata"] == {"note": "irrelevant-but-present"}
        assert latest_message["timestamp"] == timestamp.isoformat()
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_conversation_list_request_ordering_matches_latest_activity(running_server):
    """The packet's list order must match
    ConversationRepository.get_conversation_previews_for_user()'s own
    ordering exactly -- most recent activity first -- cross-checked
    directly against the repository, independent of the server
    handler's own code."""
    _state, port = running_server
    alice_payload = _register_user("order_a_")
    bob_payload = _register_user("order_b_")
    carol_payload = _register_user("order_c_")

    older_conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    newer_conversation_id = _create_direct_conversation(
        alice_payload["user_id"], carol_payload["user_id"]
    )

    _insert_message(
        older_conversation_id,
        sender_id=alice_payload["user_id"],
        receiver_id=bob_payload["user_id"],
        ciphertext="older",
        timestamp=_utc_now().replace(2026, 1, 1, 10, 0, 0),
    )
    _insert_message(
        newer_conversation_id,
        sender_id=alice_payload["user_id"],
        receiver_id=carol_payload["user_id"],
        ciphertext="newer",
        timestamp=_utc_now().replace(2026, 1, 1, 11, 0, 0),
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        response = _request_conversation_list(sock)
        actual_order = [c["conversation_id"] for c in response["conversations"]]

        db = SessionLocal()
        try:
            expected_order = [
                str(preview.conversation.id)
                for preview in ConversationRepository(db).get_conversation_previews_for_user(
                    uuid.UUID(alice_payload["user_id"])
                )
            ]
        finally:
            db.close()

        assert actual_order == expected_order
        assert actual_order == [newer_conversation_id, older_conversation_id]
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])


def test_conversation_list_request_id_correlation(running_server):
    _state, port = running_server
    alice_payload = _register_user("corr_a_")
    bob_payload = _register_user("corr_b_")

    _create_direct_conversation(alice_payload["user_id"], bob_payload["user_id"])

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        first = _request_conversation_list(sock)
        second = _request_conversation_list(sock)

        assert first["conversations"] == second["conversations"]
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_conversation_list_request_missing_request_id_is_silently_ignored(running_server):
    """Unlike login/register (pre-auth, connection torn down on a
    missing request_id), conversation_list_request is dispatched
    inside the authenticated loop -- a missing request_id must be
    ignored without killing the connection."""
    _state, port = running_server
    alice_payload = _register_user("noid_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        _send(sock, {"type": "conversation_list_request"})

        no_response = _recv_until(
            sock, lambda p: p.get("type") == "conversation_list_result", attempts=5
        )
        assert no_response is None

        response = _request_conversation_list(sock)
        assert response["conversations"] == []
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


# ----------------------------------------------------------------------
# B. Client consumption: real ClientSession, real receiver thread
# ----------------------------------------------------------------------


def test_load_conversations_uses_request_response_not_database(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("nodb_a_")
    bob_payload = _register_user("nodb_b_")

    _create_direct_conversation(alice_payload["user_id"], bob_payload["user_id"])

    session = _make_connected_session(alice_payload)

    try:
        # SessionLocal/ConversationRepository (the database entry
        # points this test used to also prove load_conversations()
        # never fell back to) are no longer imported anywhere in
        # client/session.py at all -- D4.3 migrated
        # load_conversation_history(), the module's last remaining
        # user of either name, so patching them here would itself
        # raise AttributeError rather than proving anything; the
        # assertions below already fully prove the request/response
        # path was used.
        session.load_conversations()

        summaries = session.conversation_store.get_all()
        assert len(summaries) == 1
        assert summaries[0].username == bob_payload["username"]
    finally:
        session.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_load_conversations_populates_summaries_compatibly(running_server, monkeypatch):
    """End-to-end compatibility proof: direct conversation, group
    conversation, and a real decrypted latest-message preview all
    still end up in conversation_store exactly as
    load_conversations()'s pre-D4.2 direct-DB implementation would
    have left them."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("compat_a_")
    bob_payload = _register_user("compat_b_")
    carol_payload = _register_user("compat_c_")

    direct_conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    group_conversation_id = _create_group_conversation(
        [alice_payload["user_id"], bob_payload["user_id"], carol_payload["user_id"]],
        "Compat Group",
    )

    session_key = b"0" * 32
    plaintext = "a real decrypted preview"
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    _insert_message(
        direct_conversation_id,
        sender_id=bob_payload["user_id"],
        receiver_id=alice_payload["user_id"],
        ciphertext=ciphertext,
        timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
        payload_type="text",
        epoch=1,
    )

    session = _make_connected_session(alice_payload)

    try:
        # Pre-cache the key exactly as an already-established
        # conversation would have it, so the preview's decrypt path is
        # exercised for real, not just the undecryptable fallback.
        session.key_manager.store_key(direct_conversation_id, session_key, epoch=1)

        session.load_conversations()

        direct_summary = session.conversation_store.get(bob_payload["username"])
        assert direct_summary is not None
        assert direct_summary.conversation_id == direct_conversation_id
        assert direct_summary.is_group is False
        assert direct_summary.latest_message is not None
        assert direct_summary.latest_message.text == plaintext

        group_summary = session.conversation_store.get(group_conversation_id)
        assert group_summary is not None
        assert group_summary.is_group is True
        assert group_summary.group_name == "Compat Group"
        assert sorted(group_summary.participants) == sorted(
            [bob_payload["username"], carol_payload["username"]]
        )
        assert group_summary.latest_message is None
    finally:
        session.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])
