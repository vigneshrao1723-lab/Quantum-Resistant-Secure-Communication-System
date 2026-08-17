"""
Tests for D4.1 (Message/History Operations Migration, first slice):
epoch_reservation_request/epoch_reservation_result -- the request/
response replacement for ClientSession.establish_session_key()'s
previous direct, client-side ConversationRepository.
reserve_next_epoch() call, the last remaining client-side database
write anywhere in direct-conversation key establishment.

The protocol/security tests use a raw TLS socket against the real
server.client_handler.handle_client accept loop -- the same harness
pattern as test_direct_conversation_request_response.py -- to prove
the server-side behavior (membership authorization, request/response
correlation, graceful error handling for a missing/malformed/
nonexistent conversation_id) independent of what the real client would
ever actually send. The client-consumption tests use a real, fully
connected ClientSession with a real receiver thread, proving
establish_session_key() no longer touches the database and that
ordinary encrypted key exchange -- and a real encrypted chat message
riding on top of it -- still work end-to-end.

Run with:
    pytest tests/test_epoch_reservation_request_response.py -v
"""

import json
import socket
import struct
import threading
import time
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
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


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "D4.1 Epoch Reservation Test",
            "username": f"d41_{suffix_hint}{suffix}",
            "email": f"d41_{suffix_hint}{suffix}@example.com",
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
    -> start_receiver() -- required because establish_session_key()
    now uses send_request() (D4.1), which can only be resolved by a
    running receiver thread reading real socket data."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _create_direct_conversation(user_a_id, user_b_id):
    """Test-setup helper: create the real direct conversation between
    two users ahead of time, via the same repository method the
    server itself uses -- so a test can target a real conversation_id
    without first driving a full chat/direct_conversation_request
    round trip."""
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


def _open_direct_chat(session, partner_username):
    """Mirrors ChatWindow.open_conversation() enough to mark a direct
    conversation current -- resolves/creates the real conversation via
    ClientSession._resolve_direct_conversation_id() (D3.3), not a
    direct database call."""
    summary = ConversationSummary(
        conversation_id=None,
        username=partner_username,
        is_online=True,
        latest_message=None,
    )
    session.set_current_chat(summary)


def _wait_for(predicate, attempts=100, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ----------------------------------------------------------------------
# A. Server-side protocol/security: raw TLS socket
# ----------------------------------------------------------------------


def test_epoch_reservation_request_member_can_reserve(running_server):
    _state, port = running_server
    alice_payload = _register_user("alice_")
    bob_payload = _register_user("bob_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": conversation_id,
                "request_id": request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("error") is None
        # Conversation.current_key_epoch defaults to 1 -- the first
        # reservation on a freshly created conversation always yields 2
        # (see database/models/conversation.py, and
        # test_conversation_repository.py's identical assertion at the
        # repository layer).
        assert response["epoch"] == 2
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_epoch_reservation_request_non_member_is_rejected(running_server):
    """Security: an authenticated user who is not a member of the
    requested conversation must not be able to reserve an epoch for
    it -- the exact authorization gap a direct, client-side database
    call never had a boundary for at all. The connection must remain
    usable afterward: a legitimate request for a conversation the
    caller genuinely belongs to still succeeds on the same socket."""
    _state, port = running_server
    alice_payload = _register_user("nonmem_a_")
    bob_payload = _register_user("nonmem_b_")
    carol_payload = _register_user("nonmem_c_")
    dave_payload = _register_user("nonmem_d_")

    alice_bob_conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )
    carol_dave_conversation_id = _create_direct_conversation(
        carol_payload["user_id"], dave_payload["user_id"]
    )

    sock, _carol_name = _connect_and_authenticate(port, carol_payload)

    try:
        rejected_request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": alice_bob_conversation_id,
                "request_id": rejected_request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert response is not None
        assert response["request_id"] == rejected_request_id
        assert response.get("epoch") is None
        assert response.get("error")

        # Connection must still be alive: a real, well-formed request
        # for a conversation carol genuinely belongs to still succeeds.
        follow_up_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": carol_dave_conversation_id,
                "request_id": follow_up_id,
            },
        )
        follow_up = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert follow_up is not None
        assert follow_up["request_id"] == follow_up_id
        assert follow_up.get("error") is None
        assert follow_up["epoch"] == 2
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])
        _delete_user(carol_payload["username"])
        _delete_user(dave_payload["username"])


def test_epoch_reservation_request_unauthenticated_is_rejected(running_server):
    """Regression guard, matching test_registration_integration.py's
    established "unrecognized first packet" proof: an
    epoch_reservation_request sent before authentication never reaches
    handle_epoch_reservation_request() at all -- it falls through
    authenticate_connection()'s existing fallback rejection."""
    _state, port = running_server

    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))
    try:
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": str(uuid.uuid4()),
                "request_id": str(uuid.uuid4()),
            },
        )
        response = _recv(sock)

        assert response["type"] == "auth_result"
        assert response["success"] is False
    finally:
        sock.close()


def test_epoch_reservation_request_missing_conversation_id_returns_error(running_server):
    _state, port = running_server
    alice_payload = _register_user("missing_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                # deliberately no conversation_id
                "request_id": request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("epoch") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_epoch_reservation_request_malformed_conversation_id_returns_error(running_server):
    _state, port = running_server
    alice_payload = _register_user("malform_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": "not-a-real-uuid",
                "request_id": request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("epoch") is None
        assert response.get("error")

        # Connection must still be alive after a malformed field.
        follow_up_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": "still-not-a-uuid",
                "request_id": follow_up_id,
            },
        )
        follow_up = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert follow_up is not None
        assert follow_up["request_id"] == follow_up_id
        assert follow_up.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_epoch_reservation_request_nonexistent_conversation_id_returns_error(running_server):
    """A well-formed UUID that simply doesn't correspond to any real
    conversation must be rejected exactly like a genuine non-member
    request -- get_member_user_ids() returns no rows either way, so
    there is nothing here to distinguish a bad guess from a forbidden
    one, matching this codebase's existing "don't let an error message
    reveal which guess was closer" convention."""
    _state, port = running_server
    alice_payload = _register_user("noexist_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": str(uuid.uuid4()),
                "request_id": request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("epoch") is None
        assert response.get("error")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_epoch_reservation_request_missing_request_id_is_silently_ignored(running_server):
    """Unlike login/register (pre-auth, connection torn down on a
    missing request_id), epoch_reservation_request is dispatched
    inside the authenticated loop -- a missing request_id must be
    ignored without killing the connection."""
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
                "type": "epoch_reservation_request",
                "conversation_id": conversation_id,
                # deliberately no request_id
            },
        )

        no_response = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result", attempts=5
        )
        assert no_response is None

        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "epoch_reservation_request",
                "conversation_id": conversation_id,
                "request_id": request_id,
            },
        )
        response = _recv_until(
            sock, lambda p: p.get("type") == "epoch_reservation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("epoch") == 2
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_epoch_reservation_request_id_correlation_and_increment(running_server):
    """Two distinct requests for the same conversation, correlated by
    their own request_id, and each reservation genuinely advances the
    shared counter -- proving both D1 correlation and the underlying
    reserve_next_epoch() semantics survive the move behind the
    server unchanged."""
    _state, port = running_server
    alice_payload = _register_user("corr_a_")
    bob_payload = _register_user("corr_b_")

    conversation_id = _create_direct_conversation(
        alice_payload["user_id"], bob_payload["user_id"]
    )

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        def _ask():
            request_id = str(uuid.uuid4())
            _send(
                sock,
                {
                    "type": "epoch_reservation_request",
                    "conversation_id": conversation_id,
                    "request_id": request_id,
                },
            )
            response = _recv_until(
                sock,
                lambda p: p.get("type") == "epoch_reservation_result"
                and p.get("request_id") == request_id,
            )
            assert response is not None
            assert response["request_id"] == request_id
            return response["epoch"]

        first = _ask()
        second = _ask()

        assert first == 2
        assert second == 3
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


# ----------------------------------------------------------------------
# B. Client consumption: real ClientSession, real receiver thread
# ----------------------------------------------------------------------


@pytest.fixture()
def alice_and_bob(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("cliab_")
    bob_payload = _register_user("clibb_")

    alice = _make_connected_session(alice_payload)
    bob = _make_connected_session(bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    yield {"alice": alice, "bob": bob}

    alice.disconnect()
    bob.disconnect()
    _delete_user(alice_payload["username"])
    _delete_user(bob_payload["username"])


def test_establish_session_key_uses_request_response_not_database(alice_and_bob):
    alice = alice_and_bob["alice"]
    bob = alice_and_bob["bob"]

    _open_direct_chat(alice, bob.username)
    conversation_id = alice.current_conversation_id
    assert conversation_id is not None

    assert alice.key_manager.has_key(conversation_id) is False

    # SessionLocal/ConversationRepository (the database entry points
    # this test used to also prove establish_session_key() never fell
    # back to) are no longer imported anywhere in client/session.py at
    # all -- D4.3 migrated load_conversation_history(), the module's
    # last remaining user of either name, so patching them here would
    # itself raise AttributeError rather than proving anything; the
    # assertions below already fully prove the request/response path
    # was used.
    alice.establish_session_key()

    assert alice.key_manager.has_key(conversation_id) is True
    # The reserved epoch (2 -- see the server-side test's identical
    # assertion) is what the key was actually stored under, not just
    # some value.
    assert alice.key_manager.current_epoch(conversation_id) == 2

    assert _wait_for(
        lambda: bob.key_manager.get_key(conversation_id) is not None
    )
    assert bob.key_manager.current_epoch(conversation_id) == 2


def test_direct_chat_end_to_end_still_works_through_establish_session_key(alice_and_bob):
    """The end-to-end regression check requirement 8/9 call for:
    ordinary encrypted direct chat -- handshake, real key exchange via
    establish_session_key() (now server-request-based), AES-GCM
    encrypt/decrypt -- is completely unaffected by moving epoch
    reservation behind the server. send_chat_message() drives
    establish_session_key() internally, exactly as gui/chat_window.py
    does; nothing about encryption/decryption itself is touched by
    D4.1."""
    alice = alice_and_bob["alice"]
    bob = alice_and_bob["bob"]

    _open_direct_chat(alice, bob.username)
    _open_direct_chat(bob, alice.username)

    alice.send_chat_message("hello bob, this should still work under D4.1")

    def _bob_received():
        summary = bob.conversation_store.get(alice.username)
        return (
            summary is not None
            and summary.latest_message is not None
            and summary.latest_message.text
            == "hello bob, this should still work under D4.1"
        )

    assert _wait_for(_bob_received)


def test_establish_session_key_raises_for_a_conversation_not_a_member_of(
    running_server, monkeypatch
):
    """Defense in depth: even if a client's own local state were
    forged or corrupted into pointing current_conversation_id at a
    conversation it is not actually a member of, the server-side
    membership check (requirement 5) still refuses to reserve an
    epoch for it -- establish_session_key() must surface that as a
    ValueError (mirroring _resolve_direct_conversation_id()'s
    identical error-field-to-exception contract), not silently
    proceed or crash."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("forge_a_")
    carol_payload = _register_user("forge_c_")
    dave_payload = _register_user("forge_d_")

    carol_dave_conversation_id = _create_direct_conversation(
        carol_payload["user_id"], dave_payload["user_id"]
    )

    alice = _make_connected_session(alice_payload)

    try:
        alice.current_chat = dave_payload["username"]
        alice.current_chat_is_group = False
        alice.current_conversation_id = carol_dave_conversation_id

        with pytest.raises(ValueError):
            alice.establish_session_key()
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(carol_payload["username"])
        _delete_user(dave_payload["username"])
