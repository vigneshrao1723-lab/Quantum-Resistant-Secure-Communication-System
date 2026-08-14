"""
Tests for D3.3 (Conversation Operations Migration, third slice):
direct_conversation_request/direct_conversation_result -- the
request/response counterpart to what D3.1 already resolves
automatically ahead of a direct chat/session_key relay, used for the
one client-side caller that isn't triggered by an incoming packet at
all: ClientSession.set_current_chat() opening a chat with someone
never messaged before (a genuine "create", unlike every other former
caller of ConversationStore.ensure_direct_conversation_id(), which by
this point either already has the id from a relayed packet (D3.2) or
is left for a later slice).

The protocol/security tests use a raw TLS socket against the real
server.client_handler.handle_client accept loop -- the same harness
pattern as test_direct_conversation_relay_resolution.py -- to prove
the server-side behavior independent of what the real client would
ever actually send. The client-consumption tests use a real, fully
connected ClientSession with a real receiver thread, mirroring
test_receiver_thread_conversation_id_consumption.py's rigor: proving
ConversationStore.ensure_direct_conversation_id() (the database-
touching method) is never called from set_current_chat() anymore, not
merely assuming it.

Run with:
    pytest tests/test_direct_conversation_request_response.py -v
"""

import json
import socket
import struct
import threading
import uuid
from unittest import mock

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.conversation_store import ConversationStore
from client.session import ClientSession
from database.connection import SessionLocal
from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
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
            "full_name": "D3.3 Direct Conversation Request Test",
            "username": f"d33_{suffix_hint}{suffix}",
            "email": f"d33_{suffix_hint}{suffix}@example.com",
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


def _find_direct_conversation_id(user_a_id, user_b_id):
    db = SessionLocal()
    try:
        conversation = ConversationRepository(db)._find_direct_conversation(
            uuid.UUID(user_a_id), uuid.UUID(user_b_id)
        )
        return str(conversation.id) if conversation else None
    finally:
        db.close()


def _make_connected_session(payload):
    """Real ClientSession: connect() -> login() -> send_public_key()
    -> start_receiver() -- required because set_current_chat() now
    uses send_request() (D3.3), which can only be resolved by a
    running receiver thread reading real socket data."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


# ----------------------------------------------------------------------
# A. Server-side protocol/security: raw TLS socket
# ----------------------------------------------------------------------


def test_direct_conversation_request_creates_and_returns_conversation_id(running_server):
    _state, port = running_server
    alice_payload = _register_user("alice_")
    bob_payload = _register_user("bob_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "direct_conversation_request",
                "username": bob_payload["username"],
                "request_id": request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "direct_conversation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("error") is None
        assert response.get("conversation_id")
        uuid.UUID(response["conversation_id"])

        expected = _find_direct_conversation_id(
            alice_payload["user_id"], bob_payload["user_id"]
        )
        assert expected is not None
        assert response["conversation_id"] == expected
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_direct_conversation_request_is_idempotent_get_or_create(running_server):
    _state, port = running_server
    alice_payload = _register_user("idem_a_")
    bob_payload = _register_user("idem_b_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        def _ask():
            request_id = str(uuid.uuid4())
            _send(
                sock,
                {
                    "type": "direct_conversation_request",
                    "username": bob_payload["username"],
                    "request_id": request_id,
                },
            )
            response = _recv_until(
                sock,
                lambda p: p.get("type") == "direct_conversation_result"
                and p.get("request_id") == request_id,
            )
            assert response is not None
            return response["conversation_id"]

        first = _ask()
        second = _ask()

        assert first == second

        db = SessionLocal()
        try:
            member_rows = (
                db.query(ConversationMember)
                .filter(ConversationMember.user_id == uuid.UUID(alice_payload["user_id"]))
                .all()
            )
            direct_ids = {
                str(row.conversation_id)
                for row in member_rows
                if db.get(Conversation, row.conversation_id).type == Conversation.TYPE_DIRECT
            }
            assert direct_ids == {first}
        finally:
            db.close()
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_direct_conversation_request_unknown_user_returns_error(running_server):
    _state, port = running_server
    alice_payload = _register_user("noone_a_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        bogus_username = f"nonexistent_{uuid.uuid4().hex[:10]}"
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "direct_conversation_request",
                "username": bogus_username,
                "request_id": request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "direct_conversation_result"
        )
        assert response is not None
        assert response.get("conversation_id") is None
        assert response.get("error")
        assert bogus_username in response["error"]
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_direct_conversation_request_targeting_self_returns_error(running_server):
    """Regression test: a self-targeting request (username == the
    caller's own) must not reach _resolve_direct_conversation_id()
    with an identical pair -- that raises an unhandled IntegrityError
    (ConversationMember's (conversation_id, user_id) uniqueness
    constraint), which used to kill the connection. Must instead get a
    normal error response, request_id preserved, and the connection
    must remain usable afterward."""
    _state, port = running_server
    alice_payload = _register_user("self_a_")

    sock, alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "direct_conversation_request",
                "username": alice_name,
                "request_id": request_id,
            },
        )

        response = _recv_until(
            sock, lambda p: p.get("type") == "direct_conversation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("conversation_id") is None
        assert response.get("error")

        # Connection must still be alive: a real, well-formed request
        # afterward still succeeds.
        bob_payload = _register_user("self_b_")
        try:
            follow_up_id = str(uuid.uuid4())
            _send(
                sock,
                {
                    "type": "direct_conversation_request",
                    "username": bob_payload["username"],
                    "request_id": follow_up_id,
                },
            )
            follow_up = _recv_until(
                sock, lambda p: p.get("type") == "direct_conversation_result"
            )
            assert follow_up is not None
            assert follow_up["request_id"] == follow_up_id
            assert follow_up.get("conversation_id")
            assert follow_up.get("error") is None
        finally:
            _delete_user(bob_payload["username"])
    finally:
        sock.close()
        _delete_user(alice_payload["username"])


def test_direct_conversation_request_missing_request_id_is_silently_ignored(running_server):
    """Unlike login/register (pre-auth, connection torn down on a
    missing request_id), direct_conversation_request is dispatched
    inside the authenticated loop -- a missing request_id must be
    ignored without killing the connection."""
    _state, port = running_server
    alice_payload = _register_user("noid_a_")
    bob_payload = _register_user("noid_b_")

    sock, _alice_name = _connect_and_authenticate(port, alice_payload)

    try:
        _send(
            sock,
            {
                "type": "direct_conversation_request",
                "username": bob_payload["username"],
                # deliberately no request_id
            },
        )

        # No response within a short window -- but the connection must
        # still be alive: a real, well-formed request afterward still
        # succeeds.
        no_response = _recv_until(
            sock, lambda p: p.get("type") == "direct_conversation_result", attempts=5
        )
        assert no_response is None

        request_id = str(uuid.uuid4())
        _send(
            sock,
            {
                "type": "direct_conversation_request",
                "username": bob_payload["username"],
                "request_id": request_id,
            },
        )
        response = _recv_until(
            sock, lambda p: p.get("type") == "direct_conversation_result"
        )
        assert response is not None
        assert response["request_id"] == request_id
        assert response.get("conversation_id")
    finally:
        sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_direct_conversation_request_scoped_to_authenticated_caller(running_server):
    """Security: the caller's own half of the pair always comes from
    the authenticated connection, never anything client-supplied.
    Two different callers requesting a conversation with the SAME
    target must get two DIFFERENT conversations -- proving each
    request is scoped to its own authenticated identity, not to
    whatever the packet might claim (there is no such field to forge
    here at all)."""
    _state, port = running_server
    alice_payload = _register_user("scope_a_")
    carol_payload = _register_user("scope_c_")
    bob_payload = _register_user("scope_b_")

    alice_sock, _alice_name = _connect_and_authenticate(port, alice_payload)
    carol_sock, _carol_name = _connect_and_authenticate(port, carol_payload)

    try:
        def _ask(sock):
            request_id = str(uuid.uuid4())
            _send(
                sock,
                {
                    "type": "direct_conversation_request",
                    "username": bob_payload["username"],
                    "request_id": request_id,
                },
            )
            response = _recv_until(
                sock,
                lambda p: p.get("type") == "direct_conversation_result"
                and p.get("request_id") == request_id,
            )
            assert response is not None
            return response["conversation_id"]

        alice_bob_id = _ask(alice_sock)
        carol_bob_id = _ask(carol_sock)

        assert alice_bob_id != carol_bob_id

        expected_alice_bob = _find_direct_conversation_id(
            alice_payload["user_id"], bob_payload["user_id"]
        )
        expected_carol_bob = _find_direct_conversation_id(
            carol_payload["user_id"], bob_payload["user_id"]
        )
        assert alice_bob_id == expected_alice_bob
        assert carol_bob_id == expected_carol_bob
    finally:
        alice_sock.close()
        carol_sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(carol_payload["username"])
        _delete_user(bob_payload["username"])


def test_concurrent_direct_conversation_requests_converge_on_one_conversation(running_server):
    """Same underlying pg_advisory_xact_lock() protection D3.1 already
    proved, exercised through this new request/response path
    specifically: two connections requesting the SAME pair's
    conversation at (as close to) the same instant as socket
    scheduling allows must converge on one conversation, never two."""
    _state, port = running_server
    alice_payload = _register_user("race_a_")
    bob_payload = _register_user("race_b_")

    alice_sock, _alice_name = _connect_and_authenticate(port, alice_payload)
    bob_sock, _bob_name = _connect_and_authenticate(port, bob_payload)

    try:
        barrier = threading.Barrier(2)
        results = {}

        def ask(sock, key, target_username):
            request_id = str(uuid.uuid4())
            barrier.wait(timeout=5)
            _send(
                sock,
                {
                    "type": "direct_conversation_request",
                    "username": target_username,
                    "request_id": request_id,
                },
            )
            response = _recv_until(
                sock,
                lambda p: p.get("type") == "direct_conversation_result"
                and p.get("request_id") == request_id,
            )
            results[key] = response["conversation_id"] if response else None

        thread_a = threading.Thread(
            target=ask, args=(alice_sock, "alice", bob_payload["username"])
        )
        thread_b = threading.Thread(
            target=ask, args=(bob_sock, "bob", alice_payload["username"])
        )
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=10)
        thread_b.join(timeout=10)

        assert results.get("alice")
        assert results.get("bob")
        assert results["alice"] == results["bob"]

        db = SessionLocal()
        try:
            member_rows = (
                db.query(ConversationMember)
                .filter(ConversationMember.user_id == uuid.UUID(alice_payload["user_id"]))
                .all()
            )
            direct_ids = {
                str(row.conversation_id)
                for row in member_rows
                if db.get(Conversation, row.conversation_id).type == Conversation.TYPE_DIRECT
            }
            assert direct_ids == {results["alice"]}
        finally:
            db.close()
    finally:
        alice_sock.close()
        bob_sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


# ----------------------------------------------------------------------
# B. Client consumption: real ClientSession, real receiver thread
# ----------------------------------------------------------------------


def test_set_current_chat_uses_request_response_not_database(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("nodb_a_")
    bob_payload = _register_user("nodb_b_")

    session = _make_connected_session(alice_payload)

    try:
        assert session.conversation_store.get(bob_payload["username"]) is None

        with mock.patch.object(
            ConversationStore,
            "ensure_direct_conversation_id",
            side_effect=AssertionError(
                "ensure_direct_conversation_id() must never be called from "
                "set_current_chat() (D3.3)"
            ),
        ):
            summary = ConversationSummary(
                conversation_id=None,
                username=bob_payload["username"],
                is_online=True,
                latest_message=None,
            )

            session.set_current_chat(summary)

        assert session.current_chat == bob_payload["username"]
        assert session.current_chat_is_group is False
        assert session.current_conversation_id
        uuid.UUID(session.current_conversation_id)

        expected = _find_direct_conversation_id(
            alice_payload["user_id"], bob_payload["user_id"]
        )
        assert expected is not None
        assert session.current_conversation_id == expected

        cached = session.conversation_store.get(bob_payload["username"])
        assert cached is not None
        assert cached.conversation_id == expected
    finally:
        session.disconnect()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


def test_set_current_chat_unknown_user_raises_value_error(running_server, monkeypatch):
    """Preserves ensure_direct_conversation_id()'s exact prior
    contract: an unresolvable username raises ValueError, now surfaced
    from the server's error field instead of a local user lookup."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("badpartner_a_")
    session = _make_connected_session(alice_payload)

    try:
        bogus_username = f"nonexistent_{uuid.uuid4().hex[:10]}"

        summary = ConversationSummary(
            conversation_id=None,
            username=bogus_username,
            is_online=True,
            latest_message=None,
        )

        with pytest.raises(ValueError):
            session.set_current_chat(summary)
    finally:
        session.disconnect()
        _delete_user(alice_payload["username"])


def test_set_current_chat_group_path_unaffected(running_server, monkeypatch):
    """Regression guard: a group summary (conversation_id already
    known) must still skip resolution entirely -- D3.3 only changes
    the direct, no-cached-id branch."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("group_a_")
    session = _make_connected_session(alice_payload)

    try:
        with mock.patch.object(
            client_session_module.ClientSession,
            "send_request",
            side_effect=AssertionError(
                "send_request() must never be called for an already-known "
                "group conversation_id"
            ),
        ):
            summary = ConversationSummary(
                conversation_id="a-real-group-id",
                username=None,
                is_online=False,
                latest_message=None,
                is_group=True,
                group_name="Trio",
                participants=["b", "c"],
            )

            session.set_current_chat(summary)

        assert session.current_chat == "a-real-group-id"
        assert session.current_chat_is_group is True
        assert session.current_conversation_id == "a-real-group-id"
    finally:
        session.disconnect()
        _delete_user(alice_payload["username"])
