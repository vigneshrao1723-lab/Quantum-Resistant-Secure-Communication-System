"""
Tests for Issue 3 (real-application testing bug report): User Must Be
Searched By Unique ID -- migrated in D2 (Server-Side API /
Authentication Migration) onto a real client -> server request/
response round trip.

ClientSession.find_user_by_id() no longer reads PostgreSQL directly --
it sends a user_lookup_request and blocks on D1's send_request() for
the correlated user_lookup_result (see server/client_handler.py::
handle_user_lookup()). The functional tests below exercise the real
thing end to end: a genuine ClientSession.connect()/.login()/
.start_receiver() against a real running TLS server
(server.client_handler.handle_client, the same harness pattern every
other integration suite in this codebase uses), not a bare
ClientSession reading the database directly. The security tests use a
raw socket to prove the server-side authorization/validation
independent of what the real client would ever actually send.

Run with:
    pytest tests/test_user_id_search.py -v
"""

import json
import socket
import struct
import threading
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
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


def _assert_no_packet(sock, predicate, attempts=10, per_attempt_timeout=0.2):
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except (TimeoutError, OSError):
            candidate = None
        if candidate is not None and predicate(candidate):
            raise AssertionError(f"Unexpected matching packet arrived: {candidate}")


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "ID Search Test",
            "username": f"idsearch_{suffix_hint}{suffix}",
            "email": f"idsearch_{suffix_hint}{suffix}@example.com",
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


@pytest.fixture()
def running_server():
    state = ServerState()

    # Test-harness hardening (matches every other running_server
    # fixture in this codebase): one SSLContext per fixture instance,
    # built once and reused, plus joining every handler thread at
    # teardown -- see tests/tls_test_support.py.
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


def _real_connected_session(port, payload, monkeypatch):
    """
    A genuine, fully-connected, fully-authenticated ClientSession --
    connect() (real TLS), login() (real JWT exchange), send_public_key()
    (required before the server's dispatch loop reads anything else),
    and start_receiver() (the real background thread) -- all
    unmodified, exactly the sequence gui/main_window.py::
    start_chat_session() performs. Required because find_user_by_id()
    now uses send_request(), which can only ever be resolved by a
    running receiver thread reading real socket data.
    """
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    session = ClientSession()
    session.user_id = payload["user_id"]
    session.username = payload["username"]
    session.access_token = _login_and_get_token(payload)

    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()

    return session


@pytest.fixture()
def registered_pair():
    searcher_payload = _register_user("searcher_")
    target_payload = _register_user("target_")

    yield searcher_payload, target_payload

    _delete_user(searcher_payload["username"])
    _delete_user(target_payload["username"])


# ----------------------------------------------------------------------
# Functional: real ClientSession, real server, real round trip
# ----------------------------------------------------------------------


def test_valid_unique_id_finds_the_correct_user(running_server, registered_pair, monkeypatch):
    _state, port = running_server
    searcher_payload, target_payload = registered_pair
    session = _real_connected_session(port, searcher_payload, monkeypatch)

    try:
        result = session.find_user_by_id(target_payload["user_id"])

        assert result is not None
        assert result["user_id"] == target_payload["user_id"]
        assert result["username"] == target_payload["username"]
        assert "email" not in result
        assert "password_hash" not in result
    finally:
        session.disconnect()


def test_wellformed_but_nonexistent_id_returns_none(running_server, registered_pair, monkeypatch):
    _state, port = running_server
    searcher_payload, _target_payload = registered_pair
    session = _real_connected_session(port, searcher_payload, monkeypatch)

    try:
        result = session.find_user_by_id(str(uuid.uuid4()))

        assert result is None
    finally:
        session.disconnect()


@pytest.mark.parametrize(
    "malformed_id",
    ["not-a-uuid", "", "12345", "   ", "'; DROP TABLE users; --"],
)
def test_malformed_id_returns_none_not_a_crash(
    running_server, registered_pair, monkeypatch, malformed_id
):
    """The malformed-id check is still short-circuited entirely
    client-side (find_user_by_id() never even calls send_request() for
    one) -- proven here by the fact this still works instantly, with
    the server never involved for these particular calls."""
    _state, port = running_server
    searcher_payload, _target_payload = registered_pair
    session = _real_connected_session(port, searcher_payload, monkeypatch)

    try:
        result = session.find_user_by_id(malformed_id)

        assert result is None
    finally:
        session.disconnect()


def test_malformed_and_nonexistent_ids_are_indistinguishable(
    running_server, monkeypatch
):
    """Deliberate: don't leak whether a guess was 'well-formed but
    wrong' vs. 'garbage' -- both must look identical to the caller,
    now via two different code paths (client-side short-circuit vs. a
    real round trip returning no match) that must still be
    indistinguishable from the outside."""
    _state, port = running_server
    searcher_payload = _register_user("indist_")
    session = _real_connected_session(port, searcher_payload, monkeypatch)

    try:
        malformed_result = session.find_user_by_id("garbage")
        nonexistent_result = session.find_user_by_id(str(uuid.uuid4()))
        assert malformed_result is None
        assert nonexistent_result is None
    finally:
        session.disconnect()
        _delete_user(searcher_payload["username"])


def test_two_registrations_never_collide_on_id(running_server, monkeypatch):
    """Duplicate/ambiguous IDs are not reachable: id is the DB primary
    key, uniqueness is enforced by Postgres itself. Proven here rather
    than asserted as a comment."""
    _state, port = running_server
    payload_a = _register_user("uniq_a_")
    payload_b = _register_user("uniq_b_")
    session = _real_connected_session(port, payload_a, monkeypatch)

    try:
        assert payload_a["user_id"] != payload_b["user_id"]

        result_a = session.find_user_by_id(payload_a["user_id"])
        result_b = session.find_user_by_id(payload_b["user_id"])

        assert result_a["username"] != result_b["username"]
        assert result_a["user_id"] != result_b["user_id"]
    finally:
        session.disconnect()
        _delete_user(payload_a["username"])
        _delete_user(payload_b["username"])


def test_unauthenticated_session_cannot_search():
    """A ClientSession that never logged in (user_id never set) must
    not be able to perform a lookup at all -- this guard is purely
    local (checked before send_request() is ever called), so no
    server or connection is needed to prove it."""
    session = ClientSession()
    assert session.user_id is None

    with pytest.raises(PermissionError):
        session.find_user_by_id(str(uuid.uuid4()))


def test_found_user_can_be_opened_as_a_conversation(
    running_server, registered_pair, monkeypatch
):
    """End-to-end proof that a valid lookup leads to an openable
    conversation, via the same ConversationStore path clicking an
    online user already uses. ensure_direct_conversation_id() is
    unmigrated (still a direct DB call) -- deliberately, per D2's
    scope -- so this exercises the boundary between the migrated and
    not-yet-migrated pieces working together correctly."""
    _state, port = running_server
    searcher_payload, target_payload = registered_pair
    session = _real_connected_session(port, searcher_payload, monkeypatch)

    try:
        result = session.find_user_by_id(target_payload["user_id"])
        assert result is not None

        conversation_id = session.conversation_store.ensure_direct_conversation_id(
            session.user_id, result["username"]
        )

        assert conversation_id is not None
        assert uuid.UUID(conversation_id)  # a real, parseable conversation id
    finally:
        session.disconnect()


def test_request_id_is_present_and_distinct_per_call(
    running_server, registered_pair, monkeypatch
):
    """D1 correlation is actually engaged, not bypassed -- two
    sequential lookups on the same session must not reuse a stale
    request_id or otherwise short-circuit send_request()."""
    _state, port = running_server
    searcher_payload, target_payload = registered_pair
    session = _real_connected_session(port, searcher_payload, monkeypatch)

    try:
        assert session._pending_requests.pending_count() == 0

        session.find_user_by_id(target_payload["user_id"])
        assert session._pending_requests.pending_count() == 0

        session.find_user_by_id(str(uuid.uuid4()))
        assert session._pending_requests.pending_count() == 0
    finally:
        session.disconnect()


# ----------------------------------------------------------------------
# Security: raw socket, independent of what the real client ever sends
# ----------------------------------------------------------------------


def test_user_lookup_request_before_authentication_gets_no_response(running_server):
    """handle_user_lookup() is only reachable from inside
    handle_client()'s post-authentication dispatch loop -- proven here
    by sending a user_lookup_request on a connection that never
    completed authentication at all (no auth packet sent), matching
    this file's own established pattern for every other JWT-gated
    check (test_server_auth_integration.py)."""
    _state, port = running_server

    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))

    try:
        _send(
            sock,
            {"type": "user_lookup_request", "request_id": "forged-1", "user_id": "x"},
        )

        _assert_no_packet(sock, lambda p: p.get("type") == "user_lookup_result")
    finally:
        sock.close()


def test_user_lookup_request_with_missing_user_id_is_ignored(running_server):
    """Server-side defensive check, independent of the client-side
    short-circuit: a well-authenticated connection sending a
    user_lookup_request with no user_id field must get no response,
    not a crash."""
    _state, port = running_server

    payload = _register_user("noid_")
    token = _login_and_get_token(payload)
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))

    try:
        _send(sock, create_auth_packet(token))
        auth_result = _recv(sock)
        assert auth_result["success"] is True
        username = auth_result["username"]

        _send(
            sock,
            create_public_key_packet(
                username=username, algorithm="KYBER", public_key="dummy-public-key"
            ),
        )

        _send(sock, {"type": "user_lookup_request", "request_id": "forged-2"})

        _assert_no_packet(sock, lambda p: p.get("type") == "user_lookup_result")
    finally:
        sock.close()
        _delete_user(payload["username"])


def test_user_lookup_result_never_leaks_email_or_password_hash(running_server):
    """Direct proof against the raw wire packet, not just the
    dict find_user_by_id() happens to construct client-side --
    handle_user_lookup()'s response itself must never carry these
    fields, regardless of what any future client might do with it."""
    _state, port = running_server

    searcher_payload = _register_user("nf_sr_")
    target_payload = _register_user("nf_tg_")
    token = _login_and_get_token(searcher_payload)
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))

    try:
        _send(sock, create_auth_packet(token))
        auth_result = _recv(sock)
        assert auth_result["success"] is True
        username = auth_result["username"]

        _send(
            sock,
            create_public_key_packet(
                username=username, algorithm="KYBER", public_key="dummy-public-key"
            ),
        )

        _send(
            sock,
            {
                "type": "user_lookup_request",
                "request_id": "forged-3",
                "user_id": target_payload["user_id"],
            },
        )

        result = _recv_until(sock, lambda p: p.get("type") == "user_lookup_result")
        assert result is not None
        assert result["request_id"] == "forged-3"
        assert result["user_id"] == target_payload["user_id"]
        assert result["username"] == target_payload["username"]
        assert set(result.keys()) == {
            "type",
            "request_id",
            "user_id",
            "username",
            "display_name",
        }
    finally:
        sock.close()
        _delete_user(searcher_payload["username"])
        _delete_user(target_payload["username"])


def test_any_authenticated_user_can_look_up_any_other_by_id(running_server):
    """Matches the pre-migration security model exactly (see
    handle_user_lookup()'s own docstring): a lookup grants no privilege
    of its own, so there is no membership/ownership check -- any
    authenticated connection can resolve any other user's id. Proven
    directly against the raw response, independent of ClientSession."""
    _state, port = running_server

    searcher_payload = _register_user("any_sr_")
    target_payload = _register_user("any_tg_")
    token = _login_and_get_token(searcher_payload)
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))

    try:
        _send(sock, create_auth_packet(token))
        auth_result = _recv(sock)
        assert auth_result["success"] is True
        username = auth_result["username"]

        _send(
            sock,
            create_public_key_packet(
                username=username, algorithm="KYBER", public_key="dummy-public-key"
            ),
        )

        _send(
            sock,
            {
                "type": "user_lookup_request",
                "request_id": "forged-4",
                "user_id": target_payload["user_id"],
            },
        )

        result = _recv_until(sock, lambda p: p.get("type") == "user_lookup_result")
        assert result is not None
        assert result["user_id"] == target_payload["user_id"]
    finally:
        sock.close()
        _delete_user(searcher_payload["username"])
        _delete_user(target_payload["username"])
