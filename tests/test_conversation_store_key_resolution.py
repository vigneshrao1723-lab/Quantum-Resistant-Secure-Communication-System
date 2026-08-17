"""
Tests for ClientSession.set_current_chat()'s conversation-id
resolution, against the real database.

Proves the end-to-end claim: for a direct conversation, KeyManager
ends up addressed by the real conversation_id, resolved without
ClientSession ever touching the database itself, and cached so a
second resolution is free.

D3.3 -- Conversation Operations Migration: set_current_chat() resolves
a direct conversation with no cached id yet by asking the server via a
direct_conversation_request (D1's send_request()), which requires a
real, connected, authenticated ClientSession.

D4.3 -- Message/History Operations Migration: this file originally
also tested ConversationStore.ensure_direct_conversation_id() directly
-- the client-side database round trip set_current_chat() itself
stopped using back in D3.3, but which load_conversation_history()
still relied on until D4.3 migrated it too. With that last caller
gone, ensure_direct_conversation_id() was deleted outright (dead
code, zero remaining callers) -- there is nothing left in
ConversationStore that resolves or creates a direct conversation's
identity; every path does so exclusively via the server. This file's
own two tests for that now-deleted method were removed along with it;
the set_current_chat() tests below are unaffected -- they were
already exercising the D3.3 server-request path, not the deleted one.

Run with:
    pytest tests/test_conversation_store_key_resolution.py -v
"""

import socket
import threading
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
from tests.tls_test_support import serve_tls_client


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Key Resolution Test",
            "username": f"kmres_{suffix_hint}{suffix}",
            "email": f"kmres_{suffix_hint}{suffix}@example.com",
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


def _make_connected_session(payload):
    """Real ClientSession: connect() -> login() -> send_public_key()
    -> start_receiver(), exactly gui/main_window.py::
    start_chat_session()'s sequence -- required because
    set_current_chat() now uses send_request() (D3.3), which can only
    be resolved by a running receiver thread reading real socket
    data."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def test_set_current_chat_resolves_conversation_id_for_a_new_direct_summary(
    running_server, monkeypatch
):
    """The full ClientSession-facing claim: opening a brand-new direct
    conversation (conversation_id unknown) leaves current_conversation_id
    populated with a real id, ready for KeyManager. D3.3 -- Conversation
    Operations Migration: this now goes through a real
    direct_conversation_request/result round trip rather than a local
    database call -- proved here with a real running server and a real,
    connected, authenticated ClientSession, not a bare one."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    a = _register_user("a_")
    b = _register_user("b_")

    session = _make_connected_session(a)

    try:
        summary = ConversationSummary(
            conversation_id=None,
            username=b["username"],
            is_online=True,
            latest_message=None,
        )

        session.set_current_chat(summary)

        assert session.current_chat == b["username"]
        assert session.current_chat_is_group is False
        assert session.current_conversation_id is not None
        uuid.UUID(session.current_conversation_id)

        # Matches what ConversationRepository would itself resolve for
        # the same pair -- single source of truth, now server-side --
        # cross-checked directly against the database, independent of
        # ClientSession's own code.
        db = SessionLocal()
        try:
            expected = ConversationRepository(db)._find_direct_conversation(
                uuid.UUID(a["user_id"]), uuid.UUID(b["user_id"])
            )
            assert expected is not None
            assert session.current_conversation_id == str(expected.id)
        finally:
            db.close()

        # Cached client-side too, via record_direct_conversation_id()
        # (the DB-free half _resolve_direct_conversation_id() delegates
        # its caching step to).
        cached_summary = session.conversation_store.get(b["username"])
        assert cached_summary is not None
        assert cached_summary.conversation_id == session.current_conversation_id
    finally:
        session.disconnect()
        _delete_user(a["username"])
        _delete_user(b["username"])


def test_set_current_chat_uses_group_conversation_id_directly():
    """A group summary already carries a real conversation_id -- no
    resolution should be attempted (and none is needed)."""
    session = ClientSession()
    session.user_id = str(uuid.uuid4())
    session.username = "irrelevant"

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
