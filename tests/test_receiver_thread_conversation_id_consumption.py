"""
Tests for D3.2 (Conversation Operations Migration, second slice):
ClientSession.handle_chat()/handle_session_key() -- both dispatched
exclusively from the receiver thread (client/receiver.py::
receive_messages() -> ClientSession.handle_packet()) -- now consume
the conversation identity the server already resolved and attached to
the packet (see D3.1: "direct_conversation_id" on a direct "chat"
packet, "conversation_id" on a "session_key" packet) instead of
calling ConversationStore.ensure_direct_conversation_id(), which
performs a direct database round trip. That call is exactly the
deadlock risk this migration exists to remove: send_request() can only
ever be resolved by the receiver thread itself calling handle_packet()
again, so a database call blocking that same thread was never safe to
upgrade to it.

Caching the resolved id into ConversationStore (so the sidebar stays
in sync) is preserved via the new, DB-free
ConversationStore.record_direct_conversation_id() -- the pure
in-memory half of ensure_direct_conversation_id(), extracted so a
caller that already has the id never needs the database-touching half.

Run with:
    pytest tests/test_receiver_thread_conversation_id_consumption.py -v
"""

import socket
import threading
import time
import uuid
from unittest import mock

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.conversation_store import ConversationStore
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from security.tls import build_server_context
from server.client_handler import handle_client
from server.server_state import ServerState
from tests.tls_test_support import serve_tls_client


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
            "full_name": "D3.2 Consumption Test",
            "username": f"d32_{suffix_hint}{suffix}",
            "email": f"d32_{suffix_hint}{suffix}@example.com",
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


def _make_connected_session(payload):
    """Real ClientSession: connect() -> login() -> send_public_key()
    -> start_receiver(), exactly gui/main_window.py::
    start_chat_session()'s sequence -- so handle_chat()/
    handle_session_key() run on a genuine receiver thread, not a
    direct method call standing in for one."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _open_direct_chat(session, partner_username):
    """Mirrors ChatWindow.open_conversation() enough to mark a direct
    conversation current -- unaffected by D3.2 (GUI-thread,
    out of scope); still resolves/creates the real conversation via
    ensure_direct_conversation_id()."""
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


def _last_received_text(session, from_username):
    summary = session.conversation_store.get(from_username)
    if summary is None or summary.latest_message is None:
        return None
    return summary.latest_message.text


@pytest.fixture()
def alice_and_bob(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("alice_")
    bob_payload = _register_user("bob_")

    alice = _make_connected_session(alice_payload)
    bob = _make_connected_session(bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    yield {"alice": alice, "bob": bob}

    for session in (alice, bob):
        try:
            session.disconnect()
        except Exception:
            pass
    _delete_user(alice_payload["username"])
    _delete_user(bob_payload["username"])


# ----------------------------------------------------------------------
# A + B + C + D combined: real receiver thread, fresh pair (receiver's
# ConversationStore has never heard of the sender), database calls
# from ConversationStore poisoned to raise. If handle_session_key() or
# handle_chat() fell back to ensure_direct_conversation_id() for
# either the key exchange or the message itself, this test fails --
# either via the poisoned call raising inside the receiver thread's
# own try/except (client/receiver.py), which prevents the expected
# message from ever arriving, or via the direct assertion at the end.
# ----------------------------------------------------------------------


def test_receiver_thread_uses_server_fields_and_never_touches_database(alice_and_bob):
    alice = alice_and_bob["alice"]
    bob = alice_and_bob["bob"]

    _open_direct_chat(alice, bob.username)
    expected_conversation_id = alice.current_conversation_id
    assert expected_conversation_id

    # Bob already has a placeholder summary for Alice (created the
    # moment the server's user_list broadcast told him she's online --
    # see ConversationStore.update_online_status()), but critically
    # its conversation_id is still None: nothing has resolved it yet.
    # This is exactly the case where the OLD ensure_direct_conversation_id()
    # would NOT have hit its cache and would have gone to the database.
    existing_summary = bob.conversation_store.get(alice.username)
    assert existing_summary is not None
    assert existing_summary.conversation_id is None

    with mock.patch.object(
        ConversationStore,
        "ensure_direct_conversation_id",
        side_effect=AssertionError(
            "ensure_direct_conversation_id() must never be called from "
            "the receiver thread (D3.2)"
        ),
    ):
        # A fresh pair's first message exercises BOTH handlers on
        # Bob's receiver thread: handle_session_key() (no cached key
        # yet -- Alice's establish_session_key() sends one first) and
        # then handle_chat() for the message itself.
        alice.send_chat_message("hello bob, first contact")

        assert _wait_for(
            lambda: _last_received_text(bob, alice.username)
            == "hello bob, first contact"
        )

    # The server-supplied id was genuinely consumed -- cross-checked
    # against the real, independently resolved conversation for this
    # pair, not merely "some value, who knows what."
    assert bob.key_manager.get_key(expected_conversation_id) is not None

    bob_summary = bob.conversation_store.get(alice.username)
    assert bob_summary is not None
    assert bob_summary.conversation_id == expected_conversation_id


def test_handle_session_key_alone_uses_server_field_without_database(alice_and_bob):
    """Narrower companion to the combined test above, isolating
    handle_session_key() specifically (independent of handle_chat())."""
    alice = alice_and_bob["alice"]
    bob = alice_and_bob["bob"]

    _open_direct_chat(alice, bob.username)
    expected_conversation_id = alice.current_conversation_id

    assert bob.key_manager.get_key(expected_conversation_id) is None

    with mock.patch.object(
        ConversationStore,
        "ensure_direct_conversation_id",
        side_effect=AssertionError(
            "ensure_direct_conversation_id() must never be called from "
            "the receiver thread (D3.2)"
        ),
    ):
        alice.establish_session_key()

        assert _wait_for(
            lambda: bob.key_manager.get_key(expected_conversation_id) is not None
        )

    bob_summary = bob.conversation_store.get(alice.username)
    assert bob_summary is not None
    assert bob_summary.conversation_id == expected_conversation_id


# ----------------------------------------------------------------------
# E. record_direct_conversation_id() is pure in-memory caching
# ----------------------------------------------------------------------


def test_record_direct_conversation_id_creates_a_new_summary():
    store = ConversationStore()

    emitted = []
    store.conversations_changed.connect(lambda: emitted.append(True))

    with mock.patch(
        "client.conversation_store.SessionLocal",
        side_effect=AssertionError("must never construct a database session"),
    ):
        store.record_direct_conversation_id("bob", "11111111-1111-1111-1111-111111111111")

    summary = store.get("bob")
    assert summary is not None
    assert summary.conversation_id == "11111111-1111-1111-1111-111111111111"
    assert summary.is_online is True
    assert len(emitted) == 1


def test_record_direct_conversation_id_updates_existing_summary_in_place():
    store = ConversationStore()

    store._summaries["carol"] = ConversationSummary(
        conversation_id=None,
        username="carol",
        is_online=False,
        latest_message="preserved-marker",
    )

    with mock.patch(
        "client.conversation_store.SessionLocal",
        side_effect=AssertionError("must never construct a database session"),
    ):
        store.record_direct_conversation_id(
            "carol", "22222222-2222-2222-2222-222222222222"
        )

    updated = store.get("carol")
    assert updated.conversation_id == "22222222-2222-2222-2222-222222222222"
    # Every other field is left untouched.
    assert updated.is_online is False
    assert updated.latest_message == "preserved-marker"


# ----------------------------------------------------------------------
# F. missing conversation id: graceful, no crash, no database fallback
# ----------------------------------------------------------------------


def test_handle_chat_missing_direct_conversation_id_does_not_crash_or_query_db(caplog):
    session = ClientSession()
    session.user_id = str(uuid.uuid4())
    session.username = "bob"
    session.online_users = []

    packet = {
        "type": "chat",
        "sender": "alice",
        "message": "ciphertext-irrelevant-to-this-test",
        "payload_type": "text",
        # Deliberately no "direct_conversation_id" and no
        # "conversation_id" -- simulates a broken/non-conforming
        # server response.
    }

    with mock.patch.object(
        ConversationStore,
        "ensure_direct_conversation_id",
        side_effect=AssertionError("must never fall back to the database"),
    ):
        session.handle_chat(packet)  # must not raise

    assert "No direct_conversation_id supplied by the server" in caplog.text


def test_handle_session_key_missing_conversation_id_does_not_crash_or_query_db(caplog):
    session = ClientSession()
    session.user_id = str(uuid.uuid4())
    session.username = "bob"

    packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "algorithm": "KYBER",
        "encrypted_key": "irrelevant-because-this-must-return-before-decapsulating",
        # Deliberately no "conversation_id".
    }

    with mock.patch.object(
        ConversationStore,
        "ensure_direct_conversation_id",
        side_effect=AssertionError("must never fall back to the database"),
    ):
        session.handle_session_key(packet)  # must not raise

    assert "No conversation_id supplied by the server" in caplog.text
    # Returned before ever touching KeyManager -- nothing stored under
    # a useless key.
    assert session.key_manager.get_key(None) is None


def test_handle_session_key_empty_string_conversation_id_is_treated_as_missing(caplog):
    """An empty string is falsy, same handling as an absent field --
    covers "present but malformed-to-the-point-of-uselessness"
    without needing a separate code path: neither handler ever parses
    or validates the id's format, so any non-empty string (garbage or
    not) flows through identically to a well-formed one, and only a
    falsy value (None, "", 0) is treated as "no usable id"."""
    session = ClientSession()
    session.user_id = str(uuid.uuid4())
    session.username = "bob"

    packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "algorithm": "KYBER",
        "encrypted_key": "irrelevant",
        "conversation_id": "",
    }

    with mock.patch.object(
        ConversationStore,
        "ensure_direct_conversation_id",
        side_effect=AssertionError("must never fall back to the database"),
    ):
        session.handle_session_key(packet)  # must not raise

    assert "No conversation_id supplied by the server" in caplog.text
