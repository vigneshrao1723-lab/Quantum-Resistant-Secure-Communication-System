"""
UI Finalization -- internal protocol/session/security events (a peer
joining/leaving, a public key received, a session key established)
must not be presented as ordinary chat messages. This is a
presentation-layer change only: ClientSession.handle_join()/
handle_leave()/handle_public_key()/handle_session_key() no longer emit
message_received("system", "system", ...), but every actual protocol
operation (storing a public key, storing a session key) is unchanged
and still verified working here -- only its GUI presentation moved.

handle_join()/handle_leave() are tested directly (they take a plain
packet dict, no crypto setup needed). handle_public_key()/
handle_session_key() are tested through a real running server and real
receiver threads, following the exact fixture pattern in
tests/test_receiver_thread_conversation_id_consumption.py -- reusing
fake/mocked crypto material here would prove nothing about the real
Kyber handshake actually still working.

Run with:
    pytest tests/test_internal_messages_not_shown_as_chat.py -v
"""

import time
import uuid

import pytest
from PySide6.QtCore import Qt

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_public_key
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server


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
            "full_name": "Internal Message Cleanup Test",
            "username": f"imsg_{suffix_hint}{suffix}",
            "email": f"imsg_{suffix_hint}{suffix}@example.com",
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
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _make_connected_session(payload, key_store_dir):
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    # Server-Untrusted Identity Verification, Stage 3: this lighter
    # connect()-only pattern skips authenticate_credentials(), the
    # only place a key store is normally unlocked -- unlock a real,
    # isolated, on-disk one here too (before send_public_key(), like
    # authenticate_credentials()'s own _unlock_key_store(), so this
    # identity key would persist across a reconnect), so tests can
    # verify whichever peer establish_session_key() needs.
    session.key_store = SecureKeyStore(
        payload["user_id"], storage_dir=key_store_dir / payload["username"]
    )
    session.key_store.unlock(payload["password"])
    session.key_manager.load_or_create_kyber_keypair(session.key_store)
    # Protocol-Level ML-DSA Origin Authentication: persists the signing
    # keypair too -- send_public_key() now always attaches an ML-DSA
    # signature, so a reconnecting session whose signing key was left
    # ephemeral would look like a KEY_CHANGED to an already-verified
    # peer even with its KEM key correctly persisted.
    session.key_manager.load_or_create_signing_keypair(session.key_store)
    session.send_public_key()
    session.start_receiver()
    return session


def _wait_for(predicate, attempts=100, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _capture_message_received(session):
    """Every (conversation_key, sender, message) tuple emitted on
    this session's message_received signal, in order.

    Qt.DirectConnection is required, not the default AutoConnection:
    handle_public_key()/handle_session_key()/handle_chat() run on the
    receiver thread (see client/receiver.py), which is a different
    thread than this test. A default (queued) connection would only
    ever deliver once something pumps this test's own Qt event loop --
    which never happens here -- so the lambda would silently never
    fire regardless of what's emitted, making a "no message" assertion
    vacuously true. DirectConnection runs the lambda synchronously on
    the emitting (receiver) thread instead, which is what actually
    proves something -- append() on a plain list is GIL-atomic, so
    this is safe without a lock for a single appending thread."""

    captured = []
    session.message_received.connect(
        lambda key, sender, message: captured.append((key, sender, message)),
        Qt.DirectConnection,
    )
    return captured


# ----------------------------------------------------------------------
# handle_join() / handle_leave() -- no server needed, plain packet dicts
# ----------------------------------------------------------------------


def test_handle_join_does_not_emit_a_chat_message():
    session = ClientSession()
    captured = _capture_message_received(session)

    session.handle_join({"username": "ramya"})

    assert captured == []


def test_handle_leave_does_not_emit_a_chat_message():
    session = ClientSession()
    captured = _capture_message_received(session)

    session.handle_leave({"username": "ramya"})

    assert captured == []


# ----------------------------------------------------------------------
# handle_public_key() / handle_session_key() -- real server, real
# receiver threads, real Kyber handshake.
# ----------------------------------------------------------------------


def test_public_key_exchange_still_works_but_produces_no_chat_message(
    running_server, monkeypatch, tmp_path
):
    """The actual protocol operation (storing the peer's public key)
    must still work exactly as before -- only proven by checking
    key_manager, not merely that no exception was raised."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    key_store_dir = tmp_path / "keystores"

    alice_payload = _register_user("pk_a_")
    bob_payload = _register_user("pk_b_")

    alice = _make_connected_session(alice_payload, key_store_dir)
    alice_messages = _capture_message_received(alice)

    try:
        bob = _make_connected_session(bob_payload, key_store_dir)
        bob_messages = _capture_message_received(bob)

        try:
            # The actual protocol operation: both sides genuinely
            # receive and store each other's real Kyber public key.
            assert _wait_for(
                lambda: alice.key_manager.get_public_key(bob.username) is not None
            ), "public key exchange itself is broken -- not a presentation issue"
            assert _wait_for(
                lambda: bob.key_manager.get_public_key(alice.username) is not None
            )

            # The presentation change: neither side's chat message
            # stream contains a "public key received" notice.
            assert not any("public key" in m.lower() for _k, _s, m in alice_messages)
            assert not any("public key" in m.lower() for _k, _s, m in bob_messages)
        finally:
            bob.disconnect()
            _delete_user(bob_payload["username"])
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])


def test_session_key_establishment_still_works_but_produces_no_chat_message(
    running_server, monkeypatch, tmp_path
):
    """The actual protocol operation (the recipient decapsulating and
    storing a real AES session key) must still work -- proven by
    checking key_manager and that the message itself is still
    delivered and decrypted correctly, not merely that nothing raised."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    key_store_dir = tmp_path / "keystores"

    alice_payload = _register_user("sk_a_")
    bob_payload = _register_user("sk_b_")

    alice = _make_connected_session(alice_payload, key_store_dir)

    try:
        bob = _make_connected_session(bob_payload, key_store_dir)
        bob_messages = _capture_message_received(bob)

        try:
            assert _wait_for(
                lambda: alice.key_manager.get_public_key(bob.username) is not None
            )
            assert _wait_for(
                lambda: bob.key_manager.get_public_key(alice.username) is not None
            )

            # Server-Untrusted Identity Verification, Stage 3:
            # establish_session_key() (called inside
            # send_chat_message() below) now requires Alice to have
            # explicitly verified Bob before wrapping a session key
            # for him -- unrelated to this test's actual subject (that
            # session-key establishment produces no chat message), but
            # a precondition it now needs.
            alice.key_store.verify_peer_fingerprint(
                bob.username, fingerprint_public_key(bob.key_manager.public_key)
            )
            # Phase 13 (Group-Key-Distribution ML-DSA Origin
            # Authentication): Bob is also the RECEIVER of the
            # group_key_distribution packet establish_session_key()
            # sends, which now separately requires Bob to have Alice
            # already VERIFIED too.
            bob.key_store.verify_peer_fingerprint(
                alice.username, fingerprint_public_key(alice.key_manager.public_key)
            )

            from domain.conversation_summary import ConversationSummary

            alice.set_current_chat(
                ConversationSummary(
                    conversation_id=None,
                    username=bob.username,
                    is_online=True,
                    latest_message=None,
                )
            )
            expected_conversation_id = alice.current_conversation_id
            assert expected_conversation_id

            alice.send_chat_message("hello, this is the real message")

            # The actual protocol operation: bob's KeyManager genuinely
            # ends up holding the real, usable AES session key.
            assert _wait_for(
                lambda: bob.key_manager.get_key(expected_conversation_id) is not None
            ), "session key establishment itself is broken -- not a presentation issue"

            # The real message still arrives and decrypts correctly --
            # proves the crypto/serialization pipeline is untouched.
            assert _wait_for(
                lambda: any(
                    m == "hello, this is the real message" for _k, s, m in bob_messages
                    if s == alice.username
                )
            )

            # The presentation change: no "secure session established"
            # notice anywhere in bob's chat message stream.
            assert not any(
                "session established" in m.lower() for _k, _s, m in bob_messages
            )
        finally:
            bob.disconnect()
            _delete_user(bob_payload["username"])
    finally:
        alice.disconnect()
        _delete_user(alice_payload["username"])
