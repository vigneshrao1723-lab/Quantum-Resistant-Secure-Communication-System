"""
Regression test for the direct-message key desynchronization bug
(roadmap item A1): if Alice restarts her application while Bob stays
connected, Alice's fresh KeyManager has no cached key for their
conversation and re-establishes one -- but before this fix, that new
key always landed on the hardcoded default epoch 1, which Bob's
KeyManager.store_key() (correctly, by design) refused to overwrite
since he already had epoch 1 cached. The two sides would diverge
permanently: Alice encrypting with her new key, Bob still decrypting
with his old one, with nothing to ever trigger a fresh negotiation
again.

The fix reuses ConversationRepository.reserve_next_epoch() -- the
exact same server-persisted counter Phase 7 already uses for group-key
rotation -- so a re-established direct-message key always lands in a
brand-new epoch slot instead of colliding with an existing one.

This suite drives two REAL ClientSession instances end-to-end (connect
-> login -> send_public_key -> start_receiver -> send_chat_message),
not raw sockets, because the bug lives specifically in
ClientSession.establish_session_key()/handle_session_key()'s real
behavior, not in the wire protocol or the server.

Run with:
    pytest tests/test_direct_key_desync_recovery.py -v
"""

import time
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
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
            "full_name": "Key Desync Test",
            "username": f"desync_{suffix_hint}{suffix}",
            "email": f"desync_{suffix_hint}{suffix}@example.com",
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


def _make_connected_session(payload):
    """Build and fully connect a real ClientSession for this user --
    connect() -> login() -> send_public_key() -> start_receiver(),
    exactly the sequence gui/main_window.py::start_chat_session() uses.
    A fresh KeyManager (ClientSession.__init__'s own doing) is exactly
    what a real app restart leaves a client with."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _open_direct_chat(session, partner_username):
    """Mirrors enough of ChatWindow.open_conversation() to mark a
    direct conversation current -- resolves the real conversation_id,
    creating it if this is the very first contact between the two."""
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


def _get_epoch_state(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_epoch_state(uuid.UUID(conversation_id))
    finally:
        db.close()


@pytest.fixture()
def alice_and_bob(running_server, monkeypatch):
    """Two real, fully-connected ClientSessions -- Alice and Bob --
    each already knowing the other's public key, direct conversation
    already resolved. ClientSession.connect() always dials
    config.PORT (a fixed, module-level constant) rather than taking a
    port argument, so the dynamic port this fixture's server actually
    listens on has to be patched in for the duration of the test --
    exactly the same session's-worth of a port ClientSession would use
    in the real running application, just monkeypatched to point at
    this ephemeral test server instead of the real default (5000)."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice_payload = _register_user("alice_")
    bob_payload = _register_user("bob_")

    alice = _make_connected_session(alice_payload)
    bob = _make_connected_session(bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    _open_direct_chat(alice, bob.username)
    _open_direct_chat(bob, alice.username)

    conversation_id = alice.current_conversation_id
    assert conversation_id == bob.current_conversation_id

    yield {
        "port": port,
        "conversation_id": conversation_id,
        "alice_payload": alice_payload,
        "bob_payload": bob_payload,
        "alice": alice,
        "bob": bob,
    }

    for session in (alice, bob):
        try:
            session.disconnect()
        except Exception:
            pass
    _delete_user(alice_payload["username"])
    _delete_user(bob_payload["username"])


def _last_received_text(session, from_username):
    """The most recent message ConversationStore recorded for a
    direct conversation with ``from_username``, or None."""
    summary = session.conversation_store.get(from_username)
    if summary is None or summary.latest_message is None:
        return None
    return summary.latest_message.text


def test_baseline_direct_messaging_works_before_restart(alice_and_bob):
    """Sanity check the fixture -- if this fails, the bug is
    elsewhere, not in restart recovery."""
    alice = alice_and_bob["alice"]
    bob = alice_and_bob["bob"]

    alice.send_chat_message("hello bob, before any restart")

    assert _wait_for(
        lambda: _last_received_text(bob, alice.username) == "hello bob, before any restart"
    )


def test_key_recovers_after_alice_restarts(alice_and_bob):
    """The core A1 regression test: Alice restarts (fresh
    ClientSession/KeyManager, same account), reconnects, and the
    conversation must recover automatically -- both directions."""
    fixture = alice_and_bob
    port = fixture["port"]
    bob = fixture["bob"]
    conversation_id = fixture["conversation_id"]

    old_alice = fixture["alice"]

    # Establish the pre-restart baseline both directions, so the fix
    # is proven against real prior state, not an empty conversation.
    old_alice.send_chat_message("message before the restart")
    assert _wait_for(
        lambda: _last_received_text(bob, old_alice.username) == "message before the restart"
    )

    pre_restart_epoch = old_alice.key_manager.current_epoch(conversation_id)
    assert pre_restart_epoch is not None

    # --- Alice restarts ---
    old_alice.disconnect()

    new_alice = _make_connected_session(fixture["alice_payload"])

    assert _wait_for(
        lambda: new_alice.key_manager.get_public_key(bob.username) is not None
    )

    _open_direct_chat(new_alice, bob.username)
    assert new_alice.current_conversation_id == conversation_id

    # A brand-new KeyManager -- exactly the state a real restart
    # leaves a client in, and exactly what caused the reported bug.
    assert new_alice.key_manager.get_key(conversation_id) is None

    # New Alice sends -- must establish a NEW key under a NEW epoch,
    # not the old, already-claimed one.
    new_alice.send_chat_message("message after the restart")

    assert _wait_for(
        lambda: _last_received_text(bob, new_alice.username) == "message after the restart"
    ), "Bob never received/decrypted Alice's post-restart message -- key desync reproduced"

    post_restart_epoch = new_alice.key_manager.current_epoch(conversation_id)
    assert post_restart_epoch is not None
    assert post_restart_epoch > pre_restart_epoch, (
        "the post-restart key must use a NEW epoch, not collide with the old one"
    )

    # Bob must now hold BOTH epochs -- the old one (so his own
    # pre-restart history stays readable) and the new one -- never an
    # overwrite.
    assert bob.key_manager.get_key(conversation_id, epoch=pre_restart_epoch) is not None
    assert bob.key_manager.get_key(conversation_id, epoch=post_restart_epoch) is not None
    assert bob.key_manager.current_epoch(conversation_id) == post_restart_epoch

    # Bob replies -- new Alice must decrypt it correctly, proving full
    # two-way recovery, not just Alice-to-Bob.
    bob.send_chat_message("welcome back, alice")

    assert _wait_for(
        lambda: _last_received_text(new_alice, bob.username) == "welcome back, alice"
    ), "Alice never received/decrypted Bob's reply after her restart"

    new_alice.disconnect()


def test_epoch_reservation_is_server_persisted_not_local(alice_and_bob):
    """The counter driving this fix must survive in the database, not
    just in-process -- otherwise two simultaneous restarts could
    collide. Verified directly against the same conversation row
    Phase 7's group-key epochs already use."""
    fixture = alice_and_bob
    alice = fixture["alice"]
    conversation_id = fixture["conversation_id"]

    alice.send_chat_message("first message establishes an epoch")
    assert _wait_for(lambda: alice.key_manager.current_epoch(conversation_id) is not None)

    current, _confirmed = _get_epoch_state(conversation_id)
    assert current == alice.key_manager.current_epoch(conversation_id)
    assert current >= 2, (
        "a direct conversation's first real key must reserve epoch >= 2 -- "
        "epoch 1 is the conversation row's untouched default, never assumed "
        "free without reservation"
    )


def test_key_manager_still_never_overwrites_an_existing_epoch():
    """Guard: this fix must not weaken the existing no-overwrite
    guarantee group-key rotation depends on."""
    manager = KeyManager()
    manager.store_key("conversation-1", b"original-key-32-bytes-long-here", epoch=2)
    manager.store_key("conversation-1", b"different-key-32-bytes-long-her", epoch=2)
    assert manager.get_key("conversation-1", epoch=2) == b"original-key-32-bytes-long-here"
