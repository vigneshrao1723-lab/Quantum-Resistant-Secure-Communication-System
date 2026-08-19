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

    # Every session a test creates is tracked here and disconnected in
    # teardown, whether the test passes or fails. A test that builds a
    # session locally and disconnects it on its last line leaks that
    # connection the moment any earlier assertion fails: the server's
    # handler thread stays alive holding a TLS socket, and
    # ServerHarness.shutdown() then fails with "handler thread(s) did
    # not terminate" -- which is exactly the leaked-thread condition
    # the harness exists to catch, and which can contaminate later
    # tests in the same run. Tests use fixture["connect"](payload).
    tracked = []

    def _connect(payload):
        session = _make_connected_session(payload)
        tracked.append(session)
        return session

    alice = _connect(alice_payload)
    bob = _connect(bob_payload)

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
        "connect": _connect,
    }

    for session in tracked:
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


def test_restart_recovers_the_historical_key_when_the_partner_is_connected(
    alice_and_bob,
):
    """TEST A -- a restart with the partner still connected RECOVERS
    the historical epoch rather than minting a new one (BUG 4 Fix B).

    This replaces an earlier assertion that a restarted client must
    hold no key and must reserve a NEW epoch on its next send. That
    described the world before direct key recovery existed, and it is
    no longer what the architecture does or should do:

      * Rotation in this project is triggered by GROUP MEMBERSHIP
        change and nothing else -- reserve_next_epoch() is called from
        handle_group_leave() and handle_group_add_members(). A direct
        conversation has no membership changes, so it has no rotation
        trigger at all.
      * establish_session_key()'s epoch reservation exists for
        COLLISION AVOIDANCE ("no collision is possible", see its
        docstring), not for secrecy -- and it is skipped entirely by
        the long-standing `if self.key_manager.has_key(...): return`
        rule, which is what makes a key long-lived for as long as a
        client holds it.
      * README's "Reconnection and history recovery" states that a
        client reconnecting *including after a restart* recovers state
        from the server rather than relying on local cache.

    Nothing is weakened here: the no-collision invariant the original
    test protected is asserted in full by the two tests below, and
    this one adds coverage that did not exist -- that the recovered
    key is byte-identical to the original and that pre-restart history
    stays readable.
    """

    fixture = alice_and_bob
    bob = fixture["bob"]
    old_alice = fixture["alice"]
    conversation_id = fixture["conversation_id"]

    old_alice.send_chat_message("message before the restart")
    assert _wait_for(
        lambda: _last_received_text(bob, old_alice.username)
        == "message before the restart"
    )

    pre_restart_epoch = old_alice.key_manager.current_epoch(conversation_id)
    assert pre_restart_epoch is not None
    pre_restart_key = old_alice.key_manager.get_key(
        conversation_id, epoch=pre_restart_epoch
    )
    assert pre_restart_key is not None

    # --- Alice restarts; Bob stays connected holding the key ---
    old_alice.disconnect()

    new_alice = fixture["connect"](fixture["alice_payload"])

    assert _wait_for(
        lambda: new_alice.key_manager.get_public_key(bob.username) is not None
    )

    # Deterministic: wait for recovery rather than racing it.
    assert _wait_for(
        lambda: new_alice.key_manager.get_key(
            conversation_id, epoch=pre_restart_epoch
        )
        is not None
    ), "reconnect did not recover the historical direct key"

    # The recovered key is the ORIGINAL, not a replacement.
    assert (
        new_alice.key_manager.get_key(conversation_id, epoch=pre_restart_epoch)
        == pre_restart_key
    )
    assert new_alice.key_manager.current_epoch(conversation_id) == pre_restart_epoch

    _open_direct_chat(new_alice, bob.username)
    assert new_alice.current_conversation_id == conversation_id

    # Pre-restart history is readable again -- the point of recovering.
    history = new_alice.load_conversation_history(bob.username, is_group=False)
    assert any(
        row["text"] == "message before the restart" for row in history
    ), "the pre-restart message did not decrypt after the restart"

    # --- Alice sends again: she must REUSE the recovered key ---
    new_alice.send_chat_message("message after the restart")

    assert _wait_for(
        lambda: _last_received_text(bob, new_alice.username)
        == "message after the restart"
    ), "Bob never received/decrypted Alice's post-restart message"

    assert new_alice.key_manager.current_epoch(conversation_id) == pre_restart_epoch, (
        "a recovered key must be reused, not replaced by a fresh epoch"
    )

    # No unnecessary epoch was burned server-side either.
    current, _confirmed = _get_epoch_state(conversation_id)
    assert current == pre_restart_epoch

    # Bob still holds exactly the one epoch, unchanged and unoverwritten.
    assert (
        bob.key_manager.get_key(conversation_id, epoch=pre_restart_epoch)
        == pre_restart_key
    )

    # --- Two-way ---
    bob.send_chat_message("welcome back, alice")

    assert _wait_for(
        lambda: _last_received_text(new_alice, bob.username) == "welcome back, alice"
    ), "Alice never received/decrypted Bob's reply after her restart"


def test_restart_reserves_a_new_epoch_when_no_recovery_is_possible(alice_and_bob):
    """TEST B -- recovery unavailable.

    Both sides restart, so nobody is left holding the historical key
    and there is nothing to recover. This is the path that still needs
    establish_session_key()'s epoch reservation, and it must reserve a
    genuinely NEW epoch rather than reusing a number either side might
    already have claimed.
    """

    fixture = alice_and_bob
    old_alice = fixture["alice"]
    old_bob = fixture["bob"]
    conversation_id = fixture["conversation_id"]

    old_alice.send_chat_message("message before both restart")
    assert _wait_for(
        lambda: _last_received_text(old_bob, old_alice.username)
        == "message before both restart"
    )

    pre_restart_epoch = old_alice.key_manager.current_epoch(conversation_id)
    assert pre_restart_epoch is not None

    # --- Both restart: no client anywhere still holds the key ---
    old_alice.disconnect()
    old_bob.disconnect()
    time.sleep(0.4)

    new_bob = fixture["connect"](fixture["bob_payload"])
    new_alice = fixture["connect"](fixture["alice_payload"])

    assert _wait_for(
        lambda: new_alice.key_manager.get_public_key(new_bob.username) is not None
    )
    assert _wait_for(
        lambda: new_bob.key_manager.get_public_key(new_alice.username) is not None
    )

    # Nothing can be recovered -- neither side has the key to give.
    assert new_alice.key_manager.get_key(conversation_id) is None
    assert new_bob.key_manager.get_key(conversation_id) is None

    _open_direct_chat(new_alice, new_bob.username)
    _open_direct_chat(new_bob, new_alice.username)
    assert new_alice.current_conversation_id == conversation_id

    new_alice.send_chat_message("message after both restarted")

    assert _wait_for(
        lambda: _last_received_text(new_bob, new_alice.username)
        == "message after both restarted"
    ), "Bob never received/decrypted the post-restart message -- key desync"

    post_restart_epoch = new_alice.key_manager.current_epoch(conversation_id)
    assert post_restart_epoch is not None
    assert post_restart_epoch > pre_restart_epoch, (
        "the post-restart key must use a NEW epoch, not collide with the old one"
    )

    assert new_bob.key_manager.get_key(conversation_id, epoch=post_restart_epoch) is not None

    new_bob.send_chat_message("hello again alice")
    assert _wait_for(
        lambda: _last_received_text(new_alice, new_bob.username)
        == "hello again alice"
    ), "two-way messaging did not recover after both sides restarted"


def test_restart_without_recovery_never_collides_with_the_partners_epoch(
    alice_and_bob,
):
    """TEST B, continued -- the original A1 no-collision invariant,
    preserved exactly.

    Alice restarts while Bob is briefly disconnected, so no partner is
    online to recover from; Bob then returns with his KeyManager
    intact. Alice therefore has no key and must reserve a NEW epoch --
    and Bob, who still holds the OLD one, must end up holding BOTH.
    That is precisely the desynchronization the A1 fix exists to
    prevent: before it, Alice's new key landed on epoch 1, Bob refused
    to overwrite his cached epoch 1, and the two diverged forever.
    """

    fixture = alice_and_bob
    old_alice = fixture["alice"]
    bob = fixture["bob"]
    conversation_id = fixture["conversation_id"]

    old_alice.send_chat_message("before alice restarts alone")
    assert _wait_for(
        lambda: _last_received_text(bob, old_alice.username)
        == "before alice restarts alone"
    )

    pre_restart_epoch = old_alice.key_manager.current_epoch(conversation_id)
    pre_restart_key = bob.key_manager.get_key(
        conversation_id, epoch=pre_restart_epoch
    )
    assert pre_restart_key is not None

    # Bob drops off the socket but keeps his KeyManager (a connection
    # blip, not an application restart), and Alice restarts while he
    # is away -- so there is no connected partner to recover from.
    bob.disconnect()
    time.sleep(0.4)
    old_alice.disconnect()

    new_alice = fixture["connect"](fixture["alice_payload"])
    time.sleep(0.6)

    assert new_alice.key_manager.get_key(conversation_id) is None, (
        "nothing should have been recoverable with no partner connected"
    )

    # Bob comes back, still holding the old epoch.
    bob.connect()
    bob.login(fixture["bob_payload"]["username"])
    bob.send_public_key()
    bob.start_receiver()

    assert _wait_for(
        lambda: new_alice.key_manager.get_public_key(bob.username) is not None
    )

    _open_direct_chat(new_alice, bob.username)
    new_alice.send_chat_message("after alice restarted alone")

    assert _wait_for(
        lambda: _last_received_text(bob, new_alice.username)
        == "after alice restarted alone"
    ), "Bob never received/decrypted Alice's message -- key desync reproduced"

    post_restart_epoch = new_alice.key_manager.current_epoch(conversation_id)
    assert post_restart_epoch > pre_restart_epoch, (
        "the post-restart key must use a NEW epoch, not collide with the old one"
    )

    # Bob holds BOTH -- the old one (so his own pre-restart history
    # stays readable) and the new one. Never an overwrite.
    assert (
        bob.key_manager.get_key(conversation_id, epoch=pre_restart_epoch)
        == pre_restart_key
    )
    assert bob.key_manager.get_key(conversation_id, epoch=post_restart_epoch) is not None
    assert bob.key_manager.current_epoch(conversation_id) == post_restart_epoch

    bob.send_chat_message("and hello back")
    assert _wait_for(
        lambda: _last_received_text(new_alice, bob.username) == "and hello back"
    ), "Alice never received/decrypted Bob's reply"


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
