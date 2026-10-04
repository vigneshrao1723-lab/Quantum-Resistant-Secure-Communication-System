"""
BUG -- Offline First Contact: starting a brand-new direct conversation
with a recipient who has never connected while the sender was online.

Root cause (read-only investigation, confirmed): ML-KEM (Kyber) is a
KEM, not a public-key encryption scheme -- encapsulate() always
derives its OWN fresh shared secret from the recipient's public key
(crypto/kyber.py), so ClientSession.establish_session_key() could not
even GENERATE a session key without the recipient's public key already
cached, let alone deliver one. A conversation opened via Find User with
someone currently offline was real, but the first send attempt raised
ValueError("No public key found for <user>") before anything was
encrypted.

The fix (client/session.py::establish_session_key()): the AES session
key is now always generated locally first (os.urandom(32)), stored
immediately, and used to encrypt/persist the message regardless of
public-key availability. Delivery to the recipient, when their public
key IS available, reuses KeyManager.wrap_key_for_member() -- the same
KEM-then-DEM hybrid wrap already used for group key distribution and
for direct key redelivery -- sent as a group_key_distribution packet.
When it is NOT available, delivery is deferred entirely to the
existing membership/epoch-driven recovery mechanism
(_ensure_group_keys_current_for_reconnecting_user() /
handle_direct_key_redelivery_required()), unchanged, which was already
proven (tests/test_offline_messaging.py) to redeliver an established
conversation's key on reconnect -- this file proves it also does so
for a conversation that never had a live key exchange at all.

RSA is intentionally untouched (see establish_session_key()'s
docstring and tests/test_rsa_key_exchange_integration.py): RSA-OAEP
already wraps a caller-chosen key directly, so it never had this
problem, and changing its wire shape would have broken existing,
deliberate protocol-shape coverage for no benefit.

Fixture conventions mirror tests/test_offline_messaging.py (the
`connect` factory -- a fresh ClientSession is a genuinely restarted
client) and tests/test_key_store_persistence.py (the `app` fixture --
a real authenticate_credentials() launch, which actually unlocks the
per-user encrypted local key store) for the one test that needs a
genuine sender-side restart.

Run with:
    pytest tests/test_offline_first_contact.py -v
"""

import time
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession, _UNDECRYPTABLE_PLACEHOLDER
from crypto.key_manager import KeyManager, fingerprint_combined_identity, fingerprint_public_key
from database.connection import SessionLocal
from database.models.message import Message
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server

PASSWORD = "Str0ng!Passw0rd"


# ----------------------------------------------------------------------
# Account / session helpers -- same conventions as
# tests/test_offline_messaging.py and tests/test_key_store_persistence.py
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Offline First Contact Test",
            "username": f"ofc_{hint}{suffix}",
            "email": f"ofc_{hint}{suffix}@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": "+91%012d" % (uuid.uuid4().int % 10**12),
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete(username):
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


def _token(payload):
    db = SessionLocal()
    try:
        result = AuthenticationService(db).authenticate_user(
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _wait_for(predicate, attempts=150, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


@pytest.fixture()
def accounts():
    created = []

    def _make(hint):
        payload = _register(hint)
        created.append(payload)
        return payload

    yield _make

    for payload in created:
        _delete(payload["username"])


def _identity_fingerprint(key_manager):
    """
    Protocol-Level ML-DSA Origin Authentication: the fingerprint a real
    ClientSession's signed send_public_key() packet is actually
    observed and stored under -- the COMBINED (ML-KEM + ML-DSA)
    fingerprint, since a real send_public_key() call always attaches
    an ML-DSA signature now. Used here to pre-seed a VERIFIED entry
    that will later be compared against a real signed reconnect from
    the SAME key_manager -- using the legacy single-key fingerprint
    here would make that later comparison spuriously disagree, exactly
    the failure this phase's own design predicted (see client/
    session.py::confirm_peer_verification()'s docstring)."""

    return fingerprint_combined_identity(
        key_manager.public_key, key_manager.ml_dsa.export_public_key()
    )


def _receiver_store_verifying(receiver_user_id, sender_username, sender_key_manager):
    """Phase 13: a real, unlocked SecureKeyStore for a session that
    will RECEIVE a group_key_distribution packet (a redelivery/
    recovery), pre-seeded with the sender's identity already VERIFIED
    -- built and verified before that session ever connects, exactly
    like this file's existing pattern of verifying the recipient's
    fingerprint before THEY connect (redelivery is a one-shot event
    with no retry, so verifying only afterward would race it). Reuses
    the `app` fixture's already-active KEY_STORE_DIR monkeypatch
    (this helper is only ever called from a test that has `app` as a
    fixture parameter), so this shares the same on-disk root as every
    other key store in the test."""

    store = SecureKeyStore(receiver_user_id)
    store.unlock(PASSWORD)
    store.verify_peer_fingerprint(
        sender_username,
        _identity_fingerprint(sender_key_manager),
        signing_public_key=sender_key_manager.ml_dsa.export_public_key(),
    )
    return store


@pytest.fixture()
def connect(running_server, monkeypatch):
    """Factory for real, connected ClientSessions (token-based login,
    no key-store unlock -- matches tests/test_offline_messaging.py).

    Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication): a
    session built by this lighter factory has no key_store at all, so
    it can never satisfy handle_group_key_distribution()'s new
    VERIFIED-sender requirement -- there is nowhere for that state to
    live. A test that needs THIS session to be the RECEIVER of a
    group_key_distribution packet (a redelivery/recovery, not merely
    the sender of one) must pass a real, pre-seeded `key_store=`
    (built with the `app` fixture's own KEY_STORE_DIR, and verified
    against the sender's fingerprint before this call) -- the optional
    `key_store` parameter below exists for exactly that."""

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    opened = []

    def _connect(payload, key_manager=None, key_store=None):
        session = ClientSession()
        if key_manager is not None:
            session.key_manager = key_manager
        if key_store is not None:
            session.key_store = key_store
        session.user_id = payload["user_id"]
        session.access_token = _token(payload)
        session.connect()
        session.login(payload["username"])
        session.send_public_key()
        session.start_receiver()
        opened.append(session)
        return session

    yield _connect

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001 -- teardown must not mask a failure
            pass


@pytest.fixture()
def app(running_server, monkeypatch, tmp_path):
    """Launch real application sessions with a real, isolated, on-disk
    encrypted key store (matches tests/test_key_store_persistence.py) --
    needed only for the sender-restart test, where a token-based
    `connect` session (no key-store unlock) would not prove anything
    about disk persistence."""

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr(
        "storage.secure_key_store.KEY_STORE_DIR", tmp_path / "keystore"
    )

    opened = []

    def _launch(payload, password=PASSWORD):
        session = ClientSession()
        opened.append(session)

        result = session.authenticate_credentials(payload["phone_number"], password)
        assert result.success, result.message

        session.user_id = result.user_id
        session.username = result.username
        session.session_id = result.session_id
        session.access_token = result.token_pair.access_token
        session.refresh_token = result.token_pair.refresh_token

        session.connect()
        session.login(payload["username"])
        session.send_public_key()
        session.start_receiver()
        return session

    yield _launch

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001
            pass


def _open_direct(session, partner):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=partner,
            is_online=True,
            latest_message=None,
        )
    )


def _disconnect(session):
    session.disconnect()
    time.sleep(0.3)


def _wait_for_key(session, conversation_id, epoch=None):
    return _wait_for(
        lambda: session.key_manager.has_key(conversation_id, epoch=epoch)
    )


def _history(session, partner):
    _open_direct(session, partner)
    return session.load_conversation_history(partner, is_group=False)


def _received_texts(history):
    return [row["text"] for row in history if not row["is_own"]]


# ----------------------------------------------------------------------
# 1/2 -- generation and persistence work with no recipient public key
# ----------------------------------------------------------------------


def test_session_key_generated_locally_with_no_recipient_public_key(
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")  # registered, never connects

    alice = connect(alice_payload)

    _open_direct(alice, bob_payload["username"])
    conversation_id = alice.current_conversation_id

    assert alice.key_manager.get_public_key(bob_payload["username"]) is None
    assert alice.key_manager.has_key(conversation_id) is False

    # establish_session_key() must not raise -- previously this raised
    # ValueError("No public key found for ...") at generation time.
    alice.establish_session_key()

    assert alice.key_manager.has_key(conversation_id) is True
    assert alice.key_manager.get_public_key(bob_payload["username"]) is None, (
        "generation must never require or fabricate a public key"
    )


def test_message_to_never_connected_recipient_is_encrypted_and_persisted(
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)

    _open_direct(alice, bob_payload["username"])
    conversation_id = alice.current_conversation_id

    alice.send_chat_message("hello bob, you are offline")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "hello bob, you are offline"
            for summary in alice.conversation_store.get_all()
        )
    ), "the message was never recorded as sent locally"

    def _fetch_row():
        db = SessionLocal()
        try:
            return (
                db.query(Message)
                .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
                .order_by(Message.timestamp.desc())
                .first()
            )
        finally:
            db.close()

    assert _wait_for(lambda: _fetch_row() is not None), (
        "no message row was persisted server-side"
    )
    row = _fetch_row()

    assert row.ciphertext, "the persisted row has no ciphertext"
    assert "hello bob" not in row.ciphertext, (
        "plaintext leaked into the persisted ciphertext column"
    )


# ----------------------------------------------------------------------
# 3 -- no key-delivery packet is emitted with no recipient public key
# ----------------------------------------------------------------------


def test_no_key_delivery_packet_sent_when_public_key_unavailable(
    connect, accounts, monkeypatch
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", recording_send_message)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("no key to wrap this for yet")

    time.sleep(0.3)

    key_carrying = [
        p for p in sent_packets
        if p.get("operation") == "session_key" or p.get("type") == "group_key_distribution"
    ]
    assert key_carrying == [], f"key material was transmitted: {key_carrying}"


# ----------------------------------------------------------------------
# 4/5 -- once the recipient's public key arrives, the EXACT stored key
# is wrapped and delivered, and the recipient unwraps that exact key
# ----------------------------------------------------------------------


def test_exact_stored_key_is_wrapped_delivered_and_unwrapped_once_recipient_connects(
    connect, accounts, app
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    # Server-Untrusted Identity Verification, Stage 3: the client that
    # will later redeliver the key to bob (alice) must have a real,
    # unlocked key store to record a verification against -- the
    # lighter `connect` factory never unlocks one (see
    # tests/test_peer_key_verification.py's module docstring).
    alice = app(alice_payload)

    _open_direct(alice, bob_payload["username"])
    conversation_id = alice.current_conversation_id

    alice.send_chat_message("first contact")

    original_key = alice.key_manager.get_key(conversation_id)
    original_epoch = alice.key_manager.current_epoch(conversation_id)
    assert original_key is not None
    assert len(original_key) == 32

    # Bob's real Kyber keypair is generated up front (KeyManager()
    # already does this in __init__, before any connection exists), so
    # alice can verify his fingerprint BEFORE he ever connects -- the
    # redelivery this test waits on is a one-shot event triggered right
    # at his reconnect, with no retry, so verifying only after `connect`
    # returns would race it.
    bob_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob_key_manager)
    )

    # Phase 13: bob is the RECEIVER of the redelivered key, so his own
    # session now also needs alice's identity already VERIFIED -- see
    # _receiver_store_verifying()'s docstring.
    bob_store = _receiver_store_verifying(
        bob_payload["user_id"], alice_payload["username"], alice.key_manager
    )

    bob = connect(
        bob_payload, key_manager=bob_key_manager, key_store=bob_store
    )  # triggers recovery, not a live session_key

    assert _wait_for_key(bob, conversation_id, epoch=original_epoch), (
        "bob never recovered the first-contact key"
    )

    assert bob.key_manager.get_key(conversation_id, epoch=original_epoch) == original_key, (
        "bob's recovered key does not match the exact key alice generated"
    )


# ----------------------------------------------------------------------
# 6 -- the first-contact offline message decrypts once the recipient
# reconnects
# ----------------------------------------------------------------------


def test_first_contact_offline_message_decrypts_after_recipient_reconnects(
    connect, accounts, app
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    # See test_exact_stored_key_is_wrapped_delivered_and_unwrapped_once_
    # recipient_connects above: alice needs a real key store to verify
    # bob against, since she is the one who must redeliver his key once
    # he reconnects.
    alice = app(alice_payload)

    _open_direct(alice, bob_payload["username"])
    conversation_id = alice.current_conversation_id

    alice.send_chat_message("hello bob, first message ever")

    # Verify bob's fingerprint before he ever connects -- the
    # redelivery his reconnect triggers is a one-shot event with no
    # retry.
    bob_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob_key_manager)
    )

    # Phase 13: bob is the RECEIVER of the redelivered key, so his own
    # session now also needs alice's identity already VERIFIED -- see
    # _receiver_store_verifying()'s docstring.
    bob_store = _receiver_store_verifying(
        bob_payload["user_id"], alice_payload["username"], alice.key_manager
    )

    bob = connect(bob_payload, key_manager=bob_key_manager, key_store=bob_store)

    assert _wait_for_key(bob, conversation_id), "recovery never delivered the key"

    texts = _received_texts(_history(bob, alice_payload["username"]))

    assert "hello bob, first message ever" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts


# ----------------------------------------------------------------------
# 7 -- sender restart between sending and the recipient's recovery
# ----------------------------------------------------------------------


def test_sender_restart_between_message_and_recipient_recovery_still_works(app, connect):
    """The scenario the CRITICAL ADDITIONAL QUESTION was about: Alice
    sends to offline Bob, closes her app entirely (fresh KeyManager,
    fresh Kyber/RSA identity keypair on next launch), and only later
    logs back in. Her AES session key for this conversation must
    survive via the local encrypted key store -- not via anything held
    in memory by the now-closed process -- so that when Bob eventually
    reconnects, recovery can still succeed."""

    alice_payload = _register("alice_")
    bob_payload = _register("bob_")

    try:
        alice = app(alice_payload)

        _open_direct(alice, bob_payload["username"])
        conversation_id = alice.current_conversation_id

        alice.send_chat_message("sent before alice's own restart")

        original_key = alice.key_manager.get_key(conversation_id)
        assert original_key is not None

        # Alice's app closes entirely.
        _disconnect(alice)

        # Alice logs back in later: brand-new ClientSession, brand-new
        # KeyManager, brand-new Kyber/RSA identity keypair -- but the
        # SAME on-disk key store, unlocked with the same password.
        alice_restarted = app(alice_payload)
        assert alice_restarted.key_manager is not alice.key_manager

        assert alice_restarted.key_manager.get_key(conversation_id) == original_key, (
            "the session key did not survive alice's own restart via "
            "the local encrypted key store"
        )

        # Bob's own real keypair is generated up front so alice_restarted
        # can verify his fingerprint BEFORE he ever connects -- the
        # redelivery his reconnect triggers is a one-shot event with no
        # retry, so verifying only after he connects would race it.
        bob_key_manager = KeyManager()
        alice_restarted.key_store.verify_peer_fingerprint(
            bob_payload["username"], _identity_fingerprint(bob_key_manager)
        )

        # Phase 13: bob is the RECEIVER of the redelivered key, so his
        # own session now also needs alice_restarted's (current, post-
        # restart) identity already VERIFIED -- see
        # _receiver_store_verifying()'s docstring.
        bob_store = _receiver_store_verifying(
            bob_payload["user_id"],
            alice_payload["username"],
            alice_restarted.key_manager,
        )

        # Bob connects for the first time now.
        bob = connect(bob_payload, key_manager=bob_key_manager, key_store=bob_store)

        assert _wait_for_key(bob, conversation_id), (
            "recovery never landed after alice's restart"
        )

        texts = _received_texts(_history(bob, alice_payload["username"]))

        assert "sent before alice's own restart" in texts
        assert _UNDECRYPTABLE_PLACEHOLDER not in texts
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


# ----------------------------------------------------------------------
# 8 -- existing, already-established direct conversations are
# unaffected (both sides online, live key exchange as before)
# ----------------------------------------------------------------------


def test_existing_established_direct_conversation_still_works(app, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    # Both sides send in this test, so both need a real key store to
    # verify the other against (see test_peer_key_verification.py's
    # module docstring on why the lighter `connect` factory cannot
    # exercise this).
    alice = app(alice_payload)
    bob = app(bob_payload)  # both online -> live public-key exchange

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )
    assert _wait_for(
        lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None
    )

    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob.key_manager)
    )
    bob.key_store.verify_peer_fingerprint(
        alice_payload["username"], _identity_fingerprint(alice.key_manager)
    )

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("established conversation still works")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "established conversation still works"
            for summary in bob.conversation_store.get_all()
        )
    )

    # And the reply direction, over the same key.
    _open_direct(bob, alice_payload["username"])
    bob.send_chat_message("reply also still works")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "reply also still works"
            for summary in alice.conversation_store.get_all()
        )
    )
