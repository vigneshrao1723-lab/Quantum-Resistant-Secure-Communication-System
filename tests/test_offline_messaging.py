"""
BUG 4 -- offline direct messaging.

Two fixes are covered here, and they are independent:

  Fix A -- a message to a real, registered user who is simply offline
           is persisted and ACKNOWLEDGED (message_queued), not
           reported to the sender as a delivery failure.

  Fix B -- when that user reconnects, the session key their queued
           messages were encrypted under is redelivered by a still-
           connected partner, so the messages actually become
           readable instead of rendering as the "encrypted in a
           previous session" placeholder forever.

The tests that matter most here are the ones using a FRESH
ClientSession for the reconnecting user. A fresh session means a fresh
KeyManager, which means a fresh keypair and an empty key store -- i.e.
a genuinely restarted client, which is what "offline" means in
practice when someone closes the app. Nothing in this file ever calls
key_manager.store_key() to plant a key by hand: doing so would test
decryption while skipping the exact step the bug was about (see the
scope warning on
test_offline_message_appears_and_decrypts_in_recipient_history_after_reconnect
in tests/test_message_persistence_integration.py).
"""

import socket
import time
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession, _UNDECRYPTABLE_PLACEHOLDER
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from database.connection import SessionLocal
from database.models.message import Message
from database.models.message_recipient import MessageRecipient
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.message_delivery_status import MessageDeliveryStatus
from tests.tls_test_support import start_test_server, wrap_client_socket
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_public_key_packet,
    parse_packet,
)


# ----------------------------------------------------------------------
# Account / session helpers
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Offline Messaging Test",
            "username": f"om_{hint}{suffix}",
            "email": f"om_{hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
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


def _wait_for(predicate, attempts=120, interval=0.05):
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


@pytest.fixture()
def connect(running_server, monkeypatch, tmp_path):
    """Factory for real, connected ClientSessions.

    Every call builds a brand-new ClientSession, so unless a test
    explicitly hands back a previous session's KeyManager, each
    connection is a genuinely restarted client with an empty key store
    and a new keypair.

    Server-Untrusted Identity Verification, Stage 3: establish_
    session_key()/handle_direct_key_redelivery_required() now refuse a
    cached-but-unverified peer key, so every session here also needs a
    real, unlocked SecureKeyStore to verify against (the reference
    pattern in tests/test_peer_key_verification.py's `app` fixture).
    Each call points KEY_STORE_DIR at its OWN fresh, never-reused
    directory -- not one shared by username -- so unlocking it never
    itself hands back a previous session's peer-verification record or
    conversation keys. Sharing one would defeat this file's entire
    point: a "genuinely restarted client" must recover solely through
    the redelivery mechanism under test, never through persistence
    smuggled in by the test harness.
    """

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    opened = []

    def _connect(payload, key_manager=None, pre_verify=None):
        """``pre_verify``, if given, is called with the new session
        right after its own fresh key store is unlocked but before any
        network activity (Phase 13: Group-Key-Distribution ML-DSA
        Origin Authentication) -- the hook a test uses to seed this
        session's verification of a peer's identity BEFORE it
        connects, so a one-shot, no-retry redelivery/recovery this
        connect triggers is never raced. Each call's key store is its
        own fresh, isolated directory (see this fixture's own
        docstring), so a "restarted" session's key store never already
        holds a verification from its previous incarnation -- this is
        the only way to re-establish one."""

        monkeypatch.setattr(
            "storage.secure_key_store.KEY_STORE_DIR",
            tmp_path / f"keystore-{uuid.uuid4().hex}",
        )

        session = ClientSession()
        if key_manager is not None:
            session.key_manager = key_manager

        result = session.authenticate_credentials(
            payload["phone_number"], payload["password"]
        )
        assert result.success, result.message

        session.user_id = result.user_id
        session.username = result.username
        session.access_token = result.token_pair.access_token

        if pre_verify is not None:
            pre_verify(session)

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


def _identity_fingerprint(key_manager):
    """
    Protocol-Level ML-DSA Origin Authentication: the fingerprint a real
    ClientSession's signed send_public_key() packet is actually
    observed and stored under -- the COMBINED (ML-KEM + ML-DSA)
    fingerprint, since a real send_public_key() call always attaches
    an ML-DSA signature now. Every verify_peer_fingerprint() call in
    this file pre-seeds a VERIFIED entry against a peer that will (or
    already did) send a real signed packet from this exact
    key_manager -- using the legacy single-key fingerprint would make
    that later comparison spuriously disagree (client/session.py::
    confirm_peer_verification()'s docstring covers why the two
    conventions must never be mixed for one peer)."""

    return fingerprint_combined_identity(
        key_manager.public_key, key_manager.ml_dsa.export_public_key()
    )


def _verifying(sender_name, sender_key_manager):
    """A `connect(..., pre_verify=...)` callback (Phase 13) that marks
    ``sender_name`` VERIFIED in the new session's own fresh key store
    before it ever connects -- for a session that is about to be the
    RECEIVER of a redelivered/recovered group_key_distribution packet
    from that sender, which now requires exactly this."""

    def _apply(session):
        session.key_store.verify_peer_fingerprint(
            sender_name,
            _identity_fingerprint(sender_key_manager),
            signing_public_key=sender_key_manager.ml_dsa.export_public_key(),
        )

    return _apply


def _establish_direct_key(sender, recipient, sender_name, recipient_name):
    """Get the pair to a real, exchanged session key by sending one
    message while both are connected. Returns the conversation_id."""

    assert _wait_for(lambda: sender.key_manager.get_public_key(recipient_name) is not None)
    assert _wait_for(lambda: recipient.key_manager.get_public_key(sender_name) is not None)

    # Server-Untrusted Identity Verification, Stage 3: establish_
    # session_key() now refuses a cached-but-unverified peer key, and
    # the direct-key-redelivery path silently skips an unverified
    # recipient. Every test in this file exercises one direction or
    # the other of that machinery (a live send here, a later
    # redelivery to a reconnecting partner elsewhere), so both sides
    # verify the other's CURRENT, just-exchanged fingerprint up front
    # -- the precondition this suite's setup never needed before this
    # feature existed. A party that later reconnects with a genuinely
    # new keypair is re-verified individually, at that point, by the
    # tests that do so.
    sender.key_store.verify_peer_fingerprint(
        recipient_name, _identity_fingerprint(recipient.key_manager)
    )
    recipient.key_store.verify_peer_fingerprint(
        sender_name, _identity_fingerprint(sender.key_manager)
    )

    _open_direct(sender, recipient_name)
    sender.send_chat_message("establishing the session key")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "establishing the session key"
            for summary in recipient.conversation_store.get_all()
        )
    )

    return sender.current_conversation_id


def _wait_for_key(session, conversation_id, epoch=None):
    """Wait until key recovery has actually landed.

    Recovery is asynchronous and takes several hops (server announces
    -> client asks for what it lacks -> server dispatches -> partner
    wraps -> relay -> store), so a test that reads history the instant
    it reconnects can outrun it. This waits on the real condition --
    the key being present -- rather than on a fixed sleep, so it is
    neither flaky nor slower than it has to be.
    """

    return _wait_for(
        lambda: session.key_manager.has_key(conversation_id, epoch=epoch)
    )


def _history(session, partner):
    _open_direct(session, partner)
    return session.load_conversation_history(partner, is_group=False)


def _received_texts(history):
    return [row["text"] for row in history if not row["is_own"]]


# ----------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------


def _recipient_rows(conversation_id, recipient_id):
    db = SessionLocal()
    try:
        return (
            db.query(MessageRecipient)
            .join(Message, MessageRecipient.message_id == Message.id)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .filter(MessageRecipient.recipient_id == uuid.UUID(str(recipient_id)))
            .all()
        )
    finally:
        db.close()


def _statuses(conversation_id, recipient_id):
    return sorted(row.status for row in _recipient_rows(conversation_id, recipient_id))


def _message_epochs(conversation_id):
    db = SessionLocal()
    try:
        rows = (
            db.query(Message)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .order_by(Message.timestamp)
            .all()
        )
        return [row.epoch for row in rows]
    finally:
        db.close()


# ======================================================================
# 1 -- online messaging must not regress
# ======================================================================


def test_online_direct_message_still_delivers_live(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("live message")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "live message"
            for summary in bob.conversation_store.get_all()
        )
    )

    # Live relay records DELIVERED, never QUEUED.
    assert _statuses(conversation_id, bob_payload["user_id"]) == [
        MessageDeliveryStatus.DELIVERED,
        MessageDeliveryStatus.DELIVERED,
    ]


# ======================================================================
# 2 -- Fix A: offline send is persisted, QUEUED, and acknowledged
# ======================================================================


def test_offline_send_is_persisted_queued_and_acknowledged(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    errors = []
    alice.error_occurred.connect(errors.append)

    queued_acks = []
    original = alice.handle_message_queued

    def _recording(packet, _original=original, _sink=queued_acks):
        _sink.append(dict(packet))
        return _original(packet)

    alice.handle_message_queued = _recording

    failures = []
    original_failure = alice.handle_delivery_failure

    def _recording_failure(packet, _original=original_failure, _sink=failures):
        _sink.append(dict(packet))
        return _original(packet)

    alice.handle_delivery_failure = _recording_failure

    _disconnect(bob)
    assert _wait_for(lambda: bob_payload["username"] not in alice.online_users)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("sent while bob is offline")

    assert _wait_for(lambda: len(queued_acks) == 1)

    # The sender is told the message was accepted...
    assert queued_acks[0]["receiver"] == bob_payload["username"]
    assert queued_acks[0]["message_id"]
    assert queued_acks[0]["conversation_id"] == str(conversation_id)

    # ...and is NOT told it failed. This is the reported bug.
    time.sleep(0.5)
    assert failures == []
    assert errors == []

    # Persisted as ciphertext, with the recipient row QUEUED -- not
    # DELIVERED, because nothing was relayed to anyone.
    statuses = _statuses(conversation_id, bob_payload["user_id"])
    assert statuses.count(MessageDeliveryStatus.QUEUED) == 1
    assert MessageDeliveryStatus.QUEUED in statuses

    db = SessionLocal()
    try:
        stored = (
            db.query(Message)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .order_by(Message.timestamp)
            .all()
        )
        assert len(stored) == 2
        for row in stored:
            assert row.ciphertext
            assert "sent while bob is offline" not in row.ciphertext
    finally:
        db.close()


# ======================================================================
# 3 -- reconnect with the SAME KeyManager (a network blip)
# ======================================================================


def test_queued_messages_decrypt_when_the_key_survived_in_memory(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    surviving_key_manager = bob.key_manager
    _disconnect(bob)
    assert _wait_for(lambda: bob_payload["username"] not in alice.online_users)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("queued for a blip")

    bob_again = connect(bob_payload, key_manager=surviving_key_manager)
    time.sleep(0.8)

    texts = _received_texts(_history(bob_again, alice_payload["username"]))

    assert "queued for a blip" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts


# ======================================================================
# 4 -- Fix B: reconnect with a FRESH KeyManager (a real restart)
# ======================================================================


def test_queued_messages_decrypt_after_a_real_restart_via_key_recovery(
    connect, accounts
):
    """The core BUG 4 test.

    Bob reconnects as a genuinely fresh client -- new keypair, empty
    key store -- and the queued message must still become readable,
    using only the redelivery mechanism. No key is planted by hand
    anywhere in this test.
    """

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    _disconnect(bob)
    assert _wait_for(lambda: bob_payload["username"] not in alice.online_users)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("waiting for bob to restart")

    # Fresh session == fresh KeyManager == fresh keypair. Bob's new
    # public key is generated up front so alice can verify its
    # fingerprint BEFORE he ever reconnects -- the redelivery his
    # reconnect triggers is a one-shot event with no retry, so
    # verifying only after `connect` returns would race it.
    bob_new_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob_new_key_manager)
    )
    # Phase 13: bob_restarted is the RECEIVER of the redelivered key,
    # so his own fresh session also needs alice already VERIFIED.
    bob_restarted = connect(
        bob_payload,
        key_manager=bob_new_key_manager,
        pre_verify=_verifying(alice_payload["username"], alice.key_manager),
    )
    assert bob_restarted.key_manager is not bob.key_manager
    assert _wait_for_key(bob_restarted, conversation_id), "key recovery never landed"

    texts = _received_texts(_history(bob_restarted, alice_payload["username"]))

    assert "waiting for bob to restart" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts


# ======================================================================
# 5 / 6 -- ordering, and no duplication across repeated reconnects
# ======================================================================


def test_multiple_queued_messages_arrive_in_order_without_duplicates(
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    _disconnect(bob)
    assert _wait_for(lambda: bob_payload["username"] not in alice.online_users)

    _open_direct(alice, bob_payload["username"])
    for index in range(1, 4):
        alice.send_chat_message(f"queued {index}")
        time.sleep(0.15)

    # Bob's new public key is generated up front so alice can verify
    # its fingerprint before he ever reconnects -- the redelivery his
    # reconnect triggers is a one-shot event with no retry.
    bob_restarted_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"],
        _identity_fingerprint(bob_restarted_key_manager),
    )
    # Phase 13: bob_restarted is the RECEIVER of the redelivered key,
    # so his own fresh session also needs alice already VERIFIED.
    bob_restarted = connect(
        bob_payload,
        key_manager=bob_restarted_key_manager,
        pre_verify=_verifying(alice_payload["username"], alice.key_manager),
    )
    assert _wait_for_key(bob_restarted, conversation_id)
    texts = _received_texts(_history(bob_restarted, alice_payload["username"]))

    assert texts == [
        "establishing the session key",
        "queued 1",
        "queued 2",
        "queued 3",
    ]

    # Reconnect again -- recovery re-runs, and must not duplicate
    # anything or lose what already decrypted.
    _disconnect(bob_restarted)
    bob_third_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob_third_key_manager)
    )
    bob_third = connect(
        bob_payload,
        key_manager=bob_third_key_manager,
        pre_verify=_verifying(alice_payload["username"], alice.key_manager),
    )
    assert _wait_for_key(bob_third, conversation_id)
    repeat = _received_texts(_history(bob_third, alice_payload["username"]))

    assert repeat == texts
    assert len(repeat) == len(set(repeat))


# ======================================================================
# 7 -- messages decrypt under THEIR OWN epoch, not the current one
# ======================================================================


def test_recovery_uses_each_messages_own_epoch_not_the_current_epoch(
    connect, accounts
):
    """A direct conversation's CURRENT epoch advances every time
    either side establishes a key with an empty KeyManager, so the
    epoch a queued message needs is routinely not the current one.
    Recovery must ask for the message's own epoch.

    The conversation's reserved epoch is advanced directly here --
    exactly what a later key establishment does to that column, and
    the only part of it this test needs -- so that "current" and
    "required" are provably different numbers. If recovery asked for
    the current epoch, Bob would be handed a key that decrypts none of
    what he is waiting for, and the assertions below would fail.
    """

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )
    message_epoch = alice.key_manager.current_epoch(conversation_id)

    _disconnect(bob)
    assert _wait_for(lambda: bob_payload["username"] not in alice.online_users)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("encrypted under the older epoch")
    time.sleep(0.4)

    # Every queued message really is stamped with the epoch that
    # encrypted it.
    assert set(_message_epochs(conversation_id)) == {message_epoch}

    # Advance the conversation's reserved epoch past that.
    db = SessionLocal()
    try:
        repo = ConversationRepository(db)
        reserved = repo.reserve_next_epoch(uuid.UUID(str(conversation_id)))
        db.commit()
    finally:
        db.close()

    assert reserved > message_epoch, "current epoch must now differ from required"

    # Alice still holds the OLDER epoch's key and nothing else.
    assert alice.key_manager.has_key(conversation_id, epoch=message_epoch)
    assert not alice.key_manager.has_key(conversation_id, epoch=reserved)

    # Bob's new public key is generated up front so alice can verify
    # its fingerprint before he ever reconnects -- the redelivery his
    # reconnect triggers is a one-shot event with no retry.
    bob_restarted_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"],
        _identity_fingerprint(bob_restarted_key_manager),
    )
    # Phase 13: bob_restarted is the RECEIVER of the redelivered key,
    # so his own fresh session also needs alice already VERIFIED.
    bob_restarted = connect(
        bob_payload,
        key_manager=bob_restarted_key_manager,
        pre_verify=_verifying(alice_payload["username"], alice.key_manager),
    )
    assert _wait_for_key(bob_restarted, conversation_id, epoch=message_epoch)
    texts = _received_texts(_history(bob_restarted, alice_payload["username"]))

    assert "encrypted under the older epoch" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts

    # Historical decryptability is preserved, not traded away: the
    # older message the pair exchanged while both were online still
    # reads correctly too.
    assert "establishing the session key" in texts

    # Recovery must not have invented the reserved-but-unused epoch.
    assert not bob_restarted.key_manager.has_key(conversation_id, epoch=reserved)


def test_key_requirements_come_from_message_epochs_for_both_parties(
    connect, accounts
):
    """The repository query that drives recovery must report the
    epochs the stored messages actually carry -- and must do so for
    BOTH participants.

    The sender half is the part that regressed once already: a user's
    own sent messages have no MessageRecipient row of their own, so a
    delivery-status-driven query returned nothing for them and their
    own history stayed unreadable after a restart. Membership covers
    both sides.
    """

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )
    epoch = alice.key_manager.current_epoch(conversation_id)

    _disconnect(bob)
    assert _wait_for(lambda: bob_payload["username"] not in alice.online_users)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("queued under a known epoch")
    time.sleep(0.5)

    db = SessionLocal()
    try:
        repo = MessageRepository(db)
        for_bob = repo.get_direct_conversation_epochs_for_user(
            uuid.UUID(bob_payload["user_id"])
        )
        for_alice = repo.get_direct_conversation_epochs_for_user(
            uuid.UUID(alice_payload["user_id"])
        )
    finally:
        db.close()

    key = uuid.UUID(str(conversation_id))

    # The recipient needs the epoch...
    assert epoch in for_bob.get(key, [])

    # ...and so does the SENDER, for their own history.
    assert epoch in for_alice.get(key, [])


# ======================================================================
# 8 / 9 -- both parties offline: stay QUEUED, recover later
# ======================================================================


def test_messages_stay_queued_when_no_partner_is_connected(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    _disconnect(bob)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("nobody is around")
    time.sleep(0.4)

    # Alice leaves too, so when Bob returns there is no one holding
    # the key. Nothing may be invented, and nothing may be marked
    # delivered.
    _disconnect(alice)

    bob_restarted = connect(bob_payload)
    texts = _received_texts(_history(bob_restarted, alice_payload["username"]))

    assert texts and all(text == _UNDECRYPTABLE_PLACEHOLDER for text in texts)

    # The key-establishing message was live-relayed while Bob was
    # connected, so it is correctly DELIVERED; the one sent into the
    # void stays QUEUED. Nothing is upgraded merely because Bob came
    # back, and nothing is downgraded either.
    assert _statuses(conversation_id, bob_payload["user_id"]) == [
        MessageDeliveryStatus.DELIVERED,
        MessageDeliveryStatus.QUEUED,
    ]


def test_recovery_happens_when_the_partner_comes_back(connect, accounts):
    """Requirement 9: recovery is retried naturally. Bob reconnects
    while Alice is away (nothing recoverable), and Alice returning is
    what makes the key available -- via Bob's next reconnect."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )
    alice_key_manager = alice.key_manager

    _disconnect(bob)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("recovered later")
    time.sleep(0.4)
    _disconnect(alice)

    # Bob returns first -- no partner online, so nothing recovers.
    bob_early = connect(bob_payload)
    early = _received_texts(_history(bob_early, alice_payload["username"]))
    assert all(text == _UNDECRYPTABLE_PLACEHOLDER for text in early)
    _disconnect(bob_early)

    # Alice comes back still holding the epoch's key... She keeps her
    # own KeyManager (crypto identity + cached conversation keys), but
    # this new ClientSession gets its own fresh, isolated key store
    # (see the `connect` fixture), so it has forgotten bob's earlier
    # verification even though bob's identity has not changed.
    alice_reconnected = connect(alice_payload, key_manager=alice_key_manager)
    time.sleep(0.3)

    # ...so Bob's next reconnect recovers it. Bob's new public key is
    # generated up front so alice_reconnected can verify its
    # fingerprint before he ever reconnects -- the redelivery his
    # reconnect triggers is a one-shot event with no retry.
    bob_late_key_manager = KeyManager()
    alice_reconnected.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob_late_key_manager)
    )
    # Phase 13: bob_late is the RECEIVER of the redelivered key, so his
    # own fresh session also needs alice_reconnected's (current)
    # identity already VERIFIED.
    bob_late = connect(
        bob_payload,
        key_manager=bob_late_key_manager,
        pre_verify=_verifying(alice_payload["username"], alice_reconnected.key_manager),
    )
    assert _wait_for_key(bob_late, conversation_id)
    texts = _received_texts(_history(bob_late, alice_payload["username"]))

    assert "recovered later" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts


# ======================================================================
# 10 / 11 -- genuine failures still fail
# ======================================================================


def _raw_connect(port, payload, algorithm="KYBER"):
    """Complete the auth + public-key handshake handle_client()
    requires before it routes chat packets -- the same steps
    tests/test_message_persistence_integration.py's own
    _connect_and_authenticate() performs. The public key is an inert
    placeholder: these particular tests exercise the server's
    accept/reject decision, not key material."""

    sock = wrap_client_socket(
        socket.create_connection(("127.0.0.1", port), timeout=3)
    )

    send_message(sock, create_auth_packet(_token(payload)))

    raw = receive_message(sock)
    auth_result = parse_packet(raw)
    assert auth_result["success"] is True, auth_result

    send_message(
        sock,
        create_public_key_packet(
            username=auth_result["username"],
            algorithm=algorithm,
            public_key="dummy-public-key",
        ),
    )

    return sock


def _recv_until(sock, predicate, attempts=30, per_attempt_timeout=0.3):
    for _ in range(attempts):
        sock.settimeout(per_attempt_timeout)
        try:
            raw = receive_message(sock)
        except (TimeoutError, socket.timeout, OSError):
            continue
        if not raw:
            continue
        candidate = parse_packet(raw)
        if candidate and predicate(candidate):
            return candidate
    return None


def test_unknown_recipient_still_reports_a_genuine_failure(running_server, accounts):
    """Requirement 10: nothing is persisted for a recipient who does
    not exist, so the sender must still be told it failed -- Fix A
    must not turn every send into a success."""

    _state, port = running_server
    sender_payload = accounts("sender_")

    sock = _raw_connect(port, sender_payload)

    try:
        send_message(
            sock,
            create_chat_packet(
                sender=sender_payload["username"],
                receiver="definitely-not-a-registered-user",
                message="opaque-ciphertext",
            ),
        )

        failure = _recv_until(sock, lambda p: p.get("type") == "delivery_failure")

        assert failure is not None
        assert failure["receiver"] == "definitely-not-a-registered-user"
        assert failure["reason"]

        # And it must NOT be reported as queued.
        assert _recv_until(
            sock, lambda p: p.get("type") == "message_queued", attempts=4
        ) is None
    finally:
        sock.close()


def test_persistence_failure_reports_failure_not_queued(
    running_server, accounts, monkeypatch
):
    """Requirement 11: if persistence genuinely fails, the sender is
    told it failed. Nothing may claim QUEUED for a message that was
    never stored."""

    import server.client_handler as client_handler

    _state, port = running_server
    sender_payload = accounts("sender_")
    recipient_payload = accounts("recipient_")

    def _exploding_persist(*args, **kwargs):
        raise RuntimeError("simulated persistence failure")

    monkeypatch.setattr(client_handler, "persist_message", _exploding_persist)

    sock = _raw_connect(port, sender_payload)

    try:
        send_message(
            sock,
            create_chat_packet(
                sender=sender_payload["username"],
                receiver=recipient_payload["username"],
                message="opaque-ciphertext",
            ),
        )

        failure = _recv_until(sock, lambda p: p.get("type") == "delivery_failure")

        assert failure is not None
        assert failure["receiver"] == recipient_payload["username"]

        assert _recv_until(
            sock, lambda p: p.get("type") == "message_queued", attempts=4
        ) is None

        # Nothing may have been stored.
        db = SessionLocal()
        try:
            stored = (
                db.query(Message)
                .filter(Message.sender_id == uuid.UUID(sender_payload["user_id"]))
                .count()
            )
            assert stored == 0
        finally:
            db.close()
    finally:
        sock.close()


# ======================================================================
# 12 -- authorization is unchanged
# ======================================================================


def test_sender_identity_is_taken_from_the_connection_not_the_packet(
    running_server, accounts
):
    """An authenticated user cannot inject an offline message that
    claims to come from somebody else: the persisted sender is always
    the connection's own authenticated identity."""

    _state, port = running_server
    attacker_payload = accounts("attacker_")
    victim_payload = accounts("victim_")
    recipient_payload = accounts("recipient_")

    sock = _raw_connect(port, attacker_payload)

    try:
        send_message(
            sock,
            create_chat_packet(
                sender=victim_payload["username"],  # forged
                receiver=recipient_payload["username"],
                message="opaque-ciphertext",
            ),
        )

        assert _recv_until(sock, lambda p: p.get("type") == "message_queued") is not None

        db = SessionLocal()
        try:
            forged = (
                db.query(Message)
                .filter(Message.sender_id == uuid.UUID(victim_payload["user_id"]))
                .count()
            )
            real = (
                db.query(Message)
                .filter(Message.sender_id == uuid.UUID(attacker_payload["user_id"]))
                .count()
            )
            assert forged == 0
            assert real == 1
        finally:
            db.close()
    finally:
        sock.close()


def test_key_redelivery_is_ignored_for_an_epoch_this_client_does_not_hold(
    connect, accounts
):
    """The redelivery handler must never invent a key. Asked for an
    epoch it does not have, it sends nothing at all -- a fabricated
    key would decrypt no existing ciphertext and would corrupt both
    sides' current-epoch tracking."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    sent = []
    monkey_target = client_session_module.send_message

    def _recording(sock, packet, _original=monkey_target, _sink=sent):
        _sink.append(packet)
        return _original(sock, packet)

    client_session_module.send_message = _recording

    try:
        unheld_epoch = (alice.key_manager.current_epoch(conversation_id) or 1) + 50
        assert not alice.key_manager.has_key(conversation_id, epoch=unheld_epoch)

        alice.handle_direct_key_redelivery_required(
            {
                "type": "direct_key_redelivery_required",
                "conversation_id": str(conversation_id),
                "epoch": unheld_epoch,
                "recipient": bob_payload["username"],
            }
        )

        assert sent == []
        assert not alice.key_manager.has_key(conversation_id, epoch=unheld_epoch)
    finally:
        client_session_module.send_message = monkey_target


# ======================================================================
# DEFECT-1 -- historical decryptability must survive READ + restart
#
# The first version of direct key recovery selected work from
# MessageRecipient rows with status == QUEUED. Both of the first two
# tests below fail against that version: opening a conversation marks
# its rows READ, after which nothing was QUEUED and nothing was
# recovered, and a user's own sent messages never had a row of their
# own at all.
# ======================================================================


def test_history_still_decrypts_after_being_read_and_restarting(connect, accounts):
    """The exact reproduction from the audit: recover, read, restart.

    Reading is not an event that should cost the user their history.
    """

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    _disconnect(bob)
    assert _wait_for(lambda: bob_payload["username"] not in alice.online_users)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("must survive being read")

    # 1st restart: recovery, then read the conversation (what the GUI
    # does on every open -- see ClientSession.mark_conversation_read()).
    # Bob's new public key is generated up front so alice can verify
    # its fingerprint before he ever reconnects -- the redelivery his
    # reconnect triggers is a one-shot event with no retry.
    bob_second_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob_second_key_manager)
    )
    # Phase 13: bob_second is the RECEIVER of the redelivered key, so
    # his own fresh session also needs alice already VERIFIED.
    bob_second = connect(
        bob_payload,
        key_manager=bob_second_key_manager,
        pre_verify=_verifying(alice_payload["username"], alice.key_manager),
    )
    assert _wait_for_key(bob_second, conversation_id)
    assert "must survive being read" in _received_texts(
        _history(bob_second, alice_payload["username"])
    )

    bob_second.mark_conversation_read(conversation_id)
    assert _wait_for(
        lambda: MessageDeliveryStatus.QUEUED
        not in _statuses(conversation_id, bob_payload["user_id"])
    )
    _disconnect(bob_second)

    # 2nd restart: nothing is QUEUED any more. Recovery must still
    # happen, because the messages still exist and Bob may still read
    # them.
    bob_third_key_manager = KeyManager()
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], _identity_fingerprint(bob_third_key_manager)
    )
    # Phase 13: bob_third is the RECEIVER of the redelivered key, so
    # his own fresh session also needs alice already VERIFIED.
    bob_third = connect(
        bob_payload,
        key_manager=bob_third_key_manager,
        pre_verify=_verifying(alice_payload["username"], alice.key_manager),
    )
    assert bob_third.key_manager is not bob_second.key_manager
    assert _wait_for_key(bob_third, conversation_id), (
        "recovery did not run for a conversation with no QUEUED rows"
    )

    texts = _received_texts(_history(bob_third, alice_payload["username"]))

    assert "must survive being read" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts


def test_sender_can_still_read_their_own_history_after_restarting(
    connect, accounts
):
    """A user's own sent messages have no MessageRecipient row of
    their own, so recovery must not depend on one."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice_first = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice_first, bob, alice_payload["username"], bob_payload["username"]
    )

    _open_direct(alice_first, bob_payload["username"])
    alice_first.send_chat_message("alice own words")
    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "alice own words"
            for summary in bob.conversation_store.get_all()
        )
    )

    # Alice restarts. Bob -- who holds the epoch -- stays connected.
    # Alice's new public key is generated up front so bob can verify
    # its fingerprint before she ever reconnects -- the redelivery her
    # reconnect triggers is a one-shot event with no retry.
    _disconnect(alice_first)
    alice_restarted_key_manager = KeyManager()
    # Message-Level ML-DSA Origin Authentication: this test is
    # specifically about KEM-key recovery on restart (a genuinely new
    # Kyber keypair, per the comment above) -- Alice's SIGNING identity
    # is kept continuous across the "restart" by reusing her exported
    # private seed, exactly like a real client's persisted signing
    # keypair (load_or_create_signing_keypair()) would. Without this,
    # alice_restarted would sign with a completely different ML-DSA
    # key than the one "alice own words" was originally signed with,
    # and her own historical message would (correctly, but not what
    # this test is isolating) fail signature verification when loaded
    # back -- see _verify_history_message_signature()'s "own message"
    # handling.
    alice_restarted_key_manager.ml_dsa.import_private_key(
        alice_first.key_manager.ml_dsa.export_private_key()
    )
    bob.key_store.verify_peer_fingerprint(
        alice_payload["username"],
        _identity_fingerprint(alice_restarted_key_manager),
    )
    # Phase 13: alice_restarted is the RECEIVER of the redelivered key
    # here (bob is the one who stayed connected and holds it), so her
    # own fresh session also needs bob already VERIFIED.
    alice_restarted = connect(
        alice_payload,
        key_manager=alice_restarted_key_manager,
        pre_verify=_verifying(bob_payload["username"], bob.key_manager),
    )
    assert alice_restarted.key_manager is not alice_first.key_manager
    assert _wait_for_key(alice_restarted, conversation_id), (
        "the sender recovered no key for their own conversation"
    )

    history = _history(alice_restarted, bob_payload["username"])
    own = [row["text"] for row in history if row["is_own"]]

    assert "alice own words" in own
    assert _UNDECRYPTABLE_PLACEHOLDER not in [row["text"] for row in history]


def test_recovery_requests_only_the_epochs_the_client_is_missing(
    connect, accounts
):
    """Requirement: existing locally available epochs are skipped.

    A client whose KeyManager survived asks for nothing at all, so a
    routine reconnect does not make the partner re-wrap keys it
    already holds.
    """

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    surviving = bob.key_manager
    _disconnect(bob)

    requests = []
    original = client_session_module.send_message

    def _recording(sock, packet, _original=original, _sink=requests):
        if packet.get("type") == "direct_key_recovery_request":
            _sink.append(packet)
        return _original(sock, packet)

    client_session_module.send_message = _recording

    try:
        # Reconnect still holding every epoch -> nothing to ask for.
        bob_blip = connect(bob_payload, key_manager=surviving)
        time.sleep(1.0)
        assert requests == [], "asked for keys it already had: %s" % requests
        assert bob_blip.key_manager.has_key(conversation_id)
        _disconnect(bob_blip)

        # A genuinely fresh client asks for exactly what it lacks.
        requests.clear()
        connect(bob_payload)
        assert _wait_for(lambda: len(requests) == 1)

        assert requests[0]["conversation_id"] == str(conversation_id)
        assert requests[0]["epochs"]
        assert all(isinstance(e, int) for e in requests[0]["epochs"])
    finally:
        client_session_module.send_message = original


def test_a_conversation_with_no_messages_triggers_no_recovery(connect, accounts):
    """Requirement: an empty conversation must not cause recovery."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    connect(bob_payload)

    # Resolve the direct conversation without ever sending a message,
    # so the conversation row exists but has no messages.
    _open_direct(alice, bob_payload["username"])
    assert alice.current_conversation_id is not None

    db = SessionLocal()
    try:
        required = MessageRepository(db).get_direct_conversation_epochs_for_user(
            uuid.UUID(bob_payload["user_id"])
        )
    finally:
        db.close()

    assert required == {}


def test_recovery_never_overwrites_an_epoch_the_client_already_holds(
    connect, accounts
):
    """Requirement: existing epochs are not overwritten. A redelivery
    of an epoch the client already has must leave the original key
    byte-identical, so messages encrypted under it keep decrypting."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    epoch = bob.key_manager.current_epoch(conversation_id)
    original_key = bob.key_manager.get_key(conversation_id, epoch=epoch)
    assert original_key is not None

    # Ask Alice to redeliver an epoch Bob already holds.
    alice.handle_direct_key_redelivery_required(
        {
            "type": "direct_key_redelivery_required",
            "conversation_id": str(conversation_id),
            "epoch": epoch,
            "recipient": bob_payload["username"],
        }
    )
    time.sleep(0.8)

    assert bob.key_manager.get_key(conversation_id, epoch=epoch) == original_key


def test_recovery_request_for_a_foreign_conversation_is_refused(
    connect, accounts
):
    """A client must not be able to recover keys for a conversation it
    is not a member of, even by naming a real conversation id."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    outsider_payload = accounts("outsider_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    outsider = connect(outsider_payload)

    dispatched = []
    original = alice.handle_direct_key_redelivery_required

    def _recording(packet, _original=original, _sink=dispatched):
        _sink.append(packet)
        return _original(packet)

    alice.handle_direct_key_redelivery_required = _recording

    epoch = alice.key_manager.current_epoch(conversation_id)

    send_message(
        outsider.client_socket,
        {
            "type": "direct_key_recovery_request",
            "conversation_id": str(conversation_id),
            "epochs": [epoch],
        },
    )
    time.sleep(1.0)

    assert dispatched == [], "an outsider caused a key redelivery"
    assert not outsider.key_manager.has_key(conversation_id, epoch=epoch)


def test_recovery_request_for_an_unreferenced_epoch_is_refused(connect, accounts):
    """A member must not be able to fish for epochs no message was
    ever encrypted under."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    conversation_id = _establish_direct_key(
        alice, bob, alice_payload["username"], bob_payload["username"]
    )

    dispatched = []
    original = alice.handle_direct_key_redelivery_required

    def _recording(packet, _original=original, _sink=dispatched):
        _sink.append(packet)
        return _original(packet)

    alice.handle_direct_key_redelivery_required = _recording

    unreferenced = (alice.key_manager.current_epoch(conversation_id) or 1) + 99

    send_message(
        bob.client_socket,
        {
            "type": "direct_key_recovery_request",
            "conversation_id": str(conversation_id),
            "epochs": [unreferenced],
        },
    )
    time.sleep(1.0)

    assert dispatched == []
