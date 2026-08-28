"""
BUG 2 -- read receipts must reach a CONNECTED sender in real time.

The reported symptom was that Alice saw no double tick when Bob read
her message, and that it only appeared after she logged out and back
in. The audit established that the server persisted READ correctly,
sent the notification correctly, and that Alice's ClientSession
received it and emitted read_receipt_updated -- every hop worked. What
failed was the last one: the bubble for a message sent live this
session carried no database id, and the GUI registry that
mark_all_sent_read() flips only held bubbles that had one. There was
nothing on screen to change, until history re-rendered the message
with its real id after a reconnect.

These tests drive the whole chain with real sessions over the real TLS
harness, and the GUI-facing part with a real MessageWidget rendered
offscreen -- the same pattern tests/test_read_receipts_gui.py uses.
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_public_key
from database.connection import SessionLocal
from database.models.message import Message
from database.models.message_recipient import MessageRecipient
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.message_delivery_status import MessageDeliveryStatus
from gui.message_widget import MessageWidget
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Read Receipt Test",
            "username": f"rr_{hint}{suffix}",
            "email": f"rr_{hint}{suffix}@example.com",
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
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _wait_for(predicate, attempts=150, interval=0.05):
    """Waits while pumping the Qt event loop, so cross-thread queued
    signals are actually delivered -- exactly as a running GUI would."""

    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
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
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    key_store_dir = tmp_path / "keystores"

    opened = []

    def _connect(payload):
        session = ClientSession()
        session.user_id = payload["user_id"]
        session.access_token = _token(payload)
        session.connect()
        session.login(payload["username"])
        # Server-Untrusted Identity Verification, Stage 3: this
        # lighter connect()-only pattern skips authenticate_credentials(),
        # the only place a key store is normally unlocked -- unlock a
        # real, isolated, on-disk one here too, so _send_and_receive()
        # below can verify whichever peer establish_session_key()
        # needs. Done before send_public_key(), like
        # authenticate_credentials()'s own _unlock_key_store(), so a
        # reconnecting session (Stage 2.5) broadcasts the same
        # persisted identity key rather than a fresh ephemeral one.
        session.key_store = SecureKeyStore(
            payload["user_id"], storage_dir=key_store_dir / payload["username"]
        )
        session.key_store.unlock(payload["password"])
        session.key_manager.load_or_create_kyber_keypair(session.key_store)
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


def _statuses(conversation_id):
    db = SessionLocal()
    try:
        rows = (
            db.query(MessageRecipient)
            .join(Message, MessageRecipient.message_id == Message.id)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .all()
        )
        return sorted(row.status for row in rows)
    finally:
        db.close()


def _send_and_receive(alice, bob, alice_name, bob_name, text):
    """Alice sends while both are online; returns the conversation_id
    once Bob has actually received it."""

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_name) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_name) is not None)

    # Server-Untrusted Identity Verification, Stage 3:
    # establish_session_key() (called inside send_chat_message()
    # below) now requires Alice to have explicitly verified Bob before
    # wrapping a session key for him. Only Alice ever sends in this
    # file's tests, so only this one direction is needed.
    alice.key_store.verify_peer_fingerprint(
        bob_name, fingerprint_public_key(bob.key_manager.public_key)
    )

    _open_direct(alice, bob_name)
    alice.send_chat_message(text)

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == text
            for summary in bob.conversation_store.get_all()
        )
    ), "recipient never received the message"

    return alice.current_conversation_id


# ======================================================================
# The reported scenario, end to end
# ======================================================================


def test_sender_is_notified_immediately_without_reconnecting(connect, accounts):
    """Steps 1-4 of the report: Alice sends, Bob receives, Bob reads,
    and Alice -- still connected, never reconnecting -- is told."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    conversation_id = _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"],
        "please read this",
    )

    emissions = []
    alice.read_receipt_updated.connect(
        lambda cid, reader: emissions.append((cid, reader))
    )

    # Delivered, not yet read. Waited for rather than asserted
    # instantly: the recipient row is written server-side after the
    # relay, so it can lag the message's arrival in Bob's store by a
    # moment. The assertion itself is unchanged.
    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.DELIVERED]
    )

    # Bob opens the conversation and reads it.
    _open_direct(bob, alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)

    assert _wait_for(lambda: len(emissions) == 1), "sender was never notified"

    assert emissions[0] == (str(conversation_id), bob_payload["username"])

    # Alice is still on her original connection -- no reconnect anywhere.
    assert alice.is_connected()


def test_read_state_is_persisted_when_the_receipt_is_processed(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    conversation_id = _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"],
        "persist my read state",
    )

    _open_direct(bob, alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)

    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.READ]
    )


def test_live_sent_bubble_flips_to_read_on_the_notification(connect, accounts):
    """The GUI-facing half, and the actual defect.

    The bubble is added exactly as gui/chat_window.py::send_message()
    adds it for a live send -- add_sent_message(text) with no
    message_id -- and must still flip when the real receipt arrives.
    """

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    messages = MessageWidget()

    conversation_id = _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"],
        "watch this tick",
    )
    messages.add_sent_message("watch this tick")

    bubble = next(iter(messages._sent_bubbles_by_message_id.values()))
    assert "✓✓" not in bubble.time_label.text()

    # Wire the real ClientSession signal to the real MessageWidget the
    # way ChatWindow does, filtered on the open conversation.
    def _on_receipt(cid, _reader):
        if cid == str(conversation_id):
            messages.mark_all_sent_read()

    alice.read_receipt_updated.connect(_on_receipt)

    _open_direct(bob, alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)

    assert _wait_for(lambda: "✓✓" in bubble.time_label.text()), (
        "the live-sent bubble never flipped to read"
    )


def test_repeated_mark_read_is_idempotent(connect, accounts):
    """Requirement 9. A second open must not re-notify: nothing is
    newly read, so the server sends nothing."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    conversation_id = _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"],
        "read me once",
    )

    emissions = []
    alice.read_receipt_updated.connect(
        lambda cid, reader: emissions.append((cid, reader))
    )

    _open_direct(bob, alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)
    assert _wait_for(lambda: len(emissions) == 1)

    for _ in range(3):
        bob.mark_conversation_read(bob.current_conversation_id)

    # Give any spurious extra notification time to arrive.
    _wait_for(lambda: len(emissions) > 1, attempts=20)

    assert len(emissions) == 1, f"re-reading re-notified: {emissions}"
    assert _statuses(conversation_id) == [MessageDeliveryStatus.READ]


def test_sender_offline_during_read_sees_it_after_reconnect(connect, accounts):
    """Requirement 8: the live event is an optimisation, never the
    source of truth. A sender who was away still sees READ from
    history."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    conversation_id = _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"],
        "read while I am away",
    )

    alice.disconnect()
    time.sleep(0.3)

    _open_direct(bob, alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)
    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.READ]
    )

    alice_again = connect(alice_payload)
    _open_direct(alice_again, bob_payload["username"])
    history = alice_again.load_conversation_history(
        bob_payload["username"], is_group=False
    )

    own = [row for row in history if row["is_own"]]
    assert own
    assert all(row["read_status"] is True for row in own)


def test_delivery_state_still_precedes_read(connect, accounts):
    """Requirement 11 / the QUEUED -> DELIVERED -> READ progression.
    A message is never READ merely because it was delivered."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    conversation_id = _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"],
        "delivered first",
    )

    # Delivered on arrival, and it stays that way until Bob actually
    # opens the conversation. The first check waits for the row to be
    # written (it lands just after the relay); the second proves the
    # status does not drift to READ on its own.
    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.DELIVERED]
    )
    time.sleep(0.5)
    assert _statuses(conversation_id) == [MessageDeliveryStatus.DELIVERED]

    _open_direct(bob, alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)

    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.READ]
    )


def test_a_third_party_cannot_mark_someone_elses_conversation_read(
    connect, accounts
):
    """Requirement 10. The reader is taken from the authenticated
    connection, and non-members are refused outright."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    outsider_payload = accounts("outsider_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    outsider = connect(outsider_payload)

    conversation_id = _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"],
        "not for the outsider",
    )

    emissions = []
    alice.read_receipt_updated.connect(
        lambda cid, reader: emissions.append((cid, reader))
    )

    outsider.mark_conversation_read(str(conversation_id))
    time.sleep(1.0)

    assert emissions == [], "an outsider produced a read receipt"
    assert _statuses(conversation_id) == [MessageDeliveryStatus.DELIVERED], (
        "the outsider's request changed the delivery state"
    )
