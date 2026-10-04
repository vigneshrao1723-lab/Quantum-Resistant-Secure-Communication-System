"""
Read receipt real-time update bug (GUI level).

tests/test_read_receipts_realtime.py already proves the underlying
mechanism -- ClientSession.mark_conversation_read() -> server ->
read_receipt_notification -> ClientSession.read_receipt_updated --
works correctly. What was actually broken sits one layer up, in
gui/chat_window.py: mark_conversation_read() was only ever called from
open_conversation() (clicking a conversation in the sidebar), never
from receive_message()/receive_payload_message() -- so a message that
arrived while the conversation was ALREADY open sat there displayed
but never reported as read, until the user closed and reopened it.

These tests drive a REAL ChatWindow (not a mock) against a real
running server and two real, connected ClientSessions, so the actual
production wiring -- ClientSession.message_received signal ->
ChatWindow.receive_message() -> ChatWindow._mark_current_conversation_
read() -> a real read_receipt packet -> the server -> a real
read_receipt_notification back to the sender -- is what gets proven,
not a re-implementation of it.

Run with:
    pytest tests/test_chat_window_read_receipt_on_receive.py -v
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
from gui.chat_window import ChatWindow
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

_KEEP_ALIVE = []


# ----------------------------------------------------------------------
# Helpers -- identical conventions to tests/test_read_receipts_realtime.py
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Read Receipt GUI Test",
            "username": f"rrgui_{hint}{suffix}",
            "email": f"rrgui_{hint}{suffix}@example.com",
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


def _wait_for(predicate, attempts=150, interval=0.05):
    """Pumps the Qt event loop while waiting, so cross-thread queued
    signals (a real receiver thread -> the GUI thread) are actually
    delivered -- exactly as a running GUI would."""

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
def connect(running_server, monkeypatch):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    opened = []

    def _connect(payload):
        session = ClientSession()
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


def _direct_summary(username):
    return ConversationSummary(
        conversation_id=None,
        username=username,
        is_online=True,
        latest_message=None,
    )


def _wait_for_public_keys(alice, bob, alice_name, bob_name):
    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_name) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_name) is not None)


def _verify_peer(sender_session, sender_payload, peer_session, peer_username, tmp_path):
    """The `connect` fixture logs in with a bare token (unlike gui/
    main_window.py's real authenticate_credentials() flow) and so never
    unlocks a local key store -- required, since Server-Untrusted
    Identity Verification, Stage 3 checks sender_session.key_store
    regardless. Give the sender an isolated, unlocked store of its own
    so the peer can be explicitly verified, exactly as these tests'
    original intent (read-receipt delivery) always assumed."""

    sender_session.key_store = SecureKeyStore(
        sender_payload["user_id"], storage_dir=tmp_path / f"keystore-{sender_payload['user_id']}"
    )
    sender_session.key_store.unlock(sender_payload["password"])
    sender_session.key_store.verify_peer_fingerprint(
        peer_username, fingerprint_public_key(peer_session.key_manager.public_key)
    )


# ----------------------------------------------------------------------
# The reported bug, end to end
# ----------------------------------------------------------------------


def test_message_received_into_the_open_conversation_is_marked_read_immediately(
    connect, accounts, tmp_path
):
    """Steps 1-6 of the required behavior: Bob has the conversation
    open BEFORE Alice sends, the message arrives and displays, and --
    with nobody ever calling mark_conversation_read() explicitly, and
    without Bob reopening or refreshing anything -- it is read, and
    Alice (still connected, never reconnecting) is told."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _wait_for_public_keys(alice, bob, alice_payload["username"], bob_payload["username"])
    _verify_peer(alice, alice_payload, bob, bob_payload["username"], tmp_path)
    # Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication):
    # bob is also the RECEIVER of the live group_key_distribution
    # packet alice's send_chat_message() below triggers, which now
    # separately requires bob to have alice already VERIFIED too --
    # otherwise the packet is silently rejected, bob never installs a
    # session key, and the subsequent chat message never decrypts.
    _verify_peer(bob, bob_payload, alice, alice_payload["username"], tmp_path)

    bob_window = ChatWindow(bob)
    _KEEP_ALIVE.append(bob_window)

    # Bob opens the conversation FIRST -- it is already active/visible
    # by the time Alice's message arrives, matching the reported
    # scenario exactly.
    bob_window.open_conversation(_direct_summary(alice_payload["username"]))

    alice_emissions = []
    alice.read_receipt_updated.connect(
        lambda cid, reader: alice_emissions.append((cid, reader))
    )

    # bob's current chat is already Alice's, from open_conversation()
    # above -- only alice's side still needs setting, to send.
    alice.set_current_chat(_direct_summary(bob_payload["username"]))
    alice.send_chat_message("already open when this arrives")

    conversation_id = alice.current_conversation_id

    # The message actually reached and displayed in Bob's real,
    # on-screen message list -- not just ConversationStore.
    assert _wait_for(lambda: bob_window.messages.count() > 0), (
        "the message never reached the open ChatWindow"
    )

    # The actual requirement: READ, automatically, with nobody in this
    # test ever calling mark_conversation_read() themselves.
    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.READ]
    ), "the message was not automatically marked read"

    # And the sender -- still connected, no reconnect -- was told live.
    assert _wait_for(lambda: len(alice_emissions) == 1), (
        "the sender was never notified of the automatic read"
    )
    assert alice_emissions[0] == (str(conversation_id), bob_payload["username"])
    assert alice.is_connected()


def test_message_received_into_a_different_open_conversation_stays_unread(
    connect, accounts, tmp_path
):
    """Requirement: preserve existing unread behavior when the
    conversation is NOT the one currently open. Bob has a chat open
    with Carol when Alice's message arrives -- it must not be
    auto-read, and opening Alice's conversation afterward is what
    marks it read (existing behavior, requirement 9)."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    carol = connect(carol_payload)

    _wait_for_public_keys(alice, bob, alice_payload["username"], bob_payload["username"])
    _wait_for_public_keys(carol, bob, carol_payload["username"], bob_payload["username"])
    _verify_peer(alice, alice_payload, bob, bob_payload["username"], tmp_path)
    # Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication):
    # bob is also the RECEIVER of the live group_key_distribution
    # packet alice's send_chat_message() below triggers, which now
    # separately requires bob to have alice already VERIFIED too --
    # otherwise the packet is silently rejected, bob never installs a
    # session key, and the subsequent chat message never decrypts.
    _verify_peer(bob, bob_payload, alice, alice_payload["username"], tmp_path)

    bob_window = ChatWindow(bob)
    _KEEP_ALIVE.append(bob_window)

    # Bob is looking at Carol's conversation, not Alice's -- his
    # session's current chat must stay Carol's the whole time Alice's
    # message arrives, which is the entire point of this test, so
    # nothing here may call bob.set_current_chat() for Alice.
    bob_window.open_conversation(_direct_summary(carol_payload["username"]))

    alice.set_current_chat(_direct_summary(bob_payload["username"]))
    alice.send_chat_message("bob is not looking at this one")

    conversation_id = alice.current_conversation_id

    # Delivered on arrival -- waited for rather than asserted
    # instantly, matching test_read_receipts_realtime.py's identical
    # pattern (the recipient row lands just after the relay).
    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.DELIVERED]
    )

    # And it does NOT drift to read on its own while Bob keeps looking
    # at Carol's conversation -- not because Bob is merely online.
    time.sleep(0.5)
    assert _statuses(conversation_id) == [MessageDeliveryStatus.DELIVERED]

    # Existing behavior, requirement 9: opening it now marks it read.
    bob_window.open_conversation(_direct_summary(alice_payload["username"]))

    assert _wait_for(
        lambda: _statuses(conversation_id) == [MessageDeliveryStatus.READ]
    )
