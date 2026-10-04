"""
Public-key availability bug (the "No public key found for X" error).

Root cause (read-only investigation, confirmed): Find User can locate
any registered account, online or offline -- that part was always
correct, and the username identifier used throughout (search result ->
ConversationSummary -> ClientSession.current_chat -> KeyManager lookup)
is the same string at every hop, never confused with display_name or
phone number. What was actually missing: public keys are only ever
exchanged between clients connected at the same time (see
server/broadcaster.py::distribute_public_keys(), scoped to
state.clients), and gui/chat_window.py::open_conversation() enabled
the composer unconditionally regardless of whether this client had
actually received the recipient's key yet. The first send attempt
against an offline-since-this-session recipient then failed inside
ClientSession.establish_session_key() with a blocking QMessageBox.

The fix was originally: gate the composer on KeyManager.get_public_key()
so a doomed send could never be attempted. BUG -- Offline First Contact
(client/session.py::establish_session_key()) removed the reason that
gate existed at all -- the AES session key is now always generated
locally (os.urandom(32)), independent of the recipient's public key,
so a brand-new direct conversation with a currently offline recipient
is now genuinely sendable, not just "safely disabled". Delivery of
that key to the recipient is deferred to the existing recovery
mechanism (see client/session.py::establish_session_key()'s
docstring) rather than blocking the composer.

  - ChatWindow._update_composer_availability(): now enables a direct
    conversation's composer unconditionally (like a group's always
    was) -- see its docstring for the case-by-case analysis of why no
    direct-conversation state is left that should block it.
  - ClientSession.public_key_received (Signal(str)): unchanged,
    still emitted from handle_public_key() right after a key is
    validated and stored.
  - ChatWindow.handle_public_key_received(): unchanged wiring, kept
    as a hook point even though it no longer changes enabled state.
  - ChatWindow.send_message(): the old public-key-based defense-in-
    depth pre-check was removed (it was based on the now-obsolete
    signal); the generic try/except around send_chat_message() -- and
    the deeper ValueError _send_encrypted_payload() would raise if
    establish_session_key() ever left no key stored -- remain the
    defense-in-depth for a genuine failure.

These tests drive a REAL ChatWindow against a real running server and
real, separately-connecting ClientSessions -- the same pattern
tests/test_chat_window_read_receipt_on_receive.py already established
-- so what's proven is the actual production wiring, not a
re-implementation of it.

Standalone-commit scope: _update_composer_availability() only ever
toggles InputBar.set_enabled() here -- no visible status text yet,
since that requires a QLabel (composer_status_label) whose
construction/layout placement belongs to a separate, not-yet-committed
initial-chat-state change.

Run with:
    pytest tests/test_composer_public_key_availability.py -v
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_combined_identity, fingerprint_public_key
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from gui.chat_window import ChatWindow
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

_KEEP_ALIVE = []


# ----------------------------------------------------------------------
# Helpers -- same conventions as
# tests/test_chat_window_read_receipt_on_receive.py
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Public Key Availability Test",
            "username": f"pkey_{hint}{suffix}",
            "email": f"pkey_{hint}{suffix}@example.com",
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
    """Pumps the Qt event loop while waiting, so a cross-thread queued
    signal (receiver thread -> GUI thread) is actually delivered --
    exactly as a running GUI would."""

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


def _direct_summary(username):
    """Exactly the shape gui/chat_window.py::handle_find_user() builds
    from a Find User search result -- conversation_id=None, resolved
    lazily by set_current_chat()."""

    return ConversationSummary(
        conversation_id=None,
        username=username,
        is_online=True,
        latest_message=None,
    )


def _composer_enabled(window):
    return window.input_bar.message_input.isEnabled()


# ----------------------------------------------------------------------
# A -- existing/available public key: unaffected by this fix
# ----------------------------------------------------------------------


def test_available_public_key_enables_the_composer_and_sending_works(
    connect, accounts, tmp_path
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)  # both online -> keys exchange automatically

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    # The `connect` fixture logs in with a bare token (unlike gui/
    # main_window.py's real authenticate_credentials() flow) and so
    # never unlocks a local key store -- required, since
    # Server-Untrusted Identity Verification, Stage 3 checks
    # alice.key_store regardless whenever the recipient's public key is
    # already cached, which it is here (both are online). Without this,
    # alice_window.send_message() below raises PeerNotVerifiedError,
    # which ChatWindow.send_message() turns into a MODAL QMessageBox
    # that would hang this test forever under QT_QPA_PLATFORM=offscreen.
    alice.key_store = SecureKeyStore(
        alice_payload["user_id"], storage_dir=tmp_path / "keystore"
    )
    alice.key_store.unlock(alice_payload["password"])
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"],
        fingerprint_combined_identity(
            bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key()
        ),
    )
    # Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication):
    # bob is also the RECEIVER of the live group_key_distribution
    # packet alice_window.send_message() below triggers, which now
    # separately requires bob to have alice already VERIFIED too --
    # otherwise the packet is silently rejected on bob's receiver
    # thread (no modal dialog there; the message is simply never
    # delivered) and the assertion below fails.
    bob.key_store = SecureKeyStore(
        bob_payload["user_id"], storage_dir=tmp_path / "keystore-bob"
    )
    bob.key_store.unlock(bob_payload["password"])
    bob.key_store.verify_peer_fingerprint(
        alice_payload["username"],
        fingerprint_combined_identity(
            alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
        ),
    )

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))

    assert alice_window.input_bar.message_input.isEnabled() is True
    assert alice_window.input_bar.send_button.isEnabled() is False  # empty text

    alice_window.send_message("this should just work")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "this should just work"
            for summary in bob.conversation_store.get_all()
        )
    ), "message with an available key was never delivered"


# ----------------------------------------------------------------------
# B -- missing public key: BUG -- Offline First Contact -- composer
# stays usable, sending succeeds via a locally-generated key
# ----------------------------------------------------------------------


def test_missing_public_key_keeps_composer_enabled_for_a_new_conversation(
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")  # registered, never connects -> offline

    alice = connect(alice_payload)

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    # Exactly what handle_find_user() does after a successful search.
    alice_window.open_conversation(_direct_summary(bob_payload["username"]))

    assert alice_window.chat_partner_label.text() == bob_payload["username"]

    # BUG -- Offline First Contact: establish_session_key() can now
    # always generate a key locally, regardless of public-key
    # availability, so there is no reason left to disable the
    # composer for a brand-new conversation with an offline recipient.
    assert alice_window.input_bar.message_input.isEnabled() is True


def test_missing_public_key_real_interaction_sends_via_a_locally_generated_key(
    connect, accounts
):
    """A real user interaction -- typing and pressing Enter -- must
    actually send: no error dialog, a real send attempt reaching
    ClientSession.send_chat_message(), and a session key generated
    locally with no public key involved."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))

    assert alice.key_manager.get_public_key(bob_payload["username"]) is None

    dialogs_shown = []
    alice_window.show_error = lambda message: dialogs_shown.append(message)

    send_attempts = []
    original_send_chat_message = alice.send_chat_message

    def _tracked_send_chat_message(message, **kwargs):
        # Phase 19.24 -- send_chat_message() now also accepts
        # reply_to_message_id/client_message_id (Message Lifecycle
        # Events); gui/chat_window.py::send_message() always passes
        # both on an ordinary send now (client_message_id for retry
        # idempotency). This tracking wrapper only cares about the
        # message text itself, so it forwards whatever it was given
        # rather than assuming the old 1-arg shape.
        send_attempts.append(message)
        return original_send_chat_message(message, **kwargs)

    alice.send_chat_message = _tracked_send_chat_message

    messages_before = alice_window.messages.count()

    QTest.keyClicks(alice_window.input_bar.message_input, "hello bob")
    QTest.keyClick(alice_window.input_bar.message_input, Qt.Key_Return)

    assert dialogs_shown == [], f"a blocking error dialog was shown: {dialogs_shown}"
    assert send_attempts == ["hello bob"], (
        "typing and pressing Enter with no public key available did not "
        "reach send_chat_message()"
    )
    assert alice_window.messages.count() > messages_before, (
        "no message bubble was added for the real interaction"
    )

    conversation_id = alice.current_conversation_id
    assert alice.key_manager.has_key(conversation_id), (
        "no session key was generated locally for the new conversation"
    )
    # Still no public key -- the key came from os.urandom(32), not
    # from any Kyber/RSA operation that would have required one.
    assert alice.key_manager.get_public_key(bob_payload["username"]) is None


# ----------------------------------------------------------------------
# C -- composer stays usable whether the key arrives before or after
# the first send, and the first-contact message still reaches the
# recipient once they connect (BUG -- Offline First Contact)
# ----------------------------------------------------------------------


def test_composer_stays_enabled_and_message_still_arrives_once_recipient_connects(
    connect, accounts, tmp_path
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)  # bob not connected yet

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice_window.input_bar.message_input.isEnabled() is True

    # Sent while bob is genuinely offline: locally encrypted/persisted,
    # delivery of the wrapping key deferred to recovery.
    alice_window.send_message("now it works")

    assert _composer_enabled(alice_window) is True

    conversation_id = alice.current_conversation_id

    # Bob's own Kyber identity keypair exists the instant his
    # ClientSession is constructed (KeyManager.__init__() sets
    # public_key eagerly) -- independent of any network activity -- so
    # alice can explicitly verify his fingerprint BEFORE he ever
    # connects. This matters here specifically: the moment bob comes
    # online, the server-triggered direct-key-redelivery flow (Server-
    # Untrusted Identity Verification, Stage 3 gates it exactly like
    # establish_session_key() -- see handle_direct_key_redelivery_
    # required()) fires immediately and only once, with no retry.
    # Verifying only after connect(bob_payload) returns would race that
    # one-shot delivery instead of reliably preceding it, so bob's
    # session is built here (mirroring the `connect` fixture's own
    # steps) rather than via that fixture, with verification inserted
    # in between construction and going online.
    bob = ClientSession()
    bob.user_id = bob_payload["user_id"]
    bob.access_token = _token(bob_payload)

    alice.key_store = SecureKeyStore(
        alice_payload["user_id"], storage_dir=tmp_path / "keystore"
    )
    alice.key_store.unlock(alice_payload["password"])
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"],
        fingerprint_combined_identity(
            bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key()
        ),
    )
    # Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication):
    # bob is also the RECEIVER of the redelivered group_key_
    # distribution packet his own reconnect below triggers, which now
    # separately requires bob to have alice already VERIFIED too --
    # set up here, before he ever connects, for the same one-shot-no-
    # retry race-avoidance reason as alice's own verify above.
    bob.key_store = SecureKeyStore(
        bob_payload["user_id"], storage_dir=tmp_path / "keystore-bob"
    )
    bob.key_store.unlock(bob_payload["password"])
    bob.key_store.verify_peer_fingerprint(
        alice_payload["username"],
        fingerprint_combined_identity(
            alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
        ),
    )

    bob.connect()  # triggers recovery, not live key exchange
    bob.login(bob_payload["username"])
    bob.send_public_key()
    bob.start_receiver()

    try:
        assert _wait_for(
            lambda: bob.key_manager.has_key(conversation_id)
        ), "bob never recovered the key for the first-contact conversation"

        bob.set_current_chat(_direct_summary(alice_payload["username"]))
        history = bob.load_conversation_history(
            alice_payload["username"], is_group=False
        )
        texts = [row["text"] for row in history if not row["is_own"]]

        assert "now it works" in texts, (
            f"first-contact message never decrypted for bob: {texts}"
        )
    finally:
        bob.disconnect()


# ----------------------------------------------------------------------
# D -- a different user's key must never be used for this conversation
# ----------------------------------------------------------------------


def test_a_different_users_key_is_never_used_for_this_conversation(
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")

    alice = connect(alice_payload)  # neither bob nor carol connected yet

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice_window.input_bar.message_input.isEnabled() is True

    connect(carol_payload)  # carol comes online -> alice receives CAROL's key

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(carol_payload["username"]) is not None
    ), "test setup failed: alice never received carol's key at all"

    alice_window.send_message("only for bob")

    conversation_id = alice.current_conversation_id
    assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

    bob_session_key = alice.key_manager.get_key(conversation_id)

    assert bob_session_key is not None
    # The conversation's key came from local generation, never from
    # wrapping/using carol's public key for anything.
    assert alice.key_manager.get_public_key(bob_payload["username"]) is None


# ----------------------------------------------------------------------
# E -- security: sending with no public key uses only a locally
# generated key, and no key material is ever transmitted for it
# ----------------------------------------------------------------------


def test_no_key_material_is_transmitted_when_recipient_key_is_unavailable(
    connect, accounts, monkeypatch
):
    """Sending now succeeds with no public key available -- but it must
    still never fabricate/substitute a key, and no packet carrying key
    material (session_key or group_key_distribution) may be put on the
    wire, since there is nothing valid to wrap it for yet."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", recording_send_message)

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice.key_manager.get_public_key(bob_payload["username"]) is None

    dialogs_shown = []
    alice_window.show_error = lambda message: dialogs_shown.append(message)

    alice_window.send_message("this must never leave the machine wrapped for anyone")

    assert dialogs_shown == []
    assert alice.key_manager.get_public_key(bob_payload["username"]) is None, (
        "no public key may be fabricated or substituted as a side effect"
    )

    key_carrying_packets = [
        p for p in sent_packets
        if p.get("operation") == "session_key" or p.get("type") == "group_key_distribution"
    ]
    assert key_carrying_packets == [], (
        f"key material was transmitted with no recipient key available: "
        f"{key_carrying_packets}"
    )
