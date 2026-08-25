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

The fix is entirely in gui/chat_window.py + one new ClientSession
signal -- no protocol, crypto, schema, or identifier changes:

  - ChatWindow._update_composer_availability(): the single place that
    decides whether the composer is usable for the currently-open
    direct conversation, based on KeyManager.get_public_key() alone
    (never a stale cache, never a substitute key -- see
    crypto/key_manager.py, untouched).
  - ClientSession.public_key_received (new Signal(str)): emitted from
    handle_public_key() right after a key is validated and stored --
    the same validated, unchanged storage path as before.
  - ChatWindow.handle_public_key_received(): re-checks availability
    only when the arriving key belongs to whoever is currently open.
  - ChatWindow.send_message(): a defense-in-depth guard mirroring the
    composer's own enabled state, so a doomed send can never actually
    reach the network even if triggered some other way.

These tests drive a REAL ChatWindow against a real running server and
real, separately-connecting ClientSessions -- the same pattern
tests/test_chat_window_read_receipt_on_receive.py already established
-- so what's proven is the actual production wiring, not a
re-implementation of it.

Standalone-commit scope: _update_composer_availability() only ever
toggles InputBar.set_enabled() here -- no visible "Waiting for
recipient..." status text yet, since that requires a QLabel
(composer_status_label) whose construction/layout placement belongs to
a separate, not-yet-committed initial-chat-state change. These tests
therefore assert on input_bar's own enabled state directly rather than
on any status label, which keeps this file committable independently
of that other work. A later, small follow-up change wires
composer_status_label back into this method once the initial-chat-state
work has landed; the safety/functional guarantees these tests cover
(no dialog, no transmission, correct enable/disable) do not depend on
that label existing at all.

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
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from gui.chat_window import ChatWindow
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
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)  # both online -> keys exchange automatically

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
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
# B -- missing public key: safe state, no error dialog
# ----------------------------------------------------------------------


def test_missing_public_key_disables_composer_safely(
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

    # The conversation itself is real -- opening it still names the
    # partner in the header -- only sending is blocked.
    assert alice_window.chat_partner_label.text() == bob_payload["username"]

    assert alice_window.input_bar.message_input.isEnabled() is False
    assert alice_window.input_bar.send_button.isEnabled() is False


def test_missing_public_key_no_error_dialog_and_no_send_attempt_on_real_interaction(
    connect, accounts
):
    """A real user interaction with the disabled widgets -- typing and
    pressing Enter, clicking Send -- must produce nothing: no
    message_sent emission, no error dialog, no bubble added, and (the
    security requirement) the underlying send is never even called."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))

    dialogs_shown = []
    alice_window.show_error = lambda message: dialogs_shown.append(message)

    sent_signals = []
    alice_window.input_bar.message_sent.connect(
        lambda message: sent_signals.append(message)
    )

    send_attempts = []
    original_send_chat_message = alice.send_chat_message

    def _tracked_send_chat_message(message):
        send_attempts.append(message)
        return original_send_chat_message(message)

    alice.send_chat_message = _tracked_send_chat_message

    messages_before = alice_window.messages.count()

    QTest.keyClicks(alice_window.input_bar.message_input, "hello bob")
    QTest.keyClick(alice_window.input_bar.message_input, Qt.Key_Return)
    QTest.mouseClick(alice_window.input_bar.send_button, Qt.LeftButton)

    assert sent_signals == [], "the disabled composer still emitted message_sent"
    assert dialogs_shown == [], f"a blocking error dialog was shown: {dialogs_shown}"
    assert send_attempts == [], "an encrypted send was attempted with no public key"
    assert alice_window.messages.count() == messages_before


# ----------------------------------------------------------------------
# C -- key arrives after the conversation is already open
# ----------------------------------------------------------------------


def test_public_key_arriving_while_open_enables_the_composer_automatically(
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)  # bob not connected yet

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice_window.input_bar.message_input.isEnabled() is False

    bob = connect(bob_payload)  # triggers server-side distribute_public_keys()

    assert _wait_for(lambda: _composer_enabled(alice_window)), (
        "composer never auto-enabled once the recipient's key arrived -- "
        "the user would have had to close/reopen the conversation"
    )

    # And it is now genuinely usable, not just visually enabled.
    alice_window.send_message("now it works")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "now it works"
            for summary in bob.conversation_store.get_all()
        )
    )


# ----------------------------------------------------------------------
# D -- a different user's key must not enable this conversation
# ----------------------------------------------------------------------


def test_a_different_users_key_does_not_enable_the_open_conversation(
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
    assert alice_window.input_bar.message_input.isEnabled() is False

    connect(carol_payload)  # carol comes online -> alice receives CAROL's key

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(carol_payload["username"]) is not None
    ), "test setup failed: alice never received carol's key at all"

    # Give the (wrongly-firing) case a real chance to happen before
    # asserting it didn't.
    _wait_for(lambda: _composer_enabled(alice_window), attempts=20)

    assert alice_window.input_bar.message_input.isEnabled() is False, (
        "a different user's key incorrectly enabled this conversation"
    )


# ----------------------------------------------------------------------
# E -- security: no message is ever sent without a verified key
# ----------------------------------------------------------------------


def test_no_plaintext_or_substitute_key_send_path_exists(connect, accounts):
    """Beyond "the button is disabled": even calling ChatWindow.
    send_message() directly (bypassing the widget state entirely, as
    if some other code path reached it) must not reach the network --
    the defense-in-depth guard inside send_message() itself, not just
    the composer's enabled state."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()

    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice.key_manager.get_public_key(bob_payload["username"]) is None

    send_attempts = []
    original_send_chat_message = alice.send_chat_message

    def _tracked_send_chat_message(message):
        send_attempts.append(message)
        return original_send_chat_message(message)

    alice.send_chat_message = _tracked_send_chat_message

    dialogs_shown = []
    alice_window.show_error = lambda message: dialogs_shown.append(message)

    # Direct method call -- deliberately bypassing the disabled widget.
    alice_window.send_message("this must never leave the machine")

    assert send_attempts == [], (
        "send_message() reached ClientSession.send_chat_message() with no "
        "verified public key"
    )
    assert dialogs_shown == []
    assert alice.key_manager.get_public_key(bob_payload["username"]) is None, (
        "no key may be created or substituted as a side effect"
    )
