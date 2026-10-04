"""
BUG -- Offline Unread/Notification.

Root cause (read-only investigation, confirmed): ClientSession.
unread_counts (client/session.py) is a plain in-memory dict, empty at
construction, and was only ever written to by increment_unread() --
called exclusively from the two LIVE-arrival signal handlers,
ChatWindow.receive_message()/receive_payload_message(). Messages
queued entirely while a recipient was offline never fire those
handlers (no receiver thread was running to receive them), so nothing
ever incremented the count for them -- even though the server had
already been correctly tracking exactly this state all along, via the
MessageRecipient/MessageDeliveryStatus rows the existing read-receipt
feature (C2) already writes and reads.

The fix reuses that existing, authoritative state rather than
inventing anything new:

  - ConversationRepository.get_conversation_previews_for_user() now
    also returns each conversation's unread_count -- a single batched
    query (_get_unread_counts()) over MessageRecipient rows scoped to
    (recipient_id == this user) AND (status != READ), the exact same
    fields/semantics MessageRepository.mark_conversation_read()
    already reads and writes.
  - server/client_handler.py::handle_conversation_list_request() adds
    unread_count as one additive field per conversation.
  - ClientSession.load_conversations() seeds unread_counts from it via
    a new ClientSession.set_unread_count(key, count) -- an absolute
    value, never increment_unread(), which remains exclusively for a
    live message arriving after login.

Nothing about mark_conversation_read(), handle_read_receipt(),
clear_unread(), or MessageRecipient's write path changed -- this is
purely a new read of state those already maintain.

These tests drive real ClientSessions against a real running server --
the same pattern tests/test_offline_messaging.py already established
-- so what's proven is the actual production wiring.

Run with:
    pytest tests/test_offline_unread_notification.py -v
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_public_key
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from gui.chat_window import ChatWindow
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

_KEEP_ALIVE = []


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Offline Unread Notification Test",
            "username": f"oun_{hint}{suffix}",
            "email": f"oun_{hint}{suffix}@example.com",
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
    exactly as a running GUI would (matches
    tests/test_chat_window_read_receipt_on_receive.py)."""

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


def _verify_peer(sender, peer_username, peer_session, tmp_path):
    """Server-Untrusted Identity Verification, Stage 3: the ``connect``
    fixture's sessions never call authenticate_credentials() (a
    bare-token login, matching this file's pre-Stage-3 needs), so they
    never unlock a local SecureKeyStore -- meaning
    _peer_key_is_verified() would otherwise always be False for them.
    Gives ``sender`` a real, isolated, unlocked store and verifies
    ``peer_username``'s current fingerprint, so a subsequent
    send_chat_message() is not blocked by a policy this file's own
    scenarios (unread-count bookkeeping) have nothing to do with."""

    store = SecureKeyStore(sender.user_id, storage_dir=tmp_path / f"keystore-{sender.user_id}")
    store.unlock("Str0ng!Passw0rd")
    sender.key_store = store
    store.verify_peer_fingerprint(
        peer_username, fingerprint_public_key(peer_session.key_manager.public_key)
    )


def _find_conversation_row(widget, key):
    """The real ConversationRow widget for ``key``, or None -- the same
    lookup ConversationListWidget.set_unread_count() itself does
    (gui/conversation_list_widget.py), used here read-only to inspect
    the ACTUAL rendered badge rather than trusting ClientSession state
    alone. Requires the ChatWindow to have been .show()n -- otherwise
    every child widget's isVisible() is unconditionally False
    regardless of its own setVisible(True) call, since Qt visibility
    is effective only within a shown top-level window's hierarchy."""

    for i in range(widget.count()):
        item = widget.item(i)
        summary = item.data(Qt.UserRole)
        if summary is not None and summary.key == key:
            return widget.itemWidget(item)
    return None


# ----------------------------------------------------------------------
# 4/5 -- offline messages produce the correct unread count at login,
# and opening the conversation clears it through the existing mechanism
# ----------------------------------------------------------------------


def test_offline_messages_show_unread_count_before_opening_and_clear_after(
    connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")  # never connects while alice sends

    alice = connect(alice_payload)

    _open_direct(alice, bob_payload["username"])

    for index in range(3):
        alice.send_chat_message(f"offline message {index}")
        time.sleep(0.05)

    bob = connect(bob_payload)
    # BUG -- Offline Unread/Notification is specifically about
    # load_conversations() -- the real GUI calls it once at startup
    # (ChatWindow.register_callbacks()); this minimal connect()
    # fixture, matching tests/test_offline_messaging.py's convention,
    # deliberately does not, so it is called explicitly here.
    bob.load_conversations()

    assert bob.get_unread_count(alice_payload["username"]) == 3, (
        f"expected unread_count 3, got "
        f"{bob.get_unread_count(alice_payload['username'])}"
    )

    # The messages are visible (already proven by
    # tests/test_offline_first_contact.py) -- this test's own concern
    # is only the unread count. clear_unread() and mark_conversation_
    # read() are two separate calls the GUI makes together in
    # ChatWindow.open_conversation()/_mark_current_conversation_read()
    # (client/session.py has no single "open" method that does both),
    # so both are exercised here to match that real flow.
    _open_direct(bob, alice_payload["username"])
    bob.load_conversation_history(alice_payload["username"], is_group=False)
    bob.clear_unread(alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)

    assert bob.get_unread_count(alice_payload["username"]) == 0


# ----------------------------------------------------------------------
# 6 -- already-read messages do not reappear as unread on a later login
# ----------------------------------------------------------------------


def test_already_read_offline_messages_do_not_reappear_as_unread(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("read on the first login")

    bob = connect(bob_payload)
    bob.load_conversations()
    assert bob.get_unread_count(alice_payload["username"]) == 1

    _open_direct(bob, alice_payload["username"])
    bob.load_conversation_history(alice_payload["username"], is_group=False)
    bob.clear_unread(alice_payload["username"])
    bob.mark_conversation_read(bob.current_conversation_id)
    assert bob.get_unread_count(alice_payload["username"]) == 0

    _disconnect(bob)

    # A genuinely fresh login -- unread_counts starts empty again, and
    # must be re-seeded as 0, not re-derived as if nothing were ever
    # read.
    bob_again = connect(bob_payload)
    bob_again.load_conversations()

    assert bob_again.get_unread_count(alice_payload["username"]) == 0


# ----------------------------------------------------------------------
# 7 -- live unread behavior is unchanged (both directions)
# ----------------------------------------------------------------------


def test_live_message_to_a_closed_conversation_still_increments_unread(
    connect, accounts, tmp_path
):
    """increment_unread() lives in gui/chat_window.py (called from
    receive_message()/receive_payload_message()), not in
    ClientSession, so this drives a real ChatWindow -- exactly the
    pattern tests/test_chat_window_read_receipt_on_receive.py already
    established -- to prove the unmodified live path still works."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)
    carol = connect(carol_payload)

    _wait_for_public_keys(alice, bob, alice_payload["username"], bob_payload["username"])
    _wait_for_public_keys(carol, bob, carol_payload["username"], bob_payload["username"])
    _verify_peer(alice, bob_payload["username"], bob, tmp_path)
    # Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication):
    # bob is also the RECEIVER of the live group_key_distribution
    # packet alice's send_chat_message() below triggers, which now
    # separately requires bob to have alice already VERIFIED too --
    # without this, the packet is silently rejected and bob never
    # actually decrypts alice's message.
    _verify_peer(bob, alice_payload["username"], alice, tmp_path)

    bob_window = ChatWindow(bob)
    _KEEP_ALIVE.append(bob_window)

    # Bob is looking at Carol's conversation, not Alice's, when
    # Alice's message arrives.
    bob_window.open_conversation(_direct_summary(carol_payload["username"]))

    alice.set_current_chat(_direct_summary(bob_payload["username"]))
    alice.send_chat_message("live, bob is looking elsewhere")

    assert _wait_for(
        lambda: bob.get_unread_count(alice_payload["username"]) == 1
    ), "a live message to a conversation that is not open must still increment unread"


def test_live_message_to_the_open_conversation_does_not_increment_unread(
    connect, accounts, tmp_path
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _wait_for_public_keys(alice, bob, alice_payload["username"], bob_payload["username"])
    _verify_peer(alice, bob_payload["username"], bob, tmp_path)
    # Phase 13: bob is also the RECEIVER of the live group_key_
    # distribution packet below, which now separately requires bob to
    # have alice already VERIFIED too.
    _verify_peer(bob, alice_payload["username"], alice, tmp_path)

    bob_window = ChatWindow(bob)
    _KEEP_ALIVE.append(bob_window)

    bob_window.open_conversation(_direct_summary(alice_payload["username"]))

    alice.set_current_chat(_direct_summary(bob_payload["username"]))
    alice.send_chat_message("live, bob already has this open")

    assert _wait_for(lambda: bob_window.messages.count() > 0), (
        "the message never reached the open ChatWindow"
    )

    assert bob.get_unread_count(alice_payload["username"]) == 0


# ----------------------------------------------------------------------
# 8 -- independent counts across multiple conversations, via real
# separately-connecting sessions (not just the repository layer)
# ----------------------------------------------------------------------


def test_independent_unread_counts_across_multiple_conversations(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    charlie_payload = accounts("charlie_")

    alice = connect(alice_payload)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("from alice 1")
    alice.send_chat_message("from alice 2")

    charlie = connect(charlie_payload)
    _open_direct(charlie, bob_payload["username"])
    for index in range(5):
        charlie.send_chat_message(f"from charlie {index}")
        time.sleep(0.05)

    bob = connect(bob_payload)
    bob.load_conversations()

    assert bob.get_unread_count(alice_payload["username"]) == 2
    assert bob.get_unread_count(charlie_payload["username"]) == 5


# ----------------------------------------------------------------------
# GUI regression: the ACTUAL rendered badge, not just ClientSession
# state -- reproduces the real manual test exactly (server, real
# ChatWindow, Bob never opens Alice's conversation before the badge is
# checked).
# ----------------------------------------------------------------------


def test_offline_unread_badge_renders_before_opening_and_clears_after(
    connect, accounts
):
    """The manual reproduction, automated: Alice sends 3 messages while
    Bob is completely offline; Bob then connects and a real ChatWindow
    is constructed (register_callbacks() -> load_conversations(), the
    exact production startup path) -- WITHOUT ever opening Alice's
    conversation. The sidebar's actual ConversationRow for Alice must
    already show a visible badge reading "3". Opening the conversation
    afterward must clear it, through the existing, unmodified
    clear_unread()/mark_conversation_read() flow.

    Asserts on row.unread_badge.isVisible()/.text() directly -- not
    ClientSession.get_unread_count() -- which is what actually caught
    nothing wrong here on first investigation, but is the coverage gap
    the manual test exposed: a passing session-level assertion does not
    prove the widget renders it."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")  # stays offline for steps 5-7

    alice = connect(alice_payload)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("Test 1")
    alice.send_chat_message("Test 2")
    alice.send_chat_message("Test 3")

    # Only now does Bob connect -- mirrors "do NOT connect Bob while
    # the messages are being sent" exactly.
    bob = connect(bob_payload)

    bob_window = ChatWindow(bob)  # register_callbacks() -> load_conversations()
    _KEEP_ALIVE.append(bob_window)
    bob_window.show()  # required for isVisible() to reflect reality -- see _find_conversation_row()

    assert _wait_for(
        lambda: _find_conversation_row(bob_window.conversation_list, alice_payload["username"])
        is not None
    ), "Alice's conversation never appeared in Bob's sidebar"

    def _alice_row():
        return _find_conversation_row(
            bob_window.conversation_list, alice_payload["username"]
        )

    assert _wait_for(
        lambda: _alice_row() is not None and _alice_row().unread_badge.isVisible()
    ), "unread badge for Alice was never shown before Bob opened the conversation"

    row = _alice_row()
    assert row.unread_badge.text() == "3", (
        f"expected unread badge text '3', got {row.unread_badge.text()!r}"
    )

    # Step 14/15: opening the conversation clears it.
    bob_window.open_conversation(_direct_summary(alice_payload["username"]))

    assert _wait_for(lambda: _alice_row().unread_badge.isVisible() is False), (
        "unread badge did not clear after opening the conversation"
    )


def test_offline_unread_badge_reappears_for_a_second_offline_round(
    connect, accounts, tmp_path
):
    """Kept separate from the primary scenario per the request, rather
    than overloading one test: Bob reads the first batch, disconnects,
    Alice sends 2 more while he is offline again, and the badge must
    reappear -- reading "2", not stale/leftover state from the first
    round -- when he reconnects and before he reopens the conversation."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("first round")

    bob = connect(bob_payload)
    bob_window = ChatWindow(bob)
    _KEEP_ALIVE.append(bob_window)
    bob_window.show()

    def _alice_row():
        return _find_conversation_row(
            bob_window.conversation_list, alice_payload["username"]
        )

    assert _wait_for(lambda: _alice_row() is not None and _alice_row().unread_badge.isVisible())

    # Bob reads the first round.
    bob_window.open_conversation(_direct_summary(alice_payload["username"]))
    assert _wait_for(lambda: _alice_row().unread_badge.isVisible() is False)

    # Bob's key is cached by now (proven indirectly by the badge/read
    # assertions above already having required his connection to
    # fully land) -- verify him here, before he goes offline again, so
    # the second round below is not blocked by Stage 3. "first round"
    # above needed no such step: it was sent before Bob had ever
    # connected at all -- true offline-first-contact, deliberately
    # unaffected by verification (see ClientSession.
    # establish_session_key()'s Stage-3 docstring).
    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )
    _verify_peer(alice, bob_payload["username"], bob, tmp_path)

    _disconnect(bob)

    # Alice sends 2 more while Bob is offline again.
    alice.send_chat_message("second round 1")
    alice.send_chat_message("second round 2")

    bob_again = connect(bob_payload)
    bob_again_window = ChatWindow(bob_again)
    _KEEP_ALIVE.append(bob_again_window)
    bob_again_window.show()

    def _alice_row_again():
        return _find_conversation_row(
            bob_again_window.conversation_list, alice_payload["username"]
        )

    assert _wait_for(
        lambda: _alice_row_again() is not None and _alice_row_again().unread_badge.isVisible()
    ), "badge did not reappear for the second offline round"

    row = _alice_row_again()
    assert row.unread_badge.text() == "2", (
        f"expected unread badge text '2', got {row.unread_badge.text()!r}"
    )

    bob_again_window.open_conversation(_direct_summary(alice_payload["username"]))
    assert _wait_for(lambda: _alice_row_again().unread_badge.isVisible() is False)
