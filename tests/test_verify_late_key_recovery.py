"""
Verify-late key recovery.

A direct key distribution that arrives before the receiver has
verified the sender is correctly rejected (fail-closed, unchanged).
Before this phase, that rejection was permanent for the rest of the
session -- nothing ever asked again once the user verified the peer
seconds later, and the only way to actually recover was a full
reconnect. That gap was found via a real desktop<->mobile chat: the
desktop reconnected, the server's own key-recovery announcement raced
ahead of the user tapping "Verify Identity", the redelivery attempt
was rejected as unverified, and the message stayed stuck "Not sent"
indefinitely even after verification completed moments later.

Two symmetric gaps, both fixed the same way (retry once verification
completes, using the exact request/redelivery machinery that already
runs on an ordinary reconnect -- see client/session.py's
_pending_key_requests_awaiting_verification and
_declined_redeliveries_awaiting_verification, and mobile/session.py's
identically-named counterparts):

    A) The RECEIVER of a key distribution had not yet verified the
       SENDER when it arrived (handle_group_key_distribution()'s own
       "not self._peer_key_is_verified(sender)" branch). Fixed by
       _retry_pending_key_requests(): re-asks the sender once the
       receiver verifies them.

    B) The SENDER of a would-be redelivery had not yet verified the
       RECIPIENT when the server asked it to redeliver
       (handle_direct_key_redelivery_required()'s own "SECURITY:
       refusing to redeliver" branch). Fixed by
       _retry_declined_redeliveries(): retries the redelivery once the
       sender verifies the recipient.

Together these mean verification can complete in either order, on
either side, without a manual reconnect -- exactly the two directions
a live user reported ("phone verified then desktop verified" and
"desktop verified then phone verified") both needing to work.

Run with:
    pytest tests/test_verify_late_key_recovery.py -v
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_combined_identity
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


def _wait_for(predicate, attempts=150, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Verify Late Test", "username": f"vl_{hint}{suffix}",
            "email": f"vl_{hint}{suffix}@example.com", "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


def _new_session(running_server, monkeypatch, hint, tmp_path):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", tmp_path / hint)

    payload = _register(hint)
    session = ClientSession()
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _verify(local_session, peer_session):
    """local_session verifies peer_session's identity -- the same
    action VerifyIdentityDialog's confirm button performs."""

    assert _wait_for(lambda: peer_session.username in local_session._observed_peer_signing_public_keys)
    kem = local_session._observed_peer_raw_public_keys[peer_session.username]
    signing = local_session._observed_peer_signing_public_keys[peer_session.username]
    fingerprint = fingerprint_combined_identity(kem, signing)
    local_session.confirm_combined_peer_verification(peer_session.username, fingerprint)


# ========================================================================
# A) Receiver verifies the sender AFTER a key distribution was already
#    rejected as unverified -- the exact scenario physically reproduced
#    live (desktop reconnects, redelivery races ahead of the user's
#    Verify Identity tap).
# ========================================================================


def test_receiver_verifying_late_recovers_a_previously_rejected_key(running_server, monkeypatch, tmp_path):
    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        # bob verifies alice first, so bob's own sending gate
        # (establish_session_key()) is satisfied.
        _verify(bob, alice)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        bob.set_current_chat(
            ConversationSummary(conversation_id=None, username=alice.username, is_online=True, latest_message=None)
        )

        # alice has NOT verified bob yet -- bob establishes a key and
        # sends a real message under it, exactly as a live send would.
        # The server's own recovery-request handler (client_handler.py
        # ::handle_direct_key_recovery_request()) only agrees to relay
        # a redelivery for an epoch it can see referenced by an actual
        # persisted message -- establishing a key alone is not enough.
        bob.establish_session_key()
        conversation_id = bob.current_conversation_id
        bob.send_chat_message("hello alice")
        time.sleep(0.5)
        _app.processEvents()

        # Rejected: alice never installs it, and remembers why.
        assert not alice.key_manager.has_key(conversation_id)
        assert bob.username in alice._pending_key_requests_awaiting_verification

        # alice verifies bob now -- this alone, with no reconnect,
        # must recover the key.
        _verify(alice, bob)

        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))
        assert bob.username not in alice._pending_key_requests_awaiting_verification
    finally:
        alice.disconnect()
        bob.disconnect()


# ========================================================================
# B) Sender verifies the recipient AFTER declining to redeliver a key
#    it already holds, purely for not having verified them yet -- the
#    mirror-image ordering.
# ========================================================================


def test_sender_verifying_late_retries_a_previously_declined_redelivery(running_server, monkeypatch, tmp_path):
    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        # Real connection so bob genuinely OBSERVES alice's identity
        # (populating _observed_peer_*_public_keys), without bob
        # verifying her -- exactly "peer known, not yet verified".
        assert _wait_for(lambda: alice.username in bob._observed_peer_signing_public_keys)
        assert not bob._peer_key_is_verified(alice.username)

        # bob already holds a key for some conversation with alice
        # (simulating a key established earlier, before this
        # reconnect-recovery cycle) -- store_key() alone, bypassing
        # establish_session_key()'s own sender-side verified gate,
        # since that gate is not what this test exercises.
        conversation_id = str(uuid.uuid4())
        bob.key_manager.store_key(conversation_id, os.urandom(32), epoch=1)

        # The server asks bob to redeliver to alice (a reconnecting
        # peer needing this epoch) -- driven directly, exactly as
        # handle_group_key_distribution()-adjacent tests in this suite
        # already drive handlers directly rather than requiring a full
        # server round trip for the recovery-request half.
        bob.handle_direct_key_redelivery_required({
            "conversation_id": conversation_id, "epoch": 1, "recipient": alice.username,
        })

        # Declined -- bob is not verified with alice yet -- and
        # remembered.
        assert alice.username in bob._declined_redeliveries_awaiting_verification

        # bob verifies alice now -- this alone, with no reconnect,
        # must retry the redelivery.
        _verify(bob, alice)

        assert alice.username not in bob._declined_redeliveries_awaiting_verification
    finally:
        alice.disconnect()
        bob.disconnect()
