"""
Phase 16C -- Cross-Device Key Synchronization.

Proves that an already-AUTHORIZED second device (e.g. a browser) can
receive an EXISTING conversation's key from another of the same
account's AUTHORIZED devices, via a dedicated device-to-device
protocol (crypto/device_protocol.py::canonical_device_key_sync_payload(),
server/device_handler.py::handle_device_key_sync(),
ClientSession.sync_conversation_key_to_device()/handle_device_key_sync())
-- reusing KeyManager.wrap_key_for_member()/unwrap_received_key()
(ML-KEM + AES-256-GCM) completely unchanged, never a new cryptographic
construction.

Deliberately NOT built on top of the ordinary group_key_distribution/
direct-conversation machinery: ClientSession._resolve_direct_
conversation_id() refuses a conversation with yourself, a pre-existing,
unrelated guard this phase does not weaken (see docs/architecture/
multi_device_identity.md's "Cross-device key distribution" section for
the discovery). Device-to-device sync is addressed by device_id, not
username, and routed by the server accordingly
(server/device_handler.py::_find_socket_for_bound_device()).

Run with:
    pytest tests/test_device_key_sync.py -v
"""

import base64
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
from crypto.device_protocol import canonical_device_key_sync_payload, sign_device_payload
from crypto.key_manager import fingerprint_combined_identity
from database.connection import SessionLocal
from database.models.device import DEVICE_STATE_AUTHORIZED, Device
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_VERIFIED
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
            "full_name": "Device Key Sync Test", "username": f"sync_{hint}{suffix}",
            "email": f"sync_{hint}{suffix}@example.com", "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
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
            db.query(Device).filter(Device.user_id == user.id).delete()
            db.delete(user)
            db.commit()
    finally:
        db.close()


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


@pytest.fixture()
def account():
    payload = _register("acct_")
    yield payload
    _delete(payload["username"])


def _new_device_session(running_server, monkeypatch, payload, key_store_dir):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", key_store_dir)

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


def _mutually_verify_devices(a, b):
    """Both directions of device-peer verification -- required before
    either side can wrap key material for, or trust material from, the
    other (Step 16: reuses the ordinary VERIFIED/UNVERIFIED/KEY_CHANGED
    machinery, keyed by device_id instead of username; never automatic).

    Reads key material directly from each session's own live
    KeyManager (not from anything observed over the wire), so there is
    nothing to wait for before calling observe_device_peer_identity()
    below (Phase 16D test-quality audit -- see this module's own
    "Step 13" note: a prior version of this helper opened with
    ``assert _wait_for(lambda: ... is None or True)``, a predicate that
    is always True regardless of what it inspects and therefore proved
    nothing; removed rather than fixed in place, since there was
    nothing genuine left to wait for once the redundant check itself
    was recognized as meaningless)."""

    a.observe_device_peer_identity(b.device_id, b.key_manager.public_key.decode("utf-8"), b.key_manager.ml_dsa.export_public_key())
    fp_b = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    a.confirm_device_peer_verification(b.device_id, fp_b)

    b.observe_device_peer_identity(a.device_id, a.key_manager.public_key.decode("utf-8"), a.key_manager.ml_dsa.export_public_key())
    fp_a = fingerprint_combined_identity(a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key())
    b.confirm_device_peer_verification(a.device_id, fp_a)


def _get_device_row(device_id):
    db = SessionLocal()
    try:
        return db.query(Device).filter(Device.device_id == uuid.UUID(device_id)).first()
    finally:
        db.close()


def _verify_peers(local_session, peer_session, peer_username):
    kem_wire = peer_session.key_manager.public_key
    signing_public_key = peer_session.key_manager.ml_dsa.export_public_key()
    local_session.observe_peer_identity(peer_username, kem_wire, signing_public_key)
    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    local_session.confirm_combined_peer_verification(peer_username, fingerprint)


# ========================================================================
# Step 11: direct conversation synchronization, real production path.
# ========================================================================


def test_newly_authorized_device_receives_existing_conversation_key_and_messages_bob(
    running_server, monkeypatch, account, tmp_path
):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")  # bootstrap -> AUTHORIZED
        desktop.bind_device_session()

        # 1. Alice Desktop has an existing encrypted conversation with Bob.
        assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(desktop.username) is not None)
        _verify_peers(desktop, bob, bob.username)
        _verify_peers(bob, desktop, desktop.username)

        desktop.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        desktop.establish_session_key()
        conversation_id = desktop.current_conversation_id
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        desktop.send_chat_message("hello before sync")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "hello before sync"
            for s in bob.conversation_store.get_all()
        ))

        # 2. Alice Browser is newly authorized.
        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        browser.bind_device_session()
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_AUTHORIZED

        # 3-8: mutual device-peer verification, then real key sync.
        _mutually_verify_devices(desktop, browser)

        assert not browser.key_manager.has_key(conversation_id)  # not yet synced

        sync_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        assert sync_result["success"] is True

        # Browser stores the conversation key via the REAL production
        # receive path (handle_device_key_sync()) -- never planted
        # directly into browser.key_manager.keys by the test.
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
        assert browser.key_manager.get_key(conversation_id) == desktop.key_manager.get_key(conversation_id)

        # 9-10: Browser opens the conversation.
        browser.set_current_chat(
            ConversationSummary(conversation_id=conversation_id, username=bob.username, is_online=True, latest_message=None)
        )

        # Bob must also trust Browser as a peer before secure messaging
        # works in that direction -- ordinary, unmodified peer
        # verification, unrelated to and unweakened by device sync.
        #
        # Honest note (a genuine finding of this phase, not a bug):
        # Desktop and Browser share the SAME username (same account),
        # so from BOB's point of view they are, correctly and by
        # design, still ONE peer-verification slot -- Bob already
        # VERIFIED that username against Desktop's keys earlier in
        # this test, so Browser's own public-key announcement is
        # correctly flagged KEY_CHANGED (crypto/identity_protocol.py's
        # own fail-closed behavior, completely unmodified). Disconnecting
        # Desktop first turns this into the single, clean, already-
        # covered KEY_CHANGED -> re-verify transition (see tests/
        # test_peer_identity_state_transitions.py) rather than two
        # devices racing for the same slot at once -- reconciling THAT
        # is a harder, separate problem (a third party recognizing
        # several devices as one identity) this phase does not claim
        # to solve; see docs/architecture/multi_device_identity.md.
        desktop.disconnect()

        assert _wait_for(lambda: browser.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(browser.username) is not None)
        _verify_peers(browser, bob, bob.username)
        _verify_peers(bob, browser, browser.username)
        assert bob.get_peer_verification_state(browser.username) == PEER_STATE_VERIFIED

        # 11-14: Browser sends a NEW encrypted message to Bob using the
        # synchronized key; Bob decrypts; Bob replies; Browser decrypts.
        received_by_bob = {}
        bob.message_received.connect(
            lambda identity_key, sender, text: received_by_bob.update(sender=sender, text=text)
        )
        browser.send_chat_message("hello from the synced browser")
        assert _wait_for(lambda: received_by_bob.get("text") == "hello from the synced browser")

        bob.set_current_chat(
            ConversationSummary(conversation_id=None, username=browser.username, is_online=True, latest_message=None)
        )
        received_by_browser = {}
        browser.message_received.connect(
            lambda identity_key, sender, text: received_by_browser.update(sender=sender, text=text)
        )
        bob.send_chat_message("reply from bob")
        assert _wait_for(lambda: received_by_browser.get("text") == "reply from bob")
    finally:
        desktop.disconnect()
        bob.disconnect()
        browser.disconnect()


# ========================================================================
# Step 14: restart proves real persistence, not in-memory state.
# ========================================================================


def test_restart_after_sync_preserves_key_and_can_still_message(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    browser_dir = tmp_path / "browser"
    browser = _new_device_session(running_server, monkeypatch, account, browser_dir)
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(desktop.username) is not None)
        _verify_peers(desktop, bob, bob.username)
        _verify_peers(bob, desktop, desktop.username)
        desktop.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        desktop.establish_session_key()
        conversation_id = desktop.current_conversation_id
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        browser.bind_device_session()
        _mutually_verify_devices(desktop, browser)

        desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
        synced_key = browser.key_manager.get_key(conversation_id)
    finally:
        browser.disconnect()

    # Genuinely fresh ClientSession, same on-disk key store -- NOT the
    # same in-memory KeyManager, NOT a manual key injection.
    restarted_browser = _new_device_session(running_server, monkeypatch, account, browser_dir)
    try:
        assert restarted_browser.key_manager.has_key(conversation_id)
        assert restarted_browser.key_manager.get_key(conversation_id) == synced_key

        restarted_browser.set_current_chat(
            ConversationSummary(conversation_id=conversation_id, username=bob.username, is_online=True, latest_message=None)
        )
        assert _wait_for(lambda: restarted_browser.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(restarted_browser.username) is not None)
        _verify_peers(restarted_browser, bob, bob.username)
        _verify_peers(bob, restarted_browser, restarted_browser.username)

        received = {}
        bob.message_received.connect(
            lambda identity_key, sender, text: received.update(sender=sender, text=text)
        )
        restarted_browser.send_chat_message("message after restart")
        assert _wait_for(lambda: received.get("text") == "message after restart")
    finally:
        desktop.disconnect()
        bob.disconnect()
        restarted_browser.disconnect()


# ========================================================================
# Step 15: security negative tests (fail-closed).
# ========================================================================


def test_forged_sync_signature_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        browser.bind_device_session()
        _mutually_verify_devices(desktop, browser)

        conversation_id = str(uuid.uuid4())
        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, os.urandom(32))

        from utils.protocol import create_device_key_sync_packet
        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch=1, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(os.urandom(3309)).decode("ascii"),
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


def test_sync_from_revoked_source_device_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        browser.bind_device_session()
        _mutually_verify_devices(desktop, browser)

        conversation_id = str(uuid.uuid4())
        desktop.key_manager.store_key(conversation_id, os.urandom(32), epoch=1)

        desktop.revoke_device(desktop.device_id)  # self-revoke the source

        sync_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)

        assert sync_result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


def test_pending_source_device_cannot_sync(running_server, monkeypatch, account, tmp_path):
    """Phase 19.19 -- Part 13 security matrix row 7 closure. The
    counterpart test_sync_from_revoked_source_device_rejected() above
    already proves a REVOKED source is rejected; this proves the other
    not-yet-AUTHORIZED state -- a source that was never authorized in
    the first place -- is rejected identically. Server-side, both
    states fail the exact same is_device_bound_and_authorized()-style
    check in handle_device_key_sync() (only True/AUTHORIZED passes),
    so this is not a new code path, only newly-covered evidence for
    the untested case the audit named."""

    bootstrap = _new_device_session(running_server, monkeypatch, account, tmp_path / "bootstrap")
    pending_source = _new_device_session(running_server, monkeypatch, account, tmp_path / "pending_source")
    try:
        bootstrap.enroll_device(device_name="Bootstrap", platform="linux")  # account's first device -- auto-AUTHORIZED
        bootstrap.bind_device_session()
        pending_source.enroll_device(device_name="PendingSource", platform="linux")  # left PENDING -- never authorized
        _mutually_verify_devices(pending_source, bootstrap)

        conversation_id = str(uuid.uuid4())
        pending_source.key_manager.store_key(conversation_id, os.urandom(32), epoch=1)

        sync_result = pending_source.sync_conversation_key_to_device(bootstrap.device_id, conversation_id)

        assert sync_result["success"] is False
        assert not bootstrap.key_manager.has_key(conversation_id)
    finally:
        bootstrap.disconnect()
        pending_source.disconnect()


def test_sync_to_revoked_target_device_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(desktop.username) is not None)
        _verify_peers(desktop, bob, bob.username)
        _verify_peers(bob, desktop, desktop.username)
        desktop.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        desktop.establish_session_key()
        conversation_id = desktop.current_conversation_id

        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        browser.bind_device_session()
        _mutually_verify_devices(desktop, browser)

        desktop.revoke_device(browser.device_id)

        sync_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)

        assert sync_result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        bob.disconnect()
        browser.disconnect()


def test_sync_to_device_on_different_account_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    other_payload = _register("other_")
    other = _new_device_session(running_server, monkeypatch, other_payload, tmp_path / "other")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        other.enroll_device(device_name="OtherDesktop", platform="linux")  # bootstrap on a DIFFERENT account

        assert _wait_for(lambda: desktop.key_manager.get_public_key(other.username) is not None)
        assert _wait_for(lambda: other.key_manager.get_public_key(desktop.username) is not None)
        _verify_peers(desktop, other, other.username)
        _verify_peers(other, desktop, desktop.username)
        desktop.set_current_chat(
            ConversationSummary(conversation_id=None, username=other.username, is_online=True, latest_message=None)
        )
        desktop.establish_session_key()

        # A SEPARATE conversation_id, never delivered to `other` via
        # any legitimate channel -- establish_session_key() above
        # already gave `other` a real key for ITS OWN conversation_id
        # as an ordinary verified peer, which would otherwise confound
        # this test's has_key() check below with a legitimate delivery.
        attack_conversation_id = str(uuid.uuid4())
        desktop.key_manager.store_key(attack_conversation_id, os.urandom(32), epoch=1)

        # desktop tries to "sync" (really: attack) a key sync packet
        # claiming other's device_id as the target -- other belongs to
        # a DIFFERENT account than desktop's authenticated connection.
        desktop.observe_device_peer_identity(
            other.device_id, other.key_manager.public_key.decode("utf-8"),
            other.key_manager.ml_dsa.export_public_key(),
        )
        fp = fingerprint_combined_identity(
            other.key_manager.public_key, other.key_manager.ml_dsa.export_public_key(),
        )
        desktop.confirm_device_peer_verification(other.device_id, fp)

        sync_result = desktop.sync_conversation_key_to_device(other.device_id, attack_conversation_id)

        assert sync_result["success"] is False
        assert not other.key_manager.has_key(attack_conversation_id)
    finally:
        desktop.disconnect()
        other.disconnect()


def test_sync_with_tampered_epoch_after_signing_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        browser.bind_device_session()
        _mutually_verify_devices(desktop, browser)

        conversation_id = str(uuid.uuid4())
        group_key = os.urandom(32)
        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, group_key)

        genuine_epoch = 1
        tampered_epoch = 99

        payload = canonical_device_key_sync_payload(
            desktop.username, desktop.device_id, browser.device_id, browser_pending["fingerprint"],
            conversation_id, genuine_epoch, "direct", encapsulation, wrapped_key,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)

        from utils.protocol import create_device_key_sync_packet
        tampered_packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch=tampered_epoch, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        )
        result = desktop.send_request(tampered_packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


def test_pending_target_device_cannot_receive_sync(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        browser.enroll_device(device_name="Browser", platform="web")  # left PENDING -- never authorized
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)

        desktop.observe_device_peer_identity(
            browser.device_id, browser.key_manager.public_key.decode("utf-8"),
            browser.key_manager.ml_dsa.export_public_key(),
        )
        desktop.confirm_device_peer_verification(browser.device_id, browser_pending["fingerprint"])

        conversation_id = str(uuid.uuid4())
        group_key = os.urandom(32)
        desktop.key_manager.store_key(conversation_id, group_key, epoch=1)

        sync_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)

        assert sync_result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()
