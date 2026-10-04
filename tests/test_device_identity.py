"""
Phase 16 -- Multi-Device Identity.

Proves the new account/device enrollment-authorization-revocation
protocol (crypto/device_protocol.py, server/device_handler.py,
database/models/device.py, ClientSession.enroll_device()/
list_devices()/authorize_device()/revoke_device()) against a real TLS
test server and real ClientSession instances -- the exact same
established pattern every other security test file in this suite
already uses (see tests/test_key_establishment_rejection_
observability.py's own `app` fixture).

Does NOT re-test existing peer-verification/ML-DSA/group-key
machinery -- see docs/architecture/multi_device_identity.md's own
"Preserving peer verification" section and this project's own
established rule against duplicating already-covered security
suites. Existing regression coverage for that is run separately (see
this phase's final report).

Run with:
    pytest tests/test_device_identity.py -v
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
from crypto.device_protocol import (
    canonical_device_authorization_payload,
    canonical_device_enrollment_payload,
    canonical_device_session_binding_payload,
    sign_device_payload,
)
from crypto.key_manager import fingerprint_combined_identity
from database.connection import SessionLocal
from database.models.device import DEVICE_STATE_AUTHORIZED, DEVICE_STATE_PENDING, DEVICE_STATE_REVOKED, Device
from database.models.message import Message
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
            "full_name": "Device Identity Test", "username": f"dev_{hint}{suffix}",
            "email": f"dev_{hint}{suffix}@example.com", "password": PASSWORD,
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


def _new_device_session(running_server, monkeypatch_module, payload, key_store_dir):
    """A fresh ClientSession, its OWN isolated key store (a distinct
    directory = a distinct physical device's local keypair -- exactly
    the "device local, unsynced" property docs/architecture/
    multi_device_identity.md documents), authenticated as the SAME
    account. Mirrors every other test file's `app` fixture, but
    inlined here since this file needs several independently-key-stored
    sessions for the SAME account within a single test."""

    _state, port = running_server
    monkeypatch_module.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch_module.setattr("storage.secure_key_store.KEY_STORE_DIR", key_store_dir)

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


def _get_device_row(device_id):
    db = SessionLocal()
    try:
        return db.query(Device).filter(Device.device_id == uuid.UUID(device_id)).first()
    finally:
        db.close()


# ========================================================================
# Bootstrap + happy path (A, B)
# ========================================================================


def test_bootstrap_first_device_is_auto_authorized(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    try:
        result = desktop.enroll_device(device_name="Desktop", platform="linux")
        assert result["success"] is True
        assert result["state"] == DEVICE_STATE_AUTHORIZED

        row = _get_device_row(desktop.device_id)
        assert row.state == DEVICE_STATE_AUTHORIZED
        assert row.authorized_by_device_id is None  # bootstrap -- nothing else authorized it
    finally:
        desktop.disconnect()


def test_second_device_authorized_device_can_authorize_it(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")

        enroll_result = browser.enroll_device(device_name="Browser", platform="web")
        assert enroll_result["success"] is True
        assert enroll_result["state"] == DEVICE_STATE_PENDING  # NOT auto-authorized -- Step 11

        devices = desktop.list_devices()
        pending = next(d for d in devices if d["device_id"] == browser.device_id)
        assert pending["state"] == DEVICE_STATE_PENDING

        auth_result = desktop.authorize_device(browser.device_id, pending["fingerprint"])
        assert auth_result["success"] is True

        row = _get_device_row(browser.device_id)
        assert row.state == DEVICE_STATE_AUTHORIZED
        assert str(row.authorized_by_device_id) == desktop.device_id
    finally:
        desktop.disconnect()
        browser.disconnect()


# ========================================================================
# Forgery / tamper rejection (D, E, F, G)
# ========================================================================


def test_forged_enrollment_signature_rejected(running_server, monkeypatch, account, tmp_path):
    session = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    try:
        session.device_id = str(uuid.uuid4())
        kem_wire = session.key_manager.public_key.decode("utf-8")
        dsa_pub = session.key_manager.ml_dsa.export_public_key()

        # Deliberately wrong signature -- an attacker who does not
        # hold the advertised device's private key.
        forged_signature = os.urandom(3309)

        from utils.protocol import create_device_enroll_request_packet
        packet = create_device_enroll_request_packet(
            device_id=session.device_id, device_name="Fake", platform="fake",
            kem_public_key=kem_wire, ml_dsa_public_key=base64.b64encode(dsa_pub).decode("ascii"),
            enrollment_signature=base64.b64encode(forged_signature).decode("ascii"),
        )
        result = session.send_request(packet)

        assert result["success"] is False
        assert _get_device_row(session.device_id) is None  # never inserted
    finally:
        session.disconnect()


def test_authorization_with_wrong_username_in_signed_payload_rejected(running_server, monkeypatch, account, tmp_path):
    """A signature genuinely produced by an AUTHORIZED device's own
    key, but over a payload signed for a DIFFERENT claimed username,
    must not verify against this account's own resolved identity --
    the server always reconstructs the payload from ITS OWN resolved
    `user.username`, never trusting one from the packet (there isn't
    one on the wire to trust in the first place; this proves that
    binding is load-bearing, not merely absent)."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        browser.enroll_device(device_name="Browser", platform="web")
        devices = desktop.list_devices()
        pending = next(d for d in devices if d["device_id"] == browser.device_id)

        wrong_payload = canonical_device_authorization_payload(
            "not-the-real-account-username", browser.device_id,
            pending["fingerprint"], desktop.device_id,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, wrong_payload)

        from utils.protocol import create_device_authorize_packet
        packet = create_device_authorize_packet(
            target_device_id=browser.device_id, target_fingerprint=pending["fingerprint"],
            authorizer_device_id=desktop.device_id,
            authorization_signature=base64.b64encode(signature).decode("ascii"),
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_PENDING
    finally:
        desktop.disconnect()
        browser.disconnect()


def test_modified_target_device_id_after_signing_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    another = _new_device_session(running_server, monkeypatch, account, tmp_path / "another")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        browser.enroll_device(device_name="Browser", platform="web")
        another.enroll_device(device_name="Another", platform="web")

        devices = desktop.list_devices()
        browser_pending = next(d for d in devices if d["device_id"] == browser.device_id)

        # Sign an authorization genuinely for `browser`, then relabel
        # it at the LAST moment to target `another` -- the signature
        # must not transfer.
        result = desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        assert result["success"] is True  # sanity: the real one works

        another_pending = next(d for d in desktop.list_devices() if d["device_id"] == another.device_id)
        payload = canonical_device_authorization_payload(
            desktop.username, browser.device_id, browser_pending["fingerprint"], desktop.device_id,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)

        from utils.protocol import create_device_authorize_packet
        tampered_packet = create_device_authorize_packet(
            target_device_id=another.device_id,  # swapped target, same signature
            target_fingerprint=another_pending["fingerprint"],
            authorizer_device_id=desktop.device_id,
            authorization_signature=base64.b64encode(signature).decode("ascii"),
        )
        tamper_result = desktop.send_request(tampered_packet)

        assert tamper_result["success"] is False
        assert _get_device_row(another.device_id).state == DEVICE_STATE_PENDING
    finally:
        desktop.disconnect()
        browser.disconnect()
        another.disconnect()


def test_modified_fingerprint_in_authorization_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        browser.enroll_device(device_name="Browser", platform="web")

        wrong_fingerprint = "0000 0000 0000 0000"
        result = desktop.authorize_device(browser.device_id, wrong_fingerprint)

        assert result["success"] is False
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_PENDING
    finally:
        desktop.disconnect()
        browser.disconnect()


# ========================================================================
# Replay / idempotency (H)
# ========================================================================


def test_replayed_enrollment_for_same_device_id_rejected(running_server, monkeypatch, account, tmp_path):
    session = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    try:
        first = session.enroll_device(device_name="Desktop", platform="linux")
        assert first["success"] is True

        second = session.enroll_device(device_name="Desktop", platform="linux")
        assert second["success"] is False
        assert "already enrolled" in second["error"]
    finally:
        session.disconnect()


# ========================================================================
# Unauthorized/revoked device cannot authorize or re-enter (C, I, K)
# ========================================================================


def test_pending_device_cannot_authorize_another(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    third = _new_device_session(running_server, monkeypatch, account, tmp_path / "third")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")  # bootstrap AUTHORIZED
        browser.enroll_device(device_name="Browser", platform="web")  # PENDING
        third.enroll_device(device_name="Third", platform="web")  # PENDING

        third_pending = next(d for d in desktop.list_devices() if d["device_id"] == third.device_id)

        # browser is only PENDING -- it must not be able to authorize third.
        result = browser.authorize_device(third.device_id, third_pending["fingerprint"])

        assert result["success"] is False
        assert _get_device_row(third.device_id).state == DEVICE_STATE_PENDING
    finally:
        desktop.disconnect()
        browser.disconnect()
        third.disconnect()


def test_revoked_device_cannot_authorize_another(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    third = _new_device_session(running_server, monkeypatch, account, tmp_path / "third")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_AUTHORIZED

        revoke_result = desktop.revoke_device(browser.device_id)
        assert revoke_result["success"] is True
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_REVOKED

        third.enroll_device(device_name="Third", platform="web")
        third_pending = next(d for d in desktop.list_devices() if d["device_id"] == third.device_id)

        result = browser.authorize_device(third.device_id, third_pending["fingerprint"])

        assert result["success"] is False
        assert _get_device_row(third.device_id).state == DEVICE_STATE_PENDING
    finally:
        desktop.disconnect()
        browser.disconnect()
        third.disconnect()


def test_revoked_device_cannot_be_reauthorized_by_stale_state(running_server, monkeypatch, account, tmp_path):
    """Once REVOKED, a device stays revoked -- nothing re-authorizes it
    merely by presenting its still-valid cryptographic keys again."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        desktop.revoke_device(browser.device_id)
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_REVOKED

        # Re-enrolling the SAME device_id must not silently restore it.
        re_enroll = browser.enroll_device(device_name="Browser", platform="web")
        assert re_enroll["success"] is False
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_REVOKED
    finally:
        desktop.disconnect()
        browser.disconnect()


# ========================================================================
# Server never receives private key material (Q)
# ========================================================================


def test_server_never_receives_or_stores_private_device_keys(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")

        row = _get_device_row(desktop.device_id)
        column_names = {c.name for c in Device.__table__.columns}

        assert not any("private" in name or "secret" in name for name in column_names)

        # The stored public keys must be exactly what the device
        # advertised as PUBLIC -- never longer/different in a way that
        # could suggest private material was appended.
        assert row.kem_public_key == desktop.key_manager.public_key.decode("utf-8")
        assert base64.b64decode(row.ml_dsa_public_key) == desktop.key_manager.ml_dsa.export_public_key()
    finally:
        desktop.disconnect()


# ========================================================================
# Phase 16B -- persistence, device-session binding, revocation
# enforcement on the group-key relay path.
# ========================================================================


def test_restart_preserves_device_id_fingerprint_and_avoids_duplicate_enrollment(
    running_server, monkeypatch, account, tmp_path
):
    """Step 8's mandatory restart test. Uses the REAL persistence path
    end to end -- a brand-new ClientSession, pointed at the SAME
    on-disk key-store directory an earlier "run" already wrote to, is
    what proves device_id survives a restart -- never a direct
    `session.device_id = old_id` assignment, which would prove
    nothing about the actual persistence code."""

    key_store_dir = tmp_path / "desktop"

    # "Run 1"
    first_run = _new_device_session(running_server, monkeypatch, account, key_store_dir)
    try:
        enroll_result = first_run.enroll_device(device_name="Desktop", platform="linux")
        assert enroll_result["success"] is True
        first_device_id = first_run.device_id
        first_kem_pub = first_run.key_manager.public_key
        first_dsa_pub = first_run.key_manager.ml_dsa.export_public_key()
    finally:
        first_run.disconnect()

    # "Run 2" -- a brand-new ClientSession/process, same installation
    # (same key_store_dir), reusing the real, unmodified
    # authenticate_credentials() -> connect() -> login() ->
    # send_public_key() startup sequence.
    second_run = _new_device_session(running_server, monkeypatch, account, key_store_dir)
    try:
        assert second_run.key_manager.public_key == first_kem_pub
        assert second_run.key_manager.ml_dsa.export_public_key() == first_dsa_pub

        re_enroll_result = second_run.enroll_device(device_name="Desktop", platform="linux")

        # device_id resolved purely from the persisted key store --
        # never assigned by the test.
        assert second_run.device_id == first_device_id

        # The server already has this device_id on file -- re-enrolling
        # it is correctly rejected as a duplicate (proving no SECOND,
        # unrelated device row was created for the same installation).
        assert re_enroll_result["success"] is False
        assert "already enrolled" in re_enroll_result["error"]

        row = _get_device_row(first_device_id)
        assert row.state == DEVICE_STATE_AUTHORIZED  # still the original bootstrap row

        bind_result = second_run.bind_device_session()
        assert bind_result["success"] is True
    finally:
        second_run.disconnect()


def test_revoked_device_cannot_bind_session_on_reconnect(running_server, monkeypatch, account, tmp_path):
    """Step 9's mandatory revoked-reconnect test: Device B is revoked,
    then reconnects using its REAL persistent identity (same key store,
    same device_id) and attempts to bind -- must be rejected because of
    device authorization state, not an unrelated error."""

    desktop_dir = tmp_path / "desktop"
    browser_dir = tmp_path / "browser"

    desktop = _new_device_session(running_server, monkeypatch, account, desktop_dir)
    browser = _new_device_session(running_server, monkeypatch, account, browser_dir)
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        browser.enroll_device(device_name="Browser", platform="web")
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])

        bind_before_revoke = browser.bind_device_session()
        assert bind_before_revoke["success"] is True

        desktop.revoke_device(browser.device_id)
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_REVOKED
    finally:
        desktop.disconnect()
        browser.disconnect()

    # Reconnect as Device B, using its real persisted key store --
    # never a manually-restored device_id.
    reconnected_browser = _new_device_session(running_server, monkeypatch, account, browser_dir)
    try:
        assert reconnected_browser.device_id is None  # not yet re-derived

        # enroll_device() resolves device_id from the persisted store
        # as a side effect -- call it (it will correctly fail as
        # "already enrolled", which is fine; the point is device_id
        # gets populated the same real way every other test uses it).
        reconnected_browser.enroll_device(device_name="Browser", platform="web")
        assert reconnected_browser.device_id == browser.device_id

        bind_result = reconnected_browser.bind_device_session()

        assert bind_result["success"] is False
        assert "not authorized" in bind_result["error"].lower()
    finally:
        reconnected_browser.disconnect()


def test_device_session_bind_with_forged_signature_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")

        forged_signature = os.urandom(3309)
        from utils.protocol import create_device_session_bind_packet
        packet = create_device_session_bind_packet(
            device_id=desktop.device_id, session_nonce=uuid.uuid4().hex,
            binding_signature=base64.b64encode(forged_signature).decode("ascii"),
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
    finally:
        desktop.disconnect()


def test_revoked_device_cannot_send_group_key_distribution(running_server, monkeypatch, account, tmp_path):
    """Step 4: server-side enforcement on the actual message-relay
    path (not just the device-management packets) -- the specific gap
    Phase 16's own report flagged as unresolved.

    Uses a real, different peer (Bob) as the conversation partner,
    not the same account's own second device: _resolve_direct_
    conversation_id() (pre-existing, unrelated to this phase) already
    refuses to open a conversation with yourself ("Cannot open a
    conversation with yourself"), discovered while writing this very
    test -- an existing architectural constraint, not something this
    phase works around or weakens (see this phase's own report,
    "Cross-device key distribution" section, for what this means for
    Step 5's original self-sync framing)."""

    alice_browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    try:
        alice_browser.enroll_device(device_name="Browser", platform="web")  # bootstrap -> AUTHORIZED
        alice_browser.bind_device_session()

        # Bob VERIFIES alice_browser as a normal peer -- ordinary
        # cross-account peer trust, unrelated to and unweakened by
        # device authorization (Step 11).
        bob.observe_peer_identity(
            alice_browser.username, alice_browser.key_manager.public_key,
            alice_browser.key_manager.ml_dsa.export_public_key(),
        )
        fp = fingerprint_combined_identity(
            alice_browser.key_manager.public_key, alice_browser.key_manager.ml_dsa.export_public_key(),
        )
        bob.confirm_combined_peer_verification(alice_browser.username, fp)
        assert _wait_for(lambda: bob.key_manager.get_public_key(alice_browser.username) is not None)

        # Symmetric: establish_session_key() requires THIS side (the
        # sender) to have already verified the recipient too.
        assert _wait_for(lambda: alice_browser.key_manager.get_public_key(bob.username) is not None)
        alice_browser.observe_peer_identity(
            bob.username, bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key(),
        )
        bob_fp = fingerprint_combined_identity(
            bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key(),
        )
        alice_browser.confirm_combined_peer_verification(bob.username, bob_fp)

        # Revoke alice_browser's OWN device (self-revocation -- a real,
        # legitimate case: "I lost this laptop").
        alice_browser.revoke_device(alice_browser.device_id)
        assert _get_device_row(alice_browser.device_id).state == DEVICE_STATE_REVOKED

        # Now-revoked alice_browser attempts to establish a session key
        # with Bob via the real, unmodified establish_session_key()/
        # _distribute_group_key() production path.
        alice_browser.set_current_chat(
            ConversationSummary(
                conversation_id=None, username=bob.username, is_online=True, latest_message=None,
            )
        )
        alice_browser.establish_session_key()

        conversation_id = alice_browser.current_conversation_id
        time.sleep(0.5)
        _app.processEvents()

        # Bob must never receive/install this key -- the server's own
        # sender-side enforcement (handle_group_key_distribution()'s
        # is_device_bound_and_authorized() check) must have dropped
        # the relay before it ever reached Bob.
        assert not bob.key_manager.has_key(conversation_id)
    finally:
        alice_browser.disconnect()
        bob.disconnect()


# ========================================================================
# Phase 19.18 -- L-1 closure: revocation was enforced only on the
# group-key-distribution/device-key-sync relay paths (the two tests
# above), never on the ordinary "chat" message relay -- an already-
# connected revoked device could keep using key material it already
# held. These four tests exercise server/client_handler.py's own new
# sender- and recipient-side is_device_bound_and_authorized() checks
# on that exact path, both directions, both direct and group.
# ========================================================================


def _mutual_verify(a, b):
    """Ordinary, unweakened peer verification both ways -- the same
    real production path (observe -> compute fingerprint independently
    -> confirm) every other cross-session test in this suite uses."""

    assert _wait_for(lambda: a.key_manager.get_public_key(b.username) is not None)
    assert _wait_for(lambda: b.key_manager.get_public_key(a.username) is not None)

    a.observe_peer_identity(
        b.username, b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key(),
    )
    b_fp = fingerprint_combined_identity(
        b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key(),
    )
    a.confirm_combined_peer_verification(b.username, b_fp)

    b.observe_peer_identity(
        a.username, a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key(),
    )
    a_fp = fingerprint_combined_identity(
        a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key(),
    )
    b.confirm_combined_peer_verification(a.username, a_fp)


def test_revoked_device_cannot_send_ordinary_direct_chat(running_server, monkeypatch, account, tmp_path):
    """Sender side, direct chat: a revoked device's send_chat_message()
    must never reach the recipient, even though the session key was
    established and fully valid BEFORE revocation -- this proves the
    server checks the CURRENT device state on every relayed chat
    packet, not just at key-establishment time."""

    alice = _new_device_session(running_server, monkeypatch, account, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    received = {}
    bob.message_received.connect(lambda identity_key, sender, text: received.update(sender=sender, text=text))
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()

        _mutual_verify(alice, bob)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        # Key exists and is valid -- revoke AFTER establishment, exactly
        # the "already-connected session" scenario L-1 describes.
        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        alice.send_chat_message("this must never arrive")
        time.sleep(0.5)
        _app.processEvents()

        assert received == {}
    finally:
        alice.disconnect()
        bob.disconnect()


def test_revoked_device_cannot_send_a_voice_message(running_server, monkeypatch, account, tmp_path):
    """Phase 19.24 -- Voice/Video Messages: proves the L-1 closure
    above (server/client_handler.py's single is_device_bound_and_
    authorized() check on the shared "chat" packet dispatch) also
    covers a voice/video attachment send -- send_attachment() goes
    through the EXACT SAME relay path as send_chat_message() (see
    domain/payload_type.py's own module docstring for why voice/video
    invented no new pipeline of their own), so this needs no separate
    server-side enforcement point, only this proof that the existing
    one really does cover it."""

    alice = _new_device_session(running_server, monkeypatch, account, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    received = []
    bob.payload_message_received.connect(
        lambda identity_key, sender, payload_type, data, content_metadata: received.append(payload_type)
    )
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()

        _mutual_verify(alice, bob)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        voice_path = tmp_path / "clip.m4a"
        voice_path.write_bytes(b"fake recorded audio bytes, never a real codec frame")

        # Same fire-and-forget contract as send_chat_message() -- the
        # send call itself does not raise; the server silently drops
        # the packet on its side, exactly like the direct-chat case
        # above.
        alice.send_attachment(str(voice_path))

        time.sleep(0.5)
        _app.processEvents()

        assert received == []
    finally:
        alice.disconnect()
        bob.disconnect()


def test_revoked_device_cannot_send_a_video_message(running_server, monkeypatch, account, tmp_path):
    """Closure pass (mandate Part 9): the mirror of test_revoked_
    device_cannot_send_a_voice_message above for PayloadType.VIDEO
    specifically -- do not assume the voice proof automatically covers
    video too; prove it explicitly, since the mandate's own instruction
    is not to assume L-1 covers every new payload type without a
    dedicated test."""

    alice = _new_device_session(running_server, monkeypatch, account, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    received = []
    bob.payload_message_received.connect(
        lambda identity_key, sender, payload_type, data, content_metadata: received.append(payload_type)
    )
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()

        _mutual_verify(alice, bob)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        video_path = tmp_path / "clip.mp4"
        video_path.write_bytes(b"fake recorded video bytes, never a real codec frame")

        alice.send_attachment(str(video_path))

        time.sleep(0.5)
        _app.processEvents()

        assert received == []
    finally:
        alice.disconnect()
        bob.disconnect()


def test_revoked_device_cannot_receive_a_voice_or_video_message(running_server, monkeypatch, account, tmp_path):
    """Recipient side, voice/video specifically (closure pass, mandate
    Part 9) -- mirrors test_revoked_device_cannot_receive_ordinary_
    direct_chat below, which only proves this for ordinary TEXT.
    Bob's voice/video message to a since-revoked Alice must not be
    relayed to Alice's revoked device live, proving the L-1 receive-
    side check is payload-type-agnostic, not merely assumed so because
    the send-side test above already covers it."""

    alice = _new_device_session(running_server, monkeypatch, account, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    received = []
    alice.payload_message_received.connect(
        lambda identity_key, sender, payload_type, data, content_metadata: received.append(payload_type)
    )
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()

        _mutual_verify(alice, bob)

        bob.set_current_chat(
            ConversationSummary(conversation_id=None, username=alice.username, is_online=True, latest_message=None)
        )
        bob.establish_session_key()
        conversation_id = bob.current_conversation_id
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        voice_path = tmp_path / "clip.m4a"
        voice_path.write_bytes(b"fake recorded audio bytes, never a real codec frame")

        bob.send_attachment(str(voice_path))

        time.sleep(0.5)
        _app.processEvents()

        assert received == []
    finally:
        alice.disconnect()
        bob.disconnect()


def test_revoked_device_cannot_receive_ordinary_direct_chat(running_server, monkeypatch, account, tmp_path):
    """Recipient side, direct chat: Bob's message to a since-revoked
    Alice must not be relayed to Alice's revoked device live -- the
    server drops it for that socket rather than trusting the
    connection just because it's still open."""

    alice = _new_device_session(running_server, monkeypatch, account, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    received = {}
    alice.message_received.connect(lambda identity_key, sender, text: received.update(sender=sender, text=text))
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()

        _mutual_verify(alice, bob)

        bob.set_current_chat(
            ConversationSummary(conversation_id=None, username=alice.username, is_online=True, latest_message=None)
        )
        bob.establish_session_key()
        conversation_id = bob.current_conversation_id
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        bob.send_chat_message("this must never be delivered live")
        time.sleep(0.5)
        _app.processEvents()

        assert received == {}
    finally:
        alice.disconnect()
        bob.disconnect()


def _latest_message_id(conversation_id, sender_id):
    db = SessionLocal()
    try:
        row = (
            db.query(Message)
            .filter(Message.conversation_id == conversation_id, Message.sender_id == sender_id)
            .order_by(Message.created_at.desc())
            .first()
        )
        return str(row.id)
    finally:
        db.close()


def _message_row(message_id):
    db = SessionLocal()
    try:
        return db.get(Message, uuid.UUID(str(message_id)))
    finally:
        db.close()


def test_revoked_device_does_not_receive_pin_notification(running_server, monkeypatch, account, tmp_path):
    """Phase 19.24 -- Pinned Messages, receiver side: proves the
    documented trust-model asymmetry in messaging_event_architecture.
    md's own "Multi-device and revocation" section actually holds for
    Pin specifically, not just by inheritance-by-description. Pin
    shares `_broadcast_to_conversation_members()` with edit/delete/
    reaction -- this is the first explicit regression test against
    that shared helper for ANY lifecycle-event broadcast, so it also
    stands in for edit/delete/reaction (all four route through the
    exact same fan-out code, not four separate implementations).

    Two things must both be true: (1) Bob's pin request is accepted
    and persisted (Bob's own device is never revoked -- the documented
    asymmetry is that the REQUEST is not re-gated on the sender's
    device state for lifecycle events, unlike ordinary chat); (2)
    Alice's already-revoked device must never receive the live
    `message_pinned` broadcast, exactly like it must never receive an
    ordinary chat message.
    """

    alice = _new_device_session(running_server, monkeypatch, account, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    alice_pinned_events = []
    alice.message_pinned_received.connect(
        lambda cid, mid, pinned_by, pinned_at: alice_pinned_events.append((mid, pinned_by))
    )
    bob_received = {}
    bob.message_received.connect(lambda identity_key, sender, text: bob_received.update(sender=sender, text=text))
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()

        _mutual_verify(alice, bob)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        alice.send_chat_message("pin me before you revoke me")
        assert _wait_for(lambda: bob_received.get("text") == "pin me before you revoke me")
        message_id = _latest_message_id(conversation_id, alice.user_id)

        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        bob.current_conversation_id = conversation_id
        bob.pin_message(message_id)

        assert _wait_for(lambda: _message_row(message_id).pinned_at is not None)
        assert str(_message_row(message_id).pinned_by) == str(bob.user_id)

        time.sleep(0.5)
        _app.processEvents()
        assert alice_pinned_events == []
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(bob_payload["username"])


def test_unrelated_users_unaffected_by_a_revoked_third_party_device(
    running_server, monkeypatch, account, tmp_path
):
    """The other half of L-1's own scoping requirement: the new
    per-socket check must be scoped to exactly the revoked device's
    own connection, never a blanket "something is revoked somewhere"
    switch. Alice's device is revoked; Bob and Carol -- two ordinary,
    unrelated, never-revoked accounts -- must keep messaging each
    other completely normally at the exact same time."""

    alice = _new_device_session(running_server, monkeypatch, account, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    carol_payload = _register("carol_")
    carol = _new_device_session(running_server, monkeypatch, carol_payload, tmp_path / "carol")
    received_carol = {}
    carol.message_received.connect(lambda identity_key, sender, text: received_carol.update(sender=sender, text=text))
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()
        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        _mutual_verify(bob, carol)
        bob.set_current_chat(
            ConversationSummary(conversation_id=None, username=carol.username, is_online=True, latest_message=None)
        )
        bob.establish_session_key()
        conversation_id = bob.current_conversation_id
        assert _wait_for(lambda: carol.key_manager.has_key(conversation_id))

        bob.send_chat_message("alice's revoked device must not affect this at all")
        assert _wait_for(lambda: received_carol.get("text") == "alice's revoked device must not affect this at all")
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_revoked_device_cannot_send_ordinary_group_chat(running_server, monkeypatch, tmp_path):
    """Sender side, group chat: the same server-side check on the
    group fan-out path (handle_group_chat_delivery()), not only the
    direct one."""

    alice_payload = _register("alice_")
    alice = _new_device_session(running_server, monkeypatch, alice_payload, tmp_path / "alice")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    received = {}
    bob.message_received.connect(lambda identity_key, sender, text: received.update(sender=sender, text=text))
    try:
        alice.enroll_device(device_name="Alice Device", platform="linux")
        alice.bind_device_session()

        _mutual_verify(alice, bob)

        alice.create_group_conversation("l1-group", [bob.username])

        conversation_id = None

        def _group_ready():
            nonlocal conversation_id
            for summary in alice.conversation_store.get_all():
                if summary.is_group and summary.group_name == "l1-group":
                    conversation_id = summary.conversation_id
                    return True
            return False

        assert _wait_for(_group_ready)
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        alice.revoke_device(alice.device_id)
        assert _get_device_row(alice.device_id).state == DEVICE_STATE_REVOKED

        alice.set_current_chat(
            ConversationSummary(
                conversation_id=conversation_id, username=None, is_online=True,
                latest_message=None, is_group=True, group_name="l1-group",
            )
        )
        alice.send_chat_message("this must never arrive in the group")
        time.sleep(0.5)
        _app.processEvents()

        assert received == {}
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
