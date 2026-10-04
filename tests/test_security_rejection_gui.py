"""
Phase 14.1 -- Security Rejection GUI.

ClientSession.security_rejection (Phase 13.7) already exists, is
already emitted only for genuine, already-decided security rejections,
and already carries no secret material (see its own docstring on
ClientSession). This file proves the ONE thing Phase 14.1 adds: that
signal now reaches a real GUI consumer (ChatWindow.
handle_security_rejection() -> StatusBarWidget.set_security_notice())
which displays a safe, non-blocking notice -- and nothing more. It
deliberately does NOT re-prove the underlying cryptographic rejection
decisions themselves; those are tests/test_group_key_authentication.py's,
tests/test_rsa_session_key_authentication.py's, and tests/
test_kyber_session_key_forgery_remediation.py's job, already done.

ChatWindow.__init__() itself performs a real server round trip
(register_callbacks() -> load_conversations()), so every test here
needs a real, connected ClientSession against a real TLS test server --
mirrors tests/test_offline_unread_notification.py's/tests/
test_chat_window_read_receipt_on_receive.py's established `connect`/
`accounts` fixture pattern exactly.

Run with:
    pytest tests/test_security_rejection_gui.py -v
"""

import base64
import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
import gui.chat_window as chat_window_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from crypto.group_key_protocol import sign_group_key_payload
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.security_rejection_reason import SecurityRejectionReason
from gui.chat_window import ChatWindow
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])
_KEEP_ALIVE = []

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
            "full_name": "Security Rejection GUI Test",
            "username": f"secgui_{hint}{suffix}",
            "email": f"secgui_{hint}{suffix}@example.com",
            "password": PASSWORD,
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
def app(running_server, monkeypatch, tmp_path):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    # Isolate this test's local encrypted key store from every other
    # test/run -- authenticate_credentials() unlocks a REAL, on-disk
    # SecureKeyStore, and without this it would default to the shared,
    # persistent KEY_STORE_DIR, leaking peer-verification state across
    # runs (established pattern from every other `app`/`connect`
    # fixture across tests/test_group_key_authentication.py etc.).
    monkeypatch.setattr(
        "storage.secure_key_store.KEY_STORE_DIR", tmp_path / "keystore"
    )

    opened = []
    created = []

    def _launch(payload):
        session = ClientSession()
        opened.append(session)

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

    def _register_fn(hint):
        payload = _register(hint)
        created.append(payload)
        return payload

    yield {"launch": _launch, "register": _register_fn}

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001
            pass

    for payload in created:
        _delete(payload["username"])


def _chat_window_for(session):
    window = ChatWindow(session)
    _KEEP_ALIVE.append(window)
    # QWidget.isVisible() is only ever True if every ancestor up to the
    # top-level window is also shown -- matches tests/
    # test_composer_public_key_availability.py's own established
    # pattern for the identical reason.
    window.show()
    return window


# ========================================================================
# A/B -- the signal reaches the GUI handler and produces a visible,
# non-blocking notice.
# ========================================================================


def test_security_rejection_signal_reaches_gui_and_shows_a_notice(app):
    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    assert window.status.security_label.isVisible() is False

    bob.security_rejection.emit("invalid_signature", "alice", "conv-1")

    assert window.status.security_label.isVisible() is True
    text = window.status.security_label.text()
    assert "Security warning" in text
    assert "failed authentication" in text
    assert "No trusted key or identity state was changed" in text


def test_every_defined_reason_produces_some_safe_notice_or_none(app):
    """Every SecurityRejectionReason value either produces a mapped,
    non-empty notice, or (duplicate_or_stale_key only) deliberately
    produces none -- never a crash, never a blank "Security warning:"
    with nothing after it."""

    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    for reason in SecurityRejectionReason:
        window.status._clear_security_notice()

        bob.security_rejection.emit(reason.value, "alice", "conv-1")

        if reason == SecurityRejectionReason.DUPLICATE_OR_STALE_KEY:
            assert window.status.security_label.isVisible() is False
        else:
            assert window.status.security_label.isVisible() is True
            assert len(window.status.security_label.text()) > len(
                "Security warning: an incoming packet was rejected -- . "
                "No trusted key or identity state was changed."
            )


def test_unknown_reason_falls_back_to_a_generic_safe_notice(app):
    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    bob.security_rejection.emit(
        "some_future_reason_this_gui_does_not_know", "alice", "conv-1"
    )

    assert window.status.security_label.isVisible() is True
    assert "failed a security check" in window.status.security_label.text()


# ========================================================================
# C/D/E -- displayed text is safe: no attacker-controlled sender/
# conversation_id, no secrets, no packet contents of any kind.
# ========================================================================


def test_attacker_controlled_sender_and_conversation_id_are_never_displayed(app):
    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    hostile_sender = "<script>alert(1)</script>malicious_sender_" + "A" * 500
    hostile_conversation_id = "'; DROP TABLE messages; --" + str(uuid.uuid4())

    bob.security_rejection.emit("invalid_signature", hostile_sender, hostile_conversation_id)

    text = window.status.security_label.text()
    assert hostile_sender not in text
    assert hostile_conversation_id not in text
    assert "<script>" not in text
    assert "DROP TABLE" not in text


def test_no_secret_or_cryptographic_material_ever_reaches_the_notice(app):
    """The security_rejection signal itself carries no such material
    (its only arguments are reason/sender/conversation_id -- see
    ClientSession._report_security_rejection()'s own docstring), and
    handle_security_rejection() never reads anything else off the
    session -- confirmed here by checking the notice text can never
    contain this client's own real key material, even though that
    material genuinely exists on the session object at the same time."""

    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    real_signing_key_b64 = base64.b64encode(
        bob.key_manager.ml_dsa.export_public_key()
    ).decode("ascii")

    bob.security_rejection.emit("invalid_signature", "alice", "conv-1")

    text = window.status.security_label.text()
    assert real_signing_key_b64 not in text


# ========================================================================
# F/G -- the GUI does not alter peer verification or key state; it is
# purely a consumer of an already-made decision.
# ========================================================================


def test_gui_notice_does_not_alter_peer_verification_or_key_state(app):
    """Drives a REAL forged group-key packet through the REAL
    production receiver (ClientSession.handle_group_key_distribution())
    with a REAL ChatWindow attached, proving both that the signal
    genuinely reaches the GUI end-to-end from the actual security
    decision (not just a hand-emitted signal) and that displaying the
    notice introduces no new side effect on trust/key state."""

    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    before_state = bob.get_peer_verification_state("alice")
    conversation_id = str(uuid.uuid4())
    before_key = bob.key_manager.get_key(conversation_id, epoch=1)

    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    encapsulation, wrapped_key = attacker_km.wrap_key_for_member("bob", os.urandom(32))
    forged_signature = sign_group_key_payload(
        attacker_km.ml_dsa, "alice", conversation_id, bob.username,
        encapsulation, wrapped_key, 1,
    )

    forged_packet = {
        "type": "group_key_distribution",
        "sender": "alice",
        "conversation_id": conversation_id,
        "recipient": bob.username,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": 1,
        "group_key_signature": base64.b64encode(forged_signature).decode("ascii"),
    }

    result = bob.handle_group_key_distribution(forged_packet)

    assert result == SecurityRejectionReason.UNKNOWN_SENDER
    assert window.status.security_label.isVisible() is True
    assert "unknown sender" in window.status.security_label.text()

    # State integrity: unchanged by the rejection OR by the GUI having
    # displayed a notice about it.
    assert bob.get_peer_verification_state("alice") == before_state
    assert bob.key_manager.get_key(conversation_id, epoch=1) == before_key
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


# ========================================================================
# H -- normal, non-security errors continue to use the existing modal
# handling, unchanged.
# ========================================================================


def test_ordinary_error_occurred_still_uses_the_existing_modal_path(app, monkeypatch):
    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    calls = []
    monkeypatch.setattr(
        chat_window_module.QMessageBox, "critical",
        lambda *args, **kwargs: calls.append(args)
    )

    bob.error_occurred.emit("No AES session key found for alice.")

    assert len(calls) == 1
    # The security-notice status line is untouched by an ordinary error.
    assert window.status.security_label.isVisible() is False


# ========================================================================
# I -- legitimate traffic never produces a false security warning.
# ========================================================================


def test_legitimate_group_key_delivery_produces_no_security_warning(app):
    alice_km = KeyManager()

    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    # Bob genuinely observes and verifies alice.
    bob.observe_peer_identity(
        "alice", alice_km.public_key, alice_km.ml_dsa.export_public_key()
    )
    fingerprint = fingerprint_combined_identity(
        alice_km.public_key, alice_km.ml_dsa.export_public_key()
    )
    bob.confirm_combined_peer_verification("alice", fingerprint)

    conversation_id = str(uuid.uuid4())
    alice_km.add_public_key("bob", bob.key_manager.public_key)
    encapsulation, wrapped_key = alice_km.wrap_key_for_member("bob", os.urandom(32))
    signature = sign_group_key_payload(
        alice_km.ml_dsa, "alice", conversation_id, bob.username,
        encapsulation, wrapped_key, 1,
    )

    genuine_packet = {
        "type": "group_key_distribution",
        "sender": "alice",
        "conversation_id": conversation_id,
        "recipient": bob.username,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": 1,
        "group_key_signature": base64.b64encode(signature).decode("ascii"),
    }

    result = bob.handle_group_key_distribution(genuine_packet)

    assert result is None
    assert bob.key_manager.get_key(conversation_id, epoch=1) is not None
    assert window.status.security_label.isVisible() is False


# ========================================================================
# J -- repeated rejections do not crash the GUI, and never stack/queue.
# ========================================================================


def test_repeated_security_rejections_do_not_crash_and_do_not_stack(app):
    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)
    window = _chat_window_for(bob)

    for i in range(25):
        bob.security_rejection.emit(
            "invalid_signature", f"attacker{i}", str(uuid.uuid4())
        )  # must not raise, any iteration

    assert window.status.security_label.isVisible() is True
    # Only ever one notice label, showing only the LATEST rejection --
    # nothing queues or stacks. It appears in the layout exactly once
    # (the same widget instance created once in build_ui(), never
    # re-created per notification), and its text is a single message,
    # not 25 concatenated ones.
    assert window.status.layout().indexOf(window.status.security_label) != -1
    assert window.status.security_label.text().count("Security warning") == 1
    assert "attacker24" not in window.status.security_label.text()  # untrusted content never shown anyway (see test D)
