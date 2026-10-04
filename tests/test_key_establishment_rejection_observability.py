"""
Phase 13.7 -- Key-Establishment Rejection Observability & State
Integrity.

Phase 13 (KYBER/group-key) and Phase 13.6 (RSA) already made
ClientSession.handle_group_key_distribution()/handle_session_key()
fail closed against forged/unverified/malformed key-establishment
packets. What they left unresolved: every rejection was a bare
``return`` after a log line -- nothing internally observable, nothing
a test or a future GUI layer could react to deterministically without
parsing log text, and (for the specific silent-rejection scenario this
phase's Part 7 targets) a sender who successfully sends can have no
idea the receiver silently discarded everything.

This file proves, for BOTH KYBER/group-key and RSA:

  * every rejection now returns a domain.security_rejection_reason.
    SecurityRejectionReason (None on success) and emits
    ClientSession.security_rejection(reason, sender, conversation_id) --
    Parts 3/4/8/9.
  * a rejected packet never installs a key, never overwrites a valid
    existing key, never alters peer trust state, and never crashes the
    receiver thread -- Part 2.
  * the exact silent-rejection scenario (Alice verified Bob, Bob has
    NOT verified Alice) is now deterministically observable, without
    changing the trust policy that produces it -- Part 7.
  * a receiver that just rejected an attack still works correctly for
    the next, legitimate packet -- Part 15.
  * a real, end-to-end malicious-relay attack against a live TLS
    server + real ClientSession pair produces an observable rejection
    and the receiver survives to handle the next legitimate exchange --
    Part 16.

Mirrors the established patterns from tests/test_group_key_
authentication.py and tests/test_rsa_session_key_authentication.py
exactly (bare, real -- no-mock -- ClientSession + SecureKeyStore for
hand-crafted-packet tests; real TLS server + real ClientSession pairs
for the end-to-end/malicious-relay proofs).

Run with:
    pytest tests/test_key_establishment_rejection_observability.py -v
"""

import base64
import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
import crypto.key_manager as key_manager_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.group_key_protocol import sign_group_key_payload
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from crypto.session_key_protocol import sign_rsa_session_key_payload
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.security_rejection_reason import SecurityRejectionReason
from storage.secure_key_store import PEER_STATE_VERIFIED, SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


def _wait_for(predicate, attempts=150, interval=0.05):
    """Pumps the Qt event loop while waiting -- required for a real,
    cross-thread Signal (emitted from the receiver thread, connected
    on this one) to actually be delivered, exactly as a running GUI
    would (matches tests/test_offline_unread_notification.py's own
    _wait_for()). Plain state checks (key_manager.has_key(), etc.) do
    not need this, but it is harmless for them either way."""

    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


# ========================================================================
# Session-level helpers (no server, no socket)
# ========================================================================


def _bare_session_with_store(username, tmp_path):
    session = ClientSession()
    session.username = username

    store = SecureKeyStore(f"{username}-user-id", storage_dir=tmp_path / username)
    store.unlock(PASSWORD)
    session.key_store = store

    return session


def _bare_rsa_session_with_store(username, tmp_path, monkeypatch):
    monkeypatch.setattr(key_manager_module, "KEY_EXCHANGE_ALGORITHM", "RSA")

    session = ClientSession()
    session.username = username
    assert session.key_manager.algorithm == "RSA"

    store = SecureKeyStore(f"{username}-user-id", storage_dir=tmp_path / username)
    store.unlock(PASSWORD)
    session.key_store = store

    return session


class _StubIdentity:
    def __init__(self, key_manager):
        self.key_manager = key_manager


def _verify_peer(local_session, peer_session, peer_username):
    kem_wire = peer_session.key_manager.public_key
    signing_public_key = peer_session.key_manager.ml_dsa.export_public_key()

    local_session.observe_peer_identity(peer_username, kem_wire, signing_public_key)
    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    local_session.confirm_combined_peer_verification(peer_username, fingerprint)


def _fresh_sender(algorithm=None):
    km = KeyManager()
    if algorithm is not None:
        km.algorithm = algorithm
    return km, km.ml_dsa


def _signed_group_key_packet(
    sender_username, sender_ml_dsa, sender_km, recipient_session, recipient_username,
    conversation_id, group_key, epoch=1, signer=None,
):
    sender_km.add_public_key(recipient_username, recipient_session.key_manager.public_key)
    encapsulation, wrapped_key = sender_km.wrap_key_for_member(recipient_username, group_key)
    actual_signer = signer if signer is not None else sender_ml_dsa

    signature = sign_group_key_payload(
        actual_signer, sender_username, conversation_id, recipient_username,
        encapsulation, wrapped_key, epoch,
    )

    return {
        "type": "group_key_distribution",
        "sender": sender_username,
        "conversation_id": conversation_id,
        "recipient": recipient_username,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": epoch,
        "group_key_signature": base64.b64encode(signature).decode("ascii"),
    }


def _signed_rsa_packet(
    sender_username, sender_ml_dsa, sender_km, recipient_session, recipient_username,
    conversation_id, session_key, epoch=1, signer=None, algorithm="RSA",
):
    sender_km.add_public_key(recipient_username, recipient_session.key_manager.public_key)
    encrypted_key = sender_km.encrypt_session_key(recipient_username, session_key)
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")
    actual_signer = signer if signer is not None else sender_ml_dsa

    signature = sign_rsa_session_key_payload(
        actual_signer, sender_username, recipient_username, conversation_id,
        algorithm, encrypted_key_b64, epoch,
    )

    return {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": sender_username,
        "receiver": recipient_username,
        "algorithm": algorithm,
        "encrypted_key": encrypted_key_b64,
        "conversation_id": conversation_id,
        "epoch": epoch,
        "session_key_signature": base64.b64encode(signature).decode("ascii"),
    }


def _signals(session):
    events = []
    session.security_rejection.connect(
        lambda reason, sender, conversation_id: events.append((reason, sender, conversation_id))
    )
    return events


# ========================================================================
# Part 2/3/4/8 -- every rejection reason, both paths: return value +
# signal + state-integrity invariant (no install, no overwrite, no
# trust-state change, no crash).
# ========================================================================


@pytest.mark.parametrize(
    "scenario",
    [
        "unknown_sender",
        "unverified_sender",
        "missing_signature",
        "invalid_signature",
        "sender_substitution",
        "conversation_substitution",
        "attacker_generated",
        "malformed_signature",
    ],
)
def test_group_key_rejection_is_observable_and_preserves_state(scenario, tmp_path):
    alice_km, alice_signer = _fresh_sender()
    carol_km, carol_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    events = _signals(bob)

    if scenario == "unverified_sender":
        # Observed, but never confirmed -- state is UNVERIFIED, not
        # unknown. Must NOT also call _verify_peer(): SecureKeyStore.
        # record_observed_peer_fingerprint() deliberately refuses to
        # touch an already-VERIFIED entry (see its own docstring), so
        # verifying first would make this downgrade attempt a no-op.
        bob.observe_peer_identity(
            "alice", alice_km.public_key, alice_signer.export_public_key()
        )
    elif scenario != "unknown_sender":
        _verify_peer(bob, _StubIdentity(alice_km), "alice")
    if scenario == "sender_substitution":
        _verify_peer(bob, _StubIdentity(carol_km), "carol")

    conversation_id = str(uuid.uuid4())
    group_key = os.urandom(32)

    packet = _signed_group_key_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, group_key,
    )

    if scenario == "unverified_sender":
        expected_reason = SecurityRejectionReason.UNVERIFIED_SENDER
    elif scenario == "unknown_sender":
        expected_reason = SecurityRejectionReason.UNKNOWN_SENDER
    elif scenario == "missing_signature":
        del packet["group_key_signature"]
        expected_reason = SecurityRejectionReason.MISSING_SIGNATURE
    elif scenario == "invalid_signature":
        packet["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
        expected_reason = SecurityRejectionReason.INVALID_SIGNATURE
    elif scenario == "sender_substitution":
        packet["sender"] = "carol"
        expected_reason = SecurityRejectionReason.INVALID_SIGNATURE
    elif scenario == "conversation_substitution":
        packet["conversation_id"] = str(uuid.uuid4())
        expected_reason = SecurityRejectionReason.INVALID_SIGNATURE
    elif scenario == "attacker_generated":
        packet = _signed_group_key_packet(
            "alice", carol_signer, carol_km, bob, "bob", conversation_id, group_key,
            signer=carol_signer,
        )
        expected_reason = SecurityRejectionReason.INVALID_SIGNATURE
    elif scenario == "malformed_signature":
        packet["group_key_signature"] = "not valid base64 !!"
        expected_reason = SecurityRejectionReason.MALFORMED_PACKET

    before_state = bob.get_peer_verification_state("alice")

    result = bob.handle_group_key_distribution(packet)

    assert result == expected_reason
    assert events == [(expected_reason.value, "alice", conversation_id)] or events == [
        (expected_reason.value, packet.get("sender") or "alice", packet.get("conversation_id") or conversation_id)
    ]
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    # Trust state is completely untouched by a rejection.
    assert bob.get_peer_verification_state("alice") == before_state


@pytest.mark.parametrize(
    "scenario",
    [
        "unknown_sender",
        "unverified_sender",
        "missing_signature",
        "invalid_signature",
        "sender_substitution",
        "algorithm_substitution",
        "attacker_generated",
        "malformed_signature",
    ],
)
def test_rsa_session_key_rejection_is_observable_and_preserves_state(scenario, tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_sender("RSA")
    carol_km, carol_signer = _fresh_sender("RSA")
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    events = _signals(bob)

    if scenario == "unverified_sender":
        # See the group-key test's identical comment: must NOT also
        # call _verify_peer(), or the downgrade attempt is a no-op.
        bob.observe_peer_identity(
            "alice", alice_km.public_key, alice_signer.export_public_key()
        )
    elif scenario != "unknown_sender":
        _verify_peer(bob, _StubIdentity(alice_km), "alice")
    if scenario == "sender_substitution":
        _verify_peer(bob, _StubIdentity(carol_km), "carol")

    conversation_id = str(uuid.uuid4())
    session_key = os.urandom(32)

    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, session_key,
    )

    if scenario == "unverified_sender":
        expected_reason = SecurityRejectionReason.UNVERIFIED_SENDER
    elif scenario == "unknown_sender":
        expected_reason = SecurityRejectionReason.UNKNOWN_SENDER
    elif scenario == "missing_signature":
        del packet["session_key_signature"]
        expected_reason = SecurityRejectionReason.MISSING_SIGNATURE
    elif scenario == "invalid_signature":
        packet["session_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
        expected_reason = SecurityRejectionReason.INVALID_SIGNATURE
    elif scenario == "sender_substitution":
        packet["sender"] = "carol"
        expected_reason = SecurityRejectionReason.INVALID_SIGNATURE
    elif scenario == "algorithm_substitution":
        packet["algorithm"] = "KYBER"
        expected_reason = SecurityRejectionReason.WRONG_ALGORITHM
    elif scenario == "attacker_generated":
        packet = _signed_rsa_packet(
            "alice", carol_signer, carol_km, bob, "bob", conversation_id, session_key,
            signer=carol_signer,
        )
        expected_reason = SecurityRejectionReason.INVALID_SIGNATURE
    elif scenario == "malformed_signature":
        packet["session_key_signature"] = "not valid base64 !!"
        expected_reason = SecurityRejectionReason.MALFORMED_PACKET

    before_state = bob.get_peer_verification_state("alice")

    result = bob.handle_session_key(packet)

    assert result == expected_reason
    assert len(events) == 1
    assert events[0][0] == expected_reason.value
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    assert bob.get_peer_verification_state("alice") == before_state


def test_group_key_malformed_packet_missing_fields_does_not_crash(tmp_path):
    bob = _bare_session_with_store("bob", tmp_path)
    events = _signals(bob)

    result = bob.handle_group_key_distribution(
        {"type": "group_key_distribution", "recipient": "bob"}
    )

    assert result == SecurityRejectionReason.MALFORMED_PACKET
    assert events[0][0] == SecurityRejectionReason.MALFORMED_PACKET.value


def test_rsa_session_key_malformed_packet_missing_fields_does_not_crash(tmp_path, monkeypatch):
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    events = _signals(bob)

    result = bob.handle_session_key(
        {"type": "key_exchange", "operation": "session_key"}
    )

    assert result == SecurityRejectionReason.MALFORMED_PACKET
    assert events[0][0] == SecurityRejectionReason.MALFORMED_PACKET.value


def test_group_key_changed_sender_is_reported_as_key_changed(tmp_path):
    """A previously-VERIFIED peer whose identity subsequently changed
    must be rejected as KEY_CHANGED specifically, not merely
    UNVERIFIED_SENDER -- the receiver's own state already distinguishes
    the two, so the report should too."""

    original_km, original_signer = _fresh_sender()
    new_km, new_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)

    _verify_peer(bob, _StubIdentity(original_km), "alice")
    assert bob.get_peer_verification_state("alice") == PEER_STATE_VERIFIED

    # alice reconnects with a genuinely different (KEM, signing) identity.
    bob.observe_peer_identity(
        "alice", new_km.public_key, new_signer.export_public_key()
    )
    from client.session import PEER_KEY_STATE_CHANGED
    assert bob.get_peer_verification_state("alice") == PEER_KEY_STATE_CHANGED

    events = _signals(bob)
    conversation_id = str(uuid.uuid4())
    packet = _signed_group_key_packet(
        "alice", new_signer, new_km, bob, "bob", conversation_id, os.urandom(32),
    )

    result = bob.handle_group_key_distribution(packet)

    assert result == SecurityRejectionReason.KEY_CHANGED
    assert events[0][0] == SecurityRejectionReason.KEY_CHANGED.value
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    # The KEY_CHANGED state itself is untouched -- neither silently
    # accepted nor silently cleared by the rejection.
    assert bob.get_peer_verification_state("alice") == PEER_KEY_STATE_CHANGED


def test_group_key_duplicate_delivery_is_reported_but_key_not_overwritten(tmp_path):
    """A second, independently and genuinely signed delivery for an
    ALREADY-installed epoch is reported as DUPLICATE_OR_STALE_KEY (not
    a security violation -- the sender IS who they claim -- but
    observably not-new), and the original key must survive intact."""

    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")
    events = _signals(bob)

    conversation_id = str(uuid.uuid4())
    first_key = os.urandom(32)
    packet1 = _signed_group_key_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, first_key,
    )
    result1 = bob.handle_group_key_distribution(packet1)
    assert result1 is None
    assert bob.key_manager.get_key(conversation_id, epoch=1) == first_key

    second_key = os.urandom(32)
    packet2 = _signed_group_key_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, second_key,
    )
    result2 = bob.handle_group_key_distribution(packet2)

    # Reported, but not a rejection of trust -- store_key() itself is
    # still a safe, unmodified no-op, so this is informational.
    assert any(e[0] == SecurityRejectionReason.DUPLICATE_OR_STALE_KEY.value for e in events)
    assert bob.key_manager.get_key(conversation_id, epoch=1) == first_key
    assert bob.key_manager.get_key(conversation_id, epoch=1) != second_key


# ========================================================================
# Part 7 -- the exact silent-rejection scenario, real end-to-end.
# ========================================================================


def _register_user(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Rejection Observability Test",
            "username": f"kero_{hint}{suffix}",
            "email": f"kero_{hint}{suffix}@example.com",
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


def _delete_user(username):
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


def _open_direct(session, partner_username):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=partner_username,
            is_online=True,
            latest_message=None,
        )
    )


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


@pytest.fixture()
def app(running_server, monkeypatch, tmp_path):
    """Two real, fully connected, KYBER-mode (default) ClientSessions
    with real, unlocked, isolated SecureKeyStores. Mirrors tests/
    test_group_key_authentication.py's own `app` fixture."""

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

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

    def _register(hint):
        payload = _register_user(hint)
        created.append(payload)
        return payload

    yield {"launch": _launch, "register": _register}

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001
            pass

    for payload in created:
        _delete_user(payload["username"])


def test_alice_verified_bob_but_bob_has_not_verified_alice_is_observable(app):
    """Part 7's exact scenario: Alice has verified Bob (her own
    sending-side gate is satisfied), Bob has NOT verified Alice. Alice
    attempts legitimate protected communication. Expected: Alice gets
    no false cryptographic success signal of her own (she has none to
    begin with -- send_chat_message() never confirms remote receipt);
    Bob does not install Alice's key; no valid existing key is
    overwritten (none existed); the receiver thread stays alive; a
    deterministic rejection is generated with a reason that identifies
    the trust-state problem. The trust POLICY is unchanged -- this
    only makes its existing, already-correct decision observable."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    events = _signals(bob)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    # Only Alice verifies Bob -- deliberately, this is the scenario.
    # Bob has automatically OBSERVED alice's identity (the real,
    # unconditional identity broadcast both online clients exchange on
    # connect) but never explicitly VERIFIED her -- state UNVERIFIED,
    # not unknown.
    _verify_peer(alice, bob, bob.username)
    assert bob.get_peer_verification_state(alice.username) != PEER_STATE_VERIFIED

    _open_direct(alice, bob.username)
    alice.send_chat_message("alice thinks this is protected")

    assert _wait_for(
        lambda: any(
            reason == SecurityRejectionReason.UNVERIFIED_SENDER.value
            and sender == alice.username
            for reason, sender, _cid in events
        )
    ), "bob's rejection of alice's unverified key was never observed"

    conversation_id = alice.current_conversation_id
    assert not bob.key_manager.has_key(conversation_id)
    assert bob.is_connected()
    # bob's receiver thread is still alive and usable.
    assert bob.receiver_thread is not None and bob.receiver_thread.is_alive()


# ========================================================================
# Part 15 -- attack, then immediately verify legitimate communication
# still works (receiver did not die, did not corrupt state).
# ========================================================================


@pytest.mark.parametrize(
    "corrupt",
    ["signature", "sender", "conversation_id"],
)
def test_group_key_attack_then_legitimate_packet_still_works(tmp_path, corrupt):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    malicious_key = os.urandom(32)
    malicious_packet = _signed_group_key_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, malicious_key,
    )
    if corrupt == "signature":
        malicious_packet["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
    elif corrupt == "sender":
        malicious_packet["sender"] = "mallory"
    elif corrupt == "conversation_id":
        malicious_packet["conversation_id"] = str(uuid.uuid4())

    rejection = bob.handle_group_key_distribution(malicious_packet)
    assert rejection is not None
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None

    # Immediately afterward: a genuine, legitimate packet for the SAME
    # conversation must still be accepted -- the rejection above must
    # not have left the receiver in any state that blocks this.
    legitimate_key = os.urandom(32)
    legitimate_packet = _signed_group_key_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, legitimate_key,
    )
    result = bob.handle_group_key_distribution(legitimate_packet)

    assert result is None
    assert bob.key_manager.get_key(conversation_id, epoch=1) == legitimate_key


@pytest.mark.parametrize(
    "corrupt",
    ["signature", "sender", "algorithm"],
)
def test_rsa_session_key_attack_then_legitimate_packet_still_works(tmp_path, monkeypatch, corrupt):
    alice_km, alice_signer = _fresh_sender("RSA")
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    malicious_key = os.urandom(32)
    malicious_packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, malicious_key,
    )
    if corrupt == "signature":
        malicious_packet["session_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
    elif corrupt == "sender":
        malicious_packet["sender"] = "mallory"
    elif corrupt == "algorithm":
        malicious_packet["algorithm"] = "KYBER"

    rejection = bob.handle_session_key(malicious_packet)
    assert rejection is not None
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None

    legitimate_key = os.urandom(32)
    legitimate_packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, legitimate_key,
    )
    result = bob.handle_session_key(legitimate_packet)

    assert result is None
    assert bob.key_manager.get_key(conversation_id, epoch=1) == legitimate_key


# ========================================================================
# Part 9 -- thread safety: the signal genuinely crosses from the
# receiver thread to whatever thread connected the slot, exactly like
# every other existing ClientSession Signal.
# ========================================================================


def test_security_rejection_signal_crosses_receiver_thread(app, monkeypatch):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    events = _signals(bob)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    real_send_message = client_session_module.send_message

    def tampering_send_message(sock, packet):
        if packet.get("type") == "group_key_distribution":
            tampered = dict(packet)
            tampered["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
            return real_send_message(sock, tampered)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", tampering_send_message)

    _verify_peer(alice, bob, bob.username)
    _verify_peer(bob, alice, alice.username)

    _open_direct(alice, bob.username)
    alice.send_chat_message("triggers a real, cross-thread rejection")

    # Bob's receiver thread processes this packet on ITS OWN thread and
    # emits security_rejection there -- this only becomes visible to
    # this (main) thread's connected slot once the Qt event loop is
    # pumped, exactly like every other cross-thread Signal in this
    # codebase (see tests/test_peer_key_verification.py's own
    # processEvents()-free direct-call tests versus this real-receiver-
    # thread one).
    assert _wait_for(lambda: len(events) > 0)
    assert events[0][0] == SecurityRejectionReason.INVALID_SIGNATURE.value


# ========================================================================
# Part 16 -- real malicious relay: receiver survives, rejection is
# observable, subsequent legitimate communication still works.
# ========================================================================


def test_malicious_relay_group_key_receiver_survives_and_recovers(app, monkeypatch):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    events = _signals(bob)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    _verify_peer(alice, bob, bob.username)
    _verify_peer(bob, alice, alice.username)

    attacker_km = KeyManager()
    attacker_km.add_public_key(bob.username, bob.key_manager.public_key)

    real_send_message = client_session_module.send_message
    tamper_active = {"on": True}

    def tampering_send_message(sock, packet):
        if tamper_active["on"] and packet.get("type") == "group_key_distribution":
            tampered = dict(packet)
            _, forged_wrapped = attacker_km.wrap_key_for_member(bob.username, os.urandom(32))
            tampered["wrapped_key"] = forged_wrapped
            return real_send_message(sock, tampered)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", tampering_send_message)

    alice.create_group_conversation("Rejection Observability Group", [bob.username])
    time.sleep(1.0)
    _app.processEvents()

    # Attack rejected, observably, key never installed.
    assert any(r == SecurityRejectionReason.INVALID_SIGNATURE.value for r, _s, _c in events)
    assert all(not epochs for epochs in bob.key_manager.keys.values())
    assert bob.is_connected()
    assert bob.receiver_thread.is_alive()

    # Now let a genuine (untampered) exchange through and confirm it
    # actually works -- the attack did not leave bob's receiver in a
    # state that blocks legitimate future communication.
    tamper_active["on"] = False

    _open_direct(alice, bob.username)
    _open_direct(bob, alice.username)
    alice.send_chat_message("legitimate message after the attack")

    assert _wait_for(
        lambda: any(
            s.latest_message and s.latest_message.text == "legitimate message after the attack"
            for s in bob.conversation_store.get_all()
        )
    )
