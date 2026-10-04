"""
Phase 12B -- Message-Level ML-DSA Origin Authentication: real
ClientSession-to-ClientSession integration.

crypto/message_protocol.py's own unit tests (tests/test_message_
protocol.py) prove the canonicalization and forgery-detection
properties in isolation. This file proves the PRODUCTION path: real
ClientSession.send_chat_message()/send_attachment() sign for real,
through a real TLS test server, verified for real by a real receiving
ClientSession's handle_chat() -- including the one property no crypto-
unit-test can prove: that a message tampered with IN TRANSIT (after
signing, before verification) is rejected end to end, never decrypted,
displayed, or stored as authentic.

Run with:
    pytest tests/test_message_authentication.py -v
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
from crypto.key_manager import fingerprint_combined_identity
from crypto.message_protocol import sign_message_payload
from crypto.ml_dsa import MLDSASigner
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Message Authentication Test",
            "username": f"mauth_{hint}{suffix}",
            "email": f"mauth_{hint}{suffix}@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
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


def _wait_for(predicate, attempts=300, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


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
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr(
        "storage.secure_key_store.KEY_STORE_DIR", tmp_path / "keystore"
    )

    opened = []
    created = []

    def _launch(payload, password=PASSWORD):
        session = ClientSession()
        opened.append(session)

        result = session.authenticate_credentials(payload["phone_number"], password)
        assert result.success, result.message

        session.user_id = result.user_id
        session.username = result.username
        session.session_id = result.session_id
        session.access_token = result.token_pair.access_token
        session.refresh_token = result.token_pair.refresh_token

        session.connect()
        session.login(payload["username"])
        session.send_public_key()
        session.start_receiver()
        return session

    def _register_user(hint):
        payload = _register(hint)
        created.append(payload)
        return payload

    yield {"launch": _launch, "register": _register_user}

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001
            pass

    for payload in created:
        _delete(payload["username"])


def _mutual_public_keys(alice, bob, alice_name, bob_name):
    """Waits for BOTH the KEM key (KeyManager.get_public_key()) AND the
    ML-DSA signing-key observation (_observed_peer_signing_public_keys)
    to be in place on each side. _handle_signed_public_key() installs
    the former slightly before it records the latter (a deliberate,
    unrelated ordering fix from Phase 11 -- see its own docstring) --
    waiting on the KEM key alone leaves a real, sub-millisecond race
    where confirm_combined_peer_verification() (which needs BOTH) can
    still raise PeerVerificationMismatchError immediately afterward."""

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_name) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_name) is not None)
    assert _wait_for(
        lambda: alice._observed_peer_signing_public_keys.get(bob_name) is not None
    )
    assert _wait_for(
        lambda: bob._observed_peer_signing_public_keys.get(alice_name) is not None
    )


def _mutual_verify(alice, bob, alice_name, bob_name):
    """Establishes VERIFIED both ways -- required before EITHER side
    can send a DIRECT message at all: establish_session_key()'s
    pre-existing Stage-3 gate (unrelated to message-level signing,
    already in place since well before Phase 11/12) raises
    PeerNotVerifiedError for a cached-but-unverified peer. Group
    messaging bypasses this gate entirely (_send_encrypted_payload()
    only calls establish_session_key() for a non-group chat), so tests
    below that use a group conversation do not need this."""

    _mutual_public_keys(alice, bob, alice_name, bob_name)

    alice_fingerprint = fingerprint_combined_identity(
        bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key()
    )
    alice.confirm_combined_peer_verification(bob_name, alice_fingerprint)

    bob_fingerprint = fingerprint_combined_identity(
        alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
    )
    bob.confirm_combined_peer_verification(alice_name, bob_fingerprint)


# ========================================================================
# Direct messaging -- production path, success case
# ========================================================================


def test_direct_message_real_end_to_end_signing_and_verification(app):
    """Client A -> real encryption -> real ML-DSA signing -> real
    server relay -> Client B -> real ML-DSA verification -> real
    decryption -> message accepted, displayed, and stored."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    _mutual_verify(alice, bob, alice_payload["username"], bob_payload["username"])

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("hello bob, this is really me")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "hello bob, this is really me"
            for summary in bob.conversation_store.get_all()
        )
    )


# ========================================================================
# Direct messaging -- the required adversarial integration test
# ========================================================================


def test_attacker_modifies_network_message_receiver_rejects_it(app, monkeypatch):
    """The required adversarial test: a message is intercepted between
    a real send and a real receive, and its ciphertext is modified IN
    TRANSIT -- exactly what a malicious relay server (this project's
    entire threat model) could do to any packet it forwards. The
    receiver must reject it: never decrypted, never displayed, never
    stored as authentic."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    _mutual_verify(alice, bob, alice_payload["username"], bob_payload["username"])

    real_send_message = client_session_module.send_message

    def tampering_send_message(sock, packet):
        if packet.get("type") == "chat" and packet.get("sender") == alice_payload["username"]:
            tampered = dict(packet)
            # Flip the ciphertext -- signature (over the ORIGINAL
            # ciphertext) can no longer verify.
            tampered["message"] = tampered["message"][:-4] + (
                "AAAA" if tampered["message"][-4:] != "AAAA" else "BBBB"
            )
            return real_send_message(sock, tampered)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", tampering_send_message)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("this must be rejected by bob")

    # Give the receiver thread ample opportunity to (wrongly) accept
    # it, then prove it never did.
    time.sleep(1.0)
    _app.processEvents()

    assert not any(
        summary.latest_message and summary.latest_message.text == "this must be rejected by bob"
        for summary in bob.conversation_store.get_all()
    )

    # The receiver thread must still be alive and functional -- prove
    # it by sending a second, genuine (untampered) message right after,
    # which must succeed normally.
    monkeypatch.setattr(client_session_module, "send_message", real_send_message)
    alice.send_chat_message("this one is genuine")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "this one is genuine"
            for summary in bob.conversation_store.get_all()
        )
    )


def test_attacker_forges_signature_from_a_different_key_receiver_rejects_it(app, monkeypatch):
    """A stronger adversarial variant: the attacker doesn't merely
    corrupt the signature bytes, but produces a COMPLETELY VALID ML-DSA
    signature -- just from their own, different keypair -- over the
    exact same (tampered) message, and substitutes it in transit. Must
    still be rejected, since verification uses the RECEIVER's own
    trusted key for "alice", never anything the attacker supplies."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    _mutual_verify(alice, bob, alice_payload["username"], bob_payload["username"])

    attacker_signer = MLDSASigner()
    attacker_signer.generate_keys()

    real_send_message = client_session_module.send_message

    def forging_send_message(sock, packet):
        if packet.get("type") == "chat" and packet.get("sender") == alice_payload["username"]:
            forged = dict(packet)
            forged_signature = sign_message_payload(
                attacker_signer,
                forged["sender"],
                forged.get("receiver"),
                forged.get("conversation_id"),
                forged.get("payload_type"),
                forged["message"],
                forged.get("content_metadata"),
                forged.get("epoch"),
            )
            forged["message_signature"] = base64.b64encode(forged_signature).decode("ascii")
            return real_send_message(sock, forged)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", forging_send_message)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("attacker-resigned message")

    time.sleep(1.0)
    _app.processEvents()

    assert not any(
        summary.latest_message and summary.latest_message.text == "attacker-resigned message"
        for summary in bob.conversation_store.get_all()
    )


def test_missing_signature_does_not_crash_receiver_thread(app, monkeypatch):
    """Forgery test 12: an invalid (here, entirely absent) message
    signature must not crash the receiver thread -- proven by sending
    a genuine follow-up message right after and confirming it still
    arrives normally."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    _mutual_verify(alice, bob, alice_payload["username"], bob_payload["username"])

    real_send_message = client_session_module.send_message

    def stripping_send_message(sock, packet):
        if packet.get("type") == "chat" and packet.get("sender") == alice_payload["username"]:
            stripped = dict(packet)
            stripped.pop("message_signature", None)
            return real_send_message(sock, stripped)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", stripping_send_message)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("unsigned -- must not crash bob's receiver")

    time.sleep(1.0)
    _app.processEvents()

    assert not any(
        summary.latest_message
        and summary.latest_message.text == "unsigned -- must not crash bob's receiver"
        for summary in bob.conversation_store.get_all()
    )

    assert bob.receiver_thread is not None
    assert bob.receiver_thread.is_alive()

    monkeypatch.setattr(client_session_module, "send_message", real_send_message)
    alice.send_chat_message("receiver thread still alive")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "receiver thread still alive"
            for summary in bob.conversation_store.get_all()
        )
    )


# ========================================================================
# UNVERIFIED / VERIFIED state handling
# ========================================================================


def test_message_from_unverified_peer_with_valid_signature_is_accepted_but_stays_unverified(
    app,
):
    """UNVERIFIED: message signature verification may prove possession
    of the advertised key -- and the message is accordingly accepted --
    but this must NOT silently promote the peer to VERIFIED.

    Only ALICE (the sender) verifies BOB. BOB deliberately never
    verifies ALICE, so the property under test (a message from an
    UNVERIFIED sender still authenticates, without promoting them) is
    exercised from BOB's, the receiver's, side.

    Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication):
    session-key ESTABLISHMENT itself (establish_session_key(), even for
    a direct conversation -- it reuses the group_key_distribution
    channel) now requires the RECEIVER to have the SENDER verified too,
    same as group-key distribution -- so it can no longer be used to
    reach this scenario (bob would reject the key delivery before any
    message could ever be sent). The session key is seeded directly on
    both sides instead, exactly like tests/test_offline_messaging.py's
    and tests/test_message_persistence_integration.py's own established
    "manually seed the key, then test something downstream of it"
    pattern -- isolating message-level authentication (what this test
    actually proves) from key-ESTABLISHMENT authentication (a separate,
    already-covered concern -- see tests/test_group_key_authentication.py).
    """

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    _mutual_public_keys(alice, bob, alice_payload["username"], bob_payload["username"])

    alice_fingerprint = fingerprint_combined_identity(
        bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key()
    )
    alice.confirm_combined_peer_verification(bob_payload["username"], alice_fingerprint)

    assert bob.get_peer_verification_state(alice_payload["username"]) != "VERIFIED"

    _open_direct(alice, bob_payload["username"])
    _open_direct(bob, alice_payload["username"])

    session_key = os.urandom(32)
    alice.key_manager.store_key(alice.current_conversation_id, session_key, epoch=1)
    bob.key_manager.store_key(bob.current_conversation_id, session_key, epoch=1)

    alice.send_chat_message("i am unverified but this still verifies")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "i am unverified but this still verifies"
            for summary in bob.conversation_store.get_all()
        )
    )

    # Still not VERIFIED -- message authentication never promotes trust
    # state; only explicit human confirm_peer_verification() does.
    assert bob.get_peer_verification_state(alice_payload["username"]) != "VERIFIED"


def test_message_from_verified_peer_is_accepted(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    _mutual_verify(alice, bob, alice_payload["username"], bob_payload["username"])

    fingerprint = fingerprint_combined_identity(
        alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
    )
    bob.confirm_combined_peer_verification(alice_payload["username"], fingerprint)
    assert bob.get_peer_verification_state(alice_payload["username"]) == "VERIFIED"

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("verified and signed")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "verified and signed"
            for summary in bob.conversation_store.get_all()
        )
    )


# ========================================================================
# Group messaging
# ========================================================================


def test_group_message_real_end_to_end_signing_and_verification(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")
    charlie_payload = app["register"]("charlie_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    charlie = app["launch"](charlie_payload)

    for a, b in ((alice, bob), (alice, charlie), (bob, charlie)):
        assert _wait_for(lambda a=a, b=b: a.key_manager.get_public_key(b.username) is not None)
        assert _wait_for(lambda a=a, b=b: b.key_manager.get_public_key(a.username) is not None)

    # _distribute_group_key() -- the real ClientSession group-key-
    # distribution path -- skips any recipient who is not VERIFIED
    # (see client/session.py, _peer_key_is_verified() check), the same
    # pre-existing Stage-3 rule as direct messaging's establish_
    # session_key() gate. All three members must mutually verify each
    # other for every member to actually receive the group key.
    for a, b in ((alice, bob), (alice, charlie), (bob, charlie)):
        a_fp = fingerprint_combined_identity(
            b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key()
        )
        a.confirm_combined_peer_verification(b.username, a_fp)
        b_fp = fingerprint_combined_identity(
            a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key()
        )
        b.confirm_combined_peer_verification(a.username, b_fp)

    alice.create_group_conversation(
        "Signed Group", [bob_payload["username"], charlie_payload["username"]]
    )

    assert _wait_for(
        lambda: any(
            s.is_group and s.group_name == "Signed Group"
            for s in alice.conversation_store.get_all()
        )
    )
    group_summary = next(
        s for s in alice.conversation_store.get_all()
        if s.is_group and s.group_name == "Signed Group"
    )
    conversation_id = group_summary.conversation_id

    assert _wait_for(
        lambda: bob.key_manager.has_key(conversation_id)
        and charlie.key_manager.has_key(conversation_id)
    )

    alice.set_current_chat(group_summary)
    alice.send_chat_message("hello group, this is really alice")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "hello group, this is really alice"
            for summary in bob.conversation_store.get_all()
        )
    )
    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "hello group, this is really alice"
            for summary in charlie.conversation_store.get_all()
        )
    )


# ========================================================================
# Offline messaging
# ========================================================================


def test_offline_message_signature_survives_queue_and_delivery(app, monkeypatch):
    """
    1. Alice sends a signed encrypted message.
    2. Bob is offline.
    3. Message is stored/queued (server persistence).
    4. Bob reconnects.
    5. Message is delivered (existing recovery mechanism).
    6. Bob verifies the ML-DSA signature.
    7. Bob decrypts and displays it.

    The signature travels with the message through offline storage --
    the server never needs, and never gets, the ML-DSA private key.
    """

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    _mutual_verify(alice, bob, alice_payload["username"], bob_payload["username"])

    _open_direct(alice, bob_payload["username"])
    # Establish the conversation/key while Bob is online, then take him
    # offline -- isolates "message signing survives the offline queue"
    # from "key establishment while offline", which is already covered
    # by tests/test_offline_messaging.py.
    alice.send_chat_message("priming the conversation key")
    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "priming the conversation key"
            for summary in bob.conversation_store.get_all()
        )
    )

    bob.disconnect()
    time.sleep(0.3)

    alice.send_chat_message("queued while bob is offline, still signed")

    bob_again = app["launch"](bob_payload)

    # A previously-queued message is not live-pushed through
    # handle_chat() on reconnect -- it is retrieved via history loading
    # (message_history_request/result), exactly the established
    # pattern in tests/test_offline_messaging.py. This is also where
    # _verify_history_message_signature() actually runs for this
    # message: the signature travels with it from send time, through
    # server-side persistence (messages.message_signature), to this
    # verification, unmodified and never needing the private key.
    _open_direct(bob_again, alice_payload["username"])

    def _delivered_text():
        history = bob_again.load_conversation_history(
            alice_payload["username"], is_group=False
        )
        received = [row["text"] for row in history if not row["is_own"]]
        return "queued while bob is offline, still signed" in received

    assert _wait_for(_delivered_text)
