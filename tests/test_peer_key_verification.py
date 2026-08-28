"""
Server-Untrusted Identity Verification, Stage 2 -- client/session.py
integration.

Stage 1 (storage/secure_key_store.py, crypto/key_manager.py) built the
mechanism: a deterministic fingerprint helper and an encrypted local
store distinguishing UNVERIFIED from explicitly VERIFIED peer keys,
with VERIFIED protected from silent overwrite. Stage 2 wires that
mechanism into the ONE place every peer public key this client will
ever use already passes through: ClientSession.handle_public_key().

The security property this file proves: a public key relayed by the
server is NOT automatically trusted merely because the server says it
belongs to a given username. If this user has previously, explicitly
VERIFIED a peer's fingerprint (through the Stage-1 storage API -- the
GUI verification action itself is Stage 3, not yet implemented), a
DIFFERENT key later relayed for that same username is detected,
flagged (KEY_CHANGED), and never silently trusted or persisted over
the verified record -- regardless of whether that different key is
relayed by a genuinely compromised server or (as simulated in the
tests below) hand-crafted to look like one.

What this stage does NOT yet provide (see the project's own design
report): protection against a malicious server at the VERY FIRST
contact with a peer, before any explicit verification has ever
happened. That gap is deliberately left for Stage 3's user-facing
verification workflow -- these tests do not claim otherwise.

The cryptographic path itself (ML-KEM-768 -> shared secret ->
AES-256-GCM) is untouched; these tests never assert on message
content, only on the new peer-verification state layered beside it.

Fixture conventions mirror tests/test_key_store_persistence.py's
`app` fixture (a real authenticate_credentials() launch, which is
what actually unlocks the encrypted local key store this mechanism
depends on) -- the lighter `connect()`-only pattern used elsewhere in
this suite deliberately never unlocks a key store, so it cannot
exercise this feature at all (verified directly: existing tests using
that pattern pass unchanged, proving the integration is a true no-op
without one).

Run with:
    pytest tests/test_peer_key_verification.py -v
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
from client.session import ClientSession, PEER_KEY_STATE_CHANGED, PeerNotVerifiedError
from crypto.key_manager import KeyManager, fingerprint_public_key
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED
from tests.tls_test_support import start_test_server
from utils.protocol import create_public_key_packet

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


# ----------------------------------------------------------------------
# Account / session helpers -- app fixture matches
# tests/test_key_store_persistence.py exactly, since that is the one
# already-established pattern that unlocks a real, isolated key store.
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Peer Key Verification Test",
            "username": f"pkv_{hint}{suffix}",
            "email": f"pkv_{hint}{suffix}@example.com",
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


def _wait_for(predicate, attempts=150, interval=0.05):
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
def app(running_server, monkeypatch, tmp_path):
    """Real application sessions with a real, isolated, on-disk
    encrypted key store -- required, since the mechanism under test
    lives entirely inside it."""

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

        # UI Finalization -- Login Identifier: phone number, not username,
        # is what authenticate_credentials() now authenticates with.
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


def _open_direct(session, partner):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=partner,
            is_online=True,
            latest_message=None,
        )
    )


def _fake_public_key_packet(username, algorithm, fake_key_text):
    return create_public_key_packet(
        username=username,
        algorithm=algorithm,
        public_key=fake_key_text,
    )


def _wire_text(key_manager_public_key_bytes):
    """The exact str shape ClientSession.send_public_key() puts on the
    wire (see client/session.py) -- KeyManager.public_key is bytes."""

    return key_manager_public_key_bytes.decode("utf-8")


def _a_different_but_genuinely_valid_public_key():
    """
    A different, but structurally VALID public key -- an attacker's
    own real Kyber (or RSA) keypair, exactly as realistic an adversary
    would actually have, rather than a malformed/truncated string.

    This matters: a malformed key is rejected by KeyManager.
    add_public_key() -> import_public_key() BEFORE
    _evaluate_peer_key_verification() ever runs (see
    ClientSession.handle_public_key()), so testing the KEY_CHANGED
    path specifically requires a key that passes that same validation
    -- otherwise the test would only prove "malformed keys are
    rejected" (already covered by tests/test_public_key_validation.py),
    not the property this file exists to prove.
    """

    return _wire_text(KeyManager().public_key)


# ----------------------------------------------------------------------
# A/B/C -- first-ever observation: UNVERIFIED, persisted, never
# auto-VERIFIED
# ----------------------------------------------------------------------


def test_first_observed_peer_key_becomes_unverified_and_is_persisted(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    entry = alice.key_store.get_peer_verification(bob_payload["username"])

    assert entry["state"] == PEER_STATE_UNVERIFIED
    assert entry["fingerprint"] == fingerprint_public_key(bob.key_manager.public_key)

    # Not automatically VERIFIED -- the explicit, separate assertion
    # requirement C calls for.
    assert alice.get_peer_verification_state(bob_payload["username"]) != PEER_STATE_VERIFIED


def test_first_observed_fingerprint_survives_a_reload(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    expected_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.disconnect()

    alice_again = app["launch"](alice_payload)

    entry = alice_again.key_store.get_peer_verification(bob_payload["username"])

    assert entry == {"fingerprint": expected_fingerprint, "state": PEER_STATE_UNVERIFIED}


# ----------------------------------------------------------------------
# D -- matching a verified fingerprint stays VERIFIED
# ----------------------------------------------------------------------


def test_matching_key_stays_verified(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    assert alice.get_peer_verification_state(bob_payload["username"]) == PEER_STATE_VERIFIED

    # Bob's key arrives again (e.g. a group key distribution touching
    # the same cached identity key) -- still the same, real key.
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm, bob.key_manager.public_key
        )
    )

    assert alice.get_peer_verification_state(bob_payload["username"]) == PEER_STATE_VERIFIED
    assert alice.key_store.get_peer_verification(bob_payload["username"])["fingerprint"] == (
        real_fingerprint
    )


# ----------------------------------------------------------------------
# I -- reconnecting with the same verified key: no false KEY_CHANGED
# ----------------------------------------------------------------------


def test_reconnecting_with_the_same_verified_key_does_not_flag_a_change(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    bob.disconnect()
    time.sleep(0.3)

    # Bob reconnects -- a genuinely FRESH ClientSession would normally
    # generate a new Kyber identity keypair (see the project's own
    # security audit of this exact behavior); here Bob deliberately
    # keeps the SAME KeyManager, to isolate "reconnect with the same
    # key" from "reconnect with a rotated key" (covered separately by
    # the KEY_CHANGED tests below).
    bob_again = ClientSession()
    bob_again.key_manager = bob.key_manager
    bob_again.user_id = bob_payload["user_id"]
    bob_again.access_token = bob.access_token
    bob_again.connect()
    bob_again.login(bob_payload["username"])
    bob_again.send_public_key()
    bob_again.start_receiver()

    try:
        assert _wait_for(
            lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
        )

        assert alice.get_peer_verification_state(bob_payload["username"]) == (
            PEER_STATE_VERIFIED
        )
        assert bob_payload["username"] not in alice._peer_keys_changed
    finally:
        bob_again.disconnect()


# ----------------------------------------------------------------------
# E/F/G/H -- the critical case: a mismatched key against a VERIFIED
# fingerprint
# ----------------------------------------------------------------------


def test_mismatched_key_against_verified_produces_key_changed_without_overwriting(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    verify_calls = []
    original_verify = alice.key_store.verify_peer_fingerprint
    alice.key_store.verify_peer_fingerprint = lambda *a, **kw: (
        verify_calls.append((a, kw)) or original_verify(*a, **kw)
    )

    changed_signals = []
    alice.peer_key_changed.connect(lambda username: changed_signals.append(username))

    fake_key = _a_different_but_genuinely_valid_public_key()
    assert fake_key != _wire_text(bob.key_manager.public_key)  # sanity

    alice.handle_public_key(
        _fake_public_key_packet(bob_payload["username"], bob.key_manager.algorithm, fake_key)
    )

    # E -- KEY_CHANGED state.
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )
    assert changed_signals == [bob_payload["username"]]

    # F/H -- the verified fingerprint is untouched and still retrievable.
    entry = alice.key_store.get_peer_verification(bob_payload["username"])
    assert entry == {"fingerprint": real_fingerprint, "state": PEER_STATE_VERIFIED}

    # G -- verify_peer_fingerprint() was never called automatically
    # (the one call above was Alice's own explicit pre-test setup,
    # captured before the mismatch, not triggered by it).
    assert verify_calls == []


def test_key_changed_does_not_promote_the_fake_key(app):
    """The fake key itself must never become associated with any
    VERIFIED state -- confirmed by fingerprint value, not just state
    name, so a bug that verified the WRONG fingerprint would still be
    caught."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    fake_key = _a_different_but_genuinely_valid_public_key()
    fake_fingerprint = fingerprint_public_key(fake_key)

    alice.handle_public_key(
        _fake_public_key_packet(bob_payload["username"], bob.key_manager.algorithm, fake_key)
    )

    entry = alice.key_store.get_peer_verification(bob_payload["username"])

    assert entry["fingerprint"] != fake_fingerprint
    assert entry["fingerprint"] == real_fingerprint
    assert alice.key_store.fingerprint_matches_verified(
        bob_payload["username"], fake_fingerprint
    ) is False


# ----------------------------------------------------------------------
# J -- multiple peers stay isolated
# ----------------------------------------------------------------------


def test_one_peers_key_change_does_not_affect_another_peer(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")
    charlie_payload = app["register"]("charlie_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    charlie = app["launch"](charlie_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )
    assert _wait_for(
        lambda: alice.key_manager.get_public_key(charlie_payload["username"]) is not None
    )

    bob_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    charlie_fingerprint = fingerprint_public_key(charlie.key_manager.public_key)

    alice.key_store.verify_peer_fingerprint(bob_payload["username"], bob_fingerprint)
    alice.key_store.verify_peer_fingerprint(charlie_payload["username"], charlie_fingerprint)

    fake_bob_key = _a_different_but_genuinely_valid_public_key()

    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm, fake_bob_key
        )
    )

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )
    assert alice.get_peer_verification_state(charlie_payload["username"]) == (
        PEER_STATE_VERIFIED
    )
    assert alice.key_store.get_peer_verification(charlie_payload["username"]) == {
        "fingerprint": charlie_fingerprint,
        "state": PEER_STATE_VERIFIED,
    }


# ----------------------------------------------------------------------
# M -- restart preserves VERIFIED across a genuine reload
# ----------------------------------------------------------------------


def test_verified_state_and_key_changed_flag_behave_correctly_across_restart(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    alice.disconnect()

    alice_again = app["launch"](alice_payload)

    # KEY_CHANGED is session-local -- a fresh session must never carry
    # a stale flag forward; VERIFIED, being persisted, must survive.
    assert bob_payload["username"] not in alice_again._peer_keys_changed
    assert alice_again.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_VERIFIED
    )
    assert alice_again.key_store.get_peer_verification(bob_payload["username"]) == {
        "fingerprint": real_fingerprint,
        "state": PEER_STATE_VERIFIED,
    }


# ----------------------------------------------------------------------
# Section 8 -- the essential security-property test: a malicious
# server substituting a different key for an already-verified peer
# ----------------------------------------------------------------------


def test_malicious_server_key_substitution_is_detected_and_not_trusted(app):
    """
    1. Bob has a genuine ML-KEM public key.
    2. Alice receives Bob's key.
    3. Alice explicitly verifies Bob's fingerprint (Stage-1 API).
    4. Alice: Bob -> VERIFIED -> fingerprint_A.
    5/6. A malicious server relays a DIFFERENT ("fake") ML-KEM public
       key under Bob's username -- simulated here by feeding
       handle_public_key() a hand-crafted packet, exactly the
       trust boundary a compromised server actually controls: this
       client has no way to distinguish that from a genuine relay.
    7. The fake fingerprint differs from fingerprint_A.

    Verified: state becomes KEY_CHANGED; fingerprint_A remains stored;
    fingerprint_A is not replaced; the fake key does not become
    VERIFIED; no automatic verification occurs.
    """

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    # 1/2.
    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    # 3/4.
    fingerprint_a = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], fingerprint_a)
    assert alice.get_peer_verification_state(bob_payload["username"]) == PEER_STATE_VERIFIED

    # 5/6 -- the malicious substitution: a different, but genuinely
    # valid, Kyber public key -- an attacker's own real keypair,
    # exactly what a compromised server actually has available to
    # relay (a malformed key would simply be rejected by existing
    # D6.5 input validation before ever reaching this mechanism -- see
    # _a_different_but_genuinely_valid_public_key()'s docstring).
    malicious_key = _a_different_but_genuinely_valid_public_key()

    # 7 -- sanity: genuinely a different fingerprint.
    fake_fingerprint = fingerprint_public_key(malicious_key)
    assert fake_fingerprint != fingerprint_a

    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm, malicious_key
        )
    )

    # state becomes KEY_CHANGED
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )

    # fingerprint_A remains stored, is not replaced, and the fake key
    # never becomes VERIFIED.
    entry = alice.key_store.get_peer_verification(bob_payload["username"])
    assert entry["state"] == PEER_STATE_VERIFIED
    assert entry["fingerprint"] == fingerprint_a
    assert entry["fingerprint"] != fake_fingerprint

    # no automatic verification of the fake key occurred.
    assert alice.key_store.fingerprint_matches_verified(
        bob_payload["username"], fake_fingerprint
    ) is False


# ----------------------------------------------------------------------
# ENFORCEMENT (post-audit fix): KEY_CHANGED must not just be detected
# -- the substituted key must never reach KeyManager, and must never
# be usable for any cryptographic operation.
# ----------------------------------------------------------------------


def test_malicious_key_is_never_inserted_into_key_manager(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_key_object = alice.key_manager.get_public_key(bob_payload["username"])
    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    malicious_key = _a_different_but_genuinely_valid_public_key()

    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm, malicious_key
        )
    )

    # get_public_key() still returns the trusted K1 -- not merely "a
    # key with the right fingerprint", but the EXACT object that was
    # cached before the attack, proving add_public_key() never ran.
    assert alice.key_manager.get_public_key(bob_payload["username"]) is real_key_object


def test_wrap_key_for_member_cannot_use_the_malicious_key(app):
    """The core proof: wrap_key_for_member() -- called by
    establish_session_key() and by handle_direct_key_redelivery_
    required() alike -- must wrap under the TRUSTED key, so an
    attacker holding only the malicious key's private half can never
    unwrap what it produces."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    attacker = KeyManager()
    malicious_key = _wire_text(attacker.public_key)

    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm, malicious_key
        )
    )
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )

    arbitrary_session_key = os.urandom(32)
    encapsulation, wrapped_key = alice.key_manager.wrap_key_for_member(
        bob_payload["username"], arbitrary_session_key
    )

    # Bob (the real, trusted party) can still unwrap it correctly --
    # proving it really was wrapped under HIS key, not the attacker's.
    recovered_by_bob = bob.key_manager.unwrap_received_key(encapsulation, wrapped_key)
    assert recovered_by_bob == arbitrary_session_key

    # The attacker, holding only their own substituted keypair's
    # private half, cannot unwrap it at all.
    with pytest.raises((ValueError, TypeError)):
        attacker.unwrap_received_key(encapsulation, wrapped_key)


def test_direct_key_redelivery_required_does_not_leak_to_the_malicious_key(app):
    """The exact attack the security audit proved: a malicious server
    substitutes Bob's key, then sends a direct_key_redelivery_required
    packet for an ALREADY-established conversation.

    Historical note: this test originally asserted that the redelivery
    mechanism kept working -- wrapping under the still-trusted K1 --
    while the peer was KEY_CHANGED. That was correct under Stage 2
    alone. Server-Untrusted Identity Verification, Stage 3 (approved
    after this test was written) deliberately makes this stricter,
    per an explicit mandatory decision: KEY_CHANGED blocks ALL
    protected communication, including continuing to use the old,
    still-valid K1, until the user explicitly re-verifies. Continuing
    to redeliver via K1 while an unresolved security alert is active
    would undermine the point of surfacing that alert at all. This
    test now proves the stricter, current guarantee: NOTHING is sent
    at all while KEY_CHANGED -- not a leak to the attacker (Stage 2's
    original property, still fully true, now trivially so since there
    is nothing to intercept), and not even a delivery to the real
    Bob."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("established before the attack")
    conversation_id = alice.current_conversation_id
    real_session_key = alice.key_manager.get_key(conversation_id)
    epoch = alice.key_manager.current_epoch(conversation_id)

    attacker = KeyManager()
    malicious_key = _wire_text(attacker.public_key)

    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm, malicious_key
        )
    )
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    client_session_module.send_message = recording_send_message
    try:
        # The server-triggered redelivery packet -- exactly what a
        # malicious server would send to try to harvest the key.
        alice.handle_direct_key_redelivery_required({
            "conversation_id": conversation_id,
            "epoch": epoch,
            "recipient": bob_payload["username"],
        })
    finally:
        client_session_module.send_message = real_send_message

    distributed = [p for p in sent_packets if p.get("type") == "group_key_distribution"]
    assert len(distributed) == 0, (
        "Stage 3: KEY_CHANGED must block ALL protected communication, "
        "including redelivery via the still-trusted old key, until "
        "the user explicitly re-verifies"
    )

    # The attacker gains nothing (Stage 2's original property, still
    # true): there is no packet to intercept, so their substituted
    # private key has nothing to unwrap.
    real_key_still_active = alice.key_manager.get_public_key(
        bob_payload["username"]
    )
    assert real_key_still_active is not None
    assert real_key_still_active != attacker.kyber.encapsulation_key

    # And the real, already-established session key is untouched and
    # still exactly what it was before the attack -- KEY_CHANGED does
    # not corrupt or discard it, it only withholds it from delivery.
    assert alice.key_manager.get_key(conversation_id) == real_session_key


def test_legitimate_matching_key_behavior_is_unaffected_by_the_fix(app):
    """Preserve existing behavior for the common case: a VERIFIED
    peer's key arriving again, unchanged, must still update KeyManager
    normally and stay VERIFIED -- the fix must not make ordinary,
    non-attack traffic newly fail."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    real_fingerprint = fingerprint_public_key(bob.key_manager.public_key)
    alice.key_store.verify_peer_fingerprint(bob_payload["username"], real_fingerprint)

    # Bob's real key arrives again (e.g. a group key distribution
    # event re-touching the same cached identity key).
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm,
            _wire_text(bob.key_manager.public_key),
        )
    )

    assert alice.get_peer_verification_state(bob_payload["username"]) == PEER_STATE_VERIFIED
    assert alice.key_manager.get_public_key(bob_payload["username"]) is not None

    # And it is genuinely usable -- establish_session_key() still
    # works normally for a brand new conversation with Bob.
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("still works after the fix")

    assert _wait_for(
        lambda: any(
            summary.latest_message and summary.latest_message.text == "still works after the fix"
            for summary in bob.conversation_store.get_all()
        )
    )


def test_first_contact_unverified_key_reception_is_unaffected_by_the_fix(app):
    """The Stage-2 fix (_is_verified_key_mismatch()) must never block a
    first-contact (never-verified) peer's key from being RECEIVED and
    cached -- it must return False whenever there is nothing VERIFIED
    to compare against, exactly as before.

    Historical note: this test originally also asserted that sending a
    protected message to this still-UNVERIFIED peer succeeded --
    correct under Stage 2 alone, whose scope stopped at "detect and
    protect an already-VERIFIED key." Server-Untrusted Identity
    Verification, Stage 3 (approved after this test was written)
    deliberately and explicitly changes that: an UNVERIFIED peer's key
    must no longer be usable for protected communication at all (see
    ClientSession.establish_session_key()'s Stage-3 gate, and
    test_first_contact_key_reception_does_not_grant_protected_
    communication below, which is what now covers that half). This
    test keeps proving only the half that is still true: reception and
    caching of a first-contact key remain completely unaffected."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    assert alice.key_manager.get_public_key(bob_payload["username"]) is not None


def test_first_contact_key_reception_does_not_grant_protected_communication(app):
    """Server-Untrusted Identity Verification, Stage 3: the other half
    of what the renamed test above used to assert -- and now
    explicitly no longer does. An UNVERIFIED first-contact peer's
    key is received and cached (proven above), but must NOT be usable
    to establish protected communication: establish_session_key()
    must raise PeerNotVerifiedError, and no message may reach the
    server or the recipient as a result."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    _open_direct(alice, bob_payload["username"])

    with pytest.raises(PeerNotVerifiedError):
        alice.send_chat_message("must not be sent while unverified")

    # Bob never receives anything -- the block is real, not cosmetic.
    assert not any(
        summary.latest_message
        and summary.latest_message.text == "must not be sent while unverified"
        for summary in bob.conversation_store.get_all()
    )

    # Still UNVERIFIED afterward -- a blocked send must never itself
    # change verification state in either direction.
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_UNVERIFIED
    )
