"""
Server-Untrusted Identity Verification, Stage 3 -- first-contact
identity verification, verification UI, and enforcement of trust
state.

Stage 1 (storage/secure_key_store.py, crypto/key_manager.py) built the
mechanism: a deterministic fingerprint helper and an encrypted local
store distinguishing UNVERIFIED from explicitly VERIFIED peer keys.
Stage 2 (client/session.py::handle_public_key()) made a VERIFIED key
tamper-evident: a server-substituted replacement is detected
(KEY_CHANGED) and never silently trusted. Stage 2.5 made the LOCAL
user's own ML-KEM keypair persist across logins, so a VERIFIED
fingerprint stays meaningful over time.

None of that closed the actual first-contact gap: a never-verified
peer's key was still fully usable for real cryptographic operations
(establish_session_key(), wrap_key_for_member(), automatic key
redelivery, group key distribution) -- UNVERIFIED was informational
only. Stage 3 closes it:

    UNVERIFIED  -> protected direct/group key establishment BLOCKED
    VERIFIED    -> normal communication allowed
    KEY_CHANGED -> protected communication BLOCKED using ANY key
                   (including the old, still-genuinely-trusted one)
                   until the user explicitly re-verifies

Enforcement lives entirely in ClientSession (establish_session_key(),
handle_direct_key_redelivery_required(), _distribute_group_key()) --
never in crypto/key_manager.py, never in the GUI. verify_peer_
fingerprint() (the only method that ever sets VERIFIED, unchanged
since Stage 1) is called ONLY by ClientSession.confirm_peer_
verification(), which is itself called ONLY by gui/verify_identity_
dialog.py's explicit confirm action -- the GUI is presentation and
user-confirmation control only.

This file tests items A-S of the Stage-3 test matrix plus the
malicious-server first-contact attack scenario. Existing Stage 1/2/2.5
tests are untouched by this file; two pre-existing Stage-2 tests in
tests/test_peer_key_verification.py were updated (not weakened) to
reflect this stage's explicit, approved policy change -- see that
file's own updated docstrings for exactly what changed and why.

Run with:
    pytest tests/test_first_contact_verification.py -v
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
from client.session import ClientSession, PEER_KEY_STATE_CHANGED, PeerNotVerifiedError
from crypto.key_manager import KeyManager, fingerprint_public_key
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from gui.verify_identity_dialog import VerifyIdentityDialog
from storage.secure_key_store import (
    KeyStoreError,
    PEER_STATE_UNVERIFIED,
    PEER_STATE_VERIFIED,
)
from tests.tls_test_support import start_test_server
from utils.protocol import create_public_key_packet

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


# ----------------------------------------------------------------------
# Account / session helpers -- same established pattern as
# tests/test_peer_key_verification.py and tests/test_own_kyber_keypair_
# persistence.py: a self-contained app fixture using username-based
# auth, isolated from the separate, unrelated, uncommitted
# phone-number-login feature's changes elsewhere in the working tree.
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "First Contact Verification Test",
            "username": f"fcv_{hint}{suffix}",
            "email": f"fcv_{hint}{suffix}@example.com",
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
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr(
        "storage.secure_key_store.KEY_STORE_DIR", tmp_path / "keystore"
    )

    opened = []
    created = []

    def _launch(payload, password=PASSWORD, send_key=True, start_receiving=True):
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
        if send_key:
            session.send_public_key()
        if start_receiving:
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


def _verify(alice, bob, bob_session):
    """Simulates a successful, explicit, out-of-band-confirmed
    verification -- exactly what VerifyIdentityDialog does internally
    on a confirming click, called directly here so tests can set up
    a VERIFIED baseline without a real dialog interaction."""

    fingerprint = alice.get_peer_fingerprint_for_verification(bob)
    assert fingerprint == fingerprint_public_key(bob_session.key_manager.public_key)
    alice.confirm_peer_verification(bob, fingerprint)


def _fake_public_key_packet(username, algorithm, fake_key_text):
    return create_public_key_packet(
        username=username, algorithm=algorithm, public_key=fake_key_text
    )


def _wire_text(key_manager_public_key_bytes):
    return key_manager_public_key_bytes.decode("utf-8")


# ----------------------------------------------------------------------
# A -- first contact -> UNVERIFIED
# ----------------------------------------------------------------------


def test_a_first_contact_becomes_unverified(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )


# ----------------------------------------------------------------------
# B -- first contact cannot establish a protected session before
# verification
# ----------------------------------------------------------------------


def test_b_first_contact_cannot_establish_protected_session(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    _open_direct(alice, bob_payload["username"])

    with pytest.raises(PeerNotVerifiedError) as excinfo:
        alice.send_chat_message("blocked before verification")

    assert excinfo.value.username == bob_payload["username"]
    assert excinfo.value.state == PEER_STATE_UNVERIFIED

    assert not any(
        summary.latest_message
        and summary.latest_message.text == "blocked before verification"
        for summary in bob.conversation_store.get_all()
    )


# ----------------------------------------------------------------------
# C/D/E -- verification outcomes for a first-contact UNVERIFIED peer
# ----------------------------------------------------------------------


def test_c_correct_fingerprint_becomes_verified(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    _verify(alice, bob_payload["username"], bob)

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_VERIFIED
    )


def test_d_confirming_a_wrong_fingerprint_still_verifies_it(app):
    """confirm_peer_verification() is a faithful, unconditional
    pass-through to SecureKeyStore.verify_peer_fingerprint() -- it
    performs no independent comparison of its own. The security
    property "a wrong fingerprint never gets confirmed" therefore does
    NOT rest on a check at this layer; it rests entirely on the UI
    never calling this method with anything except the exact,
    unmodified value it displayed and the user compared out-of-band
    (see test_s_dialog_never_calls_verify_without_explicit_confirm and
    VerifyIdentityDialog's own docstring). This test makes that
    boundary explicit rather than leaving it implicit."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    wrong_fingerprint = "0000 0000 0000 0000"
    alice.confirm_peer_verification(bob_payload["username"], wrong_fingerprint)

    entry = alice.key_store.get_peer_verification(bob_payload["username"])
    assert entry == {"fingerprint": wrong_fingerprint, "state": PEER_STATE_VERIFIED}


def test_e_cancel_leaves_peer_unverified(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    dialog = VerifyIdentityDialog(
        alice, bob_payload["username"], PEER_STATE_UNVERIFIED
    )
    dialog.reject()  # Cancel -- handle_confirm() is never invoked.

    assert dialog.was_verified() is False
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_UNVERIFIED
    )


# ----------------------------------------------------------------------
# F/G -- a VERIFIED peer communicates normally and survives restart
# ----------------------------------------------------------------------


def test_f_verified_peer_communicates_normally(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    _verify(alice, bob_payload["username"], bob)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("verified and working")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "verified and working"
            for summary in bob.conversation_store.get_all()
        )
    )


def test_g_verified_peer_survives_restart(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    _verify(alice, bob_payload["username"], bob)
    alice.disconnect()

    alice_again = app["launch"](alice_payload)

    assert alice_again.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_VERIFIED
    )

    _open_direct(alice_again, bob_payload["username"])
    alice_again.send_chat_message("still verified after restart")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "still verified after restart"
            for summary in bob.conversation_store.get_all()
        )
    )


# ----------------------------------------------------------------------
# H/I -- malicious key replacement -> KEY_CHANGED blocks everything
# ----------------------------------------------------------------------


def test_h_malicious_key_replacement_produces_key_changed(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    _verify(alice, bob_payload["username"], bob)

    attacker = KeyManager()
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm,
            _wire_text(attacker.public_key),
        )
    )

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )


def test_i_key_changed_blocks_all_protected_communication_not_just_the_new_key(app):
    """The mandatory Stage-3 decision: KEY_CHANGED blocks protected
    communication entirely, including continuing to use the OLD,
    still-genuinely-trusted K1 -- not only blocking the substituted
    K2 (which Stage 2 already guaranteed on its own)."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    _verify(alice, bob_payload["username"], bob)

    attacker = KeyManager()
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm,
            _wire_text(attacker.public_key),
        )
    )
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )

    # K1 (Bob's real key) is STILL what KeyManager holds -- Stage 2's
    # guarantee, unaffected -- but Stage 3 now refuses to use even
    # this genuinely trusted key until the user resolves the alert.
    assert alice.key_manager.get_public_key(bob_payload["username"]) is not None
    assert alice.key_manager.get_public_key(bob_payload["username"]) != (
        attacker.kyber.encapsulation_key
    )

    _open_direct(alice, bob_payload["username"])

    with pytest.raises(PeerNotVerifiedError) as excinfo:
        alice.send_chat_message("must not send while KEY_CHANGED")

    assert excinfo.value.state == PEER_KEY_STATE_CHANGED

    assert not any(
        summary.latest_message
        and summary.latest_message.text == "must not send while KEY_CHANGED"
        for summary in bob.conversation_store.get_all()
    )


# ----------------------------------------------------------------------
# J/K/L -- re-verification outcomes from KEY_CHANGED
# ----------------------------------------------------------------------


def test_j_correct_reverification_becomes_verified_again(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    _verify(alice, bob_payload["username"], bob)

    attacker = KeyManager()
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm,
            _wire_text(attacker.public_key),
        )
    )
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )

    # get_peer_fingerprint_for_verification() must now surface the
    # NEW (rejected) key's fingerprint, not Bob's still-VERIFIED old
    # one -- that is what the user is meant to compare/confirm here.
    pending_fingerprint = alice.get_peer_fingerprint_for_verification(
        bob_payload["username"]
    )
    assert pending_fingerprint == fingerprint_public_key(attacker.public_key)
    assert pending_fingerprint != fingerprint_public_key(bob.key_manager.public_key)

    alice.confirm_peer_verification(bob_payload["username"], pending_fingerprint)

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_VERIFIED
    )
    assert alice.key_store.get_peer_verification(bob_payload["username"]) == {
        "fingerprint": pending_fingerprint,
        "state": PEER_STATE_VERIFIED,
    }


def test_k_wrong_reverification_still_verifies_the_value_passed(app):
    """Mirrors test_d_confirming_a_wrong_fingerprint_still_verifies_it
    for the KEY_CHANGED case -- confirm_peer_verification() performs
    no comparison, here either; correctness rests entirely on the
    dialog only ever passing back the exact value it displayed."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    _verify(alice, bob_payload["username"], bob)

    attacker = KeyManager()
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm,
            _wire_text(attacker.public_key),
        )
    )
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )

    wrong_fingerprint = "1111 2222 3333 4444"
    alice.confirm_peer_verification(bob_payload["username"], wrong_fingerprint)

    entry = alice.key_store.get_peer_verification(bob_payload["username"])
    assert entry == {"fingerprint": wrong_fingerprint, "state": PEER_STATE_VERIFIED}


def test_l_cancel_reverification_leaves_peer_key_changed(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )
    _verify(alice, bob_payload["username"], bob)

    attacker = KeyManager()
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], bob.key_manager.algorithm,
            _wire_text(attacker.public_key),
        )
    )
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )

    dialog = VerifyIdentityDialog(
        alice, bob_payload["username"], PEER_KEY_STATE_CHANGED
    )
    dialog.reject()

    assert dialog.was_verified() is False
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_KEY_STATE_CHANGED
    )


# ----------------------------------------------------------------------
# M/N/O -- offline first contact interacting with verification
# ----------------------------------------------------------------------


def test_m_offline_peer_with_no_key_message_remains_deferred(app):
    """A peer whose key has never even arrived is NOT the same thing
    as UNVERIFIED -- this must behave exactly as it did before Stage
    3: no exception, the message is generated/stored locally, delivery
    is simply deferred."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)

    assert alice.key_manager.get_public_key(bob_payload["username"]) is None
    assert alice.get_peer_verification_state(bob_payload["username"]) is None

    _open_direct(alice, bob_payload["username"])

    # Must NOT raise -- this is the preserved offline-first-contact path.
    alice.send_chat_message("queued while bob is offline")

    conversation_id = alice.current_conversation_id
    assert alice.key_manager.has_key(conversation_id)


def test_n_offline_peer_key_arrives_becomes_unverified(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("queued while bob is offline")

    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )


def test_o_after_verification_deferred_delivery_can_proceed(app):
    """The full offline-first-contact + Stage-3 lifecycle: a message
    sent while Bob is offline stays queued; once Bob's key arrives he
    is UNVERIFIED (Stage 3 correctly still blocks automatic
    redelivery -- see test_q); only after Alice explicitly verifies
    him does a subsequent redelivery attempt actually succeed."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)

    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("queued while bob is offline")
    conversation_id = alice.current_conversation_id
    real_session_key = alice.key_manager.get_key(conversation_id)
    epoch = alice.key_manager.current_epoch(conversation_id)

    bob = app["launch"](bob_payload, send_key=False, start_receiving=False)
    bob.send_public_key()

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    # Still UNVERIFIED -> redelivery correctly refuses (test_q proves
    # this precisely; here we only need it to NOT have delivered yet).
    alice.handle_direct_key_redelivery_required({
        "conversation_id": conversation_id,
        "epoch": epoch,
        "recipient": bob_payload["username"],
    })
    assert bob.key_manager.get_key(conversation_id) is None

    _verify(alice, bob_payload["username"], bob)

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    client_session_module.send_message = recording_send_message
    try:
        alice.handle_direct_key_redelivery_required({
            "conversation_id": conversation_id,
            "epoch": epoch,
            "recipient": bob_payload["username"],
        })
    finally:
        client_session_module.send_message = real_send_message

    distributed = [p for p in sent_packets if p.get("type") == "group_key_distribution"]
    assert len(distributed) == 1

    recovered = bob.key_manager.unwrap_received_key(
        distributed[0]["encapsulation"], distributed[0]["wrapped_key"]
    )
    assert recovered == real_session_key


# ----------------------------------------------------------------------
# P -- group messaging obeys the same verification policy
# ----------------------------------------------------------------------


def test_p_group_key_distribution_skips_unverified_members_only(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")
    charlie_payload = app["register"]("charlie_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    charlie = app["launch"](charlie_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
        and alice.get_peer_verification_state(charlie_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    # Alice verifies Bob, but never verifies Charlie.
    _verify(alice, bob_payload["username"], bob)
    assert alice.get_peer_verification_state(charlie_payload["username"]) == (
        PEER_STATE_UNVERIFIED
    )

    # A REAL, server-authorized group -- handle_group_key_distribution()
    # requires the sender to be an actual DB member of conversation_id
    # (D6.2), so a hand-picked conversation_id would simply be dropped
    # server-side. Creating the group for real, then letting the
    # existing creator-auto-distributes-the-key path
    # (handle_group_create_result() -> _create_and_distribute_group_key()
    # -> _distribute_group_key(), unchanged) run naturally is what
    # actually exercises the Stage-3 gate the same way production does.
    alice.create_group_conversation(
        "verification-policy-test",
        [bob_payload["username"], charlie_payload["username"]],
    )

    conversation_id = None

    def _group_created():
        nonlocal conversation_id
        for summary in alice.conversation_store.get_all():
            if summary.is_group and summary.group_name == "verification-policy-test":
                conversation_id = summary.conversation_id
                return True
        return False

    assert _wait_for(_group_created)

    assert _wait_for(
        lambda: bob.key_manager.get_key(conversation_id) is not None
    )
    assert bob.key_manager.get_key(conversation_id) == alice.key_manager.get_key(
        conversation_id
    )

    # Charlie -- unverified -- never received it, even though he is a
    # genuine member of the (real, authorized) group.
    _app.processEvents()
    assert charlie.key_manager.get_key(conversation_id) is None


# ----------------------------------------------------------------------
# Q -- automatic key redelivery cannot bypass verification
# ----------------------------------------------------------------------


def test_q_automatic_redelivery_cannot_bypass_verification(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    conversation_id = str(uuid.uuid4())
    session_key = os.urandom(32)
    alice.key_manager.store_key(conversation_id, session_key, epoch=1)

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    client_session_module.send_message = recording_send_message
    try:
        # A malicious (or merely premature) server-triggered redelivery
        # request for an UNVERIFIED recipient -- must be refused.
        alice.handle_direct_key_redelivery_required({
            "conversation_id": conversation_id,
            "epoch": 1,
            "recipient": bob_payload["username"],
        })
    finally:
        client_session_module.send_message = real_send_message

    distributed = [p for p in sent_packets if p.get("type") == "group_key_distribution"]
    assert len(distributed) == 0
    assert bob.key_manager.get_key(conversation_id) is None


# ----------------------------------------------------------------------
# R -- the server cannot trigger verification automatically
# ----------------------------------------------------------------------


def test_r_server_controlled_traffic_never_promotes_to_verified(app):
    """No server-originated packet -- a public key, a redelivery
    request, a group key distribution -- can ever, by itself, cause a
    peer to become VERIFIED. verify_peer_fingerprint() is called from
    exactly one place in the whole client codebase:
    ClientSession.confirm_peer_verification(), which is itself called
    from exactly one place: VerifyIdentityDialog's explicit confirm
    action. This test bombards a peer with entirely server-controlled
    inputs and proves none of them promote anything."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    # Repeated observation of the SAME real key -- a routine,
    # server-relayed event -- must not promote anything either.
    for _ in range(3):
        alice.handle_public_key(
            _fake_public_key_packet(
                bob_payload["username"], bob.key_manager.algorithm,
                _wire_text(bob.key_manager.public_key),
            )
        )

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_UNVERIFIED
    )

    # A server-triggered redelivery request for this still-unverified
    # peer -- already proven blocked (test_q); confirm it also has no
    # side effect on verification state itself.
    alice.handle_direct_key_redelivery_required({
        "conversation_id": str(uuid.uuid4()),
        "epoch": 1,
        "recipient": bob_payload["username"],
    })

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_UNVERIFIED
    )


# ----------------------------------------------------------------------
# S -- the UI never calls verify_peer_fingerprint()/
# confirm_peer_verification() without explicit user confirmation
# ----------------------------------------------------------------------


def test_s_dialog_never_calls_verify_without_explicit_confirm(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.get_peer_verification_state(bob_payload["username"])
        == PEER_STATE_UNVERIFIED
    )

    calls = []
    original = alice.confirm_peer_verification

    def spying_confirm(username, fingerprint):
        calls.append((username, fingerprint))
        return original(username, fingerprint)

    alice.confirm_peer_verification = spying_confirm

    # Merely constructing and building the dialog's UI must not call
    # confirm_peer_verification().
    dialog = VerifyIdentityDialog(
        alice, bob_payload["username"], PEER_STATE_UNVERIFIED
    )
    assert calls == []

    # Nor does closing/cancelling it.
    dialog.reject()
    assert calls == []
    assert dialog.was_verified() is False

    # Only the explicit confirm action does.
    dialog2 = VerifyIdentityDialog(
        alice, bob_payload["username"], PEER_STATE_UNVERIFIED
    )
    dialog2.handle_confirm()
    assert len(calls) == 1
    assert calls[0][0] == bob_payload["username"]
    assert dialog2.was_verified() is True


def test_s_confirm_peer_verification_requires_an_available_key_store(app, tmp_path):
    """A second layer of the same discipline: confirm_peer_
    verification() itself refuses to silently succeed if there is
    nowhere durable to persist the confirmation."""

    alice_payload = app["register"]("alice_")

    alice = app["launch"](alice_payload)
    alice.key_store = None

    with pytest.raises(KeyStoreError):
        alice.confirm_peer_verification("nobody", "AAAA BBBB")


# ----------------------------------------------------------------------
# Attack scenario (Section 8): malicious server, first contact
# ----------------------------------------------------------------------


def test_attack_first_contact_malicious_server_substitution(app):
    """Alice has never verified Bob. A malicious server supplies
    K_ATTACKER as "Bob's" public key. Proves, before verification:
    state is UNVERIFIED, K_ATTACKER cannot be used to wrap Alice's
    protected session key, the attacker cannot recover it, automatic
    redelivery cannot bypass the gate, and group key distribution
    cannot bypass the gate either. Then performs a correct,
    out-of-band-style verification and proves communication resumes,
    using the (now, post-verification) genuinely trusted key."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)

    # The malicious server supplies an attacker-controlled key
    # claiming to be Bob's -- Bob himself is never actually online.
    attacker = KeyManager()
    alice.handle_public_key(
        _fake_public_key_packet(
            bob_payload["username"], "KYBER", _wire_text(attacker.public_key)
        )
    )

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_UNVERIFIED
    )

    # Alice already has a real, protected AES session key of her own
    # (e.g. from an earlier, different conversation) -- prove it can
    # never be wrapped for "Bob" (really the attacker) via any of the
    # three production call sites.
    real_session_key = os.urandom(32)
    conversation_id = str(uuid.uuid4())
    alice.key_manager.store_key(conversation_id, real_session_key, epoch=1)

    _open_direct(alice, bob_payload["username"])
    with pytest.raises(PeerNotVerifiedError):
        alice.send_chat_message("must not reach the attacker")

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    client_session_module.send_message = recording_send_message
    try:
        alice.handle_direct_key_redelivery_required({
            "conversation_id": conversation_id,
            "epoch": 1,
            "recipient": bob_payload["username"],
        })

        alice._distribute_group_key(
            conversation_id, real_session_key, 1, [bob_payload["username"]]
        )
    finally:
        client_session_module.send_message = real_send_message

    distributed = [p for p in sent_packets if p.get("type") == "group_key_distribution"]
    assert len(distributed) == 0, (
        "neither redelivery nor group distribution may reach the "
        "attacker-controlled key"
    )

    # None of the three production call sites reached
    # wrap_key_for_member() at all while unverified -- proven above by
    # the raise and the two empty send lists. real_session_key was
    # therefore never wrapped under the attacker's key by anything
    # this application would actually do; there is nothing further to
    # attempt to recover.

    # Now the REAL Bob comes online and Alice performs correct,
    # explicit, out-of-band-confirmed verification of his GENUINE key.
    #
    # This is still an ordinary UNVERIFIED -> VERIFIED transition, not
    # KEY_CHANGED: Alice never had a VERIFIED baseline to begin with
    # (the attacker's key was only ever OBSERVED, never verified --
    # proven above), so there is nothing on file yet for a mismatch to
    # be detected against. Bob's real key simply becomes the latest
    # UNVERIFIED observation, overwriting the attacker's -- exactly
    # first contact's ordinary behavior (see
    # storage/secure_key_store.py::record_observed_peer_fingerprint()).
    # KEY_CHANGED is reserved for a key changing AFTER an explicit
    # VERIFIED baseline exists -- see test_h/test_i above for that
    # scenario proven directly.
    bob = app["launch"](bob_payload)

    # Waits specifically for BOB's real key to have overwritten the
    # attacker's observation -- state alone was already UNVERIFIED
    # from the attacker's key, so checking only that would race ahead
    # of Bob's key actually arriving.
    assert _wait_for(
        lambda: alice.get_peer_fingerprint_for_verification(bob_payload["username"])
        == fingerprint_public_key(bob.key_manager.public_key)
    )
    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_UNVERIFIED
    )

    real_fingerprint = alice.get_peer_fingerprint_for_verification(
        bob_payload["username"]
    )
    assert real_fingerprint == fingerprint_public_key(bob.key_manager.public_key)
    assert real_fingerprint != fingerprint_public_key(attacker.public_key)

    alice.confirm_peer_verification(bob_payload["username"], real_fingerprint)

    assert alice.get_peer_verification_state(bob_payload["username"]) == (
        PEER_STATE_VERIFIED
    )

    # Communication now works, and wrapping uses the verified (real)
    # key -- the attacker still cannot recover anything.
    encapsulation, wrapped_key = alice.key_manager.wrap_key_for_member(
        bob_payload["username"], real_session_key
    )
    assert bob.key_manager.unwrap_received_key(
        encapsulation, wrapped_key
    ) == real_session_key
    with pytest.raises((ValueError, TypeError)):
        attacker.unwrap_received_key(encapsulation, wrapped_key)

    alice.send_chat_message("now verified and working")
    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "now verified and working"
            for summary in bob.conversation_store.get_all()
        )
    )
