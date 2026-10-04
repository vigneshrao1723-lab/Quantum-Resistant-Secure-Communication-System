"""
Group Admin + Inbox (verification requests, group member-add
approval) -- Phase 19.13, User Manual Feedback Implementation.

Proves, against a real TLS test server and real ClientSession
instances (the same established pattern as test_verify_late_key_
recovery.py and test_device_identity.py):

- The group creator is recorded as admin at creation.
- A non-admin member's add-member request creates a pending inbox
  notification and performs NO membership change until approved.
- Admin approval runs the real add-member + key-distribution path;
  denial performs no membership change and notifies the requester.
- Duplicate requests do not create duplicate approvable items, and a
  second Approve/Deny on an already-resolved notification is a safe
  no-op (not a repeat action).
- Only the admin can remove a member; a non-admin's attempt is
  rejected server-side with no membership change.
- A verification_request's Approve action performs REAL cryptographic
  verification (ClientSession.confirm_combined_peer_verification()),
  never a UI-only state flip -- and Deny never verifies anything.

Run with:
    pytest tests/test_group_admin_and_inbox.py -v
"""

import os
import threading
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
from gui.inbox_dialog import InboxRow
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
            "full_name": "Admin Inbox Test", "username": f"ai_{hint}{suffix}",
            "email": f"ai_{hint}{suffix}@example.com", "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
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
    assert _wait_for(lambda: peer_session.username in local_session._observed_peer_signing_public_keys)
    kem = local_session._observed_peer_raw_public_keys[peer_session.username]
    signing = local_session._observed_peer_signing_public_keys[peer_session.username]
    fingerprint = fingerprint_combined_identity(kem, signing)
    local_session.confirm_combined_peer_verification(peer_session.username, fingerprint)


def _inbox_notification_for(session, other, ntype, status="pending"):
    for entry in session.load_inbox():
        if (
            entry.get("type") == ntype
            and entry.get("status") == status
            and (entry.get("requester_username") == other.username or entry.get("candidate_username") == other.username)
        ):
            return entry
    return None


def _own_resolved_request(session, ntype, status):
    """Like _inbox_notification_for(), but for the REQUESTER checking
    their own earlier request's outcome -- the serialized notification
    dict never names the recipient/approver (a verification_request's
    recipient is implicitly whoever the requester asked; a group_add_
    request's recipient -- the admin -- is likewise not itself part of
    the dict, see _serialize_group_add_notification()), so there is no
    "other" field to match against from the requester's own side."""
    for entry in session.load_inbox():
        if entry.get("type") == ntype and entry.get("status") == status:
            return entry
    return None


# ========================================================================
# Group admin
# ========================================================================


def test_group_creator_is_admin_and_appears_in_conversation_list(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Admin Test Group", [member.username])
        time.sleep(0.3)
        _app.processEvents()

        from utils.protocol import create_conversation_list_request_packet
        response = admin.send_request(create_conversation_list_request_packet())
        group_entries = [c for c in response["conversations"] if c["is_group"]]
        assert any(c["admin_username"] == admin.username for c in group_entries)
    finally:
        admin.disconnect()
        member.disconnect()


def test_non_admin_add_member_creates_pending_request_not_immediate_add(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Approval Group", [member.username])
        assert _wait_for(lambda: True)
        time.sleep(0.3)
        _app.processEvents()

        from utils.protocol import create_conversation_list_request_packet
        response = member.send_request(create_conversation_list_request_packet())
        conversation_id = next(c["conversation_id"] for c in response["conversations"] if c["is_group"])

        # Non-admin member requests adding candidate.
        member.add_group_members(conversation_id, [candidate.username])
        time.sleep(0.3)
        _app.processEvents()

        # No membership change yet.
        response = admin.send_request(create_conversation_list_request_packet())
        group = next(c for c in response["conversations"] if c["conversation_id"] == conversation_id)
        assert candidate.username not in group["participants"]

        # Admin sees the pending request.
        notification = _inbox_notification_for(admin, member, "group_add_request")
        assert notification is not None
        assert notification["candidate_username"] == candidate.username
    finally:
        admin.disconnect()
        member.disconnect()
        candidate.disconnect()


def test_admin_approving_group_add_request_actually_adds_member(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Approve Group", [member.username])
        time.sleep(0.3)
        _app.processEvents()

        from utils.protocol import create_conversation_list_request_packet
        response = member.send_request(create_conversation_list_request_packet())
        conversation_id = next(c["conversation_id"] for c in response["conversations"] if c["is_group"])

        member.add_group_members(conversation_id, [candidate.username])
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(admin, member, "group_add_request")
        assert notification is not None

        admin.respond_to_inbox(notification, True)
        time.sleep(0.5)
        _app.processEvents()

        response = admin.send_request(create_conversation_list_request_packet())
        group = next(c for c in response["conversations"] if c["conversation_id"] == conversation_id)
        assert candidate.username in group["participants"] or candidate.username == admin.username

        # Requester (member) was notified of the approval.
        resolved = _own_resolved_request(member, "group_add_request", "approved")
        assert resolved is not None
    finally:
        admin.disconnect()
        member.disconnect()
        candidate.disconnect()


def test_admin_denying_group_add_request_adds_nobody(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Deny Group", [member.username])
        time.sleep(0.3)
        _app.processEvents()

        from utils.protocol import create_conversation_list_request_packet
        response = member.send_request(create_conversation_list_request_packet())
        conversation_id = next(c["conversation_id"] for c in response["conversations"] if c["is_group"])

        member.add_group_members(conversation_id, [candidate.username])
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(admin, member, "group_add_request")
        assert notification is not None

        admin.respond_to_inbox(notification, False)
        time.sleep(0.3)
        _app.processEvents()

        response = admin.send_request(create_conversation_list_request_packet())
        group = next(c for c in response["conversations"] if c["conversation_id"] == conversation_id)
        assert candidate.username not in group["participants"]

        resolved = _own_resolved_request(member, "group_add_request", "denied")
        assert resolved is not None
    finally:
        admin.disconnect()
        member.disconnect()
        candidate.disconnect()


def test_duplicate_group_add_request_does_not_create_two_notifications(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Dup Group", [member.username])
        time.sleep(0.3)
        _app.processEvents()

        from utils.protocol import create_conversation_list_request_packet
        response = member.send_request(create_conversation_list_request_packet())
        conversation_id = next(c["conversation_id"] for c in response["conversations"] if c["is_group"])

        member.add_group_members(conversation_id, [candidate.username])
        time.sleep(0.3)
        member.add_group_members(conversation_id, [candidate.username])
        time.sleep(0.3)
        _app.processEvents()

        pending = [
            entry for entry in admin.load_inbox()
            if entry.get("type") == "group_add_request" and entry.get("status") == "pending"
            and entry.get("candidate_username") == candidate.username
        ]
        assert len(pending) == 1
    finally:
        admin.disconnect()
        member.disconnect()
        candidate.disconnect()


def test_non_admin_cannot_remove_member(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    other = _new_session(running_server, monkeypatch, "other", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Kick Group", [member.username, other.username])
        time.sleep(0.3)
        _app.processEvents()

        from utils.protocol import create_conversation_list_request_packet
        response = member.send_request(create_conversation_list_request_packet())
        conversation_id = next(c["conversation_id"] for c in response["conversations"] if c["is_group"])

        result = member.remove_group_member(conversation_id, other.username)
        assert result.get("success") is False

        response = admin.send_request(create_conversation_list_request_packet())
        group = next(c for c in response["conversations"] if c["conversation_id"] == conversation_id)
        assert other.username in group["participants"]
    finally:
        admin.disconnect()
        member.disconnect()
        other.disconnect()


def test_admin_can_remove_member(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    other = _new_session(running_server, monkeypatch, "other", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Kick Group 2", [member.username, other.username])
        time.sleep(0.3)
        _app.processEvents()

        from utils.protocol import create_conversation_list_request_packet
        response = admin.send_request(create_conversation_list_request_packet())
        conversation_id = next(c["conversation_id"] for c in response["conversations"] if c["is_group"])

        result = admin.remove_group_member(conversation_id, other.username)
        assert result.get("success") is True

        response = admin.send_request(create_conversation_list_request_packet())
        group = next(c for c in response["conversations"] if c["conversation_id"] == conversation_id)
        assert other.username not in group["participants"]
    finally:
        admin.disconnect()
        member.disconnect()
        other.disconnect()


def test_conversation_store_admin_field_populated_and_survives_member_removal(
    running_server, monkeypatch, tmp_path
):
    """
    Phase 19.18 -- Desktop Group Info/Remove Member parity. The wire
    protocol and ClientSession.remove_group_member() already existed
    (proven by the two tests above, which assert against the raw
    conversation_list_result packet); what GroupInfoDialog actually
    reads is ConversationSummary.admin via conversation_store, which
    was never populated before this phase. Proves the field is set
    correctly from BOTH the live group_create_result path (for the
    creator AND a fellow member, since that packet is sent to every
    active member) and a fresh load_conversations() reload (the
    conversation_list_result path a newly (re)connecting client uses
    instead), and that it survives a group_member_left update rather
    than being silently reset to None -- the exact bug
    ConversationStore.update_group_participants() had until this
    phase (it rebuilt the summary from scratch, dropping every field
    not in its own parameter list).
    """

    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    other = _new_session(running_server, monkeypatch, "other", tmp_path)
    try:
        _verify(admin, member)
        _verify(member, admin)

        admin.create_group_conversation("Info Group", [member.username, other.username])

        assert _wait_for(lambda: admin.conversation_store.get_all())
        assert _wait_for(lambda: member.conversation_store.get_all())

        # Live group_create_result path -- both the creator's own
        # client and a fellow (non-creator) member's client.
        conversation_id = next(
            s.conversation_id for s in admin.conversation_store.get_all() if s.is_group
        )
        assert admin.conversation_store.get(conversation_id).admin == admin.username

        member_summary = next(
            s for s in member.conversation_store.get_all() if s.is_group
        )
        assert member_summary.admin == admin.username

        # A fresh client that never saw the live create event learns
        # admin from the conversation_list_result reload path instead.
        other.load_conversations()
        assert _wait_for(lambda: other.conversation_store.get(conversation_id) is not None)
        assert other.conversation_store.get(conversation_id).admin == admin.username

        # Removing a member must not wipe the admin field back to None
        # on either the admin's own store or the remaining member's.
        result = admin.remove_group_member(conversation_id, other.username)
        assert result.get("success") is True

        assert _wait_for(
            lambda: other.username not in (admin.conversation_store.get(conversation_id).participants or [])
        )
        assert admin.conversation_store.get(conversation_id).admin == admin.username

        assert _wait_for(
            lambda: other.username not in (member.conversation_store.get(conversation_id).participants or [])
        )
        assert member.conversation_store.get(conversation_id).admin == admin.username
    finally:
        admin.disconnect()
        member.disconnect()
        other.disconnect()


# ========================================================================
# Verification-request inbox workflow
# ========================================================================


def test_verification_request_approve_performs_real_verification(running_server, monkeypatch, tmp_path):
    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)

        alice.request_verification(bob.username)
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(bob, alice, "verification_request")
        assert notification is not None
        assert not bob._peer_key_is_verified(alice.username)

        bob.respond_to_inbox(notification, True)

        assert bob._peer_key_is_verified(alice.username)

        time.sleep(0.3)
        _app.processEvents()
        resolved = _own_resolved_request(alice, "verification_request", "approved")
        assert resolved is not None
    finally:
        alice.disconnect()
        bob.disconnect()


def test_verification_request_deny_verifies_nothing(running_server, monkeypatch, tmp_path):
    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)

        alice.request_verification(bob.username)
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(bob, alice, "verification_request")
        assert notification is not None

        bob.respond_to_inbox(notification, False)

        assert not bob._peer_key_is_verified(alice.username)
    finally:
        alice.disconnect()
        bob.disconnect()


def test_duplicate_verification_request_is_a_single_notification(running_server, monkeypatch, tmp_path):
    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)

        alice.request_verification(bob.username)
        time.sleep(0.2)
        alice.request_verification(bob.username)
        time.sleep(0.3)
        _app.processEvents()

        pending = [
            entry for entry in bob.load_inbox()
            if entry.get("type") == "verification_request" and entry.get("status") == "pending"
            and entry.get("requester_username") == alice.username
        ]
        assert len(pending) == 1
    finally:
        alice.disconnect()
        bob.disconnect()


def test_double_approve_does_not_error_or_reverify(running_server, monkeypatch, tmp_path):
    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)

        alice.request_verification(bob.username)
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(bob, alice, "verification_request")
        bob.respond_to_inbox(notification, True)
        assert bob._peer_key_is_verified(alice.username)

        # Second Approve on the same (now-resolved) notification: the
        # server no-ops (already resolved); the client-side re-confirm
        # is itself idempotent (confirm_combined_peer_verification()
        # re-derives from the same still-VERIFIED observed key).
        bob.respond_to_inbox(notification, True)
        assert bob._peer_key_is_verified(alice.username)
    finally:
        alice.disconnect()
        bob.disconnect()


def test_approve_fails_without_this_sessions_own_fresh_observation(running_server, monkeypatch, tmp_path):
    """
    PHASE 19 MANUAL ACCEPTANCE, Test 3B: a real device Approve failed
    with "No observed combined identity for X; there is nothing to
    verify" for a pending request whose requester's identity had NOT
    been (re-)observed by the CURRENT, currently-running approving
    process -- diagnosed as correct, existing fail-closed behavior,
    not a persistence bug. confirm_combined_peer_verification() (see
    its own docstring) never trusts a resurrected-from-disk
    SecureKeyStore fingerprint alone; it independently re-derives the
    fingerprint from _currently_observed_peer_identity(), which is
    deliberately session-local (_observed_peer_raw_public_keys/
    _observed_peer_signing_public_keys) and requires a FRESH signed
    identity packet THIS process has itself received -- exactly so a
    peer cannot be promoted to VERIFIED on stale, disk-only trust with
    no live proof they still hold that key right now.

    bob_restarted below is a SEPARATE ClientSession for bob's own
    account (same on-disk SecureKeyStore, via the same "bob" hint) that
    never itself observed alice -- simulating precisely what a real
    app restart/relaunch between "identity became available" (Test 3A)
    and "Approve" (Test 3B) leaves behind. This is the negative
    counterpart to test_verification_request_approve_performs_real_
    verification() above, which already proves the positive case
    (approval succeeds) within one continuous, still-observing session.
    """

    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", tmp_path / "bob")
    bob_payload = _register("bob")
    bob = ClientSession()
    result = bob.authenticate_credentials(bob_payload["phone_number"], PASSWORD)
    assert result.success, result.message
    bob.user_id = result.user_id
    bob.username = result.username
    bob.access_token = result.token_pair.access_token
    bob.connect()
    bob.login(bob_payload["username"])
    bob.send_public_key()
    bob.start_receiver()

    bob_restarted = None
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)

        alice.request_verification(bob.username)
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(bob, alice, "verification_request")
        assert notification is not None

        # Both original processes end here -- exactly like the app
        # being closed/restarted after Test 3A, before Approve is
        # pressed. alice must be offline too: distribute_public_keys()
        # broadcasts to/from whoever is online at CONNECT time, so if
        # she stayed connected, bob_restarted would legitimately
        # re-observe her the moment it logs in below -- the opposite
        # of the condition under test.
        bob.disconnect()
        alice.disconnect()

        monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", tmp_path / "bob")
        bob_restarted = ClientSession()
        result = bob_restarted.authenticate_credentials(bob_payload["phone_number"], PASSWORD)
        assert result.success, result.message
        bob_restarted.user_id = result.user_id
        bob_restarted.username = result.username
        bob_restarted.access_token = result.token_pair.access_token
        bob_restarted.connect()
        bob_restarted.login(bob_payload["username"])
        # start_receiver() IS needed here -- it drives every send_
        # request()/response round trip this test still makes
        # (load_inbox(), respond_to_inbox()'s packet), not just
        # identity observation. What's deliberately skipped is
        # send_public_key() and any online overlap with alice: with
        # her already offline above, nothing broadcasts her identity
        # to this fresh process, which is the actual condition under
        # test.
        bob_restarted.start_receiver()

        assert alice.username not in bob_restarted._observed_peer_raw_public_keys
        assert alice.username not in bob_restarted._observed_peer_signing_public_keys

        with pytest.raises(client_session_module.PeerVerificationMismatchError):
            bob_restarted.respond_to_inbox(notification, True)

        # The failed attempt verifies nothing -- no silent partial
        # promotion on the error path.
        assert not bob_restarted._peer_key_is_verified(alice.username)
    finally:
        alice.disconnect()
        try:
            bob.disconnect()
        except Exception:  # noqa: BLE001
            pass
        if bob_restarted is not None:
            bob_restarted.disconnect()


def test_has_observed_combined_identity_tracks_the_same_gate_approval_uses(
    running_server, monkeypatch, tmp_path
):
    """
    Phase 19.22 -- has_observed_combined_identity() is a pure, read-
    only query over the exact same state confirm_combined_peer_
    verification() gates on (_currently_observed_peer_identity()); it
    must agree with that gate in both directions, never just the
    happy one.
    """

    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)
        assert _wait_for(lambda: alice.username in bob._observed_peer_signing_public_keys)
        assert alice.has_observed_combined_identity(bob.username)
        assert bob.has_observed_combined_identity(alice.username)

        assert not alice.has_observed_combined_identity("nobody_ever_observed")
    finally:
        alice.disconnect()
        bob.disconnect()


def test_inbox_approve_survives_an_identity_observation_race(
    running_server, monkeypatch, tmp_path
):
    """
    Phase 19.22 -- PHASE 19 MANUAL ACCEPTANCE Test 3B: the positive
    approval flow showed a transient "No observed combined identity
    for X; there is nothing to verify" even though both users were
    continuously online -- the request notification's own arrival and
    the requester's identity packet are two independent, asynchronously
    -relayed things, and a real click can land in the (usually very
    short) window before the identity has finished being recorded.

    Reproduces that exact race directly: bob's Inbox card is asked to
    Approve a real, pending verification_request from alice at a
    moment his session has NOT yet observed her (forced by clearing
    the entries _record_peer_identity_observation() already wrote,
    simulating "not landed yet" rather than "never sent"), with her
    identity arriving a moment later on a background thread -- exactly
    like the real asynchronous delivery. gui/inbox_dialog.py::
    InboxRow._respond() must wait for it and succeed, not surface the
    error for what is genuinely just a timing race.

    Does NOT touch ClientSession.confirm_combined_peer_verification()/
    respond_to_inbox() at all -- those, and the negative test above
    proving they still fail closed with no observation whatsoever,
    are completely unchanged.
    """

    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)
        assert _wait_for(lambda: alice.username in bob._observed_peer_signing_public_keys)

        alice.request_verification(bob.username)
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(bob, alice, "verification_request")
        assert notification is not None

        # Simulate "hasn't landed in THIS process yet" -- the real
        # race -- by removing what the earlier, genuine exchange
        # above already recorded, then handing it back on a short
        # delay from another thread, exactly like the receiver thread
        # delivering it asynchronously mid-click.
        real_kem = bob._observed_peer_raw_public_keys.pop(alice.username)
        real_signing = bob._observed_peer_signing_public_keys.pop(alice.username)
        assert not bob.has_observed_combined_identity(alice.username)

        def _deliver_late():
            time.sleep(0.4)
            bob._observed_peer_raw_public_keys[alice.username] = real_kem
            bob._observed_peer_signing_public_keys[alice.username] = real_signing

        threading.Thread(target=_deliver_late, daemon=True).start()

        row = InboxRow(bob, notification, on_responded=lambda: None)
        row._respond(True)

        assert not row.status_label.isVisible()
        assert bob._peer_key_is_verified(alice.username)
    finally:
        alice.disconnect()
        bob.disconnect()


def test_requester_side_verification_completes_after_approval(running_server, monkeypatch, tmp_path):
    """
    Phase 19.22C -- closes the requester-side verification evidence gap
    left by Phase 19.22B. respond_to_inbox()'s approve path (proven by
    test_verification_request_approve_performs_real_verification()
    above) already promotes the APPROVER's own combined identity for
    the requester to VERIFIED -- but the requester's own mirror half
    was never proven end-to-end: their Inbox correctly showed
    "approved" (also already proven above via _own_resolved_request()),
    yet nothing asserted that the requester's own _peer_key_is_
    verified() for the approver ever actually flipped. This test
    asserts the final requester-side verification STATE, not merely
    that a notification arrived.
    """

    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)
        assert _wait_for(lambda: alice.username in bob._observed_peer_signing_public_keys)

        assert not alice._peer_key_is_verified(bob.username)
        assert not bob._peer_key_is_verified(alice.username)

        alice.request_verification(bob.username)
        time.sleep(0.3)
        _app.processEvents()

        notification = _inbox_notification_for(bob, alice, "verification_request")
        assert notification is not None

        bob.respond_to_inbox(notification, True)
        assert bob._peer_key_is_verified(alice.username)

        # The actual bug this closes: the approval result must reach A
        # asynchronously (a real inbox_response_result packet, handled
        # on A's own receiver thread) and complete A's OWN verification
        # state for B -- not just leave A's Inbox history showing
        # "approved" while A's live peer state for B stays unverified.
        assert _wait_for(lambda: alice._peer_key_is_verified(bob.username))
    finally:
        alice.disconnect()
        bob.disconnect()


def test_requester_side_verification_stays_fail_closed_without_fresh_observation(
    running_server, monkeypatch, tmp_path
):
    """
    Fail-closed counterpart to the test above. ClientSession._complete_
    requester_side_verification() must go through the exact same fail-
    closed get_peer_fingerprint_for_verification() + confirm_combined_
    peer_verification() gate every other verification path already
    uses -- never a blind promotion just because a server-pushed
    notification claims approval. Forces a fingerprint to be available
    (simulating stale persistent/pending state a real disk-backed key
    store could hand back) while leaving alice's CURRENT-session
    observation of bob empty -- mirroring test_approve_fails_without_
    this_sessions_own_fresh_observation()'s own negative proof for the
    approver's gate, applied here to the new requester-side path
    instead. Never touches confirm_combined_peer_verification() itself.
    """

    alice = _new_session(running_server, monkeypatch, "alice", tmp_path)
    bob = _new_session(running_server, monkeypatch, "bob", tmp_path)
    try:
        assert _wait_for(lambda: bob.username in alice._observed_peer_signing_public_keys)

        # A fingerprint alice's local store could plausibly hand back
        # (real, previously-observed data from the exchange above) --
        # the point under test is that HAVING a fingerprint available
        # is not enough on its own without a fresh observation to
        # independently re-derive and compare against.
        stale_fingerprint = fingerprint_combined_identity(
            alice._observed_peer_raw_public_keys[bob.username],
            alice._observed_peer_signing_public_keys[bob.username],
        )
        monkeypatch.setattr(
            alice, "get_peer_fingerprint_for_verification", lambda *a, **k: stale_fingerprint
        )

        # Wipe THIS session's own live observation of bob -- exactly
        # what a real restart between "identity was once seen" and "an
        # approval notification arrives" would leave behind.
        alice._observed_peer_raw_public_keys.pop(bob.username, None)
        alice._observed_peer_signing_public_keys.pop(bob.username, None)
        assert not alice.has_observed_combined_identity(bob.username)

        notification = {
            "type": "verification_request",
            "status": "approved",
            "requester_username": alice.username,
            "recipient_username": bob.username,
        }

        # Must not raise -- the failure is caught and logged, exactly
        # like every other fail-closed gate in this file -- and must
        # not promote alice's state for bob despite a fingerprint
        # being available.
        alice._complete_requester_side_verification(notification)

        assert not alice._peer_key_is_verified(bob.username)
    finally:
        alice.disconnect()
        bob.disconnect()
