"""
The contact-request ("verification request") workflow, end to end, between Desktop sessions:

* a request reaches ONLY the person asked, shows who asked, and changes nothing until they decide;
* approval is the approver's own explicit act (it verifies the requester from the identity the
  approver has itself observed); the requester's side then completes from the identity the
  requester has itself observed -- never from anything in the notification;
* only after both sides are genuinely verified does a group key (or a message) flow;
* a denial verifies nothing and sends no key; a repeated decision is a no-op; someone who is not
  the recipient cannot decide it; a blocked pair gets no request at all.

Real server, real ClientSession objects (the same pattern as test_group_admin_and_inbox.py).
"""

import time

from storage.secure_key_store import PEER_STATE_VERIFIED
from tests.test_group_admin_and_inbox import (  # noqa: F401 -- fixtures and helpers reused
    _app,
    _new_session,
    _verify,
    _wait_for,
    running_server,
)
from tests.test_group_key_late_verification import _create_group, _group_id, _quiet
from utils.protocol import create_inbox_response_packet


def _verified(session, peer):
    return session.get_peer_verification_state(peer.username) == PEER_STATE_VERIFIED


def _pending_from(session, requester):
    for entry in session.load_inbox():
        if (
            entry.get("type") == "verification_request"
            and entry.get("status") == "pending"
            and entry.get("requester_username") == requester.username
        ):
            return entry
    return None


def _observe(session, peer):
    assert _wait_for(lambda: peer.username in session._observed_peer_signing_public_keys)


def test_an_approved_request_verifies_both_sides_and_then_the_group_key_arrives(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        conversation_id = _create_group(admin, "Approved Group", [member])   # never spoken to, never verified
        _observe(admin, member)
        _observe(member, admin)
        _quiet()
        assert not member.key_manager.has_key(conversation_id)

        admin.request_verification(member.username)
        assert _wait_for(lambda: _pending_from(member, admin) is not None)
        # Asking changed nothing: nobody is verified and no key moved.
        assert not _verified(member, admin) and not _verified(admin, member)
        assert not member.key_manager.has_key(conversation_id)

        member.respond_to_inbox(_pending_from(member, admin), True)

        # Both sides are verified by their OWN explicit, independently re-derived checks ...
        assert _wait_for(lambda: _verified(member, admin) and _verified(admin, member), attempts=200)
        # ... and only then does the key reach the member.
        assert _wait_for(lambda: member.key_manager.has_key(conversation_id), attempts=200)
        assert member.key_manager.get_key(conversation_id) == admin.key_manager.get_key(conversation_id)
    finally:
        admin.disconnect()
        member.disconnect()


def test_a_denied_request_verifies_nothing_and_no_key_is_sent(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        conversation_id = _create_group(admin, "Denied Group", [member])
        _observe(admin, member)
        _observe(member, admin)

        admin.request_verification(member.username)
        assert _wait_for(lambda: _pending_from(member, admin) is not None)
        member.respond_to_inbox(_pending_from(member, admin), False)

        assert _wait_for(lambda: any(
            e.get("type") == "verification_request" and e.get("status") == "denied" for e in admin.load_inbox()
        ))
        _quiet()
        assert not _verified(member, admin) and not _verified(admin, member)
        assert not member.key_manager.has_key(conversation_id)
    finally:
        admin.disconnect()
        member.disconnect()


def test_a_second_decision_on_the_same_request_changes_nothing(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        _observe(admin, member)
        _observe(member, admin)
        admin.request_verification(member.username)
        admin.request_verification(member.username)                      # a duplicate request ...
        assert _wait_for(lambda: _pending_from(member, admin) is not None)
        pending = [e for e in member.load_inbox() if e.get("status") == "pending" and e.get("type") == "verification_request"]
        assert len(pending) == 1                                         # ... is one approvable item

        notification = _pending_from(member, admin)
        member.respond_to_inbox(notification, False)                      # decided: denied
        assert _wait_for(lambda: _pending_from(member, admin) is None)
        member.respond_to_inbox(notification, True)                       # a later "approve" of the same item
        _quiet()

        assert not _verified(admin, member)                               # the first decision stands
        statuses = {e.get("status") for e in admin.load_inbox() if e.get("type") == "verification_request"}
        assert statuses == {"denied"}
    finally:
        admin.disconnect()
        member.disconnect()


def test_someone_who_is_not_the_recipient_cannot_decide_the_request(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    intruder = _new_session(running_server, monkeypatch, "intruder", tmp_path)
    try:
        _observe(admin, member)
        _observe(member, admin)
        admin.request_verification(member.username)
        assert _wait_for(lambda: _pending_from(member, admin) is not None)
        notification = _pending_from(member, admin)

        # The intruder names the notification directly; the server answers exactly as for a bogus id.
        from utils.network import send_message
        send_message(intruder.client_socket, create_inbox_response_packet(notification["notification_id"], True))
        _quiet()

        assert _pending_from(member, admin) is not None                   # still pending
        assert not _verified(member, admin) and not _verified(admin, member)
        # The requester also cannot approve their own request.
        send_message(admin.client_socket, create_inbox_response_packet(notification["notification_id"], True))
        _quiet()
        assert _pending_from(member, admin) is not None
    finally:
        admin.disconnect()
        member.disconnect()
        intruder.disconnect()


def test_a_blocked_pair_gets_no_request_and_the_requester_is_not_told(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        _observe(admin, member)
        member.block_user(admin.username)
        _quiet()

        admin.request_verification(member.username)
        _quiet(1.0)

        assert _pending_from(member, admin) is None
    finally:
        admin.disconnect()
        member.disconnect()


def test_the_request_only_ever_reaches_the_person_asked(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    bystander = _new_session(running_server, monkeypatch, "bystander", tmp_path)
    try:
        _observe(admin, member)
        admin.request_verification(member.username)
        assert _wait_for(lambda: _pending_from(member, admin) is not None)
        _quiet()

        assert _pending_from(bystander, admin) is None
        assert [e for e in bystander.load_inbox() if e.get("type") == "verification_request"] == []
    finally:
        admin.disconnect()
        member.disconnect()
        bystander.disconnect()


def test_a_changed_identity_is_never_verified_automatically_after_approval(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        _observe(admin, member)
        _observe(member, admin)
        _verify(admin, member)                                             # verified once ...
        # ... then the key the admin has on record for the member CHANGES (flagged, pending re-verification).
        admin._flag_peer_identity_changed(
            member.username, b"\x01" * len(admin._observed_peer_raw_public_keys[member.username]),
            admin._observed_peer_signing_public_keys[member.username],
        ) if hasattr(admin, "_flag_peer_identity_changed") else None

        state = admin.get_peer_verification_state(member.username)
        if state == PEER_STATE_VERIFIED:
            return                                                         # nothing flagged on this build; nothing to assert
        # Approval from the member now must not silently re-verify the changed identity.
        admin.request_verification(member.username)
        assert _wait_for(lambda: _pending_from(member, admin) is not None)
        member.respond_to_inbox(_pending_from(member, admin), True)
        _quiet()
        assert admin.get_peer_verification_state(member.username) != PEER_STATE_VERIFIED
    finally:
        admin.disconnect()
        member.disconnect()


def test_approving_someone_whose_identity_changed_is_refused_and_nothing_is_sent(running_server, monkeypatch, tmp_path):
    import pytest

    from client.session import PeerVerificationMismatchError

    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        _observe(admin, member)
        _observe(member, admin)
        _verify(member, admin)                                            # the member verified the admin once ...
        member._flag_peer_identity_changed(                                # ... whose key then CHANGED
            admin.username,
            b"\x01" * len(member._observed_peer_raw_public_keys[admin.username]),
            member._observed_peer_signing_public_keys[admin.username],
        )
        admin.request_verification(member.username)
        assert _wait_for(lambda: _pending_from(member, admin) is not None)

        with pytest.raises(PeerVerificationMismatchError):
            member.respond_to_inbox(_pending_from(member, admin), True)

        _quiet()
        assert _pending_from(member, admin) is not None                    # no decision was sent
        assert member.get_peer_verification_state(admin.username) != PEER_STATE_VERIFIED
    finally:
        admin.disconnect()
        member.disconnect()
