"""
Joining a group by invitation: nobody becomes a member until THEY approve it in their own Inbox.

* the group's admin creates a group (or adds people later) with consent invitations: the group exists
  with only the admin, and each invited person gets an Inbox item naming who invited them and to
  which group -- and only that person gets it;
* an approval is the invitee's explicit act: it adds them (once), they and the inviter then verify
  each other from the identities each has itself observed, the group key reaches them, and group
  messages are readable both ways; a denial, silence, an expired or void invitation adds nobody;
* a non-admin's request needs the admin's approval AND then the candidate's;
* nobody but the recipient can decide an invitation; blocks, repeats and a changed identity are safe.

Real server, real ClientSession objects (the same pattern as test_group_admin_and_inbox.py).
"""

import time
import uuid

import pytest
from sqlalchemy import text

from client.session import PeerVerificationMismatchError
from database.connection import SessionLocal
from storage.secure_key_store import PEER_STATE_VERIFIED
from tests.test_group_admin_and_inbox import (  # noqa: F401 -- fixtures and helpers reused
    _app,
    _new_session,
    _verify,
    _wait_for,
    running_server,
)
from tests.test_group_key_late_verification import _quiet
from utils.network import send_message
from utils.protocol import create_inbox_response_packet


def _group_id_for(session, name):
    for summary in session.conversation_store.get_all():
        if summary.is_group and summary.group_name == name:
            return summary.conversation_id
    return None


def _invitation(session, inviter, group_name=None, status="pending"):
    for entry in session.load_inbox():
        if (
            entry.get("type") == "group_invitation"
            and entry.get("status") == status
            and entry.get("requester_username") == inviter.username
            and (group_name is None or entry.get("group_name") == group_name)
        ):
            return entry
    return None


def _members(session, conversation_id):
    summary = session.conversation_store.get(conversation_id)
    return set(summary.participants or []) | {session.username} if summary is not None else set()


def _server_members(session, conversation_id):
    from utils.protocol import create_conversation_list_request_packet

    response = session.send_request(create_conversation_list_request_packet())
    for entry in response["conversations"]:
        if entry["conversation_id"] == conversation_id:
            # The list names the OTHER participants; add the asking account to get the whole group.
            return set(entry["participants"]) | {session.username}
    return None


def _observe(session, peer):
    assert _wait_for(lambda: peer.username in session._observed_peer_signing_public_keys)


def _create_with_invitations(admin, name, invitees):
    admin.create_group_conversation(name, [i.username for i in invitees], consent_invitations=True)
    assert _wait_for(lambda: _group_id_for(admin, name) is not None)
    return _group_id_for(admin, name)


def test_a_group_created_with_invitations_has_only_the_admin_until_people_approve(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    c = _new_session(running_server, monkeypatch, "c", tmp_path)
    bystander = _new_session(running_server, monkeypatch, "bystander", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#LAB", [b, c])
        _quiet()

        # The group exists, with only its creator in it.
        assert _members(admin, conversation_id) == {admin.username}
        # Each invitee has an Inbox item naming who invited them and to which group ...
        for invitee in (b, c):
            item = _invitation(invitee, admin, "#LAB")
            assert item is not None and item["recipient_username"] == invitee.username
            assert item["candidate_username"] == invitee.username
        # ... and nobody else does; nobody sees the group yet.
        assert _invitation(bystander, admin) is None
        assert _group_id_for(b, "#LAB") is None and _group_id_for(c, "#LAB") is None
        assert not b.key_manager.has_key(conversation_id)
    finally:
        for s in (admin, b, c, bystander):
            s.disconnect()


def test_approving_adds_the_member_verifies_both_sides_and_delivers_the_key(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#KEYS", [b])
        _observe(admin, b)
        _observe(b, admin)
        assert _wait_for(lambda: _invitation(b, admin, "#KEYS") is not None)

        b.respond_to_inbox(_invitation(b, admin, "#KEYS"), True)

        assert _wait_for(lambda: _server_members(admin, conversation_id) == {admin.username, b.username})
        # Both sides verified each other, each from the identity it observed itself ...
        assert _wait_for(
            lambda: b.get_peer_verification_state(admin.username) == PEER_STATE_VERIFIED
            and admin.get_peer_verification_state(b.username) == PEER_STATE_VERIFIED,
            attempts=200,
        )
        # ... the key arrived without anyone pressing anything ...
        assert _wait_for(lambda: b.key_manager.has_key(conversation_id), attempts=300)
        assert b.key_manager.get_key(conversation_id) == admin.key_manager.get_key(conversation_id)
        # ... and the group carries messages both ways.
        got_admin, got_b = [], []
        admin.message_received.connect(lambda _k, sender, body: got_admin.append((sender, body)))
        b.message_received.connect(lambda _k, sender, body: got_b.append((sender, body)))
        assert _wait_for(lambda: _group_id_for(b, "#KEYS") is not None)
        b.set_current_chat(b.conversation_store.get(conversation_id))
        admin.set_current_chat(admin.conversation_store.get(conversation_id))
        admin.send_chat_message("welcome")
        assert _wait_for(lambda: (admin.username, "welcome") in got_b, attempts=200)
        b.send_chat_message("thanks")
        assert _wait_for(lambda: (b.username, "thanks") in got_admin, attempts=200)
    finally:
        admin.disconnect()
        b.disconnect()


def test_only_the_people_who_approve_are_added(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    c = _new_session(running_server, monkeypatch, "c", tmp_path)
    d = _new_session(running_server, monkeypatch, "d", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#THREE", [b, c, d])
        for s in (b, c, d):
            _observe(admin, s)
            _observe(s, admin)
        assert _wait_for(lambda: all(_invitation(s, admin, "#THREE") is not None for s in (b, c, d)))

        b.respond_to_inbox(_invitation(b, admin, "#THREE"), True)        # approves
        c.respond_to_inbox(_invitation(c, admin, "#THREE"), False)       # denies; d never answers

        assert _wait_for(lambda: _server_members(admin, conversation_id) == {admin.username, b.username})
        _quiet(1.0)
        assert _server_members(admin, conversation_id) == {admin.username, b.username}
        assert _group_id_for(c, "#THREE") is None and _group_id_for(d, "#THREE") is None
        assert _invitation(d, admin, "#THREE") is not None                # d's is still waiting
        assert not c.key_manager.has_key(conversation_id) and not d.key_manager.has_key(conversation_id)
        # The inviter is told what each person decided.
        statuses = {e["recipient_username"]: e["status"] for e in admin.load_inbox() if e.get("type") == "group_invitation"}
        assert statuses == {b.username: "approved", c.username: "denied", d.username: "pending"}
        assert c.get_peer_verification_state(admin.username) != PEER_STATE_VERIFIED   # a denial verifies nothing
    finally:
        for s in (admin, b, c, d):
            s.disconnect()


def test_a_second_approval_and_duplicate_invitations_change_nothing(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#ONCE", [b])
        _observe(admin, b)
        _observe(b, admin)
        admin.add_group_members(conversation_id, [b.username], consent_invitations=True)   # a repeat
        admin.add_group_members(conversation_id, [b.username], consent_invitations=True)
        _quiet()
        pending = [e for e in b.load_inbox() if e.get("type") == "group_invitation" and e.get("status") == "pending"]
        assert len(pending) == 1                                           # one approvable item

        notification = pending[0]
        b.respond_to_inbox(notification, True)
        assert _wait_for(lambda: _server_members(admin, conversation_id) == {admin.username, b.username})
        b.respond_to_inbox(notification, True)                             # the same decision again
        b.respond_to_inbox(notification, False)                            # ... or the opposite one
        _quiet(1.0)

        assert _server_members(admin, conversation_id) == {admin.username, b.username}
        statuses = {e["status"] for e in b.load_inbox() if e.get("type") == "group_invitation"}
        assert statuses == {"approved"}
    finally:
        admin.disconnect()
        b.disconnect()


def test_nobody_but_the_invitee_can_decide_an_invitation(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    intruder = _new_session(running_server, monkeypatch, "intruder", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#OWN", [b])
        assert _wait_for(lambda: _invitation(b, admin, "#OWN") is not None)
        notification = _invitation(b, admin, "#OWN")

        # The intruder, and the inviter themselves, name the notification directly.
        send_message(intruder.client_socket, create_inbox_response_packet(notification["notification_id"], True))
        send_message(admin.client_socket, create_inbox_response_packet(notification["notification_id"], True))
        _quiet(1.0)

        assert _server_members(admin, conversation_id) == {admin.username}
        assert _invitation(b, admin, "#OWN") is not None                   # still pending
    finally:
        for s in (admin, b, intruder):
            s.disconnect()


def test_a_blocked_person_is_never_invited_and_a_block_voids_a_pending_invitation(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    c = _new_session(running_server, monkeypatch, "c", tmp_path)
    try:
        c.block_user(admin.username)
        _quiet()
        conversation_id = _create_with_invitations(admin, "#BLOCK", [b, c])
        _quiet()
        assert _invitation(c, admin) is None                               # silently not invited
        assert _invitation(b, admin) is not None

        _observe(admin, b)
        _observe(b, admin)
        b.block_user(admin.username)                                       # blocks AFTER being invited
        _quiet()
        b.respond_to_inbox(_invitation(b, admin, "#BLOCK"), True)
        _quiet(1.0)

        assert _server_members(admin, conversation_id) == {admin.username}
    finally:
        for s in (admin, b, c):
            s.disconnect()


def test_an_expired_invitation_cannot_be_approved(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#OLD", [b])
        _observe(admin, b)
        _observe(b, admin)
        item = _invitation(b, admin, "#OLD")
        db = SessionLocal()
        try:
            db.execute(
                text("UPDATE inbox_notifications SET created_at = created_at - interval '30 days' WHERE id = :i"),
                {"i": uuid.UUID(item["notification_id"])},
            )
            db.commit()
        finally:
            db.close()

        assert _invitation(b, admin, status="expired") is not None         # it reads as expired already
        b.respond_to_inbox(_invitation(b, admin, status="expired") or item, True)
        _quiet(1.0)

        assert _server_members(admin, conversation_id) == {admin.username}
    finally:
        admin.disconnect()
        b.disconnect()


def test_an_invitation_from_someone_who_left_the_group_adds_nobody(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    friend = _new_session(running_server, monkeypatch, "friend", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#LEFT", [friend])
        _observe(admin, friend)
        _observe(friend, admin)
        assert _wait_for(lambda: _invitation(friend, admin, "#LEFT") is not None)
        friend.respond_to_inbox(_invitation(friend, admin, "#LEFT"), True)
        assert _wait_for(lambda: _server_members(admin, conversation_id) == {admin.username, friend.username})

        admin.add_group_members(conversation_id, [b.username], consent_invitations=True)
        assert _wait_for(lambda: _invitation(b, admin, "#LEFT") is not None)
        _observe(b, admin)
        admin.leave_group_conversation(conversation_id)                    # the inviter leaves
        _quiet(1.0)

        b.respond_to_inbox(_invitation(b, admin, "#LEFT") or _invitation(b, admin, "#LEFT", "expired"), True)
        _quiet(1.0)
        assert b.username not in (_server_members(friend, conversation_id) or set())
    finally:
        for s in (admin, friend, b):
            s.disconnect()


def test_a_non_admins_request_needs_the_admin_and_then_the_candidate(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#ASK", [member])
        for s in (member, candidate):
            _observe(admin, s)
            _observe(s, admin)
        assert _wait_for(lambda: _invitation(member, admin, "#ASK") is not None)
        member.respond_to_inbox(_invitation(member, admin, "#ASK"), True)
        assert _wait_for(lambda: _server_members(admin, conversation_id) == {admin.username, member.username})

        member.add_group_members(conversation_id, [candidate.username], consent_invitations=True)   # non-admin asks
        def _request():
            return next((e for e in admin.load_inbox() if e.get("type") == "group_add_request" and e.get("status") == "pending"), None)
        assert _wait_for(lambda: _request() is not None)
        assert _invitation(candidate, admin) is None and _invitation(candidate, member) is None   # nothing for them yet

        admin.respond_to_inbox(_request(), True, consent_invitations=True)                     # the admin approves ...
        assert _wait_for(lambda: _invitation(candidate, admin, "#ASK") is not None)
        _quiet(0.5)
        assert candidate.username not in _server_members(admin, conversation_id)               # ... still not a member

        candidate.respond_to_inbox(_invitation(candidate, admin, "#ASK"), True)               # until THEY approve
        assert _wait_for(lambda: candidate.username in (_server_members(admin, conversation_id) or set()))
        assert _wait_for(lambda: candidate.key_manager.has_key(conversation_id), attempts=300)
    finally:
        for s in (admin, member, candidate):
            s.disconnect()


def test_an_admin_denying_a_request_invites_nobody(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#NO", [member])
        _observe(admin, member)
        _observe(member, admin)
        assert _wait_for(lambda: _invitation(member, admin, "#NO") is not None)
        member.respond_to_inbox(_invitation(member, admin, "#NO"), True)
        assert _wait_for(lambda: _server_members(admin, conversation_id) == {admin.username, member.username})

        member.add_group_members(conversation_id, [candidate.username], consent_invitations=True)
        request = None
        def _find():
            nonlocal request
            request = next((e for e in admin.load_inbox() if e.get("type") == "group_add_request" and e.get("status") == "pending"), None)
            return request is not None
        assert _wait_for(_find)

        admin.respond_to_inbox(request, False, consent_invitations=True)
        _quiet(1.0)

        assert [e for e in candidate.load_inbox() if e.get("type") == "group_invitation"] == []
        assert candidate.username not in _server_members(admin, conversation_id)
    finally:
        for s in (admin, member, candidate):
            s.disconnect()


def test_an_invitee_cannot_approve_someone_whose_identity_changed(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    try:
        conversation_id = _create_with_invitations(admin, "#CHANGED", [b])
        _observe(admin, b)
        _observe(b, admin)
        _verify(b, admin)                                                  # b verified the admin once ...
        b._flag_peer_identity_changed(                                      # ... whose key then CHANGED
            admin.username,
            b"\x01" * len(b._observed_peer_raw_public_keys[admin.username]),
            b._observed_peer_signing_public_keys[admin.username],
        )
        assert _wait_for(lambda: _invitation(b, admin, "#CHANGED") is not None)

        with pytest.raises(PeerVerificationMismatchError):
            b.respond_to_inbox(_invitation(b, admin, "#CHANGED"), True)

        _quiet(1.0)
        assert _server_members(admin, conversation_id) == {admin.username}   # nothing was sent, nobody added
    finally:
        admin.disconnect()
        b.disconnect()


def test_without_the_consent_flag_adding_is_immediate_as_before(running_server, monkeypatch, tmp_path):
    """Older clients (and the existing session-level API) keep the original behaviour."""
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    b = _new_session(running_server, monkeypatch, "b", tmp_path)
    try:
        admin.create_group_conversation("#LEGACY", [b.username])
        assert _wait_for(lambda: _group_id_for(admin, "#LEGACY") is not None)
        conversation_id = _group_id_for(admin, "#LEGACY")
        assert _wait_for(lambda: _server_members(admin, conversation_id) == {admin.username, b.username})
        assert [e for e in b.load_inbox() if e.get("type") == "group_invitation"] == []
    finally:
        admin.disconnect()
        b.disconnect()
