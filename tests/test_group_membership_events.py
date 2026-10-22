"""
Group membership events: "Alice added Bob", "Bob left", "Alice removed Carol".

Proved against the real TLS test server, real ClientSessions and the real database:

* every change records exactly one event, written by the server from authenticated identities (the
  connection that asked, the membership row that changed) -- never from text a client sent;
* the actor and the subject are the real people (an approved add is the approving admin's);
* live delivery reaches the group's members only, and history returns the events a member may see,
  in order, from the moment they joined -- never to a non-member, a removed member or someone who
  was out of the group at the time;
* repeating an action (a second removal, a second leave, an add of someone already in) records
  nothing more, and a live event is the same event history later returns (one id, shown once).
"""

import time

import pytest

from database.connection import SessionLocal
from database.models.group_event import GroupEvent
from tests.test_group_admin_and_inbox import (  # noqa: F401 -- helpers and fixture reused
    _app,
    _inbox_notification_for,
    _new_session,
    _verify,
    _wait_for,
    running_server,
)
from utils.protocol import create_conversation_list_request_packet, create_message_history_request_packet


def _events_in_db(conversation_id):
    db = SessionLocal()
    try:
        rows = db.query(GroupEvent).filter(GroupEvent.conversation_id == conversation_id).order_by(
            GroupEvent.created_at.asc(), GroupEvent.id.asc()
        ).all()
        return [(r.event_type, r.actor_username, r.subject_username) for r in rows]
    finally:
        db.close()


def _history_events(session, conversation_id):
    """What the server returns for this member's history of the group (raw wire events)."""
    response = session.send_request(create_message_history_request_packet(conversation_id, True))
    return response.get("error"), [
        (e["event_type"], e["actor"], e["subject"]) for e in response.get("events") or []
    ], response.get("events") or []


def _record_events(session):
    seen = []
    session.group_event_received.connect(lambda conversation_id, event: seen.append((conversation_id, event)))
    return seen


def _group(admin, others, name):
    admin.create_group_conversation(name, [o.username for o in others])
    assert _wait_for(lambda: any(s.is_group and s.group_name == name for s in admin.conversation_store.get_all()))
    summary = next(s for s in admin.conversation_store.get_all() if s.is_group and s.group_name == name)
    for member in others:
        assert _wait_for(lambda: member.conversation_store.get(summary.conversation_id) is not None)
    return summary.conversation_id


@pytest.fixture()
def trio(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    other = _new_session(running_server, monkeypatch, "other", tmp_path)
    _verify(admin, member)
    _verify(member, admin)
    _verify(admin, other)
    _verify(other, admin)
    yield admin, member, other
    for session in (admin, member, other):
        session.disconnect()


def test_removing_a_member_records_one_event_with_the_real_actor_and_subject(trio):
    admin, member, other = trio
    live = _record_events(member)
    conversation_id = _group(admin, [member, other], "Removal Group")

    assert admin.remove_group_member(conversation_id, other.username).get("success") is True

    assert _wait_for(lambda: len(live) == 1)
    assert _events_in_db(conversation_id) == [("member_removed", admin.username, other.username)]
    live_conversation, event = live[0]
    assert live_conversation == conversation_id
    assert (event["event_type"], event["actor"], event["subject"]) == ("member_removed", admin.username, other.username)
    assert event["event_id"] and event["timestamp"] is not None

    # The same event is what history returns to a remaining member -- same id, so a client shows it once.
    error, events, raw = _history_events(member, conversation_id)
    assert error is None
    assert events == [("member_removed", admin.username, other.username)]
    assert raw[0]["event_id"] == event["event_id"]


def test_a_member_leaving_records_a_leave_by_that_member(trio):
    admin, member, other = trio
    live = _record_events(admin)
    conversation_id = _group(admin, [member, other], "Leave Group")

    member.leave_group_conversation(conversation_id)

    assert _wait_for(lambda: len(live) == 1)
    assert _events_in_db(conversation_id) == [("member_left", member.username, member.username)]
    assert live[0][1]["actor"] == live[0][1]["subject"] == member.username


def test_an_admin_add_records_the_admin_as_actor_and_the_new_member_as_subject(trio, running_server, monkeypatch, tmp_path):
    admin, member, other = trio
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    _verify(admin, candidate)
    _verify(candidate, admin)
    live = _record_events(member)
    outsider_live = _record_events(candidate)
    conversation_id = _group(admin, [member, other], "Add Group")
    try:
        # Not yet a member: nothing about this group is sent to the candidate.
        assert admin.remove_group_member(conversation_id, other.username).get("success")
        assert _wait_for(lambda: len(live) == 1)
        assert outsider_live == []

        admin.add_group_members(conversation_id, [candidate.username])

        assert _wait_for(lambda: len(live) == 2)
        assert _events_in_db(conversation_id) == [
            ("member_removed", admin.username, other.username),
            ("member_added", admin.username, candidate.username),
        ]
        assert (live[1][1]["event_type"], live[1][1]["actor"], live[1][1]["subject"]) == (
            "member_added", admin.username, candidate.username
        )

        # The newly added member sees only what happened from the moment they joined -- the earlier
        # removal of somebody else is not shown to them.
        assert _wait_for(lambda: _history_events(candidate, conversation_id)[0] is None)
        _error, events, _raw = _history_events(candidate, conversation_id)
        assert events == [("member_added", admin.username, candidate.username)]

        # A member who was there throughout sees both, oldest first.
        _error, events, _raw = _history_events(member, conversation_id)
        assert events == [
            ("member_removed", admin.username, other.username),
            ("member_added", admin.username, candidate.username),
        ]
    finally:
        candidate.disconnect()


def test_an_approved_add_request_names_the_approving_admin_as_the_actor(trio, running_server, monkeypatch, tmp_path):
    admin, member, other = trio
    candidate = _new_session(running_server, monkeypatch, "cand", tmp_path)
    try:
        conversation_id = _group(admin, [member, other], "Approval Group")
        live = _record_events(other)

        member.add_group_members(conversation_id, [candidate.username])     # a non-admin only asks
        assert _wait_for(lambda: _inbox_notification_for(admin, member, "group_add_request") is not None)
        assert _events_in_db(conversation_id) == []                          # asking records nothing
        notification = _inbox_notification_for(admin, member, "group_add_request")

        admin.respond_to_inbox(notification, True)

        assert _wait_for(lambda: len(live) == 1)
        # The admin performed the add (by approving); the requester is not the actor.
        assert _events_in_db(conversation_id) == [("member_added", admin.username, candidate.username)]
    finally:
        candidate.disconnect()


def test_repeated_or_refused_actions_record_nothing_more(trio):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Idempotent Group")

    assert admin.remove_group_member(conversation_id, other.username).get("success") is True
    assert admin.remove_group_member(conversation_id, other.username).get("success") is False   # already gone
    assert member.remove_group_member(conversation_id, admin.username).get("success") is False  # not the admin
    assert admin.remove_group_member(conversation_id, admin.username).get("success") is False   # the admin stays
    admin.add_group_members(conversation_id, [member.username])                                  # already a member
    time.sleep(0.5)
    _app.processEvents()
    member.leave_group_conversation(conversation_id)
    member.leave_group_conversation(conversation_id)                                              # a second leave

    assert _wait_for(lambda: len(_events_in_db(conversation_id)) == 2)
    time.sleep(0.5)
    assert _events_in_db(conversation_id) == [
        ("member_removed", admin.username, other.username),
        ("member_left", member.username, member.username),
    ]


def test_a_removed_member_and_a_non_member_are_never_shown_the_events(trio, running_server, monkeypatch, tmp_path):
    admin, member, other = trio
    outsider = _new_session(running_server, monkeypatch, "out", tmp_path)
    try:
        outsider_live = _record_events(outsider)
        conversation_id = _group(admin, [member, other], "Private Group")
        assert admin.remove_group_member(conversation_id, other.username).get("success")
        time.sleep(0.6)

        # Refused, with no events, for the person removed and for someone never in the group.
        for non_member in (other, outsider):
            error, events, _raw = _history_events(non_member, conversation_id)
            assert error == "Not a member of this conversation."
            assert events == []
        assert outsider_live == []

        # (Repository level: an out-of-group user's list is empty, whatever they ask.)
        from database.repositories.group_event_repository import GroupEventRepository
        db = SessionLocal()
        try:
            import uuid
            assert GroupEventRepository(db).list_visible_to(uuid.UUID(conversation_id), uuid.UUID(other.user_id)) == []
        finally:
            db.close()
    finally:
        outsider.disconnect()


def test_a_rejoining_member_is_not_shown_what_happened_while_they_were_out(trio):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Rejoin Group")
    assert admin.remove_group_member(conversation_id, other.username).get("success")
    assert admin.remove_group_member(conversation_id, member.username).get("success")      # happens while 'other' is out
    time.sleep(0.3)

    admin.add_group_members(conversation_id, [other.username])

    assert _wait_for(lambda: len(_events_in_db(conversation_id)) == 3)
    assert _wait_for(lambda: _history_events(other, conversation_id)[0] is None)
    _error, events, _raw = _history_events(other, conversation_id)
    assert events == [("member_added", admin.username, other.username)]


def test_a_chat_message_that_looks_like_an_event_is_only_a_message(trio):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Forgery Group")
    before = _events_in_db(conversation_id)
    live = _record_events(other)

    # Group text claiming a removal is just text; nothing but the server's own membership handlers
    # ever writes an event.
    admin.set_current_chat(admin.conversation_store.get(conversation_id))
    admin.send_chat_message("alice removed bob")

    time.sleep(0.6)
    assert _events_in_db(conversation_id) == before
    assert live == []


def test_malformed_events_on_the_wire_are_dropped_by_the_client(trio):
    admin, _member, _other = trio
    clean = admin._clean_group_event

    assert clean(None) is None
    assert clean("member_removed") is None
    assert clean({"event_type": "member_removed", "event_id": "1"}) is None                     # no subject
    assert clean({"event_type": "ban", "event_id": "1", "subject": "x"}) is None                # unknown type
    assert clean({"event_type": "member_left", "subject": "x"}) is None                         # no id
    kept = clean({"event_type": "member_left", "event_id": "e1", "subject": "x", "actor": "x",
                  "timestamp": "2026-10-21T10:00:00", "text": "<b>forged</b>", "extra": 1})
    assert set(kept) == {"event_id", "event_type", "actor", "subject", "timestamp"}              # nothing free-form survives
