"""
Tests for database/repositories/conversation_repository.py.

Runs against the real PostgreSQL database via the db_session fixture,
which wraps each test in a rolled-back transaction (see conftest.py).

Run with:
    pytest tests/test_conversation_repository.py -v
"""

import uuid
from datetime import datetime, timezone

from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.user_repository import UserRepository
from domain.message_delivery_status import MessageDeliveryStatus


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_user(repo, unique_suffix, tag):
    user = repo.create(
        username=f"convrepo_{tag}_{unique_suffix}",
        email=f"convrepo_{tag}_{unique_suffix}@example.com",
        display_name="Conversation Repo Test User",
        password_hash="irrelevant-hash-for-repo-tests",
        phone_number=f"+91{uuid.uuid4().int % 10**12:012d}",
    )
    repo.commit()
    return user


def test_creates_direct_conversation_with_both_members(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    conversation = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_b.id
    )
    conversation_repo.commit()

    assert conversation.id is not None
    assert conversation.type == Conversation.TYPE_DIRECT

    members = (
        db_session.query(ConversationMember)
        .filter(ConversationMember.conversation_id == conversation.id)
        .all()
    )
    member_user_ids = {member.user_id for member in members}

    assert member_user_ids == {user_a.id, user_b.id}
    assert all(member.role == ConversationMember.ROLE_MEMBER for member in members)


def test_second_call_returns_same_conversation(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    first = conversation_repo.get_or_create_direct_conversation(user_a.id, user_b.id)
    conversation_repo.commit()

    second = conversation_repo.get_or_create_direct_conversation(user_a.id, user_b.id)
    conversation_repo.commit()

    assert first.id == second.id


def test_lookup_is_symmetric_in_argument_order(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    created = conversation_repo.get_or_create_direct_conversation(user_a.id, user_b.id)
    conversation_repo.commit()

    found = conversation_repo.get_or_create_direct_conversation(user_b.id, user_a.id)
    conversation_repo.commit()

    assert created.id == found.id


def test_different_user_pairs_get_different_conversations(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation_ab = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_b.id
    )
    conversation_repo.commit()

    conversation_ac = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_c.id
    )
    conversation_repo.commit()

    assert conversation_ab.id != conversation_ac.id


def test_preview_excludes_direct_conversation_with_no_messages(db_session, unique_suffix):
    """UI Finalization Decision 1: a direct conversation row can exist
    (get_or_create_direct_conversation() creates one the moment either
    side merely OPENS a chat -- see ClientSession.set_current_chat())
    with zero real activity. It must not be returned here, or it would
    make an empty conversation appear in the sidebar merely because it
    was opened once -- see get_conversation_previews_for_user()'s
    docstring. This replaces the previous version of this test, which
    asserted the opposite (pre-Decision-1) behavior."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    conversation_repo.get_or_create_direct_conversation(user_a.id, user_b.id)
    conversation_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(user_a.id)

    assert previews == []


def test_preview_excludes_messageless_conversation_for_either_participant(
    db_session, unique_suffix
):
    """The exclusion isn't one-sided -- neither participant sees an
    unmessaged direct conversation, not just the one who happened to
    open it first."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    conversation_repo.get_or_create_direct_conversation(user_a.id, user_b.id)
    conversation_repo.commit()

    assert conversation_repo.get_conversation_previews_for_user(user_a.id) == []
    assert conversation_repo.get_conversation_previews_for_user(user_b.id) == []


def test_preview_includes_group_conversation_with_no_messages(db_session, unique_suffix):
    """The exclusion is scoped to direct conversations only -- a group
    is always eagerly created with real membership (never a lazy,
    merely-opened placeholder the way a direct conversation can be),
    so it must appear immediately, before its first message."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation = conversation_repo.create_group_conversation(
        member_ids=[user_a.id, user_b.id, user_c.id], name="Fresh Group"
    )
    conversation_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(user_a.id)

    assert len(previews) == 1
    assert previews[0].conversation.id == conversation.id
    assert previews[0].latest_message is None


def test_direct_conversation_appears_once_a_message_exists(db_session, unique_suffix):
    """The other half of Decision 1: once real activity exists, the
    same conversation that was excluded above is included -- and stays
    included across a fresh preview query, standing in for
    'survives reload/reconnect' at the repository level (the query has
    no session-scoped state to lose between calls)."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    conversation = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_b.id
    )
    conversation_repo.commit()

    assert conversation_repo.get_conversation_previews_for_user(user_a.id) == []

    message_repo.save_message(
        sender_id=user_a.id,
        receiver_id=user_b.id,
        conversation_id=conversation.id,
        ciphertext="the first real message",
        algorithm="KYBER",
        timestamp=_utc_now(),
    )
    message_repo.commit()

    previews_after = conversation_repo.get_conversation_previews_for_user(user_a.id)
    previews_after_again = conversation_repo.get_conversation_previews_for_user(user_a.id)

    assert len(previews_after) == 1
    assert previews_after[0].conversation.id == conversation.id
    assert len(previews_after_again) == 1
    assert previews_after_again[0].conversation.id == conversation.id


def test_preview_includes_latest_message_and_participant(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    conversation = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_b.id
    )
    conversation_repo.commit()

    message_repo.save_message(
        sender_id=user_b.id,
        receiver_id=user_a.id,
        conversation_id=conversation.id,
        ciphertext="ciphertext-preview-1",
        algorithm="KYBER",
        timestamp=_utc_now(),
    )
    message_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(user_a.id)

    assert len(previews) == 1
    assert previews[0].latest_message.ciphertext == "ciphertext-preview-1"
    assert [user.id for user in previews[0].participants] == [user_b.id]


def test_preview_returns_only_the_latest_message(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    conversation = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_b.id
    )
    conversation_repo.commit()

    older = _utc_now().replace(2026, 1, 1, 10, 0, 0)
    newer = _utc_now().replace(2026, 1, 1, 10, 5, 0)

    message_repo.save_message(
        sender_id=user_a.id,
        receiver_id=user_b.id,
        conversation_id=conversation.id,
        ciphertext="older-message",
        algorithm="KYBER",
        timestamp=older,
    )
    message_repo.save_message(
        sender_id=user_b.id,
        receiver_id=user_a.id,
        conversation_id=conversation.id,
        ciphertext="newer-message",
        algorithm="KYBER",
        timestamp=newer,
    )
    message_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(user_a.id)

    assert len(previews) == 1
    assert previews[0].latest_message.ciphertext == "newer-message"


def test_previews_ordered_by_latest_activity(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation_ab = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_b.id
    )
    conversation_ac = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_c.id
    )
    conversation_repo.commit()

    message_repo.save_message(
        sender_id=user_a.id,
        receiver_id=user_b.id,
        conversation_id=conversation_ab.id,
        ciphertext="to-b",
        algorithm="KYBER",
        timestamp=_utc_now().replace(2026, 1, 1, 9, 0, 0),
    )
    message_repo.save_message(
        sender_id=user_a.id,
        receiver_id=user_c.id,
        conversation_id=conversation_ac.id,
        ciphertext="to-c",
        algorithm="KYBER",
        timestamp=_utc_now().replace(2026, 1, 1, 9, 5, 0),
    )
    message_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(user_a.id)

    assert [preview.conversation.id for preview in previews] == [
        conversation_ac.id,
        conversation_ab.id,
    ]


# ----------------------------------------------------------------------
# Phase 4: Secure Group Messaging Foundation
# ----------------------------------------------------------------------


def test_create_group_conversation_has_type_group_and_name(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation = conversation_repo.create_group_conversation(
        member_ids=[user_a.id, user_b.id, user_c.id], name="Trio"
    )
    conversation_repo.commit()

    assert conversation.type == Conversation.TYPE_GROUP
    assert conversation.name == "Trio"

    members = (
        db_session.query(ConversationMember)
        .filter(ConversationMember.conversation_id == conversation.id)
        .all()
    )
    assert {m.user_id for m in members} == {user_a.id, user_b.id, user_c.id}


def test_get_member_user_ids_returns_all_active_members(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation = conversation_repo.create_group_conversation(
        member_ids=[user_a.id, user_b.id, user_c.id], name="Trio"
    )
    conversation_repo.commit()

    member_ids = conversation_repo.get_member_user_ids(conversation.id)

    assert set(member_ids) == {user_a.id, user_b.id, user_c.id}


def test_direct_conversation_creation_unaffected_by_name_parameter(
    db_session, unique_suffix
):
    """get_or_create_direct_conversation() must still create a nameless
    direct conversation exactly as before -- create_group_conversation()
    is additive, not a replacement."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")

    conversation = conversation_repo.get_or_create_direct_conversation(
        user_a.id, user_b.id
    )
    conversation_repo.commit()

    assert conversation.type == Conversation.TYPE_DIRECT
    assert conversation.name is None


def test_get_group_conversation_returns_messages_in_order(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation = conversation_repo.create_group_conversation(
        member_ids=[user_a.id, user_b.id, user_c.id], name="Trio"
    )
    conversation_repo.commit()

    message_repo.save_message(
        sender_id=user_a.id,
        receiver_id=user_a.id,
        conversation_id=conversation.id,
        ciphertext="first",
        algorithm="KYBER",
        timestamp=_utc_now().replace(2026, 1, 1, 10, 0, 0),
    )
    message_repo.save_message(
        sender_id=user_b.id,
        receiver_id=user_b.id,
        conversation_id=conversation.id,
        ciphertext="second",
        algorithm="KYBER",
        timestamp=_utc_now().replace(2026, 1, 1, 10, 5, 0),
    )
    message_repo.commit()

    messages = message_repo.get_group_conversation(conversation.id)

    assert [m.ciphertext for m in messages] == ["first", "second"]
    # Exactly one row per logical message -- no per-recipient duplication.
    assert len(messages) == 2


def test_record_recipients_marks_connected_members_delivered(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation = conversation_repo.create_group_conversation(
        member_ids=[user_a.id, user_b.id, user_c.id], name="Trio"
    )
    conversation_repo.commit()

    message = message_repo.save_message(
        sender_id=user_a.id,
        receiver_id=user_a.id,
        conversation_id=conversation.id,
        ciphertext="hello group",
        algorithm="KYBER",
        timestamp=_utc_now(),
    )

    message_repo.record_recipients(
        message.id,
        recipient_ids=[user_b.id, user_c.id],
        delivered_recipient_ids=[user_b.id],
    )
    message_repo.commit()

    recipients = message_repo.get_recipients_for_message(message.id)
    status_by_recipient = {r.recipient_id: r.status for r in recipients}

    assert status_by_recipient[user_b.id] == MessageDeliveryStatus.DELIVERED
    assert status_by_recipient[user_c.id] == MessageDeliveryStatus.QUEUED
    assert user_a.id not in status_by_recipient


# ----------------------------------------------------------------------
# BUG -- Offline Unread/Notification
# ----------------------------------------------------------------------


def test_preview_unread_count_reflects_not_yet_read_messages(db_session, unique_suffix):
    """The core case: 3 messages queued for Bob while he was offline,
    none of them READ yet -- his preview must report unread_count=3."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    alice = _make_user(user_repo, unique_suffix, "alice")
    bob = _make_user(user_repo, unique_suffix, "bob")

    conversation = conversation_repo.get_or_create_direct_conversation(
        alice.id, bob.id
    )
    conversation_repo.commit()

    for index in range(3):
        message = message_repo.save_message(
            sender_id=alice.id,
            receiver_id=bob.id,
            conversation_id=conversation.id,
            ciphertext=f"offline message {index}",
            algorithm="KYBER",
            timestamp=_utc_now(),
        )
        message_repo.record_recipients(
            message.id, recipient_ids=[bob.id], delivered_recipient_ids=[]
        )
    message_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(bob.id)

    assert len(previews) == 1
    assert previews[0].unread_count == 3


def test_preview_unread_count_excludes_already_read_messages(db_session, unique_suffix):
    """A message already marked READ (e.g. from an earlier session)
    must not be counted, regardless of how many times the preview is
    fetched afterwards -- proves this reads live status, not a cached
    "was ever queued" signal."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    alice = _make_user(user_repo, unique_suffix, "alice")
    bob = _make_user(user_repo, unique_suffix, "bob")

    conversation = conversation_repo.get_or_create_direct_conversation(
        alice.id, bob.id
    )
    conversation_repo.commit()

    message = message_repo.save_message(
        sender_id=alice.id,
        receiver_id=bob.id,
        conversation_id=conversation.id,
        ciphertext="already read",
        algorithm="KYBER",
        timestamp=_utc_now(),
    )
    message_repo.record_recipients(
        message.id, recipient_ids=[bob.id], delivered_recipient_ids=[]
    )
    message_repo.commit()

    message_repo.mark_conversation_read(conversation.id, bob.id)
    message_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(bob.id)

    assert len(previews) == 1
    assert previews[0].unread_count == 0


def test_preview_unread_count_never_counts_the_senders_own_messages(
    db_session, unique_suffix
):
    """Alice's own sent messages must never inflate HER unread count --
    record_recipients() never creates a MessageRecipient row for the
    sender, so this holds by construction; verified directly rather
    than assumed."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    alice = _make_user(user_repo, unique_suffix, "alice")
    bob = _make_user(user_repo, unique_suffix, "bob")

    conversation = conversation_repo.get_or_create_direct_conversation(
        alice.id, bob.id
    )
    conversation_repo.commit()

    message = message_repo.save_message(
        sender_id=alice.id,
        receiver_id=bob.id,
        conversation_id=conversation.id,
        ciphertext="alice's own message",
        algorithm="KYBER",
        timestamp=_utc_now(),
    )
    message_repo.record_recipients(
        message.id, recipient_ids=[bob.id], delivered_recipient_ids=[]
    )
    message_repo.commit()

    alice_previews = conversation_repo.get_conversation_previews_for_user(alice.id)

    assert len(alice_previews) == 1
    assert alice_previews[0].unread_count == 0


def test_preview_unread_counts_are_independent_per_conversation(
    db_session, unique_suffix
):
    """Bob has 2 unread from Alice and 5 unread from Charlie -- the two
    counts must not bleed into each other, and this must hold from a
    single batched query (not accidentally summing across
    conversations)."""
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)
    message_repo = MessageRepository(db_session)

    alice = _make_user(user_repo, unique_suffix, "alice")
    bob = _make_user(user_repo, unique_suffix, "bob")
    charlie = _make_user(user_repo, unique_suffix, "charlie")

    alice_conversation = conversation_repo.get_or_create_direct_conversation(
        alice.id, bob.id
    )
    charlie_conversation = conversation_repo.get_or_create_direct_conversation(
        charlie.id, bob.id
    )
    conversation_repo.commit()

    for index in range(2):
        message = message_repo.save_message(
            sender_id=alice.id,
            receiver_id=bob.id,
            conversation_id=alice_conversation.id,
            ciphertext=f"from alice {index}",
            algorithm="KYBER",
            timestamp=_utc_now(),
        )
        message_repo.record_recipients(
            message.id, recipient_ids=[bob.id], delivered_recipient_ids=[]
        )

    for index in range(5):
        message = message_repo.save_message(
            sender_id=charlie.id,
            receiver_id=bob.id,
            conversation_id=charlie_conversation.id,
            ciphertext=f"from charlie {index}",
            algorithm="KYBER",
            timestamp=_utc_now(),
        )
        message_repo.record_recipients(
            message.id, recipient_ids=[bob.id], delivered_recipient_ids=[]
        )

    message_repo.commit()

    previews = {
        preview.conversation.id: preview.unread_count
        for preview in conversation_repo.get_conversation_previews_for_user(bob.id)
    }

    assert previews[alice_conversation.id] == 2
    assert previews[charlie_conversation.id] == 5


# ----------------------------------------------------------------------
# Phase 7: Group Membership Management
# ----------------------------------------------------------------------


def _make_trio_group(db_session, unique_suffix):
    user_repo = UserRepository(db_session)
    conversation_repo = ConversationRepository(db_session)

    user_a = _make_user(user_repo, unique_suffix, "a")
    user_b = _make_user(user_repo, unique_suffix, "b")
    user_c = _make_user(user_repo, unique_suffix, "c")

    conversation = conversation_repo.create_group_conversation(
        member_ids=[user_a.id, user_b.id, user_c.id], name="Trio"
    )
    conversation_repo.commit()

    return conversation_repo, conversation, user_a, user_b, user_c


def test_leave_conversation_sets_left_at(db_session, unique_suffix):
    conversation_repo, conversation, _a, _b, user_c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.leave_conversation(conversation.id, user_c.id)
    conversation_repo.commit()

    member = (
        db_session.query(ConversationMember)
        .filter(
            ConversationMember.conversation_id == conversation.id,
            ConversationMember.user_id == user_c.id,
        )
        .one()
    )

    assert member.left_at is not None


def test_leave_conversation_excludes_member_from_active_list(db_session, unique_suffix):
    conversation_repo, conversation, user_a, user_b, user_c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.leave_conversation(conversation.id, user_c.id)
    conversation_repo.commit()

    member_ids = conversation_repo.get_member_user_ids(conversation.id)

    assert set(member_ids) == {user_a.id, user_b.id}
    assert user_c.id not in member_ids


def test_leave_conversation_excludes_member_from_previews(db_session, unique_suffix):
    """Bonus, self-healing property: the departed member's own next
    preview query already excludes the group, independent of any live
    notification packet -- verified directly, not assumed."""
    conversation_repo, conversation, _a, _b, user_c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.leave_conversation(conversation.id, user_c.id)
    conversation_repo.commit()

    previews = conversation_repo.get_conversation_previews_for_user(user_c.id)

    assert previews == []


def test_leave_conversation_is_idempotent(db_session, unique_suffix):
    """A second leave attempt for an already-departed member matches
    no active-membership row and is a safe no-op -- it must not raise,
    and must not disturb the already-set left_at."""
    conversation_repo, conversation, _a, _b, user_c = _make_trio_group(
        db_session, unique_suffix
    )

    first = conversation_repo.leave_conversation(conversation.id, user_c.id)
    conversation_repo.commit()

    second = conversation_repo.leave_conversation(conversation.id, user_c.id)
    conversation_repo.commit()

    assert first is not None
    assert second is None

    member = (
        db_session.query(ConversationMember)
        .filter(
            ConversationMember.conversation_id == conversation.id,
            ConversationMember.user_id == user_c.id,
        )
        .one()
    )
    assert member.left_at == first.left_at


def test_leave_conversation_for_non_member_is_a_no_op(db_session, unique_suffix):
    conversation_repo, conversation, _a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    user_repo = UserRepository(db_session)
    outsider = _make_user(user_repo, unique_suffix, "outsider")

    result = conversation_repo.leave_conversation(conversation.id, outsider.id)
    conversation_repo.commit()

    assert result is None


def test_new_group_conversation_starts_at_epoch_1(db_session, unique_suffix):
    conversation_repo, conversation, _a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    current, confirmed = conversation_repo.get_epoch_state(conversation.id)

    assert current == 1
    assert confirmed == 1


def test_reserve_next_epoch_increments_current_key_epoch(db_session, unique_suffix):
    conversation_repo, conversation, _a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    new_epoch = conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.commit()

    assert new_epoch == 2

    current, confirmed = conversation_repo.get_epoch_state(conversation.id)
    assert current == 2
    assert confirmed == 1


def test_reserve_next_epoch_twice_reaches_epoch_3(db_session, unique_suffix):
    """Two leaves before either rotation completes: current_key_epoch
    must advance sequentially, 1 -> 2 -> 3, never skipping."""
    conversation_repo, conversation, _a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.commit()

    current, confirmed = conversation_repo.get_epoch_state(conversation.id)
    assert current == 3
    assert confirmed == 1


def test_confirm_epoch_advances_confirmed_key_epoch(db_session, unique_suffix):
    conversation_repo, conversation, _a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.commit()

    result = conversation_repo.confirm_epoch(conversation.id, 2)
    conversation_repo.commit()

    assert result == 2

    current, confirmed = conversation_repo.get_epoch_state(conversation.id)
    assert current == 2
    assert confirmed == 2


def test_confirm_epoch_never_regresses(db_session, unique_suffix):
    """A stale or duplicate completion signal (an epoch lower than
    what's already confirmed) must not move confirmed_key_epoch
    backwards."""
    conversation_repo, conversation, _a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.commit()

    conversation_repo.confirm_epoch(conversation.id, 3)
    conversation_repo.commit()

    result = conversation_repo.confirm_epoch(conversation.id, 2)
    conversation_repo.commit()

    assert result == 3

    _current, confirmed = conversation_repo.get_epoch_state(conversation.id)
    assert confirmed == 3


def test_get_group_conversations_with_pending_rotation_finds_outstanding(
    db_session, unique_suffix
):
    conversation_repo, conversation, user_a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.commit()

    pending = conversation_repo.get_group_conversations_with_pending_rotation(
        user_a.id
    )

    assert conversation.id in pending


def test_get_group_conversations_with_pending_rotation_excludes_caught_up(
    db_session, unique_suffix
):
    conversation_repo, conversation, user_a, _b, _c = _make_trio_group(
        db_session, unique_suffix
    )

    pending = conversation_repo.get_group_conversations_with_pending_rotation(
        user_a.id
    )

    assert conversation.id not in pending


def test_get_group_conversations_with_pending_rotation_excludes_departed_member(
    db_session, unique_suffix
):
    """A member who has left must not be told to rotate a group they
    are no longer part of."""
    conversation_repo, conversation, _a, _b, user_c = _make_trio_group(
        db_session, unique_suffix
    )

    conversation_repo.leave_conversation(conversation.id, user_c.id)
    conversation_repo.reserve_next_epoch(conversation.id)
    conversation_repo.commit()

    pending = conversation_repo.get_group_conversations_with_pending_rotation(
        user_c.id
    )

    assert conversation.id not in pending
