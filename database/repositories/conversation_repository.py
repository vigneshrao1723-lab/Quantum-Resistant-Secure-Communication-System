"""
Conversation repository.

The lookup/creation abstraction for conversations -- the addressing
unit messaging is built around (Architecture Blueprint v2, S01/S10).

Phase 1 only ever creates two-member "direct" conversations, through
get_or_create_direct_conversation(). _create_conversation() is written
generically over a conversation type and a list of member user ids so
a future create_group_conversation() can reuse it without rewriting
this file.

Phase 2 (Conversation List Foundation) adds
get_conversation_previews_for_user() -- the read side of the sidebar,
returning each of a user's conversations paired with its latest
message and other participant(s) in two efficient, set-based queries.

Phase 7 (Group Membership Management) adds leave_conversation() and
the group-key-epoch bookkeeping methods (reserve_next_epoch(),
get_epoch_state(), confirm_epoch(), get_group_conversations_with_pending_rotation())
-- all operating on the existing ConversationMember.left_at column and
the new Conversation.current_key_epoch/confirmed_key_epoch columns,
never a second membership-state mechanism.

A later real-application bug-fix pass adds add_members() (Issue 2 --
add members to an existing group, reusing the exact same epoch-
rotation machinery a leave already uses) and
get_active_group_conversation_ids() (Issue 4 -- reconnect key
recovery), both still built on left_at/current_key_epoch/
confirmed_key_epoch alone.
"""

import hashlib
from collections import namedtuple
from datetime import datetime, timezone

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import aliased

from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.models.message import Message
from database.models.message_recipient import MessageRecipient
from database.models.user import User
from database.repositories.base_repository import BaseRepository
from domain.message_delivery_status import MessageDeliveryStatus


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale -- duplicated here rather than
    shared, matching this codebase's existing per-file convention.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _direct_conversation_lock_key(user_a_id, user_b_id):
    """
    A deterministic, order-independent 64-bit signed integer for
    pg_advisory_xact_lock() (D3.1 -- Conversation Operations
    Migration), derived from the two users' ids sorted into a
    canonical order first -- so concurrent calls with the arguments
    swapped still contend for the exact same lock, matching
    get_or_create_direct_conversation()'s own documented "argument
    order does not matter" contract.

    Application-level locking rather than a schema change: nothing in
    the current conversations/conversation_members tables prevents two
    concurrent check-then-insert calls from both finding "no existing
    conversation" for the same pair and both creating one (their only
    unique constraint is per-membership-row, (conversation_id,
    user_id), which says nothing about *which* conversation two users
    end up in). A partial unique index encoding "at most one direct
    conversation per unordered pair" would fix this too, but requires
    a migration and a place to store the canonical pair; this achieves
    the same safety with no schema change, which is all that's needed
    now that every direct-conversation creation funnels through this
    one method (server-side, D3.1) rather than being spread across
    independent, uncoordinated client processes as before.
    """

    sorted_ids = sorted([str(user_a_id), str(user_b_id)])
    digest = hashlib.sha256("|".join(sorted_ids).encode("utf-8")).digest()

    return int.from_bytes(digest[:8], "big", signed=True)

# One row per conversation this user belongs to: the Conversation
# itself, its latest Message (None if it has none yet), the User rows
# of every other member (a list, not a scalar, so a future group
# conversation's multiple other participants need no redesign of this
# shape), and how many of this user's own MessageRecipient rows in it
# are not yet READ (BUG -- Offline Unread/Notification).
ConversationPreview = namedtuple(
    "ConversationPreview",
    ["conversation", "latest_message", "participants", "unread_count"],
)


class ConversationRepository(BaseRepository):
    """Repository for conversation lookup and creation."""

    def get_or_create_direct_conversation(self, user_a_id, user_b_id):
        """
        Return the existing direct conversation between these two
        users, creating it (plus both memberships) if none exists yet.

        Argument order does not matter -- the same conversation is
        returned regardless of which user is passed first.

        Concurrency (D3.1 -- Conversation Operations Migration): takes
        a transaction-scoped Postgres advisory lock keyed on this pair
        (see _direct_conversation_lock_key()) before the check-then-
        insert below, so two concurrent calls for the same pair -- now
        a real possibility once this is called from the server on
        behalf of two different connections, rather than only ever
        from one client's own decentralized, uncoordinated process --
        serialize instead of racing to both create a conversation. The
        second caller blocks until the first commits (or rolls back),
        then its own _find_direct_conversation() call, running under
        Postgres's default READ COMMITTED isolation, sees the first
        caller's now-committed row and returns it instead of creating
        a duplicate. pg_advisory_xact_lock() releases automatically at
        transaction end (commit, rollback, or connection loss) -- no
        manual unlock, no risk of a lock stuck past its caller's
        commit()/rollback().
        """

        lock_key = _direct_conversation_lock_key(user_a_id, user_b_id)

        self.db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": lock_key})

        existing = self._find_direct_conversation(user_a_id, user_b_id)

        if existing is not None:
            return existing

        return self._create_conversation(
            Conversation.TYPE_DIRECT,
            [user_a_id, user_b_id],
        )

    def _find_direct_conversation(self, user_a_id, user_b_id):
        """
        Return the "direct" conversation whose members include both
        given users, or None. Only "direct" conversations are
        considered, and (by construction -- nothing in this phase
        adds a third member to one) a "direct" conversation always has
        exactly these two members once both are matched.
        """

        user_a_conversation_ids = select(ConversationMember.conversation_id).where(
            ConversationMember.user_id == user_a_id
        )

        statement = (
            select(Conversation)
            .join(
                ConversationMember,
                ConversationMember.conversation_id == Conversation.id,
            )
            .where(
                Conversation.type == Conversation.TYPE_DIRECT,
                Conversation.id.in_(user_a_conversation_ids),
                ConversationMember.user_id == user_b_id,
            )
        )

        return self.db.scalar(statement)

    def _create_conversation(self, conversation_type, member_user_ids, name=None, admin_user_id=None):
        """
        Create a conversation of the given type with one
        ConversationMember row per user id.

        Generic over member count, type, and (Phase 4) name -- this is
        the exact extension point named since Phase 1;
        create_group_conversation() below is its first real caller.

        ``admin_user_id`` (Phase 19.13 -- Group Admin): when given,
        that one member's row gets ROLE_ADMIN instead of the default
        ROLE_MEMBER -- every other member is unaffected. None for a
        direct conversation (get_or_create_direct_conversation() never
        passes it): admin/member has no meaning for a two-party direct
        chat.
        """

        conversation = Conversation(type=conversation_type, name=name)
        self.add(conversation)

        for user_id in member_user_ids:
            role = (
                ConversationMember.ROLE_ADMIN
                if admin_user_id is not None and user_id == admin_user_id
                else ConversationMember.ROLE_MEMBER
            )
            self.add(
                ConversationMember(
                    conversation_id=conversation.id,
                    user_id=user_id,
                    role=role,
                )
            )

        return conversation

    def create_group_conversation(self, member_ids, name, creator_id=None):
        """
        Create a new "group" conversation with the given members
        (the creator's own id is expected to already be included in
        member_ids by the caller). Reuses _create_conversation() --
        the same generic helper get_or_create_direct_conversation()
        already uses -- unchanged.

        ``creator_id`` (Phase 19.13 -- Group Admin): the member
        recorded as this group's ROLE_ADMIN. The group always has
        exactly one admin from creation onward -- nothing in this
        phase adds a second one or transfers the role. Optional
        (defaults to None, i.e. no admin recorded -- every member gets
        the plain ROLE_MEMBER default, matching this method's
        behavior before this phase) purely so every pre-existing
        direct caller of this repository method in the test suite
        keeps working unchanged; the real production path (server/
        client_handler.py::handle_group_create()) always passes it.
        """

        return self._create_conversation(
            Conversation.TYPE_GROUP, member_ids, name=name, admin_user_id=creator_id,
        )

    def get_admin_user_id(self, conversation_id):
        """
        Return the active admin's user id for a group conversation, or
        None if it has none (a direct conversation, or -- should never
        happen by construction -- a group whose admin has left without
        the role ever transferring). Server-side authorization checks
        (remove-member, approve member-add request) call this rather
        than trusting anything client-supplied.
        """

        statement = select(ConversationMember.user_id).where(
            ConversationMember.conversation_id == conversation_id,
            ConversationMember.role == ConversationMember.ROLE_ADMIN,
            ConversationMember.left_at.is_(None),
        )

        return self.db.scalar(statement)

    def get_member_user_ids(self, conversation_id):
        """
        Return the user ids of every active member of a conversation.
        """

        statement = select(ConversationMember.user_id).where(
            ConversationMember.conversation_id == conversation_id,
            ConversationMember.left_at.is_(None),
        )

        return list(self.db.scalars(statement).all())

    def leave_conversation(self, conversation_id, user_id):
        """
        Mark an active member as having left -- sets left_at exactly
        once (Phase 7 -- Group Membership Management). Idempotent: a
        second call for a user who has already left (or never was an
        active member) matches no row and is a safe no-op, mirroring
        UserRepository's mutate-then-flush pattern (e.g.
        update_last_login()).

        Every existing query that filters left_at.is_(None)
        (get_member_user_ids(), get_conversation_previews_for_user(),
        _get_other_participants()) automatically excludes this member
        afterward -- no other method needs to change.
        """

        statement = select(ConversationMember).where(
            ConversationMember.conversation_id == conversation_id,
            ConversationMember.user_id == user_id,
            ConversationMember.left_at.is_(None),
        )

        member = self.db.scalar(statement)

        if member is None:
            return None

        member.left_at = _utc_now()

        self.refresh(member)

        return member

    def reserve_next_epoch(self, conversation_id):
        """
        Reserve the next group-key epoch -- increments
        current_key_epoch by exactly one (Phase 7 -- Group Membership
        Management). Must be called in the same transaction as
        leave_conversation() for the same leave event (see
        server/client_handler.py::handle_group_leave()) so the
        membership change and the epoch reservation either both
        commit or neither does -- a departed member excluded from
        messaging without a reserved next epoch would leave the group
        silently stuck on its old key forever.
        """

        conversation = self.db.get(Conversation, conversation_id)

        if conversation is None:
            return None

        conversation.current_key_epoch += 1

        self.refresh(conversation)

        return conversation.current_key_epoch

    def get_epoch_state(self, conversation_id):
        """
        Return (current_key_epoch, confirmed_key_epoch) for a
        conversation, or (None, None) if it doesn't exist.
        """

        conversation = self.db.get(Conversation, conversation_id)

        if conversation is None:
            return None, None

        return conversation.current_key_epoch, conversation.confirmed_key_epoch

    def confirm_epoch(self, conversation_id, epoch):
        """
        Advance confirmed_key_epoch to at least ``epoch`` -- never
        decreases it (Phase 7 -- Group Membership Management), so a
        stale or duplicate group_key_rotation_complete cannot regress
        state. Mirrors the max()-based guard KeyManager.store_key()
        uses for current_epoch, for the same reason.
        """

        conversation = self.db.get(Conversation, conversation_id)

        if conversation is None:
            return None

        conversation.confirmed_key_epoch = max(
            conversation.confirmed_key_epoch, epoch
        )

        self.refresh(conversation)

        return conversation.confirmed_key_epoch

    def get_group_conversations_with_pending_rotation(self, user_id):
        """
        Return the ids of every group conversation this user is an
        active member of where confirmed_key_epoch is behind
        current_key_epoch -- a rotation reserved by a leave event that
        hasn't finished distributing yet (Phase 7 -- Group Membership
        Management). Used only by the reconnect-recovery hook in
        server/client_handler.py::handle_client().
        """

        member_conversation_ids = select(ConversationMember.conversation_id).where(
            ConversationMember.user_id == user_id,
            ConversationMember.left_at.is_(None),
        )

        statement = select(Conversation.id).where(
            Conversation.id.in_(member_conversation_ids),
            Conversation.type == Conversation.TYPE_GROUP,
            Conversation.current_key_epoch > Conversation.confirmed_key_epoch,
        )

        return list(self.db.scalars(statement).all())

    def get_active_group_conversation_ids(self, user_id):
        """
        Return the ids of every group conversation this user is
        currently an active member of, unfiltered by epoch state
        (real-application bug fix: "add members"/reconnect key
        recovery both need the full set, not just the ones with a
        pending rotation -- see
        get_group_conversations_with_pending_rotation() for that
        narrower, Phase-7-specific query this one is a sibling to).
        """

        member_conversation_ids = select(ConversationMember.conversation_id).where(
            ConversationMember.user_id == user_id,
            ConversationMember.left_at.is_(None),
        )

        statement = select(Conversation.id).where(
            Conversation.id.in_(member_conversation_ids),
            Conversation.type == Conversation.TYPE_GROUP,
        )

        return list(self.db.scalars(statement).all())

    def add_members(self, conversation_id, user_ids):
        """
        Add users to an existing group conversation (real-application
        bug fix: "add members after creation" -- Issue 2). Reuses
        ConversationMember/left_at exactly as leave_conversation()
        does, never a second membership mechanism:

        - a user_id with no existing row gets a fresh one (a genuinely
          new member);
        - a user_id whose existing row has left_at set is rejoining --
          left_at is cleared rather than inserting a second row, since
          (conversation_id, user_id) is uniquely constrained;
        - a user_id already an active member (left_at IS NULL) is a
          no-op.

        Returns the list of user_ids actually added or rejoined --
        excludes already-active members -- so the caller knows whether
        anything actually changed (and therefore whether a key epoch
        needs reserving).
        """

        existing_rows = {
            member.user_id: member
            for member in self.db.scalars(
                select(ConversationMember).where(
                    ConversationMember.conversation_id == conversation_id,
                    ConversationMember.user_id.in_(user_ids),
                )
            ).all()
        }

        affected = []

        for user_id in user_ids:

            row = existing_rows.get(user_id)

            if row is None:

                self.add(
                    ConversationMember(
                        conversation_id=conversation_id,
                        user_id=user_id,
                    )
                )

                affected.append(user_id)

            elif row.left_at is not None:

                row.left_at = None

                affected.append(user_id)

            # else: already an active member -- no-op.

        return affected

    def get_conversation_previews_for_user(self, user_id):
        """
        Return every INITIALIZED conversation this user belongs to,
        each paired with its latest message and its other
        participant(s), ordered by latest activity (most recent
        message first).

        "Initialized" is deliberately narrower than "exists in the
        database": a direct conversation row is created the moment
        either side opens a chat with someone never messaged before
        (ConversationRepository.get_or_create_direct_conversation()),
        purely so a conversation_id is available for key-manager/epoch
        setup before anything is actually sent -- see
        ClientSession.set_current_chat(). That row must not appear in
        the sidebar merely because it exists; a direct conversation is
        excluded here unless it has at least one real message. A group
        conversation has no such lazy-creation window (it is always
        created eagerly, already populated with members, via an
        explicit create-group action) and is therefore always
        included regardless of message count.

        Two queries total, regardless of how many conversations the
        user has: the latest-message-per-conversation lookup uses a
        window function, so no message history is loaded into Python
        to be sorted here, and participants are resolved in a single
        batched query. Both are designed to be reused, not rewritten,
        once unread counts, pinning, and archiving are added -- those
        only add a WHERE/ORDER BY term to this same shape.
        """

        member_conversation_ids = select(ConversationMember.conversation_id).where(
            ConversationMember.user_id == user_id,
            ConversationMember.left_at.is_(None),
        )

        rank = (
            func.row_number()
            .over(
                partition_by=Message.conversation_id,
                # Phase 19.18: same client-suppliable-timestamp tie as
                # MessageRepository.get_conversation() -- created_at
                # (server-assigned, never client input) breaks ties in
                # true receipt order so the sidebar preview always
                # shows the actually-most-recent message.
                order_by=(Message.timestamp.desc(), Message.created_at.desc()),
            )
            .label("rank")
        )

        ranked_messages = (
            select(Message, rank)
            .where(Message.conversation_id.in_(member_conversation_ids))
            .subquery()
        )

        latest_message = aliased(Message, ranked_messages)

        statement = (
            select(Conversation, latest_message)
            .outerjoin(
                ranked_messages,
                and_(
                    ranked_messages.c.conversation_id == Conversation.id,
                    ranked_messages.c.rank == 1,
                ),
            )
            .where(
                Conversation.id.in_(member_conversation_ids),
                or_(
                    Conversation.type == Conversation.TYPE_GROUP,
                    ranked_messages.c.id.isnot(None),
                ),
            )
            .order_by(
                func.coalesce(
                    ranked_messages.c.timestamp, Conversation.created_at
                ).desc()
            )
        )

        rows = self.db.execute(statement).all()

        conversation_ids = [conversation.id for conversation, _ in rows]
        participants_by_conversation = self._get_other_participants(
            conversation_ids, user_id
        )
        unread_counts_by_conversation = self._get_unread_counts(
            conversation_ids, user_id
        )

        return [
            ConversationPreview(
                conversation=conversation,
                latest_message=message,
                participants=participants_by_conversation.get(conversation.id, []),
                unread_count=unread_counts_by_conversation.get(conversation.id, 0),
            )
            for conversation, message in rows
        ]

    def _get_unread_counts(self, conversation_ids, user_id):
        """
        Return {conversation_id: count} of not-yet-READ MessageRecipient
        rows belonging to ``user_id``, across the given conversations
        (BUG -- Offline Unread/Notification).

        Reuses MessageRecipient/MessageDeliveryStatus exactly as
        MessageRepository.mark_conversation_read() (C2 -- Read
        Receipts) already does -- same join through Message (
        MessageRecipient has no conversation_id column of its own),
        same status field, no new table, no new write path. This is
        the read side of state that read-receipt handling already
        writes; a message a recipient has already read (on this
        session or a previous one) is therefore never counted here,
        regardless of when the login happens.

        One batched query for every conversation in the list, not one
        per conversation -- GROUP BY conversation_id, same shape as
        _get_other_participants() alongside it.
        """

        if not conversation_ids:
            return {}

        statement = (
            select(Message.conversation_id, func.count(MessageRecipient.id))
            .join(MessageRecipient, MessageRecipient.message_id == Message.id)
            .where(
                Message.conversation_id.in_(conversation_ids),
                MessageRecipient.recipient_id == user_id,
                MessageRecipient.status != MessageDeliveryStatus.READ,
            )
            .group_by(Message.conversation_id)
        )

        return dict(self.db.execute(statement).all())

    def _get_other_participants(self, conversation_ids, excluding_user_id):
        """
        Return every other member's User row for the given
        conversations in one query, grouped by conversation id.
        Already returns a list per conversation rather than a single
        row, so a group conversation's multiple other participants
        need no redesign here.
        """

        if not conversation_ids:
            return {}

        statement = (
            select(ConversationMember.conversation_id, User)
            .join(User, User.id == ConversationMember.user_id)
            .where(
                ConversationMember.conversation_id.in_(conversation_ids),
                ConversationMember.user_id != excluding_user_id,
                ConversationMember.left_at.is_(None),
            )
        )

        grouped = {}

        for conversation_id, user in self.db.execute(statement).all():
            grouped.setdefault(conversation_id, []).append(user)

        return grouped
