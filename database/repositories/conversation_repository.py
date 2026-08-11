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

from collections import namedtuple
from datetime import datetime, timezone

from sqlalchemy import and_, func, select
from sqlalchemy.orm import aliased

from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.models.message import Message
from database.models.user import User
from database.repositories.base_repository import BaseRepository


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale -- duplicated here rather than
    shared, matching this codebase's existing per-file convention.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

# One row per conversation this user belongs to: the Conversation
# itself, its latest Message (None if it has none yet), and the
# User rows of every other member (a list, not a scalar, so a future
# group conversation's multiple other participants need no redesign
# of this shape).
ConversationPreview = namedtuple(
    "ConversationPreview", ["conversation", "latest_message", "participants"]
)


class ConversationRepository(BaseRepository):
    """Repository for conversation lookup and creation."""

    def get_or_create_direct_conversation(self, user_a_id, user_b_id):
        """
        Return the existing direct conversation between these two
        users, creating it (plus both memberships) if none exists yet.

        Argument order does not matter -- the same conversation is
        returned regardless of which user is passed first.
        """

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

    def _create_conversation(self, conversation_type, member_user_ids, name=None):
        """
        Create a conversation of the given type with one
        ConversationMember row per user id.

        Generic over member count, type, and (Phase 4) name -- this is
        the exact extension point named since Phase 1;
        create_group_conversation() below is its first real caller.
        """

        conversation = Conversation(type=conversation_type, name=name)
        self.add(conversation)

        for user_id in member_user_ids:
            self.add(
                ConversationMember(
                    conversation_id=conversation.id,
                    user_id=user_id,
                )
            )

        return conversation

    def create_group_conversation(self, member_ids, name):
        """
        Create a new "group" conversation with the given members
        (the creator's own id is expected to already be included in
        member_ids by the caller). Reuses _create_conversation() --
        the same generic helper get_or_create_direct_conversation()
        already uses -- unchanged.
        """

        return self._create_conversation(Conversation.TYPE_GROUP, member_ids, name=name)

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
        Return every active conversation this user belongs to, each
        paired with its latest message (if any) and its other
        participant(s), ordered by latest activity (most recent
        message first; a conversation with no messages yet sorts by
        its own creation time).

        Two queries total, regardless of how many conversations the
        user has: the latest-message-per-conversation lookup uses a
        window function, so no message history is loaded into Python
        to be sorted here, and participants are resolved in a single
        batched query. Both are designed to be reused, not rewritten,
        once group conversations, unread counts, pinning, and
        archiving are added -- those only add a WHERE/ORDER BY term to
        this same shape.
        """

        member_conversation_ids = select(ConversationMember.conversation_id).where(
            ConversationMember.user_id == user_id,
            ConversationMember.left_at.is_(None),
        )

        rank = (
            func.row_number()
            .over(
                partition_by=Message.conversation_id,
                order_by=Message.timestamp.desc(),
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
            .where(Conversation.id.in_(member_conversation_ids))
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

        return [
            ConversationPreview(
                conversation=conversation,
                latest_message=message,
                participants=participants_by_conversation.get(conversation.id, []),
            )
            for conversation, message in rows
        ]

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
