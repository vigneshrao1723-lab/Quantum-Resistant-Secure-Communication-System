"""
Message repository.
"""

from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.models.message import Message
from database.models.message_hidden_for_user import MessageHiddenForUser
from database.models.message_reaction import MessageReaction
from database.models.message_recipient import MessageRecipient
from database.repositories.base_repository import BaseRepository
from domain.message_delivery_status import MessageDeliveryStatus


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class MessageRepository(BaseRepository):
    """Repository for private message persistence."""

    def save_message(self, **kwargs):
        message = Message(**kwargs)
        self.add(message)
        return message

    def save_message_idempotent(self, **kwargs):
        """
        Phase 19.24 -- Message Retry idempotency. Identical to
        save_message(), except a UNIQUE-constraint collision on
        client_message_id (a client-generated UUID a sender optionally
        attaches to a live send -- see database/models/message.py::
        client_message_id's own docstring) is treated as "this exact
        send already succeeded", not an error: the caller's retry
        after an ambiguous network failure gets back the ALREADY-
        persisted row instead of creating a duplicate message.

        A no-op (returns None) when client_message_id was not
        supplied at all -- there is nothing to deduplicate against,
        identical to save_message()'s behavior for every pre-Phase-
        19.24 caller.

        Callers MUST call self.db.flush() (this uses self.add(), which
        already does) inside a savepoint-safe context; on IntegrityError
        this method rolls back only to before its own flush attempt
        (via a nested transaction) so the caller's surrounding
        transaction is not aborted.
        """

        client_message_id = kwargs.get("client_message_id")

        if not client_message_id:
            return self.save_message(**kwargs), False

        existing = self.db.scalar(
            select(Message).where(Message.client_message_id == client_message_id)
        )

        if existing is not None:
            return existing, True

        try:
            with self.db.begin_nested():
                message = Message(**kwargs)
                self.db.add(message)
                self.db.flush()
        except IntegrityError:
            # A genuine race: two concurrent requests for the SAME
            # client_message_id both passed the SELECT above before
            # either flushed. The loser here simply re-reads what the
            # winner just committed -- still a correct, idempotent
            # result, not an error surfaced to the caller.
            existing = self.db.scalar(
                select(Message).where(Message.client_message_id == client_message_id)
            )
            if existing is None:
                raise
            return existing, True

        return message, False

    def get_message(self, message_id):
        statement = select(Message).where(Message.id == message_id)
        return self.db.scalar(statement)

    def get_conversation(self, user_a_id, user_b_id):
        statement = (
            select(Message)
            .where(
                or_(
                    (Message.sender_id == user_a_id)
                    & (Message.receiver_id == user_b_id),
                    (Message.sender_id == user_b_id)
                    & (Message.receiver_id == user_a_id),
                )
            )
            # Phase 19.18: Message.timestamp is client-supplied (see
            # server/client_handler.py::_parse_message_timestamp()) --
            # two messages sent in quick succession from the same
            # client can round-trip through JSON with an identical
            # value (e.g. web/client's millisecond-resolution
            # `Date.toISOString()`), and a single-column ORDER BY gives
            # ties no defined order. Message.created_at is never
            # client-suppliable -- always the server-side
            # datetime.now() default assigned when this row is
            # persisted -- and since one connection's packets are
            # always handled by one thread in strict arrival order
            # (docs/architecture/server_architecture.md, Concurrency),
            # it reflects true receipt order even when `timestamp`
            # ties. Kept as a secondary key, not primary, so a
            # legitimately later message with an earlier client
            # timestamp (e.g. clock skew across devices) still sorts
            # by when it was actually sent in the common case.
            .order_by(Message.timestamp, Message.created_at)
        )
        return self.db.scalars(statement).all()

    def get_group_conversation(self, conversation_id):
        """
        Return every message sent in a group conversation, in
        chronological order. Content is stored once per logical
        message (Phase 4 -- Secure Group Messaging Foundation), so
        unlike get_conversation() this needs no sender/receiver pair
        and no de-duplication -- a plain filter on conversation_id.
        """

        statement = (
            select(Message)
            .where(Message.conversation_id == conversation_id)
            # Phase 19.18: see get_conversation()'s identical comment --
            # created_at breaks a timestamp tie using true server
            # receipt order.
            .order_by(Message.timestamp, Message.created_at)
        )
        return self.db.scalars(statement).all()

    def record_recipients(self, message_id, recipient_ids, delivered_recipient_ids):
        """
        Record one MessageRecipient row per recipient of a group
        message, separate from the message's content -- the delivery-
        state table future read receipts extend additively (see
        domain/message_delivery_status.py).

        recipient_ids: every member who should receive this message
        (excluding the sender). delivered_recipient_ids: the subset
        who were connected and actually relayed to at send time.
        """

        delivered = set(delivered_recipient_ids)

        for recipient_id in recipient_ids:
            status = (
                MessageDeliveryStatus.DELIVERED
                if recipient_id in delivered
                else MessageDeliveryStatus.QUEUED
            )
            self.add(
                MessageRecipient(
                    message_id=message_id,
                    recipient_id=recipient_id,
                    status=status,
                )
            )

    def mark_delivered(self, message_id, recipient_ids):
        """
        Upgrade QUEUED -> DELIVERED for the given recipients of one
        message, and only for them (BUG 2 -- read-receipt relay race).

        Recipient rows are now written BEFORE the message is relayed,
        so that the row a read receipt needs always exists by the time
        the recipient could possibly send one. They are created QUEUED
        -- "persisted, not yet live-delivered" -- and this promotes
        exactly those recipients the relay actually reached.

        READ is terminal with respect to delivery status, and the
        ``status == QUEUED`` filter below is what enforces that: a row
        the recipient has already read is simply not selected, so a
        read receipt that lands in the gap between row creation and
        this promotion can never be downgraded back to DELIVERED. That
        ordering is real -- it is the whole reason the rows are written
        early -- so this is a guard against a reachable state, not a
        theoretical one.

        Filtering on QUEUED also makes this idempotent: a row already
        DELIVERED is not re-selected and its updated_at is not bumped.

        Returns the recipient ids actually promoted (empty if there was
        nothing to promote), so a caller can log what happened without
        a second query.
        """

        recipient_ids = list(recipient_ids)

        if not recipient_ids:
            return []

        statement = select(MessageRecipient).where(
            MessageRecipient.message_id == message_id,
            MessageRecipient.recipient_id.in_(recipient_ids),
            MessageRecipient.status == MessageDeliveryStatus.QUEUED,
        )

        rows = self.db.scalars(statement).all()

        for row in rows:
            row.status = MessageDeliveryStatus.DELIVERED

        return [row.recipient_id for row in rows]

    def get_recipients_for_message(self, message_id):
        """
        Return every MessageRecipient row for a message. No caller in
        Phase 4 -- this is the read-side surface a future delivery/
        read-receipts phase uses, present now so that phase needs no
        repository redesign.
        """

        statement = select(MessageRecipient).where(
            MessageRecipient.message_id == message_id
        )
        return self.db.scalars(statement).all()

    def get_direct_conversation_epochs_for_user(self, user_id, conversation_id=None):
        """
        Return ``{conversation_id: [epochs]}`` -- every key epoch the
        user's accessible DIRECT message history is encrypted under
        (BUG 4 -- Fix B), epochs ascending.

        Authorization is CONVERSATION MEMBERSHIP, deliberately, and
        that choice is what makes this correct where the first
        attempt was not. Driving recovery from MessageRecipient rows
        (status == QUEUED) had two defects that membership fixes at
        once:

          * A queued message that has been read is no longer QUEUED,
            so on the next restart its epoch was never recovered and
            history the user had already read went permanently dark.
          * A user's own SENT messages have no MessageRecipient row
            of their own at all, so the sender could never recover
            the epochs needed to read their own history.

        Membership is also exactly the authorization model
        handle_message_history_request() already enforces for reading
        these same messages, so this grants no access to anything the
        user could not already fetch. It needs no new rows, and
        specifically no fabricated MessageRecipient entries.

        Derived from messages.epoch -- the epoch each specific message
        was actually encrypted under -- and never from the
        conversation's current_key_epoch. Those are routinely
        different: ClientSession.establish_session_key() reserves a
        BRAND-NEW epoch every time a client needs a key it doesn't
        have cached, so a direct conversation accumulates one epoch
        per key establishment, and a conversation sitting at epoch 5
        can easily hold messages at epochs 2 and 3. Substituting the
        current epoch would hand the user a key that decrypts none of
        their history.

        NULL epoch reads as 1 -- the same NULL->1 normalization
        Message.epoch documents and every other reader of that column
        already applies. It is a true statement about rows written
        before the column existed, not a convenient default.

        A conversation with no messages yields no entry: the join to
        messages is what puts a conversation in the result at all, so
        an empty conversation can never trigger recovery.

        ``conversation_id`` optionally narrows the query to one
        conversation -- used server-side to validate that the epochs a
        client asks to recover are really referenced by that
        conversation's messages, rather than numbers it made up.

        Restricted to TYPE_DIRECT: group conversations have their own
        reconnect recovery
        (_ensure_group_keys_current_for_reconnecting_user), and
        running both over the same rows would duplicate dispatches
        without changing the outcome.

        Read-only. Returns coordination metadata only -- conversation
        ids and epoch numbers, never key material, of which the server
        holds none.
        """

        epoch = func.coalesce(Message.epoch, 1)

        filters = [
            ConversationMember.user_id == user_id,
            ConversationMember.left_at.is_(None),
            Conversation.type == Conversation.TYPE_DIRECT,
            Message.conversation_id.is_not(None),
        ]

        if conversation_id is not None:
            filters.append(Message.conversation_id == conversation_id)

        statement = (
            select(Message.conversation_id, epoch)
            .join(Conversation, Conversation.id == Message.conversation_id)
            .join(
                ConversationMember,
                ConversationMember.conversation_id == Conversation.id,
            )
            .where(*filters)
            .distinct()
            .order_by(Message.conversation_id, epoch)
        )

        required = {}

        for row_conversation_id, row_epoch in self.db.execute(statement).all():
            required.setdefault(row_conversation_id, []).append(int(row_epoch))

        return required

    def mark_conversation_read(self, conversation_id, recipient_id):
        """
        Transition every not-yet-READ MessageRecipient row belonging
        to ``recipient_id``, in ``conversation_id``, to READ (C2 --
        Read Receipts). Reuses MessageRecipient/MessageDeliveryStatus
        exactly as they already exist -- no schema change, no new
        table; MessageRecipient has no conversation_id column of its
        own, so this joins through Message to reach it.

        Security: restricted to rows matching BOTH conversation_id AND
        recipient_id -- the caller (server/client_handler.py::
        handle_read_receipt()) must pass only the authenticated
        connection's own user id here, never a client-supplied one, so
        this can never touch another user's row regardless of what a
        malicious client sends. Already-READ rows are left untouched
        (filtered out, not just idempotently re-set) so updated_at
        isn't bumped for no reason.

        Returns the list of message_ids actually transitioned (empty
        if there was nothing new to mark) -- the caller uses this to
        decide whether a read_receipt_notification is even worth
        sending.
        """

        statement = (
            select(MessageRecipient)
            .join(Message, MessageRecipient.message_id == Message.id)
            .where(
                Message.conversation_id == conversation_id,
                MessageRecipient.recipient_id == recipient_id,
                MessageRecipient.status != MessageDeliveryStatus.READ,
            )
        )

        rows = self.db.scalars(statement).all()

        message_ids = []

        for row in rows:
            row.status = MessageDeliveryStatus.READ
            message_ids.append(row.message_id)

        return message_ids

    # ==================================================================
    # Phase 19.24 -- Message Lifecycle Events
    # ==================================================================

    def apply_edit(self, message, ciphertext, content_metadata, epoch, message_signature):
        """
        Overwrite ``message``'s content in place and bump its edit
        bookkeeping. Authorization (actor == message.sender_id) and
        edit_version staleness checks are the CALLER's responsibility
        (server/client_handler.py::handle_message_edit()) -- this
        method only performs the mutation, exactly like every other
        repository method in this class leaves authorization to its
        caller (see mark_conversation_read()'s identical division of
        responsibility).

        Same logical message_id, never a new row -- there is no
        "second fake message" for an edit.
        """

        message.ciphertext = ciphertext
        message.content_metadata = content_metadata
        message.epoch = epoch
        message.message_signature = message_signature
        message.edited_at = _utc_now()
        message.edit_version += 1

        return message

    def apply_delete_for_everyone(self, message, deleted_by_user_id):
        """
        REAL data minimization, not a soft UI flag: nulls the
        columns that actually reconstruct plaintext (ciphertext,
        content_metadata, message_signature) -- blob_ref is left for
        the caller to read BEFORE calling this (so it can still delete
        the referenced encrypted_blob_store file) and is nulled here
        too, after. deleted_at/deleted_by are the only things that
        survive, for UI attribution and for history filtering to
        recognize this row as "deleted" rather than merely empty.
        """

        message.ciphertext = None
        message.content_metadata = None
        message.message_signature = None
        message.blob_ref = None
        message.deleted_at = _utc_now()
        message.deleted_by = deleted_by_user_id

        return message

    def hide_for_user(self, message_id, user_id):
        """
        "Delete for me" (database/models/message_hidden_for_user.py).
        Idempotent: a second hide request for an already-hidden
        message is a silent no-op, never a duplicate-row error.
        """

        existing = self.db.scalar(
            select(MessageHiddenForUser).where(
                MessageHiddenForUser.message_id == message_id,
                MessageHiddenForUser.user_id == user_id,
            )
        )

        if existing is not None:
            return existing

        return self.add(MessageHiddenForUser(message_id=message_id, user_id=user_id))

    def get_hidden_message_ids_for_user(self, user_id, message_ids):
        """
        Which of ``message_ids`` this user has hidden for themself --
        used to filter history/search results. Scoped to a specific
        set of ids (rather than "every hidden message ever") so a
        caller already holding one conversation's message list can
        filter it with a single indexed query.
        """

        if not message_ids:
            return set()

        statement = select(MessageHiddenForUser.message_id).where(
            MessageHiddenForUser.user_id == user_id,
            MessageHiddenForUser.message_id.in_(message_ids),
        )
        return set(self.db.scalars(statement).all())

    def upsert_reaction(self, message_id, user_id, ciphertext, epoch, message_signature=None):
        """
        Set/replace ``user_id``'s reaction on ``message_id`` (add
        semantics -- a user has at most one active reaction per
        message; adding a new one replaces, never stacks, the old
        one). Returns the row. ``message_signature`` (continued Phase
        19.24 -- receiver-side verification) is persisted alongside
        the ciphertext so history recovery can verify it too, not only
        a live notification.
        """

        existing = self.db.scalar(
            select(MessageReaction).where(
                MessageReaction.message_id == message_id,
                MessageReaction.user_id == user_id,
            )
        )

        if existing is not None:
            existing.ciphertext = ciphertext
            existing.epoch = epoch
            existing.message_signature = message_signature
            existing.updated_at = _utc_now()
            return existing

        return self.add(
            MessageReaction(
                message_id=message_id, user_id=user_id,
                ciphertext=ciphertext, epoch=epoch,
                message_signature=message_signature,
            )
        )

    def remove_reaction(self, message_id, user_id):
        """Remove ``user_id``'s reaction on ``message_id``, if any.
        Returns True if a row was actually removed (so the caller
        knows whether a reaction_updated notification is worth
        sending), False if there was nothing to remove."""

        existing = self.db.scalar(
            select(MessageReaction).where(
                MessageReaction.message_id == message_id,
                MessageReaction.user_id == user_id,
            )
        )

        if existing is None:
            return False

        self.delete(existing)
        return True

    def pin_message(self, message_id, user_id):
        """
        Mark ``message_id`` pinned by ``user_id``. Idempotent-ish: a
        re-pin (already pinned, by anyone) simply overwrites pinned_at/
        pinned_by to reflect this latest pin action -- mirrors
        upsert_reaction()'s own "replace, never stack" semantics.
        Authorization (active conversation membership) is the CALLER's
        responsibility (server/client_handler.py::handle_message_pin()),
        exactly like apply_edit()'s identical division of
        responsibility. Returns the row, or None if message_id does not
        exist.
        """

        message = self.get_message(message_id)

        if message is None:
            return None

        message.pinned_at = _utc_now()
        message.pinned_by = user_id

        return message

    def unpin_message(self, message_id):
        """
        Clear message_id's pin state. Idempotent: unpinning an already-
        unpinned message is a silent no-op. Returns the row, or None if
        message_id does not exist.
        """

        message = self.get_message(message_id)

        if message is None:
            return None

        message.pinned_at = None
        message.pinned_by = None

        return message

    def get_pinned_messages(self, conversation_id):
        """
        Every currently-pinned message in a conversation, most-
        recently-pinned first -- the server-side source of truth
        handle_pinned_messages_list_request() answers with, so a
        client (including one just reconnecting, or a newly-authorized
        device with no local history of its own yet) can always
        recover the CURRENT pinned set rather than relying only on live
        message_pinned/message_unpinned notifications it may have
        missed while offline.
        """

        statement = (
            select(Message)
            .where(
                Message.conversation_id == conversation_id,
                Message.pinned_at.is_not(None),
            )
            .order_by(Message.pinned_at.desc())
        )
        return self.db.scalars(statement).all()

    def get_reactions_for_messages(self, message_ids):
        """
        {message_id: [(user_id, ciphertext, epoch, message_signature), ...]}
        for every reaction on any of ``message_ids`` -- used by history
        reload to restore reaction state (Phase 19.24's own "history
        recovery" requirement) in one batched query rather than one per
        message.
        """

        if not message_ids:
            return {}

        statement = select(MessageReaction).where(
            MessageReaction.message_id.in_(message_ids)
        )

        by_message = {}
        for row in self.db.scalars(statement).all():
            by_message.setdefault(row.message_id, []).append(
                (row.user_id, row.ciphertext, row.epoch, row.message_signature)
            )
        return by_message
