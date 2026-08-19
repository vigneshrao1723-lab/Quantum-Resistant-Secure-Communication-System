"""
Message repository.
"""

from sqlalchemy import func, or_, select

from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.models.message import Message
from database.models.message_recipient import MessageRecipient
from database.repositories.base_repository import BaseRepository
from domain.message_delivery_status import MessageDeliveryStatus


class MessageRepository(BaseRepository):
    """Repository for private message persistence."""

    def save_message(self, **kwargs):
        message = Message(**kwargs)
        self.add(message)
        return message

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
            .order_by(Message.timestamp)
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
            .order_by(Message.timestamp)
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
