"""
Message repository.
"""

from sqlalchemy import or_, select

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
