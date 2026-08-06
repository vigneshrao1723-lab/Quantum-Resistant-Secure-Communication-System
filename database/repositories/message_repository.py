"""
Message repository.
"""

from sqlalchemy import or_, select

from database.models.message import Message
from database.repositories.base_repository import BaseRepository


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
