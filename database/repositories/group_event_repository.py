"""Group membership events: record one per change, list the ones a member may see."""

from sqlalchemy import select

from database.models.conversation_member import ConversationMember
from database.models.group_event import GroupEvent
from database.repositories.base_repository import BaseRepository


class GroupEventRepository(BaseRepository):

    def record(self, conversation_id, event_type, subject_user_id, subject_username,
               actor_user_id=None, actor_username=None):
        """Add (not commit) one event -- call it in the same transaction as the membership change."""

        if event_type not in GroupEvent.TYPES:
            raise ValueError(f"Unknown group event type: {event_type!r}")

        event = GroupEvent(
            conversation_id=conversation_id,
            event_type=event_type,
            subject_user_id=subject_user_id,
            subject_username=subject_username,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
        )

        self.add(event)
        self.db.flush()

        return event

    def list_visible_to(self, conversation_id, user_id):
        """
        The events ``user_id`` may be shown for this group, oldest first: only while they are an
        active member, and only those from the moment they (last) joined -- never what happened
        before they were in the group or while they were out of it.
        """

        member = self.db.scalar(
            select(ConversationMember).where(
                ConversationMember.conversation_id == conversation_id,
                ConversationMember.user_id == user_id,
                ConversationMember.left_at.is_(None),
            )
        )

        if member is None:
            return []

        statement = (
            select(GroupEvent)
            .where(
                GroupEvent.conversation_id == conversation_id,
                GroupEvent.created_at >= member.joined_at,
            )
            .order_by(GroupEvent.created_at.asc(), GroupEvent.id.asc())
        )

        return list(self.db.scalars(statement).all())
