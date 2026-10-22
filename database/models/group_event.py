"""
Group membership events: "Alice added Bob", "Bob left", "Alice removed Carol".

One row per membership change, written by the SERVER in the same transaction as the change itself
(see server/client_handler.py::handle_group_leave()/handle_group_remove_member()/
_perform_group_add_members()), never from anything a client sends. The actor and the subject are
resolved from authenticated identities (the connection that asked, and the membership row that
changed), so a client cannot forge "X removed Y" by typing it: clients render these from the
structured fields with a fixed sentence and never display free text from a peer.

The usernames are kept as a snapshot next to the ids so an old event still reads correctly if an
account is later renamed or removed (the id columns are SET NULL on user deletion for the same
reason). Events are shown, in order, to members from the moment they joined; a non-member -- and a
member for the period they were not one -- is never sent them.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime -- see database/models/message.py's identical helper."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class GroupEvent(Base):
    """One membership change in one group conversation."""

    TYPE_MEMBER_ADDED = "member_added"
    TYPE_MEMBER_LEFT = "member_left"
    TYPE_MEMBER_REMOVED = "member_removed"

    TYPES = (TYPE_MEMBER_ADDED, TYPE_MEMBER_LEFT, TYPE_MEMBER_REMOVED)

    __tablename__ = "group_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)

    conversation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    event_type = Column(String(32), nullable=False)

    # Who did it (the admin who added/removed; the member themself for a leave) and who it is about.
    actor_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    subject_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_username = Column(String(255), nullable=True)
    subject_username = Column(String(255), nullable=False)

    created_at = Column(DateTime, nullable=False, default=_utc_now, index=True)

    def __repr__(self):
        return (
            f"<GroupEvent(conversation_id={self.conversation_id}, type={self.event_type}, "
            f"actor={self.actor_username}, subject={self.subject_username})>"
        )
