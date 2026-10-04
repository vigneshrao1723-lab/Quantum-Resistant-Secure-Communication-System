"""
Inbox notification model (Phase 19.13 -- User Manual Feedback
Implementation).

The first persisted, cross-session "thing a user must see and act on
later" in this schema -- before this phase, nothing like it existed
(verification was always independent/local on each side, and group
membership changes were always immediate, self-service actions with
no approval step). Backs two workflows with one shape:

- verification_request: USER A asks USER B to verify A's identity.
  Approving does NOT itself perform the cryptographic verification --
  that stays exactly ClientSession.confirm_combined_peer_
  verification(), called locally by B's own client using the
  fingerprint it has already observed. This table only ever records
  who asked whom and what B decided.

- group_add_request: a non-admin group member asks the group's admin
  to add a candidate. Approving runs the SAME server-side add-member +
  group-key-distribution path an admin's own direct add already uses
  (server/client_handler.py::_perform_group_add_members()) -- this
  table only gates WHETHER that path runs, never re-implements it.

``status`` transitions exactly once, pending -> approved|denied
(InboxRepository.resolve() only ever updates a still-pending row --
see its own docstring for how that is what makes a second Approve/Deny
on the same notification a safe no-op rather than a repeat action).
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime -- see auth/
    authentication_service.py's identical helper for the full
    rationale."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


TYPE_VERIFICATION_REQUEST = "verification_request"
TYPE_GROUP_ADD_REQUEST = "group_add_request"

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"


class InboxNotification(Base):
    """One pending-or-resolved request a user must approve or deny."""

    __tablename__ = "inbox_notifications"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    type = Column(String(32), nullable=False)
    status = Column(String(16), nullable=False, default=STATUS_PENDING)

    # Who must act on this (verification_request: the person being
    # asked to verify; group_add_request: the group's admin).
    recipient_user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Who triggered it (verification_request: the person asking to be
    # verified; group_add_request: the non-admin member who wants to
    # add someone). Notified of the outcome once resolved.
    requester_user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # group_add_request only -- NULL for verification_request.
    conversation_id = Column(
        UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=True,
    )
    candidate_user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )

    created_at = Column(DateTime, nullable=False, default=_utc_now)
    resolved_at = Column(DateTime, nullable=True)

    recipient = relationship("User", foreign_keys=[recipient_user_id])
    requester = relationship("User", foreign_keys=[requester_user_id])
    candidate = relationship("User", foreign_keys=[candidate_user_id])
    conversation = relationship("Conversation")

    def __repr__(self):
        return (
            f"<InboxNotification(id={self.id}, type={self.type}, "
            f"status={self.status}, recipient_user_id={self.recipient_user_id})>"
        )
