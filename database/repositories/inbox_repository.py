"""
Inbox notification repository (Phase 19.13 -- User Manual Feedback
Implementation).

See database/models/inbox_notification.py's own docstring for what
this backs. Duplicate-request protection lives here, not in the
server handler: create_verification_request()/create_group_add_
request() each check for an existing PENDING row for the same
(requester, recipient[, candidate]) combination before inserting a
new one, so pressing the same "Verify"/"Add" action twice in a row
(a double-tap, a retried request) never creates two separate
approvable items for the same thing.
"""

from datetime import datetime, timezone

from sqlalchemy import select

from database.models.inbox_notification import (
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_PENDING,
    TYPE_GROUP_ADD_REQUEST,
    TYPE_VERIFICATION_REQUEST,
    InboxNotification,
)
from database.repositories.base_repository import BaseRepository


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime -- see auth/
    authentication_service.py's identical helper for the full
    rationale."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class InboxRepository(BaseRepository):

    def create_verification_request(self, requester_id, recipient_id):
        """
        Create a pending verification_request from ``requester_id`` to
        ``recipient_id``, or return the existing pending one
        unchanged if the same pair already has one outstanding
        (duplicate protection -- see this module's own docstring).
        """

        existing = self.db.scalar(
            select(InboxNotification).where(
                InboxNotification.type == TYPE_VERIFICATION_REQUEST,
                InboxNotification.status == STATUS_PENDING,
                InboxNotification.requester_user_id == requester_id,
                InboxNotification.recipient_user_id == recipient_id,
            )
        )

        if existing is not None:
            return existing

        return self.add(
            InboxNotification(
                type=TYPE_VERIFICATION_REQUEST,
                status=STATUS_PENDING,
                requester_user_id=requester_id,
                recipient_user_id=recipient_id,
            )
        )

    def create_group_add_request(self, requester_id, admin_id, conversation_id, candidate_id):
        """
        Create a pending group_add_request from ``requester_id`` (a
        non-admin member) addressed to ``admin_id``, asking to add
        ``candidate_id`` to ``conversation_id``. Returns the existing
        pending one unchanged if this exact (conversation, candidate)
        pair already has one outstanding, regardless of who requested
        it -- there is never a need for two simultaneous pending
        requests to add the same person to the same group.
        """

        existing = self.db.scalar(
            select(InboxNotification).where(
                InboxNotification.type == TYPE_GROUP_ADD_REQUEST,
                InboxNotification.status == STATUS_PENDING,
                InboxNotification.conversation_id == conversation_id,
                InboxNotification.candidate_user_id == candidate_id,
            )
        )

        if existing is not None:
            return existing

        return self.add(
            InboxNotification(
                type=TYPE_GROUP_ADD_REQUEST,
                status=STATUS_PENDING,
                requester_user_id=requester_id,
                recipient_user_id=admin_id,
                conversation_id=conversation_id,
                candidate_user_id=candidate_id,
            )
        )

    def get_for_user(self, user_id):
        """
        Every notification (pending or resolved) where ``user_id`` is
        EITHER the recipient (something to act on) or the original
        requester (their own sent requests, so they can see the
        outcome of one that was approved/denied while they were
        offline), newest first.
        """

        statement = (
            select(InboxNotification)
            .where(
                (InboxNotification.recipient_user_id == user_id)
                | (InboxNotification.requester_user_id == user_id)
            )
            .order_by(InboxNotification.created_at.desc())
        )

        return list(self.db.scalars(statement).all())

    def get_by_id(self, notification_id):
        return self.db.get(InboxNotification, notification_id)

    def resolve(self, notification_id, approve):
        """
        Transition a notification from PENDING to APPROVED/DENIED.

        Returns the notification if this call actually performed the
        transition, or None if it was not found or was not PENDING
        (already resolved) -- the ONLY thing that makes a second
        Approve/Deny on the same notification a safe no-op rather than
        a repeat action (duplicate-processing protection). Callers
        must check for None and skip any further side effect (the
        actual group-member-add, the "you have been verified" push)
        when it is returned.
        """

        notification = self.db.get(InboxNotification, notification_id)

        if notification is None or notification.status != STATUS_PENDING:
            return None

        notification.status = STATUS_APPROVED if approve else STATUS_DENIED
        notification.resolved_at = _utc_now()

        self.db.flush()

        return notification
