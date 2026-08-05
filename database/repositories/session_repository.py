"""
Session repository.
"""

from sqlalchemy import select

from database.models.session import Session
from database.repositories.base_repository import BaseRepository


class SessionRepository(BaseRepository):
    """Repository for authentication session operations."""

    def get_by_id(self, session_id):
        statement = select(Session).where(Session.id == session_id)
        return self.db.scalar(statement)

    def get_by_session_id(self, session_id):
        statement = select(Session).where(Session.session_id == session_id)
        return self.db.scalar(statement)

    def get_active_sessions_for_user(self, user_id):
        statement = select(Session).where(
            Session.user_id == user_id,
            Session.is_active == True,
            Session.revoked == False,
        )
        return self.db.scalars(statement).all()

    def create(self, **kwargs):
        session = Session(**kwargs)
        self.add(session)
        return session

    def deactivate(self, session):
        session.is_active = False
        session.logout_time = session.logout_time or session.last_used_at
        self.refresh(session)
        return session

    def revoke(self, session):
        session.revoked = True
        session.is_active = False
        self.refresh(session)
        return session
