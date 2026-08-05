"""
Session model for refresh tokens and device-aware login sessions.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Session(Base):
    """Represents an authenticated login session or device session."""

    __tablename__ = "sessions"
    __table_args__ = (UniqueConstraint("session_id", name="uq_sessions_session_id"),)

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    session_id = Column(String(64), nullable=False)
    refresh_token_hash = Column(Text, nullable=True)
    device_name = Column(String(128), nullable=True)
    ip_address = Column(String(45), nullable=True)
    platform = Column(String(128), nullable=True)
    app_version = Column(String(64), nullable=True)

    created_at = Column(DateTime, nullable=False, default=_utc_now)
    login_time = Column(DateTime, nullable=False, default=_utc_now)
    logout_time = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=False, default=_utc_now)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    revoked = Column(Boolean, nullable=False, default=False)

    user = relationship("User", back_populates="sessions")

    def __repr__(self):
        return (
            f"<Session(id={self.id}, user_id={self.user_id}, "
            f"session_id={self.session_id}, active={self.is_active})>"
        )
