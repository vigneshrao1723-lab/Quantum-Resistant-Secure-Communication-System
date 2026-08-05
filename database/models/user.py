"""
User model definitions for authentication.
"""

import uuid
from datetime import datetime
from datetime import timezone as dt_timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
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
    return datetime.now(dt_timezone.utc).replace(tzinfo=None)


class User(Base):
    """Represents an authenticated user."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email", name="uq_users_email"),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    username = Column(String(32), nullable=False, index=True)
    email = Column(String(254), nullable=False, index=True)
    password_hash = Column(Text, nullable=False)

    display_name = Column(String(64), nullable=False)
    profile_picture = Column(String(256), nullable=True)

    role = Column(String(32), nullable=False, default="user")
    status = Column(String(32), nullable=False, default="active")
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    last_failed_login = Column(DateTime, nullable=True)

    is_active = Column(Boolean, nullable=False, default=True)
    is_verified = Column(Boolean, nullable=False, default=False)
    is_superuser = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime, nullable=False, default=_utc_now)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=_utc_now,
        onupdate=_utc_now,
    )
    last_login_at = Column(DateTime, nullable=True)

    bio = Column(String(256), nullable=True)
    locale = Column(String(16), nullable=True)
    timezone = Column(String(64), nullable=True)

    sessions = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self):
        return (
            f"<User(id={self.id}, username={self.username}, "
            f"email={self.email}, active={self.is_active})>"
        )
