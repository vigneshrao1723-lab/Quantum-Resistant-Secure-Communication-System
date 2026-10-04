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
        UniqueConstraint("phone_number", name="uq_users_phone_number"),
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

    # The user-facing discovery identifier (BUG 7). users.id stays the
    # internal primary key -- nothing about identity, foreign keys, or
    # authentication moves onto this column; it exists so one person
    # can find another without having to exchange a UUID, which the
    # application never displayed and therefore nobody could share.
    #
    # Stored ALREADY NORMALISED (see security/phone_number.py): a
    # leading "+" when the caller supplied one, digits only after
    # that. Normalising before storage is what makes the UNIQUE
    # constraint mean what it should -- "+91 98765 43210" and
    # "+919876543210" are the same person's number and must collide,
    # which they only do if both are canonicalised on the way in.
    #
    # 20 characters: E.164 allows at most 15 digits, so "+" plus 15 is
    # 16; 20 leaves room without inviting free-form text.
    phone_number = Column(String(20), nullable=False, index=True)

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

    # Phase 19.24 -- Presence/Last Seen: overwritten (never appended
    # to -- a single timestamp, not a history log, so this is not the
    # "unnecessary historical storage" the phase's own mandate warns
    # against) every time this account's connection closes (server/
    # client_handler.py's disconnect path). NULL for an account that
    # has never disconnected yet (still online, or never logged in) --
    # a client reads that as "no last-seen information", never as a
    # fabricated time. Deliberately server-side and persisted (not a
    # purely live signal like the online/offline broadcast already is)
    # because "when did they last leave" must survive this client's
    # own restart, unlike an ephemeral typing indicator.
    last_seen_at = Column(DateTime, nullable=True)

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
