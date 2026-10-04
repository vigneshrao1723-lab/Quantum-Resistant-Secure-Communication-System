"""
Device model (Phase 16 -- Multi-Device Identity).

Records the PUBLIC half of a device's cryptographic identity (its
ML-KEM-768 and ML-DSA-65 public keys, and the fingerprint derived from
them -- crypto/key_manager.py::fingerprint_combined_identity(),
unchanged) and its authorization state for one account. No private key
column exists anywhere in this model, and no code path in this project
ever has a device private key to put in one -- see docs/architecture/
multi_device_identity.md's own "Database changes" section.

Distinct from database/models/session.py::Session (an ephemeral,
per-login JWT session that already expires and already carries
device_name/platform for that one login) -- a Device is the stable,
long-lived cryptographic identity that persists across many logins,
exactly mirroring how storage/secure_key_store.py persists a device's
keys locally across many app restarts.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database.models.base import Base


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime -- see auth/
    authentication_service.py's identical helper for the full
    rationale (avoids the deprecated naive-by-default datetime.utcnow()
    while keeping every column's stored value naive/UTC, consistent
    with every other timestamp column in this schema)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Not a DB-level CHECK constraint (this project's other state-like
# columns -- e.g. domain/payload_type.py's PayloadType -- are also
# plain strings validated in application code, not enum types at the
# schema level, so this follows that existing convention rather than
# introducing a new one).
DEVICE_STATE_PENDING = "PENDING"
DEVICE_STATE_AUTHORIZED = "AUTHORIZED"
DEVICE_STATE_REVOKED = "REVOKED"


class Device(Base):
    """One account's device's public cryptographic identity + authorization state."""

    __tablename__ = "devices"

    device_id = Column(
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

    device_name = Column(String(128), nullable=True)
    platform = Column(String(128), nullable=True)

    # Wire-form (base64) public keys -- the exact same representation
    # already used on the "key_exchange"/"public_key" packet
    # (utils/protocol.py::create_public_key_packet()), not re-decoded
    # or re-encoded into any other form here.
    kem_public_key = Column(Text, nullable=False)
    ml_dsa_public_key = Column(Text, nullable=False)

    fingerprint = Column(String(128), nullable=False, index=True)

    state = Column(String(16), nullable=False, default=DEVICE_STATE_PENDING)

    created_at = Column(DateTime, nullable=False, default=_utc_now)
    authorized_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)

    # NULL for the bootstrap first device (nothing authorized it but
    # the account's own credentials -- see docs/architecture/
    # multi_device_identity.md's "Bootstrap case").
    authorized_by_device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("devices.device_id", ondelete="SET NULL"),
        nullable=True,
    )

    user = relationship("User")

    def __repr__(self):
        return (
            f"<Device(device_id={self.device_id}, user_id={self.user_id}, "
            f"state={self.state})>"
        )
