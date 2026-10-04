"""
Device repository (Phase 16 -- Multi-Device Identity).
"""

from datetime import datetime, timezone

from sqlalchemy import select

from database.models.device import (
    DEVICE_STATE_AUTHORIZED,
    DEVICE_STATE_PENDING,
    DEVICE_STATE_REVOKED,
    Device,
)
from database.repositories.base_repository import BaseRepository


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class DeviceRepository(BaseRepository):
    """Repository for device enrollment/authorization/revocation operations."""

    def get_by_id(self, device_id):
        statement = select(Device).where(Device.device_id == device_id)
        return self.db.scalar(statement)

    def get_devices_for_user(self, user_id, state=None):
        statement = select(Device).where(Device.user_id == user_id)
        if state is not None:
            statement = statement.where(Device.state == state)
        return self.db.scalars(statement).all()

    def get_authorized_device_count(self, user_id):
        return len(self.get_devices_for_user(user_id, state=DEVICE_STATE_AUTHORIZED))

    def enroll(
        self,
        device_id,
        user_id,
        kem_public_key,
        ml_dsa_public_key,
        fingerprint,
        device_name=None,
        platform=None,
        auto_authorize=False,
    ):
        """
        Insert a new device row.

        ``auto_authorize`` is set only for the bootstrap first device
        of an account (see docs/architecture/multi_device_identity.md's
        "Bootstrap case") -- the caller (server/device_handler.py)
        decides this by checking get_authorized_device_count() == 0
        BEFORE calling this, never here, so the authorization decision
        stays visible at the call site rather than hidden inside the
        repository.
        """

        device = Device(
            device_id=device_id,
            user_id=user_id,
            device_name=device_name,
            platform=platform,
            kem_public_key=kem_public_key,
            ml_dsa_public_key=ml_dsa_public_key,
            fingerprint=fingerprint,
            state=DEVICE_STATE_AUTHORIZED if auto_authorize else DEVICE_STATE_PENDING,
            authorized_at=_utc_now() if auto_authorize else None,
        )
        self.add(device)
        return device

    def authorize(self, device, authorized_by_device_id):
        device.state = DEVICE_STATE_AUTHORIZED
        device.authorized_at = _utc_now()
        device.authorized_by_device_id = authorized_by_device_id
        self.refresh(device)
        return device

    def revoke(self, device):
        device.state = DEVICE_STATE_REVOKED
        device.revoked_at = _utc_now()
        self.refresh(device)
        return device
