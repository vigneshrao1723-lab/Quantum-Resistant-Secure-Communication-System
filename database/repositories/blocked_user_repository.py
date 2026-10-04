"""
Blocked-user repository (Phase 19.24 -- Block User).
"""

from sqlalchemy import select

from database.models.blocked_user import BlockedUser
from database.repositories.base_repository import BaseRepository


class BlockedUserRepository(BaseRepository):
    """Repository for one user blocking another (directional -- see
    database/models/blocked_user.py's own docstring)."""

    def is_blocked(self, blocker_id, blocked_id):
        """True if blocker_id has blocked blocked_id (this direction
        only -- callers that care about EITHER direction call this
        twice, see server/client_handler.py's own enforcement points
        for why the two directions are never conflated)."""

        statement = select(BlockedUser).where(
            BlockedUser.blocker_id == blocker_id,
            BlockedUser.blocked_id == blocked_id,
        )
        return self.db.scalar(statement) is not None

    def block(self, blocker_id, blocked_id):
        """Insert a block row if one does not already exist -- calling
        this twice for the same pair is a safe no-op, never a duplicate
        row or an error."""

        if self.is_blocked(blocker_id, blocked_id):
            return
        self.add(BlockedUser(blocker_id=blocker_id, blocked_id=blocked_id))

    def unblock(self, blocker_id, blocked_id):
        """Remove a block row if one exists -- calling this on a pair
        that was never blocked is a safe no-op."""

        statement = select(BlockedUser).where(
            BlockedUser.blocker_id == blocker_id,
            BlockedUser.blocked_id == blocked_id,
        )
        row = self.db.scalar(statement)
        if row is not None:
            self.delete(row)

    def get_blocked_user_ids(self, blocker_id):
        """Every user_id that blocker_id has blocked."""

        statement = select(BlockedUser.blocked_id).where(
            BlockedUser.blocker_id == blocker_id,
        )
        return set(self.db.scalars(statement).all())

    def get_blocker_user_ids(self, blocked_id):
        """Every user_id that has blocked blocked_id -- the reverse of
        get_blocked_user_ids(), needed by enforcement points that must
        check "has anyone involved here blocked the other party",
        which is a two-directional question."""

        statement = select(BlockedUser.blocker_id).where(
            BlockedUser.blocked_id == blocked_id,
        )
        return set(self.db.scalars(statement).all())

    def get_all_block_pairs(self):
        """Every (blocker_id, blocked_id) pair that currently exists --
        one query, for a caller (server/broadcaster.py::
        broadcast_user_list()) that needs to check many pairs at once
        rather than pay one query per pair."""

        statement = select(BlockedUser.blocker_id, BlockedUser.blocked_id)
        return set(self.db.execute(statement).all())
