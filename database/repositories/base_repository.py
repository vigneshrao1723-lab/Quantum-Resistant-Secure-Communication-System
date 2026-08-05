"""
Base repository with common database operations.
"""

from sqlalchemy.orm import Session


class BaseRepository:
    """Base repository that provides an ORM session.

    Concrete repositories should inherit from this class and
    operate through the provided session object.
    """

    def __init__(self, db: Session):
        self.db = db

    def add(self, instance):
        self.db.add(instance)
        self.db.flush()
        return instance

    def delete(self, instance):
        self.db.delete(instance)
        self.db.flush()

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def refresh(self, instance):
        """Persist pending in-memory attribute changes on ``instance``.

        Despite the name, this flushes rather than reloads. The session
        is configured with autoflush=False, so a prior implementation
        calling Session.refresh() here silently discarded any unflushed
        in-memory mutation (it reloads attributes FROM the database,
        overwriting what the caller just set) instead of persisting it.
        Every caller in this codebase wants the mutation preserved, so
        this flushes the pending change within the current transaction;
        the caller is still expected to commit() afterwards.
        """
        self.db.flush()
        return instance
