"""
User repository.
"""

from sqlalchemy import select

from database.models.user import User
from database.repositories.base_repository import BaseRepository


class UserRepository(BaseRepository):
    """Repository for user read/write operations."""

    def get_by_id(self, user_id):
        statement = select(User).where(User.id == user_id)
        return self.db.scalar(statement)

    def get_by_username(self, username):
        statement = select(User).where(User.username == username)
        return self.db.scalar(statement)

    def get_by_email(self, email):
        statement = select(User).where(User.email == email)
        return self.db.scalar(statement)

    def get_by_username_or_email(self, identifier):
        statement = select(User).where(
            (User.username == identifier) | (User.email == identifier)
        )
        return self.db.scalar(statement)

    def create(self, **kwargs):
        user = User(**kwargs)
        self.add(user)
        return user

    def update_last_login(self, user, last_login_at):
        user.last_login_at = last_login_at
        user.updated_at = last_login_at
        self.refresh(user)
        return user

    def increment_failed_logins(self, user, timestamp):
        user.failed_login_attempts += 1
        user.last_failed_login = timestamp
        self.refresh(user)
        return user

    def reset_failed_logins(self, user):
        user.failed_login_attempts = 0
        user.last_failed_login = None
        self.refresh(user)
        return user

    def set_locked(self, user, locked: bool):
        user.status = "locked" if locked else "active"
        self.refresh(user)
        return user
