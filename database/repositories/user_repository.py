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

    def get_by_phone_number(self, phone_number):
        """Look up a user by their canonical phone number (BUG 7).

        The caller must pass an already-normalised value -- the column
        stores the canonical form, so an un-normalised search term
        would silently miss. server/client_handler.py's lookup handler
        normalises before calling this.
        """
        statement = select(User).where(User.phone_number == phone_number)
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

    def update_last_seen(self, user, last_seen_at):
        """Phase 19.24 -- Presence/Last Seen: overwrites (never
        appends to) this account's single last-seen timestamp, called
        when its connection closes (server/client_handler.py's
        disconnect path). Deliberately does NOT touch updated_at --
        unlike a real profile edit, going offline is not a change to
        the account's own data worth reflecting there."""

        user.last_seen_at = last_seen_at
        self.refresh(user)
        return user

    def update_username(self, user, new_username, timestamp):
        """Phase 19.14 -- Settings: rename an existing account.
        Caller (auth/authentication_service.py::change_username())
        already checked uniqueness under the SAME transaction this
        commits in, mirroring register_user()'s own uniqueness-then-
        insert pattern."""
        user.username = new_username
        user.updated_at = timestamp
        self.refresh(user)
        return user

    def update_password_hash(self, user, password_hash, timestamp):
        """Phase 19.14 -- Settings: change an existing account's
        password. Caller has already verified the current password
        and hashed the new one (security.password_handler.
        PasswordHandler.hash_password()) -- this only ever writes an
        already-hashed value, never plaintext."""
        user.password_hash = password_hash
        user.updated_at = timestamp
        self.refresh(user)
        return user

    def update_profile_picture(self, user, profile_picture, timestamp):
        """Phase 19.14 -- Settings: set/replace the stored reference
        (a filename under storage/profile_pictures/, never a raw
        filesystem path) to an account's profile picture."""
        user.profile_picture = profile_picture
        user.updated_at = timestamp
        self.refresh(user)
        return user

    def update_bio(self, user, bio, timestamp):
        """Phase 19.22 -- Settings: the ``bio`` column has existed on
        this model (and in the initial migration) since before this
        phase, but was never read or written anywhere -- this is the
        first real caller. A plain text column, unlike profile_picture,
        needs no blob-store reference; the value itself is persisted
        directly, same pattern as update_profile_picture() above."""
        user.bio = bio
        user.updated_at = timestamp
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
