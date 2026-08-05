"""
Password handling utilities.

This module contains only cryptographic logic for hashing, verifying, and
validating passwords using Argon2.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

from config import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
)


class PasswordHandler:
    """Encapsulates Argon2 password hashing and verification."""

    def __init__(self):
        self.hasher = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
        )

    def validate_password_policy(self, password: str) -> bool:
        """Validate the raw password against local policy rules."""
        return len(self.get_password_policy_violations(password)) == 0

    def get_password_policy_violations(self, password: str) -> list[str]:
        """Return a list of violated password policy rules."""
        violations: list[str] = []

        if not isinstance(password, str) or len(password) < 12:
            violations.append("Password must be at least 12 characters long.")

        if not any(char.isupper() for char in password):
            violations.append("Password must contain at least one uppercase letter.")

        if not any(char.islower() for char in password):
            violations.append("Password must contain at least one lowercase letter.")

        if not any(char.isdigit() for char in password):
            violations.append("Password must contain at least one digit.")

        if not any(char in "!@#$%^&*()-_=+[]{}|;:,.<>/?`~" for char in password):
            violations.append("Password must contain at least one special character.")

        return violations

    def hash_password(self, password: str) -> str:
        """Hash a plaintext password."""
        return self.hasher.hash(password)

    def verify_password(self, hashed_password: str, password: str) -> bool:
        """Verify a plaintext password against a hash."""
        try:
            return self.hasher.verify(hashed_password, password)
        except (VerifyMismatchError, InvalidHash, TypeError):
            return False

    def needs_rehash(self, hashed_password: str) -> bool:
        """Return whether the stored hash should be rehashed under current policy."""
        try:
            return self.hasher.check_needs_rehash(hashed_password)
        except InvalidHash:
            return False
