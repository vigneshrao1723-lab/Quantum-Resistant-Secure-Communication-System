"""
JWT handling utilities.

This module contains only cryptographic/security logic for
creating and validating JSON Web Tokens.
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
)

from config_server import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    JWT_SECRET_KEY,
    REFRESH_TOKEN_EXPIRE_DAYS,
)


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale -- this module has no shared utils
    location to import it from, so it's duplicated here rather than
    introducing a new cross-cutting module.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TokenValidationError(Exception):
    """Raised when a token cannot be validated."""


class TokenExpiredError(TokenValidationError):
    """Raised when a token has expired."""


class JWTHandler:
    """Encapsulates JWT creation and validation."""

    def create_access_token(
        self,
        subject: str,
        session_id: str,
        username: str,
        role: str,
        extra_claims: dict | None = None,
    ) -> str:
        """Create a signed access token."""
        now = _utc_now()
        payload = {
            "sub": subject,
            "session_id": session_id,
            "username": username,
            "role": role,
            "jti": uuid.uuid4().hex,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "type": "access",
        }

        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    def create_refresh_token(
        self,
        subject: str,
        session_id: str,
        username: str,
        role: str,
        extra_claims: dict | None = None,
    ) -> str:
        """Create a signed refresh token."""
        now = _utc_now()
        payload = {
            "sub": subject,
            "session_id": session_id,
            "username": username,
            "role": role,
            "jti": uuid.uuid4().hex,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            "type": "refresh",
        }

        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    def decode_token(self, token: str) -> dict:
        """Decode and validate a JWT."""
        try:
            return jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                issuer=JWT_ISSUER,
                audience=JWT_AUDIENCE,
                options={
                    "require_sub": True,
                    "require_iat": True,
                    "require_exp": True,
                    "require_jti": True,
                    "require_iss": True,
                    "require_aud": True,
                },
            )
        except ExpiredSignatureError as exc:
            raise TokenExpiredError("Token has expired.") from exc
        except (InvalidIssuerError, InvalidAudienceError, InvalidTokenError) as exc:
            raise TokenValidationError("Token is invalid.") from exc

    def hash_token(self, token: str) -> str:
        """Return a deterministic SHA-256 hex digest of a token for storage.

        Refresh tokens are high-entropy signed JWTs, not low-entropy
        secrets like passwords, so a fast deterministic hash is
        appropriate here (unlike Argon2, which is deliberately slow and
        salted for guessable inputs). Determinism is required so a
        presented token can be looked up by exact-match hash comparison.
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def is_token_valid(self, token: str) -> bool:
        """Return whether a token is valid."""
        try:
            self.decode_token(token)
            return True
        except TokenValidationError:
            return False
