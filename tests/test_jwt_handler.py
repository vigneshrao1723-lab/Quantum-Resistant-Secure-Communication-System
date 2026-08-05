"""
Tests for security/jwt_handler.py.

No database required -- JWTHandler is pure JWT create/decode/hash logic.

Run with:
    pytest tests/test_jwt_handler.py -v
"""

from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from config import JWT_ALGORITHM, JWT_AUDIENCE, JWT_ISSUER, JWT_SECRET_KEY
from security.jwt_handler import JWTHandler, TokenExpiredError, TokenValidationError


def _utc_now() -> datetime:
    """Naive UTC now via the non-deprecated timezone-aware API, matching
    the production code's own _utc_now() helpers."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


SUBJECT = "11111111-1111-1111-1111-111111111111"
SESSION_ID = "22222222-2222-2222-2222-222222222222"
USERNAME = "jwt_test_user"
ROLE = "user"


@pytest.fixture()
def handler():
    return JWTHandler()


def test_create_and_decode_access_token(handler):
    token = handler.create_access_token(SUBJECT, SESSION_ID, USERNAME, ROLE)
    claims = handler.decode_token(token)

    assert claims["sub"] == SUBJECT
    assert claims["session_id"] == SESSION_ID
    assert claims["username"] == USERNAME
    assert claims["role"] == ROLE
    assert claims["type"] == "access"
    assert "jti" in claims


def test_create_and_decode_refresh_token(handler):
    token = handler.create_refresh_token(SUBJECT, SESSION_ID, USERNAME, ROLE)
    claims = handler.decode_token(token)

    assert claims["type"] == "refresh"
    assert claims["sub"] == SUBJECT


def test_access_and_refresh_tokens_are_distinguishable(handler):
    access = handler.create_access_token(SUBJECT, SESSION_ID, USERNAME, ROLE)
    refresh = handler.create_refresh_token(SUBJECT, SESSION_ID, USERNAME, ROLE)

    assert handler.decode_token(access)["type"] == "access"
    assert handler.decode_token(refresh)["type"] == "refresh"
    assert access != refresh


def test_is_token_valid_true_for_fresh_token(handler):
    token = handler.create_access_token(SUBJECT, SESSION_ID, USERNAME, ROLE)
    assert handler.is_token_valid(token) is True


def test_is_token_valid_false_for_garbage(handler):
    assert handler.is_token_valid("not-a-jwt") is False


def test_decode_raises_on_tampered_signature(handler):
    token = handler.create_access_token(SUBJECT, SESSION_ID, USERNAME, ROLE)
    tampered = token[:-4] + ("A" * 4 if not token.endswith("AAAA") else "BBBB")

    with pytest.raises(TokenValidationError):
        handler.decode_token(tampered)


def test_decode_raises_on_wrong_secret(handler):
    token = handler.create_access_token(SUBJECT, SESSION_ID, USERNAME, ROLE)
    # Re-sign the same payload with a different key to simulate a forged token.
    claims = pyjwt.decode(token, options={"verify_signature": False})
    forged = pyjwt.encode(
        claims, "a-completely-different-secret", algorithm=JWT_ALGORITHM
    )

    with pytest.raises(TokenValidationError):
        handler.decode_token(forged)


def test_decode_raises_token_expired_error_on_expired_token(handler):
    now = _utc_now()
    expired_payload = {
        "sub": SUBJECT,
        "session_id": SESSION_ID,
        "username": USERNAME,
        "role": ROLE,
        "jti": "expired-test-jti",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now - timedelta(minutes=30),
        "exp": now - timedelta(minutes=15),
        "type": "access",
    }
    expired_token = pyjwt.encode(
        expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM
    )

    with pytest.raises(TokenExpiredError):
        handler.decode_token(expired_token)

    assert handler.is_token_valid(expired_token) is False


def test_decode_raises_on_wrong_issuer(handler):
    now = _utc_now()
    payload = {
        "sub": SUBJECT,
        "session_id": SESSION_ID,
        "username": USERNAME,
        "role": ROLE,
        "jti": "wrong-issuer-jti",
        "iss": "someone-else",
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "type": "access",
    }
    token = pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    with pytest.raises(TokenValidationError):
        handler.decode_token(token)


def test_hash_token_is_deterministic_and_sha256(handler):
    token = "some.jwt.value"
    import hashlib

    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert handler.hash_token(token) == expected
    assert handler.hash_token(token) == handler.hash_token(token)


def test_hash_token_differs_for_different_tokens(handler):
    assert handler.hash_token("token-a") != handler.hash_token("token-b")
