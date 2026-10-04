"""
Tests for auth/authentication_service.py: registration, login, session
management, refresh token rotation, logout, and the middleware helpers.

Runs against the real PostgreSQL database via the db_session/auth_service
fixtures, which wrap each test in a rolled-back transaction (see
conftest.py).

Run with:
    pytest tests/test_authentication_service.py -v
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from auth.authentication_service import SessionInvalidError
from auth.schemas import LoginRequest, RegisterRequest
from config_server import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    JWT_SECRET_KEY,
    MAX_FAILED_LOGIN_ATTEMPTS,
)
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from security.jwt_handler import TokenExpiredError, TokenValidationError


def _utc_now() -> datetime:
    """Naive UTC now via the non-deprecated timezone-aware API, matching
    the production code's own _utc_now() helpers."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _register(auth_service, payload):
    return auth_service.register_user(RegisterRequest(**payload))


def _login(auth_service, payload, **overrides):
    # UI Finalization -- Login Identifier: phone number, not username,
    # is what authenticate_user() now accepts -- see the dedicated
    # "Login Identifier" section below for tests proving username/email
    # are specifically rejected.
    kwargs = {"identifier": payload["phone_number"], "password": payload["password"]}
    kwargs.update(overrides)
    return auth_service.authenticate_user(LoginRequest(**kwargs))


def _expired_access_token(user_id, session_id):
    now = _utc_now()
    payload = {
        "sub": user_id,
        "session_id": session_id,
        "username": "irrelevant",
        "role": "user",
        "jti": "expired-jti",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now - timedelta(minutes=30),
        "exp": now - timedelta(minutes=15),
        "type": "access",
    }
    return pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def test_register_user_success(auth_service, registration_payload):
    result = _register(auth_service, registration_payload)

    assert result.success is True
    assert result.user_id is not None
    assert result.errors is None


def test_register_user_duplicate_username(
    auth_service, registration_payload, unique_suffix
):
    _register(auth_service, registration_payload)

    dup_payload = dict(registration_payload)
    dup_payload["email"] = f"different_{unique_suffix}@example.com"
    result = _register(auth_service, dup_payload)

    assert result.success is False
    assert "username" in result.errors


def test_register_user_duplicate_email(
    auth_service, registration_payload, unique_suffix
):
    _register(auth_service, registration_payload)

    dup_payload = dict(registration_payload)
    dup_payload["username"] = f"different_{unique_suffix}"
    result = _register(auth_service, dup_payload)

    assert result.success is False
    assert "email" in result.errors


def test_register_user_password_policy_violation(auth_service, registration_payload):
    registration_payload["password"] = "weak"
    registration_payload["confirm_password"] = "weak"
    result = _register(auth_service, registration_payload)

    assert result.success is False
    assert "password" in result.errors


def test_register_user_password_confirmation_mismatch(
    auth_service, registration_payload
):
    registration_payload["confirm_password"] = (
        registration_payload["password"] + "different"
    )
    result = _register(auth_service, registration_payload)

    assert result.success is False
    assert "confirm_password" in result.errors


# ----------------------------------------------------------------------
# Login
# ----------------------------------------------------------------------


def test_authenticate_user_success(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    result = _login(auth_service, registration_payload)

    assert result.success is True
    assert result.token_pair is not None
    assert result.session_id is not None


def test_authenticate_user_invalid_password(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    result = _login(auth_service, registration_payload, password="WrongPassword!123")

    assert result.success is False
    assert "password" in result.errors


def test_authenticate_user_rejects_malformed_identifier(auth_service):
    """"no-such-user" is not a plausible phone number at all (letters,
    no digits) -- rejected by normalize_phone_number() before any
    database lookup happens. See
    test_authenticate_user_rejects_unregistered_phone_number below for
    the "well-formed but no account has it" case."""

    result = auth_service.authenticate_user(
        LoginRequest(identifier="no-such-user", password="whatever")
    )

    assert result.success is False
    assert "identifier" in result.errors


def test_authenticate_user_rejects_inactive(
    auth_service, db_session, registration_payload
):
    _register(auth_service, registration_payload)
    user = UserRepository(db_session).get_by_username(registration_payload["username"])
    user.is_active = False
    db_session.commit()

    result = _login(auth_service, registration_payload)

    assert result.success is False
    assert result.errors["status"] == "Account is inactive."


def test_authenticate_user_rejects_locked(
    auth_service, db_session, registration_payload
):
    _register(auth_service, registration_payload)
    user = UserRepository(db_session).get_by_username(registration_payload["username"])
    user.status = "locked"
    db_session.commit()

    result = _login(auth_service, registration_payload)

    assert result.success is False
    assert result.errors["status"] == "Account is locked."


def test_authenticate_user_locks_after_max_failed_attempts(
    auth_service, db_session, registration_payload
):
    _register(auth_service, registration_payload)

    # Each of the first MAX_FAILED_LOGIN_ATTEMPTS wrong-password attempts is
    # reported as a password failure -- including the triggering attempt
    # itself, since the account becomes locked as a *side effect* of that
    # call, not as the reason that specific call failed.
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        result = _login(
            auth_service, registration_payload, password="WrongPassword!123"
        )
        assert result.success is False
        assert result.errors.get("status") is None
        assert result.errors.get("password") == "Password verification failed."

    user = UserRepository(db_session).get_by_username(registration_payload["username"])
    assert user.status == "locked"
    assert user.failed_login_attempts == MAX_FAILED_LOGIN_ATTEMPTS

    # The *next* attempt after the account is already locked is rejected
    # up front, before password verification, with the locked-account error.
    next_attempt = _login(
        auth_service, registration_payload, password="WrongPassword!123"
    )
    assert next_attempt.success is False
    assert next_attempt.errors["status"] == "Account is locked."

    # Even the correct password is now rejected.
    correct_attempt = _login(auth_service, registration_payload)
    assert correct_attempt.success is False
    assert correct_attempt.errors["status"] == "Account is locked."


# ----------------------------------------------------------------------
# Login Identifier (UI Finalization) -- phone number + password is the
# only valid login combination; username and email, though still valid
# UNIQUE columns on the user, are display/registration identifiers
# only and must never authenticate a login.
# ----------------------------------------------------------------------


def test_authenticate_user_accepts_phone_number(auth_service, registration_payload):
    _register(auth_service, registration_payload)

    result = _login(auth_service, registration_payload)

    assert result.success is True
    assert result.token_pair is not None


def test_authenticate_user_accepts_an_equivalent_written_form_of_the_phone_number(
    auth_service, registration_payload
):
    """"+91 98765 43210" and "+919876543210" identify the same account
    (security/phone_number.py normalises both to the same canonical
    form) -- login must accept the written form exactly as
    registration does, not only the already-canonical one stored in
    the database."""

    _register(auth_service, registration_payload)

    raw_digits = registration_payload["phone_number"].lstrip("+")
    spaced_identifier = f"+{raw_digits[:2]} {raw_digits[2:7]} {raw_digits[7:]}"
    assert spaced_identifier != registration_payload["phone_number"]

    result = _login(auth_service, registration_payload, identifier=spaced_identifier)

    assert result.success is True


def test_authenticate_user_rejects_username_as_identifier(
    auth_service, registration_payload
):
    """Requirement: username cannot be used as a login identifier, even
    though it is a real, valid, UNIQUE value on the account -- the
    lookup only ever queries the phone_number column now (see
    AuthenticationService.authenticate_user()), so a real username
    simply never matches. This is also what stops another user's
    username from being substituted through the client login form: no
    username -- the account's own or anyone else's -- is ever an
    accepted identifier."""

    _register(auth_service, registration_payload)

    result = _login(
        auth_service, registration_payload, identifier=registration_payload["username"]
    )

    assert result.success is False
    assert "identifier" in result.errors


def test_authenticate_user_rejects_email_as_identifier(
    auth_service, registration_payload
):
    """Requirement: email cannot be used as a login identifier."""

    _register(auth_service, registration_payload)

    result = _login(
        auth_service, registration_payload, identifier=registration_payload["email"]
    )

    assert result.success is False
    assert "identifier" in result.errors


def test_authenticate_user_rejects_unregistered_phone_number(auth_service):
    """A well-formed phone number that simply has no account -- the
    "invalid phone/password combination" case distinct from a
    malformed identifier (test_authenticate_user_rejects_malformed_
    identifier above)."""

    result = auth_service.authenticate_user(
        LoginRequest(identifier="+919999999999", password="whatever")
    )

    assert result.success is False
    assert "identifier" in result.errors


def test_authenticate_user_rejects_correct_phone_wrong_password(
    auth_service, registration_payload
):
    _register(auth_service, registration_payload)

    result = _login(auth_service, registration_payload, password="WrongPassword!123")

    assert result.success is False
    assert "password" in result.errors


def test_authenticate_user_returns_the_authenticated_users_own_username(
    auth_service, registration_payload
):
    """Requirement: the authenticated user's username is obtained from
    the server/database profile -- not echoed back from anything the
    client submitted (the login form no longer even collects a
    username -- see gui/login_window.py)."""

    _register(auth_service, registration_payload)

    result = _login(auth_service, registration_payload)

    assert result.success is True
    assert result.username == registration_payload["username"]


def test_authenticate_user_cannot_be_tricked_into_returning_a_different_users_username(
    auth_service, unique_suffix, strong_password
):
    """Two real accounts; logging in with account A's own phone number
    must return exactly account A's username, never account B's --
    guards against a mixed-up lookup returning the wrong profile."""

    payload_a = {
        "full_name": "User A",
        "username": f"user_a_{unique_suffix}",
        "email": f"user_a_{unique_suffix}@example.com",
        "password": strong_password,
        "confirm_password": strong_password,
        "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
    }
    payload_b = {
        "full_name": "User B",
        "username": f"user_b_{unique_suffix}",
        "email": f"user_b_{unique_suffix}@example.com",
        "password": strong_password,
        "confirm_password": strong_password,
        "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
    }

    _register(auth_service, payload_a)
    _register(auth_service, payload_b)

    result = _login(auth_service, payload_a)

    assert result.success is True
    assert result.username == payload_a["username"]
    assert result.username != payload_b["username"]


# ----------------------------------------------------------------------
# Session management
# ----------------------------------------------------------------------


def test_login_persists_device_metadata_and_refresh_token_hash(
    auth_service, db_session, registration_payload
):
    _register(auth_service, registration_payload)
    result = _login(
        auth_service,
        registration_payload,
        device_name="Pixel 8",
        platform="Android",
        app_version="1.2.3",
        ip_address="203.0.113.5",
    )

    session = SessionRepository(db_session).get_by_session_id(result.session_id)
    assert session.device_name == "Pixel 8"
    assert session.platform == "Android"
    assert session.app_version == "1.2.3"
    assert session.ip_address == "203.0.113.5"
    assert session.refresh_token_hash is not None
    assert session.refresh_token_hash != result.token_pair.refresh_token


def test_each_login_creates_a_distinct_session(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    first = _login(auth_service, registration_payload)
    second = _login(auth_service, registration_payload)

    assert first.session_id != second.session_id
    assert first.session_id
    assert second.session_id


# ----------------------------------------------------------------------
# Refresh token rotation
# ----------------------------------------------------------------------


def test_refresh_access_token_rotates_tokens(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    refreshed = auth_service.refresh_access_token(login_result.token_pair.refresh_token)

    assert refreshed.success is True
    assert refreshed.token_pair.access_token != login_result.token_pair.access_token
    assert refreshed.token_pair.refresh_token != login_result.token_pair.refresh_token
    assert refreshed.session_id == login_result.session_id


def test_refresh_access_token_rejects_reused_old_token_and_revokes_session(
    auth_service, db_session, registration_payload
):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)
    old_refresh_token = login_result.token_pair.refresh_token

    first_refresh = auth_service.refresh_access_token(old_refresh_token)
    assert first_refresh.success is True

    reuse_attempt = auth_service.refresh_access_token(old_refresh_token)
    assert reuse_attempt.success is False

    # The session should now be revoked entirely, so even the freshly
    # rotated token from the successful call above no longer works.
    session = SessionRepository(db_session).get_by_session_id(login_result.session_id)
    assert session.revoked is True

    new_token_attempt = auth_service.refresh_access_token(
        first_refresh.token_pair.refresh_token
    )
    assert new_token_attempt.success is False


def test_refresh_access_token_rejects_wrong_token_type(
    auth_service, registration_payload
):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    result = auth_service.refresh_access_token(login_result.token_pair.access_token)

    assert result.success is False
    assert result.errors["refresh_token"] == "Token is not a refresh token."


def test_refresh_access_token_rejects_expired_refresh_token(
    auth_service, registration_payload
):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    now = _utc_now()
    expired_payload = {
        "sub": login_result.user_id,
        "session_id": login_result.session_id,
        "username": registration_payload["username"],
        "role": "user",
        "jti": "expired-refresh-jti",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now - timedelta(days=10),
        "exp": now - timedelta(days=1),
        "type": "refresh",
    }
    expired_token = pyjwt.encode(
        expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM
    )

    result = auth_service.refresh_access_token(expired_token)

    assert result.success is False
    assert result.errors["refresh_token"] == "Token has expired."


# ----------------------------------------------------------------------
# Logout
# ----------------------------------------------------------------------


def test_logout_revokes_session_and_clears_refresh_hash(
    auth_service, db_session, registration_payload
):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    assert auth_service.logout(login_result.session_id) is True

    session = SessionRepository(db_session).get_by_session_id(login_result.session_id)
    assert session.revoked is True
    assert session.is_active is False
    assert session.logout_time is not None
    assert session.refresh_token_hash is None


def test_logout_unknown_session_returns_false(auth_service):
    assert auth_service.logout("no-such-session-id") is False


def test_refresh_fails_after_logout(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)
    auth_service.logout(login_result.session_id)

    result = auth_service.refresh_access_token(login_result.token_pair.refresh_token)
    assert result.success is False


# ----------------------------------------------------------------------
# Middleware helpers
# ----------------------------------------------------------------------


def test_authenticate_access_token_success(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    claims = auth_service.authenticate_access_token(
        login_result.token_pair.access_token
    )
    assert claims["sub"] == login_result.user_id
    assert claims["type"] == "access"


def test_authenticate_access_token_rejects_revoked_session(
    auth_service, registration_payload
):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)
    auth_service.logout(login_result.session_id)

    with pytest.raises(SessionInvalidError):
        auth_service.authenticate_access_token(login_result.token_pair.access_token)


def test_authenticate_access_token_raises_on_expired_token(
    auth_service, registration_payload
):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)
    expired = _expired_access_token(login_result.user_id, login_result.session_id)

    with pytest.raises(TokenExpiredError):
        auth_service.authenticate_access_token(expired)


def test_authenticate_refresh_token_rejects_access_token(
    auth_service, registration_payload
):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    with pytest.raises(TokenValidationError):
        auth_service.authenticate_refresh_token(login_result.token_pair.access_token)


def test_get_current_user_success(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    user = auth_service.get_current_user(login_result.token_pair.access_token)
    assert user.username == registration_payload["username"]


def test_get_current_user_raises_after_logout(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)
    auth_service.logout(login_result.session_id)

    with pytest.raises(SessionInvalidError):
        auth_service.get_current_user(login_result.token_pair.access_token)


def test_get_current_session_success(auth_service, registration_payload):
    _register(auth_service, registration_payload)
    login_result = _login(auth_service, registration_payload)

    session = auth_service.get_current_session(login_result.token_pair.access_token)
    assert session.session_id == login_result.session_id
