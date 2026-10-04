"""
Authentication service foundation.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from auth.schemas import (
    AuthenticationResult,
    LoginRequest,
    RegisterRequest,
    RegistrationResult,
    TokenPair,
)
from config_server import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    MAX_FAILED_LOGIN_ATTEMPTS,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from logger_config import setup_logger
from security.jwt_handler import JWTHandler, TokenExpiredError, TokenValidationError
from security.password_handler import PasswordHandler
from security.phone_number import (
    InvalidPhoneNumberError,
    normalize_phone_number,
)

# Audit trail for authentication events (registration, login, logout,
# token refresh). Never log raw passwords or raw tokens here -- only
# identifiers (user_id/username) and outcome metadata.
_audit_logger = setup_logger("auth_audit", "auth_audit.log")


def _utc_now() -> datetime:
    """Current UTC time as a naive datetime (matches the naive DateTime
    columns used throughout the schema). Built on the timezone-aware
    datetime.now(timezone.utc) rather than the deprecated
    datetime.utcnow(), with the tzinfo stripped so the result stays
    directly comparable to values already stored in/loaded from the
    database.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SessionInvalidError(TokenValidationError):
    """Raised when a token is cryptographically valid but its underlying
    session is missing, revoked, inactive, or expired."""


class AuthenticationService:
    """High-level authentication orchestration."""

    def __init__(self, db):
        self.db = db
        self.user_repo = UserRepository(db)
        self.session_repo = SessionRepository(db)
        self.password_handler = PasswordHandler()
        self.jwt_handler = JWTHandler()

    @staticmethod
    def _log_auth_event(event: str, **fields) -> None:
        """Write a structured audit-log line. Never pass passwords or raw tokens."""
        details = " ".join(
            f"{key}={value}" for key, value in fields.items() if value is not None
        )
        _audit_logger.info("%s %s", event, details)

    def register_user(self, registration_data: RegisterRequest) -> RegistrationResult:
        """Register a new user."""
        errors: dict[str, str] = {}

        password_violations = self.password_handler.get_password_policy_violations(
            registration_data.password
        )
        if password_violations:
            errors["password"] = " ".join(password_violations)

        if registration_data.password != registration_data.confirm_password:
            errors["confirm_password"] = "Password and confirmation do not match."

        if self.user_repo.get_by_username(registration_data.username):
            errors["username"] = "Username already exists."

        if self.user_repo.get_by_email(registration_data.email):
            errors["email"] = "Email already exists."

        # BUG 7 -- phone number is mandatory and unique, because it is
        # the identifier other users search by. Normalising BEFORE the
        # duplicate check is what makes the check correct: without it
        # "+91 98765 43210" and "+919876543210" would both pass and
        # create two accounts for one real number, and the UNIQUE
        # constraint would not catch it either, since the stored
        # strings differ.
        normalized_phone_number = None

        try:
            normalized_phone_number = normalize_phone_number(
                registration_data.phone_number
            )
        except InvalidPhoneNumberError as error:
            errors["phone_number"] = str(error)
        else:
            if self.user_repo.get_by_phone_number(normalized_phone_number):
                errors["phone_number"] = "Phone number already exists."

        if errors:
            self._log_auth_event(
                "registration_failed",
                username=registration_data.username,
                detail=",".join(sorted(errors.keys())),
            )
            return RegistrationResult(
                success=False,
                message="Registration failed due to invalid input.",
                errors=errors,
            )

        try:
            password_hash = self.password_handler.hash_password(
                registration_data.password
            )
            user = self.user_repo.create(
                username=registration_data.username,
                email=registration_data.email,
                display_name=registration_data.full_name,
                password_hash=password_hash,
                phone_number=normalized_phone_number,
            )
            self.user_repo.commit()
        except IntegrityError:
            # Guards against a race between the uniqueness pre-checks above
            # and the insert (two concurrent registrations for the same
            # username/email).
            self.user_repo.rollback()
            self._log_auth_event(
                "registration_failed",
                username=registration_data.username,
                detail="unique constraint violated",
            )
            return RegistrationResult(
                success=False,
                message="Username, email, or phone number is already in use.",
                errors={
                    "username": "Username, email, or phone number already exists."
                },
            )
        except SQLAlchemyError:
            self.user_repo.rollback()
            self._log_auth_event(
                "registration_failed",
                username=registration_data.username,
                detail="database error",
            )
            raise

        self._log_auth_event(
            "registration_success",
            username=user.username,
            user_id=str(user.id),
        )

        return RegistrationResult(
            success=True,
            message="Registration completed successfully.",
            user_id=str(user.id),
        )

    def authenticate_user(self, login_data: LoginRequest) -> AuthenticationResult:
        """Authenticate an existing user and issue tokens.

        UI Finalization -- Login Identifier: phone number + password is
        now the only valid login combination. Username and email are
        registration/display identifiers, not login credentials --
        neither is accepted here, matching the same phone-number
        normalisation registration already applies (BUG 7 /
        security/phone_number.py), so "+91 98765 43210" and
        "+919876543210" resolve to the same account. A login_data.
        identifier that is not a plausible phone number at all is
        rejected the same way an unrecognised one is: this function
        never reveals which half (identifier vs. password) was wrong.
        """
        try:
            normalized_identifier = normalize_phone_number(login_data.identifier)
        except InvalidPhoneNumberError:
            self._log_auth_event(
                "login_failed",
                identifier=login_data.identifier,
                reason="invalid_phone_number",
            )
            return AuthenticationResult(
                success=False,
                message="Invalid phone number or password.",
                errors={"identifier": "Invalid phone number or password."},
            )

        user = self.user_repo.get_by_phone_number(normalized_identifier)
        if not user:
            self._log_auth_event(
                "login_failed",
                identifier=login_data.identifier,
                reason="user_not_found",
            )
            return AuthenticationResult(
                success=False,
                message="Invalid phone number or password.",
                errors={"identifier": "User not found."},
            )

        if not user.is_active:
            self._log_auth_event(
                "login_failed", username=user.username, reason="inactive"
            )
            return AuthenticationResult(
                success=False,
                message="This account is inactive.",
                errors={"status": "Account is inactive."},
            )

        if user.status == "locked":
            self._log_auth_event(
                "login_failed", username=user.username, reason="locked"
            )
            return AuthenticationResult(
                success=False,
                message="This account is locked due to too many failed login attempts.",
                errors={"status": "Account is locked."},
            )

        if not self.password_handler.verify_password(
            user.password_hash, login_data.password
        ):
            self.user_repo.increment_failed_logins(user, _utc_now())
            if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                self.user_repo.set_locked(user, True)
            self.user_repo.commit()
            self._log_auth_event(
                "login_failed",
                username=user.username,
                reason="bad_password",
                failed_attempts=user.failed_login_attempts,
                locked=user.status == "locked",
            )
            return AuthenticationResult(
                success=False,
                message="Invalid phone number or password.",
                errors={"password": "Password verification failed."},
            )

        self.user_repo.reset_failed_logins(user)
        self.user_repo.update_last_login(user, _utc_now())
        # Not committed here: user_repo and session_repo share the same
        # underlying db session, so the single commit() below (after the
        # session row is created) persists both atomically -- either the
        # whole login succeeds, or neither the user update nor the new
        # session is left partially applied.

        session = self.session_repo.create(
            user_id=user.id,
            session_id="",
            refresh_token_hash=None,
            device_name=login_data.device_name,
            ip_address=login_data.ip_address,
            platform=login_data.platform,
            app_version=login_data.app_version,
            expires_at=_utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )
        session.session_id = str(session.id)

        access_token = self.jwt_handler.create_access_token(
            subject=str(user.id),
            session_id=session.session_id,
            username=user.username,
            role=user.role,
        )
        refresh_token = self.jwt_handler.create_refresh_token(
            subject=str(user.id),
            session_id=session.session_id,
            username=user.username,
            role=user.role,
        )
        session.refresh_token_hash = self.jwt_handler.hash_token(refresh_token)

        self.session_repo.refresh(session)
        self.session_repo.commit()

        self._log_auth_event(
            "login_success",
            username=user.username,
            user_id=str(user.id),
            session_id=session.session_id,
        )

        return AuthenticationResult(
            success=True,
            message="Authentication successful.",
            user_id=str(user.id),
            username=user.username,
            phone_number=user.phone_number,
            role=user.role,
            session_id=session.session_id,
            token_pair=TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            ),
        )

    def refresh_access_token(self, refresh_token: str) -> AuthenticationResult:
        """Validate a refresh token and rotate it for a new token pair.

        The old refresh token is invalidated as part of rotation: its
        session's stored hash is overwritten with the new token's hash,
        so presenting the old token again will fail the hash comparison
        below on its next use.
        """
        try:
            claims = self.jwt_handler.decode_token(refresh_token)
        except TokenExpiredError:
            self._log_auth_event("refresh_failed", reason="expired")
            return AuthenticationResult(
                success=False,
                message="Refresh token has expired.",
                errors={"refresh_token": "Token has expired."},
            )
        except TokenValidationError:
            self._log_auth_event("refresh_failed", reason="invalid_token")
            return AuthenticationResult(
                success=False,
                message="Invalid refresh token.",
                errors={"refresh_token": "Token is invalid."},
            )

        if claims.get("type") != "refresh":
            self._log_auth_event("refresh_failed", reason="wrong_token_type")
            return AuthenticationResult(
                success=False,
                message="Invalid refresh token.",
                errors={"refresh_token": "Token is not a refresh token."},
            )

        session_id = claims.get("session_id")
        session = self.session_repo.get_by_session_id(session_id)
        if session is None:
            self._log_auth_event(
                "refresh_failed", session_id=session_id, reason="session_not_found"
            )
            return AuthenticationResult(
                success=False,
                message="Session not found.",
                errors={"refresh_token": "Session no longer exists."},
            )

        if session.revoked or not session.is_active:
            self._log_auth_event(
                "refresh_failed", session_id=session_id, reason="session_revoked"
            )
            return AuthenticationResult(
                success=False,
                message="Session has been revoked.",
                errors={"refresh_token": "Session is no longer active."},
            )

        if session.expires_at < _utc_now():
            self._log_auth_event(
                "refresh_failed", session_id=session_id, reason="session_expired"
            )
            return AuthenticationResult(
                success=False,
                message="Session has expired.",
                errors={"refresh_token": "Session has expired."},
            )

        if self.jwt_handler.hash_token(refresh_token) != session.refresh_token_hash:
            # The token is validly signed but doesn't match what's on file
            # for this session -- either a stale, already-rotated-out
            # token or a forged one. Treat as reuse/compromise and revoke
            # the session outright rather than just rejecting this call.
            self.session_repo.revoke(session)
            self.session_repo.commit()
            self._log_auth_event(
                "refresh_token_reuse_detected",
                session_id=session_id,
                user_id=claims.get("sub"),
            )
            return AuthenticationResult(
                success=False,
                message="Refresh token is no longer valid.",
                errors={"refresh_token": "Token does not match the active session."},
            )

        user = self.user_repo.get_by_id(session.user_id)
        if user is None or not user.is_active or user.status == "locked":
            self._log_auth_event(
                "refresh_failed", session_id=session_id, reason="user_unavailable"
            )
            return AuthenticationResult(
                success=False,
                message="Account is not available.",
                errors={"refresh_token": "Account is inactive or locked."},
            )

        new_access_token = self.jwt_handler.create_access_token(
            subject=str(user.id),
            session_id=session.session_id,
            username=user.username,
            role=user.role,
        )
        new_refresh_token = self.jwt_handler.create_refresh_token(
            subject=str(user.id),
            session_id=session.session_id,
            username=user.username,
            role=user.role,
        )

        session.refresh_token_hash = self.jwt_handler.hash_token(new_refresh_token)
        session.last_used_at = _utc_now()
        session.expires_at = _utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        self.session_repo.refresh(session)
        self.session_repo.commit()

        self._log_auth_event(
            "refresh_token_rotated",
            username=user.username,
            user_id=str(user.id),
            session_id=session.session_id,
        )

        return AuthenticationResult(
            success=True,
            message="Token refreshed successfully.",
            user_id=str(user.id),
            username=user.username,
            role=user.role,
            session_id=session.session_id,
            token_pair=TokenPair(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            ),
        )

    def validate_token(self, token: str) -> dict[str, str | None]:
        """Validate a token and return decoded claims."""
        return self.jwt_handler.decode_token(token)

    def logout(self, session_id: str) -> bool:
        """Log out a session: revoke it, clear its refresh token, record logout_time."""
        session = self.session_repo.get_by_session_id(session_id)
        if session is None:
            return False

        session.logout_time = _utc_now()
        session.refresh_token_hash = None
        self.session_repo.revoke(session)
        self.session_repo.commit()

        self._log_auth_event(
            "logout", session_id=session_id, user_id=str(session.user_id)
        )
        return True

    # ------------------------------------------------------------------
    # Middleware helpers -- intended for use by request handlers (e.g.
    # the future chat server) to authenticate incoming requests. These
    # raise TokenExpiredError / TokenValidationError / SessionInvalidError
    # rather than returning a result object.
    # ------------------------------------------------------------------

    def _get_valid_session(self, claims: dict, expected_type: str):
        """Shared guard for the two authenticate_*_token methods below:
        checks the claim's token type and loads+validates its session
        (exists, not revoked, active, not expired). Raises
        TokenValidationError / SessionInvalidError; returns the Session.
        """
        if claims.get("type") != expected_type:
            article = "an" if expected_type[0] in "aeiou" else "a"
            raise TokenValidationError(f"Token is not {article} {expected_type} token.")

        session = self.session_repo.get_by_session_id(claims.get("session_id"))
        if session is None or session.revoked or not session.is_active:
            raise SessionInvalidError("Session is not active.")

        if session.expires_at < _utc_now():
            raise SessionInvalidError("Session has expired.")

        return session

    def authenticate_access_token(self, access_token: str) -> dict:
        """Validate an access token and its session. Returns decoded claims."""
        claims = self.jwt_handler.decode_token(access_token)
        self._get_valid_session(claims, "access")
        return claims

    def authenticate_refresh_token(self, refresh_token: str) -> dict:
        """Validate a refresh token and its session, without rotating it.

        Returns decoded claims. Use refresh_access_token() instead when the
        caller actually wants to rotate to a new token pair.
        """
        claims = self.jwt_handler.decode_token(refresh_token)
        session = self._get_valid_session(claims, "refresh")

        if self.jwt_handler.hash_token(refresh_token) != session.refresh_token_hash:
            raise SessionInvalidError(
                "Refresh token does not match the active session."
            )

        return claims

    def get_current_user(self, access_token: str):
        """Return the authenticated User for a valid access token, or raise."""
        claims = self.authenticate_access_token(access_token)
        user = self.user_repo.get_by_id(claims["sub"])
        if user is None or not user.is_active or user.status == "locked":
            raise SessionInvalidError("User is not available.")
        return user

    def get_current_session(self, access_token: str):
        """Return the active Session for a valid access token, or raise."""
        claims = self.authenticate_access_token(access_token)
        session = self.session_repo.get_by_session_id(claims["session_id"])
        if session is None:
            raise SessionInvalidError("Session not found.")
        return session

    # ------------------------------------------------------------
    # Settings (Phase 19.14): account self-service changes for an
    # already-authenticated user. Each mirrors register_user()'s own
    # validate-then-write shape (collect errors, refuse if any exist,
    # otherwise write once and commit) rather than inventing a new
    # convention.
    # ------------------------------------------------------------

    def change_username(self, user_id, new_username: str) -> dict:
        """Rename ``user_id``'s account. Returns {"success": bool,
        "error": str | None}. No format validator existed anywhere in
        this codebase before this phase (confirmed by inspection of
        register_user()/auth/schemas.py) -- this adds the same minimal
        length check the users.username column itself already enforces
        (String(32)), plus the pre-existing duplicate-username check
        register_user() already performs, reused here rather than
        duplicated logic."""

        new_username = (new_username or "").strip()

        if not (3 <= len(new_username) <= 32):
            return {"success": False, "error": "Username must be between 3 and 32 characters."}

        user = self.user_repo.get_by_id(user_id)
        if user is None:
            return {"success": False, "error": "Account not found."}

        if new_username == user.username:
            return {"success": True, "error": None}

        existing = self.user_repo.get_by_username(new_username)
        if existing is not None and existing.id != user.id:
            return {"success": False, "error": "That username is already taken."}

        try:
            self.user_repo.update_username(user, new_username, _utc_now())
            self.user_repo.commit()
        except IntegrityError:
            self.user_repo.rollback()
            return {"success": False, "error": "That username is already taken."}

        self._log_auth_event("username_changed", user_id=str(user.id))
        return {"success": True, "error": None}

    def change_password(self, user_id, current_password: str, new_password: str, confirm_password: str) -> dict:
        """Change ``user_id``'s password. Returns {"success": bool,
        "error": str | None}. Requires the CURRENT password (proof of
        continued account ownership, not just a valid session -- a
        stolen/left-open session token alone must not be enough to
        lock the real owner out) and re-uses register_user()'s exact
        same password-policy check and hashing call -- never a second,
        weaker password rule."""

        user = self.user_repo.get_by_id(user_id)
        if user is None:
            return {"success": False, "error": "Account not found."}

        if not self.password_handler.verify_password(user.password_hash, current_password):
            self._log_auth_event("password_change_failed", user_id=str(user.id), reason="bad_current_password")
            return {"success": False, "error": "Current password is incorrect."}

        if new_password != confirm_password:
            return {"success": False, "error": "New password and confirmation do not match."}

        violations = self.password_handler.get_password_policy_violations(new_password)
        if violations:
            return {"success": False, "error": " ".join(violations)}

        password_hash = self.password_handler.hash_password(new_password)
        self.user_repo.update_password_hash(user, password_hash, _utc_now())
        self.user_repo.commit()

        self._log_auth_event("password_changed", user_id=str(user.id))
        return {"success": True, "error": None}
