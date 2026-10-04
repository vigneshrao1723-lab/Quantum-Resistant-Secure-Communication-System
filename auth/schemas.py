"""
Schemas for authentication input and output.
"""

from dataclasses import dataclass


@dataclass
class RegisterRequest:
    full_name: str
    username: str
    email: str
    password: str
    confirm_password: str
    # BUG 7 -- the user-facing discovery identifier. Mandatory:
    # discovery only works if every account has one. Normalised
    # by security/phone_number.py before it is stored.
    phone_number: str = ""


@dataclass
class LoginRequest:
    # UI Finalization -- Login Identifier: the registered phone number
    # (any of its accepted written forms -- see
    # security/phone_number.py -- AuthenticationService.authenticate_
    # user() normalises it before lookup). Username and email are not
    # accepted here.
    identifier: str
    password: str
    remember_me: bool = False
    device_name: str | None = None
    platform: str | None = None
    app_version: str | None = None
    ip_address: str | None = None


@dataclass
class RegistrationResult:
    success: bool
    message: str
    user_id: str | None = None
    errors: dict[str, str] | None = None


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"


@dataclass
class AuthenticationResult:
    success: bool
    message: str
    user_id: str | None = None
    username: str | None = None
    # BUG 7 (7.5) -- the authenticated user's OWN discovery identifier,
    # returned so the UI can show it back to them to share. Never
    # another account's number.
    phone_number: str | None = None
    role: str | None = None
    session_id: str | None = None
    token_pair: TokenPair | None = None
    errors: dict[str, str] | None = None
