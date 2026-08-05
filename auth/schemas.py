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


@dataclass
class LoginRequest:
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
    role: str | None = None
    session_id: str | None = None
    token_pair: TokenPair | None = None
    errors: dict[str, str] | None = None
