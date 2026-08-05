"""
Login service foundation.
"""

from auth.authentication_service import AuthenticationService


class LoginService(AuthenticationService):
    """Login-specific authentication service."""

    def authenticate_user(self, login_data):
        raise NotImplementedError
