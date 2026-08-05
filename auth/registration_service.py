"""
Registration service foundation.
"""

from auth.authentication_service import AuthenticationService


class RegistrationService(AuthenticationService):
    """Registration-specific authentication service."""

    def register_user(self, registration_data):
        raise NotImplementedError
