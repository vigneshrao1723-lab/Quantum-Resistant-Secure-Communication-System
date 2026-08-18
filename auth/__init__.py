"""Authentication package.

Only the schema dataclasses are re-exported here (D7 -- Remove
remaining client -> database dependencies).

The service classes (AuthenticationService, LoginService,
RegistrationService) are deliberately NOT imported at package level.
Importing any of them pulls in database.repositories -> database ->
database.connection, which calls create_engine(DATABASE_URL) at module
scope and imports config_server. Because a package's __init__ runs
before any of its submodules, an eager re-export here meant that
``from auth.schemas import TokenPair`` -- the single line
client/session.py needs -- dragged SQLAlchemy, psycopg2, the server's
database engine, and config_server (including JWT_SECRET_KEY and
FILE_STORAGE_ROOT) into every client process.

That was the last remaining client -> server-database dependency: not
a database *call* (D2-D4.3 removed all of those), but a database
*import*. auth/schemas.py itself imports only ``dataclasses``, so
keeping this module limited to schemas breaks the chain completely.

Consumers import the services by their full module path
(``from auth.authentication_service import AuthenticationService``),
which is what every caller in this repository already did -- nothing
ever used ``from auth import ...``. Server-side behavior is therefore
unchanged; only the import graph is.

Do not re-add service imports here. Doing so silently restores the
client's dependency on the server's database and secrets. The
boundary is enforced by
tests/test_client_import_boundary.py.
"""

from auth.schemas import (
    AuthenticationResult,
    LoginRequest,
    RegisterRequest,
    RegistrationResult,
    TokenPair,
)

__all__ = [
    "AuthenticationResult",
    "LoginRequest",
    "RegisterRequest",
    "RegistrationResult",
    "TokenPair",
]
