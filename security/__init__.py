"""Security utilities package.

Intentionally empty of re-exports (D7 -- Remove remaining client ->
database dependencies).

This package holds three unrelated things: TLS transport setup
(security/tls.py), which BOTH the client and the server need, and JWT
and password handling (security/jwt_handler.py,
security/password_handler.py), which only the server needs. The latter
two import config_server for JWT_SECRET_KEY, JWT_ALGORITHM and the
Argon2 parameters.

Re-exporting JWTHandler and PasswordHandler here meant that
``from security.tls import build_client_context`` -- the one line
client/session.py needs to open its TLS connection -- ran this
__init__ first and pulled config_server, and therefore the server's
JWT signing secret and blob-storage root, into every client process.
security/tls.py itself imports only ``ssl`` and the shared ``config``
module, so keeping this file free of re-exports leaves the client with
exactly the transport code it needs and nothing server-side.

This is the same defect as the one fixed in auth/__init__.py, in a
second package: a package __init__ eagerly importing server-only
submodules on behalf of a client-safe sibling.

Consumers import by full module path
(``from security.jwt_handler import JWTHandler``), which is what every
caller in this repository already did -- nothing ever used
``from security import ...``. Server behavior is unchanged; only the
import graph is.

Do not add re-exports here. The boundary is enforced by
tests/test_client_import_boundary.py.
"""
