"""
Server-Only Configuration

Everything the SERVER needs and a client must never hold: database
credentials, the JWT signing secret, password-hashing parameters, and
the blob-storage root (D0 -- Configuration & Network Separation).

Split out of config.py so the boundary is structural rather than
conventional: config.py is safe to ship to every client machine, this
module is not. A client build that reaches for any value here is
importing the wrong module, and that is visible at the import line
rather than buried in a runtime failure.

Imported only by server-side modules:
    database/connection.py      -- DATABASE_URL
    security/jwt_handler.py     -- JWT_* / token lifetimes
    security/password_handler.py-- ARGON2_*
    auth/authentication_service.py -- token lifetimes, lockout policy
    storage/encrypted_blob_store.py -- FILE_STORAGE_ROOT
    alembic/env.py              -- DATABASE_URL

Known, temporary exception (D0 scope limit): client code still reads
the database directly (client/session.py, client/conversation_store.py,
gui/main_window.py), so a client process today still imports this
module transitively through database.connection. Moving those
operations behind the server is what removes that dependency; D0 only
establishes the boundary they will later respect.

Environment variable names are unchanged from before the split -- an
existing .env keeps working as-is.
"""

import os
from pathlib import Path

from config import ROOT_DIR

# ---------------------------------------------------------------
# Database Configuration
#
# Overridable via the DATABASE_URL environment variable so the same
# code can point at a local dev Postgres instance or a production one
# without editing source.
#
# The database is reached by the server only. It should stay bound to
# the server host's loopback interface -- clients connect to the chat
# server over TLS, never to PostgreSQL directly.
# ---------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5432/qrscs"
)

# ---------------------------------------------------------------
# Authentication Configuration
#
# JWT_SECRET_KEY MUST be overridden via the environment in any real
# deployment -- the fallback below is for local development only and
# must never be used in production. Anyone holding this value can
# forge a token for any user, which is precisely why it lives here and
# not in the shared module.
# ---------------------------------------------------------------

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-insecure-secret-change-me")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.environ.get("JWT_ISSUER", "qrscs")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "qrscs_users")

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Argon2id parameters (time_cost, memory_cost in KiB, parallelism).
# These defaults follow OWASP's current minimum recommendation for
# Argon2id and can be tuned per deployment hardware.
ARGON2_TIME_COST = int(os.environ.get("ARGON2_TIME_COST", "3"))
ARGON2_MEMORY_COST = int(os.environ.get("ARGON2_MEMORY_COST", "65536"))
ARGON2_PARALLELISM = int(os.environ.get("ARGON2_PARALLELISM", "4"))

# Number of consecutive failed login attempts after which an account is
# automatically locked (status set to "locked") and login is rejected
# until manually unlocked.
MAX_FAILED_LOGIN_ATTEMPTS = int(os.environ.get("MAX_FAILED_LOGIN_ATTEMPTS", "5"))

# ---------------------------------------------------------------
# File Storage Configuration
#
# Root directory for encrypted payload blobs too large to store
# inline in messages.ciphertext (Phase 6 -- Secure File & Image
# Transfer Infrastructure). Overridable via FILE_STORAGE_ROOT for
# deployments that want blobs outside the project tree. Named
# "storage_blobs" (not "storage") to avoid colliding with the
# storage/ code package. Mirrors the logs/ directory pattern
# (logger_config.py) -- created on first use, not at import time.
# ---------------------------------------------------------------

FILE_STORAGE_ROOT = Path(
    os.environ.get("FILE_STORAGE_ROOT", str(ROOT_DIR / "storage_blobs"))
)


def validate_server_config():
    """
    Validate required server-side configuration and raise helpful
    errors. Shared settings are validated separately by
    config.validate_config().
    """

    if not DATABASE_URL:
        raise ValueError(
            "DATABASE_URL must be set in the environment or in .env. "
            "Example: postgresql+psycopg2://user:pass@host:5432/dbname"
        )

    if DATABASE_URL.startswith("sqlite"):
        raise ValueError(
            "SQLite is not supported. DATABASE_URL must point to PostgreSQL."
        )

    if not JWT_SECRET_KEY or JWT_SECRET_KEY == "dev-only-insecure-secret-change-me":
        raise ValueError(
            "JWT_SECRET_KEY must be set to a strong secret in the environment or .env. "
            "The development fallback is insecure and may not be used in production."
        )

    if ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
        raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer.")

    if REFRESH_TOKEN_EXPIRE_DAYS <= 0:
        raise ValueError("REFRESH_TOKEN_EXPIRE_DAYS must be a positive integer.")

    if not JWT_ISSUER:
        raise ValueError("JWT_ISSUER must be set in the environment or .env.")

    if not JWT_AUDIENCE:
        raise ValueError("JWT_AUDIENCE must be set in the environment or .env.")

    if ARGON2_TIME_COST <= 0:
        raise ValueError("ARGON2_TIME_COST must be a positive integer.")

    if ARGON2_MEMORY_COST < 8:
        raise ValueError("ARGON2_MEMORY_COST must be at least 8 KiB.")

    if ARGON2_PARALLELISM <= 0:
        raise ValueError("ARGON2_PARALLELISM must be a positive integer.")

    if MAX_FAILED_LOGIN_ATTEMPTS <= 0:
        raise ValueError("MAX_FAILED_LOGIN_ATTEMPTS must be a positive integer.")


validate_server_config()
