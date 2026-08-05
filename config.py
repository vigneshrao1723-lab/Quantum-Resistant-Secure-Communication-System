"""
Global Configuration

Shared configuration used by both the client and server.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent
load_dotenv(ROOT_DIR / ".env")

# Network Configuration
HOST = "127.0.0.1"
PORT = 5000

# Communication Configuration
BUFFER_SIZE = 1024
ENCODING = "utf-8"

# Key Exchange Configuration
# Choose which algorithm establishes the AES-256 session key.
# "KYBER" -> post-quantum ML-KEM-768 key encapsulation
# "RSA"   -> classical RSA-2048 encryption (kept for benchmarking)
KEY_EXCHANGE_ALGORITHM = "KYBER"

# ---------------------------------------------------------------
# Database Configuration (server-side only)
#
# Overridable via the DATABASE_URL environment variable so the
# same code can point at a local dev Postgres instance or a
# production one without editing source.
# ---------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5432/qrscs"
)

# ---------------------------------------------------------------
# Authentication Configuration (server-side only)
#
# JWT_SECRET_KEY MUST be overridden via the environment in any
# real deployment -- the fallback below is for local development
# only and must never be used in production.
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

# Application Information
APP_NAME = "Quantum-Resistant Secure Communication System"
VERSION = "1.0.0"


def validate_config():
    """Validate required configuration values and raise helpful errors."""

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


validate_config()
