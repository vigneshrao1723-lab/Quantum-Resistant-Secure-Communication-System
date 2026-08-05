"""
Database connection module.

Initializes the SQLAlchemy engine and session factory using
environment configuration loaded by config.py.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    future=True,
    echo=False,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


def get_db():
    """Yield a database session for request or service usage."""

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
