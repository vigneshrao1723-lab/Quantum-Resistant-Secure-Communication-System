"""
Shared pytest fixtures for the authentication test suite.

Tests run against the real PostgreSQL database configured via
DATABASE_URL (config.py forbids SQLite), so every test is wrapped in an
outer transaction + SAVEPOINT that is rolled back on teardown. This
means tests can freely call session.commit() (as the application code
under test does) without ever persisting anything permanently, and
without needing manual cleanup.
"""

import uuid

import pytest
from sqlalchemy import event

from auth.authentication_service import AuthenticationService
from database.connection import SessionLocal, engine


@pytest.fixture()
def db_session():
    """A SQLAlchemy session bound to a transaction that is always rolled back."""
    connection = engine.connect()
    outer_transaction = connection.begin()
    session = SessionLocal(bind=connection)

    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, trans):
        nonlocal nested
        if not nested.is_active:
            nested = connection.begin_nested()

    try:
        yield session
    finally:
        session.close()
        outer_transaction.rollback()
        connection.close()


@pytest.fixture()
def auth_service(db_session):
    """An AuthenticationService wired to the transactional test session."""
    return AuthenticationService(db_session)


@pytest.fixture()
def unique_suffix():
    """A short unique string to keep per-test usernames/emails collision-free."""
    return uuid.uuid4().hex[:10]


@pytest.fixture()
def strong_password():
    """A password that satisfies PasswordHandler's policy."""
    return "Str0ng!Passw0rd"


@pytest.fixture()
def registration_payload(unique_suffix, strong_password):
    """A valid RegisterRequest-shaped dict of kwargs, unique per test."""
    return {
        "full_name": "Test User",
        "username": f"user_{unique_suffix}",
        "email": f"user_{unique_suffix}@example.com",
        "password": strong_password,
        "confirm_password": strong_password,
        "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
    }
