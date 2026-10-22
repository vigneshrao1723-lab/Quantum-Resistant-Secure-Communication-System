"""
Shared pytest fixtures for the authentication test suite.

Tests run against the real PostgreSQL database configured via
DATABASE_URL (config.py forbids SQLite), so every test is wrapped in an
outer transaction + SAVEPOINT that is rolled back on teardown. This
means tests can freely call session.commit() (as the application code
under test does) without ever persisting anything permanently, and
without needing manual cleanup.
"""

import sys
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


@pytest.fixture(autouse=True)
def _retire_chat_windows_of_finished_test():
    """
    Desktop GUI tests deliberately keep their ChatWindow objects alive after
    the test body (``_KEEP_ALIVE``) so Qt never garbage-collects a window that
    still has live socket threads. A window kept alive that way outlives its
    own ClientSession, which the test's fixtures disconnect at teardown. A
    message or error still in flight for it is then delivered on the NEXT
    test's Qt event pump, fails against the disconnected session, and
    ChatWindow.show_error() opens a modal QMessageBox.critical that nothing in
    a headless run can dismiss -- hanging an unrelated test forever.

    After each test, stop those finished-test windows from raising modals.
    Only windows that already exist when the test ends are touched (so the
    running test's own dialogs, patched or real, are unaffected), and nothing
    is hidden, closed or destroyed.
    """
    yield

    widgets = sys.modules.get("PySide6.QtWidgets")
    chat_window = sys.modules.get("gui.chat_window")
    if widgets is None or chat_window is None:
        return
    app = widgets.QApplication.instance()
    if app is None:
        return
    for window in app.topLevelWidgets():
        if not isinstance(window, chat_window.ChatWindow):
            continue
        if getattr(window, "_retired_by_test_teardown", False):
            continue
        window._retired_by_test_teardown = True
        if "show_error" in vars(window):
            # The test already replaced show_error on this window itself.
            continue
        try:
            window.session.error_occurred.disconnect(window.show_error)
        except (RuntimeError, TypeError):
            pass
        window.show_error = lambda message: None


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
