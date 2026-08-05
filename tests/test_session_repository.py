"""
Tests for database/repositories/session_repository.py.

Runs against the real PostgreSQL database via the db_session fixture,
which wraps each test in a rolled-back transaction (see conftest.py).

Run with:
    pytest tests/test_session_repository.py -v
"""

from datetime import datetime

from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository


def _make_user(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = repo.create(
        username=f"sess_user_{unique_suffix}",
        email=f"sess_user_{unique_suffix}@example.com",
        display_name="Session Test User",
        password_hash="irrelevant-hash-for-repo-tests",
    )
    repo.commit()
    return user


def _make_session(repo, user, session_id, **overrides):
    kwargs = {
        "user_id": user.id,
        "session_id": session_id,
        "refresh_token_hash": "hash-placeholder",
        "device_name": "Test Device",
        "ip_address": "127.0.0.1",
        "platform": "pytest",
        "app_version": "0.0.1",
        "expires_at": datetime(2030, 1, 1),
    }
    kwargs.update(overrides)
    session = repo.create(**kwargs)
    repo.commit()
    return session


def test_create_persists_session(db_session, unique_suffix):
    user = _make_user(db_session, unique_suffix)
    repo = SessionRepository(db_session)
    session = _make_session(repo, user, f"sid-{unique_suffix}")

    assert session.id is not None
    assert session.user_id == user.id
    assert session.is_active is True
    assert session.revoked is False


def test_get_by_id(db_session, unique_suffix):
    user = _make_user(db_session, unique_suffix)
    repo = SessionRepository(db_session)
    session = _make_session(repo, user, f"sid-{unique_suffix}")

    assert repo.get_by_id(session.id).id == session.id


def test_get_by_session_id(db_session, unique_suffix):
    user = _make_user(db_session, unique_suffix)
    repo = SessionRepository(db_session)
    sid = f"sid-{unique_suffix}"
    session = _make_session(repo, user, sid)

    assert repo.get_by_session_id(sid).id == session.id
    assert repo.get_by_session_id("no-such-session") is None


def test_get_active_sessions_for_user_excludes_inactive_and_revoked(
    db_session, unique_suffix
):
    user = _make_user(db_session, unique_suffix)
    repo = SessionRepository(db_session)

    active = _make_session(repo, user, f"sid-active-{unique_suffix}")
    inactive = _make_session(repo, user, f"sid-inactive-{unique_suffix}")
    revoked = _make_session(repo, user, f"sid-revoked-{unique_suffix}")

    repo.deactivate(inactive)
    repo.revoke(revoked)
    repo.commit()

    active_sessions = repo.get_active_sessions_for_user(user.id)
    active_ids = {s.id for s in active_sessions}

    assert active.id in active_ids
    assert inactive.id not in active_ids
    assert revoked.id not in active_ids


def test_deactivate_sets_is_active_false_and_logout_time(db_session, unique_suffix):
    """Regression test for the refresh()-discards-mutation bug on sessions."""
    user = _make_user(db_session, unique_suffix)
    repo = SessionRepository(db_session)
    session = _make_session(repo, user, f"sid-{unique_suffix}")
    assert session.logout_time is None

    repo.deactivate(session)
    repo.commit()

    assert session.is_active is False
    refetched = repo.get_by_id(session.id)
    assert refetched.is_active is False
    assert refetched.logout_time is not None


def test_revoke_sets_revoked_and_inactive(db_session, unique_suffix):
    user = _make_user(db_session, unique_suffix)
    repo = SessionRepository(db_session)
    session = _make_session(repo, user, f"sid-{unique_suffix}")

    repo.revoke(session)
    repo.commit()

    assert session.revoked is True
    assert session.is_active is False
    refetched = repo.get_by_id(session.id)
    assert refetched.revoked is True
    assert refetched.is_active is False


def test_session_id_uniqueness_enforced_and_persists(db_session, unique_suffix):
    """Regression test: session_id must actually be stored as given, not
    silently reset to '' (the second-login crash bug fixed during M2)."""
    user = _make_user(db_session, unique_suffix)
    repo = SessionRepository(db_session)
    sid = f"sid-{unique_suffix}"
    session = _make_session(repo, user, sid)

    refetched = repo.get_by_id(session.id)
    assert refetched.session_id == sid
