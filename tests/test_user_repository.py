"""
Tests for database/repositories/user_repository.py.

Runs against the real PostgreSQL database via the db_session fixture,
which wraps each test in a rolled-back transaction (see conftest.py).

Run with:
    pytest tests/test_user_repository.py -v
"""

from datetime import datetime

from database.repositories.user_repository import UserRepository


def _make_user(repo, unique_suffix, **overrides):
    kwargs = {
        "username": f"repo_user_{unique_suffix}",
        "email": f"repo_user_{unique_suffix}@example.com",
        "display_name": "Repo Test User",
        "password_hash": "irrelevant-hash-for-repo-tests",
    }
    kwargs.update(overrides)
    user = repo.create(**kwargs)
    repo.commit()
    return user


def test_create_persists_user(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)

    assert user.id is not None
    assert user.username == f"repo_user_{unique_suffix}"
    assert user.failed_login_attempts == 0
    assert user.is_active is True
    assert user.status == "active"


def test_get_by_id(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)

    fetched = repo.get_by_id(user.id)
    assert fetched is not None
    assert fetched.id == user.id


def test_get_by_username(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)

    assert repo.get_by_username(user.username).id == user.id
    assert repo.get_by_username("does-not-exist") is None


def test_get_by_email(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)

    assert repo.get_by_email(user.email).id == user.id
    assert repo.get_by_email("nobody@example.com") is None


def test_get_by_username_or_email_matches_either(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)

    assert repo.get_by_username_or_email(user.username).id == user.id
    assert repo.get_by_username_or_email(user.email).id == user.id
    assert repo.get_by_username_or_email("neither-match") is None


def test_update_last_login_persists_across_flush(db_session, unique_suffix):
    """Regression test for the refresh()-discards-mutation bug: setting
    last_login_at must survive a subsequent flush/commit, not be silently
    reloaded away."""
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)
    assert user.last_login_at is None

    stamp = datetime(2026, 1, 1, 12, 0, 0)
    repo.update_last_login(user, stamp)
    repo.commit()

    assert user.last_login_at == stamp
    refetched = repo.get_by_id(user.id)
    assert refetched.last_login_at == stamp


def test_increment_failed_logins_persists_across_flush(db_session, unique_suffix):
    """Regression test: the counter must actually persist, not silently
    stay at 0 (the exact bug found and fixed during M2)."""
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)

    stamp = datetime(2026, 1, 1, 12, 0, 0)
    repo.increment_failed_logins(user, stamp)
    repo.commit()

    assert user.failed_login_attempts == 1
    assert user.last_failed_login == stamp

    repo.increment_failed_logins(user, stamp)
    repo.commit()
    assert user.failed_login_attempts == 2


def test_reset_failed_logins(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)

    repo.increment_failed_logins(user, datetime(2026, 1, 1))
    repo.commit()
    assert user.failed_login_attempts == 1

    repo.reset_failed_logins(user)
    repo.commit()
    assert user.failed_login_attempts == 0
    assert user.last_failed_login is None


def test_set_locked_true_and_false(db_session, unique_suffix):
    repo = UserRepository(db_session)
    user = _make_user(repo, unique_suffix)
    assert user.status == "active"

    repo.set_locked(user, True)
    repo.commit()
    assert user.status == "locked"
    assert repo.get_by_id(user.id).status == "locked"

    repo.set_locked(user, False)
    repo.commit()
    assert user.status == "active"
