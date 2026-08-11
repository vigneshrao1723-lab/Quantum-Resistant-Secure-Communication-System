"""
Tests for Issue 3 (real-application testing bug report): User Must Be
Searched By Unique ID.

ClientSession.find_user_by_id() is a direct client-side DB read (see
its docstring for why that's consistent with this app's existing
trust model) -- these tests exercise it directly against real
registered users, without needing a running server/socket at all.

Run with:
    pytest tests/test_user_id_search.py -v
"""

import uuid

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "ID Search Test",
            "username": f"idsearch_{suffix_hint}{suffix}",
            "email": f"idsearch_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete_user(username):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(username)
        if user is not None:
            for session in SessionRepository(db).get_active_sessions_for_user(user.id):
                db.delete(session)
            db.delete(user)
            db.commit()
    finally:
        db.close()


def _make_authenticated_session(user_payload):
    session = ClientSession()
    session.user_id = user_payload["user_id"]
    session.username = user_payload["username"]
    return session


@pytest.fixture()
def registered_pair():
    searcher_payload = _register_user("searcher_")
    target_payload = _register_user("target_")

    yield searcher_payload, target_payload

    _delete_user(searcher_payload["username"])
    _delete_user(target_payload["username"])


def test_valid_unique_id_finds_the_correct_user(registered_pair):
    searcher_payload, target_payload = registered_pair
    session = _make_authenticated_session(searcher_payload)

    result = session.find_user_by_id(target_payload["user_id"])

    assert result is not None
    assert result["user_id"] == target_payload["user_id"]
    assert result["username"] == target_payload["username"]
    assert "email" not in result
    assert "password_hash" not in result


def test_wellformed_but_nonexistent_id_returns_none(registered_pair):
    searcher_payload, _target_payload = registered_pair
    session = _make_authenticated_session(searcher_payload)

    result = session.find_user_by_id(str(uuid.uuid4()))

    assert result is None


@pytest.mark.parametrize(
    "malformed_id",
    ["not-a-uuid", "", "12345", "   ", "'; DROP TABLE users; --"],
)
def test_malformed_id_returns_none_not_a_crash(registered_pair, malformed_id):
    searcher_payload, _target_payload = registered_pair
    session = _make_authenticated_session(searcher_payload)

    result = session.find_user_by_id(malformed_id)

    assert result is None


def test_malformed_and_nonexistent_ids_are_indistinguishable():
    """Deliberate: don't leak whether a guess was 'well-formed but
    wrong' vs. 'garbage' -- both must look identical to the caller."""
    searcher_payload = _register_user("indist_")
    session = _make_authenticated_session(searcher_payload)

    try:
        malformed_result = session.find_user_by_id("garbage")
        nonexistent_result = session.find_user_by_id(str(uuid.uuid4()))
        assert malformed_result is None
        assert nonexistent_result is None
    finally:
        _delete_user(searcher_payload["username"])


def test_two_registrations_never_collide_on_id():
    """Duplicate/ambiguous IDs are not reachable: id is the DB primary
    key, uniqueness is enforced by Postgres itself. Proven here rather
    than asserted as a comment."""
    payload_a = _register_user("uniq_a_")
    payload_b = _register_user("uniq_b_")

    try:
        assert payload_a["user_id"] != payload_b["user_id"]

        session = _make_authenticated_session(payload_a)
        result_a = session.find_user_by_id(payload_a["user_id"])
        result_b = session.find_user_by_id(payload_b["user_id"])

        assert result_a["username"] != result_b["username"]
        assert result_a["user_id"] != result_b["user_id"]
    finally:
        _delete_user(payload_a["username"])
        _delete_user(payload_b["username"])


def test_unauthenticated_session_cannot_search():
    """A ClientSession that never logged in (user_id never set) must
    not be able to perform a lookup at all."""
    session = ClientSession()
    assert session.user_id is None

    with pytest.raises(PermissionError):
        session.find_user_by_id(str(uuid.uuid4()))


def test_found_user_can_be_opened_as_a_conversation(registered_pair):
    """End-to-end proof that a valid lookup leads to an openable
    conversation, via the same ConversationStore path online-user
    clicking already uses."""
    searcher_payload, target_payload = registered_pair
    session = _make_authenticated_session(searcher_payload)

    result = session.find_user_by_id(target_payload["user_id"])
    assert result is not None

    conversation_id = session.conversation_store.ensure_direct_conversation_id(
        session.user_id, result["username"]
    )

    assert conversation_id is not None
    assert uuid.UUID(conversation_id)  # a real, parseable conversation id
