"""
Tests for Phase 5 (Secure Group Key Distribution)'s core mechanism:
ConversationStore.ensure_direct_conversation_id() and
ClientSession.set_current_chat() consuming it, against the real
database.

Proves the end-to-end claim: for a direct conversation, KeyManager
ends up addressed by the real conversation_id, resolved without
ClientSession ever touching the database itself, and cached so a
second resolution is free.

Run with:
    pytest tests/test_conversation_store_key_resolution.py -v
"""

import uuid

from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.conversation_store import ConversationStore
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Key Resolution Test",
            "username": f"kmres_{suffix_hint}{suffix}",
            "email": f"kmres_{suffix_hint}{suffix}@example.com",
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


def test_ensure_direct_conversation_id_creates_and_caches():
    a = _register_user("a_")
    b = _register_user("b_")

    try:
        store = ConversationStore()

        conversation_id = store.ensure_direct_conversation_id(a["user_id"], b["username"])

        assert conversation_id is not None
        uuid.UUID(conversation_id)  # must be a real UUID string

        # Second call must be a cache hit returning the identical id,
        # not a second row.
        again = store.ensure_direct_conversation_id(a["user_id"], b["username"])
        assert again == conversation_id
    finally:
        _delete_user(a["username"])
        _delete_user(b["username"])


def test_ensure_direct_conversation_id_updates_existing_summary():
    a = _register_user("a_")
    b = _register_user("b_")

    try:
        store = ConversationStore()

        # A placeholder summary exists (e.g. "b" just came online), with
        # no conversation_id yet -- exactly update_online_status()'s shape.
        store._summaries[b["username"]] = ConversationSummary(
            conversation_id=None,
            username=b["username"],
            is_online=True,
            latest_message=None,
        )

        conversation_id = store.ensure_direct_conversation_id(a["user_id"], b["username"])

        assert store._summaries[b["username"]].conversation_id == conversation_id
    finally:
        _delete_user(a["username"])
        _delete_user(b["username"])


def test_set_current_chat_resolves_conversation_id_for_a_new_direct_summary():
    """The full ClientSession-facing claim: opening a brand-new direct
    conversation (conversation_id unknown) leaves current_conversation_id
    populated with a real id, ready for KeyManager -- with zero database
    code inside ClientSession itself (only conversation_store is called)."""
    a = _register_user("a_")
    b = _register_user("b_")

    try:
        session = ClientSession()
        session.user_id = a["user_id"]
        session.username = a["username"]

        summary = ConversationSummary(
            conversation_id=None,
            username=b["username"],
            is_online=True,
            latest_message=None,
        )

        session.set_current_chat(summary)

        assert session.current_chat == b["username"]
        assert session.current_chat_is_group is False
        assert session.current_conversation_id is not None
        uuid.UUID(session.current_conversation_id)

        # Matches what ensure_direct_conversation_id() would itself
        # resolve for the same pair -- single source of truth.
        expected = session.conversation_store.ensure_direct_conversation_id(
            a["user_id"], b["username"]
        )
        assert session.current_conversation_id == expected
    finally:
        _delete_user(a["username"])
        _delete_user(b["username"])


def test_set_current_chat_uses_group_conversation_id_directly():
    """A group summary already carries a real conversation_id -- no
    resolution should be attempted (and none is needed)."""
    session = ClientSession()
    session.user_id = str(uuid.uuid4())
    session.username = "irrelevant"

    summary = ConversationSummary(
        conversation_id="a-real-group-id",
        username=None,
        is_online=False,
        latest_message=None,
        is_group=True,
        group_name="Trio",
        participants=["b", "c"],
    )

    session.set_current_chat(summary)

    assert session.current_chat == "a-real-group-id"
    assert session.current_chat_is_group is True
    assert session.current_conversation_id == "a-real-group-id"
