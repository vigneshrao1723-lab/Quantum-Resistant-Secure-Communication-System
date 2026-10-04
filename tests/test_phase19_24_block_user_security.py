"""
Phase 19.24 -- Block User: server-side security and enforcement tests.

Unlike Mute/Archive (storage/secure_key_store.py -- local-only,
never server-enforced, since neither is a security control), a block
MUST be enforced by the SERVER to mean anything -- a local-only block
would still let the blocked party message, verify, and see presence
from a second device or a fresh reinstall. These tests drive REAL
ClientSession objects against a REAL test server (the exact same
`connect`/`accounts`/`_wait_for` harness tests/test_read_receipts_
realtime.py already established) and prove every real-application
enforcement point in server/client_handler.py: direct-message relay,
verification requests, presence (user_list), typing indicators, user
search, and new-group membership -- plus the one thing blocking must
NOT do: retroactively split an EXISTING shared group thread.

Run with:
    pytest tests/test_phase19_24_block_user_security.py -v
"""

import time
import uuid

from crypto.key_manager import fingerprint_public_key
from database.connection import SessionLocal
from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from tests.test_read_receipts_realtime import (  # noqa: F401
    _open_direct,
    _wait_for,
    accounts,
    connect,
    running_server,
)


def _mutually_verify(a, b, a_name, b_name):
    assert _wait_for(lambda: a.key_manager.get_public_key(b_name) is not None)
    assert _wait_for(lambda: b.key_manager.get_public_key(a_name) is not None)
    a.key_store.verify_peer_fingerprint(b_name, fingerprint_public_key(b.key_manager.public_key))
    b.key_store.verify_peer_fingerprint(a_name, fingerprint_public_key(a.key_manager.public_key))


def _group_member_usernames(conversation_id):
    db = SessionLocal()
    try:
        rows = (
            db.query(ConversationMember)
            .filter(ConversationMember.conversation_id == uuid.UUID(str(conversation_id)))
            .all()
        )
        user_repo = UserRepository(db)
        return {user_repo.get_by_id(row.user_id).username for row in rows}
    finally:
        db.close()


def _find_group_id_by_name(name):
    """create_group_conversation() is fire-and-forget (no return
    value -- the result arrives asynchronously via handle_group_
    create_result()), so the real, server-assigned conversation_id is
    read directly from the database instead, by the unique name this
    test gave the group."""

    db = SessionLocal()
    try:
        row = (
            db.query(Conversation)
            .filter(Conversation.name == name, Conversation.type == Conversation.TYPE_GROUP)
            .order_by(Conversation.created_at.desc())
            .first()
        )
        return str(row.id) if row is not None else None
    finally:
        db.close()


# ========================================================================
# Direct messaging
# ========================================================================


def test_blocking_prevents_direct_message_delivery_in_both_directions(
    tmp_path, connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    alice_name, bob_name = alice_payload["username"], bob_payload["username"]

    _mutually_verify(alice, bob, alice_name, bob_name)

    result = alice.block_user(bob_name)
    assert result["success"], result.get("error")

    received_by_alice = []
    received_by_bob = []
    alice.message_received.connect(
        lambda identity_key, sender, text: received_by_alice.append(text)
    )
    bob.message_received.connect(
        lambda identity_key, sender, text: received_by_bob.append(text)
    )

    _open_direct(bob, alice_name)
    bob.send_chat_message("hi alice, can you hear me?")

    _open_direct(alice, bob_name)
    alice.send_chat_message("hi bob, can you hear me?")

    # A real, deterministic wait for either message to have had a
    # genuine chance to arrive.
    time.sleep(0.5)

    assert received_by_alice == []
    assert received_by_bob == []


def test_unblocking_restores_direct_message_delivery(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    alice_name, bob_name = alice_payload["username"], bob_payload["username"]

    _mutually_verify(alice, bob, alice_name, bob_name)

    assert alice.block_user(bob_name)["success"]
    assert alice.unblock_user(bob_name)["success"]

    received_by_alice = []
    alice.message_received.connect(
        lambda identity_key, sender, text: received_by_alice.append(text)
    )

    _open_direct(bob, alice_name)
    bob.send_chat_message("are you there now?")

    assert _wait_for(lambda: received_by_alice == ["are you there now?"])


# ========================================================================
# Verification requests
# ========================================================================


def test_blocking_prevents_verification_requests(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    alice_name, bob_name = alice_payload["username"], bob_payload["username"]

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_name) is not None)

    assert alice.block_user(bob_name)["success"]

    notifications = []
    alice.inbox_updated.connect(lambda notification: notifications.append(notification))

    bob.request_verification(alice_name)

    time.sleep(0.5)
    assert notifications == []


# ========================================================================
# Presence
# ========================================================================


def test_blocking_hides_presence_in_both_directions(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    alice_name, bob_name = alice_payload["username"], bob_payload["username"]

    assert _wait_for(lambda: bob_name in alice.online_users)
    assert _wait_for(lambda: alice_name in bob.online_users)

    assert alice.block_user(bob_name)["success"]

    assert _wait_for(lambda: bob_name not in alice.online_users)
    assert _wait_for(lambda: alice_name not in bob.online_users)


# ========================================================================
# Typing indicator
# ========================================================================


def test_blocking_prevents_typing_indicator_in_direct_conversation(
    tmp_path, connect, accounts
):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    alice_name, bob_name = alice_payload["username"], bob_payload["username"]

    _mutually_verify(alice, bob, alice_name, bob_name)

    # A real conversation_id both sides agree on -- set_current_chat()
    # resolves (and, if needed, creates) it via the same real server
    # round-trip open_conversation() uses.
    _open_direct(bob, alice_name)
    bob.send_chat_message("seed the conversation")
    _open_direct(alice, bob_name)
    conversation_id = alice.current_conversation_id
    assert conversation_id is not None

    assert alice.block_user(bob_name)["success"]

    received = []
    alice.typing_indicator_received.connect(
        lambda conv_id, username, is_typing: received.append((username, is_typing))
    )

    bob.send_typing_indicator(conversation_id, True)

    time.sleep(0.5)
    assert received == []


# ========================================================================
# Search / discovery
# ========================================================================


def test_blocking_hides_user_from_phone_number_search(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    alice_name, bob_name = alice_payload["username"], bob_payload["username"]

    # Before blocking, the search genuinely finds the other party.
    found_before = alice.find_user_by_phone_number(bob_payload["phone_number"])
    assert found_before is not None
    assert found_before["username"] == bob_name

    assert alice.block_user(bob_name)["success"]

    found_after = alice.find_user_by_phone_number(bob_payload["phone_number"])
    assert found_after is None

    # And the reverse direction -- bob looking up alice -- is ALSO
    # hidden, since the block check covers either direction.
    found_reverse = bob.find_user_by_phone_number(alice_payload["phone_number"])
    assert found_reverse is None


def test_blocking_hides_user_from_id_lookup(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    bob_name = bob_payload["username"]

    assert alice.find_user_by_id(str(bob_payload["user_id"])) is not None

    assert alice.block_user(bob_name)["success"]

    assert alice.find_user_by_id(str(bob_payload["user_id"])) is None


# ========================================================================
# Groups
# ========================================================================


def test_blocked_user_excluded_from_a_brand_new_group(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    carol = connect(carol_payload)
    alice_name = alice_payload["username"]
    bob_name = bob_payload["username"]
    carol_name = carol_payload["username"]

    assert alice.block_user(bob_name)["success"]

    # A unique name per run -- this is a REAL, persistent Postgres
    # database (not a throwaway per-test schema), so a fixed literal
    # name risks matching a stale, member-less row left over from an
    # earlier debugging run whose creator account has since been
    # deleted, silently resolving to the WRONG conversation_id.
    group_name = f"Trip Planning {uuid.uuid4().hex[:8]}"
    alice.create_group_conversation(group_name, [bob_name, carol_name])
    assert _wait_for(lambda: _find_group_id_by_name(group_name) is not None)
    conversation_id = _find_group_id_by_name(group_name)

    assert _wait_for(lambda: carol_name in _group_member_usernames(conversation_id))
    assert bob_name not in _group_member_usernames(conversation_id)
    assert alice_name in _group_member_usernames(conversation_id)


def test_blocked_candidate_excluded_from_group_add_members(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    carol = connect(carol_payload)
    carol_name = carol_payload["username"]
    bob_name = bob_payload["username"]

    group_name = f"Book Club {uuid.uuid4().hex[:8]}"
    alice.create_group_conversation(group_name, [carol_name])
    assert _wait_for(lambda: _find_group_id_by_name(group_name) is not None)
    conversation_id = _find_group_id_by_name(group_name)
    assert _wait_for(lambda: carol_name in _group_member_usernames(conversation_id))

    assert alice.block_user(bob_name)["success"]

    alice.add_group_members(conversation_id, [bob_name])

    time.sleep(0.5)
    assert bob_name not in _group_member_usernames(conversation_id)


def test_existing_shared_group_messaging_is_unaffected_by_a_block(
    tmp_path, connect, accounts
):
    """A 1:1 block must never retroactively split messages already
    flowing through a shared group thread -- see database/models/
    blocked_user.py's own docstring."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    alice_name, bob_name = alice_payload["username"], bob_payload["username"]

    _mutually_verify(alice, bob, alice_name, bob_name)

    group_name = f"Old Friends {uuid.uuid4().hex[:8]}"
    alice.create_group_conversation(group_name, [bob_name])
    assert _wait_for(lambda: _find_group_id_by_name(group_name) is not None)
    conversation_id = _find_group_id_by_name(group_name)
    assert _wait_for(lambda: bob_name in _group_member_usernames(conversation_id))
    assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

    assert alice.block_user(bob_name)["success"]

    received = []
    bob.message_received.connect(
        lambda identity_key, sender, text: received.append(text)
    )

    # The real path a group chat's own composer uses: set_current_chat()
    # with a group summary, exactly like gui/chat_window.py::
    # open_conversation() does for a group row.
    alice.set_current_chat(ConversationSummary(
        conversation_id=conversation_id, username=None, is_group=True,
        group_name=group_name, is_online=True, latest_message=None,
    ))
    alice.send_chat_message("still in the group together")

    assert _wait_for(lambda: received == ["still in the group together"])


# ========================================================================
# Basic validation / bookkeeping
# ========================================================================


def test_cannot_block_yourself(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    alice = connect(alice_payload)

    result = alice.block_user(alice_payload["username"])
    assert not result["success"]


def test_blocking_a_nonexistent_user_fails(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    alice = connect(alice_payload)

    result = alice.block_user("no_such_user_at_all_xyz")
    assert not result["success"]


def test_get_blocked_users_reflects_current_state(tmp_path, connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    bob_name = bob_payload["username"]

    assert alice.get_blocked_users() == []

    assert alice.block_user(bob_name)["success"]
    assert alice.get_blocked_users() == [bob_name]

    assert alice.unblock_user(bob_name)["success"]
    assert alice.get_blocked_users() == []


def test_block_is_directional_not_reflexive(tmp_path, connect, accounts):
    """Alice blocking Bob never blocks Bob FROM Alice's perspective --
    only the row Alice created exists; Bob's own block list stays
    empty (the messaging enforcement above is a SEPARATE, deliberate
    either-direction check -- this test proves the underlying DATA
    itself stays directional, not that messaging is one-directional)."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    bob_name = bob_payload["username"]

    assert alice.block_user(bob_name)["success"]

    assert alice.get_blocked_users() == [bob_name]
    assert bob.get_blocked_users() == []
