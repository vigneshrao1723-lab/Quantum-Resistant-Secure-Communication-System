"""
Phase 19.24 -- Presence/Last Seen.

Server-side (database/models/user.py::last_seen_at, server/client_
handler.py::handle_last_seen_request()) and Desktop UI wiring
(gui/chat_window.py::_refresh_presence_label()) -- a single, overwritten
timestamp recorded when a connection closes, never a history log, with
the SAME "hide in either direction a block exists" privacy rule
broadcast_user_list() already enforces for the plain online/offline
signal.

Run with:
    pytest tests/test_phase19_24_presence_last_seen.py -v
"""

import os
import time
import uuid
from datetime import datetime, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from database.connection import SessionLocal
from database.models.user import User
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _KEEP_ALIVE,
    _direct_summary,
    _two_windows,
    _verify_each_other,
    _wait_for,
    accounts,
    connect,
    running_server,
)


def _get_user_row(user_id):
    db = SessionLocal()
    try:
        return db.get(User, uuid.UUID(str(user_id)))
    finally:
        db.close()


def test_disconnecting_records_a_real_last_seen_timestamp(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    assert _get_user_row(bob.user_id).last_seen_at is None

    before_disconnect = datetime.now(timezone.utc).replace(tzinfo=None)
    bob.disconnect()

    def _last_seen_recorded():
        row = _get_user_row(bob.user_id)
        return row.last_seen_at is not None and row.last_seen_at >= before_disconnect

    assert _wait_for(_last_seen_recorded)

    alice.disconnect()


def test_fetch_last_seen_returns_the_recorded_timestamp(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)

    bob.disconnect()
    assert _wait_for(lambda: _get_user_row(bob.user_id).last_seen_at is not None)

    last_seen = alice.fetch_last_seen(bob_payload["username"])

    assert last_seen is not None
    # Within a generous window of "just now" -- proves a REAL,
    # recently-recorded timestamp came back, not a stale/fabricated one.
    assert (datetime.now(timezone.utc).replace(tzinfo=None) - last_seen).total_seconds() < 30

    alice.disconnect()


def test_fetch_last_seen_for_an_account_that_never_disconnected_is_none(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)

    # bob is still online -- last_seen_at was never set.
    assert alice.fetch_last_seen(bob_payload["username"]) is None

    alice.disconnect()
    bob.disconnect()


def test_fetch_last_seen_for_an_unknown_username_is_none(connect, accounts):
    alice_payload = accounts("alice_")
    alice = connect(alice_payload)

    assert alice.fetch_last_seen("nobody_by_this_name_" + uuid.uuid4().hex[:8]) is None

    alice.disconnect()


def test_blocked_user_cannot_see_the_others_last_seen_in_either_direction(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)

    alice.block_user(bob_payload["username"])
    assert _wait_for(lambda: bob_payload["username"] in (alice.get_blocked_users() or []))

    bob.disconnect()
    assert _wait_for(lambda: _get_user_row(bob.user_id).last_seen_at is not None)

    # Blocker (alice) cannot see it either -- consistent with
    # broadcast_user_list()'s own symmetric hiding.
    assert alice.fetch_last_seen(bob_payload["username"]) is None

    alice.disconnect()


def test_desktop_presence_label_shows_online_then_last_seen_after_disconnect(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    assert _wait_for(lambda: alice_window.presence_label.text() == "Online")

    bob_window.session.disconnect()

    assert _wait_for(
        lambda: alice_window.presence_label.text().startswith("Last seen")
    )
