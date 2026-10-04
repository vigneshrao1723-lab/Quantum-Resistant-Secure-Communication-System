"""
Phase 19.24 (continued) -- Message Lifecycle Events: mobile session-
layer wiring (message_id_received / own_message_id_resolved /
message_lifecycle_state_received -- see mobile/session.py's own
declarations for the full rationale).

Mirrors tests/test_mobile_client_session.py's exact harness (real
MobileClientSession against a real server, real desktop ClientSession
as the interop peer) -- proves the DATA these three new signals carry
is correct end to end, on both the live and historical-reload paths,
including receiver-side ML-DSA signature verification for a reaction's
history-recovery path (mirrors tests/test_phase19_24_message_lifecycle
_security.py's identical desktop-side proof).

mobile/app.py's ChatScreen (the actual UI consumer of these signals)
has no existing test harness in this codebase at all -- every existing
mobile test (test_mobile_client_session.py and siblings) exercises
MobileClientSession directly, never a Kivy widget. These tests follow
that same, already-established convention.

Run with:
    pytest tests/test_phase19_24_mobile_lifecycle_wiring.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

import mobile.session as mobile_session_module
from crypto.key_manager import fingerprint_combined_identity
from domain.conversation_summary import ConversationSummary
from mobile.session import MobileClientSession
from tests.test_device_key_sync import PASSWORD, _delete, _register, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def _new_mobile_session(running_server, monkeypatch, payload, storage_dir):
    _state, port = running_server
    monkeypatch.setattr(mobile_session_module, "SERVER_PORT", port)

    session = MobileClientSession(storage_dir=str(storage_dir))
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _mutual_verify(a, b):
    a.observe_peer_identity(b.username, b.key_manager.public_key.decode("utf-8"), b.key_manager.ml_dsa.export_public_key())
    fp_b = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    a.confirm_peer_verified(b.username, fp_b)

    b.observe_peer_identity(a.username, a.key_manager.public_key.decode("utf-8"), a.key_manager.ml_dsa.export_public_key())
    fp_a = fingerprint_combined_identity(a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key())
    b.confirm_peer_verified(a.username, fp_a)


def _two_mobile_sessions(running_server, monkeypatch, tmp_path, hint):
    alice_payload = _register(f"{hint}a_")
    bob_payload = _register(f"{hint}b_")

    alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile")
    bob = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    _mutual_verify(alice, bob)

    # mobile/app.py::ChatScreen._send_text() always calls establish_
    # session_key() before the first send_message() to a conversation
    # -- send_message() itself raises RuntimeError otherwise (mobile/
    # session.py:1463's own guard). A real UI session key exchange, not
    # a shortcut: this generates+distributes a real AES-256 key exactly
    # like a genuine first message would.
    alice.establish_session_key(bob.username)

    return alice, alice_payload, bob, bob_payload


# ------------------------------------------------------------------
# own_message_id_resolved -- the SENDER learns their own live-sent
# message's real id.
# ------------------------------------------------------------------


def test_own_message_id_resolved_fires_for_the_sender(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "ownid"
    )
    try:
        resolved = {}
        alice.own_message_id_resolved.connect(
            lambda receiver, message_id: resolved.update(receiver=receiver, message_id=message_id)
        )

        received = {}
        bob.message_received.connect(
            lambda identity_key, sender, text, historical, status=None: received.update(text=text)
        )

        alice.send_message(bob.username, "hello, learn my own id")

        assert _wait_for(lambda: received.get("text") == "hello, learn my own id")
        assert _wait_for(lambda: resolved.get("message_id") is not None)
        assert resolved["receiver"] == bob.username
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


# ------------------------------------------------------------------
# message_id_received -- a RECEIVER learns a live message's real id,
# and message_lifecycle_state_received carries its reply_to_message_id.
# ------------------------------------------------------------------


def test_message_id_received_and_reply_to_message_id_for_a_live_message(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "liveid"
    )
    try:
        received_ids = []
        bob.message_id_received.connect(
            lambda identity_key, message_id: received_ids.append((identity_key, message_id))
        )

        lifecycle_events = []
        bob.message_lifecycle_state_received.connect(
            lambda *args: lifecycle_events.append(args)
        )

        received_text = {}
        bob.message_received.connect(
            lambda identity_key, sender, text, historical, status=None: received_text.update(text=text)
        )

        alice.send_message(bob.username, "original")
        assert _wait_for(lambda: received_text.get("text") == "original")
        assert _wait_for(lambda: len(received_ids) == 1)

        original_message_id = received_ids[0][1]
        assert received_ids[0][0] == alice.username

        received_text.clear()
        alice.send_message(bob.username, "a reply", reply_to_message_id=original_message_id)
        assert _wait_for(lambda: received_text.get("text") == "a reply")
        assert _wait_for(lambda: len(received_ids) == 2)

        assert _wait_for(lambda: len(lifecycle_events) == 2)

        reply_event = lifecycle_events[1]
        # (identity_key, message_id, reply_to_message_id, is_deleted, edit_version, reactions)
        assert reply_event[2] == original_message_id
        assert reply_event[3] is False
        assert reply_event[4] == 0
        assert reply_event[5] == []
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


# ------------------------------------------------------------------
# Historical reload: message_id_received/message_lifecycle_state_
# received fire per row, correctly carrying deleted/edited/reaction
# state, including receiver-side signature verification for a
# reaction recovered from history.
# ------------------------------------------------------------------


def test_history_reload_reports_lifecycle_state_for_every_row(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "histstate"
    )
    try:
        received_text = {}
        bob.message_received.connect(
            lambda identity_key, sender, text, historical, status=None: received_text.update(text=text)
        )
        received_ids = []
        bob.message_id_received.connect(
            lambda identity_key, message_id: received_ids.append(message_id)
        )

        alice.send_message(bob.username, "will be edited")
        assert _wait_for(lambda: received_text.get("text") == "will be edited")
        assert _wait_for(lambda: len(received_ids) == 1)
        edited_message_id = received_ids[0]

        received_text.clear()
        alice.send_message(bob.username, "will be deleted")
        assert _wait_for(lambda: received_text.get("text") == "will be deleted")
        assert _wait_for(lambda: len(received_ids) == 2)
        deleted_message_id = received_ids[1]

        conversation_id = bob.direct_conversation_ids.get(alice.username)
        assert conversation_id is not None

        # Waited on directly -- confirms the edit was actually applied
        # server-side BEFORE the history reload below runs, so the
        # reload can never race it.
        edited_seen = {}
        bob.message_edited_received.connect(
            lambda conv_id, msg_id, new_text, editor, edited_at, edit_version: edited_seen.update(
                message_id=msg_id, text=new_text
            )
        )

        alice.edit_message(conversation_id, edited_message_id, "now edited", 0)
        assert _wait_for(lambda: edited_seen.get("text") == "now edited")

        deleted_seen = {}
        bob.message_deleted_received.connect(
            lambda conv_id, msg_id, deleted_by, deleted_at: deleted_seen.update(message_id=msg_id)
        )

        alice.delete_message_for_everyone(deleted_message_id)
        assert _wait_for(lambda: deleted_seen.get("message_id") == deleted_message_id)

        bob.forget_rendered_history(conversation_id)

        lifecycle_by_id = {}
        bob.message_lifecycle_state_received.connect(
            lambda identity_key, message_id, reply_to, is_deleted, edit_version, reactions,
            is_pinned=False, pinned_by=None: lifecycle_by_id.__setitem__(
                message_id, (is_deleted, edit_version, reactions)
            )
        )

        bob.load_history(conversation_id, is_group=False)

        assert edited_message_id in lifecycle_by_id
        edited_is_deleted, edited_edit_version, _ = lifecycle_by_id[edited_message_id]
        assert edited_is_deleted is False
        assert edited_edit_version >= 1

        assert deleted_message_id in lifecycle_by_id
        deleted_is_deleted, _, _ = lifecycle_by_id[deleted_message_id]
        assert deleted_is_deleted is True
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_history_reload_recovers_a_verified_reaction(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "histreact"
    )
    try:
        received_text = {}
        bob.message_received.connect(
            lambda identity_key, sender, text, historical, status=None: received_text.update(text=text)
        )
        received_ids = []
        bob.message_id_received.connect(
            lambda identity_key, message_id: received_ids.append(message_id)
        )

        alice.send_message(bob.username, "react to me")
        assert _wait_for(lambda: received_text.get("text") == "react to me")
        assert _wait_for(lambda: len(received_ids) == 1)
        message_id = received_ids[0]

        conversation_id = bob.direct_conversation_ids.get(alice.username)

        bob.add_reaction(conversation_id, message_id, "\U0001F44D")
        time.sleep(0.3)
        _app.processEvents()

        alice.forget_rendered_history(conversation_id)

        lifecycle_by_id = {}
        alice.message_lifecycle_state_received.connect(
            lambda identity_key, msg_id, reply_to, is_deleted, edit_version, reactions,
            is_pinned=False, pinned_by=None: lifecycle_by_id.__setitem__(
                msg_id, reactions
            )
        )

        alice.load_history(conversation_id, is_group=False)

        assert message_id in lifecycle_by_id
        reactions = lifecycle_by_id[message_id]
        assert any(r.get("reaction") == "\U0001F44D" and r.get("user") == bob.username for r in reactions)
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
