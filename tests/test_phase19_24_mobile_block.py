"""
Phase 19.24 -- Block User: mobile ChatScreen UI wiring.

Server-side enforcement is already proven by tests/test_phase19_24_
block_user_security.py. Reuses tests/test_phase19_24_mobile_drafts.py's
ChatScreen harness rather than reimplementing it. Drives the REAL
_apply_mute_action()/_open_mute_popup()'s real "Block"/"Unblock" option
against a REAL running server and REAL MobileClientSession.

Run with:
    pytest tests/test_phase19_24_mobile_block.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mobile.app import ChatScreen
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def test_blocking_via_real_popup_action_prevents_delivery(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mblocka"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        # The real action a tapped "Block" popup button invokes;
        # _do_block_user() is the action itself, with only the
        # confirmation popup bypassed (see _confirm_and_block_user()'s
        # own docstring).
        screen._do_block_user(bob.username)
        assert alice.is_user_blocked(bob.username)

        received = []
        alice.message_received.connect(
            lambda identity_key, sender, text, historical, status: received.append(text)
        )

        bob.establish_session_key(alice.username)
        bob.send_message(alice.username, "can you hear me?")

        time.sleep(0.5)
        assert received == []
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_unblocking_via_real_popup_action_restores_delivery(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mblockb"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._do_block_user(bob.username)
        screen._apply_mute_action(bob.username, "unblock")
        assert not alice.is_user_blocked(bob.username)

        received = []
        alice.message_received.connect(
            lambda identity_key, sender, text, historical, status: received.append(text)
        )

        bob.establish_session_key(alice.username)
        bob.send_message(alice.username, "are you there now?")

        assert _wait_for(lambda: received == ["are you there now?"])
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
