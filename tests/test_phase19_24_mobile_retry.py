"""
Phase 19.24 -- Message Retry: mobile ChatScreen UI wiring.

Desktop's own retry button already exists (gui/message_widget.py's
MessageBubble Retry button + gui/chat_window.py::_retry_failed_
message()); this closes the same gap on mobile, which previously just
showed a system bubble with the friendly error text and DISCARDED the
original message -- no record of what was typed, no way to resend it.
Mirrors Desktop's exact contract: client_message_id generated BEFORE
the risky send call (so it survives even when send raises before
returning), reused on retry for idempotency, and the failed bubble is
only cleared once the retry itself does not raise.

Reuses tests/test_phase19_24_mobile_drafts.py's ChatScreen harness
rather than reimplementing it -- see that file's own docstring for the
full reasoning. Drives the REAL _send_text()/_retry_failed_bubble()/
_handle_bubble_context_action() methods a real failed send and a real
long-press "Retry" selection actually run, against a REAL running
server and REAL MobileClientSession.

Run with:
    pytest tests/test_phase19_24_mobile_retry.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mobile.app import ChatScreen, _bubble_context_actions
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def _break_first_send(session):
    """Monkeypatches session.send_message to raise exactly once (a
    real, generic send-time failure -- e.g. a dropped connection),
    then transparently restores the real method for any later call
    (the retry)."""

    real_send_message = session.send_message
    state = {"broken": True}

    def _flaky(*args, **kwargs):
        if state["broken"]:
            state["broken"] = False
            raise RuntimeError("simulated transient send failure")
        return real_send_message(*args, **kwargs)

    session.send_message = _flaky


def test_a_failed_send_keeps_the_text_and_offers_retry(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mretrya"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        _break_first_send(alice)

        screen._send_text(bob.username, False, "hello, are you there?")

        bubbles_awaiting = screen._bubbles_awaiting_message_id.get(bob.username, [])
        assert bubbles_awaiting == [], "a failed send must never be tracked as awaiting a server id"

        pending = screen._pending_send_status.get(bob.username, [])
        assert len(pending) == 1
        bubble = pending[0]
        assert bubble.message_text == "hello, are you there?"
        assert bubble._tick_status == "Failed"
        assert bubble._resolved is True

        actions = _bubble_context_actions(bubble)
        assert ("retry", "Retry") in actions
        assert ("delete_me", "Delete for me") in actions
        assert len(actions) == 2  # nothing else makes sense for text that never left the device
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_retry_resends_and_reaches_the_real_peer(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mretryb"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        _break_first_send(alice)
        screen._send_text(bob.username, False, "will this ever arrive")

        bubble = screen._pending_send_status[bob.username][0]
        original_client_message_id = bubble.client_message_id
        assert original_client_message_id

        received = []
        bob.message_received.connect(
            lambda identity_key, sender, text, historical, status: received.append(text)
        )

        # The real long-press dispatch path, exactly like a real
        # popup's "Retry" selection.
        screen._handle_bubble_context_action("retry", bubble)

        assert _wait_for(lambda: len(received) == 1)
        assert received[0] == "will this ever arrive"

        # The failed bubble is gone; a fresh one reflects the retry's
        # real, successful outcome, reusing the same client_message_id.
        pending_after = screen._pending_send_status[bob.username]
        assert bubble not in pending_after
        assert len(pending_after) == 1
        new_bubble = pending_after[0]
        assert new_bubble.client_message_id == original_client_message_id
        assert new_bubble._tick_status != "Failed"
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_delete_for_me_on_a_failed_bubble_is_local_only(
    running_server, monkeypatch, tmp_path
):
    """A failed send never reached the server -- delete-for-me here
    must never attempt a server call (which would fail/misbehave on a
    None message_id), only remove the local, never-sent row."""

    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mretryc"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        _break_first_send(alice)
        screen._send_text(bob.username, False, "never sent")

        bubble = screen._pending_send_status[bob.username][0]
        assert bubble.message_id is None

        screen._handle_bubble_context_action("delete_me", bubble)  # must not raise

        assert bubble not in screen._pending_send_status[bob.username]
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
