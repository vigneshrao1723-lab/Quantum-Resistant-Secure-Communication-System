"""
Phase 19.24 -- Typing Indicator: protocol/server + Desktop UI wiring.

Drives REAL gui.chat_window.ChatWindow instances (the exact composer
textChanged -> _on_composer_text_changed() -> ClientSession.send_
typing_indicator() -> server/client_handler.py::handle_typing_
indicator() -> the OTHER window's own typing_status_label a real user
would see) against a REAL running server and REAL, separately-
connecting ClientSessions -- the same harness tests/test_phase19_24_
desktop_ui_wiring.py already established (its _two_windows()/
_verify_each_other()/_direct_summary() helpers are reused unchanged).

Every test below is independently verified correct -- passes cleanly
alone and in every small combination checked (up to 4 together). Ran
as the full 8-test file (or combined with certain other real-send
GUI tests), an intermittent hang was observed and root-caused to be
INDEPENDENT of anything typing-indicator-specific: a minimal 2-test
reproduction with ZERO typing-indicator code involved (just "a real
end-to-end chat send" immediately followed by a second, unrelated
_two_windows() test) reproduces the identical hang. This matches this
project's own already-documented, already-accepted native-level test-
*process* resource-accumulation class (see scripts/run_regression_
batches.py's own module docstring: "not fixable from application
code") -- not a defect in the feature or in this file's own test
logic. Consequently this file is deliberately NOT added to the shared
desktop_gui batch (to avoid risking that batch's own stability); run
it standalone, or a few tests at a time, rather than as one combined
invocation with many other real-send GUI tests.

Run with:
    pytest tests/test_phase19_24_typing_indicator.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _direct_summary,
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)


# ----------------------------------------------------------------------
# Live send/receive, driven through the real composer
# ----------------------------------------------------------------------


def test_typing_a_real_keystroke_shows_the_indicator_on_the_recipient(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, _ = _two_windows(connect, accounts, tmp_path)

    assert bob_window.typing_status_label.isVisible() is False

    QTest.keyClicks(alice_window.input_bar.message_input, "h")

    assert _wait_for(
        lambda: bob_window.typing_status_label.isVisible()
        and "is typing" in bob_window.typing_status_label.text()
    )
    assert alice_payload["username"] in bob_window.typing_status_label.text()


def test_only_one_is_typing_packet_sent_for_a_burst_of_keystrokes(
    tmp_path, connect, accounts
):
    """Real production behavior: the FIRST keystroke after being idle
    arms is_typing=True once -- every keystroke after that only ever
    re-arms the idle timer, never re-sends (see _on_composer_text_
    changed()'s own docstring)."""

    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    received = []
    bob_window.session.typing_indicator_received.connect(
        lambda conversation_id, username, is_typing: received.append(is_typing)
    )

    QTest.keyClicks(alice_window.input_bar.message_input, "hello there")

    assert _wait_for(lambda: len(received) >= 1)
    # Give any (incorrect) duplicate sends a real chance to arrive.
    assert _wait_for(lambda: len(received) > 1, attempts=20, interval=0.05) is False
    assert received == [True]


def test_clearing_the_composer_stops_typing_immediately(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    QTest.keyClicks(alice_window.input_bar.message_input, "h")
    assert _wait_for(lambda: bob_window.typing_status_label.isVisible())

    alice_window.input_bar.message_input.clear()

    assert _wait_for(lambda: bob_window.typing_status_label.isVisible() is False)


def test_sending_the_message_stops_typing_immediately(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    QTest.keyClicks(alice_window.input_bar.message_input, "hello")
    assert _wait_for(lambda: bob_window.typing_status_label.isVisible())

    QTest.keyClick(alice_window.input_bar.message_input, Qt.Key_Return)

    assert _wait_for(lambda: bob_window.typing_status_label.isVisible() is False)
    assert _wait_for(lambda: bob_window.messages.count() > 0)


def test_idle_timeout_stops_typing(tmp_path, connect, accounts):
    """Directly fires the idle-timeout path (_send_typing_stopped()) --
    a white-box unit test of that exact method, avoiding a real 3-
    second wait in the suite -- while test_typing_a_real_keystroke_
    shows_the_indicator_on_the_recipient above already proves the real
    QTimer is genuinely armed by real keystrokes."""

    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    QTest.keyClicks(alice_window.input_bar.message_input, "h")
    assert _wait_for(lambda: bob_window.typing_status_label.isVisible())

    alice_window._send_typing_stopped()

    assert _wait_for(lambda: bob_window.typing_status_label.isVisible() is False)


# ----------------------------------------------------------------------
# Correctness / security
# ----------------------------------------------------------------------


def test_typing_is_never_echoed_back_to_the_sender(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    received_by_alice = []
    alice_window.session.typing_indicator_received.connect(
        lambda conversation_id, username, is_typing: received_by_alice.append(is_typing)
    )

    QTest.keyClicks(alice_window.input_bar.message_input, "hello")
    assert _wait_for(lambda: bob_window.typing_status_label.isVisible())

    assert received_by_alice == []


def test_typing_indicator_is_scoped_to_the_open_conversation(tmp_path, connect, accounts):
    """A typing hint for a conversation that is NOT the one currently
    on screen must never render -- mirrors handle_read_receipt_
    updated()'s identical gating."""

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    # Bob switches away to a conversation with Carol -- Alice's typing
    # hint must not appear there.
    bob_window.open_conversation(_direct_summary(carol_payload["username"]))

    received_by_bob = []
    bob_window.session.typing_indicator_received.connect(
        lambda conversation_id, username, is_typing: received_by_bob.append(is_typing)
    )

    QTest.keyClicks(alice_window.input_bar.message_input, "hello")

    # The packet genuinely DOES arrive at Bob's session (proving this
    # isn't just "the server never sent it") -- it is gui/chat_window.
    # py's own conversation-scoped rendering (handle_typing_indicator_
    # received()'s own gate) that correctly refuses to show it, not an
    # absence of the signal firing at all.
    assert _wait_for(lambda: received_by_bob == [True])
    assert bob_window.typing_status_label.isVisible() is False


def test_non_member_cannot_broadcast_typing_into_a_conversation(tmp_path, connect, accounts):
    """Security-negative: a user who is not a member of a conversation
    cannot make its real members see a typing indicator, even by
    directly sending a forged conversation_id -- server/client_
    handler.py::handle_typing_indicator()'s own membership check."""

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    mallory_payload = accounts("mallory_")
    mallory = connect(mallory_payload)

    conversation_id = alice_window.session.current_conversation_id
    assert conversation_id is not None

    received_by_bob = []
    bob_window.session.typing_indicator_received.connect(
        lambda cid, username, is_typing: received_by_bob.append((cid, username, is_typing))
    )

    mallory.send_typing_indicator(conversation_id, True)

    app = QApplication.instance()
    for _ in range(20):
        time.sleep(0.05)
        app.processEvents()

    assert received_by_bob == []
