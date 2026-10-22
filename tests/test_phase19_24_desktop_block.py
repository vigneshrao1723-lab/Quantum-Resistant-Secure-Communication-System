"""
Phase 19.24 -- Block User: Desktop UI wiring.

Server-side enforcement is already proven by tests/test_phase19_24_
block_user_security.py (session-layer, against the real server). This
file proves the thing the mandate explicitly calls out: "a feature is
not complete merely because a session method exists -- it must be
usable through actual Desktop UI". Drives the REAL gui.chat_window.
ChatWindow/gui.conversation_list_widget.ConversationListWidget/gui.
blocked_users_dialog.BlockedUsersDialog code a real right-click
"Block"/"Unblock" selection and a real "Manage" button in Settings
actually run (bypassing only the modal QMenu.exec() call itself) --
against a REAL running server and REAL ClientSessions.

Run with:
    pytest tests/test_phase19_24_desktop_block.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton

from gui.blocked_users_dialog import BlockedUsersDialog
from tests.test_phase19_24_desktop_mute import _row_for  # noqa: F401
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _direct_summary,
    _KEEP_ALIVE,
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)


def test_unblocking_via_context_menu_restores_delivery(tmp_path, connect, accounts):
    # NOTE: kept declared before test_blocking_via_context_menu_prevents_
    # delivery_and_updates_menu_state (below). That ordering used to matter: the
    # blocking test leaves a "User is offline" error in flight for its sender's
    # window, which was delivered during the NEXT test's event pump as a modal
    # QMessageBox that nothing headless can dismiss, hanging the run (root cause
    # found with faulthandler, 2026-10-19). The blocking test now captures and
    # asserts that error itself, so the order no longer affects the outcome.
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    alice_window._do_block_user(bob_username)
    alice_window._handle_mute_action(_direct_summary(bob_username), "unblock")
    assert not alice_window.session.is_user_blocked(bob_username)

    received_by_alice = []
    alice_window.session.message_received.connect(
        lambda identity_key, sender, text: received_by_alice.append(text)
    )

    bob_window.send_message("are you there now?")

    assert _wait_for(lambda: received_by_alice == ["are you there now?"])


def test_blocking_via_context_menu_prevents_delivery_and_updates_menu_state(
    tmp_path, connect, accounts, monkeypatch
):
    # The server answers a send to a blocker with "User is offline" (so a
    # block is never revealed to the sender), and the sender's window reports
    # that through a modal QMessageBox.critical. Nothing dismisses a modal in
    # a headless run, and that response is delivered on the NEXT Qt event
    # pump -- i.e. inside the following test, on this test's kept-alive
    # window -- where it blocked forever. Capture it here instead, where it
    # belongs, and assert on it.
    reported_to_sender = []
    monkeypatch.setattr(
        QMessageBox,
        "critical",
        staticmethod(lambda parent, title, text, *a, **k: reported_to_sender.append(text)),
    )

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    # Real right-click "Block" -- the exact handler a real QMenu
    # selection invokes; _do_block_user() is the action itself, with
    # only the confirmation QMessageBox.exec() bypassed (same
    # convention as the Attachment Menu/Mute popup elsewhere in this
    # project -- see _confirm_block_user()'s own docstring).
    alice_window._do_block_user(bob_username)
    assert alice_window.session.is_user_blocked(bob_username)

    alice_window.render_conversations()
    row = _row_for(alice_window.conversation_list, bob_username)
    if row is not None:
        assert row._blocked is True

    received_by_alice = []
    alice_window.session.message_received.connect(
        lambda identity_key, sender, text: received_by_alice.append(text)
    )

    bob_window.send_message("can you still hear me?")

    time.sleep(0.5)
    assert received_by_alice == []

    # Bob is told the message could not be delivered (not that he is blocked).
    assert _wait_for(lambda: len(reported_to_sender) > 0)
    assert "offline" in reported_to_sender[0].lower()
    assert "block" not in reported_to_sender[0].lower()


def test_blocked_users_dialog_lists_and_unblocks(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    alice_window._do_block_user(bob_username)

    dialog = BlockedUsersDialog(alice_window.session)
    _KEEP_ALIVE.append(dialog)

    assert dialog.list_widget.count() == 1
    row_widget = dialog.list_widget.itemWidget(dialog.list_widget.item(0))

    labels = [c for c in row_widget.children() if isinstance(c, QLabel)]
    # Shown by display name with the account handle beside it (names are not unique).
    assert any(bob_username in label.text() for label in labels)

    # Real click on the real Unblock button embedded in the row.
    buttons = [c for c in row_widget.children() if isinstance(c, QPushButton)]
    unblock_button = next(b for b in buttons if b.text() == "Unblock")
    unblock_button.click()

    assert not alice_window.session.is_user_blocked(bob_username)
    assert dialog.list_widget.count() == 0
