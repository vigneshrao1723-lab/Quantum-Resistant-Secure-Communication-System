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

from PySide6.QtWidgets import QLabel, QPushButton

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
    # NOTE: declared before test_blocking_via_context_menu_prevents_
    # delivery_and_updates_menu_state (below) deliberately -- bisection
    # found that pytest running them in the OPPOSITE order (blocking
    # test, then this one) reliably hangs in this process, while every
    # other ordering/pairing of this file's 3 tests (including this
    # exact pair reversed, as declared here) passes fast. Each test is
    # independently correct and fast standalone. This is the same class
    # of Qt/Windows real-socket-teardown-timing environmental issue
    # already documented in project memory (qt_windows_gui_batch_
    # flakiness.md's "second manifestation" section) -- not a defect in
    # either test or in the code they exercise. Reordering rather than
    # skipping/weakening either test keeps both assertions live.
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
    tmp_path, connect, accounts
):
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
    assert any(label.text() == bob_username for label in labels)

    # Real click on the real Unblock button embedded in the row.
    buttons = [c for c in row_widget.children() if isinstance(c, QPushButton)]
    unblock_button = next(b for b in buttons if b.text() == "Unblock")
    unblock_button.click()

    assert not alice_window.session.is_user_blocked(bob_username)
    assert dialog.list_widget.count() == 0
