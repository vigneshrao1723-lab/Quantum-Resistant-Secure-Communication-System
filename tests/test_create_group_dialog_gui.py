"""
GUI regression test for Issue 1 (real-application testing bug report):
CreateGroupDialog appeared to only allow selecting one member.

Follows the established offscreen-QApplication pattern (see
tests/test_chat_window_connection_status.py).

Run with:
    pytest tests/test_create_group_dialog_gui.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from gui.create_group_dialog import CreateGroupDialog

_app = QApplication.instance() or QApplication([])


def test_clicking_multiple_rows_checks_all_of_them():
    """The exact bug: clicking several rows (not the checkbox glyph
    precisely) must check every one of them, not just the last."""
    dialog = CreateGroupDialog(["alice", "bob", "carol", "dave"])

    for i in range(4):
        dialog._toggle_item_check_state(dialog.member_list.item(i))

    _name, selected = dialog.get_result()
    assert set(selected) == {"alice", "bob", "carol", "dave"}


def test_clicking_a_row_twice_unchecks_it():
    dialog = CreateGroupDialog(["alice", "bob"])

    item = dialog.member_list.item(0)
    dialog._toggle_item_check_state(item)
    dialog._toggle_item_check_state(item)

    _name, selected = dialog.get_result()
    assert "alice" not in selected


def test_checking_one_member_does_not_affect_another():
    dialog = CreateGroupDialog(["alice", "bob", "carol"])

    dialog._toggle_item_check_state(dialog.member_list.item(1))  # bob only

    _name, selected = dialog.get_result()
    assert selected == ["bob"]


def test_member_list_uses_no_native_selection_mode():
    """Guards against the highlight-only regression coming back --
    checkbox state must be the sole selection mechanism."""
    from PySide6.QtWidgets import QAbstractItemView

    dialog = CreateGroupDialog(["alice", "bob"])
    assert dialog.member_list.selectionMode() == QAbstractItemView.NoSelection


def test_item_clicked_signal_is_wired_to_toggle():
    """End-to-end signal check: emitting itemClicked (as a real click
    would) toggles the row, not just calling the handler directly."""
    dialog = CreateGroupDialog(["alice"])
    item = dialog.member_list.item(0)

    assert item.checkState() == Qt.Unchecked
    dialog.member_list.itemClicked.emit(item)
    assert item.checkState() == Qt.Checked
