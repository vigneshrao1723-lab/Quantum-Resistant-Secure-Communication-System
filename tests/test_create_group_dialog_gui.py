"""
GUI regression test for Issue 1 (real-application testing bug report):
CreateGroupDialog appeared to only allow selecting one member.

Also covers UI Finalization Decision 2 (phone-number member search) --
CreateGroupDialog now requires a session (find_user_by_phone_number()
+ get_username()), so every dialog in this file is constructed with a
mock session, following the established pattern in
tests/test_find_user_dialog_gui.py.

Follows the established offscreen-QApplication pattern (see
tests/test_chat_window_connection_status.py).

Run with:
    pytest tests/test_create_group_dialog_gui.py -v
"""

import os
from unittest.mock import MagicMock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from gui.create_group_dialog import CreateGroupDialog

_app = QApplication.instance() or QApplication([])


def _make_session(find_result=None, find_side_effect=None, username="me"):
    session = MagicMock()
    session.get_username.return_value = username
    if find_side_effect is not None:
        session.find_user_by_phone_number.side_effect = find_side_effect
    else:
        session.find_user_by_phone_number.return_value = find_result
    return session


def test_clicking_multiple_rows_checks_all_of_them():
    """The exact bug: clicking several rows (not the checkbox glyph
    precisely) must check every one of them, not just the last."""
    dialog = CreateGroupDialog(_make_session(), ["alice", "bob", "carol", "dave"])

    for i in range(4):
        dialog._toggle_item_check_state(dialog.member_list.item(i))

    _name, selected = dialog.get_result()
    assert set(selected) == {"alice", "bob", "carol", "dave"}


def test_clicking_a_row_twice_unchecks_it():
    dialog = CreateGroupDialog(_make_session(), ["alice", "bob"])

    item = dialog.member_list.item(0)
    dialog._toggle_item_check_state(item)
    dialog._toggle_item_check_state(item)

    _name, selected = dialog.get_result()
    assert "alice" not in selected


def test_checking_one_member_does_not_affect_another():
    dialog = CreateGroupDialog(_make_session(), ["alice", "bob", "carol"])

    dialog._toggle_item_check_state(dialog.member_list.item(1))  # bob only

    _name, selected = dialog.get_result()
    assert selected == ["bob"]


def test_member_list_uses_no_native_selection_mode():
    """Guards against the highlight-only regression coming back --
    checkbox state must be the sole selection mechanism."""
    from PySide6.QtWidgets import QAbstractItemView

    dialog = CreateGroupDialog(_make_session(), ["alice", "bob"])
    assert dialog.member_list.selectionMode() == QAbstractItemView.NoSelection


def test_item_clicked_signal_is_wired_to_toggle():
    """End-to-end signal check: emitting itemClicked (as a real click
    would) toggles the row, not just calling the handler directly."""
    dialog = CreateGroupDialog(_make_session(), ["alice"])
    item = dialog.member_list.item(0)

    assert item.checkState() == Qt.Unchecked
    dialog.member_list.itemClicked.emit(item)
    assert item.checkState() == Qt.Checked


# ----------------------------------------------------------------------
# UI Finalization Decision 2 -- phone-number member search
# ----------------------------------------------------------------------


def test_phone_search_found_user_is_appended_as_an_unchecked_row():
    session = _make_session(
        find_result={"user_id": "x", "username": "eve", "display_name": "Eve"}
    )
    dialog = CreateGroupDialog(session, ["alice"])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    session.find_user_by_phone_number.assert_called_once_with("+919876543210")

    assert dialog.member_list.count() == 2
    added = dialog.member_list.item(1)
    assert added.text() == "eve"
    assert added.checkState() == Qt.Unchecked
    assert "Eve" in dialog.search_status_label.text()


def test_phone_search_found_user_can_then_be_checked_and_selected():
    """The full required flow: search/add, then check, then it's in
    get_result()."""
    session = _make_session(
        find_result={"user_id": "x", "username": "eve", "display_name": "Eve"}
    )
    dialog = CreateGroupDialog(session, [])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    added = dialog.member_list.item(0)
    dialog._toggle_item_check_state(added)

    _name, selected = dialog.get_result()
    assert selected == ["eve"]


def test_phone_search_offline_user_is_accepted():
    """Requirement: offline users may be added -- discovery is a pure
    lookup, this dialog never checks or requires presence."""
    session = _make_session(
        find_result={"user_id": "x", "username": "offline_eve", "display_name": "Offline Eve"}
    )
    dialog = CreateGroupDialog(session, [])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert dialog.member_list.item(0).text() == "offline_eve"


def test_phone_search_not_found_shows_clear_message_and_adds_no_row():
    session = _make_session(find_result=None)
    dialog = CreateGroupDialog(session, ["alice"])

    dialog.phone_search_input.setText("+919999000111")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    message = dialog.search_status_label.text().lower()
    assert "no user" in message and "phone number" in message


def test_phone_search_rejects_self():
    session = _make_session(
        find_result={"user_id": "self", "username": "me", "display_name": "Me"},
        username="me",
    )
    dialog = CreateGroupDialog(session, ["alice"])

    dialog.phone_search_input.setText("+919876500000")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert dialog.search_status_label.text() == "That is your own account."


def test_phone_search_rejects_duplicate_of_an_already_listed_candidate():
    """Requirement: prevent duplicates -- searching someone already
    shown as an online candidate must not add a second row for them."""
    session = _make_session(
        find_result={"user_id": "b", "username": "bob", "display_name": "Bob"}
    )
    dialog = CreateGroupDialog(session, ["alice", "bob"])

    dialog.phone_search_input.setText("+919876500001")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 2
    assert dialog.search_status_label.text() == "Bob (@bob) is already in this list."


def test_phone_search_rejects_duplicate_of_a_previously_added_search_result():
    """Two searches for the same number in a row must not double-add."""
    session = _make_session(
        find_result={"user_id": "x", "username": "eve", "display_name": "Eve"}
    )
    dialog = CreateGroupDialog(session, [])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()
    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1


def test_phone_search_empty_input_does_nothing():
    session = _make_session()
    dialog = CreateGroupDialog(session, ["alice"])

    dialog.phone_search_input.setText("")
    dialog._handle_add_by_phone()

    session.find_user_by_phone_number.assert_not_called()
    assert dialog.member_list.count() == 1


def test_phone_search_permission_error_shown_as_message_not_crash():
    session = _make_session(find_side_effect=PermissionError("You must be logged in."))
    dialog = CreateGroupDialog(session, ["alice"])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert "logged in" in dialog.search_status_label.text().lower()


def test_phone_search_does_not_disturb_existing_candidate_checks():
    """Adding a new row via search must not reset any box already
    checked among the original online candidates."""
    session = _make_session(
        find_result={"user_id": "x", "username": "eve", "display_name": "Eve"}
    )
    dialog = CreateGroupDialog(session, ["alice", "bob"])

    dialog._toggle_item_check_state(dialog.member_list.item(0))  # check alice

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    _name, selected = dialog.get_result()
    assert selected == ["alice"]
