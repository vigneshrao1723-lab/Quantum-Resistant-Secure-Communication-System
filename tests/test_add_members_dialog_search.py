"""
GUI tests for AddMembersDialog's phone-number search (UI Finalization
Decision 2). Checkbox-selection mechanics for this dialog are already
covered, via real mouse clicks, in tests/test_group_member_selection_clicks.py
-- this file is scoped to the search-and-append behavior only, mirroring
tests/test_create_group_dialog_gui.py's equivalent section for
CreateGroupDialog.

Follows the established offscreen-QApplication pattern (see
tests/test_chat_window_connection_status.py).

Run with:
    pytest tests/test_add_members_dialog_search.py -v
"""

import os
from unittest.mock import MagicMock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from gui.add_members_dialog import AddMembersDialog

_app = QApplication.instance() or QApplication([])


def _make_session(find_result=None, find_side_effect=None, username="me"):
    session = MagicMock()
    session.get_username.return_value = username
    if find_side_effect is not None:
        session.find_user_by_phone_number.side_effect = find_side_effect
    else:
        session.find_user_by_phone_number.return_value = find_result
    return session


def test_phone_search_found_user_is_appended_as_an_unchecked_row():
    session = _make_session(
        find_result={"user_id": "x", "username": "eve", "display_name": "Eve"}
    )
    dialog = AddMembersDialog(session, ["alice"], ["me", "someone_already_in_group"])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    session.find_user_by_phone_number.assert_called_once_with("+919876543210")

    assert dialog.member_list.count() == 2
    added = dialog.member_list.item(1)
    assert added.text() == "eve"
    assert added.checkState() == Qt.Unchecked


def test_phone_search_result_can_then_be_checked_and_added():
    session = _make_session(
        find_result={"user_id": "x", "username": "eve", "display_name": "Eve"}
    )
    dialog = AddMembersDialog(session, [], ["me"])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    dialog._toggle_item_check_state(dialog.member_list.item(0))

    assert dialog.get_result() == ["eve"]


def test_phone_search_offline_user_is_accepted():
    session = _make_session(
        find_result={"user_id": "x", "username": "offline_eve", "display_name": "Offline Eve"}
    )
    dialog = AddMembersDialog(session, [], ["me"])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert dialog.member_list.item(0).text() == "offline_eve"


def test_phone_search_not_found_shows_clear_message():
    session = _make_session(find_result=None)
    dialog = AddMembersDialog(session, ["alice"], ["me"])

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
    dialog = AddMembersDialog(session, ["alice"], ["me"])

    dialog.phone_search_input.setText("+919876500000")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert dialog.search_status_label.text() == "That is your own account."


def test_phone_search_rejects_an_existing_group_participant():
    """The AddMembersDialog-specific guard: someone already IN the
    group (never shown as a row at all) must still be rejected, not
    just a duplicate visible row."""
    session = _make_session(
        find_result={"user_id": "b", "username": "bob", "display_name": "Bob"}
    )
    # bob is an existing participant, NOT in the candidate list --
    # matches ChatWindow.handle_add_members()'s actual filtering.
    dialog = AddMembersDialog(session, ["alice"], ["me", "bob"])

    dialog.phone_search_input.setText("+919876500001")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert dialog.search_status_label.text() == "Bob (@bob) is already in this group."


def test_phone_search_rejects_duplicate_of_an_already_listed_candidate():
    session = _make_session(
        find_result={"user_id": "a", "username": "alice", "display_name": "Alice"}
    )
    dialog = AddMembersDialog(session, ["alice"], ["me"])

    dialog.phone_search_input.setText("+919876500002")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert dialog.search_status_label.text() == "Alice (@alice) is already in this list."


def test_phone_search_empty_input_does_nothing():
    session = _make_session()
    dialog = AddMembersDialog(session, ["alice"], ["me"])

    dialog.phone_search_input.setText("")
    dialog._handle_add_by_phone()

    session.find_user_by_phone_number.assert_not_called()
    assert dialog.member_list.count() == 1


def test_phone_search_permission_error_shown_as_message_not_crash():
    session = _make_session(find_side_effect=PermissionError("You must be logged in."))
    dialog = AddMembersDialog(session, ["alice"], ["me"])

    dialog.phone_search_input.setText("+919876543210")
    dialog._handle_add_by_phone()

    assert dialog.member_list.count() == 1
    assert "logged in" in dialog.search_status_label.text().lower()
