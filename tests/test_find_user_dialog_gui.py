"""
GUI tests for Issue 3 (real-application testing bug report): User
Must Be Searched By Unique ID.

Follows the established offscreen-QApplication pattern (see
tests/test_chat_window_connection_status.py). ClientSession.find_user_by_phone_number()
itself is unit-tested against a real database in
tests/test_user_id_search.py -- here it's monkeypatched so these tests
stay fast and isolated to the dialog's own behavior.

Run with:
    pytest tests/test_find_user_dialog_gui.py -v
"""

import os
from unittest.mock import MagicMock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui.find_user_dialog import FindUserDialog

_app = QApplication.instance() or QApplication([])


def _make_session(find_result=None, find_side_effect=None, username="me"):
    session = MagicMock()
    session.get_username.return_value = username
    if find_side_effect is not None:
        session.find_user_by_phone_number.side_effect = find_side_effect
    else:
        session.find_user_by_phone_number.return_value = find_result
    return session


def test_search_with_empty_input_does_nothing():
    session = _make_session()
    dialog = FindUserDialog(session)

    dialog.id_input.setText("")
    dialog.handle_search()

    session.find_user_by_phone_number.assert_not_called()
    assert dialog.get_result() is None


def test_search_found_user_enables_open_button():
    session = _make_session(
        find_result={"user_id": "abc-123", "username": "bob", "display_name": "Bob"}
    )
    dialog = FindUserDialog(session)

    dialog.id_input.setText("+919876543210")
    dialog.handle_search()

    assert dialog.open_button.isEnabled() is True
    assert "Bob" in dialog.result_label.text()
    assert dialog.get_result()["username"] == "bob"


def test_search_not_found_shows_clear_message_and_disables_open():
    session = _make_session(find_result=None)
    dialog = FindUserDialog(session)

    dialog.id_input.setText("+919999000111")
    dialog.handle_search()

    assert dialog.open_button.isEnabled() is False
    # BUG 7: the wording now names the identifier the user typed.
    message = dialog.result_label.text().lower()
    assert "no user" in message and "phone number" in message
    assert dialog.get_result() is None


def test_search_own_id_is_rejected():
    session = _make_session(
        find_result={"user_id": "self-id", "username": "me", "display_name": "Me"},
        username="me",
    )
    dialog = FindUserDialog(session)

    dialog.id_input.setText("+919876500000")
    dialog.handle_search()

    assert dialog.open_button.isEnabled() is False
    assert dialog.get_result() is None


def test_unauthenticated_permission_error_shown_as_message_not_crash():
    session = _make_session(find_side_effect=PermissionError("You must be logged in."))
    dialog = FindUserDialog(session)

    dialog.id_input.setText("+919876543210")
    dialog.handle_search()

    assert dialog.open_button.isEnabled() is False
    assert "logged in" in dialog.result_label.text().lower()


def test_open_button_disabled_by_default():
    session = _make_session()
    dialog = FindUserDialog(session)

    assert dialog.open_button.isEnabled() is False
