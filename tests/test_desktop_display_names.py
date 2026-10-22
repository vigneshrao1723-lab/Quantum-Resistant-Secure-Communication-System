"""
Desktop: a refused registration reads as one plain sentence, and two people who chose the same
display name are shown by that name but stay distinguishable (and separately addressable) by
their account handles.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from auth.authentication_service import ACCOUNT_EXISTS_MESSAGE
from auth.schemas import RegistrationResult
from domain.conversation_summary import ConversationSummary
from gui.conversation_list_widget import ConversationListWidget
from gui.login_window import LoginWindow
from gui.main_window import registration_error_text
from gui.message_widget import MessageWidget

_app = QApplication.instance() or QApplication([])

NAMES = {"vignesh": "Vignesh", "vignesh_3fa2c1": "Vignesh"}


def test_an_existing_phone_number_is_reported_as_one_sentence_without_a_login_prefix():
    result = RegistrationResult(
        success=False, message=ACCOUNT_EXISTS_MESSAGE, errors={"phone_number": ACCOUNT_EXISTS_MESSAGE},
    )
    window = LoginWindow()
    window.set_mode(register=True)

    window.show_registration_error(registration_error_text(result))

    assert window.status.text() == "An account with this phone number already exists. Please log in."
    assert "Authentication failed" not in window.status.text()
    assert window.status.wordWrap()


def test_several_reasons_are_each_shown_once():
    result = RegistrationResult(
        success=False, message="Registration failed.",
        errors={"password": "Password is too weak.", "confirm_password": "Password is too weak.",
                "username": "Please enter a username."},
    )

    assert registration_error_text(result).splitlines() == ["Password is too weak.", "Please enter a username."]


def test_namesakes_are_listed_by_display_name_with_their_distinct_handles():
    widget = ConversationListWidget()
    widget.name_for = NAMES.get
    widget.render([
        ConversationSummary(conversation_id=None, username=handle, is_online=False, latest_message=None)
        for handle in NAMES
    ])

    texts = [widget.item(i).data(Qt.AccessibleTextRole) for i in range(widget.count())]
    # Both rows say "Vignesh", each with its own handle -- and each row still carries
    # the handle as its identity (what opening/sending uses), never the display name.
    assert texts[0].startswith("Vignesh") and texts[1].startswith("Vignesh")
    assert "@vignesh_3fa2c1" in texts[1] and "@vignesh_3fa2c1" not in texts[0]
    assert [widget.item(i).data(Qt.UserRole).key for i in range(widget.count())] == list(NAMES)


def test_a_received_group_message_names_its_sender_by_display_name():
    widget = MessageWidget()
    widget.name_for = NAMES.get

    bubble = widget.add_received_message("vignesh_3fa2c1", "hello")

    assert bubble._accessible_sender == "Vignesh"
