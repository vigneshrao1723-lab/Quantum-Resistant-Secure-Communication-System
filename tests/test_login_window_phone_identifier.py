"""
UI Finalization -- Login Identifier: gui/login_window.py's field
layout and the (phone_number, password) shape of login_requested.

No server/session involved -- LoginWindow only ever builds and emits a
signal; whether the SERVER actually then only accepts a phone number
is covered separately in tests/test_authentication_service.py's
"Login Identifier" section and tests/test_login_logout_integration.py.

Run with:
    pytest tests/test_login_window_phone_identifier.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from gui.login_window import LoginWindow

_app = QApplication.instance() or QApplication([])

_KEEP_ALIVE = []


@pytest.fixture()
def login_window():
    # Shown (even under the offscreen platform): isVisible() reflects
    # a widget's own setVisible() state only relative to a SHOWN
    # top-level window -- an unshown one makes isVisible() report
    # False for every child regardless of what set_mode() actually
    # did, which is exactly the behavior these tests check.
    window = LoginWindow()
    _KEEP_ALIVE.append(window)
    window.show()
    QTest.qWaitForWindowExposed(window)
    return window


def test_login_mode_asks_for_phone_number_and_password_only(login_window):
    assert login_window.phone_label.text() == "PHONE NUMBER"
    assert login_window.phone_label.isVisible() is True
    assert login_window.phone_input.isVisible() is True

    # Username -- the previous "USERNAME OR EMAIL" identifier field --
    # and confirm-password are register-only now.
    assert login_window.username_label.isVisible() is False
    assert login_window.username_input.isVisible() is False
    assert login_window.confirm_password_label.isVisible() is False
    assert login_window.confirm_password_input.isVisible() is False


def test_login_mode_no_longer_offers_username_or_email_wording(login_window):
    assert login_window.username_label.text() != "USERNAME OR EMAIL"
    assert "email" not in login_window.phone_label.text().lower()


def test_register_mode_still_shows_username_and_phone_number(login_window):
    login_window.set_mode(register=True)

    assert login_window.username_label.isVisible() is True
    assert login_window.username_input.isVisible() is True
    assert login_window.phone_label.isVisible() is True
    assert login_window.phone_input.isVisible() is True
    assert login_window.confirm_password_label.isVisible() is True
    assert login_window.confirm_password_input.isVisible() is True


def test_toggling_back_to_login_hides_username_again(login_window):
    login_window.set_mode(register=True)
    login_window.set_mode(register=False)

    assert login_window.username_input.isVisible() is False
    assert login_window.phone_input.isVisible() is True


def test_submit_with_empty_phone_number_shows_validation_error(login_window):
    login_window.phone_input.setText("")
    login_window.password_input.setText("Str0ng!Passw0rd")

    login_window.handle_submit()

    assert "phone number" in login_window.status.text().lower()


def test_submit_with_malformed_phone_number_shows_validation_error(login_window):
    login_window.phone_input.setText("not-a-phone-number")
    login_window.password_input.setText("Str0ng!Passw0rd")

    login_window.handle_submit()

    assert "valid phone number" in login_window.status.text().lower()


def test_login_requested_emits_phone_number_and_password(login_window):
    captured = []
    login_window.login_requested.connect(lambda phone, pw: captured.append((phone, pw)))

    login_window.phone_input.setText("+91 98765 43210")
    login_window.password_input.setText("Str0ng!Passw0rd")

    login_window.handle_submit()

    assert captured == [("+91 98765 43210", "Str0ng!Passw0rd")]


def test_register_requested_still_emits_username_phone_password_confirm(login_window):
    captured = []
    login_window.register_requested.connect(
        lambda *args: captured.append(args)
    )

    login_window.set_mode(register=True)
    login_window.username_input.setText("newuser")
    login_window.phone_input.setText("+91 98765 43210")
    login_window.password_input.setText("Str0ng!Passw0rd")
    login_window.confirm_password_input.setText("Str0ng!Passw0rd")

    login_window.handle_submit()

    assert captured == [
        ("newuser", "+91 98765 43210", "Str0ng!Passw0rd", "Str0ng!Passw0rd")
    ]


def test_register_mode_missing_username_shows_validation_error_not_a_crash(
    login_window,
):
    login_window.set_mode(register=True)
    login_window.username_input.setText("")
    login_window.phone_input.setText("+91 98765 43210")
    login_window.password_input.setText("Str0ng!Passw0rd")
    login_window.confirm_password_input.setText("Str0ng!Passw0rd")

    login_window.handle_submit()

    assert "registration fields" in login_window.status.text().lower()
