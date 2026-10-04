"""
Login Window

Allows the user to enter their phone number and
connect to the secure chat server.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.styles import COLOR_DANGER, COLOR_TEXT_MUTED
from security.phone_number import is_valid_phone_number


class LoginWindow(QWidget):
    """
    Login and registration page for the application.
    """

    # UI Finalization -- Login Identifier: phone_number, password.
    login_requested = Signal(str, str)
    # username, phone_number, password, confirm_password
    register_requested = Signal(str, str, str, str)

    def __init__(self):
        super().__init__()

        self.is_register_mode = False
        self.build_ui()

    # ======================================================
    # UI
    # ======================================================

    def build_ui(self):

        outer_layout = QVBoxLayout(self)

        outer_layout.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Card
        # ----------------------------------

        card = QFrame()

        card.setObjectName("Card")

        card.setFixedWidth(420)

        card_layout = QVBoxLayout(card)

        # Trimmed from (40, 40, 40, 32) / spacing 6: with the register
        # fields shown the card's sizeHint exceeded the 650px minimum
        # window height, which clipped the Register button. This keeps
        # the same visual style with a vertical budget that fits.
        card_layout.setContentsMargins(36, 24, 36, 24)

        card_layout.setSpacing(4)

        card_layout.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Logo
        # ----------------------------------

        self.logo = QLabel()

        pixmap = QPixmap("gui/resources/logo.png")

        if not pixmap.isNull():

            self.logo.setPixmap(
                pixmap.scaled(
                    64,
                    64,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
            )

        self.logo.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Title
        # ----------------------------------

        title = QLabel(
            "Quantum-Resistant\nSecure Communication"
        )

        title.setObjectName("Title")

        title.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Subtitle
        # ----------------------------------

        subtitle = QLabel(
            "End-to-end chat secured with post-quantum cryptography"
        )

        subtitle.setObjectName("Subtitle")

        subtitle.setWordWrap(True)

        subtitle.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Username
        #
        # REGISTRATION ONLY (UI Finalization -- Login Identifier): the
        # application identity and the name shown to other users. Not
        # collected at login -- see set_mode(), which hides this field
        # entirely outside register mode -- because the authenticated
        # user's username is obtained from the server/database profile
        # AuthenticationService.authenticate_user() returns, never
        # re-entered by hand (see MainWindow.handle_login()). Full name
        # and email were removed from this form entirely: the identity
        # model is username (displayed) + phone number (login +
        # searchable), so neither was carrying its weight. See
        # MainWindow.handle_registration() for how the two database
        # columns that still exist are populated without asking the
        # user for them.
        # ----------------------------------

        self.username_label = QLabel("USERNAME")
        self.username_label.setObjectName("FieldLabel")
        self.username_label.setAlignment(Qt.AlignLeft)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText(
            "Enter your username"
        )
        self.username_input.returnPressed.connect(
            self.handle_submit
        )

        # ----------------------------------
        # Phone Number
        #
        # BUG 7 -- the discovery identifier other users search by.
        # Mandatory at registration; registration is rejected
        # server-side without one.
        #
        # UI Finalization -- Login Identifier: also the ONLY login
        # identifier -- shown in both modes now (see set_mode(), which
        # no longer hides this field for login). Username and email are
        # never accepted as login identifiers -- see
        # AuthenticationService.authenticate_user().
        # ----------------------------------

        self.phone_label = QLabel("PHONE NUMBER")
        self.phone_label.setObjectName("FieldLabel")
        self.phone_label.setAlignment(Qt.AlignLeft)

        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText(
            "+91 98765 43210"
        )
        self.phone_input.returnPressed.connect(
            self.handle_submit
        )

        # ----------------------------------
        # Password Label
        # ----------------------------------

        password_label = QLabel("PASSWORD")
        password_label.setObjectName("FieldLabel")
        password_label.setAlignment(Qt.AlignLeft)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText(
            "Enter your password"
        )
        self.password_input.returnPressed.connect(
            self.handle_submit
        )

        # ----------------------------------
        # Confirm Password Label
        # ----------------------------------

        self.confirm_password_label = QLabel("CONFIRM PASSWORD")
        self.confirm_password_label.setObjectName("FieldLabel")
        self.confirm_password_label.setAlignment(Qt.AlignLeft)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText(
            "Confirm your password"
        )
        self.confirm_password_input.returnPressed.connect(
            self.handle_submit
        )

        # ----------------------------------
        # Submit Button
        # ----------------------------------

        self.submit_button = QPushButton("Login")
        self.submit_button.setFixedHeight(46)
        self.submit_button.setCursor(Qt.PointingHandCursor)
        self.submit_button.clicked.connect(self.handle_submit)

        # ----------------------------------
        # Toggle Mode Button
        # ----------------------------------

        self.toggle_mode_button = QPushButton("Create an account")
        self.toggle_mode_button.setFlat(True)
        self.toggle_mode_button.clicked.connect(self.toggle_mode)

        # ----------------------------------
        # Status
        # ----------------------------------

        self.status = QLabel(
            "Not connected"
        )

        # L-1: show_connection_error() puts server-supplied error
        # text in here.
        self.status.setTextFormat(Qt.PlainText)

        self.status.setAlignment(Qt.AlignCenter)

        self.status.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;"
        )

        # ----------------------------------
        # Assemble
        # ----------------------------------

        card_layout.addWidget(self.logo)
        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)
        card_layout.addSpacing(14)

        # Field order matches the registration spec:
        # USERNAME, PHONE NUMBER, PASSWORD, CONFIRM PASSWORD.
        # In login mode the username and confirm-password rows hide,
        # which leaves PHONE NUMBER + PASSWORD in the same positions.
        card_layout.addWidget(self.username_label)
        card_layout.addWidget(self.username_input)
        card_layout.addWidget(self.phone_label)
        card_layout.addWidget(self.phone_input)
        card_layout.addWidget(password_label)
        card_layout.addWidget(self.password_input)
        card_layout.addWidget(self.confirm_password_label)
        card_layout.addWidget(self.confirm_password_input)

        card_layout.addSpacing(10)
        card_layout.addWidget(self.submit_button)
        card_layout.addWidget(self.toggle_mode_button)
        card_layout.addSpacing(6)
        card_layout.addWidget(self.status)

        outer_layout.addWidget(card)

        self.set_mode(register=False)

        # Login mode starts with the username field hidden -- focus the
        # field that's actually shown and actually the login identifier.
        self.phone_input.setFocus()

    # ======================================================
    # Private Helpers
    # ======================================================

    def set_mode(self, register: bool):
        self.is_register_mode = register

        # UI Finalization -- Login Identifier: the phone number field is
        # now shown in BOTH modes (it's the login identifier as well as
        # the registration-only discovery identifier); only username
        # (register-only, the display identity) and confirm-password
        # (register-only) toggle with the mode.
        self.username_label.setVisible(register)
        self.username_input.setVisible(register)
        self.confirm_password_label.setVisible(register)
        self.confirm_password_input.setVisible(register)

        self.submit_button.setText("Register" if register else "Login")
        self.toggle_mode_button.setText(
            "Already have an account? Login" if register else "Create an account"
        )
        self.status.setText("Not connected")

    # ======================================================
    # Public Methods
    # ======================================================

    def set_connecting(self, connecting):
        """
        Toggle the busy/connecting state so the
        user gets feedback and can't double-submit.
        """

        self.submit_button.setEnabled(not connecting)
        self.toggle_mode_button.setEnabled(not connecting)
        self.username_input.setEnabled(not connecting)
        self.password_input.setEnabled(not connecting)
        self.phone_input.setEnabled(not connecting)
        self.confirm_password_input.setEnabled(not connecting)

        self.status.setText(
            "Connecting..." if connecting else "Not connected"
        )
        self.status.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;"
        )

    def show_connection_error(self, message):
        """
        Reset the form and surface the failure reason.
        """

        self.set_connecting(False)

        self.status.setText(f"Authentication failed: {message}")
        self.status.setStyleSheet(
            f"color: {COLOR_DANGER}; font-size: 9.5pt;"
        )

    def show_validation_error(self, message):
        """
        Surface a field-validation problem through the same inline
        status channel as show_connection_error(), rather than a
        separate modal QMessageBox.

        This screen previously reported two different categories of
        "something is wrong with what you entered/tried" through two
        different UI mechanisms -- a blocking dialog for missing/
        invalid fields, inline text for a rejected login/registration.
        Both are the same kind of feedback from the user's point of
        view, so they now go through the same channel.
        """

        self.status.setText(message)
        self.status.setStyleSheet(
            f"color: {COLOR_DANGER}; font-size: 9.5pt;"
        )

    # ======================================================
    # Events
    # ======================================================

    def handle_submit(self):

        if not self.submit_button.isEnabled():
            return

        # UI Finalization -- Login Identifier: phone number + password
        # is the credential pair in BOTH modes now -- register mode
        # additionally needs username + confirm_password, checked
        # below.
        phone_number = self.phone_input.text().strip()
        password = self.password_input.text()

        if not phone_number:
            self.show_validation_error("Please enter your phone number.")
            return

        if not password:
            self.show_validation_error("Please enter a password.")
            return

        # Checked here only to fail fast with a clear message -- the
        # server validates and normalises independently, and is the
        # actual boundary. Applies to login too now, not just
        # registration: an unparsable phone number can never match a
        # stored (already-normalised) one.
        if not is_valid_phone_number(phone_number):
            self.show_validation_error(
                "Enter a valid phone number, for example +91 98765 43210."
            )
            return

        self.set_connecting(True)

        if self.is_register_mode:
            username = self.username_input.text().strip()
            confirm_password = self.confirm_password_input.text()

            if not username or not confirm_password:
                # set_connecting(False) first: it overwrites the status
                # text with "Not connected", so calling it before the
                # validation message would immediately erase what we
                # just told the user.
                self.set_connecting(False)
                self.show_validation_error("Please complete all registration fields.")
                return

            self.register_requested.emit(
                username,
                phone_number,
                password,
                confirm_password,
            )
        else:
            self.login_requested.emit(phone_number, password)

    def toggle_mode(self):
        self.set_mode(not self.is_register_mode)
