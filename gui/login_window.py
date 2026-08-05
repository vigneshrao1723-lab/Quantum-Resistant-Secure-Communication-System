"""
Login Window

Allows the user to enter a username and
connect to the secure chat server.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap

from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QVBoxLayout,
    QFrame,
    QLineEdit,
    QPushButton,
    QMessageBox,
)

from gui.styles import COLOR_TEXT_MUTED, COLOR_OFFLINE


class LoginWindow(QWidget):
    """
    Login and registration page for the application.
    """

    login_requested = Signal(str, str)
    register_requested = Signal(str, str, str, str, str)

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

        card_layout.setContentsMargins(40, 40, 40, 32)

        card_layout.setSpacing(6)

        card_layout.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Logo
        # ----------------------------------

        self.logo = QLabel()

        pixmap = QPixmap("gui/resources/logo.png")

        if not pixmap.isNull():

            self.logo.setPixmap(
                pixmap.scaled(
                    96,
                    96,
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
        # Full Name Label
        # ----------------------------------

        self.full_name_label = QLabel("FULL NAME")
        self.full_name_label.setObjectName("FieldLabel")
        self.full_name_label.setAlignment(Qt.AlignLeft)

        self.full_name_input = QLineEdit()
        self.full_name_input.setPlaceholderText(
            "Enter your full name"
        )
        self.full_name_input.returnPressed.connect(
            self.handle_submit
        )

        # ----------------------------------
        # Email Label
        # ----------------------------------

        self.email_label = QLabel("EMAIL")
        self.email_label.setObjectName("FieldLabel")
        self.email_label.setAlignment(Qt.AlignLeft)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText(
            "Enter your email"
        )
        self.email_input.returnPressed.connect(
            self.handle_submit
        )

        # ----------------------------------
        # Username or Email Label
        # ----------------------------------

        username_label = QLabel("USERNAME OR EMAIL")
        username_label.setObjectName("FieldLabel")
        username_label.setAlignment(Qt.AlignLeft)

        # ----------------------------------
        # Username Input
        # ----------------------------------

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText(
            "Enter your username or email"
        )
        self.username_input.returnPressed.connect(
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

        self.status.setAlignment(Qt.AlignCenter)

        self.status.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;"
        )

        # ----------------------------------
        # Assemble
        # ----------------------------------

        card_layout.addWidget(self.logo)
        card_layout.addSpacing(4)
        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)
        card_layout.addSpacing(24)

        card_layout.addWidget(self.full_name_label)
        card_layout.addWidget(self.full_name_input)
        card_layout.addWidget(self.email_label)
        card_layout.addWidget(self.email_input)

        card_layout.addWidget(username_label)
        card_layout.addWidget(self.username_input)
        card_layout.addWidget(password_label)
        card_layout.addWidget(self.password_input)
        card_layout.addWidget(self.confirm_password_label)
        card_layout.addWidget(self.confirm_password_input)

        card_layout.addSpacing(14)
        card_layout.addWidget(self.submit_button)
        card_layout.addWidget(self.toggle_mode_button)
        card_layout.addSpacing(16)
        card_layout.addWidget(self.status)

        outer_layout.addWidget(card)

        self.username_input.setFocus()
        self.set_mode(register=False)

    # ======================================================
    # Private Helpers
    # ======================================================

    def set_mode(self, register: bool):
        self.is_register_mode = register

        self.full_name_label.setVisible(register)
        self.full_name_input.setVisible(register)
        self.email_label.setVisible(register)
        self.email_input.setVisible(register)
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
        self.full_name_input.setEnabled(not connecting)
        self.email_input.setEnabled(not connecting)
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
            f"color: {COLOR_OFFLINE}; font-size: 9.5pt;"
        )

    # ======================================================
    # Events
    # ======================================================

    def handle_submit(self):

        if not self.submit_button.isEnabled():
            return

        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username:
            QMessageBox.warning(
                self,
                "Username or Email Required",
                "Please enter your username or email."
            )
            return

        if not password:
            QMessageBox.warning(
                self,
                "Password Required",
                "Please enter a password."
            )
            return

        self.set_connecting(True)

        if self.is_register_mode:
            full_name = self.full_name_input.text().strip()
            email = self.email_input.text().strip()
            confirm_password = self.confirm_password_input.text()

            if not full_name or not email or not confirm_password:
                QMessageBox.warning(
                    self,
                    "Registration Required",
                    "Please complete all registration fields."
                )
                self.set_connecting(False)
                return

            self.register_requested.emit(
                full_name,
                username,
                email,
                password,
                confirm_password,
            )
        else:
            self.login_requested.emit(username, password)

    def toggle_mode(self):
        self.set_mode(not self.is_register_mode)
