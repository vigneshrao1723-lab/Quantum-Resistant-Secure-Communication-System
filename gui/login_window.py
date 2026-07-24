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
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QMessageBox,
)


class LoginWindow(QWidget):
    """
    Login page for the application.
    """

    connect_requested = Signal(str)

    def __init__(self):
        super().__init__()

        self.build_ui()

    # ======================================================
    # UI
    # ======================================================

    def build_ui(self):

        main_layout = QVBoxLayout()

        main_layout.setAlignment(Qt.AlignCenter)

        main_layout.setSpacing(20)

        # ----------------------------------
        # Logo
        # ----------------------------------

        self.logo = QLabel()

        pixmap = QPixmap("gui/resources/logo.png")

        if not pixmap.isNull():

            self.logo.setPixmap(
                pixmap.scaled(
                    140,
                    140,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
            )

        self.logo.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Title
        # ----------------------------------

        title = QLabel(
            "Quantum-Resistant Secure Communication System"
        )

        title.setObjectName("Title")

        title.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Subtitle
        # ----------------------------------

        subtitle = QLabel(
            "Secure Chat using Post-Quantum Cryptography"
        )

        subtitle.setObjectName("Subtitle")

        subtitle.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Username Label
        # ----------------------------------

        username_label = QLabel("Username")

        # ----------------------------------
        # Username Input
        # ----------------------------------

        self.username_input = QLineEdit()

        self.username_input.setPlaceholderText(
            "Enter your username"
        )

        self.username_input.setMaximumWidth(350)

        # ----------------------------------
        # Connect Button
        # ----------------------------------

        self.connect_button = QPushButton("Connect")

        self.connect_button.setFixedHeight(45)

        self.connect_button.setMaximumWidth(350)

        self.connect_button.clicked.connect(
            self.handle_connect
        )

        # ----------------------------------
        # Status
        # ----------------------------------

        self.status = QLabel(
            "Status : Not Connected"
        )

        self.status.setAlignment(Qt.AlignCenter)

        # ----------------------------------
        # Layout
        # ----------------------------------

        form = QVBoxLayout()

        form.setAlignment(Qt.AlignCenter)

        form.addWidget(username_label)

        form.addWidget(self.username_input)

        form.addSpacing(10)

        form.addWidget(self.connect_button)

        form.setAlignment(
            self.connect_button,
            Qt.AlignCenter
        )

        main_layout.addWidget(self.logo)

        main_layout.addWidget(title)

        main_layout.addWidget(subtitle)

        main_layout.addSpacing(20)

        main_layout.addLayout(form)

        main_layout.addSpacing(20)

        main_layout.addWidget(self.status)

        self.setLayout(main_layout)

    # ======================================================
    # Events
    # ======================================================

    def handle_connect(self):

        username = self.username_input.text().strip()

        if not username:

            QMessageBox.warning(
                self,
                "Username Required",
                "Please enter a username."
            )

            return

        self.status.setText(
            "Status : Connecting..."
        )

        self.connect_requested.emit(username)