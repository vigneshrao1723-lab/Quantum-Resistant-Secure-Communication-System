"""
Status Bar Widget

Displays the current connection status,
active encryption algorithm, and logged-in user.
"""

from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QHBoxLayout,
)


class StatusBarWidget(QWidget):
    """
    Status bar displayed at the bottom
    of the chat window.
    """

    def __init__(self):
        super().__init__()

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QHBoxLayout(self)

        self.connection_label = QLabel(
            "🔴 Disconnected"
        )

        self.algorithm_label = QLabel(
            "Encryption: RSA"
        )

        self.user_label = QLabel(
            "User: -"
        )

        layout.addWidget(self.connection_label)

        layout.addStretch()

        layout.addWidget(self.algorithm_label)

        layout.addSpacing(20)

        layout.addWidget(self.user_label)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def set_connected(self, connected):
        """
        Update the connection status.
        """

        if connected:
            self.connection_label.setText(
                "🟢 Connected"
            )
        else:
            self.connection_label.setText(
                "🔴 Disconnected"
            )

    def set_algorithm(self, algorithm):
        """
        Update the encryption algorithm.
        """

        self.algorithm_label.setText(
            f"Encryption: {algorithm}"
        )

    def set_username(self, username):
        """
        Update the logged-in username.
        """

        self.user_label.setText(
            f"User: {username}"
        )