"""
Message Widget

Displays the conversation between the
current user and the selected chat partner.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
)


class MessageWidget(QListWidget):
    """
    Displays chat messages.
    """

    def __init__(self):
        super().__init__()

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):
        """
        Configure the message list.
        """

        self.setWordWrap(True)

        self.setSpacing(5)

        self.setSelectionMode(
            QAbstractItemView.NoSelection
        )

        self.setFocusPolicy(
            Qt.NoFocus
        )

    # ==========================================================
    # Public Methods
    # ==========================================================

    def add_system_message(self, message):
        """
        Display a system message.
        """

        item = QListWidgetItem(
            f"[SYSTEM] {message}"
        )

        self.addItem(item)

        self.scrollToBottom()

    def add_received_message(
        self,
        sender,
        message,
    ):
        """
        Display a received message.
        """

        item = QListWidgetItem(
            f"{sender}: {message}"
        )

        self.addItem(item)

        self.scrollToBottom()

    def add_sent_message(
        self,
        message,
    ):
        """
        Display a sent message.
        """

        item = QListWidgetItem(
            f"You: {message}"
        )

        self.addItem(item)

        self.scrollToBottom()

    def clear_messages(self):
        """
        Remove every message.
        """

        self.clear()