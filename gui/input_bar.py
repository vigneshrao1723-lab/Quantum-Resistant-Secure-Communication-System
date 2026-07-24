"""
Input Bar

Contains the message input field and send button.
"""

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
)


class InputBar(QWidget):
    """
    Message input widget.

    Emits the entered message whenever the
    user presses Enter or clicks the Send button.
    """

    message_sent = Signal(str)

    def __init__(self):
        super().__init__()

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QHBoxLayout(self)

        self.message_input = QLineEdit()

        self.message_input.setPlaceholderText(
            "Type your message..."
        )

        self.message_input.returnPressed.connect(
            self.send_message
        )

        self.send_button = QPushButton("Send")

        self.send_button.setFixedHeight(42)

        self.send_button.clicked.connect(
            self.send_message
        )

        layout.addWidget(self.message_input)

        layout.addWidget(self.send_button)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def clear_input(self):
        """
        Clear the message input field.
        """

        self.message_input.clear()

    def set_enabled(self, enabled):
        """
        Enable or disable the input controls.
        """

        self.message_input.setEnabled(enabled)

        self.send_button.setEnabled(enabled)

    # ==========================================================
    # Events
    # ==========================================================

    def send_message(self):
        """
        Emit the message entered by the user.
        """

        message = self.message_input.text().strip()

        if not message:
            return

        self.message_sent.emit(message)

        self.clear_input()