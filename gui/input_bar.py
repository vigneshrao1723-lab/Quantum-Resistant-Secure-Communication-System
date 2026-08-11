"""
Input Bar

Contains the message input field and send button.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
)


class InputBar(QWidget):
    """
    Message input widget.

    Emits the entered message whenever the
    user presses Enter or clicks the Send button.

    Also emits attachment_selected (Phase 8 -- File & Image Transfer)
    when the user picks a local file via the Attach button -- a bare
    file path, not its content; ChatWindow/ClientSession own reading,
    classifying, and sending it. This widget has no opinion on File
    vs. Image -- the user is never asked to choose (see
    domain/payload_type.py::classify_attachment()).
    """

    message_sent = Signal(str)
    attachment_selected = Signal(str)

    def __init__(self):
        super().__init__()

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QHBoxLayout(self)
        layout.setSpacing(10)

        self.attach_button = QPushButton("\U0001F4CE")

        self.attach_button.setObjectName("IconButton")

        self.attach_button.setFixedSize(44, 44)

        self.attach_button.setCursor(Qt.PointingHandCursor)

        self.attach_button.setToolTip("Attach a file or image")

        self.attach_button.clicked.connect(
            self._handle_attach_clicked
        )

        self.message_input = QLineEdit()

        self.message_input.setPlaceholderText(
            "Type a message..."
        )

        self.message_input.returnPressed.connect(
            self.send_message
        )

        self.message_input.textChanged.connect(
            self._update_send_button_state
        )

        self.send_button = QPushButton("Send")

        self.send_button.setFixedHeight(44)

        self.send_button.setFixedWidth(90)

        self.send_button.setEnabled(False)

        self.send_button.clicked.connect(
            self.send_message
        )

        layout.addWidget(self.attach_button)

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

        self.attach_button.setEnabled(enabled)

        if enabled:
            self._update_send_button_state()
        else:
            self.send_button.setEnabled(False)

    def focus_input(self):
        """
        Move keyboard focus to the message field.
        """

        self.message_input.setFocus()

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

    def _update_send_button_state(self):
        """
        Only allow sending when there is
        non-whitespace text in the input.
        """

        has_text = bool(
            self.message_input.text().strip()
        )

        self.send_button.setEnabled(has_text)

    def _handle_attach_clicked(self):
        """
        Open a native file picker and emit the chosen path (Phase 8 --
        File & Image Transfer). One dialog, no File/Image filter split
        -- classification happens downstream, never here.
        """

        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Attach File"
        )

        if path:
            self.attachment_selected.emit(path)