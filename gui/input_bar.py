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
    QMenu,
    QPushButton,
)

from gui.media_recorder_dialog import MediaRecorderDialog


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
    # Phase 19.24 -- Attachment Menu / Voice & Video Messages: a real
    # recorded clip's local temp file path -- ChatWindow connects this
    # to the SAME handle_attachment_selected() the plain file/image
    # path above already uses (send_attachment() classifies it as
    # PayloadType.VOICE/VIDEO by its own mime type, see domain/
    # payload_type.py::classify_attachment()), then deletes the temp
    # file once its bytes are read into memory.
    voice_message_recorded = Signal(str)
    video_message_recorded = Signal(str)

    def __init__(self):
        super().__init__()

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QHBoxLayout(self)
        layout.setSpacing(10)

        # ︎ (VS15, text presentation selector) keeps this rendering
        # as a plain monochrome glyph -- without it, Windows renders
        # U+1F4CE in its full-color emoji style, which reads as
        # out of place next to the app's other flat, single-color
        # icon glyphs (the arrows/gear elsewhere in this app).
        self.attach_button = QPushButton("\U0001F4CE︎")

        self.attach_button.setObjectName("IconButton")

        self.attach_button.setFixedSize(44, 44)

        self.attach_button.setStyleSheet("font-size: 20px;")

        self.attach_button.setCursor(Qt.PointingHandCursor)

        self.attach_button.setToolTip("Attach a photo, file, voice, or video message")

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

    def set_text(self, text):
        """
        Phase 19.24 (continued) -- pre-fill the composer with existing
        text (used to seed Edit mode with the message's current
        content) and move the cursor to the end, exactly where a user
        resuming a draft would expect it.
        """

        self.message_input.setText(text or "")

        self.message_input.setCursorPosition(len(self.message_input.text()))

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
        Phase 19.24 -- Attachment Menu: one small, consistent menu
        exposing every attachment kind (Photo/File picker, Voice
        Message, Video Message) -- mirrors mobile/app.py's
        _start_attachment_pick()/web/client's #attachmentMenu offering
        the exact same three choices, so the feature looks and behaves
        like the same app across all three clients.
        """

        menu = QMenu(self)
        menu.addAction("\U0001F5BC️ Photo / File").setData("file")
        menu.addAction("\U0001F3A4 Voice Message").setData("voice")
        menu.addAction("\U0001F3AC Video Message").setData("video")

        chosen = menu.exec(self.attach_button.mapToGlobal(
            self.attach_button.rect().topLeft()
        ))

        if chosen is None:
            return

        choice = chosen.data()

        if choice == "file":
            self._pick_file()
        elif choice == "voice":
            self._record_media("voice")
        elif choice == "video":
            self._record_media("video")

    def _pick_file(self):
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

    def _record_media(self, mode):
        """
        Opens the real voice/video recorder dialog (gui/media_recorder_
        dialog.py) and, if the user actually recorded and chose Send,
        emits the resulting local temp file's path via voice_message_
        recorded/video_message_recorded -- ChatWindow connects both to
        the SAME handle_attachment_selected() the plain file picker
        above already uses.
        """

        dialog = MediaRecorderDialog(mode, parent=self)

        if dialog.exec() != MediaRecorderDialog.Accepted or not dialog.recorded_file_path:
            return

        if mode == "voice":
            self.voice_message_recorded.emit(dialog.recorded_file_path)
        else:
            self.video_message_recorded.emit(dialog.recorded_file_path)