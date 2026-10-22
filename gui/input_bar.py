"""
Input Bar

The conversation composer: an attachment button, a rounded multi-line message
field that grows with its content, and a circular send button.
"""

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
)

from gui.icons import toolbar_icon
from gui.media_recorder_dialog import MediaRecorderDialog
from gui.styles import COLOR_ON_ACCENT, COLOR_TEXT_MUTED


class ComposerTextEdit(QPlainTextEdit):
    """
    Multi-line message field with the small slice of the QLineEdit API the rest
    of the application already uses (``text()``, ``setText()``,
    ``setCursorPosition()``, ``returnPressed``), so it is a drop-in replacement.

    Enter sends (``returnPressed``); Shift+Enter inserts a line break. The field
    is one line tall when empty and grows to ``MAX_LINES`` lines before it
    starts scrolling, so a long message never hides the conversation above it
    and a short one never wastes space.
    """

    returnPressed = Signal()

    MAX_LINES = 6
    _VERTICAL_PADDING = 4

    def __init__(self):
        super().__init__()

        self.setObjectName("ComposerInput")
        self.setFrameShape(QFrame.NoFrame)
        self.setTabChangesFocus(True)
        self.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.document().setDocumentMargin(2)

        self.textChanged.connect(self._fit_height)
        self._fit_height()

    # -- QLineEdit-compatible surface ----------------------------------------

    def text(self):
        return self.toPlainText()

    def setText(self, text):
        self.setPlainText(text or "")

    def setCursorPosition(self, position):
        cursor = self.textCursor()
        cursor.setPosition(max(0, min(position, len(self.toPlainText()))))
        self.setTextCursor(cursor)

    def cursorPosition(self):
        return self.textCursor().position()

    # -- behaviour ------------------------------------------------------------

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter) and not (
            event.modifiers() & Qt.ShiftModifier
        ):
            event.accept()
            self.returnPressed.emit()
            return

        super().keyPressEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit_height()

    def _fit_height(self):
        line_height = self.fontMetrics().lineSpacing()
        lines = int(self.document().documentLayout().documentSize().height())
        lines = max(1, min(lines, self.MAX_LINES))
        margin = int(self.document().documentMargin()) * 2
        height = lines * line_height + margin + self._VERTICAL_PADDING

        if self.height() != height or self.minimumHeight() != height:
            self.setFixedHeight(height)

        if lines >= self.MAX_LINES:
            self.ensureCursorVisible()

    def focusInEvent(self, event):
        super().focusInEvent(event)
        self._set_field_focus(True)

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        self._set_field_focus(False)

    def _set_field_focus(self, focused):
        # The rounded field around this widget carries the visible focus
        # ring -- see QFrame#ComposerField[focused="true"] in gui/styles.py.
        field = self.parentWidget()
        if field is None:
            return
        field.setProperty("focused", focused)
        field.style().unpolish(field)
        field.style().polish(field)


class InputBar(QFrame):
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

        self.setObjectName("Composer")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 12)
        layout.setSpacing(10)
        layout.setAlignment(Qt.AlignBottom)

        self.attach_button = QPushButton()
        self.attach_button.setObjectName("ComposerButton")
        self.attach_button.setIcon(toolbar_icon("attach"))
        self.attach_button.setIconSize(QSize(22, 22))
        self.attach_button.setFixedSize(40, 40)
        self.attach_button.setCursor(Qt.PointingHandCursor)
        self.attach_button.setToolTip("Attach a photo, file, voice, or video message")
        self.attach_button.setAccessibleName("Attach")
        self.attach_button.clicked.connect(self._handle_attach_clicked)

        field = QFrame()
        field.setObjectName("ComposerField")
        field.setProperty("focused", False)
        field_layout = QHBoxLayout(field)
        field_layout.setContentsMargins(16, 7, 14, 7)

        self.message_input = ComposerTextEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setAccessibleName("Message")
        self.message_input.returnPressed.connect(self.send_message)
        self.message_input.textChanged.connect(self._update_send_button_state)
        field_layout.addWidget(self.message_input)

        self.send_button = QPushButton()
        self.send_button.setObjectName("SendButton")
        self.send_button.setIcon(
            toolbar_icon("send", color=COLOR_ON_ACCENT, active_color=COLOR_ON_ACCENT, disabled_color=COLOR_TEXT_MUTED)
        )
        self.send_button.setIconSize(QSize(20, 20))
        self.send_button.setFixedSize(40, 40)
        self.send_button.setCursor(Qt.PointingHandCursor)
        self.send_button.setToolTip("Send (Enter)")
        self.send_button.setAccessibleName("Send message")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)

        layout.addWidget(self.attach_button, 0, Qt.AlignBottom)
        layout.addWidget(field, 1)
        layout.addWidget(self.send_button, 0, Qt.AlignBottom)

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

        self.message_input.moveCursor(QTextCursor.End)

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

        self.send_button.setEnabled(has_text and self.message_input.isEnabled())

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
        menu.addAction(toolbar_icon("gallery"), "Photo or file").setData("file")
        menu.addAction(toolbar_icon("mic"), "Voice message").setData("voice")
        menu.addAction(toolbar_icon("video"), "Video message").setData("video")

        # Open upward from the button so the menu never falls off the bottom
        # of the screen (the composer sits at the very bottom of the window).
        menu_height = menu.sizeHint().height()
        origin = self.attach_button.mapToGlobal(self.attach_button.rect().topLeft())
        origin.setY(origin.y() - menu_height - 6)

        chosen = menu.exec(origin)

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
