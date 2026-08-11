"""
Message Widget

Displays the conversation between the current user and the
selected chat partner as chat bubbles (sent / received / system).
"""

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
    QWidget,
    QLabel,
    QFileDialog,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QSizePolicy,
)

from gui.styles import (
    COLOR_BUBBLE_SENT,
    COLOR_BUBBLE_RECEIVED,
    COLOR_BUBBLE_SYSTEM,
    COLOR_TEXT_MUTED,
)


class MessageBubble(QWidget):
    """
    A single chat bubble.

    kind is one of "sent", "received", "system".
    """

    def __init__(self, text, kind, sender=None, timestamp=None):
        super().__init__()

        self.kind = kind

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(14, 8, 14, 8)
        bubble_layout.setSpacing(2)

        bubble.setMaximumWidth(480)
        bubble.setSizePolicy(
            QSizePolicy.Maximum,
            QSizePolicy.Minimum,
        )

        if kind == "system":

            label = QLabel(text)
            label.setWordWrap(True)
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet(
                f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt; "
                "font-style: italic;"
            )

            bubble_layout.addWidget(label)

            bubble.setStyleSheet(
                f"background-color: {COLOR_BUBBLE_SYSTEM}; "
                "border-radius: 12px;"
            )

            outer.addStretch()
            outer.addWidget(bubble)
            outer.addStretch()

        else:

            if sender and kind == "received":

                name_label = QLabel(sender)
                name_label.setStyleSheet(
                    "font-size: 9pt; font-weight: 600; "
                    "color: #9EB4FF;"
                )
                bubble_layout.addWidget(name_label)

            text_label = QLabel(text)
            text_label.setWordWrap(True)
            text_label.setTextInteractionFlags(
                Qt.TextSelectableByMouse
            )
            text_label.setStyleSheet(
                "color: white; font-size: 10.5pt; "
                "background: transparent;"
            )

            bubble_layout.addWidget(text_label)

            time_label = QLabel(
                timestamp or datetime.now().strftime("%H:%M")
            )
            time_label.setStyleSheet(
                "color: rgba(255, 255, 255, 0.55); "
                "font-size: 8pt; background: transparent;"
            )
            time_label.setAlignment(
                Qt.AlignRight if kind == "sent" else Qt.AlignLeft
            )

            bubble_layout.addWidget(time_label)

            if kind == "sent":

                bubble.setStyleSheet(
                    f"background-color: {COLOR_BUBBLE_SENT}; "
                    "border-radius: 14px;"
                )

                outer.addStretch()
                outer.addWidget(bubble)

            else:

                bubble.setStyleSheet(
                    f"background-color: {COLOR_BUBBLE_RECEIVED}; "
                    "border-radius: 14px;"
                )

                outer.addWidget(bubble)
                outer.addStretch()


def _format_file_size(size_bytes):
    """Human-readable file size (Phase 8 -- File & Image Transfer)."""

    size = float(size_bytes)

    for unit in ("B", "KB", "MB", "GB"):

        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"

        size /= 1024

    return f"{size:.1f} TB"


class ImageMessageBubble(QWidget):
    """
    A single image chat bubble -- an inline thumbnail rendered
    directly from already-decrypted bytes (Phase 8 -- File & Image
    Transfer).

    A sibling class to MessageBubble, not a modification of it: it
    duplicates MessageBubble's small amount of outer/bubble/alignment/
    timestamp scaffolding rather than generalizing MessageBubble
    itself, so the existing, tested text-bubble code path is provably
    untouched by this addition -- zero lines of MessageBubble changed.
    """

    MAX_THUMBNAIL_WIDTH = 320

    def __init__(self, image_bytes, kind, sender=None, timestamp=None):
        super().__init__()

        self.kind = kind

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(8, 8, 8, 8)
        bubble_layout.setSpacing(4)

        bubble.setMaximumWidth(self.MAX_THUMBNAIL_WIDTH + 16)
        bubble.setSizePolicy(
            QSizePolicy.Maximum,
            QSizePolicy.Minimum,
        )

        if sender and kind == "received":

            name_label = QLabel(sender)
            name_label.setStyleSheet(
                "font-size: 9pt; font-weight: 600; color: #9EB4FF;"
            )
            bubble_layout.addWidget(name_label)

        image_label = QLabel()

        pixmap = QPixmap()
        loaded = pixmap.loadFromData(image_bytes)

        if loaded and not pixmap.isNull():

            scaled = pixmap.scaledToWidth(
                self.MAX_THUMBNAIL_WIDTH, Qt.SmoothTransformation
            )
            image_label.setPixmap(scaled)

        else:

            image_label.setText("[Unable to display image]")
            image_label.setStyleSheet("color: white;")

        bubble_layout.addWidget(image_label)

        time_label = QLabel(
            timestamp or datetime.now().strftime("%H:%M")
        )
        time_label.setStyleSheet(
            "color: rgba(255, 255, 255, 0.55); "
            "font-size: 8pt; background: transparent;"
        )
        time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(time_label)

        bubble.setStyleSheet(
            f"background-color: "
            f"{COLOR_BUBBLE_SENT if kind == 'sent' else COLOR_BUBBLE_RECEIVED}; "
            "border-radius: 14px;"
        )

        if kind == "sent":
            outer.addStretch()
            outer.addWidget(bubble)
        else:
            outer.addWidget(bubble)
            outer.addStretch()


class FileMessageBubble(QWidget):
    """
    A single file chat bubble -- filename, human-readable size, and a
    "Save As..." button that writes the already-decrypted bytes held
    in memory (Phase 8 -- File & Image Transfer). No plaintext is ever
    written to disk until the user explicitly chooses to save it.

    A sibling class to MessageBubble, for the same reason
    ImageMessageBubble is -- see its docstring.
    """

    def __init__(self, file_bytes, content_metadata, kind, sender=None, timestamp=None):
        super().__init__()

        self.kind = kind
        self._file_bytes = file_bytes
        self._filename = (content_metadata or {}).get("filename") or "file"

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(14, 10, 14, 10)
        bubble_layout.setSpacing(4)

        bubble.setMaximumWidth(480)
        bubble.setSizePolicy(
            QSizePolicy.Maximum,
            QSizePolicy.Minimum,
        )

        if sender and kind == "received":

            sender_label = QLabel(sender)
            sender_label.setStyleSheet(
                "font-size: 9pt; font-weight: 600; color: #9EB4FF;"
            )
            bubble_layout.addWidget(sender_label)

        name_label = QLabel(f"\U0001F4C4 {self._filename}")
        name_label.setWordWrap(True)
        name_label.setStyleSheet(
            "color: white; font-size: 10.5pt; background: transparent;"
        )
        bubble_layout.addWidget(name_label)

        size_bytes = (content_metadata or {}).get("size_bytes", len(file_bytes))
        size_label = QLabel(_format_file_size(size_bytes))
        size_label.setStyleSheet(
            "color: rgba(255, 255, 255, 0.6); "
            "font-size: 8.5pt; background: transparent;"
        )
        bubble_layout.addWidget(size_label)

        save_button = QPushButton("Save As...")
        save_button.setObjectName("SecondaryButton")
        save_button.setCursor(Qt.PointingHandCursor)
        save_button.clicked.connect(self._handle_save_as)
        bubble_layout.addWidget(save_button)

        time_label = QLabel(
            timestamp or datetime.now().strftime("%H:%M")
        )
        time_label.setStyleSheet(
            "color: rgba(255, 255, 255, 0.55); "
            "font-size: 8pt; background: transparent;"
        )
        time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(time_label)

        bubble.setStyleSheet(
            f"background-color: "
            f"{COLOR_BUBBLE_SENT if kind == 'sent' else COLOR_BUBBLE_RECEIVED}; "
            "border-radius: 14px;"
        )

        if kind == "sent":
            outer.addStretch()
            outer.addWidget(bubble)
        else:
            outer.addWidget(bubble)
            outer.addStretch()

    def _handle_save_as(self):
        """
        Write the already-decrypted bytes this bubble holds to a
        user-chosen local path. A no-op if the dialog is cancelled.
        """

        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save File",
            self._filename
        )

        if path:
            Path(path).write_bytes(self._file_bytes)


class MessageWidget(QListWidget):
    """
    Displays chat messages as bubbles.
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

        self.setSelectionMode(
            QAbstractItemView.NoSelection
        )

        self.setFocusPolicy(
            Qt.NoFocus
        )

        self.setVerticalScrollMode(
            QAbstractItemView.ScrollPerPixel
        )

        self.setStyleSheet(
            "QListWidget { border: none; background: transparent; }"
        )

        self.setSpacing(2)

    # ==========================================================
    # Internal Helpers
    # ==========================================================

    def _add_bubble(self, bubble):

        item = QListWidgetItem()

        item.setFlags(Qt.NoItemFlags)

        item.setSizeHint(
            bubble.sizeHint()
        )

        self.addItem(item)

        self.setItemWidget(item, bubble)

        self.scrollToBottom()

    # ==========================================================
    # Public Methods
    # ==========================================================

    def add_system_message(self, message):
        """
        Display a system message.
        """

        self._add_bubble(
            MessageBubble(message, kind="system")
        )

    def add_received_message(
        self,
        sender,
        message,
        timestamp=None,
    ):
        """
        Display a received message.
        """

        self._add_bubble(
            MessageBubble(
                message, kind="received", sender=sender, timestamp=timestamp
            )
        )

    def add_sent_message(
        self,
        message,
        timestamp=None,
    ):
        """
        Display a sent message.
        """

        self._add_bubble(
            MessageBubble(message, kind="sent", timestamp=timestamp)
        )

    def add_received_image(self, sender, image_bytes, timestamp=None):
        """
        Display a received image (Phase 8 -- File & Image Transfer).
        """

        self._add_bubble(
            ImageMessageBubble(
                image_bytes, kind="received", sender=sender, timestamp=timestamp
            )
        )

    def add_sent_image(self, image_bytes, timestamp=None):
        """
        Display a sent image (Phase 8 -- File & Image Transfer).
        """

        self._add_bubble(
            ImageMessageBubble(image_bytes, kind="sent", timestamp=timestamp)
        )

    def add_received_file(self, sender, file_bytes, content_metadata, timestamp=None):
        """
        Display a received file (Phase 8 -- File & Image Transfer).
        """

        self._add_bubble(
            FileMessageBubble(
                file_bytes,
                content_metadata,
                kind="received",
                sender=sender,
                timestamp=timestamp,
            )
        )

    def add_sent_file(self, file_bytes, content_metadata, timestamp=None):
        """
        Display a sent file (Phase 8 -- File & Image Transfer).
        """

        self._add_bubble(
            FileMessageBubble(
                file_bytes, content_metadata, kind="sent", timestamp=timestamp
            )
        )

    def clear_messages(self):
        """
        Remove every message.
        """

        self.clear()