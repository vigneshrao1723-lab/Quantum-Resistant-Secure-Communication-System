"""
Message Widget

Displays the conversation between the current user and the
selected chat partner as chat bubbles (sent / received / system).
"""

from datetime import datetime

from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
    QWidget,
    QLabel,
    QHBoxLayout,
    QVBoxLayout,
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

    def clear_messages(self):
        """
        Remove every message.
        """

        self.clear()