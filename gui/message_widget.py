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


def _read_status_suffix(read_status):
    """
    Read-receipt glyph appended to a sent bubble's timestamp label (C2
    -- Read Receipts): nothing for None (no receipt data at all -- a
    legacy message persisted before C2, or a conversation partner who
    predates MessageRecipient rows for direct messages), a single
    check for sent/delivered-but-not-yet-fully-read, a double check
    once fully read. Never called for a received/system bubble, which
    never shows a receipt indicator at all -- see each bubble class's
    set_read_status().
    """

    if read_status is None:
        return ""

    return "  ✓✓" if read_status else "  ✓"


class MessageBubble(QWidget):
    """
    A single chat bubble.

    kind is one of "sent", "received", "system".
    """

    def __init__(self, text, kind, sender=None, timestamp=None, read_status=None):
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

            self._timestamp_text = timestamp or datetime.now().strftime("%H:%M")

            self.time_label = QLabel(
                self._timestamp_text + (
                    _read_status_suffix(read_status) if kind == "sent" else ""
                )
            )
            self.time_label.setStyleSheet(
                "color: rgba(255, 255, 255, 0.55); "
                "font-size: 8pt; background: transparent;"
            )
            self.time_label.setAlignment(
                Qt.AlignRight if kind == "sent" else Qt.AlignLeft
            )

            bubble_layout.addWidget(self.time_label)

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

    def set_read_status(self, read_status):
        """
        Update this sent bubble's check-mark glyph in place (C2 --
        Read Receipts), without touching the timestamp it's appended
        to. A no-op for a received/system bubble -- neither ever shows
        one, by design (see _read_status_suffix()'s docstring).
        """

        if self.kind != "sent":
            return

        self.time_label.setText(self._timestamp_text + _read_status_suffix(read_status))


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

    def __init__(self, image_bytes, kind, sender=None, timestamp=None, read_status=None):
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

        self._timestamp_text = timestamp or datetime.now().strftime("%H:%M")

        self.time_label = QLabel(
            self._timestamp_text + (
                _read_status_suffix(read_status) if kind == "sent" else ""
            )
        )
        self.time_label.setStyleSheet(
            "color: rgba(255, 255, 255, 0.55); "
            "font-size: 8pt; background: transparent;"
        )
        self.time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(self.time_label)

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

    def set_read_status(self, read_status):
        """
        Update this sent bubble's check-mark glyph in place (C2 --
        Read Receipts). A no-op for a received bubble -- see
        MessageBubble.set_read_status()'s identical docstring.
        """

        if self.kind != "sent":
            return

        self.time_label.setText(self._timestamp_text + _read_status_suffix(read_status))


class FileMessageBubble(QWidget):
    """
    A single file chat bubble -- filename, human-readable size, and a
    "Save As..." button that writes the already-decrypted bytes held
    in memory (Phase 8 -- File & Image Transfer). No plaintext is ever
    written to disk until the user explicitly chooses to save it.

    A sibling class to MessageBubble, for the same reason
    ImageMessageBubble is -- see its docstring.
    """

    def __init__(
        self,
        file_bytes,
        content_metadata,
        kind,
        sender=None,
        timestamp=None,
        read_status=None,
    ):
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

        self._timestamp_text = timestamp or datetime.now().strftime("%H:%M")

        self.time_label = QLabel(
            self._timestamp_text + (
                _read_status_suffix(read_status) if kind == "sent" else ""
            )
        )
        self.time_label.setStyleSheet(
            "color: rgba(255, 255, 255, 0.55); "
            "font-size: 8pt; background: transparent;"
        )
        self.time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(self.time_label)

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

    def set_read_status(self, read_status):
        """
        Update this sent bubble's check-mark glyph in place (C2 --
        Read Receipts). A no-op for a received bubble -- see
        MessageBubble.set_read_status()'s identical docstring.
        """

        if self.kind != "sent":
            return

        self.time_label.setText(self._timestamp_text + _read_status_suffix(read_status))


class MessageWidget(QListWidget):
    """
    Displays chat messages as bubbles.
    """

    def __init__(self):
        super().__init__()

        # C2 -- Read Receipts: this client's own sent bubbles in the
        # currently-open conversation, so a later
        # read_receipt_notification can flip them to "read" in place --
        # see mark_all_sent_read(). Cleared on every clear_messages()
        # call (i.e. every conversation open/switch), since bubbles are
        # always re-rendered fresh from history at that point anyway.
        #
        # Keyed by the database message_id where one is known (a
        # history-loaded row), and by a synthetic per-bubble key where
        # one is not (a message sent live this session, which has no
        # database id on this client -- the id is assigned server-side
        # by persist_message() and never sent back). BUG 2: a live
        # bubble used to be left out of this registry entirely, which
        # is precisely why a sender watching the conversation saw
        # nothing when the other party read it -- there was no
        # reference to flip -- and why the tick only appeared after a
        # logout/login, when history re-rendered the same message with
        # its real id. Every sent bubble is now reachable, whatever the
        # client happens to know about its id.
        #
        # Real ids are still used as keys wherever they exist, so a
        # future per-message (rather than conversation-level) receipt
        # can address exactly one bubble without changing this
        # structure.
        self._sent_bubbles_by_message_id = {}

        # Source of the synthetic keys above. A plain counter, never
        # persisted and never sent anywhere -- it exists only to keep
        # two live bubbles in the same conversation distinct.
        self._live_bubble_sequence = 0

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

    def _add_bubble(self, bubble, message_id=None):

        item = QListWidgetItem()

        item.setFlags(Qt.NoItemFlags)

        item.setSizeHint(
            bubble.sizeHint()
        )

        self.addItem(item)

        self.setItemWidget(item, bubble)

        self.scrollToBottom()

        # C2 -- Read Receipts: every SENT bubble is registered, with or
        # without a database id (BUG 2 -- see __init__'s note on this
        # registry for why the id cannot be a precondition). A received
        # bubble is still never registered: it never shows a receipt
        # indicator (set_read_status() is a no-op for it regardless),
        # so tracking it would only waste memory.
        if bubble.kind == "sent":

            if message_id is None:
                self._live_bubble_sequence += 1
                message_id = f"live-{self._live_bubble_sequence}"

            self._sent_bubbles_by_message_id[message_id] = bubble

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
        message_id=None,
        read_status=None,
    ):
        """
        Display a sent message. ``message_id``/``read_status`` (C2 --
        Read Receipts) are optional -- omitted for a message sent live
        this session (no database id yet); supplied by
        gui/chat_window.py::load_history() for a history-loaded row,
        which always has both.
        """

        self._add_bubble(
            MessageBubble(
                message, kind="sent", timestamp=timestamp, read_status=read_status
            ),
            message_id=message_id,
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

    def add_sent_image(self, image_bytes, timestamp=None, message_id=None, read_status=None):
        """
        Display a sent image (Phase 8 -- File & Image Transfer). See
        add_sent_message() for ``message_id``/``read_status`` (C2 --
        Read Receipts).
        """

        self._add_bubble(
            ImageMessageBubble(
                image_bytes, kind="sent", timestamp=timestamp, read_status=read_status
            ),
            message_id=message_id,
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

    def add_sent_file(
        self, file_bytes, content_metadata, timestamp=None, message_id=None, read_status=None
    ):
        """
        Display a sent file (Phase 8 -- File & Image Transfer). See
        add_sent_message() for ``message_id``/``read_status`` (C2 --
        Read Receipts).
        """

        self._add_bubble(
            FileMessageBubble(
                file_bytes,
                content_metadata,
                kind="sent",
                timestamp=timestamp,
                read_status=read_status,
            ),
            message_id=message_id,
        )

    def mark_all_sent_read(self):
        """
        Flip every currently-tracked sent bubble in this conversation
        to the "read" check-mark state (C2 -- Read Receipts).

        Correct, not an approximation, given this app's conversation-
        level "read up to now" semantics (server/client_handler.py::
        handle_read_receipt() marks every one of the reader's unread
        MessageRecipient rows in the conversation at once, not a
        single message) -- when a read_receipt_notification arrives
        for a direct conversation, the one other party has, by
        definition, just read every message they could see; for a
        group, the caller (gui/chat_window.py) only calls this once
        every currently-active recipient has been accounted for.
        Covers every sent bubble in the conversation, including one
        sent live this session that has no database id on this client
        (BUG 2 -- such bubbles used to be skipped, so a sender watching
        the conversation saw nothing until a logout/login re-rendered
        them from history).
        """

        for bubble in self._sent_bubbles_by_message_id.values():
            bubble.set_read_status(True)

    def clear_messages(self):
        """
        Remove every message.
        """

        self.clear()

        self._sent_bubbles_by_message_id = {}

        self._live_bubble_sequence = 0