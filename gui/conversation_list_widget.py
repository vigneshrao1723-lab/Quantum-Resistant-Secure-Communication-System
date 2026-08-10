"""
Conversation List Widget

Sidebar rendering for the conversation-centric chat window (Phase 2:
Conversation List Foundation). Purely a renderer: every row reflects
whatever ConversationStore last reported via conversations_changed
(see client/conversation_store.py) -- this widget never computes or
caches conversation state of its own, only the Qt widgets needed to
paint what it was given. render() is the single entry point that
populates it; there is no partial-update API for conversation data,
so this widget cannot drift from ConversationStore.

gui/online_users_widget.py is left in place, unused, for this phase
(rollback safety) rather than deleted.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.styles import COLOR_ACCENT, COLOR_OFFLINE, COLOR_ONLINE, COLOR_TEXT_MUTED


class ConversationRow(QWidget):
    """
    A single sidebar row for one conversation: an avatar-initial
    placeholder, the partner's name, an online/offline dot, the
    latest message preview, its timestamp, and an unread badge.

    Designed to display group/media conversations later without a
    rewrite: the avatar becomes a real image or group icon, the name
    becomes a group name, and the preview line already renders
    whatever ConversationSummary.latest_message.render() produces
    (payload-independent -- see domain/conversation_summary.py) --
    none of that requires touching this class's structure.
    """

    def __init__(self, summary):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(2)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        # Phase 4 (Secure Group Messaging Foundation): the only branch
        # in this class -- which display name to use. Everything else
        # below (avatar, timestamp, badge, preview) is unchanged,
        # unbranched code, exactly as anticipated when this class was
        # written in Phase 2.
        display_name = summary.group_name if summary.is_group else summary.username

        initial = display_name[0].upper() if display_name else "?"

        avatar = QLabel(initial)
        avatar.setFixedSize(34, 34)
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: #0B0D16; "
            "border-radius: 17px; font-weight: 700;"
        )

        name = QLabel(display_name)
        name.setStyleSheet("font-size: 10.5pt; font-weight: 500;")

        timestamp_text = ""

        if summary.latest_message and summary.latest_message.timestamp:
            timestamp_text = summary.latest_message.timestamp.strftime("%H:%M")

        timestamp = QLabel(timestamp_text)
        timestamp.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 8.5pt;")

        self.unread_badge = QLabel("")
        self.unread_badge.setFixedHeight(20)
        self.unread_badge.setAlignment(Qt.AlignCenter)
        self.unread_badge.setStyleSheet(
            f"background-color: {COLOR_OFFLINE}; color: #0B0D16; "
            "border-radius: 10px; font-size: 8.5pt; font-weight: 700; "
            "padding: 0px 7px;"
        )
        self.unread_badge.setVisible(False)

        dot_color = COLOR_ONLINE if summary.is_online else COLOR_TEXT_MUTED

        dot = QLabel("●")
        dot.setStyleSheet(f"color: {dot_color}; font-size: 9pt;")

        top_row.addWidget(avatar)
        top_row.addWidget(name, stretch=1)
        top_row.addWidget(timestamp)
        top_row.addWidget(self.unread_badge)
        top_row.addWidget(dot)

        preview_text = (
            summary.latest_message.render()
            if summary.latest_message
            else "No messages yet"
        )

        preview = QLabel(preview_text)
        preview.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;")

        layout.addLayout(top_row)
        layout.addWidget(preview)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def set_unread_count(self, count):
        """
        Show or hide the unread badge for this row. Unread counts are
        intentionally not part of ConversationSummary/ConversationStore
        (Phase 2 reuses the existing, pre-Phase-2 mechanism in
        ClientSession unmodified rather than reimplementing it) -- this
        is a narrow, presentation-only exception, not a channel for the
        GUI to mutate conversation metadata.
        """

        if count > 0:
            self.unread_badge.setText(str(count))
            self.unread_badge.setVisible(True)
        else:
            self.unread_badge.setVisible(False)


class ConversationListWidget(QListWidget):
    """
    Renders the conversation sidebar from a list of ConversationSummary
    objects supplied by ConversationStore. Emits conversation_selected
    with the selected row's whole ConversationSummary -- widened from a
    bare username in Phase 2 to the full object in Phase 4 (Secure
    Group Messaging Foundation), the exact seam Phase 2 documented,
    since a group has no single username to identify it by.
    ConversationSummary.key is the addressing identity either way.
    """

    conversation_selected = Signal(object)

    def __init__(self):
        super().__init__()

        self.setSpacing(4)

        self.itemClicked.connect(self._on_item_clicked)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def render(self, summaries):
        """
        Fully rebuild the list from the given summaries, which are
        already ordered by latest activity (ConversationStore.get_all()).
        This is the only method that populates conversation data --
        there is no separate "update a row" entry point, so the widget
        cannot hold state ConversationStore doesn't know about.
        """

        current = self.currentItem()

        current_key = (
            current.data(Qt.UserRole).key
            if current is not None and current.data(Qt.UserRole) is not None
            else None
        )

        self.clear()

        if not summaries:

            placeholder = QListWidgetItem("No conversations yet")
            placeholder.setFlags(Qt.NoItemFlags)
            placeholder.setForeground(self._muted_color())
            self.addItem(placeholder)
            return

        for summary in summaries:

            item = QListWidgetItem()
            item.setData(Qt.UserRole, summary)

            self.addItem(item)

            row = ConversationRow(summary)

            item.setSizeHint(row.sizeHint())

            self.setItemWidget(item, row)

            if summary.key == current_key:
                self.setCurrentItem(item)

    def set_unread_count(self, key, count):
        """
        Update the unread badge for a single row in place. See
        ConversationRow.set_unread_count()'s docstring for why unread
        counts are the one narrow exception to render()-only updates.
        """

        for i in range(self.count()):

            item = self.item(i)

            summary = item.data(Qt.UserRole)

            if summary is not None and summary.key == key:

                row = self.itemWidget(item)

                if row is not None:
                    row.set_unread_count(count)

                break

    # ==========================================================
    # Events
    # ==========================================================

    def _on_item_clicked(self, item):

        summary = item.data(Qt.UserRole)

        if summary is not None:
            self.conversation_selected.emit(summary)

    # ==========================================================
    # Helpers
    # ==========================================================

    @staticmethod
    def _muted_color():

        from PySide6.QtGui import QColor

        return QColor(COLOR_TEXT_MUTED)
