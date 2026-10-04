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

from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QVBoxLayout,
    QWidget,
)

from gui.message_widget import to_local_time
from gui.styles import (
    COLOR_ACCENT,
    COLOR_ONLINE,
    COLOR_TEXT_MUTED,
    COLOR_UNREAD,
    LIST_ITEM_VERTICAL_MARGIN,
)


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

        # Phase 19.24 -- Mute: kept so contextMenuEvent() below can
        # address the right conversation, and re-verified against
        # ConversationStore's own key rather than anything cached
        # (mirrors gui/message_widget.py's bubble.on_context_action
        # callback pattern exactly).
        self.summary = summary
        self.on_context_action = None

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
        # L-1: every label in this row renders a display name, a
        # group name or a message preview -- all of it written by
        # other users and none of it markup.
        avatar.setTextFormat(Qt.PlainText)
        avatar.setFixedSize(34, 34)
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: #FFFFFF; "
            "border-radius: 17px; font-weight: 700;"
        )

        name = QLabel(display_name)
        name.setTextFormat(Qt.PlainText)
        name.setStyleSheet("font-size: 10.5pt; font-weight: 500;")

        # Phase 19.24 -- Mute: a small, always-present-but-hidden glyph,
        # same "zero-footprint until relevant" convention as the unread
        # badge below. Local UI preference only -- never part of
        # ConversationSummary, see set_muted()'s own docstring.
        self.mute_icon = QLabel("🔕")
        self.mute_icon.setTextFormat(Qt.PlainText)
        self.mute_icon.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;")
        self.mute_icon.setVisible(False)

        # BUG -- Timestamp/Timezone: summary.latest_message.timestamp
        # is naive UTC (ConversationStore.record_message()'s callers
        # both pass a UTC value). Converted to local time before
        # formatting -- see gui/message_widget.py::to_local_time() for
        # why, and gui/chat_window.py::load_history() for the
        # transcript-side fix this mirrors.
        timestamp_text = ""

        if summary.latest_message and summary.latest_message.timestamp:
            timestamp_text = to_local_time(
                summary.latest_message.timestamp
            ).strftime("%H:%M")

        timestamp = QLabel(timestamp_text)
        timestamp.setTextFormat(Qt.PlainText)
        timestamp.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 8.5pt;")

        self.unread_badge = QLabel("")
        self.unread_badge.setTextFormat(Qt.PlainText)
        self.unread_badge.setFixedHeight(20)
        self.unread_badge.setAlignment(Qt.AlignCenter)
        self.unread_badge.setStyleSheet(
            f"background-color: {COLOR_UNREAD}; color: #FFFFFF; "
            "border-radius: 10px; font-size: 8.5pt; font-weight: 700; "
            "padding: 0px 7px;"
        )
        self.unread_badge.setVisible(False)

        # Phase 19.24 -- Mute: the badge's real count is always tracked
        # (get_unread_count() elsewhere stays honest), but its VISUAL
        # display is suppressed while muted -- "affects notifications,
        # not delivery" applied to the one notification surface this
        # desktop client actually has (there is no OS toast/sound
        # system in this codebase to suppress).
        self._muted = False
        self._last_count = 0
        # Phase 19.24 -- Archive: no dedicated icon (the row's presence
        # in the Archived-filtered list already communicates this),
        # tracked only so contextMenuEvent() below offers the correct
        # Archive/Unarchive label.
        self._archived = False

        # Phase 19.24 -- Block User: no dedicated icon either (Block/
        # Unblock is directional and security-relevant, not a local
        # preference like Mute/Archive -- there is no ambiguity for
        # the label to resolve visually, only for the menu text).
        # Only ever offered for a direct conversation -- see
        # contextMenuEvent()'s own guard.
        self._blocked = False

        dot_color = COLOR_ONLINE if summary.is_online else COLOR_TEXT_MUTED

        dot = QLabel("●")
        dot.setTextFormat(Qt.PlainText)
        dot.setStyleSheet(f"color: {dot_color}; font-size: 9pt;")

        top_row.addWidget(avatar)
        top_row.addWidget(name, stretch=1)
        top_row.addWidget(self.mute_icon)
        top_row.addWidget(timestamp)
        top_row.addWidget(self.unread_badge)
        top_row.addWidget(dot)

        preview_text = (
            summary.latest_message.render()
            if summary.latest_message
            else "No messages yet"
        )

        preview = QLabel(preview_text)
        preview.setTextFormat(Qt.PlainText)
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

        self._last_count = count
        self._refresh_badge()

    def set_muted(self, muted):
        """
        Show or hide the muted indicator, and re-apply the unread
        badge's visibility accordingly (Phase 19.24 -- Mute). Mirrors
        set_unread_count()'s own docstring: a narrow, presentation-only
        exception, not a channel for the GUI to mutate conversation
        metadata -- mute state lives in storage/secure_key_store.py,
        never in ConversationSummary/ConversationStore.
        """

        self._muted = muted
        self.mute_icon.setVisible(muted)
        self._refresh_badge()

    def _refresh_badge(self):
        if self._last_count > 0 and not self._muted:
            self.unread_badge.setText(str(self._last_count))
            self.unread_badge.setVisible(True)
        else:
            self.unread_badge.setVisible(False)

    def set_archived(self, archived):
        """Phase 19.24 -- Archive: tracked only so contextMenuEvent()
        offers the correct Archive/Unarchive label -- see this
        attribute's own __init__ comment for why no visible indicator
        is needed beyond the row's list membership itself."""

        self._archived = archived

    def set_blocked(self, blocked):
        """Phase 19.24 -- Block User: tracked only so contextMenuEvent()
        offers the correct Block/Unblock label."""

        self._blocked = blocked

    # ==========================================================
    # Events
    # ==========================================================

    def contextMenuEvent(self, event):
        """
        Phase 19.24 -- Mute: right-click a conversation row for Mute
        (with duration options) or Unmute, mirroring gui/message_
        widget.py's identical on_context_action callback pattern --
        the row builds and shows the menu, the CALLER (ConversationList
        Widget, then ChatWindow) decides what the chosen action means.
        """

        if self.on_context_action is None:
            return

        menu = QMenu(self)

        if self._muted:
            menu.addAction("Unmute").setData("unmute")
        else:
            mute_menu = menu.addMenu("Mute")
            mute_menu.addAction("For 1 hour").setData("mute_1h")
            mute_menu.addAction("For 8 hours").setData("mute_8h")
            mute_menu.addAction("For 1 week").setData("mute_1w")
            mute_menu.addAction("Until I turn it back on").setData("mute_forever")

        # Phase 19.24 -- Archive: retains history, purely a "don't show
        # in the main list" local preference -- see gui/chat_window.py
        # ::render_conversations()'s own filtering comment.
        if self._archived:
            menu.addAction("Unarchive").setData("unarchive")
        else:
            menu.addAction("Archive").setData("archive")

        # Phase 19.24 -- Block User: only meaningful for a direct
        # conversation -- summary.key is a username there (what
        # ClientSession.block_user() needs); for a group it is a
        # conversation_id, and blocking a "conversation" rather than a
        # person has no meaning (see database/models/blocked_user.py's
        # own docstring on groups being unaffected by 1:1 blocks).
        if not self.summary.is_group:
            if self._blocked:
                menu.addAction("Unblock").setData("unblock")
            else:
                menu.addAction("Block").setData("block")

        chosen = menu.exec(event.globalPos())

        if chosen is None:
            return

        self.on_context_action(chosen.data(), self.summary)


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

    # Phase 19.24 -- Mute: (summary, action) where action is "unmute" or
    # "mute_1h"/"mute_8h"/"mute_1w"/"mute_forever" -- bubbled up exactly
    # like conversation_selected above, since only ChatWindow (which
    # owns self.session) can actually act on it.
    mute_action_requested = Signal(object, str)

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
            row.on_context_action = self._on_row_context_action

            # gui/styles.py's global QListWidget::item margin carves
            # LIST_ITEM_VERTICAL_MARGIN out of the same rect this row
            # widget is given on top of its own sizeHint() -- without
            # adding it back, the row is silently granted less height
            # than it asked for, which can crop a descender (e.g. the
            # tail of a lowercase "y") out of the preview text. See
            # LIST_ITEM_VERTICAL_MARGIN's docstring in gui/styles.py.
            row_hint = row.sizeHint()
            item.setSizeHint(
                QSize(row_hint.width(), row_hint.height() + LIST_ITEM_VERTICAL_MARGIN)
            )

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

    def set_muted(self, key, muted):
        """
        Update the muted indicator for a single row in place. See
        ConversationRow.set_muted()'s docstring -- same narrow,
        presentation-only exception to render()-only updates as
        set_unread_count() above.
        """

        for i in range(self.count()):

            item = self.item(i)

            summary = item.data(Qt.UserRole)

            if summary is not None and summary.key == key:

                row = self.itemWidget(item)

                if row is not None:
                    row.set_muted(muted)

                break

    def set_archived(self, key, archived):
        """Update the archived state for a single row in place -- see
        ConversationRow.set_archived()'s own docstring for why this
        carries no visible effect beyond the context menu's label."""

        for i in range(self.count()):

            item = self.item(i)

            summary = item.data(Qt.UserRole)

            if summary is not None and summary.key == key:

                row = self.itemWidget(item)

                if row is not None:
                    row.set_archived(archived)

                break

    def set_blocked(self, key, blocked):
        """Update the blocked state for a single row in place -- see
        ConversationRow.set_blocked()'s own docstring."""

        for i in range(self.count()):

            item = self.item(i)

            summary = item.data(Qt.UserRole)

            if summary is not None and summary.key == key:

                row = self.itemWidget(item)

                if row is not None:
                    row.set_blocked(blocked)

                break

    # ==========================================================
    # Events
    # ==========================================================

    def _on_item_clicked(self, item):

        summary = item.data(Qt.UserRole)

        if summary is not None:
            self.conversation_selected.emit(summary)

    def _on_row_context_action(self, action, summary):
        """Phase 19.24 -- Mute: ConversationRow.on_context_action's
        target, re-emitted as mute_action_requested for ChatWindow to
        actually act on (it owns self.session; this widget never
        touches session/storage directly)."""

        self.mute_action_requested.emit(summary, action)

    # ==========================================================
    # Helpers
    # ==========================================================

    @staticmethod
    def _muted_color():

        from PySide6.QtGui import QColor

        return QColor(COLOR_TEXT_MUTED)
