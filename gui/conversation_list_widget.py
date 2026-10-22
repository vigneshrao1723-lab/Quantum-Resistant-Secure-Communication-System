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
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from gui.avatar import AvatarWidget
from gui.icons import toolbar_icon
from gui.message_widget import to_local_time
from gui.styles import (
    COLOR_ON_ACCENT,
    COLOR_TEXT,
    COLOR_TEXT_MUTED,
    COLOR_UNREAD,
    LIST_ITEM_VERTICAL_MARGIN,
)


class ElidedLabel(QLabel):
    """A QLabel that shows one line and ends it with an ellipsis when it does
    not fit, instead of forcing its parent wider. ``text()`` still returns the
    full text -- only what is painted is shortened."""

    def __init__(self, text=""):
        super().__init__(text)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)

    def minimumSizeHint(self):
        return QSize(0, super().minimumSizeHint().height())

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setPen(self.palette().windowText().color())
        painter.setFont(self.font())
        elided = self.fontMetrics().elidedText(self.text(), Qt.ElideRight, self.width())
        painter.drawText(self.rect(), int(self.alignment()) | Qt.AlignVCenter, elided)
        painter.end()


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

    def __init__(self, summary, name_for=None, show_handle=True):
        super().__init__()

        # Phase 19.24 -- Mute: kept so contextMenuEvent() below can
        # address the right conversation, and re-verified against
        # ConversationStore's own key rather than anything cached
        # (mirrors gui/message_widget.py's bubble.on_context_action
        # callback pattern exactly).
        self.summary = summary
        self.on_context_action = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(12)

        # Phase 4 (Secure Group Messaging Foundation): the only branch
        # in this class -- which display name to use. Everything else
        # below (avatar, timestamp, badge, preview) is unchanged,
        # unbranched code, exactly as anticipated when this class was
        # written in Phase 2.
        # A person is SHOWN by their display name, which is not unique; summary.username (the
        # account handle) stays the row's identity and is shown, muted, beside the name when it
        # differs, so two people who chose the same name can still be told apart.
        handle = None if summary.is_group else summary.username
        display_name = summary.group_name if summary.is_group else ((name_for or str)(handle) or handle)
        # The handle is shown beside the name only where it is needed to tell two people apart (the
        # Website does the same); everywhere else the name gets the whole line.
        handle_text = f"@{handle}" if handle and display_name != handle and show_handle else ""

        # Presence is a property of a person, not of a group.
        avatar = AvatarWidget(
            display_name,
            size=44,
            online=None if summary.is_group else bool(summary.is_online),
            is_group=summary.is_group,
        )

        # L-1: every label in this row renders a display name, a
        # group name or a message preview -- all of it written by
        # other users and none of it markup.
        name = ElidedLabel(display_name)
        name.setTextFormat(Qt.PlainText)
        name.setStyleSheet(
            f"font-size: 10.5pt; font-weight: 600; color: {COLOR_TEXT}; background: transparent;"
        )

        self.handle_label = QLabel(handle_text)
        self.handle_label.setTextFormat(Qt.PlainText)
        self.handle_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 8.5pt; background: transparent;"
        )
        self.handle_label.setVisible(bool(handle_text))

        # Phase 19.24 -- Mute: a small, always-present-but-hidden glyph,
        # same "zero-footprint until relevant" convention as the unread
        # badge below. Local UI preference only -- never part of
        # ConversationSummary, see set_muted()'s own docstring.
        self.mute_icon = QLabel()
        self.mute_icon.setTextFormat(Qt.PlainText)
        self.mute_icon.setPixmap(toolbar_icon("mute").pixmap(QSize(14, 14)))
        self.mute_icon.setToolTip("Muted")
        self.mute_icon.setStyleSheet("background: transparent;")
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
        timestamp.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 8.5pt; background: transparent;"
        )

        self.unread_badge = QLabel("")
        self.unread_badge.setTextFormat(Qt.PlainText)
        self.unread_badge.setFixedHeight(20)
        self.unread_badge.setMinimumWidth(20)
        self.unread_badge.setAlignment(Qt.AlignCenter)
        self.unread_badge.setStyleSheet(
            f"background-color: {COLOR_UNREAD}; color: {COLOR_ON_ACCENT}; "
            "border-radius: 10px; font-size: 8.5pt; font-weight: 700; "
            "padding: 0px 6px;"
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

        preview_text = (
            summary.latest_message.render()
            if summary.latest_message
            else "No messages yet"
        )

        self._accessible_name = ("Group " if summary.is_group else "") + display_name + (
            f" ({handle_text})" if handle_text else ""
        )
        self._accessible_preview = preview_text

        preview = ElidedLabel(preview_text)
        preview.setTextFormat(Qt.PlainText)
        preview.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt; background: transparent;"
        )

        title_row = QHBoxLayout()
        title_row.setSpacing(6)
        title_row.addWidget(name, stretch=1)
        title_row.addWidget(self.handle_label)
        title_row.addWidget(self.mute_icon)
        title_row.addWidget(timestamp)

        preview_row = QHBoxLayout()
        preview_row.setSpacing(6)
        preview_row.addWidget(preview, stretch=1)
        preview_row.addWidget(self.unread_badge)

        text_column = QVBoxLayout()
        text_column.setSpacing(3)
        text_column.addLayout(title_row)
        text_column.addLayout(preview_row)

        layout.addWidget(avatar, 0, Qt.AlignVCenter)
        layout.addLayout(text_column, stretch=1)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def accessible_summary(self):
        """Plain-text description of this row for assistive technology: a row is a
        setItemWidget() widget, which screen readers cannot look inside."""

        parts = [self._accessible_name, self._accessible_preview]

        if self._last_count > 0:
            parts.append(f"{self._last_count} unread")

        return ", ".join(part for part in parts if part)

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

        # handle -> name to show; ChatWindow supplies the session's display-name cache.
        self.name_for = None

        # Rows elide their own text; a row that is a few px wider than the
        # viewport must not summon a horizontal scrollbar.
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.itemClicked.connect(self._on_item_clicked)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def _is_namesake(self, summary, summaries):
        """True when another person in the list is shown under the same display name."""

        if summary.is_group:
            return False
        lookup = self.name_for or str
        shown = lookup(summary.username) or summary.username
        return sum(
            1 for other in summaries
            if not other.is_group and (lookup(other.username) or other.username) == shown
        ) > 1

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

            row = ConversationRow(summary, self.name_for, show_handle=self._is_namesake(summary, summaries))
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
            item.setData(Qt.AccessibleTextRole, row.accessible_summary())

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
                    item.setData(Qt.AccessibleTextRole, row.accessible_summary())

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
