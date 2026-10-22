"""
Chat settings (details) window for the open conversation.

One place for everything that is about THIS chat rather than the whole account:

* who it is with -- the contact's picture (select it to see it enlarged), display name, handle,
  bio and presence;
* its security -- the verification status with a Verify / Re-verify action (the safety-number
  comparison itself, with your own number behind "Show my safety number", is in the Verify window)
  and the encryption in use;
* the chat's tools -- search, pinned messages, media, wallpaper, mute, archive, block;
* for a group -- its members and roles, and the actions the person's role allows: only the group
  admin sees "Add members", every member can leave.

Verification status and essential group controls are also visible in the chat header; this window
adds detail, it does not hide anything the header needs to show. Nothing private about the
contact is shown beyond what their profile already shares (picture, name, handle, bio).

The window decides nothing itself: every button runs the ChatWindow handler that already existed.
Tools that open their own window/menu run after this one closes (``chosen``).
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from client.session import PEER_KEY_STATE_CHANGED
from gui.avatar import AvatarButton
from gui.icons import toolbar_icon
from gui.styles import (
    COLOR_CLASSICAL,
    COLOR_DANGER,
    COLOR_ONLINE,
    COLOR_QUANTUM,
    COLOR_TEXT,
    COLOR_TEXT_MUTED,
)
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED


def _section_title(text):
    label = QLabel(text)
    label.setTextFormat(Qt.PlainText)
    label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9pt; font-weight: 700;")
    return label


class ChatDetailsDialog(QDialog):

    def __init__(self, window, parent=None):
        super().__init__(parent or window)

        self.window_ = window
        self.session = window.session
        self.is_group = bool(self.session.current_chat_is_group)
        self.peer = None if self.is_group else window._current_direct_peer_username
        self.key = self.session.get_current_chat()
        # The store's summary is the current one (members, admin); the opened summary is the
        # fallback for a chat the store has no row for yet (a contact just found by search).
        self.summary = (
            (self.session.conversation_store.get(self.key) if self.key else None)
            or getattr(window, "_current_summary", None)
        )

        # Set by a tool button; ChatWindow runs it once this window has closed.
        self.chosen = None

        self.setWindowTitle("Chat settings")
        self.setMinimumWidth(400)

        self._build_ui()

    # ------------------------------------------------------------------ helpers

    def _name_of(self, handle):
        return self.window_.name_for(handle)

    def _action_button(self, text, icon_name, handler, danger=False, close_first=True, accessible=None):
        button = QPushButton(text)
        button.setObjectName("HeaderDangerButton" if danger else "SecondaryButton")
        button.setCursor(Qt.PointingHandCursor)
        button.setIcon(
            toolbar_icon(icon_name, color=COLOR_DANGER, active_color=COLOR_DANGER) if danger
            else toolbar_icon(icon_name)
        )
        if accessible:
            button.setAccessibleName(accessible)
        if close_first:
            def run(_checked=False):
                self.chosen = handler
                self.accept()
        else:
            def run(_checked=False):
                handler()
                self.refresh()
        button.clicked.connect(run)
        return button

    def _card(self):
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)
        return card, layout

    # ------------------------------------------------------------------ UI

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 18, 20, 16)
        outer.setSpacing(12)

        title = QLabel("Chat settings")
        title.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14pt; font-weight: 700;")
        outer.addWidget(title)

        body = QWidget()
        body.setObjectName("ChatSettingsBody")
        body.setStyleSheet("QWidget#ChatSettingsBody { background: transparent; }")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 6, 0)
        body_layout.setSpacing(12)

        body_layout.addWidget(self._build_profile_card())
        body_layout.addWidget(self._build_security_card())
        if self.is_group:
            body_layout.addWidget(self._build_group_card())
        body_layout.addWidget(self._build_tools_card())
        body_layout.addStretch()

        scroll = QScrollArea()
        scroll.setObjectName("ChatSettingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea#ChatSettingsScroll { background: transparent; border: none; }"
            "QScrollArea#ChatSettingsScroll > QWidget > QWidget { background: transparent; }"
        )
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.setMinimumWidth(110)
        close_button.clicked.connect(self.reject)
        close_row.addWidget(close_button)
        outer.addLayout(close_row)

        self.resize(440, 640)

    # -- profile

    def _build_profile_card(self):
        card, layout = self._card()
        row = QHBoxLayout()
        row.setSpacing(14)

        shown = (self.summary.group_name if (self.is_group and self.summary) else self._name_of(self.peer)) or ""
        self.avatar_button = AvatarButton(
            shown, size=72,
            accessible_name=("Group" if self.is_group else "Contact's profile picture. Open to view it enlarged."),
        )
        if self.is_group:
            self.avatar_button.set_name(shown, is_group=True)
            self.avatar_button.setCursor(Qt.ArrowCursor)
            self.avatar_button.setFocusPolicy(Qt.NoFocus)
        else:
            self.avatar_button.setToolTip("View profile picture")
            self.avatar_button.clicked.connect(self._open_picture)
            try:
                data = self.session.fetch_profile_picture(self.peer)
            except Exception:  # noqa: BLE001
                data = None
            if data:
                self.avatar_button.set_picture_bytes(data)
        row.addWidget(self.avatar_button, 0, Qt.AlignTop)

        column = QVBoxLayout()
        column.setSpacing(2)
        self.name_label = QLabel(shown)
        self.name_label.setTextFormat(Qt.PlainText)
        self.name_label.setWordWrap(True)
        self.name_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 13pt; font-weight: 700;")
        column.addWidget(self.name_label)

        if self.is_group:
            count = len(self.summary.participants or []) if self.summary else 0
            sub = f"Group · {count} member{'s' if count != 1 else ''}"
        else:
            sub = f"@{self.peer}"
        self.sub_label = QLabel(sub)
        self.sub_label.setTextFormat(Qt.PlainText)
        self.sub_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;")
        column.addWidget(self.sub_label)

        self.presence_label = QLabel("" if self.is_group else self.window_.presence_label.text())
        self.presence_label.setTextFormat(Qt.PlainText)
        self.presence_label.setStyleSheet(f"color: {COLOR_ONLINE}; font-size: 9pt;")
        self.presence_label.setVisible(bool(self.presence_label.text()))
        column.addWidget(self.presence_label)

        row.addLayout(column, 1)
        layout.addLayout(row)

        self.bio_label = QLabel("")
        self.bio_label.setTextFormat(Qt.PlainText)
        self.bio_label.setWordWrap(True)
        self.bio_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 10pt;")
        self.bio_label.setVisible(False)
        if not self.is_group:
            try:
                bio = self.session.fetch_bio(self.peer)
            except Exception:  # noqa: BLE001
                bio = ""
            if bio:
                self.bio_label.setText(bio)
                self.bio_label.setVisible(True)
        layout.addWidget(self.bio_label)
        return card

    def _open_picture(self):
        self.window_.handle_view_peer_profile()

    # -- security

    def _build_security_card(self):
        card, layout = self._card()
        layout.addWidget(_section_title("SECURITY"))

        self.status_label = QLabel("")
        self.status_label.setTextFormat(Qt.PlainText)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.verify_button = self._action_button(
            "Verify identity", "shield", self.window_.handle_verify_identity, close_first=False
        )
        self.request_button = self._action_button(
            "Request approval", "profile", self.window_.handle_request_verification, close_first=False
        )
        buttons.addWidget(self.verify_button)
        buttons.addWidget(self.request_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        algorithm = ""
        try:
            algorithm = (self.session.key_manager.algorithm or "").upper()
        except Exception:  # noqa: BLE001
            algorithm = ""
        if algorithm == "KYBER":
            encryption = "Encryption: Kyber (post-quantum)"
            color = COLOR_QUANTUM
        elif algorithm == "RSA":
            encryption = "Encryption: RSA (classical)"
            color = COLOR_CLASSICAL
        else:
            encryption = f"Encryption: {algorithm or 'not yet known'}"
            color = COLOR_TEXT_MUTED
        self.encryption_label = QLabel(encryption)
        self.encryption_label.setTextFormat(Qt.PlainText)
        self.encryption_label.setStyleSheet(f"color: {color}; font-size: 9.5pt; font-weight: 600;")
        layout.addWidget(self.encryption_label)

        note = QLabel("Messages in this chat are end-to-end encrypted.")
        note.setTextFormat(Qt.PlainText)
        note.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;")
        layout.addWidget(note)

        if self.is_group:
            self.status_label.setText(
                "Each member's identity is verified when they receive the group key."
            )
            self.status_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;")
            self.verify_button.setVisible(False)
            self.request_button.setVisible(False)
        else:
            self.refresh()
        return card

    def refresh(self):
        """Re-read the verification state (after the Verify window closed, say)."""

        if self.is_group or self.peer is None:
            return

        state = self.session.get_peer_verification_state(self.peer)
        name = self._name_of(self.peer)

        if state == PEER_STATE_VERIFIED:
            self.status_label.setText(f"✓ Verified -- {name}'s identity matches what you compared.")
            self.status_label.setStyleSheet(f"color: {COLOR_ONLINE}; font-size: 10pt; font-weight: 700;")
            self.verify_button.setText("Re-verify")
            self.verify_button.setVisible(True)
            self.request_button.setVisible(False)
        elif state == PEER_KEY_STATE_CHANGED:
            self.status_label.setText(
                f"⚠ {name}'s identity changed. Protected messages are blocked until you verify the new one."
            )
            self.status_label.setStyleSheet(f"color: {COLOR_DANGER}; font-size: 10pt; font-weight: 700;")
            self.verify_button.setText("Verify new identity")
            self.verify_button.setVisible(True)
            self.request_button.setVisible(True)
        elif state == PEER_STATE_UNVERIFIED:
            self.status_label.setText(f"Not verified -- compare safety numbers with {name} to confirm who they are.")
            self.status_label.setStyleSheet(f"color: {COLOR_CLASSICAL}; font-size: 10pt; font-weight: 700;")
            self.verify_button.setText("Verify identity")
            self.verify_button.setVisible(True)
            self.request_button.setVisible(True)
        else:
            self.status_label.setText("No identity has been received for this contact yet.")
            self.status_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 10pt;")
            self.verify_button.setVisible(False)
            self.request_button.setVisible(False)

    # -- group

    def _build_group_card(self):
        card, layout = self._card()
        layout.addWidget(_section_title("MEMBERS"))

        own = self.session.get_username()
        admin = self.summary.admin if self.summary else None
        self.is_admin = bool(admin and admin == own)

        members = sorted(set(self.summary.participants or []) | {own}) if self.summary else [own]
        self.member_labels = []
        for handle in members:
            name = self._name_of(handle)
            text = name if name == handle else f"{name}  (@{handle})"
            if handle == admin:
                text += "  ·  admin"
            if handle == own:
                text += "  ·  you"
            label = QLabel(text)
            label.setTextFormat(Qt.PlainText)
            label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 10pt;")
            layout.addWidget(label)
            self.member_labels.append(label)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        # The admin adds directly; any other member can ask (the request goes to the admin's Inbox
        # for approval -- the server decides, whatever this window offers).
        self.add_members_button = self._action_button(
            "Add members" if self.is_admin else "Request to add a member", "group", self.window_.handle_add_members
        )
        self.group_info_button = self._action_button("Members and roles", "info", self.window_.handle_open_group_info)
        buttons.addWidget(self.add_members_button)
        buttons.addWidget(self.group_info_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        return card

    # -- tools

    def _build_tools_card(self):
        card, layout = self._card()
        layout.addWidget(_section_title("THIS CHAT"))

        window = self.window_
        key = self.key

        def tool(text, icon, handler, **kwargs):
            button = self._action_button(text, icon, handler, **kwargs)
            layout.addWidget(button)
            return button

        self.search_button = tool("Search in conversation", "search", window.handle_toggle_search_bar)
        self.pinned_button = tool("Pinned messages", "pin", window.handle_open_pinned_messages_panel)
        self.gallery_button = tool("Media gallery", "gallery", window.handle_open_media_gallery)
        self.wallpaper_button = tool("Chat wallpaper", "wallpaper", window.handle_open_wallpaper_picker)

        summary = self.summary
        muted = bool(key and self.session.is_conversation_muted(key))
        if muted:
            self.mute_button = tool(
                "Unmute notifications", "mute",
                lambda: window._handle_mute_action(summary, "unmute"),
            )
        else:
            self.mute_button = tool("Mute notifications…", "mute", self._choose_mute_duration)

        archived = bool(key and self.session.is_conversation_archived(key))
        self.archive_button = tool(
            "Unarchive chat" if archived else "Archive chat", "archive",
            lambda: window._handle_mute_action(summary, "unarchive" if archived else "archive"),
        )

        if self.is_group:
            self.leave_button = tool("Leave group", "close", window.handle_leave_group, danger=True)
        else:
            blocked = bool(self.session.is_user_blocked(self.peer))
            self.block_button = tool(
                "Unblock" if blocked else "Block", "close",
                lambda: window._handle_mute_action(summary, "unblock" if blocked else "block"),
                danger=not blocked,
            )
        return card

    def _choose_mute_duration(self):
        """A small duration menu (the choice runs after this window has closed)."""

        from PySide6.QtWidgets import QMenu

        menu = QMenu(self.window_)
        for label, action in (
            ("For 1 hour", "mute_1h"), ("For 8 hours", "mute_8h"),
            ("For 1 week", "mute_1w"), ("Until I turn it back on", "mute_forever"),
        ):
            menu.addAction(label).setData(action)
        chosen = menu.exec(self.window_.mapToGlobal(self.window_.rect().center()))
        if chosen is not None:
            self.window_._handle_mute_action(self.summary, chosen.data())
