"""
Chat Window

Main chat interface for the Quantum-Resistant
Secure Communication System.
"""

import uuid
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QRectF, QTimer, Signal
from PySide6.QtGui import QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QFrame,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QScrollArea,
    QVBoxLayout,
    QMessageBox,
    QPushButton,
)

from client.session import PEER_KEY_STATE_CHANGED, PeerNotVerifiedError
from domain.conversation_summary import ConversationSummary
from domain.payload_type import PayloadType
from gui.add_members_dialog import AddMembersDialog
from gui.conversation_list_widget import ConversationListWidget
from gui.create_group_dialog import CreateGroupDialog
from gui.find_user_dialog import FindUserDialog
from gui.forward_dialog import ForwardDialog
from gui.account_settings_dialog import AccountSettingsDialog
from gui.device_management_dialog import DeviceManagementDialog
from gui.group_info_dialog import GroupInfoDialog
from gui.inbox_dialog import InboxDialog
from gui.profile_picture_dialog import ProfilePictureDialog
from gui.message_widget import (
    STATUS_DELIVERED, STATUS_FAILED, MessageWidget, to_local_time,
    MessageBubble, ImageMessageBubble, FileMessageBubble,
)
from gui.input_bar import InputBar
from gui.status_bar import StatusBarWidget
from gui.styles import (
    COLOR_ACCENT,
    COLOR_CLASSICAL,
    COLOR_DANGER,
    COLOR_ONLINE,
    COLOR_TEXT_MUTED,
    WALLPAPER_PRESETS,
)
from gui.verify_identity_dialog import VerifyIdentityDialog
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED

# Phase 14.1 -- Security Rejection GUI: safe, human-readable text for
# each ClientSession.security_rejection reason string (domain/
# security_rejection_reason.py's SecurityRejectionReason values --
# compared here as the plain strings the signal itself already carries,
# exactly as that signal's own docstring says a listener should, so
# this module never needs to import the enum just to react to it).
# Deliberately excludes "duplicate_or_stale_key": that reason means an
# already-authenticated, already-trusted sender re-sent something this
# client already has -- informative for logs, but not an attack and
# not something a user needs to be warned about (see ChatWindow.
# handle_security_rejection()'s own docstring). Never includes
# anything from the rejected packet itself (signatures, key material,
# ciphertext) -- only this fixed, hand-written vocabulary.
SECURITY_REJECTION_MESSAGES = {
    "unknown_sender": "it claimed to be from an unknown sender",
    "unverified_sender": "it claimed to be from a sender you have not verified",
    "key_changed": "the sender's identity key has changed and has not been re-verified",
    "missing_signature": "it was missing required authentication",
    "invalid_signature": "it failed authentication",
    "malformed_packet": "it was malformed",
    "wrong_receiver": "it was addressed to the wrong recipient",
    "wrong_conversation": "it targeted the wrong conversation",
    "wrong_algorithm": "it used an unexpected encryption algorithm",
    "invalid_epoch": "it had an invalid key version",
    "decryption_failure": "it could not be processed safely",
    "other_security_rejection": "it failed a security check",
}


class ChatWindow(QWidget):
    """
    Main chat interface.
    """

    logout_requested = Signal()

    def __init__(self, session):
        super().__init__()

        self.session = session

        # C2 -- Read Receipts: usernames who have confirmed reading
        # the currently-open conversation "up to now" since it was
        # opened -- see handle_read_receipt_updated(). Reset every
        # time open_conversation() runs, since bubbles are always
        # re-rendered fresh from history at that point (already
        # reflecting current status), making any prior accumulation
        # stale.
        self._read_receipt_readers = set()

        self.build_ui()

        self.connect_signals()

        self.register_callbacks()

        self.initialize_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        root_layout = QHBoxLayout(self)

        root_layout.setContentsMargins(16, 16, 16, 16)

        root_layout.setSpacing(16)

        # -----------------------------
        # Left Panel
        # -----------------------------

        left_panel = QFrame()

        left_panel.setObjectName("Panel")

        left_layout = QVBoxLayout(left_panel)

        left_layout.setContentsMargins(14, 14, 14, 14)

        users_title = QLabel("CHATS")

        users_title.setObjectName("SectionTitle")

        self.find_user_button = QPushButton("Find User")

        self.find_user_button.setCursor(Qt.PointingHandCursor)

        self.find_user_button.clicked.connect(
            self.handle_find_user
        )

        self.new_group_button = QPushButton("+ Group")

        self.new_group_button.setCursor(Qt.PointingHandCursor)

        self.new_group_button.clicked.connect(
            self.handle_create_group
        )

        self.inbox_button = QPushButton("Inbox")

        self.inbox_button.setCursor(Qt.PointingHandCursor)

        self.inbox_button.clicked.connect(
            self.handle_open_inbox
        )

        self.account_settings_button = QPushButton("Settings")

        self.account_settings_button.setCursor(Qt.PointingHandCursor)

        self.account_settings_button.clicked.connect(
            self.handle_open_account_settings
        )

        self.device_management_button = QPushButton("Devices")

        self.device_management_button.setCursor(Qt.PointingHandCursor)

        self.device_management_button.clicked.connect(
            self.handle_open_device_management
        )

        # Phase 19.24 -- Archive: toggles the sidebar between the main
        # (non-archived) list and the archived one -- render_
        # conversations() is the single place that actually filters by
        # self._show_archived, this button only flips that flag.
        self._show_archived = False

        self.archived_toggle_button = QPushButton("Archived")

        self.archived_toggle_button.setCursor(Qt.PointingHandCursor)

        self.archived_toggle_button.setCheckable(True)

        self.archived_toggle_button.toggled.connect(
            self._handle_archived_toggle
        )

        conversations_header = QHBoxLayout()

        conversations_header.addWidget(users_title)

        conversations_header.addStretch()

        conversations_actions = QGridLayout()
        conversations_actions.setContentsMargins(0, 4, 0, 4)
        conversations_actions.setHorizontalSpacing(6)
        conversations_actions.setVerticalSpacing(6)
        sidebar_actions = (
            self.find_user_button,
            self.new_group_button,
            self.inbox_button,
            self.account_settings_button,
            self.device_management_button,
            self.archived_toggle_button,
        )
        for index, button in enumerate(sidebar_actions):
            button.setObjectName("SidebarToolButton")
            button.setMinimumWidth(0)
            conversations_actions.addWidget(button, index // 3, index % 3)

        self.conversation_list = ConversationListWidget()

        left_layout.addLayout(conversations_header)
        left_layout.addLayout(conversations_actions)

        left_layout.addWidget(self.conversation_list)

        # -----------------------------
        # Right Panel
        # -----------------------------

        right_layout = QVBoxLayout()

        right_layout.setSpacing(12)

        # Header: current chat partner (primary) + app title (secondary)
        #
        # The chat partner's name is what changes on every navigation and
        # is what the user actually needs to confirm at a glance ("am I
        # in the right conversation?") -- it is now the large/bold line.
        # The static app title never changes across the whole session, so
        # it is demoted to a small muted subtitle instead of occupying
        # the header's most prominent slot on every screen.

        header = QFrame()

        header.setObjectName("Panel")

        header_layout = QVBoxLayout(header)

        header_layout.setContentsMargins(18, 12, 18, 12)

        header_layout.setSpacing(2)

        app_title = QLabel("Quantum-Resistant Secure Chat")

        app_title.setStyleSheet(
            f"font-size: 9pt; font-weight: 500; color: {COLOR_TEXT_MUTED};"
        )

        self.add_members_button = QPushButton("Add Members")

        self.add_members_button.setCursor(Qt.PointingHandCursor)

        self.add_members_button.clicked.connect(
            self.handle_add_members
        )

        self.add_members_button.setVisible(False)

        self.group_info_button = QPushButton("Group Info")

        self.group_info_button.setCursor(Qt.PointingHandCursor)

        self.group_info_button.clicked.connect(
            self.handle_open_group_info
        )

        self.group_info_button.setVisible(False)

        self.leave_group_button = QPushButton("Leave Group")

        self.leave_group_button.setCursor(Qt.PointingHandCursor)

        self.leave_group_button.clicked.connect(
            self.handle_leave_group
        )

        self.leave_group_button.setVisible(False)

        # Phase 19.22 -- Part G: Logout moved into Settings (see
        # handle_open_account_settings()); the header keeps only what
        # identifies/acts on the OPEN CONVERSATION, never a whole-
        # account action.

        # Phase 19.22 -- Part G: a small circular avatar beside the
        # partner's name -- the account's REAL profile picture when
        # one is set (center-cropped square, then circularly clipped
        # by _circular_pixmap(), never just a CSS border-radius on a
        # QLabel, which does not clip pixmap content in Qt), falling
        # back to the same colored-initial placeholder ConversationRow
        # already uses everywhere else in this app for consistency.
        self.header_avatar_label = QLabel()
        self.header_avatar_label.setFixedSize(32, 32)
        self.header_avatar_label.setAlignment(Qt.AlignCenter)
        self.header_avatar_label.setTextFormat(Qt.PlainText)

        # UI Finalization -- Initial Chat State: this is what the header
        # shows before any conversation has ever been opened in this
        # window. open_conversation() overwrites it with the partner
        # username or group name (both chosen by other users); nothing
        # else ever restores this default, since a fresh ChatWindow is
        # what re-enters this state (see MainWindow.show_chat()) --
        # there is no "close conversation" action to return to it.
        self.chat_partner_label = QLabel(
            "Quantum-Resistant Secure Communication System"
        )

        # L-1: set_conversation() rewrites this with a partner
        # username or a group name, both chosen by other users.
        self.chat_partner_label.setTextFormat(Qt.PlainText)

        self.chat_partner_label.setStyleSheet(
            "font-size: 15px; font-weight: 700;"
        )
        self.chat_partner_label.setMinimumWidth(0)
        self.chat_partner_label.setWordWrap(True)

        # Phase 19.24 -- Presence/Last Seen: a direct conversation's
        # own online/offline subtitle -- Desktop previously showed NO
        # live presence indicator anywhere in the chat header at all
        # (unlike mobile/app.py's TappableCircleAvatar online dot +
        # presence label). Driven by session.users_updated (already an
        # efficient, event-based server push -- see handle_online_
        # users_updated()'s own docstring for why this needed no new
        # polling), plus one fetch_last_seen() request when a direct
        # conversation opens with the peer currently offline. Hidden
        # (empty, zero-height-via-empty-text) for a group conversation
        # and whenever nothing is known yet.
        self.presence_label = QLabel("")
        self.presence_label.setTextFormat(Qt.PlainText)
        self.presence_label.setStyleSheet(
            f"font-size: 10px; color: {COLOR_TEXT_MUTED};"
        )

        # Server-Untrusted Identity Verification, Stage 3: a
        # persistent (never a one-shot toast) indicator of the open
        # direct conversation's verification state -- presentation
        # only, driven entirely by ClientSession.
        # get_peer_verification_state(), which is also the exact same
        # state client/session.py's enforcement gates
        # (establish_session_key() etc.) already check. Hidden for a
        # group conversation, where verification is a per-member
        # concern enforced at key-distribution time rather than a
        # single conversation-wide state -- see
        # _update_verification_status()'s docstring.
        self.verification_status_label = QLabel("")

        self.verification_status_label.setTextFormat(Qt.PlainText)

        self.verification_status_label.setStyleSheet(
            "font-size: 11px; font-weight: 700;"
        )

        self.verification_status_label.setVisible(False)

        self.verify_identity_button = QPushButton("Verify Identity")

        self.verify_identity_button.setCursor(Qt.PointingHandCursor)

        self.verify_identity_button.clicked.connect(
            self.handle_verify_identity
        )

        self.verify_identity_button.setVisible(False)

        # Phase 19.22 -- Part A/B: Desktop previously had no way to
        # INITIATE the async, Inbox-mediated verification flow at
        # all -- only mobile/app.py::VerifiedBadge.request_btn had
        # this (see ClientSession.request_verification()'s own
        # docstring: "the exact same confirm_combined_peer_
        # verification() call the existing Verify Identity dialog
        # already makes, just triggered from the Inbox instead of
        # that dialog"). Gated by the exact same state as verify_
        # identity_button in _update_verification_status() below,
        # mirroring VerifiedBadge.set_state()'s own show_request
        # condition exactly -- both actions are legitimate at once for
        # an unverified/changed peer (this account's own already-
        # observed key vs. asking the other side to confirm THEIRS),
        # and neither is ever shown once state is VERIFIED or no
        # identity has been observed yet at all.
        self.request_verification_button = QPushButton("Request Approval")

        self.request_verification_button.setCursor(Qt.PointingHandCursor)

        self.request_verification_button.clicked.connect(
            self.handle_request_verification
        )

        self.request_verification_button.setVisible(False)

        self.view_profile_button = QPushButton("View Profile")

        self.view_profile_button.setCursor(Qt.PointingHandCursor)

        self.view_profile_button.clicked.connect(
            self.handle_view_peer_profile
        )

        self.view_profile_button.setVisible(False)

        # Phase 19.24 -- Chat Wallpaper: always visible once a
        # conversation is open (direct or group alike) -- see
        # handle_open_wallpaper_picker()'s own docstring.
        self.wallpaper_button = QPushButton("\U0001F5BC")

        self.wallpaper_button.setObjectName("IconButton")

        self.wallpaper_button.setCursor(Qt.PointingHandCursor)

        self.wallpaper_button.setToolTip("Chat wallpaper")

        self.wallpaper_button.clicked.connect(
            self.handle_open_wallpaper_picker
        )

        # Phase 19.24 -- Message Search: toggles self.search_bar
        # (built below, next to messages_panel_layout). Always
        # visible once a conversation is open, same as wallpaper_
        # button -- see handle_toggle_search_bar()'s own docstring.
        self.search_button = QPushButton("\U0001F50D")

        self.search_button.setObjectName("IconButton")

        self.search_button.setCursor(Qt.PointingHandCursor)

        self.search_button.setToolTip("Search in this conversation")

        self.search_button.clicked.connect(
            self.handle_toggle_search_bar
        )

        # Phase 19.24 -- Pinned Messages: a real, server-synchronized
        # panel (not a fake local-only button -- see handle_open_
        # pinned_messages_panel()'s own docstring) listing every
        # currently-pinned message in the open conversation, with
        # click-to-navigate.
        self.pinned_messages_button = QPushButton("\U0001F4CC")

        self.pinned_messages_button.setObjectName("IconButton")

        self.pinned_messages_button.setCursor(Qt.PointingHandCursor)

        self.pinned_messages_button.setToolTip("Pinned messages")

        self.pinned_messages_button.clicked.connect(
            self.handle_open_pinned_messages_panel
        )

        # Phase 19.24 -- Media Gallery: a real, per-conversation view
        # over already-decrypted, already-rendered image/video/voice/
        # file bubbles -- see handle_open_media_gallery()'s own
        # docstring.
        self.gallery_button = QPushButton("\U0001F39E")

        self.gallery_button.setObjectName("IconButton")

        self.gallery_button.setCursor(Qt.PointingHandCursor)

        self.gallery_button.setToolTip("Media gallery")

        self.gallery_button.clicked.connect(
            self.handle_open_media_gallery
        )

        self._current_direct_peer_username = None

        header_identity_row = QHBoxLayout()
        header_identity_row.setSpacing(8)
        header_identity_row.addWidget(self.header_avatar_label)
        header_identity_row.addWidget(self.chat_partner_label, 1)
        header_identity_row.addWidget(self.view_profile_button)
        header_identity_row.addWidget(self.verification_status_label)
        header_layout.addLayout(header_identity_row)

        header_actions_row = QHBoxLayout()
        header_actions_row.setSpacing(4)
        header_actions_row.addWidget(self.verify_identity_button)
        header_actions_row.addWidget(self.request_verification_button)
        header_actions_row.addStretch()
        header_actions_row.addWidget(self.search_button)
        header_actions_row.addWidget(self.pinned_messages_button)
        header_actions_row.addWidget(self.gallery_button)
        header_actions_row.addWidget(self.wallpaper_button)
        header_actions_row.addWidget(self.add_members_button)
        header_actions_row.addWidget(self.group_info_button)
        header_actions_row.addWidget(self.leave_group_button)
        header_layout.addLayout(header_actions_row)

        header_layout.addWidget(self.presence_label)

        header_layout.addWidget(app_title)

        # Messages panel

        messages_panel = QFrame()

        messages_panel.setObjectName("Panel")

        messages_panel_layout = QVBoxLayout(messages_panel)

        messages_panel_layout.setContentsMargins(4, 4, 4, 4)

        # Phase 19.24 -- Message Search: hidden until search_button
        # is clicked. Operates entirely on MessageWidget.find_matches()
        # -- see that method's own docstring for why this never sends
        # the query text (or anything else) to the server.
        self.search_bar = QWidget()
        search_bar_layout = QHBoxLayout(self.search_bar)
        search_bar_layout.setContentsMargins(0, 0, 0, 6)
        search_bar_layout.setSpacing(6)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in this conversation")
        self.search_input.textChanged.connect(self._handle_search_query_changed)
        self.search_input.returnPressed.connect(self.handle_search_next)
        search_bar_layout.addWidget(self.search_input)

        self.search_result_label = QLabel("")
        self.search_result_label.setTextFormat(Qt.PlainText)
        self.search_result_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;"
        )
        search_bar_layout.addWidget(self.search_result_label)

        self.search_prev_button = QPushButton("▲")
        self.search_prev_button.setObjectName("IconButton")
        self.search_prev_button.setCursor(Qt.PointingHandCursor)
        self.search_prev_button.setToolTip("Previous match")
        self.search_prev_button.clicked.connect(self.handle_search_previous)
        search_bar_layout.addWidget(self.search_prev_button)

        self.search_next_button = QPushButton("▼")
        self.search_next_button.setObjectName("IconButton")
        self.search_next_button.setCursor(Qt.PointingHandCursor)
        self.search_next_button.setToolTip("Next match")
        self.search_next_button.clicked.connect(self.handle_search_next)
        search_bar_layout.addWidget(self.search_next_button)

        self.search_close_button = QPushButton("✕")
        self.search_close_button.setObjectName("IconButton")
        self.search_close_button.setCursor(Qt.PointingHandCursor)
        self.search_close_button.setToolTip("Close search")
        self.search_close_button.clicked.connect(self.handle_close_search_bar)
        search_bar_layout.addWidget(self.search_close_button)

        self.search_bar.setVisible(False)

        # The matched row indices (into self.messages) for the
        # current query, and which one is currently highlighted --
        # -1 until there is at least one match. Recomputed on every
        # keystroke and reset whenever the bar closes or the
        # conversation switches (see handle_close_search_bar() /
        # open_conversation()).
        self._search_matches = []
        self._search_match_index = -1

        messages_panel_layout.addWidget(self.search_bar)

        self.messages = MessageWidget()
        # Phase 19.24 (continued) -- Message Lifecycle Events UI.
        self.messages.set_context_action_handler(self._handle_bubble_context_action)
        # Set/cleared by _handle_bubble_context_action()'s "reply"
        # case / cancelled by the composer's own reply-preview bar --
        # the message_id this window's NEXT send should attach
        # reply_to_message_id for, or None for an ordinary send.
        self._pending_reply_message_id = None

        messages_panel_layout.addWidget(self.messages)

        # Input bar

        self.input_bar = InputBar()

        self.input_bar.set_enabled(False)

        # BUG -- Public-Key Availability: shown instead of an error
        # dialog while a direct conversation's composer is disabled
        # because this client has not yet received the recipient's
        # public key -- see _update_composer_availability(). Empty and
        # hidden whenever the composer is usable, so it takes no space
        # in the normal case.
        self.composer_status_label = QLabel("")

        self.composer_status_label.setTextFormat(Qt.PlainText)

        self.composer_status_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9pt; font-style: italic;"
        )

        self.composer_status_label.setVisible(False)

        # Phase 19.24 -- Typing Indicator: "X is typing..." (or "X and
        # Y are typing..." for a group), shown just above the composer
        # -- empty/hidden whenever nobody in the currently open
        # conversation is typing, so it takes no space in the normal
        # case, exactly like composer_status_label just above.
        self.typing_status_label = QLabel("")
        self.typing_status_label.setTextFormat(Qt.PlainText)
        self.typing_status_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9pt; font-style: italic;"
        )
        self.typing_status_label.setVisible(False)

        # Phase 19.24 (continued) -- Message Lifecycle Events UI: the
        # composer's Reply/Edit context bar -- shown only while
        # self._pending_reply_message_id or self._editing_message_id
        # is set (see _handle_bubble_context_action()'s "reply"/"edit"
        # cases and _clear_composer_context()). Same visible-only-when-
        # relevant pattern as composer_status_label just above.
        self.composer_context_bar = QWidget()
        composer_context_layout = QHBoxLayout(self.composer_context_bar)
        composer_context_layout.setContentsMargins(0, 0, 0, 0)
        composer_context_layout.setSpacing(8)

        self.composer_context_label = QLabel("")
        self.composer_context_label.setTextFormat(Qt.PlainText)
        self.composer_context_label.setWordWrap(True)
        self.composer_context_label.setStyleSheet(
            f"color: {COLOR_ACCENT}; font-size: 9pt;"
        )
        composer_context_layout.addWidget(self.composer_context_label, stretch=1)

        composer_context_cancel = QPushButton("✕")
        composer_context_cancel.setFixedSize(24, 24)
        composer_context_cancel.setCursor(Qt.PointingHandCursor)
        composer_context_cancel.setToolTip("Cancel")
        composer_context_cancel.clicked.connect(self._clear_composer_context)
        composer_context_layout.addWidget(composer_context_cancel)

        self.composer_context_bar.setVisible(False)
        self._editing_message_id = None
        self._editing_expected_version = 0

        # UI Finalization -- Initial Chat State: message history and the
        # composer are grouped into one widget so opening a conversation
        # is a single visibility swap against empty_state_panel below,
        # rather than juggling two widgets' visibility separately.
        self.chat_content = QWidget()

        chat_content_layout = QVBoxLayout(self.chat_content)

        chat_content_layout.setContentsMargins(0, 0, 0, 0)

        chat_content_layout.setSpacing(12)

        chat_content_layout.addWidget(messages_panel, stretch=1)

        chat_content_layout.addWidget(self.typing_status_label)

        chat_content_layout.addWidget(self.composer_status_label)

        chat_content_layout.addWidget(self.composer_context_bar)

        chat_content_layout.addWidget(self.input_bar)

        self.chat_content.setVisible(False)

        # Shown instead of chat_content until the user actually clicks a
        # conversation in the sidebar (open_conversation() swaps the
        # two) -- there is deliberately no message history or composer
        # to interact with here, since no conversation is open yet.
        self.empty_state_panel = QFrame()

        self.empty_state_panel.setObjectName("Panel")

        empty_state_layout = QVBoxLayout(self.empty_state_panel)

        empty_state_layout.setAlignment(Qt.AlignCenter)

        empty_state_label = QLabel(
            "Quantum-Resistant Secure Communication System"
        )

        # L-1: static, app-generated text -- never markup.
        empty_state_label.setTextFormat(Qt.PlainText)

        empty_state_label.setAlignment(Qt.AlignCenter)

        empty_state_label.setWordWrap(True)

        empty_state_label.setStyleSheet(
            f"font-size: 14pt; font-weight: 600; color: {COLOR_TEXT_MUTED};"
        )

        empty_state_layout.addWidget(empty_state_label)

        # Status bar

        self.status = StatusBarWidget()

        right_layout.addWidget(header)

        right_layout.addWidget(self.empty_state_panel, stretch=1)

        right_layout.addWidget(self.chat_content, stretch=1)

        right_layout.addWidget(self.status)

        root_layout.addWidget(left_panel, 1)

        root_layout.addLayout(right_layout, 3)

    # ==========================================================
    # Initialization
    # ==========================================================

    def initialize_ui(self):

        self.status.set_connected(True)

        self.status.set_algorithm(
            self.session.key_manager.algorithm
        )

        # BUG 7 (7.5) -- show the user their own discovery identifier.
        self.status.set_phone_number(
            getattr(self.session, "phone_number", "")
        )

        self.status.set_username(
            self.session.get_username()
        )

    # ==========================================================
    # Signal Connections
    # ==========================================================

    def connect_signals(self):

        self.conversation_list.conversation_selected.connect(
            self.open_conversation
        )

        # Phase 19.24 -- Mute.
        self.conversation_list.mute_action_requested.connect(
            self._handle_mute_action
        )

        self.input_bar.message_sent.connect(
            self.send_message
        )

        self.input_bar.attachment_selected.connect(
            self.handle_attachment_selected
        )

        # Phase 19.24 -- Presence/Last Seen.
        self.session.users_updated.connect(
            self.handle_online_users_updated
        )

        # Phase 19.24 -- Voice/Video Messages: a recorded clip is just
        # another local file path at this point (gui/input_bar.py's
        # MediaRecorderDialog already wrote it to a real temp file) --
        # reuses handle_attachment_selected() completely unmodified,
        # then deletes the now-sent temp recording (see
        # handle_recorded_media_selected()'s own docstring).
        self.input_bar.voice_message_recorded.connect(
            self.handle_recorded_media_selected
        )
        self.input_bar.video_message_recorded.connect(
            self.handle_recorded_media_selected
        )

        # Phase 19.24 -- Typing Indicator: every composer keystroke
        # re-arms the idle timer; see _on_composer_text_changed()'s own
        # docstring for the full debounce contract.
        self.input_bar.message_input.textChanged.connect(
            self._on_composer_text_changed
        )

    # ==========================================================
    # Backend Callbacks
    # ==========================================================

    def register_callbacks(self):

        # ConversationStore (client/conversation_store.py) is the
        # single source of truth for sidebar state -- it already
        # reacts to session.users_updated internally (see
        # ClientSession.handle_user_list()), so this window only ever
        # needs to listen for conversations_changed, never
        # users_updated directly.
        self.session.conversation_store.conversations_changed.connect(
            self.render_conversations
        )

        self.session.message_received.connect(
            self.receive_message
        )

        # payload_message_received carries binary content (Phase 8 --
        # File & Image Transfer) that message_received's fixed
        # Signal(str, str, str) cannot -- see ClientSession's
        # declaration for why this is a separate signal rather than a
        # change to the existing one.
        self.session.payload_message_received.connect(
            self.receive_payload_message
        )

        # connection_changed carries only True/False (client/session.py
        # emits it on successful connect(), on explicit disconnect(),
        # and -- the gap this closes -- on an unexpected mid-session
        # drop detected by the receiver thread, client/receiver.py).
        # StatusBarWidget.set_connected() already takes exactly that
        # bool, so this is a direct connection: no new connection-state
        # concept, no polling, no second source of truth.
        self.session.connection_changed.connect(
            self.status.set_connected
        )

        # Phase 19.24 -- Typing Indicator: a disconnect (explicit or a
        # mid-session drop) must never leave a typing-related QTimer
        # armed -- see _on_disconnected_stop_all_typing_timers()'s own
        # docstring for the full rationale.
        self.session.connection_changed.connect(
            self._on_connection_changed_stop_typing_timers
        )

        self.session.error_occurred.connect(
            self.show_error
        )

        # Phase 14.1 -- Security Rejection GUI: the backend already
        # decided this packet was rejected and never altered any
        # trusted key/identity state doing so (ClientSession.
        # security_rejection's own docstring) -- this GUI is purely a
        # consumer of that already-made decision, never a second
        # place a security judgment is made.
        self.session.security_rejection.connect(
            self.handle_security_rejection
        )

        # C2 -- Read Receipts: a live "someone read up to now" hint
        # for whichever conversation is currently open -- see
        # handle_read_receipt_updated(). The authoritative status is
        # always re-derived from the database at load_history() time
        # regardless, so this is purely a same-session UI refresh.
        self.session.read_receipt_updated.connect(
            self.handle_read_receipt_updated
        )

        # Phase 19.23 -- Issue 3: a live "delivered to the recipient's
        # device" hint for whichever conversation is currently open --
        # see handle_message_delivered_updated(). Same "live hint
        # only, history is authoritative" contract as read_receipt_
        # updated above.
        self.session.message_delivered_updated.connect(
            self.handle_message_delivered_updated
        )

        # Phase 19.24 (continued) -- Message Lifecycle Events UI.
        self.session.own_message_id_resolved.connect(
            self.handle_own_message_id_resolved
        )
        self.session.message_edited_received.connect(
            self.handle_message_edited_received
        )
        self.session.message_deleted_received.connect(
            self.handle_message_deleted_received
        )
        self.session.reaction_updated_received.connect(
            self.handle_reaction_updated_received
        )
        self.session.message_pinned_received.connect(
            self.handle_message_pinned_received
        )
        self.session.message_unpinned_received.connect(
            self.handle_message_unpinned_received
        )
        self.session.message_id_received.connect(
            self.handle_incoming_message_id_resolved
        )
        self.session.typing_indicator_received.connect(
            self.handle_typing_indicator_received
        )

        # Phase 19.24 -- Typing Indicator. _typing_active: whether THIS
        # client has an outstanding is_typing=True it has not yet told
        # the server stopped (composer text became empty, the message
        # was actually sent, or the idle timer below fired).
        # _typing_stop_timer: restarted on every keystroke; firing it
        # means "idle long enough to consider typing stopped". _typing_
        # senders: conversation_id -> {username: QTimer}, the RECEIVING
        # side's own per-sender auto-expiry (a sender whose connection
        # drops mid-type never sends the matching is_typing=False, so
        # each entry ages itself out independently -- this is what
        # makes group multi-typer display correct: one silent sender
        # never blocks or is blocked by another).
        self._typing_active = False
        self._typing_stop_timer = QTimer(self)
        self._typing_stop_timer.setSingleShot(True)
        self._typing_stop_timer.setInterval(3000)
        self._typing_stop_timer.timeout.connect(self._send_typing_stopped)
        self._typing_senders = {}

        # Phase 19.24 -- Drafts: conversation key (summary.key -- a
        # username for direct, conversation_id for group, same identity
        # ConversationStore/session.current_chat already use) -> unsent
        # composer text. In-memory only, this window's lifetime -- never
        # persisted to disk or sent anywhere, and never touched while a
        # reply/edit is in progress (that text belongs to the pending
        # action, not a draft of a fresh message).
        self._drafts = {}

        # Phase 19.24 (continued) -- the bubble receive_message()/
        # receive_payload_message() most recently added to the
        # CURRENTLY open conversation, awaiting message_id_received
        # (see handle_incoming_message_id_resolved() below). None once
        # resolved, once the conversation is switched, or before any
        # message has arrived this session -- a live message aimed at a
        # conversation that is NOT open is never assigned here (Reply/
        # React/etc. on it become available once that conversation is
        # opened, via load_history() supplying the id directly).
        self._last_received_bubble = None

        # BUG -- Public-Key Availability: a live "this key just
        # arrived" hint for whichever conversation is currently open --
        # see handle_public_key_received().
        self.session.public_key_received.connect(
            self.handle_public_key_received
        )

        # Server-Untrusted Identity Verification, Stage 2 signal,
        # first connected here in Stage 3: a previously VERIFIED
        # peer's key just changed -- see handle_peer_key_changed().
        self.session.peer_key_changed.connect(
            self.handle_peer_key_changed
        )

        # -----------------------------------------
        # Sync UI with current session state
        # -----------------------------------------

        self.session.load_conversations()

        # Phase 19.24 -- Block User: seeds session.blocked_usernames
        # (the local cache render_conversations()/the context menu
        # both read from) once at startup -- see get_blocked_users()'s
        # own docstring for why this isn't re-fetched on every render.
        self.session.get_blocked_users()

    def render_conversations(self):
        """
        Re-render the sidebar from ConversationStore -- the single
        source of truth for conversation state. This is the only
        place the sidebar widget is populated; nothing else in this
        class (or anywhere else) mutates it directly.
        """

        # Phase 19.24 -- Archive: the sidebar shows either the main
        # (non-archived) list or the archived one, never both at once
        # -- self._show_archived (flipped only by the Archived toggle
        # button) is the single filter this method applies; archiving
        # never deletes/hides anything server-side, it just moves a
        # conversation between these two locally-filtered views.
        summaries = [
            s for s in self.session.conversation_store.get_all()
            if self.session.is_conversation_archived(s.key) == self._show_archived
        ]

        self.conversation_list.render(summaries)

        for summary in summaries:

            self.conversation_list.set_unread_count(
                summary.key,
                self.session.get_unread_count(summary.key)
            )

            # Phase 19.24 -- Mute: same narrow, presentation-only
            # per-row update as set_unread_count() above -- mute state
            # is a local UI preference (storage/secure_key_store.py),
            # never conversation metadata ConversationStore would know
            # about.
            self.conversation_list.set_muted(
                summary.key,
                self.session.is_conversation_muted(summary.key)
            )

            self.conversation_list.set_archived(
                summary.key,
                self.session.is_conversation_archived(summary.key)
            )

            # Phase 19.24 -- Block User: only meaningful for a direct
            # conversation -- see gui/conversation_list_widget.py::
            # ConversationRow.contextMenuEvent()'s identical guard.
            if not summary.is_group:
                self.conversation_list.set_blocked(
                    summary.key,
                    self.session.is_user_blocked(summary.key)
                )

    def _handle_archived_toggle(self, checked):
        """Phase 19.24 -- Archive: flips which of the two locally-
        filtered sidebar views render_conversations() shows."""

        self._show_archived = checked
        self.archived_toggle_button.setText("Back to Chats" if checked else "Archived")
        self.render_conversations()

    def _handle_mute_action(self, summary, action):
        """
        Phase 19.24 -- Mute/Archive: ConversationListWidget.mute_
        action_requested's target (the signal predates Archive being
        added to the same context menu -- its name is now slightly
        narrower than what it actually carries). ``action`` is
        "unmute", "mute_<duration>", "archive", or "unarchive" (see
        gui/conversation_list_widget.py::ConversationRow.
        contextMenuEvent() for the exact set) -- re-renders the sidebar
        afterward so the mute icon/badge suppression/archived-list
        membership reflect the change immediately, without waiting for
        the next unrelated refresh.
        """

        if action == "unmute":
            self.session.unmute_conversation(summary.key)
        elif action == "archive":
            self.session.archive_conversation(summary.key)
        elif action == "unarchive":
            self.session.unarchive_conversation(summary.key)
        elif action == "block":
            if self._confirm_block_user(summary.key):
                self._do_block_user(summary.key)
        elif action == "unblock":
            self.session.unblock_user(summary.key)
        else:
            duration = action[len("mute_"):]
            self.session.mute_conversation(summary.key, duration)

        self.render_conversations()

    def _confirm_block_user(self, username):
        """
        Blocking Yes/No confirmation shown before Block User is sent
        (a real, server-side-enforced action -- see feature_security_
        matrix.md row 28). Split out so tests can call _do_block_user()
        directly and bypass only this modal, same convention as
        _confirm_delete_for_everyone() above.
        """

        box = QMessageBox(self)

        box.setIcon(QMessageBox.Warning)

        box.setWindowTitle("Block User?")

        box.setText(
            f"Block {username}? They will no longer be able to message "
            f"you, see your presence, or verify your identity. You can "
            f"unblock them later."
        )

        block_button = box.addButton("Block", QMessageBox.AcceptRole)

        box.addButton("Cancel", QMessageBox.RejectRole)

        box.exec()

        return box.clickedButton() == block_button

    def _do_block_user(self, username):
        """The actual Block User request, extracted so tests can call
        it directly without driving the confirmation dialog above."""

        self.session.block_user(username)

    # ==========================================================
    # Events
    # ==========================================================

    def handle_find_user(self):
        """
        Search for a user by their unique ID and, if found, open a
        direct conversation with them (Issue 3 fix -- User Must Be
        Searched By Unique ID). Reuses the exact same conversation-
        opening path a sidebar click already uses (open_conversation())
        -- a ConversationSummary built from the lookup result is
        indistinguishable to that method from one ConversationStore
        would have produced for an online user with no history yet
        (see ConversationStore.update_online_status()'s identical
        placeholder shape).
        """

        dialog = FindUserDialog(self.session, self)

        if dialog.exec() != QDialog.Accepted:
            return

        found = dialog.get_result()

        if found is None:
            return

        summary = ConversationSummary(
            conversation_id=None,
            username=found["username"],
            is_online=found["username"] in self.session.get_online_users(),
            latest_message=None,
        )

        self.open_conversation(summary)

    def handle_open_inbox(self):
        """
        Open the Inbox (Phase 19.17C -- Desktop previously had no
        Inbox UI at all). Purely presentational: InboxDialog calls the
        session's own already-existing, already-tested inbox methods
        (load_inbox()/respond_to_inbox()) -- no separate Desktop-only
        inbox implementation.
        """

        dialog = InboxDialog(self.session, self)
        dialog.exec()

    def handle_open_account_settings(self):
        """
        Open Settings -- Profile Picture, Bio, Change Password, Change
        Username, Logout (Phase 19.22 -- Part D/E/F/G: consolidates
        what were previously separate sidebar entry points, Profile
        Picture and the header's own Logout button, into one screen;
        see AccountSettingsDialog's own docstring). AccountSettingsDialog
        never emits logout_requested itself -- it only ever accept()s
        (Logout was clicked) or reject()s (Close/dismissed); ChatWindow
        stays the single place that signal is ever raised from, exactly
        as before this phase, so MainWindow.handle_logout() needs no
        change at all.
        """

        dialog = AccountSettingsDialog(self.session, self)

        if dialog.exec() == QDialog.Accepted:
            self.logout_requested.emit()

    def handle_view_peer_profile(self):
        """
        Open the currently open direct peer's profile picture,
        read-only (Phase 19.19 -- ClientSession.fetch_profile_picture()
        already accepted an arbitrary target username; Desktop's GUI
        never called it for anyone but the account's own username).
        A no-op if no direct conversation is open -- the button is
        only visible when one is, but this guards direct calls too.
        """

        if not self._current_direct_peer_username:
            return

        dialog = ProfilePictureDialog(self.session, self, target_username=self._current_direct_peer_username)
        dialog.exec()

    def handle_open_wallpaper_picker(self):
        """
        Phase 19.24 -- Chat Wallpaper: a small preset picker for
        whichever conversation is currently open. Local-only (storage/
        secure_key_store.py) -- never sent to or stored by the server.
        A no-op if no conversation is open (the header, and therefore
        this button, is not visible before one is anyway).
        """

        key = self.session.get_current_chat()

        if key is None:
            return

        menu = QMenu(self)

        current = self.session.get_conversation_wallpaper(key)

        default_action = menu.addAction("Default")
        default_action.setCheckable(True)
        default_action.setChecked(current is None)
        default_action.setData(None)

        for wallpaper_id, (label, _gradient) in WALLPAPER_PRESETS.items():
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(current == wallpaper_id)
            action.setData(wallpaper_id)

        chosen = menu.exec(self.wallpaper_button.mapToGlobal(
            self.wallpaper_button.rect().bottomLeft()
        ))

        if chosen is None:
            return

        self.session.set_conversation_wallpaper(key, chosen.data())
        self.messages.set_wallpaper(chosen.data())

    # ==========================================================
    # Phase 19.24 -- Message Search
    # ==========================================================
    #
    # Searches only the ALREADY-DECRYPTED bubbles MessageWidget has
    # already rendered for the currently open conversation (see
    # MessageWidget.find_matches()'s own docstring) -- the query text
    # never reaches the server, and there is no second history fetch.

    def handle_toggle_search_bar(self):
        """
        Show the search bar and focus it, or hide it (and clear any
        active search) if it is already open. A no-op if no
        conversation is open, same guard as the wallpaper picker.
        """

        if self.session.get_current_chat() is None:
            return

        if self.search_bar.isVisible():
            self.handle_close_search_bar()
            return

        self.search_bar.setVisible(True)
        self.search_input.setFocus()

    def handle_close_search_bar(self):
        """Hide the search bar and clear any active match/highlight."""

        self.search_bar.setVisible(False)
        self.search_input.clear()
        self._search_matches = []
        self._search_match_index = -1
        self.search_result_label.setText("")
        self.messages.clear_highlight()

    def _handle_search_query_changed(self, text):
        """
        Recompute matches for the currently-open conversation on
        every keystroke and jump to the first one, exactly like a
        browser's in-page find. An empty query clears the highlight
        without closing the bar, so the user can keep typing.
        """

        self._search_matches = self.messages.find_matches(text)

        if not self._search_matches:
            self._search_match_index = -1
            self.messages.clear_highlight()
            self.search_result_label.setText(
                "No matches" if text.strip() else ""
            )
            return

        self._search_match_index = 0
        self._show_current_search_match()

    def _show_current_search_match(self):
        row = self._search_matches[self._search_match_index]
        self.messages.highlight_row(row)
        self.search_result_label.setText(
            f"{self._search_match_index + 1} of {len(self._search_matches)}"
        )

    def handle_search_next(self):
        """Jump to the next match, wrapping around to the first."""

        if not self._search_matches:
            return

        self._search_match_index = (
            self._search_match_index + 1
        ) % len(self._search_matches)
        self._show_current_search_match()

    def handle_search_previous(self):
        """Jump to the previous match, wrapping around to the last."""

        if not self._search_matches:
            return

        self._search_match_index = (
            self._search_match_index - 1
        ) % len(self._search_matches)
        self._show_current_search_match()

    # ==========================================================
    # Phase 19.24 -- Pinned Messages
    # ==========================================================

    def handle_open_pinned_messages_panel(self):
        """
        A real, server-synchronized panel: every currently-pinned
        message in the open conversation, most-recently-pinned messages
        with a click-to-navigate action that scrolls to and highlights
        the real rendered bubble (MessageWidget.scroll_to_bubble(),
        reusing Message Search's own highlight machinery). Pin state
        itself is NOT local-only -- it is a real message_pin/
        message_unpin protocol round trip (ClientSession.pin_message())
        with a server-side row (database/models/message.py::pinned_at)
        that synchronizes to every conversation member and every one of
        this account's own other authorized devices via ordinary
        history reload, exactly like edit/delete/reactions already do;
        this panel is simply a VIEW over that already-synchronized
        state, never its own separate source of truth.
        """

        key = self.session.get_current_chat()

        if key is None:
            return

        pinned = self.messages.get_pinned_bubbles()

        menu = QMenu(self)

        if not pinned:
            action = menu.addAction("No pinned messages")
            action.setEnabled(False)
        else:
            for bubble in reversed(pinned):
                preview = getattr(bubble, "message_text", None) or "[Attachment]"
                shown = preview if len(preview) <= 60 else preview[:57] + "…"
                by = f" — pinned by {bubble.pinned_by}" if bubble.pinned_by else ""
                action = menu.addAction(f"{shown}{by}")
                action.setData(bubble)

        chosen = menu.exec(self.pinned_messages_button.mapToGlobal(
            self.pinned_messages_button.rect().bottomLeft()
        ))

        if chosen is None or chosen.data() is None:
            return

        self.messages.scroll_to_bubble(chosen.data())

    # ==========================================================
    # Phase 19.24 -- Media Gallery
    # ==========================================================

    def handle_open_media_gallery(self):
        """
        A real per-conversation gallery: every image/video thumbnail
        currently rendered (tap to open the SAME real, already-tested
        viewers those bubbles already offer inline -- ImageMessage
        Bubble.open_viewer()/FileMessageBubble._open_video_player()),
        plus a plain list of voice/file attachments below (tap to
        play/Save via those same bubbles' own existing controls).
        Operates entirely over MessageWidget.get_media_bubbles() --
        already-decrypted, already-rendered bubbles -- so this never
        touches the server or triggers a second history fetch, and
        never exposes decrypted media to it.
        """

        key = self.session.get_current_chat()

        if key is None:
            return

        media = self.messages.get_media_bubbles()

        dialog = QDialog(self)
        dialog.setWindowTitle("Media Gallery")
        dialog.resize(420, 480)

        outer = QVBoxLayout(dialog)

        if not media:
            outer.addWidget(QLabel("No media in this conversation yet."))
            dialog.exec()
            return

        images_and_videos = [
            b for b in media
            if isinstance(b, ImageMessageBubble) or getattr(b, "payload_type", None) == PayloadType.VIDEO
        ]
        other_files = [b for b in media if b not in images_and_videos]

        if images_and_videos:
            outer.addWidget(QLabel("Photos & Videos"))
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            grid_holder = QWidget()
            grid = QGridLayout(grid_holder)
            columns = 3
            for index, bubble in enumerate(images_and_videos):
                tile = self._build_gallery_tile(bubble)
                grid.addWidget(tile, index // columns, index % columns)
            scroll.setWidget(grid_holder)
            outer.addWidget(scroll, stretch=2)

        if other_files:
            outer.addWidget(QLabel("Voice Messages & Files"))
            files_scroll = QScrollArea()
            files_scroll.setWidgetResizable(True)
            files_holder = QWidget()
            files_layout = QVBoxLayout(files_holder)
            for bubble in other_files:
                row_label = QLabel(getattr(bubble, "_filename", "attachment"))
                row_label.setTextFormat(Qt.PlainText)
                files_layout.addWidget(row_label)
            files_layout.addStretch()
            files_scroll.setWidget(files_holder)
            outer.addWidget(files_scroll, stretch=1)

        dialog.exec()

    def _build_gallery_tile(self, bubble):
        """One clickable thumbnail tile in the Media Gallery grid --
        a real scaled-down copy of the bubble's own already-decoded
        pixmap for an image (never re-decrypts or re-fetches anything),
        or a plain "Video" placeholder tile for a video attachment
        (this project has no separate video-frame-thumbnail extraction
        -- see docs/architecture/media_security_architecture.md).
        Aspect ratio is always preserved, never distorted (Qt.KeepAspectRatio).
        """

        tile = QPushButton()
        tile.setFixedSize(120, 120)
        tile.setCursor(Qt.PointingHandCursor)

        if isinstance(bubble, ImageMessageBubble):
            if bubble.full_size() is not None:
                pixmap = bubble._full_pixmap.scaled(
                    116, 116, Qt.KeepAspectRatio, Qt.SmoothTransformation
                )
                tile.setIcon(QIcon(pixmap))
                tile.setIconSize(pixmap.size())
            else:
                # A real image bubble whose own decode failed (corrupt/
                # unsupported bytes -- see gui/message_widget.py::
                # _decode_image()'s own "returns None for every
                # rejection" contract) -- not a video, so it must never
                # be routed to _open_video_player(), which does not
                # exist on this bubble type at all.
                tile.setText("[Image]")
            tile.clicked.connect(bubble.open_viewer)
        else:
            tile.setText("▶\nVideo")
            tile.clicked.connect(bubble._open_video_player)

        return tile

    def handle_open_device_management(self):
        """
        Open the device list (Phase 19.19 -- Desktop previously had no
        device-management UI at all, despite ClientSession.
        enroll_device()/list_devices()/authorize_device()/
        revoke_device() already existing and being server-enforced
        identically for every client). See DeviceManagementDialog's
        own docstring for the lazy self-enrollment this triggers the
        first time it is opened.
        """

        dialog = DeviceManagementDialog(self.session, self)
        dialog.exec()

    def handle_open_group_info(self):
        """
        Open the member list for the currently open group, with an
        admin-only Remove button per member (Phase 19.18 -- Desktop
        previously had no way to even view a group's membership,
        despite ClientSession.remove_group_member() already existing
        and being server-enforced identically for every client).
        A no-op if the open conversation isn't a group -- the button
        is only visible when it is, but this guards direct calls too.
        """

        if not self.session.current_chat_is_group:
            return

        conversation_id = self.session.get_current_chat()

        if conversation_id is None:
            return

        dialog = GroupInfoDialog(self.session, conversation_id, self)
        dialog.exec()

    def handle_create_group(self):
        """
        Open the group-creation dialog and, if confirmed with a name
        and at least one member, ask the session to create it. The
        new group appears in the sidebar asynchronously, once the
        server confirms it (see ClientSession.handle_group_create_result())
        -- there is no optimistic local update here.
        """

        dialog = CreateGroupDialog(self.session, self.session.get_online_users(), self)

        if dialog.exec() == QDialog.Accepted:

            name, member_usernames = dialog.get_result()

            if name and member_usernames:
                self.session.create_group_conversation(name, member_usernames)

    def handle_add_members(self):
        """
        Add one or more users to the currently open group conversation
        (Issue 2 fix -- Add Members After Group Creation). Candidates
        are the currently online users minus whoever is already a
        participant (including this client itself) -- ConversationStore.
        get() is the read-only accessor added for exactly this lookup.
        No optimistic local update: the sidebar refreshes once the
        server confirms via ClientSession.handle_group_members_added().
        """

        if not self.session.current_chat_is_group:
            return

        conversation_id = self.session.get_current_chat()

        if conversation_id is None:
            return

        summary = self.session.conversation_store.get(conversation_id)

        existing_participants = set(summary.participants or []) if summary else set()
        existing_participants.add(self.session.get_username())

        candidates = [
            username for username in self.session.get_online_users()
            if username not in existing_participants
        ]

        if not candidates:

            QMessageBox.information(
                self,
                "Add Members",
                "No additional online users are available to add."
            )

            return

        dialog = AddMembersDialog(self.session, candidates, existing_participants, self)

        if dialog.exec() == QDialog.Accepted:

            selected = dialog.get_result()

            if selected:
                self.session.add_group_members(conversation_id, selected)

    def handle_leave_group(self):
        """
        Leave the currently open group conversation (Phase 7 -- Group
        Membership Management). A no-op if the open conversation isn't
        a group -- the button is only visible when it is, but this
        guards direct calls/races too. No optimistic local update:
        the sidebar/message panel update once the server confirms via
        ClientSession.handle_group_member_left() ->
        conversations_changed, the same path every other conversation-
        store change already goes through.
        """

        if not self.session.current_chat_is_group:
            return

        conversation_id = self.session.get_current_chat()

        if conversation_id is None:
            return

        self.session.leave_group_conversation(conversation_id)

    def open_conversation(self, summary):
        """
        Open a conversation -- direct or group. ``summary`` is the
        whole ConversationSummary the sidebar row was rendered from
        (see ConversationListWidget.conversation_selected); passed to
        the session as-is (Phase 5 -- Secure Group Key Distribution)
        so it can resolve the real conversation_id via
        ConversationStore without ClientSession ever needing a bare
        key guessed at here. ``summary.key`` remains the addressing
        identity for everything else in this method (unread counts,
        history loading) -- unchanged since Phase 4.
        """

        key = summary.key

        # Phase 19.24 -- Typing Indicator: an outstanding is_typing=True
        # for whichever conversation was open BEFORE this call belongs
        # to that conversation, not the one about to open -- stopped
        # here, before set_current_chat() below moves current_
        # conversation_id, so the "stopped" packet still addresses the
        # right one. self._typing_senders (what OTHER people are
        # typing) is reset separately below, once the new conversation_
        # id is known, since that state is scoped per-conversation and
        # simply becomes irrelevant here rather than needing an
        # explicit "stopped" of its own.
        self._stop_typing_immediately()

        # Phase 19.24 -- Drafts: save whatever unsent text sits in the
        # composer for whichever conversation was open BEFORE this call,
        # keyed by self.session.current_chat -- still the OLD key here,
        # since set_current_chat() below hasn't moved it yet. Skipped
        # while a reply/edit is in progress: that text is not a draft of
        # a fresh message, it belongs to the pending action.
        old_key = self.session.current_chat
        if (
            old_key is not None
            and self._editing_message_id is None
            and self._pending_reply_message_id is None
        ):
            draft_text = self.input_bar.message_input.text()
            if draft_text:
                self._drafts[old_key] = draft_text
            else:
                self._drafts.pop(old_key, None)

        self.session.set_current_chat(summary)

        # C2 -- Read Receipts: any reader accumulated for whatever
        # conversation was open before is now stale -- bubbles are
        # about to be fully re-rendered from fresh history below,
        # already reflecting current status.
        self._read_receipt_readers = set()

        self.session.clear_unread(key)

        self.render_conversations()

        self.leave_group_button.setVisible(summary.is_group)

        self.add_members_button.setVisible(summary.is_group)

        self.group_info_button.setVisible(summary.is_group)

        self.view_profile_button.setVisible(not summary.is_group)

        self._current_direct_peer_username = None if summary.is_group else summary.username

        # Phase 19.24 -- Presence/Last Seen: refreshed fresh for
        # whichever conversation is now open -- group conversations
        # never show this (there is no single "the other person" to
        # report presence for), matching wallpaper_button's own
        # earlier identical group-vs-direct precedent.
        self._refresh_presence_label()

        display_name = summary.group_name if summary.is_group else summary.username

        # UI Finalization Decision 4 -- the static "Chatting with
        # <user>" phrasing is gone; the header now names the open
        # conversation plainly, and "when" (today/yesterday/a date)
        # lives in the message timeline as a proper list element (see
        # MessageWidget.DateSeparatorBubble), not squeezed into this
        # fixed header. "Group: <name>" is unchanged -- it wasn't the
        # phrasing asked to be removed, and a group's header still
        # needs to say it's a group, not just its name.
        label = (
            f"Group: {display_name}" if summary.is_group
            else display_name
        )

        self.chat_partner_label.setText(label)

        self._refresh_header_avatar(display_name, self._current_direct_peer_username)

        # Phase 19.24 -- Typing Indicator: whatever was shown belonged
        # to the previous conversation (or nothing) -- this one starts
        # with a clean slate; a live typing_indicator_notification for
        # it, if one is already in flight, re-renders correctly once it
        # arrives.
        self.typing_status_label.setText("")
        self.typing_status_label.setVisible(False)

        # Phase 19.24 -- Chat Wallpaper: applied fresh for whichever
        # conversation is now open -- key is `key` (summary.key), the
        # same identity Mute/Archive/Block already use.
        self.messages.set_wallpaper(self.session.get_conversation_wallpaper(key))

        # Phase 19.24 -- Message Search: match row indices are only
        # valid for the conversation they were computed against, so
        # switching conversations must always close/reset the bar --
        # never carry a stale match list into the newly-opened chat.
        self.handle_close_search_bar()

        # UI Finalization -- Initial Chat State: the first conversation
        # ever opened in this window is what makes message history and
        # the composer visible at all; every later open_conversation()
        # call is a no-op against widgets already visible.
        self.empty_state_panel.setVisible(False)

        self.chat_content.setVisible(True)

        # BUG -- Public-Key Availability: replaces the previous
        # unconditional set_enabled(True) -- see
        # _update_composer_availability()'s docstring for why a direct
        # conversation's composer must not be usable until this client
        # has actually received the recipient's public key.
        self._update_composer_availability()

        # Server-Untrusted Identity Verification, Stage 3: refresh the
        # persistent verification badge for whichever conversation is
        # now open -- see _update_verification_status()'s docstring.
        self._update_verification_status()

        # Phase 19.24 -- Drafts: restore whatever unsent text this
        # conversation had, or leave the composer empty if it never had
        # one -- key is `key` (summary.key), the same identity
        # session.current_chat now holds after set_current_chat() above.
        self.input_bar.set_text(self._drafts.get(key, ""))

        self.input_bar.focus_input()

        self.messages.clear_messages()

        # Phase 19.24 (continued) -- a pending resolution belonged to
        # whichever conversation was open before; a message_id_received
        # that arrives after this switch is for a DIFFERENT bubble that
        # no longer exists on screen, so it must not be misapplied here.
        self._last_received_bubble = None

        self.messages.add_system_message(label)

        self.load_history(key, summary.is_group)

        # C2 -- Read Receipts: tell the server everything in this
        # conversation is now read -- only once the user has actually
        # opened it and its history has been loaded/rendered above,
        # never merely because the client reconnected or logged in.
        self._mark_current_conversation_read()

    def _mark_current_conversation_read(self):
        """
        Tell the server everything in the currently-open conversation
        is read (C2 -- Read Receipts).

        Two call sites, both meaning "the user is actually looking at
        this conversation right now": open_conversation() (opening it
        is itself that moment) and receive_message()/
        receive_payload_message() (BUG -- Read Receipt Real-Time
        Update: a message that arrives WHILE the conversation is
        already open is just as immediately read as one that was
        already there when it was opened -- previously nothing marked
        it read until the conversation was closed and reopened).
        mark_conversation_read() is idempotent server-side (see
        MessageRepository.mark_conversation_read()/handle_read_receipt()
        -- a no-op once nothing is left unread), so calling this once
        per incoming message rather than once per "read session" costs
        nothing extra.

        Never called merely because the user is online or the client
        reconnected -- both call sites require the conversation to
        already be the one on screen.
        """

        try:

            self.session.mark_conversation_read(self.session.current_conversation_id)

        except Exception as error:  # noqa: BLE001

            # Intentionally broad, matching send_message()'s/
            # handle_attachment_selected()'s outbound-failure pattern:
            # mark_conversation_read() can fail for reasons spanning
            # unrelated exception hierarchies (a socket-level OSError,
            # or anything session-state related), and the conversation
            # has already fully opened/rendered by every caller of this
            # method -- a failure here only means the read receipt
            # itself didn't go out; it must never block or undo
            # anything already on screen.
            self.show_error(str(error))

    def _refresh_header_avatar(self, display_name, peer_username):
        """
        Phase 19.22 -- Part G: the small circular avatar beside the
        chat header's partner name. ``peer_username`` is None for a
        group (groups have no per-conversation picture concept in
        this app) or a direct conversation whose real picture could
        not be loaded -- both fall back to the same colored-initial
        placeholder ConversationRow uses, keeping the visual language
        consistent everywhere an avatar appears.
        """

        image_bytes = None

        if peer_username:
            try:
                image_bytes = self.session.fetch_profile_picture(peer_username)
            except Exception:  # noqa: BLE001
                image_bytes = None

        if image_bytes:
            pixmap = QPixmap()
            if pixmap.loadFromData(image_bytes):
                side = min(pixmap.width(), pixmap.height())
                square = pixmap.copy(
                    (pixmap.width() - side) // 2,
                    (pixmap.height() - side) // 2,
                    side, side,
                )
                self.header_avatar_label.setPixmap(self._circular_pixmap(square, 32))
                self.header_avatar_label.setStyleSheet("")
                return

        initial = display_name[0].upper() if display_name else "?"
        self.header_avatar_label.setText(initial)
        self.header_avatar_label.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: #FFFFFF; "
            "border-radius: 16px; font-weight: 700;"
        )

    @staticmethod
    def _circular_pixmap(square_pixmap, size):
        """
        A CSS border-radius on a QLabel only rounds the widget's own
        background/border box -- it does not clip pixmap CONTENT drawn
        via setPixmap() in Qt. This is the actual pixel-level circular
        clip, via a QPainterPath ellipse used as the paint clip while
        drawing the (already square-cropped) source into a fresh,
        transparent output pixmap.
        """

        scaled = square_pixmap.scaled(
            size, size, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation,
        )
        result = QPixmap(size, size)
        result.fill(Qt.transparent)
        painter = QPainter(result)
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addEllipse(QRectF(0, 0, size, size))
        painter.setClipPath(path)
        painter.drawPixmap(0, 0, scaled)
        painter.end()
        return result

    def _update_composer_availability(self):
        """
        Enable the composer whenever the currently-open conversation
        can actually be messaged right now (BUG -- Public-Key
        Availability; revised by BUG -- Offline First Contact).

        Two direct-conversation cases used to matter here:

        A. Brand-new conversation, no session key yet. Previously
           gated on the recipient's public key, because
           ClientSession.establish_session_key() needed it just to
           GENERATE a Kyber-derived key (encapsulate() derives its own
           secret from the recipient's public key -- see
           crypto/kyber.py) -- so a conversation opened via Find User
           with someone currently offline had a real conversation but
           no way to even create a key, and the first send attempt
           failed with a blocking "No public key found" dialog.
           establish_session_key() now generates the AES key locally
           (os.urandom(32)) regardless of public-key availability, and
           defers only WRAPPED DELIVERY of that key to the existing
           recovery mechanism when the recipient is offline (see its
           docstring in client/session.py) -- so this case no longer
           needs to block sending at all.

        B. Existing conversation that already has a session key
           (KeyManager.has_key(conversation_id)). Sending here has
           never actually needed the recipient's public key -- it
           reuses the existing key, whether still in memory or
           restored on login from the local encrypted key store
           (storage/secure_key_store.py) -- regardless of the peer's
           current public-key state. This was already true before
           this fix; the old gate simply checked the wrong signal.

        With A now also key-generation-independent of the public key,
        there is no remaining direct-conversation state where a
        missing public key should block the composer. The deeper
        safety net -- _send_encrypted_payload() raising if
        establish_session_key() somehow still leaves no key stored --
        is untouched and remains the actual defense-in-depth for any
        other failure (e.g. the epoch-reservation request itself
        failing), surfaced through send_message()'s existing generic
        exception handling.

        Not applicable to a group conversation: a group's key is
        established entirely differently (group key distribution at
        creation/add-member time -- see KeyManager.wrap_key_for_member()
        via server-side group handlers), never gated on a single
        peer's public key here.
        """

        if self.session.current_chat_is_group:

            self.input_bar.set_enabled(True)

            return

        partner = self.session.get_current_chat()

        self.input_bar.set_enabled(partner is not None)

    def _update_verification_status(self):
        """
        Refresh the persistent verification badge/button for the
        currently open conversation (Server-Untrusted Identity
        Verification, Stage 3).

        Presentation only: reads ClientSession.
        get_peer_verification_state(), the exact same state
        client/session.py's enforcement (establish_session_key(),
        handle_direct_key_redelivery_required(),
        _distribute_group_key()) already gates on -- this method never
        decides whether communication IS protected, only reflects a
        decision ClientSession has already made. Hidden entirely for
        a group conversation: verification there is a per-member
        concern enforced at key-distribution time (see
        _distribute_group_key()'s Stage-3 gate), not a single state
        for the whole conversation the way a direct partner's is.

        Deliberately persistent, not a one-shot notification -- stays
        visible for as long as the conversation is open and the state
        warrants it, satisfying the requirement that a user blocked
        from protected communication is never left to wonder why.
        """

        if self.session.current_chat_is_group:

            self.verification_status_label.setVisible(False)

            self.verify_identity_button.setVisible(False)

            self.request_verification_button.setVisible(False)

            return

        partner = self.session.get_current_chat()

        if partner is None:

            self.verification_status_label.setVisible(False)

            self.verify_identity_button.setVisible(False)

            self.request_verification_button.setVisible(False)

            return

        state = self.session.get_peer_verification_state(partner)

        # Phase 19.22 -- Part B: request_verification_button (asking
        # the OTHER side to confirm THIS account's identity) is a
        # legitimate action alongside verify_identity_button (using
        # THIS account's own already-observed key for the peer) for
        # exactly the same two states -- never shown once already
        # VERIFIED (nothing left to ask), and never shown before any
        # identity has been observed at all (nothing to ask FROM).
        self.request_verification_button.setVisible(
            state in (PEER_STATE_UNVERIFIED, PEER_KEY_STATE_CHANGED)
        )

        if state == PEER_STATE_VERIFIED:

            self.verification_status_label.setText("✓ Verified")

            self.verification_status_label.setStyleSheet(
                f"font-size: 11px; font-weight: 700; color: {COLOR_ONLINE}; "
                "background: #2DC8A422; padding: 4px 9px; border-radius: 10px;"
            )

            self.verification_status_label.setVisible(True)

            self.verify_identity_button.setText("Re-verify")

            self.verify_identity_button.setVisible(True)

        elif state == PEER_KEY_STATE_CHANGED:

            self.verification_status_label.setText(
                "⚠ Security identity changed"
            )

            self.verification_status_label.setStyleSheet(
                f"font-size: 11px; font-weight: 700; color: {COLOR_DANGER}; "
                "background: #D9525222; padding: 4px 9px; border-radius: 10px;"
            )

            self.verification_status_label.setVisible(True)

            self.verify_identity_button.setText("Verify New Identity")

            self.verify_identity_button.setVisible(True)

        elif state == PEER_STATE_UNVERIFIED:

            self.verification_status_label.setText(
                "Identity not verified"
            )

            self.verification_status_label.setStyleSheet(
                f"font-size: 11px; font-weight: 700; color: {COLOR_CLASSICAL}; "
                "background: #C97A0A22; padding: 4px 9px; border-radius: 10px;"
            )

            self.verification_status_label.setVisible(True)

            self.verify_identity_button.setText("Verify Identity")

            self.verify_identity_button.setVisible(True)

        else:

            # No key has ever been received for this partner yet
            # (Offline First Contact) -- nothing to verify, and this
            # is explicitly NOT the same thing as UNVERIFIED (see
            # ClientSession.establish_session_key()'s Stage-3
            # docstring): showing a verification prompt for a peer
            # whose key hasn't even arrived would be misleading.
            self.verification_status_label.setVisible(False)

            self.verify_identity_button.setVisible(False)

    def handle_verify_identity(self):
        """
        Open VerifyIdentityDialog for the currently open direct
        partner (Server-Untrusted Identity Verification, Stage 3).

        The dialog is the only place confirm_peer_verification() is
        ever called, and only on an explicit confirming click inside
        it -- this method itself makes no trust decision, it only
        opens/refreshes the UI around one already made in
        ClientSession.
        """

        partner = self.session.get_current_chat()

        if partner is None or self.session.current_chat_is_group:
            return

        state = self.session.get_peer_verification_state(partner)

        dialog = VerifyIdentityDialog(self.session, partner, state, self)

        dialog.exec()

        self._update_verification_status()

    def handle_request_verification(self):
        """
        Ask the currently open direct partner to verify THIS account's
        identity (Phase 19.22 -- Part A/B: the async, Inbox-mediated
        counterpart to handle_verify_identity() above). Fire-and-
        forget, exactly like ClientSession.request_verification()
        itself -- the actual verification happens on the OTHER side
        when they Approve from their own Inbox (gui/inbox_dialog.py),
        never here.
        """

        partner = self.session.get_current_chat()

        if partner is None or self.session.current_chat_is_group:
            return

        try:
            self.session.request_verification(partner)
        except Exception as error:  # noqa: BLE001
            self.messages.add_system_message(f"Could not send verification request: {error}")
            return

        self.messages.add_system_message(f"Verification request sent to {partner}.")

    def handle_peer_key_changed(self, username):
        """
        A previously VERIFIED peer's key just changed (Server-
        Untrusted Identity Verification, Stage 2's peer_key_changed
        signal, first connected to the GUI in Stage 3).

        Refreshes the badge only if this is the conversation currently
        open -- otherwise the next open_conversation() picks up the
        correct state, exactly like handle_public_key_received().
        """

        if self.session.current_chat_is_group:
            return

        if username != self.session.get_current_chat():
            return

        self._update_verification_status()

    def handle_public_key_received(self, username):
        """
        A public key just arrived and was cached (BUG -- Public-Key
        Availability -- see ClientSession.public_key_received's
        docstring).

        Since BUG -- Offline First Contact, _update_composer_
        availability() no longer gates a direct conversation's
        composer on public-key availability at all, so this no longer
        changes whether the composer is enabled. Kept -- rather than
        removed -- because re-running _update_composer_availability()
        here is harmless and this remains the correct place to hook
        any future "a key just arrived" UI reaction for whichever
        conversation is currently open.

        Ignored for a group conversation (its composer's availability
        is never gated on a single peer's key -- see
        _update_composer_availability()) and for any username other
        than the one currently open.

        Server-Untrusted Identity Verification, Stage 3: also the
        point a first-contact key's arrival (UNVERIFIED) needs to
        become visible -- see _update_verification_status().
        """

        if self.session.current_chat_is_group:
            return

        if username != self.session.get_current_chat():
            return

        self._update_composer_availability()

        self._update_verification_status()

    def load_history(self, key, is_group=False):
        """
        Populate the message panel with this conversation's stored
        history. Runs once per conversation open, right after the
        panel is cleared -- live messages continue to arrive and
        append via the unchanged receive_message()/send_message()
        paths after this returns.

        Phase 19.24 (continued) -- Message Lifecycle Events survive a
        reload, not just a live in-session notification: a deleted
        message renders as a tombstone, an edited one shows its
        current text with "(edited)", a reply shows its quoted
        preview, and every reaction badge is restored -- all from the
        SAME already-decrypted/verified fields ClientSession.load_
        conversation_history() now returns per row, never a second
        network round trip per message.
        """

        history = self.session.load_conversation_history(key, is_group=is_group)

        # Reply previews are resolved locally, from whatever text this
        # SAME history batch already decrypted for the referenced
        # message -- never a second server round trip. A reply always
        # references an EARLIER message (chronological order, exactly
        # how history is returned), so by the time this loop reaches
        # the reply, the entry it points to has already been recorded
        # here. A reply to a message this account cannot see at all
        # (hidden-for-me, or simply older than this account's own
        # membership) is left with no preview -- set_reply_preview() is
        # just never called, matching MessageBubble's own "no preview
        # until one is explicitly supplied" default.
        preview_text_by_id = {}

        for entry in history:

            # BUG -- Timestamp/Timezone: entry["timestamp"] is naive
            # UTC (this app's canonical storage/wire convention -- see
            # ClientSession._parse_incoming_timestamp()). Converted to
            # local time here, for display only, before either the
            # clock text or the calendar date is derived from it --
            # otherwise a history-loaded message showed the raw UTC
            # hour (e.g. "15:06") while a message sent live in this
            # session showed local time (built from datetime.now()
            # directly), an apparent multi-hour mismatch that was
            # really just two different timezones being displayed side
            # by side. See gui/message_widget.py::to_local_time().
            timestamp = entry["timestamp"]

            local_timestamp = to_local_time(timestamp) if timestamp else None

            timestamp_text = (
                local_timestamp.strftime("%H:%M") if local_timestamp else None
            )

            # UI Finalization Decision 4 -- the calendar date a
            # DateSeparatorBubble anchors to, derived from the same
            # real (now local-converted) timestamp already available
            # here rather than a second server round trip. None for an
            # entry with no timestamp at all, exactly like
            # timestamp_text above -- MessageWidget.
            # _maybe_insert_date_separator() already treats None as
            # "don't touch the separator state". Using the LOCAL date
            # (not the UTC one) matters at day boundaries: a message
            # sent at 23:45 UTC is already the next calendar day in a
            # timezone ahead of UTC.
            message_date = local_timestamp.date() if local_timestamp else None

            payload_type = entry.get("payload_type", PayloadType.TEXT)

            # C2 -- Read Receipts: message_id/read_status are only
            # ever meaningful for entry["is_own"] rows (see
            # ClientSession.load_conversation_history()'s docstring);
            # read_status is already None for a received row, so
            # passing it through unconditionally is safe -- the bubble
            # classes only ever render it for kind="sent" regardless.
            message_id = entry.get("message_id")
            read_status = entry.get("read_status")

            # Phase 19.23 -- Issue 3: promote a not-yet-read own
            # message to the grey "✓✓ delivered" state using the
            # additive "delivery_status" field (server/client_handler.
            # py::_delivery_status_for_own_message()) -- this is what
            # makes DELIVERED survive reconnect/history-reload, not
            # just a live message_delivered packet this client might
            # have missed entirely (e.g. it was offline at the time).
            # Only ever touches the False case: None (no receipt data)
            # and True (read) already carry all the information there
            # is, and STATUS_FAILED is a purely local, never-persisted
            # state history can never report.
            if read_status is False and entry.get("delivery_status") == STATUS_DELIVERED:
                read_status = STATUS_DELIVERED

            is_deleted = entry.get("is_deleted", False)

            bubble = None
            preview_text = None

            if payload_type == PayloadType.TEXT:

                preview_text = entry["text"]

                if entry["is_own"]:

                    bubble = self.messages.add_sent_message(
                        entry["text"],
                        timestamp=timestamp_text,
                        message_id=message_id,
                        read_status=read_status,
                        message_date=message_date,
                    )

                else:

                    bubble = self.messages.add_received_message(
                        entry["sender"],
                        entry["text"],
                        timestamp=timestamp_text,
                        message_date=message_date,
                        message_id=message_id,
                    )

            else:

                content = entry.get("content")
                content_metadata = entry.get("content_metadata") or {}

                if content is None and not is_deleted:

                    # This client never received the epoch's key, or
                    # the blob is missing -- mirror the existing
                    # undecryptable-text placeholder rather than
                    # silently skipping it.
                    placeholder = "[Attachment unavailable]"
                    preview_text = placeholder

                    if entry["is_own"]:
                        bubble = self.messages.add_sent_message(
                            placeholder,
                            timestamp=timestamp_text,
                            message_id=message_id,
                            read_status=read_status,
                            message_date=message_date,
                        )
                    else:
                        bubble = self.messages.add_received_message(
                            entry["sender"], placeholder, timestamp=timestamp_text,
                            message_date=message_date,
                            message_id=message_id,
                        )

                elif payload_type == PayloadType.IMAGE:

                    preview_text = "[Image]"

                    if entry["is_own"]:
                        bubble = self.messages.add_sent_image(
                            content,
                            timestamp=timestamp_text,
                            message_id=message_id,
                            read_status=read_status,
                            content_metadata=content_metadata,
                            message_date=message_date,
                        )
                    else:
                        bubble = self.messages.add_received_image(
                            entry["sender"],
                            content,
                            timestamp=timestamp_text,
                            content_metadata=content_metadata,
                            message_date=message_date,
                            message_id=message_id,
                        )

                else:

                    preview_text = {
                        PayloadType.VOICE: "[Voice message]",
                        PayloadType.VIDEO: "[Video message]",
                    }.get(payload_type, "[File]")

                    if entry["is_own"]:
                        bubble = self.messages.add_sent_file(
                            content,
                            content_metadata,
                            timestamp=timestamp_text,
                            message_id=message_id,
                            read_status=read_status,
                            message_date=message_date,
                            payload_type=payload_type,
                        )
                    else:
                        bubble = self.messages.add_received_file(
                            entry["sender"], content, content_metadata, timestamp=timestamp_text,
                            message_date=message_date,
                            message_id=message_id,
                            payload_type=payload_type,
                        )

            if bubble is None:
                continue

            if message_id:
                preview_text_by_id[message_id] = preview_text

            # Phase 19.24 (continued): a deleted message's own edit/
            # reply/reactions state is irrelevant -- mark_deleted()
            # already renders the tombstone and clears whatever else
            # was set on the bubble at construction (none of it, here,
            # since it is applied BEFORE any of the calls below).
            if is_deleted:
                bubble.mark_deleted()
                continue

            edit_version = entry.get("edit_version", 0)

            if edit_version and bubble.supports_edit:
                bubble.apply_edit(entry.get("text") or "", edit_version)

            reply_to_message_id = entry.get("reply_to_message_id")

            if reply_to_message_id and hasattr(bubble, "set_reply_preview"):
                # ImageMessageBubble/FileMessageBubble have no reply-
                # preview label at all (only MessageBubble does) -- the
                # reply relationship is still correctly stored and
                # returned by the server regardless of which bubble
                # type is replying; only the quoted-snippet RENDERING
                # is TEXT-bubble-only today.
                referenced_preview = preview_text_by_id.get(reply_to_message_id)
                if referenced_preview:
                    bubble.set_reply_preview(referenced_preview)

            reactions = entry.get("reactions") or []

            if reactions:
                bubble.update_reactions(reactions)

            if entry.get("is_pinned"):
                bubble.set_pinned(True, entry.get("pinned_by"))

    # ------------------------------------------------------------------
    # Phase 19.24 (continued) -- Message Lifecycle Events UI.
    # ------------------------------------------------------------------

    def _handle_bubble_context_action(self, action, bubble):
        """
        Dispatches a chosen right-click menu action (gui/message_
        widget.py's _build_message_context_menu()) to the matching
        ClientSession call or composer state change. ``bubble`` is
        whichever concrete bubble class (MessageBubble/
        ImageMessageBubble/FileMessageBubble) the action was chosen
        on -- all three expose the same message_id/message_text/
        supports_edit/edit_version/kind surface this method relies on.

        Every ClientSession call here is fire-and-forget over an
        already-authenticated socket, exactly like send_chat_message()
        -- a raised exception (e.g. the socket dropped) is reported via
        show_error() and nothing is applied to the bubble speculatively;
        the actual state change (edit/delete/reaction) always arrives
        back through the server's own broadcast notification (handle_
        message_edited_received() etc. above), which reaches this
        sender's own client exactly like every other member's, since
        the server broadcasts lifecycle notifications to the full
        conversation membership without excluding the actor. The one
        exception is delete-for-me, which the server never broadcasts
        at all (it is a per-viewer-only preference) -- that one bubble
        update is applied directly below.
        """

        if action == "reply":

            self._editing_message_id = None

            self._pending_reply_message_id = bubble.message_id

            preview = getattr(bubble, "message_text", None) or "[Attachment]"

            shown = preview if len(preview) <= 80 else preview[:77] + "…"

            self.composer_context_label.setText(f"Replying to: {shown}")

            self.composer_context_bar.setVisible(True)

            self.input_bar.focus_input()

            return

        if action == "copy":

            text = getattr(bubble, "message_text", None)

            if text:
                QApplication.clipboard().setText(text)

            return

        if action == "forward":

            self._handle_forward_bubble(bubble)

            return

        if action == "react":

            self._handle_react_bubble(bubble)

            return

        if action == "pin":

            try:
                self.session.pin_message(bubble.message_id)
            except Exception as error:
                self.show_error(str(error))
                return

            # Applied optimistically here too (not only on the
            # server's own broadcast-back) so the ACTOR's own view
            # updates immediately, exactly like React/Reply's own
            # immediate local feedback -- the eventual message_pinned
            # notification (handle_message_pinned_received()) simply
            # re-applies the same state, a harmless no-op repeat.
            bubble.set_pinned(True)

            return

        if action == "unpin":

            try:
                self.session.unpin_message(bubble.message_id)
            except Exception as error:
                self.show_error(str(error))
                return

            bubble.set_pinned(False)

            return

        if action == "edit":

            if not bubble.supports_edit or bubble.kind != "sent":
                return

            self._pending_reply_message_id = None

            self._editing_message_id = bubble.message_id

            self._editing_expected_version = bubble.edit_version

            self.composer_context_label.setText("Editing message")

            self.composer_context_bar.setVisible(True)

            self.input_bar.set_text(bubble.message_text)

            self.input_bar.focus_input()

            return

        if action == "delete_me":

            try:
                self.session.delete_message_for_me(bubble.message_id)
            except Exception as error:
                self.show_error(str(error))
                return

            # No server broadcast for delete-for-me (server/client_
            # handler.py::handle_message_delete_for_me()'s own
            # docstring) -- this is the one lifecycle action this
            # client must apply to the bubble itself rather than wait
            # for a notification that will never arrive.
            bubble.mark_deleted()

            return

        if action == "delete_everyone":

            if bubble.kind != "sent":
                return

            if not self._confirm_delete_for_everyone():
                return

            self._do_delete_for_everyone(bubble)

            return

    def _confirm_delete_for_everyone(self):
        """
        Blocking Yes/No confirmation shown before a real, irreversible
        Delete-for-everyone request is sent (see message_lifecycle.md's
        own "what delete actually means" statement -- the server-side
        data minimization this triggers cannot be undone). Split out
        from _handle_bubble_context_action()/_do_delete_for_everyone()
        so tests can call _do_delete_for_everyone() directly and bypass
        only this modal, the same "bypass only the modal, call the
        real handler directly" convention this project already uses
        for the Attachment Menu/Mute popup/etc.
        """

        box = QMessageBox(self)

        box.setIcon(QMessageBox.Warning)

        box.setWindowTitle("Delete for Everyone?")

        box.setText(
            "This message will be permanently deleted for everyone in "
            "this conversation. This cannot be undone."
        )

        delete_button = box.addButton("Delete", QMessageBox.AcceptRole)

        box.addButton("Cancel", QMessageBox.RejectRole)

        box.exec()

        return box.clickedButton() == delete_button

    def _do_delete_for_everyone(self, bubble):
        """The actual Delete-for-everyone request, extracted so tests
        can call it directly without driving the confirmation dialog
        above."""

        try:
            self.session.delete_message_for_everyone(bubble.message_id)
        except Exception as error:
            self.show_error(str(error))

    def _handle_forward_bubble(self, bubble):
        """
        Ask (via ForwardDialog) which existing conversation to forward
        this bubble to, then hand off to _forward_bubble_to() -- split
        out so tests can drive the actual forward logic directly
        without needing to interact with a real modal dialog.
        """

        dialog = ForwardDialog(self.session, self)

        if dialog.exec() != QDialog.Accepted:
            return

        result = dialog.get_result()

        if result is None:
            return

        target_chat, target_is_group = result

        self._forward_bubble_to(bubble, target_chat, target_is_group)

    def _forward_bubble_to(self, bubble, target_chat, target_is_group):
        """
        Forward this bubble's content to ``target_chat`` (a username
        for a direct conversation, a conversation_id for a group --
        see domain/conversation_summary.py::ConversationSummary.key).
        Reuses ClientSession.forward_message() end to end -- see its
        own docstring for why this always produces a genuinely new,
        independently encrypted message under the target
        conversation's key rather than reusing this bubble's
        ciphertext.
        """

        try:

            if isinstance(bubble, MessageBubble):

                if not bubble.message_text:
                    return

                self.session.forward_message(
                    target_chat, target_is_group, PayloadType.TEXT,
                    bubble.message_text,
                )

            elif isinstance(bubble, ImageMessageBubble):

                self.session.forward_message(
                    target_chat, target_is_group, PayloadType.IMAGE,
                    bubble.image_bytes, content_metadata=bubble.content_metadata,
                )

            elif isinstance(bubble, FileMessageBubble):

                # FileMessageBubble also represents Voice/Video bubbles
                # (bubble.payload_type is VOICE/VIDEO in that case, see
                # gui/message_widget.py's own __init__) -- forward.
                # message() is fully payload-type-generic already (it
                # just swaps the send target before reusing the normal
                # send pipeline), so the only fix needed here is to
                # stop hardcoding FILE and forward the bubble's ACTUAL
                # payload type, so a forwarded voice/video message
                # keeps its voice/video identity (playback controls,
                # correct bubble label) on the target conversation
                # instead of silently degrading to a generic file.
                self.session.forward_message(
                    target_chat, target_is_group, bubble.payload_type,
                    bubble._file_bytes, content_metadata=bubble.content_metadata,
                )

        except Exception as error:
            self.show_error(str(error))

    def _handle_react_bubble(self, bubble):
        """
        Show a small emoji picker and, if the user chooses one, hand
        off to _send_reaction() -- split out so tests can drive the
        actual reaction send directly without needing to interact with
        a real popup menu.
        """

        conversation_id = self.session.current_conversation_id

        if conversation_id is None:
            return

        menu = QMenu(self)

        for emoji in ("\U0001F44D", "❤️", "\U0001F602", "\U0001F62E", "\U0001F622", "\U0001F64F"):
            menu.addAction(emoji).setData(emoji)

        chosen = menu.exec(self.mapToGlobal(self.rect().center()))

        if chosen is None:
            return

        self._send_reaction(bubble, chosen.data())

    def _send_reaction(self, bubble, emoji):
        """
        Set/replace this account's reaction on ``bubble``'s message.
        The reaction badge itself is never applied directly here -- it
        appears via the server's own reaction_updated notification
        (handle_reaction_updated_received() above), reaching this
        client's own view the same way it reaches every other member's.
        """

        conversation_id = self.session.current_conversation_id

        if conversation_id is None:
            return

        try:
            self.session.add_reaction(conversation_id, bubble.message_id, emoji)
        except Exception as error:
            self.show_error(str(error))

    def _clear_composer_context(self):
        """
        Cancel whichever of Reply/Edit is currently pending and hide
        the composer context bar -- called by its own "✕" button, and
        internally once an edit has actually been submitted.
        """

        self._pending_reply_message_id = None

        self._editing_message_id = None

        self._editing_expected_version = 0

        self.composer_context_label.setText("")

        self.composer_context_bar.setVisible(False)

        self.input_bar.clear_input()

    # ------------------------------------------------------------------
    # Phase 19.24 -- Typing Indicator.
    # ------------------------------------------------------------------

    def _on_composer_text_changed(self, text):
        """
        Debounced typing-indicator sender: arms on the FIRST keystroke
        after being idle (is_typing=True, once, not re-sent on every
        subsequent keystroke -- there is nothing more to tell the
        recipient), and re-arms a 3-second idle timer on every
        keystroke thereafter. Clearing the composer entirely (text
        deleted back to empty) is itself treated as "stopped typing"
        immediately, without waiting for the idle timer -- the empty
        composer is already unambiguous evidence.

        A no-op with no conversation open (nothing to announce typing
        in) -- this fires from a plain Qt textChanged signal, which
        does not know or care whether a chat is currently selected.
        """

        conversation_id = self.session.current_conversation_id

        if conversation_id is None or self.session.current_chat is None:
            return

        if not text:
            self._stop_typing_immediately()
            return

        if not self._typing_active:
            self._typing_active = True
            self.session.send_typing_indicator(conversation_id, True)

        self._typing_stop_timer.start()

    def _send_typing_stopped(self):
        """Idle-timeout fire: the user stopped typing without sending
        (switched away, walked off, or is just thinking) -- see
        _on_composer_text_changed()'s own docstring for the full
        debounce contract this is one half of."""

        self._stop_typing_immediately()

    def _stop_typing_immediately(self):
        """Shared by the idle timeout, an actual send, and clearing the
        composer back to empty -- tells the server typing has stopped
        exactly once per is_typing=True already sent, never redundantly
        (self._typing_active is what makes this idempotent)."""

        self._typing_stop_timer.stop()

        if not self._typing_active:
            return

        self._typing_active = False

        conversation_id = self.session.current_conversation_id

        if conversation_id is not None:
            self.session.send_typing_indicator(conversation_id, False)

    def _on_connection_changed_stop_typing_timers(self, connected):
        """
        A disconnect (explicit logout, or a mid-session drop the
        receiver thread detected -- connection_changed's own docstring
        above) must stop EVERY typing-related QTimer this window owns,
        not just clear state: self._typing_stop_timer (this account's
        own idle-typing timer) and every per-sender expiry timer in
        self._typing_senders (mirrors mobile/app.py's identical
        session-scoped cleanup need). A timer left armed across a
        disconnect would otherwise still fire at its original real-
        time deadline -- for _typing_stop_timer, calling send_
        typing_indicator() on a connection that is no longer there
        (already a safe no-op -- see ClientSession.send_typing_
        indicator()'s own "not self.connected" guard -- but pointless
        to attempt at all); for a per-sender timer, nothing unsafe,
        just delayed cleanup work this makes immediate instead. A
        no-op on connected=True -- there is nothing to clean up when a
        connection is (re-)established.
        """

        if connected:
            return

        self._typing_stop_timer.stop()

        for senders in self._typing_senders.values():
            for timer in senders.values():
                timer.stop()

        self._typing_senders = {}

    def handle_typing_indicator_received(self, conversation_id, username, is_typing):
        """
        A live typing hint arrived for SOME conversation -- only acted
        on (rendered) when it is the one currently open; a conversation
        not on screen right now needs no indicator, and this is purely
        a live signal with nothing to catch up on later (mirrors every
        other "live hint only" handler in this file, e.g. handle_
        read_receipt_updated()'s identical gating).

        Per-sender auto-expiry (self._typing_senders[conversation_id]
        [username], a QTimer restarted on every is_typing=True for that
        exact sender): if this sender's connection drops mid-type, the
        matching is_typing=False this method would otherwise wait for
        forever never arrives -- this is what keeps a stale "X is
        typing..." from lingering on screen indefinitely, and (for a
        group) keeps one silent sender from blocking another's own
        indicator from clearing correctly.
        """

        if conversation_id != self.session.current_conversation_id:
            return

        senders = self._typing_senders.setdefault(conversation_id, {})

        existing_timer = senders.get(username)

        if is_typing:

            if existing_timer is None:
                existing_timer = QTimer(self)
                existing_timer.setSingleShot(True)
                existing_timer.timeout.connect(
                    lambda: self._expire_typing_sender(conversation_id, username)
                )
                senders[username] = existing_timer

            existing_timer.start(5000)

        else:

            if existing_timer is not None:
                existing_timer.stop()

            senders.pop(username, None)

        self._render_typing_status(conversation_id)

    def _expire_typing_sender(self, conversation_id, username):
        """A typing sender's own 5-second auto-expiry fired -- see
        handle_typing_indicator_received()'s own docstring for why this
        exists (a dropped connection mid-type never sends the matching
        is_typing=False)."""

        senders = self._typing_senders.get(conversation_id)

        if senders is not None:
            senders.pop(username, None)

        self._render_typing_status(conversation_id)

    def _render_typing_status(self, conversation_id):
        """Renders self.typing_status_label from self._typing_senders'
        current state for ``conversation_id`` -- a no-op (label stays
        as it already is) if that conversation is not the one currently
        open, since this is only ever meaningful for the on-screen
        conversation."""

        if conversation_id != self.session.current_conversation_id:
            return

        senders = self._typing_senders.get(conversation_id) or {}
        names = sorted(senders.keys())

        if not names:
            text = ""
        elif len(names) == 1:
            text = f"{names[0]} is typing…"
        elif len(names) == 2:
            text = f"{names[0]} and {names[1]} are typing…"
        else:
            text = f"{len(names)} people are typing…"

        self.typing_status_label.setText(text)
        self.typing_status_label.setVisible(bool(text))

    def send_message(self, message, reply_to_message_id=None):

        if self.session.get_current_chat() is None:

            QMessageBox.warning(
                self,
                "No User Selected",
                "Please select an online user."
            )

            return

        # Phase 19.24 -- Typing Indicator: an actual send (ordinary or
        # edit) always ends any outstanding is_typing=True immediately
        # -- never left to the idle timer, since the recipient(s)
        # already have unambiguous, stronger evidence (the message
        # itself) that typing has stopped.
        self._stop_typing_immediately()

        if self._editing_message_id is not None:

            message_id = self._editing_message_id

            expected_version = self._editing_expected_version

            conversation_id = self.session.current_conversation_id

            self._clear_composer_context()

            try:
                self.session.edit_message(conversation_id, message_id, message, expected_version)
            except Exception as error:
                self.show_error(str(error))

            return

        if reply_to_message_id is None:
            reply_to_message_id = self._pending_reply_message_id

        self._pending_reply_message_id = None

        self.composer_context_label.setText("")

        self.composer_context_bar.setVisible(False)

        # Phase 19.24 -- Message Retry idempotency: generated BEFORE
        # the risky send call, not read back from its return value, so
        # it is still available to attach to the FAILED bubble even
        # when send_chat_message() raises before ever returning
        # anything -- see ClientSession._send_encrypted_payload()'s own
        # docstring. A later retry of this exact bubble reuses this
        # SAME id (see _retry_failed_message() below), so the server
        # can recognize a retry-after-an-actually-successful-send as
        # the same message rather than a duplicate.
        client_message_id = str(uuid.uuid4())

        try:

            self.session.send_chat_message(
                message,
                reply_to_message_id=reply_to_message_id,
                client_message_id=client_message_id,
            )

        except PeerNotVerifiedError as error:

            # Server-Untrusted Identity Verification, Stage 3: caught
            # BEFORE the generic Exception handler below, specifically
            # so the user gets a direct path to resolve this rather
            # than just an acknowledgment -- see
            # _show_peer_not_verified_dialog(). The bubble is still
            # added as FAILED, exactly like any other blocked send,
            # so the drafted text is never silently lost.
            bubble = self.messages.add_sent_message(
                message,
                read_status=STATUS_FAILED,
                on_retry=self._retry_failed_message,
                message_date=datetime.now().date(),
            )
            bubble.client_message_id = client_message_id

            self._show_peer_not_verified_dialog(error)

            return

        except Exception as error:

            # Task 2 -- the bubble is added for a FAILED send too, not
            # just dropped behind a dialog. Previously the message
            # simply vanished from the transcript, so a user whose
            # connection dropped mid-send had no record that they had
            # ever written it, and no way to copy the text back out.
            #
            # STATUS_FAILED here is a fact, not a guess: send_chat_
            # message() raised, so the ciphertext never reached the
            # server. This is the one failure the sender can attribute
            # to a specific message with certainty -- the asynchronous
            # delivery_failure packet carries only a receiver and a
            # reason, no message identity, so it stays on show_error()
            # rather than guessing which bubble it belongs to.
            #
            # on_retry makes the failure recoverable rather than merely
            # visible: the bubble keeps the text and offers to send it
            # again, so a dropped connection costs the user nothing.
            bubble = self.messages.add_sent_message(
                message,
                read_status=STATUS_FAILED,
                on_retry=self._retry_failed_message,
                message_date=datetime.now().date(),
            )
            bubble.client_message_id = client_message_id

            self.show_error(str(error))

            return

        # False, not None: "the server accepted this over TLS", which
        # is what a single tick means. Not True, and not a grey double
        # tick -- neither delivery nor reading has been reported by
        # anybody yet. A read_receipt_notification later promotes this
        # bubble to ✓✓ in place via MessageWidget.mark_sent_read().
        self.messages.add_sent_message(
            message, read_status=False, message_date=datetime.now().date()
        )

    def _retry_failed_message(self, bubble):
        """
        Re-send the text of a bubble whose original send failed
        (Task 2).

        Called by MessageBubble's Retry button. The bubble is only
        cleared of its failed state if send_chat_message() returns
        without raising -- the same single fact the original send is
        judged by, so a retry can never leave the transcript claiming
        more than actually happened.

        A retry into a different conversation is refused rather than
        silently redirected: the failed bubble belongs to the
        conversation it was written in, and send_chat_message() always
        targets whatever chat is currently open.
        """

        if self.session.get_current_chat() is None:

            self.show_error(
                "Select the conversation again before retrying."
            )

            return

        try:
            # Phase 19.24: reuses the SAME client_message_id the
            # original (failed) attempt was given -- see send_message()
            # above -- so persist_message() on the server recognizes
            # this as the same message if, against expectation, the
            # original attempt actually did reach it.
            self.session.send_chat_message(
                bubble.message_text,
                client_message_id=getattr(bubble, "client_message_id", None),
            )
        except PeerNotVerifiedError as error:
            self._show_peer_not_verified_dialog(error)
            return
        except Exception as error:
            self.show_error(str(error))
            return

        bubble.mark_retry_succeeded()

    def handle_attachment_selected(self, file_path):
        """
        Send a locally-picked file/image as the next message in the
        open conversation (Phase 8 -- File & Image Transfer).
        Classification (IMAGE vs. FILE) happens inside
        ClientSession.send_attachment() -- this method never decides
        it. Renders the local "sent" bubble from the same bytes
        send_attachment() already read, rather than reading the file
        a second time.
        """

        if self.session.get_current_chat() is None:

            QMessageBox.warning(
                self,
                "No User Selected",
                "Please select a conversation."
            )

            return

        try:

            payload_type, content, content_metadata = (
                self.session.send_attachment(file_path)
            )

        except PeerNotVerifiedError as error:

            # Server-Untrusted Identity Verification, Stage 3: caught
            # ahead of the generic (OSError, ValueError) branch below
            # -- PeerNotVerifiedError is itself a ValueError (see its
            # docstring) and would otherwise be caught there too, just
            # without the direct path to resolve it.
            self._show_peer_not_verified_dialog(error)

            return

        except (OSError, ValueError) as error:

            self.show_error(str(error))

            return

        if payload_type == PayloadType.IMAGE:
            self.messages.add_sent_image(
                content, content_metadata=content_metadata,
                message_date=datetime.now().date(),
            )
        else:
            self.messages.add_sent_file(
                content, content_metadata, message_date=datetime.now().date(),
                payload_type=payload_type,
            )

    def handle_recorded_media_selected(self, temp_file_path):
        """
        Phase 19.24 -- Voice/Video Messages: send a just-recorded clip
        (gui/input_bar.py::MediaRecorderDialog already wrote it to a
        real local temp file -- QMediaRecorder has no in-memory
        recording mode) through the EXACT SAME path an ordinary picked
        file/image already goes through -- classification (PayloadType.
        VOICE/VIDEO, by mime type) happens inside ClientSession.
        send_attachment(), exactly like IMAGE/FILE. The temp recording
        is deleted here once its bytes are safely read into memory and
        encrypted -- whether the send succeeded or failed, there is no
        reason for the plaintext recording to linger on disk any
        longer than an ordinary picked file already would.
        """

        try:
            self.handle_attachment_selected(temp_file_path)
        finally:
            try:
                Path(temp_file_path).unlink(missing_ok=True)
            except OSError:
                pass

    def receive_message(self, conversation_key, sender, message):
        """
        ``conversation_key`` identifies which conversation this
        belongs to (a username for direct, a conversation_id for
        group -- see ClientSession.handle_chat()); ``sender`` is
        always the individual who wrote it, used only for display.
        For a direct message the two are the same value, so this
        check behaves exactly as it did before Phase 4.
        """

        if sender == "system":

            self.messages.add_system_message(
                message
            )

            return

        if conversation_key != self.session.get_current_chat():

            # This message belongs to a different conversation. It is
            # already correctly persisted and will be shown when that
            # conversation is opened -- the currently open conversation
            # must stay completely unchanged. Track it as unread
            # instead, then re-render through the single sidebar
            # render path (ConversationStore already recorded this
            # message's preview via ClientSession.handle_chat()).
            self.session.increment_unread(conversation_key)

            self.render_conversations()

            return

        # Phase 19.24 (continued) -- kept so handle_incoming_message_id_
        # resolved() (fired from the SEPARATE message_id_received signal
        # this same "chat" packet also triggers, right after this one)
        # can attach the real message_id to THIS exact bubble.
        self._last_received_bubble = self.messages.add_received_message(
            sender,
            message,
            message_date=datetime.now().date(),
        )

        # BUG -- Read Receipt Real-Time Update: this message is being
        # displayed into the conversation the user is actually looking
        # at right now (the branch above already returned for any
        # other conversation), so it is read the instant it appears --
        # see _mark_current_conversation_read()'s docstring.
        self._mark_current_conversation_read()

    def receive_payload_message(
        self, conversation_key, sender, payload_type, content, content_metadata
    ):
        """
        Display a received file/image (Phase 8 -- File & Image
        Transfer). Mirrors receive_message()'s unread/current-
        conversation handling exactly -- the two differ only in what
        they hand to MessageWidget at the end, since binary content
        cannot flow through message_received (see ClientSession's
        payload_message_received declaration).
        """

        if conversation_key != self.session.get_current_chat():

            self.session.increment_unread(conversation_key)

            self.render_conversations()

            return

        if payload_type == PayloadType.IMAGE:
            self._last_received_bubble = self.messages.add_received_image(
                sender, content, content_metadata=content_metadata,
                message_date=datetime.now().date(),
            )
        else:
            self._last_received_bubble = self.messages.add_received_file(
                sender, content, content_metadata,
                message_date=datetime.now().date(),
                payload_type=payload_type,
            )

        # BUG -- Read Receipt Real-Time Update: see receive_message()'s
        # identical call for the full rationale.
        self._mark_current_conversation_read()

    def handle_incoming_message_id_resolved(self, conversation_key, message_id):
        """
        Phase 19.24 (continued) -- the real, server-assigned id for the
        message receive_message()/receive_payload_message() most
        recently rendered into the CURRENTLY open conversation (see
        ClientSession's message_id_received signal declaration for why
        this arrives as a second, separate signal rather than bundled
        into message_received/payload_message_received). Ignored for
        any other conversation -- a message aimed elsewhere gets its id
        the next time that conversation is opened, via load_history().
        """

        if conversation_key != self.session.get_current_chat():
            return

        if self._last_received_bubble is None:
            return

        self.messages.register_received_bubble_id(
            self._last_received_bubble, message_id
        )

        self._last_received_bubble = None

    def handle_read_receipt_updated(self, conversation_id, reader):
        """
        A live "someone read up to now" hint arrived (C2 -- Read
        Receipts). Ignored if it's not for the conversation currently
        on screen -- compared against current_conversation_id (the
        real conversation_id ClientSession.set_current_chat() already
        resolves), not get_current_chat() (which is a partner
        *username* for a direct conversation, not its conversation_id).

        Direct: the one other party has, by definition, just read
        every message they could see -- flip every sent bubble
        immediately. Group: accumulate readers and only flip once
        every currently-active participant (ConversationStore's own
        already-left-member-excluded list -- see
        ConversationStore.update_group_participants()) has been
        accounted for, per your "double-check only when all active
        recipients have read" decision. A departed member is simply
        never in that list, so they can never block it.
        """

        if conversation_id != self.session.current_conversation_id:
            return

        self._read_receipt_readers.add(reader)

        if not self.session.current_chat_is_group:
            self.messages.mark_all_sent_read()
            return

        summary = self.session.conversation_store.get(conversation_id)

        active_participants = set(summary.participants or []) if summary else set()

        if active_participants and self._read_receipt_readers.issuperset(active_participants):
            self.messages.mark_all_sent_read()

    def handle_message_delivered_updated(self, conversation_id, receiver):
        """
        Phase 19.23 -- Issue 3: a live message_delivered packet arrived
        (ClientSession.handle_message_delivered()). Ignored if it's not
        for the conversation currently on screen -- identical gating to
        handle_read_receipt_updated() above, for the identical reason
        (a conversation not open now will simply show the correct
        status, via history's own new delivery_status field, the next
        time it is opened).

        Direct messages only -- group sends get no per-recipient
        delivered ack at all (server/client_handler.py's relay branch
        that emits this packet is direct-only), so this is never
        called while a group conversation is open in practice; the
        explicit guard just makes that stated, not assumed.
        """

        if conversation_id != self.session.current_conversation_id:
            return

        if self.session.current_chat_is_group:
            return

        self.messages.mark_oldest_undelivered_sent()

    def handle_own_message_id_resolved(self, conversation_id, message_id):
        """
        Phase 19.24 (continued) -- the first time this client learns a
        just-sent (direct) message's REAL, server-assigned id -- see
        ClientSession.own_message_id_resolved's own docstring for why
        message_delivered/message_queued are what carries this. Same
        gating as handle_message_delivered_updated() above, for the
        identical reason: a conversation not open now gets the right
        id the next time it IS opened, via history reload.
        """

        if conversation_id != self.session.current_conversation_id:
            return

        if self.session.current_chat_is_group:
            return

        self.messages.resolve_oldest_live_bubble_id(message_id)

    def handle_message_edited_received(self, conversation_id, message_id, new_text, editor, edited_at, edit_version):
        """Phase 19.24 (continued) -- a message was edited (this
        client's own signature verification already ran inside
        ClientSession.handle_message_edited() before this signal was
        even emitted -- see that method's own docstring). Ignored for
        a conversation not currently open; the next history reload of
        that conversation already reflects the edit regardless."""

        if conversation_id != self.session.current_conversation_id:
            return

        self.messages.apply_edit_to_message(message_id, new_text, edit_version)

    def handle_message_deleted_received(self, conversation_id, message_id, deleted_by, deleted_at):
        """Phase 19.24 (continued) -- a message was deleted for
        everyone. Same conversation-open gating as the edit handler
        above."""

        if conversation_id != self.session.current_conversation_id:
            return

        self.messages.mark_message_deleted(message_id)

    def handle_reaction_updated_received(self, conversation_id, message_id, actor, action, reaction):
        """Phase 19.24 (continued) -- a reaction was added or removed.
        Maintains this window's own per-message reaction list (the
        bubble itself only ever displays a SUMMARY via update_
        reactions(); this dict is the source of truth kept in sync by
        every add/remove notification, direct-conversation-open gating
        matching every other live lifecycle-event handler above)."""

        if conversation_id != self.session.current_conversation_id:
            return

        bubble = self.messages.get_bubble(message_id)

        if bubble is None:
            return

        reactions = [r for r in bubble.reactions if r.get("user") != actor]

        if action == "add":
            reactions.append({"user": actor, "reaction": reaction})

        self.messages.update_message_reactions(message_id, reactions)

    # ==========================================================
    # Phase 19.24 -- Presence/Last Seen
    # ==========================================================

    def handle_online_users_updated(self, users):
        """session.users_updated is already an efficient, server-
        pushed event (fires on every connect/disconnect anywhere on
        the server) -- no polling is added here, this just re-renders
        the currently open direct conversation's own presence line
        whenever that event arrives."""

        self._refresh_presence_label(users)

    def _refresh_presence_label(self, users=None):
        peer = self._current_direct_peer_username

        if peer is None:
            self.presence_label.setText("")
            return

        if users is None:
            users = self.session.get_online_users()

        if peer in users:
            self.presence_label.setStyleSheet(f"font-size: 10px; color: {COLOR_ONLINE};")
            self.presence_label.setText("Online")
            return

        self.presence_label.setStyleSheet(f"font-size: 10px; color: {COLOR_TEXT_MUTED};")
        self.presence_label.setText("")

        try:
            last_seen = self.session.fetch_last_seen(peer)
        except Exception:  # noqa: BLE001
            return

        # fetch_last_seen() is a blocking round trip -- the open
        # conversation may already be a DIFFERENT one by the time it
        # returns; never apply a stale result to it.
        if self._current_direct_peer_username != peer:
            return

        if last_seen is None:
            return

        local_time = to_local_time(last_seen)
        today = datetime.now().date()

        if local_time.date() == today:
            text = f"Last seen today at {local_time.strftime('%H:%M')}"
        elif (today - local_time.date()).days == 1:
            text = f"Last seen yesterday at {local_time.strftime('%H:%M')}"
        else:
            text = f"Last seen {local_time.strftime('%d %b %Y, %H:%M')}"

        self.presence_label.setText(text)

    def handle_message_pinned_received(self, conversation_id, message_id, pinned_by, pinned_at):
        """Phase 19.24 -- Pinned Messages: a message was pinned. Same
        conversation-open gating as every other live lifecycle-event
        handler above -- a no-op notification for a conversation that
        is not currently open simply has no rendered bubble to update
        (apply_pin_to_message() is itself a safe no-op in that case
        too, this early return just avoids the pointless lookup)."""

        if conversation_id != self.session.current_conversation_id:
            return

        self.messages.apply_pin_to_message(message_id, True, pinned_by)

    def handle_message_unpinned_received(self, conversation_id, message_id, unpinned_by):
        """Phase 19.24 -- Pinned Messages: a message was unpinned."""

        if conversation_id != self.session.current_conversation_id:
            return

        self.messages.apply_pin_to_message(message_id, False)

    def show_error(self, message):
        """
        Report an operation that was actually attempted and failed
        (a send, an attachment read, a read-receipt round trip) --
        always a modal dialog, since these need explicit
        acknowledgment rather than a passive status line.

        This is deliberately distinct from
        MessageWidget.add_system_message(), which this window uses for
        ambient, non-blocking information -- a conversation being
        opened, a join/leave event relayed by the server, the BUG 1
        key-store notice. Nothing here has failed in that case; there
        is nothing to acknowledge, only to be aware of.
        """

        QMessageBox.critical(
            self,
            "Error",
            message
        )

    def handle_security_rejection(self, reason, sender, conversation_id):
        """
        Phase 14.1 -- Security Rejection GUI: the sole GUI consumer of
        ClientSession.security_rejection. Nothing here makes a
        security decision -- the packet was already rejected, and no
        trusted key or identity state was already altered, before this
        signal was ever emitted (see security_rejection's own
        docstring on ClientSession). This method's only job is
        translating that already-made decision into a safe, visible,
        non-blocking notice.

        Deliberately non-blocking (StatusBarWidget.set_security_notice(),
        not show_error()'s QMessageBox): this event was never something
        the user attempted and needs to acknowledge -- it is ambient
        background information about incoming traffic, exactly the
        category show_error()'s own docstring says belongs to a
        passive notice rather than a modal. A modal here would also
        let a malicious server force repeated dialogs onto the user
        just by resending forged packets.

        ``reason`` is looked up in SECURITY_REJECTION_MESSAGES, never
        displayed raw, and an unrecognized value (a future reason this
        GUI does not yet know about) falls back to a generic-but-still-
        accurate message rather than silently doing nothing or
        crashing. ``sender``/``conversation_id`` are the packet's own
        UNTRUSTED, attacker-influenceable claims -- see this method's
        own restraint below: neither is echoed into the notice text,
        so nothing attacker-controlled ever reaches the display.
        """

        if reason == "duplicate_or_stale_key":
            # Not an attack: an already-trusted, already-authenticated
            # sender re-sent something this client already has. Worth
            # logging (already done, backend-side); not worth alarming
            # the user about.
            return

        message = SECURITY_REJECTION_MESSAGES.get(
            reason, "it failed a security check"
        )

        self.status.set_security_notice(
            f"Security warning: an incoming packet was rejected -- {message}. "
            f"No trusted key or identity state was changed."
        )

    def _show_peer_not_verified_dialog(self, error):
        """
        Report a send blocked by PeerNotVerifiedError (Server-
        Untrusted Identity Verification, Stage 3) -- deliberately
        distinct from show_error(): a bare acknowledgment would leave
        the user knowing WHY but not what to do about it, so this
        modal offers a direct action instead of only a message. This
        is the reactive counterpart to the persistent header badge
        (_update_verification_status()) -- that badge is the proactive
        warning shown before the user even tries to send; this dialog
        is what they see if they try anyway.
        """

        box = QMessageBox(self)

        box.setIcon(QMessageBox.Warning)

        box.setWindowTitle("Identity Not Verified")

        box.setText(str(error))

        verify_button = box.addButton(
            "Verify Identity", QMessageBox.AcceptRole
        )

        box.addButton("Close", QMessageBox.RejectRole)

        box.exec()

        if box.clickedButton() == verify_button:
            self.handle_verify_identity()