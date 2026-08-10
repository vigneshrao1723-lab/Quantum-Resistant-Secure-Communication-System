"""
Chat Window

Main chat interface for the Quantum-Resistant
Secure Communication System.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QFrame,
    QDialog,
    QHBoxLayout,
    QVBoxLayout,
    QMessageBox,
    QPushButton,
)

from gui.conversation_list_widget import ConversationListWidget
from gui.create_group_dialog import CreateGroupDialog
from gui.message_widget import MessageWidget
from gui.input_bar import InputBar
from gui.status_bar import StatusBarWidget
from gui.styles import COLOR_TEXT_MUTED


class ChatWindow(QWidget):
    """
    Main chat interface.
    """

    logout_requested = Signal()

    def __init__(self, session):
        super().__init__()

        self.session = session

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

        users_title = QLabel("CONVERSATIONS")

        users_title.setObjectName("SectionTitle")

        self.new_group_button = QPushButton("+ Group")

        self.new_group_button.setCursor(Qt.PointingHandCursor)

        self.new_group_button.clicked.connect(
            self.handle_create_group
        )

        conversations_header = QHBoxLayout()

        conversations_header.addWidget(users_title)

        conversations_header.addStretch()

        conversations_header.addWidget(self.new_group_button)

        self.conversation_list = ConversationListWidget()

        left_layout.addLayout(conversations_header)

        left_layout.addWidget(self.conversation_list)

        # -----------------------------
        # Right Panel
        # -----------------------------

        right_layout = QVBoxLayout()

        right_layout.setSpacing(12)

        # Header: app title + current chat partner

        header = QFrame()

        header.setObjectName("Panel")

        header_layout = QVBoxLayout(header)

        header_layout.setContentsMargins(18, 12, 18, 12)

        header_layout.setSpacing(2)

        app_title = QLabel("Quantum-Resistant Secure Chat")

        app_title.setStyleSheet(
            "font-size: 15px; font-weight: 700;"
        )

        self.logout_button = QPushButton("Logout")

        self.logout_button.setCursor(Qt.PointingHandCursor)

        self.logout_button.clicked.connect(
            self.logout_requested.emit
        )

        header_top_row = QHBoxLayout()

        header_top_row.addWidget(app_title)

        header_top_row.addStretch()

        header_top_row.addWidget(self.logout_button)

        self.chat_partner_label = QLabel(
            "Select a user to start chatting"
        )

        self.chat_partner_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 10pt;"
        )

        header_layout.addLayout(header_top_row)

        header_layout.addWidget(self.chat_partner_label)

        # Messages panel

        messages_panel = QFrame()

        messages_panel.setObjectName("Panel")

        messages_panel_layout = QVBoxLayout(messages_panel)

        messages_panel_layout.setContentsMargins(4, 4, 4, 4)

        self.messages = MessageWidget()

        messages_panel_layout.addWidget(self.messages)

        # Input bar

        self.input_bar = InputBar()

        self.input_bar.set_enabled(False)

        # Status bar

        self.status = StatusBarWidget()

        right_layout.addWidget(header)

        right_layout.addWidget(messages_panel, stretch=1)

        right_layout.addWidget(self.input_bar)

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

        self.input_bar.message_sent.connect(
            self.send_message
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

        self.session.error_occurred.connect(
            self.show_error
        )

        # -----------------------------------------
        # Sync UI with current session state
        # -----------------------------------------

        self.session.load_conversations()

    def render_conversations(self):
        """
        Re-render the sidebar from ConversationStore -- the single
        source of truth for conversation state. This is the only
        place the sidebar widget is populated; nothing else in this
        class (or anywhere else) mutates it directly.
        """

        summaries = self.session.conversation_store.get_all()

        self.conversation_list.render(summaries)

        for summary in summaries:

            self.conversation_list.set_unread_count(
                summary.key,
                self.session.get_unread_count(summary.key)
            )

    # ==========================================================
    # Events
    # ==========================================================

    def handle_create_group(self):
        """
        Open the group-creation dialog and, if confirmed with a name
        and at least one member, ask the session to create it. The
        new group appears in the sidebar asynchronously, once the
        server confirms it (see ClientSession.handle_group_create_result())
        -- there is no optimistic local update here.
        """

        dialog = CreateGroupDialog(self.session.get_online_users(), self)

        if dialog.exec() == QDialog.Accepted:

            name, member_usernames = dialog.get_result()

            if name and member_usernames:
                self.session.create_group_conversation(name, member_usernames)

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

        self.session.set_current_chat(summary)

        self.session.clear_unread(key)

        self.render_conversations()

        display_name = summary.group_name if summary.is_group else summary.username

        label = (
            f"Group: {display_name}" if summary.is_group
            else f"Chatting with {display_name}"
        )

        self.chat_partner_label.setText(label)

        self.input_bar.set_enabled(True)

        self.input_bar.focus_input()

        self.messages.clear_messages()

        self.messages.add_system_message(label)

        self.load_history(key, summary.is_group)

    def load_history(self, key, is_group=False):
        """
        Populate the message panel with this conversation's stored
        history. Runs once per conversation open, right after the
        panel is cleared -- live messages continue to arrive and
        append via the unchanged receive_message()/send_message()
        paths after this returns.
        """

        history = self.session.load_conversation_history(key, is_group=is_group)

        for entry in history:

            timestamp = entry["timestamp"]

            timestamp_text = (
                timestamp.strftime("%H:%M") if timestamp else None
            )

            if entry["is_own"]:

                self.messages.add_sent_message(
                    entry["text"],
                    timestamp=timestamp_text
                )

            else:

                self.messages.add_received_message(
                    entry["sender"],
                    entry["text"],
                    timestamp=timestamp_text
                )

    def send_message(self, message):

        if self.session.get_current_chat() is None:

            QMessageBox.warning(
                self,
                "No User Selected",
                "Please select an online user."
            )

            return

        try:

            self.session.send_chat_message(message)

            self.messages.add_sent_message(
                message
            )

        except Exception as error:

            self.show_error(str(error))

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

        self.messages.add_received_message(
            sender,
            message
        )

    def show_error(self, message):

        QMessageBox.critical(
            self,
            "Error",
            message
        )