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
    QHBoxLayout,
    QVBoxLayout,
    QMessageBox,
    QPushButton,
)

from gui.online_users_widget import OnlineUsersWidget
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

        users_title = QLabel("ONLINE USERS")

        users_title.setObjectName("SectionTitle")

        self.online_users = OnlineUsersWidget()

        left_layout.addWidget(users_title)

        left_layout.addWidget(self.online_users)

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

        self.online_users.user_selected.connect(
            self.user_selected
        )

        self.input_bar.message_sent.connect(
            self.send_message
        )

    # ==========================================================
    # Backend Callbacks
    # ==========================================================

    def register_callbacks(self):

        self.session.users_updated.connect(
            self.handle_users_updated
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

        self.handle_users_updated(
            self.session.get_online_users()
        )

    def handle_users_updated(self, users):
        """
        Refresh the online users list, then reapply each user's
        current unread badge -- update_users() rebuilds the row
        widgets from scratch, which would otherwise silently drop
        any badge already being shown.
        """

        self.online_users.update_users(users)

        for username in users:

            self.online_users.set_unread_count(
                username,
                self.session.get_unread_count(username)
            )

    # ==========================================================
    # Events
    # ==========================================================

    def user_selected(self, username):

        self.session.set_current_chat(username)

        self.session.clear_unread(username)

        self.online_users.set_unread_count(username, 0)

        self.chat_partner_label.setText(
            f"Chatting with {username}"
        )

        self.input_bar.set_enabled(True)

        self.input_bar.focus_input()

        self.messages.clear_messages()

        self.messages.add_system_message(
            f"Chatting with {username}"
        )

        self.load_history(username)

    def load_history(self, username):
        """
        Populate the message panel with this conversation's stored
        history. Runs once per conversation open, right after the
        panel is cleared -- live messages continue to arrive and
        append via the unchanged receive_message()/send_message()
        paths after this returns.
        """

        history = self.session.load_conversation_history(username)

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

    def receive_message(self, sender, message):

        if sender == "system":

            self.messages.add_system_message(
                message
            )

            return

        if sender != self.session.get_current_chat():

            # This message belongs to a different conversation. It is
            # already correctly persisted (Milestone 2) and will be
            # shown when that conversation is opened (Milestone 3's
            # history load) -- the currently open conversation must
            # stay completely unchanged. Track it as unread instead.
            unread_count = self.session.increment_unread(sender)

            self.online_users.set_unread_count(sender, unread_count)

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