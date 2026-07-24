"""
Chat Window

Main chat interface for the Quantum-Resistant
Secure Communication System.
"""

from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QHBoxLayout,
    QVBoxLayout,
    QMessageBox,
)

from gui.online_users_widget import OnlineUsersWidget
from gui.message_widget import MessageWidget
from gui.input_bar import InputBar
from gui.status_bar import StatusBarWidget


class ChatWindow(QWidget):
    """
    Main chat interface.
    """

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

        # -----------------------------
        # Left Panel
        # -----------------------------

        left_layout = QVBoxLayout()

        users_title = QLabel("Online Users")
        users_title.setObjectName("Title")

        self.online_users = OnlineUsersWidget()

        left_layout.addWidget(users_title)
        left_layout.addWidget(self.online_users)

        # -----------------------------
        # Right Panel
        # -----------------------------

        right_layout = QVBoxLayout()

        title = QLabel(
            "Quantum-Resistant Secure Chat"
        )

        title.setObjectName("Title")

        self.messages = MessageWidget()

        self.input_bar = InputBar()

        self.status = StatusBarWidget()

        right_layout.addWidget(title)
        right_layout.addWidget(self.messages)
        right_layout.addWidget(self.input_bar)
        right_layout.addWidget(self.status)

        root_layout.addLayout(left_layout, 1)
        root_layout.addLayout(right_layout, 3)

    # ==========================================================
    # Initialization
    # ==========================================================

    def initialize_ui(self):

        self.status.set_connected(True)

        self.status.set_algorithm("RSA")

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
           self.online_users.update_users
    )

        self.session.message_received.connect(
            self.receive_message
    )

        self.session.error_occurred.connect(
            self.show_error
    )
        # Synchronize UI with current session state
        self.online_users.update_users(
            self.session.get_online_users()
    )

    # -----------------------------------------
    # Sync UI with current session state
    # -----------------------------------------

        self.online_users.update_users(
            self.session.get_online_users()
    )
    # ==========================================================
    # Events
    # ==========================================================

    def user_selected(self, username):

        self.session.set_current_chat(username)

        self.messages.add_system_message(
            f"Chatting with {username}"
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

        else:

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