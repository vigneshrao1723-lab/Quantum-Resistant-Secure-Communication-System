"""
Terminal UI Manager

Provides a live terminal interface for the
Quantum Resistant Secure Communication System.
"""

from threading import Lock

from prompt_toolkit.application import Application
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.widgets import Frame
from prompt_toolkit.layout.controls import FormattedTextControl


class TerminalUI:
    """
    Terminal UI Manager.
    """

    def __init__(self, session):

        self.session = session

        self.lock = Lock()

        # ---------------------------------
        # UI State
        # ---------------------------------

        self.chat_partner = None

        self.message_history = []

        # ---------------------------------
        # Online Users Panel
        # ---------------------------------

        self.user_text = FormattedTextControl(
            text=self.build_online_users
        )

        # ---------------------------------
        # Chat Panel
        # ---------------------------------

        self.chat_text = FormattedTextControl(
            text=self.build_chat_history
        )

        # ---------------------------------
        # Layout
        # ---------------------------------

        self.root = HSplit(
            [

                Frame(
                    Window(
                        content=self.user_text,
                        always_hide_cursor=True,
                    ),
                    title="ONLINE USERS",
                ),

                Frame(
                    Window(
                        content=self.chat_text,
                        always_hide_cursor=True,
                    ),
                    title="CHAT",
                )

            ]
        )

        self.application = Application(
            layout=Layout(self.root),
            full_screen=False,
            refresh_interval=0.25,
        )

    # ====================================================
    # ONLINE USERS
    # ====================================================

    def build_online_users(self):

        with self.lock:

            text = []

            if not self.session.online_users:

                text.append(
                    "No users online.\n"
                )

            else:

                for index, user in enumerate(
                    self.session.online_users,
                    start=1
                ):

                    text.append(
                        f"{index}. {user}\n"
                    )

            return text

    # ====================================================
    # CHAT HISTORY
    # ====================================================

    def build_chat_history(self):

        with self.lock:

            if not self.message_history:

                return [
                    "No conversation yet.\n"
                ]

            return self.message_history

    # ====================================================
    # ADD MESSAGE
    # ====================================================

    def add_message(self, message):

        with self.lock:

            self.message_history.append(
                message + "\n"
            )

        self.invalidate()

    # ====================================================
    # CHANGE CHAT PARTNER
    # ====================================================

    def set_chat_partner(self, username):

        with self.lock:

            self.chat_partner = username

        self.invalidate()

    # ====================================================
    # REFRESH SCREEN
    # ====================================================

    def invalidate(self):

        self.application.invalidate()

    # ====================================================
    # RUN UI
    # ====================================================

    def run(self):

        self.application.run()