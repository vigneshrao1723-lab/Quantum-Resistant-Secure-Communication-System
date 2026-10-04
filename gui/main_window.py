"""
Main Window

Root window of the Quantum-Resistant Secure Communication System.
"""

from PySide6.QtWidgets import QMainWindow

from client.session import ClientSession
from gui.chat_window import ChatWindow
from gui.login_window import LoginWindow


class MainWindow(QMainWindow):
    """
    Root application window.

    Acts as the controller between
    the GUI and backend.
    """

    def __init__(self):
        super().__init__()

        self.session = ClientSession()

        self.login_window = None
        self.chat_window = None

        self.setup_window()

        self.show_login()

    # ==========================================================
    # Window
    # ==========================================================

    def setup_window(self):

        self.setWindowTitle(
            "Quantum-Resistant Secure Communication System"
        )

        self.resize(1200, 750)

        self.setMinimumSize(1000, 650)

    # ==========================================================
    # Pages
    # ==========================================================

    def show_login(self):

        self.login_window = LoginWindow()

        self.login_window.login_requested.connect(
            self.handle_login
        )
        self.login_window.register_requested.connect(
            self.handle_registration
        )

        self.setCentralWidget(
            self.login_window
        )

    def show_chat(self):

        self.chat_window = ChatWindow(
            self.session
        )

        self.chat_window.logout_requested.connect(
            self.handle_logout
        )

        self.setCentralWidget(
            self.chat_window
        )

    # ==========================================================
    # Backend
    # ==========================================================

    def handle_registration(
        self,
        username,
        phone_number,
        password,
        confirm_password,
    ):
        """
        Register using the app's actual identity model: username is the
        displayed name, phone number is the searchable identifier.

        The registration form no longer collects a full name or an
        email, but users.display_name and users.email are both NOT NULL
        (and email is UNIQUE), so both are derived here rather than
        dropped from the schema. Deliberately NOT a migration: removing
        those columns would rewrite a table that existing accounts still
        depend on -- email remains a valid login identifier for anyone
        who registered before this change, and the server accepts it.

        display_name = username, which is exactly what the app shows.

        email is synthesised from the username under the .invalid TLD,
        which RFC 2606 reserves precisely so it can never resolve or be
        routed to. Uniqueness follows from the username's own UNIQUE
        constraint, so the derived value cannot collide any more often
        than the username itself. Nothing is ever sent to it.
        """

        try:
            result = self.session.register(
                full_name=username,
                username=username,
                email=f"{username}@users.invalid",
                phone_number=phone_number,
                password=password,
                confirm_password=confirm_password,
            )
        except Exception as error:
            self.login_window.show_connection_error(str(error))
            return

        if not result.success:
            self.login_window.show_connection_error(
                result.errors and "; ".join(result.errors.values()) or result.message
            )
            return

        self.login_window.set_mode(False)
        # UI Finalization -- Login Identifier: login now asks for phone
        # number, not username -- prefill the one the user just
        # registered with so they can log in immediately without
        # retyping it. username_input is cleared instead: it's hidden
        # in login mode and would otherwise carry stale text into the
        # next register-mode visit.
        self.login_window.phone_input.setText(phone_number)
        self.login_window.password_input.clear()
        self.login_window.confirm_password_input.clear()
        self.login_window.username_input.clear()
        self.login_window.set_connecting(False)
        self.login_window.status.setText(
            "Registration successful. Please login."
        )

    def handle_login(self, phone_number, password):
        """
        UI Finalization -- Login Identifier: ``phone_number`` is exactly
        what the user typed into LoginWindow's phone field (login_
        requested's first argument -- see LoginWindow.handle_submit()).
        Passed straight through as the generic ``identifier`` the
        server/AuthenticationService already accepted before this
        change; only what that identifier is now REQUIRED to be
        changed, not the plumbing that carries it.
        """

        try:
            result = self.session.authenticate_credentials(phone_number, password)
        except Exception as error:
            self.login_window.show_connection_error(str(error))
            return

        if not result.success:
            self.login_window.show_connection_error(
                result.errors and "; ".join(result.errors.values()) or result.message
            )
            return

        self.start_chat_session(
            user_id=result.user_id,
            username=result.username,
            session_id=result.session_id,
            phone_number=result.phone_number,
            access_token=result.token_pair.access_token if result.token_pair else None,
            refresh_token=result.token_pair.refresh_token if result.token_pair else None,
        )

    def start_chat_session(
        self,
        user_id,
        username,
        session_id,
        access_token,
        refresh_token,
        phone_number="",
    ):

        self.session.user_id = user_id
        self.session.username = username
        self.session.phone_number = phone_number or ""
        self.session.session_id = session_id
        self.session.access_token = access_token
        self.session.refresh_token = refresh_token

        try:
            self.session.connect()
            self.session.login(username)
            self.session.send_public_key()
            # D4.2 -- Message/History Operations Migration:
            # show_chat() constructs ChatWindow, whose initialize_ui()
            # calls ClientSession.load_conversations() synchronously --
            # which now blocks on send_request(), resolvable only by
            # the receiver thread. The receiver must therefore already
            # be running before show_chat() is reached, not after.
            self.session.start_receiver()
            self.show_chat()

            # BUG 1 -- if the local encrypted key store could not be
            # unlocked, say so plainly. Login itself succeeded and new
            # messages work normally; what the user needs to know is
            # that OLDER history may not be readable on this device.
            # Deliberately vague about the cause: it carries no
            # password, no key, and no cryptographic detail.
            if self.session.key_store_error:
                self.chat_window.messages.add_system_message(
                    "Saved message keys on this device could not be "
                    "unlocked, so older messages may not be readable. "
                    "New messages are unaffected."
                )
        except Exception as error:
            self.login_window.show_connection_error(str(error))

    def handle_logout(self):

        if self.session.session_id:

            try:
                self.session.logout()
            except Exception as error:
                self.session.logger.error(
                    f"Failed to revoke session on logout: {error}"
                )

        self.session.disconnect()

        self.session.user_id = None
        self.session.username = ""
        self.session.session_id = None
        self.session.access_token = None
        self.session.refresh_token = None
        self.session.current_chat = None
        self.session.online_users = []
        self.session.unread_counts = {}

        self.chat_window = None

        self.show_login()
