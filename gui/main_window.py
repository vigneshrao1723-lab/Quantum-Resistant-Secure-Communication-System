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
        full_name,
        username,
        email,
        phone_number,
        password,
        confirm_password,
    ):

        try:
            result = self.session.register(
                full_name=full_name,
                username=username,
                email=email,
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
        self.login_window.username_input.setText(username)
        self.login_window.password_input.clear()
        self.login_window.confirm_password_input.clear()
        self.login_window.email_input.clear()
        self.login_window.full_name_input.clear()
        self.login_window.set_connecting(False)
        self.login_window.status.setText(
            "Registration successful. Please login."
        )

    def handle_login(self, username, password):

        try:
            result = self.session.authenticate_credentials(username, password)
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
