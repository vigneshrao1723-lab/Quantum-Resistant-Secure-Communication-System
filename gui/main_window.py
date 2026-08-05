"""
Main Window

Root window of the Quantum-Resistant Secure Communication System.
"""

from PySide6.QtWidgets import QMainWindow

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
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
        self.db_factory = SessionLocal

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
        password,
        confirm_password,
    ):

        try:
            with self.db_factory() as db:
                auth_service = AuthenticationService(db)
                result = auth_service.register_user(
                    RegisterRequest(
                        full_name=full_name,
                        username=username,
                        email=email,
                        password=password,
                        confirm_password=confirm_password,
                    )
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
            with self.db_factory() as db:
                auth_service = AuthenticationService(db)
                result = auth_service.authenticate_user(
                    LoginRequest(
                        identifier=username,
                        password=password,
                    )
                )
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
    ):

        self.session.user_id = user_id
        self.session.username = username
        self.session.session_id = session_id
        self.session.access_token = access_token
        self.session.refresh_token = refresh_token

        try:
            self.session.connect()
            self.session.login(username)
            self.session.send_public_key()
            self.show_chat()
            self.session.start_receiver()
        except Exception as error:
            self.login_window.show_connection_error(str(error))
