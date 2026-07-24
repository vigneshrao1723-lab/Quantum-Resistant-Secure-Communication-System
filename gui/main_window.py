"""
Main Window

Root window of the Quantum-Resistant Secure Communication System.
"""

from PySide6.QtWidgets import (
    QMainWindow,
    QMessageBox,
)

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

        self.login_window.connect_requested.connect(
            self.connect_to_server
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

    def connect_to_server(self, username):

        try:

            # ---------------------------------
            # Connect to server
            # ---------------------------------

            self.session.connect()

            # ---------------------------------
            # Login
            # ---------------------------------

            self.session.login(username)

            # ---------------------------------
            # Send RSA Public Key
            # ---------------------------------

            self.session.send_public_key()

            # ---------------------------------
            # IMPORTANT:
            # Create Chat Window BEFORE
            # starting the receiver thread.
            # This ensures all Qt signal
            # connections already exist.
            # ---------------------------------

            self.show_chat()

            # ---------------------------------
            # Start receiver thread
            # ---------------------------------

            self.session.start_receiver()

            QMessageBox.information(
                self,
                "Connected",
                "Successfully connected to the server."
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Connection Error",
                str(error)
            )