"""
Quantum-Resistant Secure Communication System

Client Entry Point
"""

import getpass

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest
from client.session import ClientSession
from client.sender import send_messages
from database.connection import SessionLocal

from utils.console_ui import (
    display_chat,
    display_system,
    display_warning,
    display_online_users,
)


def authenticate(session):
    """
    Prompt for credentials and authenticate against the database,
    storing the resulting JWT/session info on the session object.

    Mirrors the DB-backed login gui/main_window.py performs before
    ever touching the socket -- the terminal client needs the same
    JWT in hand before ClientSession.login() can authenticate the
    connection with the server.
    """

    identifier = input("Username or email: ").strip()
    password = getpass.getpass("Password: ")

    db = SessionLocal()

    try:
        auth_service = AuthenticationService(db)
        result = auth_service.authenticate_user(
            LoginRequest(identifier=identifier, password=password)
        )
    finally:
        db.close()

    if not result.success:
        raise PermissionError(
            result.errors and "; ".join(result.errors.values()) or result.message
        )

    session.user_id = result.user_id
    session.username = result.username
    session.session_id = result.session_id
    session.access_token = result.token_pair.access_token
    session.refresh_token = result.token_pair.refresh_token

    return result.username


def terminal_message_handler(sender, message):
    """
    Handle incoming messages for the terminal UI.
    """

    if sender == "system":
        display_system(message)
    else:
        display_chat(sender, message)


def terminal_users_handler(users):
    """
    Update the terminal UI with online users.
    """

    display_online_users(users)


def terminal_error_handler(message):
    """
    Display warnings/errors in the terminal UI.
    """

    display_warning(message)


def start_client():
    """
    Start the secure chat client.
    """

    # ---------------------------------
    # Create Client Session
    # ---------------------------------
    session = ClientSession()

    # ---------------------------------
    # Register Terminal Callbacks
    # ---------------------------------
    session.on_message = terminal_message_handler
    session.on_users_changed = terminal_users_handler
    session.on_error = terminal_error_handler

    print("=" * 50)
    print(" Secure Communication Client")
    print("=" * 50)

    try:

        # ---------------------------------
        # Connect to Server
        # ---------------------------------
        session.connect()

        # ---------------------------------
        # Login
        # ---------------------------------
        username = authenticate(session)
        session.login(username)

        # ---------------------------------
        # Exchange RSA Public Key
        # ---------------------------------
        session.send_public_key()

        # ---------------------------------
        # Start Receiver
        # ---------------------------------
        session.start_receiver()

        # ---------------------------------
        # Start Sender
        # ---------------------------------
        send_messages(session)

    except KeyboardInterrupt:

        print("\nShutting down client...")

    except Exception as error:

        session.logger.exception(
            f"Client Error: {error}"
        )

    finally:

        # ---------------------------------
        # Disconnect
        # ---------------------------------
        session.disconnect()

        print("\nDisconnected from server.")


if __name__ == "__main__":
    start_client()