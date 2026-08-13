"""
Quantum-Resistant Secure Communication System

Client Entry Point
"""

import getpass

from client.sender import send_messages
from client.session import ClientSession
from utils.console_ui import (
    display_chat,
    display_online_users,
    display_system,
    display_warning,
)


def authenticate(session):
    """
    Prompt for credentials and authenticate against the server,
    storing the resulting JWT/session info on the session object (D2
    -- Server-Side API / Authentication Migration; final slice,
    replacing this function's previous direct, local
    AuthenticationService.authenticate_user() call).

    Uses ClientSession.authenticate_credentials(), which opens and
    tears down its own short-lived connection -- this must be called
    before start_client()'s own session.connect(), not after (see
    start_client(): connecting for real, and sending the resulting
    JWT via session.login(), both now happen only once this returns).
    """

    identifier = input("Username or email: ").strip()
    password = getpass.getpass("Password: ")

    result = session.authenticate_credentials(identifier, password)

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
        # Login (authenticate_credentials()
        # uses its own short-lived connection;
        # nothing here is connected yet)
        # ---------------------------------
        username = authenticate(session)

        # ---------------------------------
        # Connect to Server
        # ---------------------------------
        session.connect()

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