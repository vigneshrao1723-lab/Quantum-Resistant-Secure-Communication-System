"""
Quantum-Resistant Secure Communication System

Client Entry Point
"""

from client.session import ClientSession
from client.sender import send_messages

from utils.console_ui import (
    display_chat,
    display_system,
    display_warning,
    display_online_users,
)


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
        username = input("Enter your username: ")
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