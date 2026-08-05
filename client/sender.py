"""
Sender Module

Handles terminal interaction for sending private messages.
Business logic (encryption, key exchange, networking)
is delegated to ClientSession.
"""

import time

from utils.console_ui import (
    display_online_users,
    display_system,
    display_error,
    display_help,
    display_stats,
    prompt,
)


def choose_chat_partner(session):
    """
    Allow the user to choose a chat partner
    using the displayed user number.
    """

    waiting_message_displayed = False

    while True:

        # ---------------------------------------
        # Wait until at least one user is online
        # ---------------------------------------
        if not session.online_users:

            if not waiting_message_displayed:

                display_system(
                    "No other users are currently online."
                )

                print(
                    "Waiting for someone to connect...\n"
                )

                waiting_message_displayed = True

            time.sleep(1)
            continue

        waiting_message_displayed = False

        # ---------------------------------------
        # Display Online Users
        # ---------------------------------------
        display_online_users(session)

        choice = input(
            f"Choose user (1-{len(session.online_users)}): "
        ).strip()

        if not choice:
            continue

        if choice.lower() == "exit":
            raise KeyboardInterrupt

        if not choice.isdigit():

            display_system(
                "Please enter a valid number."
            )

            continue

        index = int(choice)

        if index < 1 or index > len(session.online_users):

            display_system(
                "Invalid selection."
            )

            continue

        partner = session.online_users[index - 1]

        if session.key_manager.get_public_key(partner) is None:

            display_system(
                "Waiting for public key from user..."
            )

            continue

        session.current_chat = partner

        display_system(
            f"Now chatting with {partner}"
        )

        session.logger.info(
            f"Current chat partner: {partner}"
        )

        break


def send_messages(session):
    """
    Continuously read user input and send
    encrypted private messages.
    """

    choose_chat_partner(session)

    while True:

        try:

            prompt(session)

            message = input().strip()

            if not message:
                continue

            # ---------------------------------------
            # Exit
            # ---------------------------------------
            if message.lower() == "exit":

                session.logger.info(
                    "Disconnecting from server..."
                )

                break

            # ---------------------------------------
            # Help
            # ---------------------------------------
            if message.lower() == "/help":

                display_help()
                continue

            # ---------------------------------------
            # Online Users
            # ---------------------------------------
            if message.lower() == "/users":

                display_online_users(session)
                continue

            # ---------------------------------------
            # Session Statistics
            # ---------------------------------------
            if message.lower() == "/stats":

                display_stats(session)
                continue

            # ---------------------------------------
            # Switch Conversation
            # ---------------------------------------
            if message.lower() == "/switch":

                choose_chat_partner(session)
                continue

            # ---------------------------------------
            # Send Encrypted Message
            # ---------------------------------------
            session.send_chat_message(message)

        except (KeyboardInterrupt, EOFError):

            display_system(
                "Disconnecting..."
            )

            session.logger.info(
                "Client interrupted."
            )

            break

        except Exception as e:

            display_error(str(e))

            session.logger.error(
                f"Sender Error: {e}"
            )

            break