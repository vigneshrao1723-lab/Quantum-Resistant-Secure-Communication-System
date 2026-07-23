"""
Sender Module

Handles sending encrypted messages to the server.
"""

from utils.network import send_message


def send_messages(session):
    """
    Continuously read user input and send encrypted messages.
    """

    while True:

        try:

            message = input("You: ").strip()

            if not message:
                continue

            if message.lower() == "exit":

                session.logger.info("Disconnecting from server...")
                break

            # Encrypt message
            encrypted_message = session.aes.encrypt(message)

            session.logger.info(
                f"SENT (Encrypted): {encrypted_message}"
            )

            # Send encrypted message
            send_message(
                session.client_socket,
                encrypted_message
            )

        except (KeyboardInterrupt, EOFError):

            print("\nDisconnecting...")

            session.logger.info(
                "Client interrupted."
            )

            break