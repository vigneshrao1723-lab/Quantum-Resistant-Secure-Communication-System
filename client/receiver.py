"""
Receiver Module

Handles all incoming messages from the server.
"""

from utils.network import receive_message
from utils.protocol import parse_packet
from utils.console_ui import display_error


def receive_messages(session):
    """
    Continuously receive messages from the server.
    """

    while True:

        try:

            data = receive_message(session.client_socket)

            if data is None:

                session.logger.info(
                    "Server disconnected."
                )

                break

            packet = parse_packet(data)

            # ---------------------------------
            # Delegate packet handling
            # ---------------------------------
            session.handle_packet(packet)

        except (ConnectionResetError, OSError):

            session.logger.info(
                "Connection closed."
            )

            break

        except Exception as error:

            display_error(str(error))

            session.logger.exception(
                f"Receive Error: {error}"
            )

            break