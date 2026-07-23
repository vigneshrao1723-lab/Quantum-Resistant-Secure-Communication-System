"""
Receiver Module

Handles all incoming messages from the server.
"""

from utils.protocol import parse_packet
from utils.network import receive_message


def receive_messages(session):
    """
    Continuously receive messages from the server.
    """

    while True:

        try:

            data = receive_message(session.client_socket)

            if data is None:
                session.logger.info("Server disconnected.")
                break

            packet = parse_packet(data)

            packet_type = packet["type"]

            if packet_type == "join":

                print(f"\n[INFO] {packet['username']} joined the chat.")

                session.logger.info(
                    f"{packet['username']} joined"
                )

            elif packet_type == "leave":

                print(f"\n[INFO] {packet['username']} left the chat.")

                session.logger.info(
                    f"{packet['username']} left"
                )

            elif packet_type == "chat":

                username = packet["username"]

                encrypted_message = packet["message"]

                decrypted_message = session.aes.decrypt(
                    encrypted_message
                )

                print(f"\n{username}: {decrypted_message}")

                session.logger.info(
                    f"RECEIVED (Decrypted): "
                    f"{username}: {decrypted_message}"
                )

            print("You: ", end="", flush=True)

        except (ConnectionResetError, OSError):

            session.logger.info("Connection closed.")

            break

        except Exception as e:

            session.logger.error(
                f"Receive Error: {e}"
            )

            break