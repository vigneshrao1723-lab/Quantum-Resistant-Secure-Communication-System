"""
Multi-Client Chat Client with Usernames
Quantum-Resistant Secure Communication System
"""

import socket
import threading
import sys
from pathlib import Path

# Allow importing from the project root
sys.path.append(str(Path(__file__).resolve().parent.parent))

from logger_config import setup_logger
from config import HOST, PORT
from crypto.aes import AESCipher
from utils.protocol import parse_packet
from utils.network import send_message, receive_message

# Create client logger
logger = setup_logger("client_logger", "client.log")

# Temporary shared AES key
# (Will be replaced by RSA/Kyber key exchange later)
aes = AESCipher()


def receive_messages(client_socket):
    """
    Receive messages from the server.
    """

    while True:

        try:

            data = receive_message(client_socket)

            if data is None:
                logger.info("Server disconnected.")
                break

            packet = parse_packet(data)

            packet_type = packet["type"]

            if packet_type == "join":

                print(f"\n[INFO] {packet['username']} joined the chat.")
                logger.info(f"{packet['username']} joined")

            elif packet_type == "leave":

                print(f"\n[INFO] {packet['username']} left the chat.")
                logger.info(f"{packet['username']} left")

            elif packet_type == "chat":

                username = packet["username"]
                encrypted_message = packet["message"]

                decrypted_message = aes.decrypt(encrypted_message)

                print(f"\n{username}: {decrypted_message}")

                logger.info(
                    f"RECEIVED (Decrypted): {username}: {decrypted_message}"
                )

            print("You: ", end="", flush=True)

        except (ConnectionResetError, OSError):

            logger.info("Connection closed.")
            break

        except Exception as e:

            logger.error(f"Receive Error: {e}")
            break


def start_client():
    """
    Start the secure chat client.
    """

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((HOST, PORT))

    logger.info("Connected to server")

    print("=" * 50)
    print(" Secure Communication Client")
    print("=" * 50)

    # Ask for username
    username = input("Enter your username: ").strip()

    if not username:
        username = "Anonymous"

    logger.info(f"Username: {username}")

    # Send username
    send_message(client_socket, username)

    # Start receive thread
    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket,)
    )

    receive_thread.start()

    while True:

        try:

            message = input("You: ").strip()

            if not message:
                continue

            if message.lower() == "exit":

                logger.info("Disconnecting from server...")
                break

            # Encrypt message
            encrypted_message = aes.encrypt(message)

            logger.info(f"SENT (Encrypted): {encrypted_message}")

            # Send encrypted message
            send_message(client_socket, encrypted_message)

        except (KeyboardInterrupt, EOFError):

            print("\nDisconnecting...")
            logger.info("Client interrupted.")
            break

    logger.info("Closing connection...")

    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    client_socket.close()

    # Wait for receive thread to exit
    receive_thread.join(timeout=2)

    print("\nDisconnected from server.")


if __name__ == "__main__":
    start_client()