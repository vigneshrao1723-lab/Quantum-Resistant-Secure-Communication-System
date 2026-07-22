"""
Multi-Client Chat Client with Usernames
"""

import socket
import threading
import sys
from pathlib import Path

# Allow importing from the project root
sys.path.append(str(Path(__file__).resolve().parent.parent))

from logger_config import setup_logger
from config import HOST, PORT, BUFFER_SIZE, ENCODING

# Create client logger
logger = setup_logger("client_logger", "client.log")


def receive_messages(client_socket):
    """
    Receive messages from the server.
    """
    while True:
        try:
            message = client_socket.recv(BUFFER_SIZE).decode(ENCODING)

            if not message:
                break

            logger.info(f"RECEIVED: {message}")

            print(f"\n{message}")
            print("You: ", end="", flush=True)

        except (ConnectionResetError, OSError):
            # Normal socket shutdown
            break

        except Exception:
            break


def start_client():

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((HOST, PORT))
    logger.info("Connected to server")

    print("=" * 50)
    print(" Secure Communication Client")
    print("=" * 50)

    # Ask for username
    username = input("Enter your username: ")
    logger.info(f"Username: {username}")

    # Send username to server
    client_socket.send(username.encode(ENCODING))

    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket,)
    )

    receive_thread.start()

    while True:

        message = input("You: ")

        if message.lower() == "exit":
            logger.info("Disconnected from server")
            break

        logger.info(f"SENT: {message}")

        client_socket.send(message.encode(ENCODING))

    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    client_socket.close()

    receive_thread.join()


if __name__ == "__main__":
    start_client()