"""
Quantum-Resistant Secure Communication System

Client Entry Point
"""

import threading

from config import HOST, PORT
from client.session import ClientSession
from client.receiver import receive_messages
from client.sender import send_messages
from utils.network import send_message


def start_client():
    """
    Start the secure chat client.
    """

    # Create client session
    session = ClientSession()

    # Connect to server
    session.client_socket.connect((HOST, PORT))

    session.logger.info("Connected to server")

    print("=" * 50)
    print(" Secure Communication Client")
    print("=" * 50)

    # Username
    session.username = input("Enter your username: ").strip()

    if not session.username:
        session.username = "Anonymous"

    session.logger.info(f"Username: {session.username}")

    # Send username
    send_message(
        session.client_socket,
        session.username
    )

    # Start receiver thread
    receiver_thread = threading.Thread(
        target=receive_messages,
        args=(session,)
    )

    receiver_thread.start()

    # Start sender
    send_messages(session)

    # Shutdown
    session.logger.info("Closing connection...")

    try:
        session.client_socket.shutdown(2)
    except OSError:
        pass

    session.client_socket.close()

    receiver_thread.join(timeout=2)

    print("\nDisconnected from server.")


if __name__ == "__main__":
    start_client()