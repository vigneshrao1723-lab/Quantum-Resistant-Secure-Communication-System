"""
Basic TCP Client
Quantum-Resistant Secure Communication System
"""

import socket
from config import HOST, PORT, BUFFER_SIZE, ENCODING


def start_client():
    """Connect to the server and send messages."""

    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((HOST, PORT))

    print("=" * 50)
    print(" Connected to Secure Communication Server")
    print(" Type 'exit' to disconnect.")
    print("=" * 50)

    while True:
        message = input("You: ")

        if message.lower() == "exit":
            break

        client_socket.send(message.encode(ENCODING))

    client_socket.close()
    print("Disconnected from server.")


if __name__ == "__main__":
    start_client()