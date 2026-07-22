"""
Basic TCP Server
Quantum-Resistant Secure Communication System
"""

import socket
from config import HOST, PORT, BUFFER_SIZE, ENCODING


def start_server():
    """Start the TCP server."""

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to host and port
    server_socket.bind((HOST, PORT))

    # Listen for incoming connections
    server_socket.listen(1)

    print("=" * 50)
    print(" Secure Communication Server Started")
    print(f" Listening on {HOST}:{PORT}")
    print(" Waiting for client connection...")
    print("=" * 50)

    # Accept a client connection
    client_socket, client_address = server_socket.accept()

    print(f"\n Client connected: {client_address}")

    while True:
        message = client_socket.recv(BUFFER_SIZE).decode(ENCODING)

        if not message:
            break

        print(f"Client: {message}")

    print("Client disconnected.")

    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    start_server()