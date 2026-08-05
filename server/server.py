"""
Quantum-Resistant Secure Communication System

Server Entry Point
"""

import socket
import threading

from config import HOST, PORT
from server.server_state import ServerState
from server.client_handler import handle_client


def start_server():
    """
    Start the secure communication server.
    """

    # Create shared server state
    state = ServerState()

    # Create server socket
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.bind((HOST, PORT))

    server_socket.listen()

    print("=" * 60)
    print(" Quantum-Resistant Secure Communication Server")
    print(f" Listening on {HOST}:{PORT}")
    print(" Waiting for clients...")
    print("=" * 60)

    state.logger.info(
        f"Server started on {HOST}:{PORT}"
    )

    while True:

        client_socket, client_address = server_socket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(
                state,
                client_socket,
                client_address
            )
        )

        thread.start()

        print(
            f"Active Connections: "
            f"{len(state.clients)}"
        )


if __name__ == "__main__":
    start_server()