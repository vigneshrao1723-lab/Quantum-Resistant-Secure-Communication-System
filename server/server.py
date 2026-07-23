"""
Multi-Client Broadcast Server
Quantum-Resistant Secure Communication System
"""

import socket
import threading
import sys
from pathlib import Path

from config import HOST, PORT
sys.path.append(str(Path(__file__).resolve().parent.parent))

from logger_config import setup_logger
from utils.protocol import (
    create_chat_packet,
    create_join_packet,
    create_leave_packet
)
from utils.network import send_message, receive_message

# Dictionary to store connected clients
clients = {}

logger = setup_logger("server_logger", "server.log")


def broadcast(message, sender_socket):
    """
    Send a message to every connected client except the sender.
    """

    disconnected_clients = []

    for client in clients:

        if client != sender_socket:

            try:
                send_message(client, message)

            except Exception:

                disconnected_clients.append(client)

    # Remove disconnected clients safely
    for client in disconnected_clients:

        client.close()

        if client in clients:
            del clients[client]


def handle_client(client_socket, client_address):
    """
    Handle communication with a connected client.
    """

    username = None

    try:

        # Receive username
        username = receive_message(client_socket)

        if not username:
            return

        clients[client_socket] = username

        print(f"[CONNECTED] {username} ({client_address})")
        logger.info(f"{username} connected")

        # Notify other clients
        join_packet = create_join_packet(username)
        broadcast(join_packet, client_socket)

        while True:

            message = receive_message(client_socket)

            if not message:
                break

            print(f"{username}: [Encrypted Message]")
            logger.info(f"{username}: [Encrypted Message]")

            chat_packet = create_chat_packet(username, message)

            broadcast(chat_packet, client_socket)

    except Exception as e:

        print(f"[ERROR] {e}")
        logger.error(str(e))

    finally:

        if client_socket in clients:

            username = clients.pop(client_socket)

            leave_packet = create_leave_packet(username)

            broadcast(leave_packet, client_socket)

        client_socket.close()

        print(f"[DISCONNECTED] {client_address}")

        if username:
            logger.info(f"{username} disconnected")


def start_server():
    """
    Start the TCP server.
    """

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((HOST, PORT))

    server_socket.listen()

    print("=" * 60)
    print(" Quantum-Resistant Secure Communication Server")
    print(f" Listening on {HOST}:{PORT}")
    print(" Waiting for clients...")
    print("=" * 60)

    logger.info(f"Server started on {HOST}:{PORT}")

    while True:

        client_socket, client_address = server_socket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(client_socket, client_address)
        )

        thread.start()

        print(f"Active Connections: {len(clients)}")


if __name__ == "__main__":
    start_server()