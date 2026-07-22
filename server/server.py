"""
Multi-Client Broadcast Server
Quantum-Resistant Secure Communication System
"""

import socket
import threading
import sys
from pathlib import Path


from config import HOST, PORT, BUFFER_SIZE, ENCODING
sys.path.append(str(Path(__file__).resolve().parent.parent))
from logger_config import setup_logger

# List to store connected clients
clients = {}
logger = setup_logger("server_logger", "server.log")

def broadcast(message, sender_socket):
    """
    Send a message to every connected client except the sender.
    """

    for client in clients:

        if client != sender_socket:

            try:
                client.send(message.encode(ENCODING))

            except:

                client.close()

                del clients[client]

def handle_client(client_socket, client_address):

    try:

        username = client_socket.recv(BUFFER_SIZE).decode(ENCODING)

        clients[client_socket] = username

        print(f"[CONNECTED] {username} ({client_address})")
        logger.info(f"{username} connected")

        broadcast(f"{username} joined the chat.", client_socket)

        while True:

            message = client_socket.recv(BUFFER_SIZE).decode(ENCODING)

            if not message:
                break

            print(f"{username}: {message}")
            logger.info(f"{username}: {message}")

            broadcast(f"{username}: {message}", client_socket)

    except Exception as e:

        print(e)

    finally:

        if client_socket in clients:

            username = clients[client_socket]

            del clients[client_socket]

            broadcast(f"{username} left the chat.", client_socket)

        client_socket.close()

        print(f"[DISCONNECTED] {client_address}")
        logger.info(f"{username} disconnected")

def start_server():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((HOST, PORT))

    server_socket.listen()

    print("=" * 60)
    print(" Quantum-Resistant Secure Communication Server")
    print(f" Listening on {HOST}:{PORT}")
    print(" Waiting for clients...")
    logger.info(f"Server started on {HOST}:{PORT}")
    print("=" * 60)

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