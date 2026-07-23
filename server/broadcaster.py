"""
Broadcaster Module

Handles broadcasting messages to all connected clients.
"""

from utils.network import send_message


def broadcast(state, message, sender_socket):
    """
    Send a message to every connected client except the sender.
    """

    disconnected_clients = []

    for client_socket in state.clients:

        if client_socket != sender_socket:

            try:

                send_message(client_socket, message)

            except Exception:

                disconnected_clients.append(client_socket)

    # Remove disconnected clients safely
    for client_socket in disconnected_clients:

        try:
            client_socket.close()
        except OSError:
            pass

        if client_socket in state.clients:
            del state.clients[client_socket]