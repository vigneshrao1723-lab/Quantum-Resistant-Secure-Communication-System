"""
Client Handler Module

Handles communication with individual clients.
"""

from utils.protocol import (
    create_chat_packet,
    create_join_packet,
    create_leave_packet,
)

from utils.network import receive_message
from server.broadcaster import broadcast


def handle_client(state, client_socket, client_address):
    """
    Handle communication with a connected client.
    """

    username = None

    try:

        # Receive username
        username = receive_message(client_socket)

        if not username:
            return

        state.clients[client_socket] = username

        print(f"[CONNECTED] {username} ({client_address})")
        state.logger.info(f"{username} connected")

        # Notify other clients
        join_packet = create_join_packet(username)
        broadcast(state, join_packet, client_socket)

        while True:

            message = receive_message(client_socket)

            if not message:
                break

            print(f"{username}: [Encrypted Message]")
            state.logger.info(f"{username}: [Encrypted Message]")

            chat_packet = create_chat_packet(
                username,
                message
            )

            broadcast(
                state,
                chat_packet,
                client_socket
            )

    except Exception as e:

        print(f"[ERROR] {e}")
        state.logger.error(str(e))

    finally:

        if client_socket in state.clients:

            username = state.clients.pop(client_socket)

            leave_packet = create_leave_packet(username)

            broadcast(
                state,
                leave_packet,
                client_socket
            )

        try:
            client_socket.close()
        except OSError:
            pass

        print(f"[DISCONNECTED] {client_address}")

        if username:
            state.logger.info(f"{username} disconnected")