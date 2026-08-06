"""
Broadcaster Module

Handles broadcasting and sending packets to clients.
"""

from utils.network import send_message
from utils.protocol import (
    create_public_key_packet,
    create_user_list_packet
)


def send_to_client(client_socket, packet):
    """
    Send a packet to a single client.
    """

    try:
        send_message(client_socket, packet)

    except Exception:
        pass


def broadcast(state, packet, sender_socket):
    """
    Send a packet to every connected client except the sender.
    """

    disconnected_clients = []

    for client_socket in list(state.clients.keys()):

        if client_socket == sender_socket:
            continue

        try:
            send_message(client_socket, packet)

        except Exception:
            disconnected_clients.append(client_socket)

    # Remove disconnected clients safely
    for client_socket in disconnected_clients:

        try:
            client_socket.close()
        except OSError:
            pass

        state.remove_client(client_socket)


def distribute_public_keys(state, new_client_socket):
    """
    Synchronize RSA public keys between the newly connected client
    and all existing connected clients.
    """

    new_client = state.get_client(new_client_socket)

    if not new_client:
        return

    # If the new client has not sent a public key yet, stop.
    if new_client["public_key"] is None:
        return

    # Send existing clients' public keys to the new client,
    # and send the new client's public key to existing clients.
    for client_socket, client in list(state.clients.items()):

        if client_socket == new_client_socket:
            continue

        # -----------------------------
        # Existing client -> New client
        # -----------------------------
        if client["public_key"] is not None:

            packet = create_public_key_packet(
                username=client["username"],
                algorithm=client["algorithm"],
                public_key=client["public_key"]
            )

            send_to_client(
                new_client_socket,
                packet
            )

        # -----------------------------
        # New client -> Existing client
        # -----------------------------
        packet = create_public_key_packet(
            username=new_client["username"],
            algorithm=new_client["algorithm"],
            public_key=new_client["public_key"]
        )

        send_to_client(
            client_socket,
            packet
        )


def broadcast_user_list(state):
    """
    Broadcast the current list of online users to every connected client.

    Each client receives a personalized list that excludes
    their own username.
    """

    print("\n========== USER LIST BROADCAST ==========")
    state.logger.info("Broadcasting online user lists...")

    for client_socket, client in list(state.clients.items()):

        users = []

        for other_socket, other_client in list(state.clients.items()):

            if other_socket == client_socket:
                continue

            users.append(other_client["username"])

        packet = create_user_list_packet(users)

        print(
            f"Sending to {client['username']:<15} -> {users}"
        )

        state.logger.info(
            f"User list sent to "
            f"{client['username']}: {users}"
        )

        send_to_client(
            client_socket,
            packet
        )

    print("=========================================\n")