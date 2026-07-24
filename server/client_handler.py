"""
Client Handler Module

Handles communication with individual clients.
"""

from utils.protocol import (
    create_join_packet,
    create_leave_packet,
    parse_packet,
)

from utils.network import receive_message

from server.broadcaster import (
    broadcast,
    broadcast_user_list,
    distribute_public_keys,
    send_to_client,
)


def handle_client(state, client_socket, client_address):
    """
    Handle communication with a connected client.
    """

    username = None

    try:

        # -----------------------------
        # Receive username
        # -----------------------------
        username = receive_message(client_socket)

        if not username:
            return

        # Register client
        state.add_client(
            client_socket,
            username
        )

        print(f"[CONNECTED] {username} ({client_address})")
        state.logger.info(f"{username} connected")

        # -----------------------------
        # Receive RSA public key
        # -----------------------------
        key_packet = receive_message(client_socket)

        if not key_packet:
            return

        key_packet = parse_packet(key_packet)

        if (
            key_packet.get("type") == "key_exchange"
            and key_packet.get("operation") == "public_key"
        ):

            state.set_public_key(
                client_socket,
                key_packet["algorithm"],
                key_packet["public_key"]
            )

            state.logger.info(
                f"Received {key_packet['algorithm']} public key "
                f"from {username}"
            )

            # Synchronize public keys between all connected clients
            distribute_public_keys(
                state,
                client_socket
            )

        # -----------------------------
        # Notify other clients
        # -----------------------------
        join_packet = create_join_packet(username)

        broadcast(
            state,
            join_packet,
            client_socket
        )

        # -----------------------------
        # Broadcast updated online users
        # -----------------------------
        broadcast_user_list(state)

        # -----------------------------
        # Receive packets
        # -----------------------------
        while True:

            packet = receive_message(client_socket)

            if not packet:
                break

            packet = parse_packet(packet)

            # -----------------------------
            # Private Chat Packet
            # -----------------------------
            if packet.get("type") == "chat":

                receiver = packet.get("receiver")

                for sock, client in state.clients.items():

                    if client["username"] == receiver:

                        print(
                            f"{username} -> {receiver}: "
                            f"[Encrypted Message]"
                        )

                        state.logger.info(
                            f"{username} -> {receiver}: "
                            f"[Encrypted Message]"
                        )

                        send_to_client(
                            sock,
                            packet
                        )

                        break

            # -----------------------------
            # Session Key Exchange Packet
            # -----------------------------
            elif (
                packet.get("type") == "key_exchange"
                and packet.get("operation") == "session_key"
            ):

                receiver = packet.get("receiver")

                for sock, client in state.clients.items():

                    if client["username"] == receiver:

                        send_to_client(
                            sock,
                            packet
                        )

                        state.logger.info(
                            f"Forwarded session key "
                            f"from {username} to {receiver}"
                        )

                        break

    except Exception as e:

        print(f"[ERROR] {e}")
        state.logger.error(str(e))

    finally:

        client = state.get_client(client_socket)

        if client:

            username = client["username"]

            leave_packet = create_leave_packet(username)

            broadcast(
                state,
                leave_packet,
                client_socket
            )

            # Remove client before broadcasting
            state.remove_client(client_socket)

            # Broadcast updated online users
            broadcast_user_list(state)

        try:
            client_socket.close()
        except OSError:
            pass

        print(f"[DISCONNECTED] {client_address}")

        if username:
            state.logger.info(f"{username} disconnected")