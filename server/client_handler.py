"""
Client Handler Module

Handles communication with individual clients.
"""

from datetime import datetime, timezone

from auth.authentication_service import AuthenticationService
from config import KEY_EXCHANGE_ALGORITHM
from database.connection import SessionLocal
from database.repositories.message_repository import MessageRepository
from security.jwt_handler import TokenExpiredError, TokenValidationError
from utils.protocol import (
    create_auth_result_packet,
    create_delivery_failure_packet,
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


def _parse_message_timestamp(raw_timestamp):
    """
    Parse the client-supplied ISO 8601 timestamp from a chat packet.

    Falls back to the current server time if the timestamp is
    missing or malformed, rather than failing the persistence.
    """

    if raw_timestamp:
        try:
            parsed = datetime.fromisoformat(raw_timestamp)

            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

            return parsed
        except ValueError:
            pass

    return datetime.now(timezone.utc).replace(tzinfo=None)


def persist_message(sender_id, receiver_id, algorithm, packet):
    """
    Persist a successfully delivered private message.

    Only ever called after a "chat" packet has been routed to a
    connected recipient -- failed deliveries are never stored. Stores
    ciphertext only; the server never decrypts messages.
    """

    db = SessionLocal()

    try:
        message_repo = MessageRepository(db)

        message_repo.save_message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            ciphertext=packet.get("message"),
            algorithm=algorithm or KEY_EXCHANGE_ALGORITHM,
            timestamp=_parse_message_timestamp(packet.get("timestamp")),
        )

        db.commit()
    finally:
        db.close()


def authenticate_connection(state, client_socket, client_address):
    """
    Receive and validate the client's JWT access token.

    Returns the authenticated (user, session) pair on success, or
    None on failure. In both cases an "auth_result" packet is sent
    back to the client before returning.
    """

    auth_packet = receive_message(client_socket)

    if not auth_packet:
        return None

    auth_packet = parse_packet(auth_packet)

    if not isinstance(auth_packet, dict) or auth_packet.get("type") != "auth":
        send_to_client(
            client_socket,
            create_auth_result_packet(False, "Authentication required.")
        )
        return None

    access_token = auth_packet.get("access_token")

    db = SessionLocal()

    try:
        auth_service = AuthenticationService(db)

        try:
            user = auth_service.get_current_user(access_token)
            user_session = auth_service.get_current_session(access_token)
        except TokenExpiredError:
            state.logger.info(
                f"Rejected connection from {client_address}: token expired"
            )
            send_to_client(
                client_socket,
                create_auth_result_packet(
                    False,
                    "Session token has expired. Please log in again."
                )
            )
            return None
        except TokenValidationError:
            state.logger.info(
                f"Rejected connection from {client_address}: invalid token"
            )
            send_to_client(
                client_socket,
                create_auth_result_packet(
                    False,
                    "Invalid or unauthorized session."
                )
            )
            return None
    finally:
        db.close()

    send_to_client(
        client_socket,
        create_auth_result_packet(True, "Authenticated.", username=user.username)
    )

    return user, user_session


def handle_client(state, client_socket, client_address):
    """
    Handle communication with a connected client.
    """

    username = None

    try:

        # -----------------------------
        # Authenticate via JWT
        # -----------------------------
        authenticated = authenticate_connection(state, client_socket, client_address)

        if authenticated is None:
            return

        user, user_session = authenticated
        username = user.username

        # Register client, associated with the authenticated user/session
        state.add_client(
            client_socket,
            username,
            user_id=str(user.id),
            session_id=user_session.session_id
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

                for sock, client in list(state.clients.items()):

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

                        sender_client = state.get_client(client_socket)

                        persist_message(
                            sender_id=user.id,
                            receiver_id=client["user_id"],
                            algorithm=(sender_client or {}).get("algorithm"),
                            packet=packet
                        )

                        break

                else:

                    # Loop completed without finding a matching
                    # connected recipient -- report delivery failure
                    # to the sender instead of silently dropping it.
                    state.logger.info(
                        f"Delivery failed: {username} -> {receiver} "
                        f"(recipient not connected)"
                    )

                    send_to_client(
                        client_socket,
                        create_delivery_failure_packet(receiver)
                    )

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