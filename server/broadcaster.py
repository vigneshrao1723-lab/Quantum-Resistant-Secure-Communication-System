"""
Broadcaster Module

Handles broadcasting and sending packets to clients.
"""

from database.connection import SessionLocal
from database.repositories.blocked_user_repository import BlockedUserRepository
from logger_config import setup_logger
from utils.network import send_message
from utils.protocol import create_public_key_packet, create_user_list_packet

# Same singleton logger ServerState.logger already is (setup_logger()
# returns the existing "server_logger" instance once it's been
# configured once, rather than creating a second one) -- so a send
# failure logged here lands in the exact same server.log a caller's
# own state.logger calls do, without send_to_client() needing state
# threaded through every one of its call sites just to log.
_logger = setup_logger("server_logger", "server.log")


def send_to_client(client_socket, packet):
    """
    Send a packet to a single client.

    Returns True if the send actually succeeded, False otherwise --
    the exception is logged, never silently discarded. A caller must
    check this return value before reporting delivery (e.g. logging
    "Forwarded X to Y", or recording a message as DELIVERED rather
    than QUEUED) -- the fact that this function was called and didn't
    raise past this point is not itself proof the packet arrived.
    """

    try:
        send_message(client_socket, packet)
        return True

    except Exception as error:  # noqa: BLE001

        # Intentionally broad: a failed send can surface as ssl.SSLError,
        # OSError (connection reset/aborted), or BrokenPipeError,
        # depending on platform and exactly when the peer went away --
        # all of them mean the same thing here (this send did not
        # happen) and must be reported the same way, not partially
        # missed by a narrower except.
        _logger.warning(f"Failed to send to client: {error}")
        return False


def broadcast(state, packet, sender_socket):
    """
    Send a packet to every connected client except the sender.
    """

    disconnected_clients = []

    for client_socket in list(state.clients.keys()):

        if client_socket == sender_socket:
            continue

        if not send_to_client(client_socket, packet):
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
                public_key=client["public_key"],
                signing_public_key=client.get("signing_public_key"),
                identity_signature=client.get("identity_signature"),
                # Phase 18.5: "announced_device_id" (client-claimed,
                # relayed as transport metadata only) -- deliberately
                # NOT "device_id" (that key is reserved for a
                # cryptographically-verified device_session_bind()
                # result; see server_state.py::set_public_key()'s own
                # docstring for why the two must never collide).
                device_id=client.get("announced_device_id"),
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
            public_key=new_client["public_key"],
            signing_public_key=new_client.get("signing_public_key"),
            identity_signature=new_client.get("identity_signature"),
            device_id=new_client.get("announced_device_id"),
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

    # Phase 19.24 -- Block User: presence is a form of "can this
    # person see something about me", so a block in EITHER direction
    # hides each party from the other's online list, one query for
    # every pair rather than one query per pair (this runs on every
    # broadcast, potentially per connect/disconnect).
    db = SessionLocal()
    try:
        # state.clients stores user_id as a plain string (see e.g.
        # this module's own handle_client() connection setup), while
        # BlockedUser's columns come back as uuid.UUID objects -- both
        # sides of the comparison below are normalized to strings so
        # they actually compare equal.
        block_pairs = {
            (str(blocker_id), str(blocked_id))
            for blocker_id, blocked_id in BlockedUserRepository(db).get_all_block_pairs()
        }
    finally:
        db.close()

    def _blocked(user_id_a, user_id_b):
        return (user_id_a, user_id_b) in block_pairs or (user_id_b, user_id_a) in block_pairs

    for client_socket, client in list(state.clients.items()):

        users = []

        for other_socket, other_client in list(state.clients.items()):

            if other_socket == client_socket:
                continue

            if client.get("user_id") and other_client.get("user_id") and _blocked(
                client["user_id"], other_client["user_id"]
            ):
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