"""
Server State

Stores shared resources used by the server.
"""

from datetime import datetime, timezone

from logger_config import setup_logger


def _utc_now():
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ServerState:
    """
    Stores all shared server resources.
    """

    def __init__(self):

        # Connected clients
        #
        # Format:
        # {
        #     client_socket: {
        #         "username": "...",
        #         "user_id": "...",
        #         "session_id": "...",
        #         "algorithm": "RSA",
        #         "public_key": "...",
        #         "connected_at": datetime(...)
        #     }
        # }
        self.clients = {}

        # Logger
        self.logger = setup_logger(
            "server_logger",
            "server.log"
        )

    def add_client(self, client_socket, username, user_id=None, session_id=None):
        """
        Add a newly connected, authenticated client.
        """

        self.clients[client_socket] = {
            "username": username,
            "user_id": user_id,
            "session_id": session_id,
            "algorithm": None,
            "public_key": None,
            "connected_at": _utc_now()
        }

    def remove_client(self, client_socket):
        """
        Remove a disconnected client.
        """

        if client_socket in self.clients:
            del self.clients[client_socket]

    def set_public_key(self,
                       client_socket,
                       algorithm,
                       public_key):
        """
        Store a client's public key.
        """

        if client_socket in self.clients:

            self.clients[client_socket]["algorithm"] = algorithm

            self.clients[client_socket]["public_key"] = public_key

    def get_username(self, client_socket):
        """
        Return the username for a client.
        """

        if client_socket in self.clients:
            return self.clients[client_socket]["username"]

        return None

    def get_client(self, client_socket):
        """
        Return the complete client information.
        """

        return self.clients.get(client_socket)