"""
Server State

Stores shared resources used by the server.
"""

from logger_config import setup_logger


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
        #         "algorithm": "RSA",
        #         "public_key": "..."
        #     }
        # }
        self.clients = {}

        # Logger
        self.logger = setup_logger(
            "server_logger",
            "server.log"
        )

    def add_client(self, client_socket, username):
        """
        Add a newly connected client.
        """

        self.clients[client_socket] = {
            "username": username,
            "algorithm": None,
            "public_key": None
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