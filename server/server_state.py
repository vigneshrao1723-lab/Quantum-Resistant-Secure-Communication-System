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
        self.clients = {}

        # Logger
        self.logger = setup_logger(
            "server_logger",
            "server.log"
        )