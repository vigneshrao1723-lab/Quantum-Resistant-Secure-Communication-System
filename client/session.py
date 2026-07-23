"""
Client Session

Stores all information related to a connected client.
"""

import socket

from logger_config import setup_logger
from crypto.aes import AESCipher


class ClientSession:
    """
    Represents a single client session.
    """

    def __init__(self):

        # Network socket
        self.client_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        # Client information
        self.username = ""

        # Logger
        self.logger = setup_logger(
            "client_logger",
            "client.log"
        )

        # AES Cipher
        # (Temporary shared key until RSA/Kyber module)
        self.aes = AESCipher()