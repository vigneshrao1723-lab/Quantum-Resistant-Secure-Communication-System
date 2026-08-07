"""
Client Session

Stores and manages all information related to a connected client.
Acts as the central controller between the GUI, networking,
and cryptography layers.
"""

import socket
import threading
import time
import base64
import os
import uuid
from datetime import datetime, timezone

from PySide6.QtCore import QObject, Signal

from client.receiver import receive_messages
from config import HOST, PORT
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.repositories.message_repository import MessageRepository
from database.repositories.user_repository import UserRepository
from logger_config import setup_logger
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_public_key_packet,
    create_session_key_packet,
    create_chat_packet,
)

# Placeholder shown for a historical message that cannot be decrypted
# with the currently cached AES session key (e.g. it was encrypted in
# a previous run, under a key that no longer exists in memory).
_UNDECRYPTABLE_PLACEHOLDER = "Message unavailable (encrypted in a previous session)"


class ClientSession(QObject):
    """
    Represents a single client session.

    Responsible for maintaining the client's runtime state
    and coordinating networking, cryptography and the GUI.
    """

    # ==========================================================
    # Qt Signals
    # ==========================================================

    message_received = Signal(str, str)
    users_updated = Signal(list)
    error_occurred = Signal(str)
    connection_changed = Signal(bool)

    def __init__(self):
        super().__init__()

        # ---------------------------------
        # Network Socket
        # ---------------------------------

        self.client_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        self.connected = False
        self.receiver_thread = None

        # ---------------------------------
        # Client Information
        # ---------------------------------

        self.user_id = None
        self.username = ""
        self.session_id = None
        self.access_token = None
        self.refresh_token = None
        self.current_chat = None

        # ---------------------------------
        # Online Users
        # ---------------------------------

        self.online_users = []

        # ---------------------------------
        # Unread Message Counts
        #
        # Client-side only, in-memory for the lifetime of the app.
        # {username: count}
        # ---------------------------------

        self.unread_counts = {}

        # ---------------------------------
        # Legacy Terminal UI
        # (Will be removed later)
        # ---------------------------------

        self.ui = None
        self.input_text = ""
        self.messages = []
        self.refresh_required = False
        self.selected_user_index = 0
        self.chat_selected = False

        # ---------------------------------
        # Logger
        # ---------------------------------

        self.logger = setup_logger(
            "client_logger",
            "client.log"
        )

        # ---------------------------------
        # Cryptography
        # ---------------------------------

        self.key_manager = KeyManager()

        # ---------------------------------
        # Legacy Callbacks
        # (Temporary during migration)
        # ---------------------------------

        self.on_message = None
        self.on_users_changed = None
        self.on_connection_changed = None
        self.on_error = None

    # ==========================================================
    # Connection Lifecycle
    # ==========================================================

    def connect(self):
        """
        Connect to the chat server.

        Always builds a fresh socket first: disconnect() closes
        self.client_socket, and ClientSession is reused across a
        logout/login cycle within the same running app (it is not
        recreated), so without this a reconnect would call .connect()
        on an already-closed socket object -- raising
        OSError: [WinError 10038] on Windows.
        """

        self.client_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        self.client_socket.connect((HOST, PORT))

        self.connected = True

        self.connection_changed.emit(True)

        self.logger.info(
            f"Connected to server ({HOST}:{PORT})"
        )

    def login(self, username):
        """
        Authenticate this client with the server using the JWT
        access token obtained earlier from AuthenticationService
        (set on self.access_token before this call), then wait for
        the server's authentication result before proceeding.

        Raises PermissionError if no access token is available or
        the server rejects the token (expired, invalid, inactive,
        or locked user).
        """

        username = username.strip()

        if not username:
            username = "Anonymous"

        self.username = username

        if not self.access_token:
            raise PermissionError(
                "No access token available. Please log in again."
            )

        send_message(
            self.client_socket,
            create_auth_packet(self.access_token)
        )

        self.logger.info(
            "Sent authentication request to server."
        )

        response = receive_message(self.client_socket)

        if not isinstance(response, dict) or response.get("type") != "auth_result":
            raise PermissionError(
                "Server did not respond to the authentication request."
            )

        if not response.get("success"):
            raise PermissionError(
                response.get("message") or "Authentication failed."
            )

        # The server derives the authoritative username from the
        # validated JWT/DB record rather than trusting the client.
        server_username = response.get("username")

        if server_username:
            self.username = server_username

        self.logger.info(
            f"Authenticated as {self.username}."
        )

    def send_public_key(self):
        """
        Send this client's public key (Kyber or RSA,
        depending on config.KEY_EXCHANGE_ALGORITHM)
        to the server.
        """

        algorithm = self.key_manager.algorithm

        public_key_packet = create_public_key_packet(
            username=self.username,
            algorithm=algorithm,
            public_key=self.key_manager.public_key.decode(
                "utf-8"
            )
        )

        send_message(
            self.client_socket,
            public_key_packet
        )

        self.logger.info(
            f"{algorithm} public key sent to server."
        )

    def start_receiver(self):
        """
        Start the receiver thread.
        """

        if self.receiver_thread is not None:
            return

        self.receiver_thread = threading.Thread(
            target=receive_messages,
            args=(self,),
            daemon=True
        )

        self.receiver_thread.start()

        self.logger.info(
            "Receiver thread started."
        )

    def disconnect(self):
        """
        Gracefully disconnect.
        """

        self.logger.info(
            "Closing connection..."
        )

        self.connected = False

        self.connection_changed.emit(False)

        # Guard against a redundant disconnect() call (e.g. a rapid
        # double-click on Logout): client_socket is None once already
        # disconnected, and shutdown()/close() have nothing to do.
        if self.client_socket is not None:

            try:
                self.client_socket.shutdown(
                    socket.SHUT_RDWR
                )

            except OSError:
                pass

            self.client_socket.close()

            # Drop the reference to the now-closed socket object rather
            # than leaving it dangling. Doesn't change behavior beyond
            # this -- connect() already unconditionally builds a fresh
            # socket every time -- but makes the "not connected" state
            # unambiguous instead of a closed-yet-still-truthy socket
            # object sitting here.
            self.client_socket = None

        if self.receiver_thread is not None:

            self.receiver_thread.join(timeout=2)

            self.receiver_thread = None

        self.logger.info(
            "Disconnected."
        )

    def establish_session_key(self):
        """
        Generate and exchange an AES session key
        with the currently selected user, using
        whichever algorithm is active
        (Kyber encapsulation or RSA encryption).
        """

        if self.current_chat is None:
            raise ValueError(
                "No active chat partner selected."
            )

        receiver = self.current_chat

        if self.key_manager.has_session_key(receiver):
            return

        algorithm = self.key_manager.algorithm

        if algorithm == "KYBER":

            # Kyber derives the shared secret and its
            # encapsulation together -- there is no
            # separate "generate then encrypt" step.
            encrypted_key, session_key = (
                self.key_manager.encapsulate_session_key(
                    receiver
                )
            )

        else:

            session_key = os.urandom(32)

            encrypted_key = self.key_manager.encrypt_session_key(
                receiver,
                session_key
            )

            encrypted_key = base64.b64encode(
                encrypted_key
            ).decode("utf-8")

        self.key_manager.add_session_key(
            receiver,
            session_key
        )

        self.logger.info(
            f"Generated AES session key for {receiver} "
            f"({algorithm})"
        )

        packet = create_session_key_packet(
            sender=self.username,
            receiver=receiver,
            algorithm=algorithm,
            encrypted_key=encrypted_key
        )

        send_message(
            self.client_socket,
            packet
        )

        self.logger.info(
            f"Secure session established with {receiver}"
        )

        time.sleep(0.2)

    def send_chat_message(self, message):
        """
        Encrypt and send a private message.
        """

        if self.current_chat is None:
            raise ValueError(
                "No chat partner selected."
            )

        self.establish_session_key()

        session_key = self.key_manager.get_session_key(
            self.current_chat
        )

        if session_key is None:
            raise RuntimeError(
                f"No AES session key for {self.current_chat}"
            )

        aes = AESCipher(session_key)

        encrypted_message = aes.encrypt(message)

        self.logger.info(
            f"SENT (Encrypted): {encrypted_message}"
        )

        packet = create_chat_packet(
            sender=self.username,
            receiver=self.current_chat,
            message=encrypted_message,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        send_message(
            self.client_socket,
            packet
        )

    def _decrypt_history_message(self, partner_username, ciphertext):
        """
        Best-effort AES decryption of a stored historical message.

        Reuses the currently cached session key for this partner, if
        any -- never establishes a new one (history loading must not
        trigger a fresh key exchange). Never raises: returns the
        placeholder text if no key is cached, or if AES-GCM
        authentication fails (the message was encrypted under a
        different, since-discarded key from a previous session).
        """

        session_key = self.key_manager.get_session_key(partner_username)

        if session_key is None:
            return _UNDECRYPTABLE_PLACEHOLDER

        try:
            return AESCipher(session_key).decrypt(ciphertext)
        except Exception:
            return _UNDECRYPTABLE_PLACEHOLDER

    def load_conversation_history(self, partner_username):
        """
        Load and best-effort decrypt the stored conversation history
        with a partner from PostgreSQL.

        Reuses the existing MessageRepository.get_conversation() query
        and the current user's already-known UUID (self.user_id, set
        at login) -- the only new database lookup is resolving the
        partner's username to their UUID via the existing
        UserRepository. No new SQL, no new repository methods, no
        protocol or packet changes.

        This method performs no GUI operations; it returns a plain
        list of dicts, ordered chronologically exactly as stored:
            {"sender": str, "text": str, "timestamp": datetime, "is_own": bool}
        """

        db = SessionLocal()

        try:
            user_repo = UserRepository(db)
            message_repo = MessageRepository(db)

            partner = user_repo.get_by_username(partner_username)

            if partner is None:
                return []

            own_id = uuid.UUID(self.user_id)

            conversation = message_repo.get_conversation(own_id, partner.id)

            history = []

            for message in conversation:

                is_own = message.sender_id == own_id

                sender_name = self.username if is_own else partner_username

                text = self._decrypt_history_message(
                    partner_username,
                    message.ciphertext
                )

                history.append({
                    "sender": sender_name,
                    "text": text,
                    "timestamp": message.timestamp,
                    "is_own": is_own,
                })

            return history
        finally:
            db.close()

    # ==========================================================
    # Packet Handlers
    # ==========================================================

    def handle_packet(self, packet):
        """
        Route an incoming packet to the
        appropriate handler.
        """

        packet_type = packet.get("type")

        if packet_type == "join":
            self.handle_join(packet)

        elif packet_type == "leave":
            self.handle_leave(packet)

        elif packet_type == "user_list":
            self.handle_user_list(packet)

        elif packet_type == "chat":
            self.handle_chat(packet)

        elif packet_type == "delivery_failure":
            self.handle_delivery_failure(packet)

        elif (
            packet_type == "key_exchange"
            and packet.get("operation") == "public_key"
        ):
            self.handle_public_key(packet)

        elif (
            packet_type == "key_exchange"
            and packet.get("operation") == "session_key"
        ):
            self.handle_session_key(packet)

        else:

            self.logger.warning(
                f"Unknown packet: {packet_type}"
            )

    # ----------------------------------------------------------

    def handle_join(self, packet):

        username = packet["username"]

        self.logger.info(
            f"{username} joined"
        )

        self.message_received.emit(
            "system",
            f"{username} joined the chat."
        )

    # ----------------------------------------------------------

    def handle_leave(self, packet):

        username = packet["username"]

        self.logger.info(
            f"{username} left"
        )

        self.message_received.emit(
            "system",
            f"{username} left the chat."
        )

    # ----------------------------------------------------------

    def handle_user_list(self, packet):

        self.online_users = packet.get(
            "users",
            []
        )

        self.logger.info(
            f"Updated online users: {self.online_users}"
        )

        self.users_updated.emit(
            self.online_users
        )

    # ----------------------------------------------------------

    def handle_chat(self, packet):

        sender = packet["sender"]

        encrypted_message = packet["message"]

        session_key = None

        for _ in range(10):

            session_key = self.key_manager.get_session_key(
                sender
            )

            if session_key is not None:
                break

            time.sleep(0.1)

        if session_key is None:

            self.logger.warning(
                f"No AES session key for {sender}"
            )

            self.error_occurred.emit(
                f"No AES session key found for {sender}."
            )

            return

        aes = AESCipher(session_key)

        decrypted_message = aes.decrypt(
            encrypted_message
        )

        self.logger.info(
            f"RECEIVED: {sender}: {decrypted_message}"
        )

        self.message_received.emit(
            sender,
            decrypted_message
        )

    # ----------------------------------------------------------

    def handle_delivery_failure(self, packet):

        receiver = packet.get("receiver")

        reason = packet.get(
            "reason",
            "Message could not be delivered."
        )

        self.logger.warning(
            f"Delivery failed to {receiver}: {reason}"
        )

        self.error_occurred.emit(
            f"Could not deliver message to {receiver}: {reason}"
        )

    # ----------------------------------------------------------

    def handle_public_key(self, packet):

        username = packet["username"]

        algorithm = packet["algorithm"]

        public_key = packet["public_key"]

        self.key_manager.add_public_key(
            username,
            public_key
        )

        self.logger.info(
            f"Stored {algorithm} public key for {username}"
        )

        self.message_received.emit(
            "system",
            f"Received {algorithm} public key from {username}."
        )

    # ----------------------------------------------------------

    def handle_session_key(self, packet):

        sender = packet["sender"]

        algorithm = packet.get(
            "algorithm",
            self.key_manager.algorithm
        )

        if algorithm == "KYBER":

            session_key = (
                self.key_manager.decapsulate_session_key(
                    packet["encrypted_key"]
                )
            )

        else:

            encrypted_key = base64.b64decode(
                packet["encrypted_key"]
            )

            session_key = (
                self.key_manager.decrypt_session_key(
                    encrypted_key
                )
            )

        self.key_manager.add_session_key(
            sender,
            session_key
        )

        self.logger.info(
            f"Session key established with {sender}"
        )

        self.message_received.emit(
            "system",
            f"Secure session established with {sender}."
        )

    # ==========================================================
    # Utility Methods
    # ==========================================================

    def is_connected(self):
        """
        Returns the connection status.
        """
        return self.connected

    def get_username(self):
        """
        Returns the logged-in username.
        """
        return self.username

    def get_online_users(self):
        """
        Returns the current online users list.
        """
        return self.online_users

    def set_current_chat(self, username):
        """
        Select the active chat partner.
        """
        self.current_chat = username

    def get_current_chat(self):
        """
        Returns the active chat partner.
        """
        return self.current_chat

    def increment_unread(self, username):
        """
        Increment and return the unread count for a user.
        """
        self.unread_counts[username] = self.unread_counts.get(username, 0) + 1
        return self.unread_counts[username]

    def clear_unread(self, username):
        """
        Reset the unread count for a user to zero.
        """
        self.unread_counts[username] = 0

    def get_unread_count(self, username):
        """
        Returns the current unread count for a user.
        """
        return self.unread_counts.get(username, 0)