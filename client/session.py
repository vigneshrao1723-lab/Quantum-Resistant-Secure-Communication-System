"""
Client Session

Stores and manages all information related to a connected client.
Acts as the central controller between the GUI, networking,
and cryptography layers.
"""

import base64
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone

from PySide6.QtCore import QObject, Signal

from client.conversation_store import ConversationStore
from client.receiver import receive_messages
from config import HOST, PORT
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.models.conversation import Conversation
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary, MessagePreview
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from logger_config import setup_logger
from payload.file_adapter import FilePayloadAdapter
from payload.text_adapter import TextPayloadAdapter
from security.tls import build_client_context
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_group_create_packet,
    create_group_key_distribution_packet,
    create_payload_packet,
    create_public_key_packet,
    create_session_key_packet,
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

    message_received = Signal(str, str, str)
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

        # Whether current_chat currently holds a conversation_id
        # (group) rather than a username (direct) -- Phase 4 (Secure
        # Group Messaging Foundation). See set_current_chat().
        self.current_chat_is_group = False

        # The real conversation_id for the active conversation, direct
        # or group alike -- the only identity ever passed to
        # KeyManager (Phase 5 -- Secure Group Key Distribution). Set
        # exclusively by set_current_chat(); never resolved or cached
        # anywhere else in this class.
        self.current_conversation_id = None

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
        # Conversation List (Phase 2)
        #
        # The single source of truth for sidebar/conversation state
        # -- see client/conversation_store.py. Populated once by
        # load_conversations(), then updated incrementally by
        # send_chat_message(), handle_chat(), and handle_user_list().
        # ---------------------------------

        self.conversation_store = ConversationStore()

        # ---------------------------------
        # Payload Pipeline (Phase 3)
        #
        # Payload -> Serialization -> Encryption -> Packet -> Network.
        # A lightweight registry keyed by payload_type -- a future
        # voice or video type registers its own PayloadAdapter here
        # (see payload/adapter.py) without adding branches to
        # send_chat_message()/handle_chat()/_decrypt_history_message()
        # below, which only ever call _adapter_for(). FILE and IMAGE
        # (Phase 6 -- Secure File & Image Transfer Infrastructure)
        # share one FilePayloadAdapter instance per payload_type, since
        # their encryption strategy is identical -- see
        # payload/file_adapter.py.
        # ---------------------------------

        self._payload_adapters = {
            PayloadType.TEXT: TextPayloadAdapter(),
            PayloadType.FILE: FilePayloadAdapter(PayloadType.FILE),
            PayloadType.IMAGE: FilePayloadAdapter(PayloadType.IMAGE),
        }

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

    def _adapter_for(self, payload_type):
        """
        The payload-type routing layer (Phase 4): look up which
        PayloadAdapter handles a given payload_type, so
        send_chat_message()/handle_chat()/_decrypt_history_message()
        never need to branch on payload_type themselves. A future
        payload type is a new self._payload_adapters entry, never a
        new branch in this class.
        """

        return self._payload_adapters[payload_type]

    # ==========================================================
    # Connection Lifecycle
    # ==========================================================

    def connect(self):
        """
        Connect to the chat server over TLS.

        Always builds a fresh socket first: disconnect() closes
        self.client_socket, and ClientSession is reused across a
        logout/login cycle within the same running app (it is not
        recreated), so without this a reconnect would call .connect()
        on an already-closed socket object -- raising
        OSError: [WinError 10038] on Windows.

        TLS Transport Security: the TCP connection is immediately
        wrapped with the authoritative client TLS context
        (security.tls.build_client_context() -- the same function
        every test and the server's own context-building counterpart
        use; no second TLS implementation exists). The handshake --
        including verifying the server's certificate against the
        configured CA and matching its SAN against HOST -- completes
        before this method returns, so self.client_socket is never
        assigned until it is TLS-wrapped. Every packet sent afterwards
        by login()/send_public_key()/send_chat_message()/etc. --
        starting with login()'s JWT -- therefore only ever travels
        over TLS; nothing here changes about what those methods send
        or when they're called. A handshake failure (untrusted
        certificate, wrong host, non-TLS server) raises ssl.SSLError,
        which propagates to this method's existing callers
        (gui/main_window.py, client/client.py), both of which already
        wrap connect() in a generic try/except -- no new error
        handling was needed for this.
        """

        raw_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        raw_socket.connect((HOST, PORT))

        tls_context = build_client_context()

        try:
            self.client_socket = tls_context.wrap_socket(
                raw_socket,
                server_hostname=HOST
            )
        except Exception:
            # A failed handshake (untrusted certificate, wrong host,
            # non-TLS server) must not leak the raw TCP socket -- close
            # it and re-raise unchanged; self.client_socket is left
            # untouched (still __init__'s original, never-connected
            # socket) so a subsequent connect() attempt starts clean.
            raw_socket.close()
            raise

        self.connected = True

        self.connection_changed.emit(True)

        self.logger.info(
            f"Connected to server ({HOST}:{PORT}) over TLS "
            f"({self.client_socket.version()})"
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
        Generate and exchange an AES session key with the currently
        selected direct partner, using whichever algorithm is active
        (Kyber encapsulation or RSA encryption).

        The wire packet is unchanged -- still addressed by
        ``receiver`` (username), since direct routing stays
        username-based (Phase 1's approved scope decision). Only
        where the resulting key is stored changes (Phase 5): under
        ``self.current_conversation_id`` -- the real conversation_id,
        already resolved by set_current_chat() via ConversationStore,
        never looked up here.
        """

        if self.current_chat is None:
            raise ValueError(
                "No active chat partner selected."
            )

        receiver = self.current_chat
        conversation_id = self.current_conversation_id

        if self.key_manager.has_key(conversation_id):
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

        self.key_manager.store_key(
            conversation_id,
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
        Encrypt and send a message to the currently open conversation
        -- direct or group (Phase 4 -- Secure Group Messaging
        Foundation). One shared pipeline: only key lookup (group keys
        need no live exchange) and packet addressing branch; encrypt,
        log, send, and record steps are identical code for both.
        """

        if self.current_chat is None:
            raise ValueError(
                "No chat partner selected."
            )

        if not self.current_chat_is_group:
            self.establish_session_key()

        session_key = self.key_manager.get_key(
            self.current_conversation_id
        )

        if session_key is None:
            raise RuntimeError(
                f"No encryption key for conversation {self.current_conversation_id}"
            )

        aes = AESCipher(session_key)

        envelope = self._adapter_for(PayloadType.TEXT).encrypt(message, aes)

        self.logger.info(
            f"SENT (Encrypted): {envelope.ciphertext}"
        )

        sent_at = datetime.now(timezone.utc)

        if self.current_chat_is_group:

            packet = create_payload_packet(
                sender=self.username,
                envelope=envelope,
                timestamp=sent_at.isoformat(),
                conversation_id=self.current_chat,
            )

        else:

            packet = create_payload_packet(
                sender=self.username,
                envelope=envelope,
                timestamp=sent_at.isoformat(),
                receiver=self.current_chat,
            )

        send_message(
            self.client_socket,
            packet
        )

        self.conversation_store.record_message(
            self.current_chat,
            MessagePreview(
                payload_type=PayloadType.TEXT,
                text=message,
                timestamp=sent_at.replace(tzinfo=None),
            ),
            is_own=True,
            is_online=(
                False
                if self.current_chat_is_group
                else self.current_chat in self.online_users
            ),
        )

    def _decrypt_history_message(self, conversation_id, ciphertext):
        """
        Best-effort AES decryption of a stored historical message.

        ``conversation_id`` is always the real conversation_id now
        (Phase 5 -- Secure Group Key Distribution), direct or group
        alike -- KeyManager.keys is addressed by nothing else; this
        method needs no branch for either.

        Reuses the currently cached key, if any -- never establishes a
        new one (history loading must not trigger a fresh key
        exchange). Never raises: returns the placeholder text if no
        key is cached, or if AES-GCM authentication fails (the message
        was encrypted under a different, since-discarded key from a
        previous session).
        """

        session_key = self.key_manager.get_key(conversation_id)

        if session_key is None:
            return _UNDECRYPTABLE_PLACEHOLDER

        try:
            envelope = PayloadEnvelope(
                payload_type=PayloadType.TEXT, ciphertext=ciphertext, content_metadata={}
            )
            return self._adapter_for(PayloadType.TEXT).decrypt(envelope, AESCipher(session_key))
        except Exception:
            return _UNDECRYPTABLE_PLACEHOLDER

    def load_conversation_history(self, key, is_group=False):
        """
        Load and best-effort decrypt the stored conversation history
        for a direct partner (``key`` = username, the default) or a
        group (``key`` = conversation_id, Phase 4 -- Secure Group
        Messaging Foundation).

        One shared method, not a sibling per addressing mode: only
        which repository query to run and how to resolve each row's
        sender name differ; decrypting and building the returned dict
        is identical code either way. Every existing caller is
        unaffected -- ``is_group`` defaults to False.

        Returns a plain list of dicts, ordered chronologically exactly
        as stored:
            {"sender": str, "text": str, "timestamp": datetime, "is_own": bool}
        """

        db = SessionLocal()

        try:
            message_repo = MessageRepository(db)

            own_id = uuid.UUID(self.user_id)

            if is_group:

                conversation_id = uuid.UUID(key)

                messages = message_repo.get_group_conversation(conversation_id)

                conversation_repo = ConversationRepository(db)
                user_repo = UserRepository(db)

                member_ids = conversation_repo.get_member_user_ids(conversation_id)

                usernames_by_id = {}

                for member_id in member_ids:
                    member = user_repo.get_by_id(member_id)
                    if member is not None:
                        usernames_by_id[member_id] = member.username

                # Already a real conversation_id -- the KeyManager
                # identity (Phase 5) and the addressing key are the
                # same value for a group.
                decrypt_key = key

            else:

                user_repo = UserRepository(db)

                partner = user_repo.get_by_username(key)

                if partner is None:
                    return []

                messages = message_repo.get_conversation(own_id, partner.id)

                # Resolve the real conversation_id for the KeyManager
                # lookup (Phase 5) -- via ConversationStore, the sole
                # place this is ever resolved; a cache hit in the
                # overwhelming common case, since opening this
                # conversation already resolved it (set_current_chat()).
                # Skipped entirely when there's no history to decrypt,
                # so viewing an empty/new conversation never touches
                # the database from here.
                decrypt_key = (
                    self.conversation_store.ensure_direct_conversation_id(
                        self.user_id, key
                    )
                    if messages else None
                )

            history = []

            for message in messages:

                is_own = message.sender_id == own_id

                if is_group:
                    sender_name = (
                        self.username if is_own
                        else usernames_by_id.get(message.sender_id, "Unknown")
                    )
                else:
                    sender_name = self.username if is_own else key

                text = self._decrypt_history_message(
                    decrypt_key,
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

    def load_conversations(self):
        """
        Load this user's conversations from PostgreSQL into
        conversation_store -- the single source of truth for sidebar
        state (see client/conversation_store.py). Called once, at
        chat startup; from then on the store is updated incrementally
        by send_chat_message(), handle_chat(), and handle_user_list(),
        never by another full reload.

        Reuses the existing best-effort decrypt helper
        (_decrypt_history_message) -- no new cryptography.
        """

        db = SessionLocal()

        try:
            conversation_repo = ConversationRepository(db)

            previews = conversation_repo.get_conversation_previews_for_user(
                uuid.UUID(self.user_id)
            )

            summaries = []

            for preview in previews:

                if preview.conversation.type == Conversation.TYPE_GROUP:

                    conversation_id = str(preview.conversation.id)
                    participant_usernames = [p.username for p in preview.participants]

                    latest_message = None

                    if preview.latest_message is not None:

                        text = self._decrypt_history_message(
                            conversation_id,
                            preview.latest_message.ciphertext
                        )

                        latest_message = MessagePreview(
                            payload_type=PayloadType.TEXT,
                            text=text,
                            timestamp=preview.latest_message.timestamp,
                        )

                    summaries.append(
                        ConversationSummary(
                            conversation_id=conversation_id,
                            username=None,
                            is_online=False,
                            latest_message=latest_message,
                            is_group=True,
                            group_name=preview.conversation.name,
                            participants=participant_usernames,
                        )
                    )

                    continue

                partner = preview.participants[0] if preview.participants else None

                if partner is None:
                    continue

                latest_message = None

                if preview.latest_message is not None:

                    # The real conversation_id, already known from
                    # this query -- the KeyManager identity (Phase 5),
                    # not the partner's username.
                    text = self._decrypt_history_message(
                        str(preview.conversation.id),
                        preview.latest_message.ciphertext
                    )

                    latest_message = MessagePreview(
                        payload_type=PayloadType.TEXT,
                        text=text,
                        timestamp=preview.latest_message.timestamp,
                    )

                summaries.append(
                    ConversationSummary(
                        conversation_id=str(preview.conversation.id),
                        username=partner.username,
                        is_online=partner.username in self.online_users,
                        latest_message=latest_message,
                    )
                )

            self.conversation_store.set_initial(summaries)
        finally:
            db.close()

    @staticmethod
    def _parse_incoming_timestamp(raw_timestamp):
        """
        Best-effort parse of a chat packet's ISO 8601 timestamp, for
        conversation_store ordering. Mirrors
        server/client_handler.py::_parse_message_timestamp -- same
        naive-UTC convention as every stored timestamp in this
        codebase, and falls back to now() rather than failing message
        handling over a malformed or missing value.
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

        elif packet_type == "group_create_result":
            self.handle_group_create_result(packet)

        elif packet_type == "group_key_distribution":
            self.handle_group_key_distribution(packet)

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

        self.conversation_store.update_online_status(self.online_users)

        self.users_updated.emit(
            self.online_users
        )

    # ----------------------------------------------------------

    def handle_chat(self, packet):
        """
        Handle an incoming "chat" packet -- direct or group (Phase 4
        -- Secure Group Messaging Foundation), addressed by
        conversation_id or by receiver respectively (see
        create_payload_packet()). ``sender`` is always the individual
        who wrote the message, for bubble display, whether direct or
        group.

        Two distinct identities, kept deliberately separate:
        ``identity_key`` is the ConversationStore/GUI addressing key,
        unchanged since Phase 4 (conversation_id for group, sender's
        username for direct). ``key_conversation_id`` (Phase 5 --
        Secure Group Key Distribution) is the KeyManager lookup
        identity -- always the real conversation_id, resolved via
        ConversationStore for a direct message (a cache hit in the
        common case: the conversation was already opened, or a
        message was already exchanged, either of which already
        resolved it).
        """

        sender = packet["sender"]

        conversation_id = packet.get("conversation_id")

        is_group = bool(conversation_id)

        identity_key = conversation_id if is_group else sender

        key_conversation_id = (
            conversation_id if is_group
            else self.conversation_store.ensure_direct_conversation_id(
                self.user_id, sender
            )
        )

        encrypted_message = packet["message"]

        session_key = None

        for _ in range(10):

            session_key = self.key_manager.get_key(
                key_conversation_id
            )

            if session_key is not None:
                break

            time.sleep(0.1)

        if session_key is None:

            self.logger.warning(
                f"No AES session key for {identity_key}"
            )

            self.error_occurred.emit(
                f"No AES session key found for {identity_key}."
            )

            return

        aes = AESCipher(session_key)

        envelope = PayloadEnvelope(
            payload_type=packet.get("payload_type") or PayloadType.TEXT,
            ciphertext=encrypted_message,
            content_metadata=packet.get("content_metadata") or {},
        )

        decrypted_message = self._adapter_for(envelope.payload_type).decrypt(envelope, aes)

        self.logger.info(
            f"RECEIVED: {sender}: {decrypted_message}"
        )

        self.conversation_store.record_message(
            identity_key,
            MessagePreview(
                payload_type=PayloadType.TEXT,
                text=decrypted_message,
                timestamp=self._parse_incoming_timestamp(packet.get("timestamp")),
            ),
            is_own=False,
            is_online=(False if is_group else sender in self.online_users),
        )

        self.message_received.emit(
            identity_key,
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
            "system",
            f"Received {algorithm} public key from {username}."
        )

    # ----------------------------------------------------------

    def handle_session_key(self, packet):
        """
        Store an incoming direct session key under the real
        conversation_id (Phase 5), resolved via ConversationStore --
        never looked up or cached here. Decryption/decapsulation
        itself is unrelated to conversation identity and unchanged.
        """

        sender = packet["sender"]

        conversation_id = self.conversation_store.ensure_direct_conversation_id(
            self.user_id, sender
        )

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

        self.key_manager.store_key(
            conversation_id,
            session_key
        )

        self.logger.info(
            f"Session key established with {sender}"
        )

        self.message_received.emit(
            "system",
            "system",
            f"Secure session established with {sender}."
        )

    # ----------------------------------------------------------

    def handle_group_create_result(self, packet):
        """
        A group conversation this user belongs to was created (or
        this client is catching up on one it wasn't yet aware of) --
        sent to every currently connected member, including the
        creator (see server/client_handler.py::handle_group_create()).

        Adds/refreshes the group in conversation_store so it appears
        in the sidebar, then, if this client is the creator, generates
        and distributes the group key -- the only client that ever
        generates one.
        """

        conversation_id = packet["conversation_id"]

        name = packet["name"]

        members = packet.get("members", [])

        creator = packet.get("creator")

        participants = [m for m in members if m != self.username]

        self.conversation_store.add_or_update_group(
            conversation_id, name, participants
        )

        self.logger.info(
            f"Group '{name}' ({conversation_id}) ready -- members: {members}"
        )

        if creator == self.username:
            self._create_and_distribute_group_key(conversation_id, participants)

    def _create_and_distribute_group_key(self, conversation_id, participants):
        """
        Generate a fresh group key and deliver it to every other
        member whose public key is already known -- see
        crypto/key_manager.py::wrap_key_for_member() for the
        KEM-then-DEM composition. A member with no cached public key
        (never online this session) does not receive it; retroactive
        delivery to a late-joining or previously-offline member is out
        of scope for this foundation phase.
        """

        group_key = os.urandom(32)

        self.key_manager.store_key(conversation_id, group_key)

        for member in participants:

            if self.key_manager.get_public_key(member) is None:

                self.logger.warning(
                    f"No public key for {member}; cannot distribute "
                    f"group key for {conversation_id}."
                )

                continue

            encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(
                member, group_key
            )

            packet = create_group_key_distribution_packet(
                sender=self.username,
                conversation_id=conversation_id,
                recipient=member,
                encapsulation=encapsulation,
                wrapped_key=wrapped_key,
            )

            send_message(
                self.client_socket,
                packet
            )

        self.logger.info(
            f"Distributed group key for {conversation_id} to {participants}"
        )

    def handle_group_key_distribution(self, packet):
        """
        Recover this client's wrapped copy of a group key -- see
        crypto/key_manager.py::unwrap_received_key(). Uses only this
        client's own private key material; nothing from the sender is
        needed beyond the packet's opaque fields.
        """

        if packet.get("recipient") != self.username:
            return

        conversation_id = packet["conversation_id"]

        group_key = self.key_manager.unwrap_received_key(
            packet["encapsulation"], packet["wrapped_key"]
        )

        self.key_manager.store_key(conversation_id, group_key)

        self.logger.info(
            f"Group key established for conversation {conversation_id}"
        )

    def create_group_conversation(self, name, member_usernames):
        """
        Ask the server to create a new group conversation. The result
        (including this client's own confirmation) arrives
        asynchronously via handle_group_create_result() -- there is no
        optimistic local update; the server's confirmation is the
        single source of truth, exactly as for every other
        conversation-store change.
        """

        packet = create_group_create_packet(
            sender=self.username,
            name=name,
            member_usernames=member_usernames,
        )

        send_message(
            self.client_socket,
            packet
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

    def set_current_chat(self, summary):
        """
        Select the active conversation from its ConversationSummary
        (Phase 5 -- Secure Group Key Distribution: ChatWindow passes
        the whole object, not a bare key, since ConversationStore is
        the sole source of conversation identity).

        self.current_chat / self.current_chat_is_group keep their
        Phase 4 meaning unchanged -- used for packet addressing and
        the ConversationStore key: a username for direct, the
        conversation_id for group.

        self.current_conversation_id is new here: always the real
        conversation_id, direct or group alike -- the only identity
        ever passed to KeyManager from this point on. For a group it's
        already known (summary.conversation_id). For a direct
        conversation it's resolved via ConversationStore -- which may
        create it, for a conversation with no messages yet -- never
        looked up or cached by ClientSession itself.
        """

        self.current_chat = summary.key
        self.current_chat_is_group = summary.is_group

        if summary.is_group or summary.conversation_id is not None:
            self.current_conversation_id = summary.conversation_id
        else:
            self.current_conversation_id = (
                self.conversation_store.ensure_direct_conversation_id(
                    self.user_id, summary.username
                )
            )

    def get_current_chat(self):
        """
        Returns the active conversation's key (username or
        conversation_id -- see set_current_chat()).
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