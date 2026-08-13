"""
Client Session

Stores and manages all information related to a connected client.
Acts as the central controller between the GUI, networking,
and cryptography layers.
"""

import base64
import mimetypes
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from auth.schemas import AuthenticationResult, RegistrationResult, TokenPair
from client.conversation_store import ConversationStore
from client.receiver import receive_messages
from config import (
    MAX_ATTACHMENT_SIZE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    SERVER_HOST,
    SERVER_PORT,
)
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.models.conversation import Conversation
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary, MessagePreview
from domain.message_delivery_status import MessageDeliveryStatus
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import (
    BLOB_STORAGE_PAYLOAD_TYPES,
    PayloadType,
    classify_attachment,
)
from logger_config import setup_logger
from payload.file_adapter import FilePayloadAdapter
from payload.text_adapter import TextPayloadAdapter
from security.tls import build_client_context
from storage import encrypted_blob_store
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_group_add_members_packet,
    create_group_create_packet,
    create_group_key_distribution_packet,
    create_group_key_rotation_complete_packet,
    create_group_leave_packet,
    create_login_request_packet,
    create_logout_request_packet,
    create_payload_packet,
    create_public_key_packet,
    create_read_receipt_packet,
    create_register_request_packet,
    create_session_key_packet,
    create_user_lookup_request_packet,
)
from utils.request_registry import PendingRequestRegistry, RequestTimeoutError

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

    # Phase 8 -- File & Image Transfer: a separate signal for binary
    # payload content (identity_key, sender, payload_type,
    # content: bytes, content_metadata: dict). message_received stays
    # Signal(str, str, str) and TEXT-only, unmodified -- Qt signals are
    # fixed-type, so bytes cannot flow through it; this is additive,
    # not a replacement.
    payload_message_received = Signal(str, str, str, bytes, dict)

    # C2 -- Read Receipts: identity_key (the GUI addressing key -- see
    # ClientSession.handle_chat()'s docstring), reader's username.
    # Purely a live-update signal for a conversation that's already
    # open -- the authoritative read status is always re-derived from
    # the database at load_conversation_history() time (see its
    # "read_status" field), so a client that never receives this
    # signal (e.g. the conversation isn't open) is not out of sync --
    # it just sees the correct status next time it opens/reloads.
    read_receipt_updated = Signal(str, str)

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
        # Request/Response Correlation (D1 -- Request/Response
        # Infrastructure)
        #
        # Lets send_request() block the calling thread for its own
        # reply while the receiver thread (client/receiver.py) keeps
        # dispatching every other incoming packet normally -- see
        # utils/request_registry.py. Rebuilt fresh per ClientSession
        # instance/connection; nothing here survives a reconnect, so a
        # request from a previous connection can never be resolved by
        # a reply on a new one.
        # ---------------------------------

        self._pending_requests = PendingRequestRegistry()

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
        configured CA and matching its SAN against SERVER_HOST -- completes
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

        raw_socket.connect((SERVER_HOST, SERVER_PORT))

        tls_context = build_client_context()

        try:
            self.client_socket = tls_context.wrap_socket(
                raw_socket,
                # SERVER_HOST is both what we dialled and what the
                # certificate's SAN must cover (D0 -- Configuration &
                # Network Separation): pointing a client at a LAN IP
                # or DNS name therefore also changes what the TLS
                # handshake verifies, with no code change. The
                # certificate must list that address -- see
                # config.TLS_CERT_SANS.
                server_hostname=SERVER_HOST
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
            f"Connected to server ({SERVER_HOST}:{SERVER_PORT}) over TLS "
            f"({self.client_socket.version()})"
        )

    def send_request(self, packet, timeout=REQUEST_TIMEOUT_SECONDS):
        """
        Send ``packet`` and block the calling thread until a response
        carrying a matching ``request_id`` arrives, or ``timeout``
        seconds elapse (D1 -- Request/Response Infrastructure).

        Requires the receiver thread to already be running (see
        start_receiver()) -- the response is delivered by
        handle_packet() being called from that thread, exactly like
        every other incoming packet; nothing here reads the socket
        itself. Calling this before start_receiver() (or after
        disconnect()) will simply time out, since nothing will ever
        call handle_packet() to resolve it.

        Purely correlation plumbing: it attaches a request_id, sends,
        and waits. It has no opinion on packet shape or content --
        the caller passes a complete packet dict (any existing
        create_*_packet() helper's output, or a plain dict), and gets
        the raw response packet dict back. No packet type currently
        opts into this path; adding one is a later phase's job (see
        docs/architecture -- D1 only adds the mechanism).

        Raises ``utils.request_registry.RequestTimeoutError`` if no
        matching response arrives in time. Any exception raised while
        sending (e.g. a dead socket) propagates immediately, and the
        pending registration is cleaned up first so nothing is left
        waiting for a request that was never actually sent.
        """

        request_id = self._pending_requests.new_request_id()

        packet = dict(packet)
        packet["request_id"] = request_id

        self._pending_requests.register(request_id)

        try:
            send_message(self.client_socket, packet)
        except Exception:
            self._pending_requests.cancel(request_id)
            raise

        try:
            return self._pending_requests.wait(request_id, timeout)
        except RequestTimeoutError:
            self.logger.warning(
                f"Timed out waiting for a response to "
                f"{packet.get('type')!r} (request_id={request_id})"
            )
            raise

    def authenticate_credentials(self, identifier, password):
        """
        Authenticate a username/email + password against the server
        (D2 -- Server-Side API / Authentication Migration; final slice,
        replacing gui/main_window.py's and client/client.py's previous
        direct, local AuthenticationService.authenticate_user() call).
        This is what obtains the JWT access/refresh tokens login()
        below then sends -- password verification and token issuance
        happen only on the server (AuthenticationService.
        authenticate_user(), unchanged); nothing here duplicates or
        second-guesses it, and the password hash is never part of the
        response.

        Opens and tears down its own short-lived connection, exactly
        like register(): this runs before any user identity, JWT, or
        receiver thread exists, so -- like register() and login()
        itself -- it talks to the server directly (send_message()/
        receive_message() on the calling thread) rather than through
        send_request()/D1's PendingRequestRegistry, which requires
        start_receiver() to already be running. The connection this
        method opens is always closed again before returning,
        regardless of outcome; the caller makes a completely separate,
        subsequent connect() (see start_chat_session()) before ever
        calling login() with the tokens this returns.

        Returns an auth.schemas.AuthenticationResult reconstructed from
        the server's response -- the same shape
        AuthenticationService.authenticate_user() already returned
        locally, so callers need no changes beyond how this result is
        obtained.

        Raises ConnectionError if the server's response is missing or
        malformed. Any exception raised by connect() itself (e.g. a
        failed TLS handshake) propagates unchanged.
        """

        self.connect()

        try:
            packet = create_login_request_packet(
                identifier=identifier,
                password=password,
            )
            packet["request_id"] = str(uuid.uuid4())

            send_message(self.client_socket, packet)

            response = receive_message(self.client_socket)
        finally:
            self.disconnect()

        if not isinstance(response, dict) or response.get("type") != "login_result":
            raise ConnectionError(
                "Server did not respond to the login request."
            )

        token_pair = None

        if response.get("access_token") and response.get("refresh_token"):
            token_pair = TokenPair(
                access_token=response["access_token"],
                refresh_token=response["refresh_token"],
                expires_in=response.get("expires_in"),
                token_type=response.get("token_type") or "Bearer",
            )

        return AuthenticationResult(
            success=bool(response.get("success")),
            message=response.get("message") or "Authentication failed.",
            user_id=response.get("user_id"),
            username=response.get("username"),
            role=response.get("role"),
            session_id=response.get("session_id"),
            token_pair=token_pair,
            errors=response.get("errors"),
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

    def register(
        self,
        full_name,
        username,
        email,
        password,
        confirm_password
    ):
        """
        Register a new user account via the server (D2 -- Server-Side
        API / Authentication Migration; second slice, replacing
        gui/main_window.py's previous direct, local
        AuthenticationService/PostgreSQL call).

        Opens and tears down its own short-lived connection: this is
        called from the login screen, before any user identity, JWT,
        or receiver thread exists -- self.connect() is otherwise only
        ever reached via a successful login (see
        start_chat_session()). The connection is always closed again
        before returning, regardless of outcome, so login() (untouched
        by this migration) still always starts from its own fresh
        connect() afterward.

        Like login() -- the only other request/response exchange that
        also runs before any receiver thread exists -- this talks to
        the server directly (send_message()/receive_message() on the
        calling thread) rather than through send_request()/D1's
        PendingRequestRegistry, which requires start_receiver() to
        already be running; forcing that machinery on for a single,
        exclusive, one-shot exchange would add no correlation benefit.

        Returns an auth.schemas.RegistrationResult reconstructed from
        the server's response -- the same shape
        AuthenticationService.register_user() already returned
        locally, so gui/main_window.py::handle_registration() needed
        no changes beyond how this result is obtained. Validation
        (password policy, username/email uniqueness, etc.) is still
        performed entirely server-side by that same, unchanged
        register_user() -- nothing here duplicates or second-guesses
        it.

        Raises ConnectionError if the server's response is missing or
        malformed. Any exception raised by connect() itself (e.g. a
        failed TLS handshake) propagates unchanged.
        """

        self.connect()

        try:
            packet = create_register_request_packet(
                full_name=full_name,
                username=username,
                email=email,
                password=password,
                confirm_password=confirm_password,
            )
            packet["request_id"] = str(uuid.uuid4())

            send_message(self.client_socket, packet)

            response = receive_message(self.client_socket)
        finally:
            self.disconnect()

        if not isinstance(response, dict) or response.get("type") != "register_result":
            raise ConnectionError(
                "Server did not respond to the registration request."
            )

        return RegistrationResult(
            success=bool(response.get("success")),
            message=response.get("message") or "Registration failed.",
            user_id=response.get("user_id"),
            errors=response.get("errors"),
        )

    def logout(self):
        """
        Ask the server to revoke this session (D2 -- Server-Side API /
        Authentication Migration; final slice, replacing
        gui/main_window.py's previous direct, local
        AuthenticationService.logout(session_id) call).

        Unlike authenticate_credentials()/register(), this runs on the
        already-established, already-authenticated connection -- the
        receiver thread is already running by the time logout is
        reachable from the GUI (chat is only ever entered after
        start_chat_session()'s start_receiver() call) -- so this uses
        D1's send_request(), exactly like find_user_by_id(), rather
        than the throwaway-connection pattern those two pre-auth
        operations use.

        This method never sends self.session_id or any other identity
        field -- create_logout_request_packet() carries none. The
        server derives which session to revoke entirely from its own
        authenticated connection state (see server/client_handler.py::
        handle_logout_request()), so there is nothing for a caller to
        get wrong or forge here.

        Returns True if the server confirms the session was revoked,
        False if it reports it could not (e.g. already logged out).
        Does not disconnect the socket itself -- the caller
        (gui/main_window.py::handle_logout()) still owns that decision
        and timing, unchanged from before this migration.
        """

        response = self.send_request(create_logout_request_packet())

        return bool(response.get("success"))

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

        Key-desynchronization fix: every key established here is
        stamped with a freshly RESERVED epoch (never an assumed
        "epoch 1"), via the exact same
        ConversationRepository.reserve_next_epoch()/current_key_epoch
        counter Phase 7 already uses for group-key rotation -- reused
        completely unchanged, just called from a second place. This
        is what fixes the one-sided-restart bug: previously, a client
        with no cached key always (re)established under the hardcoded
        default epoch 1, which collided with -- and was silently
        rejected by -- a still-connected partner who already had
        epoch 1 cached (KeyManager.store_key() never overwrites an
        existing epoch), leaving the two sides permanently talking
        past each other. Reserving a genuinely new epoch every time
        means the partner always receives it into a brand-new,
        never-before-seen epoch slot -- no collision is possible, and
        KeyManager's existing "current epoch is whichever is highest"
        rule (already proven for groups) makes both sides converge on
        it. A brand-new conversation "wastes" epoch 1 this way (its
        first real key lands on epoch 2) -- a harmless, permanent
        quirk, not a bug: epoch numbers only need to be unique and
        monotonically increasing, never to start at exactly 1.

        Reserving via the server-persisted counter (not a purely
        local guess) is what makes this safe even when BOTH sides
        have lost their cached key at once: the counter itself
        survives any number of client restarts, so it can never
        replay an epoch either side has already used.
        """

        if self.current_chat is None:
            raise ValueError(
                "No active chat partner selected."
            )

        receiver = self.current_chat
        conversation_id = self.current_conversation_id

        if self.key_manager.has_key(conversation_id):
            return

        db = SessionLocal()

        try:
            conversation_repo = ConversationRepository(db)

            epoch = conversation_repo.reserve_next_epoch(
                uuid.UUID(conversation_id)
            )

            conversation_repo.commit()
        finally:
            db.close()

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
            session_key,
            epoch=epoch
        )

        self.logger.info(
            f"Generated AES session key for {receiver} "
            f"({algorithm}, epoch {epoch})"
        )

        packet = create_session_key_packet(
            sender=self.username,
            receiver=receiver,
            algorithm=algorithm,
            encrypted_key=encrypted_key,
            epoch=epoch
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
        Encrypt and send a text message to the currently open
        conversation -- direct or group (Phase 4 -- Secure Group
        Messaging Foundation). A thin, TEXT-specific wrapper around
        _send_encrypted_payload() (Phase 8 -- File & Image Transfer):
        signature and behavior are unchanged from before Phase 8.
        """

        self._send_encrypted_payload(
            PayloadType.TEXT,
            message,
            content_metadata=None,
            preview_text=message,
        )

    def send_attachment(self, file_path):
        """
        Read, classify, encrypt, and send a local file as the next
        message in the currently open conversation -- direct or group
        (Phase 8 -- File & Image Transfer). Classification (IMAGE vs.
        FILE) is by MIME type (domain/payload_type.py::
        classify_attachment()) -- never asked of the user.

        Returns (payload_type, data, content_metadata) so the caller
        (the GUI) can render the local "sent" bubble from the same
        bytes just read, without a second disk read.

        Size is checked via a stat() call, before the file is read
        into memory or anything is encrypted -- config.py's
        MAX_ATTACHMENT_SIZE_BYTES documents why this project enforces
        a cap at all (the existing wire framing holds a whole message
        in memory, with no chunking/streaming). Raises ValueError for
        an oversized file or no open conversation, OSError if the file
        cannot be read -- both before any network or crypto work, so a
        rejection here has no side effects to unwind.
        """

        path = Path(file_path)

        size_bytes = path.stat().st_size

        if size_bytes > MAX_ATTACHMENT_SIZE_BYTES:
            raise ValueError(
                f"'{path.name}' is {size_bytes:,} bytes, which exceeds the "
                f"maximum attachment size of {MAX_ATTACHMENT_SIZE_BYTES:,} bytes."
            )

        if self.current_chat is None:
            raise ValueError(
                "No chat partner selected."
            )

        data = path.read_bytes()

        payload_type = classify_attachment(path.name)

        content_metadata = {
            "filename": path.name,
            "mime_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "size_bytes": len(data),
        }

        self._send_encrypted_payload(
            payload_type,
            data,
            content_metadata=content_metadata,
            preview_text=None,
        )

        return payload_type, data, content_metadata

    def _send_encrypted_payload(self, payload_type, content, content_metadata, preview_text):
        """
        Shared encrypt-and-send pipeline for every payload type (Phase
        8 -- File & Image Transfer): key lookup, epoch stamping, packet
        addressing, send, and local conversation_store recording are
        identical regardless of what ``content`` is -- only the
        adapter chosen (via _adapter_for()) and the packet's
        payload_type/content_metadata differ. Extracted from the body
        send_chat_message() used to have; send_chat_message() and
        send_attachment() are both thin callers now, so there is
        exactly one place this logic exists.
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

        envelope = self._adapter_for(payload_type).encrypt(
            content, aes, content_metadata=content_metadata
        )

        if payload_type == PayloadType.TEXT:
            self.logger.info(f"SENT (Encrypted): {envelope.ciphertext}")
        else:
            self.logger.info(
                f"SENT (Encrypted {payload_type}): {len(envelope.ciphertext)} "
                f"base64 chars"
            )

        sent_at = datetime.now(timezone.utc)

        # Phase 7 -- Group Membership Management: every outgoing
        # message is stamped with the epoch that encrypted it (always
        # 1 for a direct conversation, or a group before its first
        # rotation). current_epoch() reflects whatever key
        # session_key above actually is, since both are read from
        # KeyManager for the same conversation_id without anything in
        # between that could change it.
        epoch = self.key_manager.current_epoch(self.current_conversation_id) or 1

        if self.current_chat_is_group:

            packet = create_payload_packet(
                sender=self.username,
                envelope=envelope,
                timestamp=sent_at.isoformat(),
                conversation_id=self.current_chat,
                epoch=epoch,
            )

        else:

            packet = create_payload_packet(
                sender=self.username,
                envelope=envelope,
                timestamp=sent_at.isoformat(),
                receiver=self.current_chat,
                epoch=epoch,
            )

        send_message(
            self.client_socket,
            packet
        )

        self.conversation_store.record_message(
            self.current_chat,
            MessagePreview(
                payload_type=payload_type,
                text=preview_text,
                timestamp=sent_at.replace(tzinfo=None),
                content_metadata=content_metadata or {},
            ),
            is_own=True,
            is_online=(
                False
                if self.current_chat_is_group
                else self.current_chat in self.online_users
            ),
        )

    def _decrypt_history_message(self, conversation_id, ciphertext, epoch=1):
        """
        Best-effort AES decryption of a stored historical message.

        ``conversation_id`` is always the real conversation_id now
        (Phase 5 -- Secure Group Key Distribution), direct or group
        alike -- KeyManager.keys is addressed by nothing else; this
        method needs no branch for either.

        ``epoch`` (Phase 7 -- Group Membership Management): exactly
        the epoch that encrypted this specific message (Message.epoch,
        with NULL already normalized to 1 by the caller) -- never
        "whatever this client's current key is". A group that has
        rotated has messages at multiple epochs in the same
        conversation; using the wrong one here would either fail to
        decrypt a message this client CAN read, or -- far worse --
        silently return garbage if two different epochs' keys somehow
        both happened to authenticate (AES-GCM's tag makes this
        effectively impossible per-message, but the point is this
        method never relies on that; it asks for the one correct key).

        Reuses the currently cached key, if any -- never establishes a
        new one (history loading must not trigger a fresh key
        exchange). Never raises: returns the placeholder text if this
        client never received that epoch's key, or if AES-GCM
        authentication fails (the message was encrypted under a
        different, since-discarded key from a previous session).
        """

        session_key = self.key_manager.get_key(conversation_id, epoch=epoch)

        if session_key is None:
            return _UNDECRYPTABLE_PLACEHOLDER

        try:
            envelope = PayloadEnvelope(
                payload_type=PayloadType.TEXT, ciphertext=ciphertext, content_metadata={}
            )
            return self._adapter_for(PayloadType.TEXT).decrypt(envelope, AESCipher(session_key))
        except Exception:
            return _UNDECRYPTABLE_PLACEHOLDER

    def _load_blob_history_content(self, conversation_id, message, epoch):
        """
        Decrypt a stored FILE/IMAGE message's content for history
        display (Phase 8 -- File & Image Transfer). Mirrors
        _decrypt_history_message()'s epoch-aware, never-raise contract,
        but reads the ciphertext from local blob storage (via
        Message.blob_ref) instead of Message.ciphertext -- the exact
        mirror of where persist_message() decided to write it.

        Reuses storage.encrypted_blob_store.load_blob() directly --
        the same reuse-the-existing-client-DB-access-model this
        client already relies on for every other bit of history (see
        SessionLocal usage throughout this class): no new client<->
        server retrieval packet is introduced, since the client
        already reads the database (and, with this addition, the
        blob directory) directly rather than through the server.

        Returns the decrypted bytes, or None if this client never
        received this epoch's key, the blob is missing, or decryption
        fails -- the binary equivalent of _UNDECRYPTABLE_PLACEHOLDER
        (callers render their own placeholder for None; a text
        placeholder string cannot stand in for missing bytes here).
        """

        if not message.blob_ref:
            return None

        session_key = self.key_manager.get_key(conversation_id, epoch=epoch)

        if session_key is None:
            return None

        try:
            ciphertext = encrypted_blob_store.load_blob(message.blob_ref).decode("utf-8")

            envelope = PayloadEnvelope(
                payload_type=message.payload_type,
                ciphertext=ciphertext,
                content_metadata=message.content_metadata or {},
            )

            return self._adapter_for(message.payload_type).decrypt(envelope, AESCipher(session_key))
        except Exception:
            return None

    def _read_status_for_own_message(self, message_repo, message, is_group, member_ids):
        """
        Compute the read-receipt display state for one of THIS user's
        own sent messages (C2 -- Read Receipts): True (double check --
        fully read), False (single check -- sent/delivered, not yet
        fully read), or None (no MessageRecipient rows at all -- a
        legacy message persisted before C2 shipped, or before this
        direct conversation started creating rows; show no receipt
        state at all rather than fabricate one).

        For a group, "fully read" means every CURRENTLY active member
        (``member_ids``, already left-member-filtered by
        get_member_user_ids()) who has a recipient row for this
        specific message has read it -- a departed member's row is
        simply excluded from consideration, so they can never block
        the all-read state (see the row-filtering below). A member
        added after this message was sent was never one of its
        recipients in the first place (Issue 2's epoch rotation means
        they couldn't decrypt it anyway), so they're correctly absent
        from message_recipients for it and need no special-casing
        here.

        Only ever called for is_own rows -- never for a message this
        user received, which this codebase's own security model
        already keeps this user from seeing anyone else's read state
        for anyway (MessageRepository.mark_conversation_read() is
        scoped to the authenticated recipient; there is no query
        surface here that could reveal a stranger's read state).
        """

        recipient_rows = message_repo.get_recipients_for_message(message.id)

        if not recipient_rows:
            return None

        if is_group:
            relevant_rows = [
                row for row in recipient_rows if row.recipient_id in member_ids
            ]
        else:
            relevant_rows = recipient_rows

        if not relevant_rows:
            return False

        return all(row.status == MessageDeliveryStatus.READ for row in relevant_rows)

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
            {"sender": str, "text": str, "timestamp": datetime,
             "is_own": bool, "message_id": str,
             "read_status": bool | None}
        ``read_status`` (C2 -- Read Receipts) is only ever meaningful
        for ``is_own`` rows -- see _read_status_for_own_message(); it
        is always None for a received message (no receipt indicator
        is ever shown for those, by design).
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

                payload_type = message.payload_type or PayloadType.TEXT
                epoch = message.epoch or 1

                # Phase 8 -- File & Image Transfer: TEXT keeps using
                # the existing inline-ciphertext path unchanged; a
                # blob-stored payload_type (BLOB_STORAGE_PAYLOAD_TYPES)
                # reads its ciphertext from local blob storage instead
                # -- Message.ciphertext is NULL for those rows (see
                # persist_message()), so message.ciphertext must never
                # be passed to _decrypt_history_message() for them.
                if payload_type in BLOB_STORAGE_PAYLOAD_TYPES:
                    text = None
                    content = self._load_blob_history_content(decrypt_key, message, epoch)
                else:
                    text = self._decrypt_history_message(
                        decrypt_key,
                        message.ciphertext,
                        epoch=epoch,
                    )
                    content = None

                read_status = (
                    self._read_status_for_own_message(
                        message_repo, message, is_group, member_ids if is_group else None
                    )
                    if is_own
                    else None
                )

                history.append({
                    "sender": sender_name,
                    "text": text,
                    "timestamp": message.timestamp,
                    "is_own": is_own,
                    "message_id": str(message.id),
                    "read_status": read_status,
                    "payload_type": payload_type,
                    "content": content,
                    "content_metadata": message.content_metadata or {},
                })

            return history
        finally:
            db.close()

    def find_user_by_id(self, user_id_str):
        """
        Look up a user by their unique ID (Issue 3 fix -- User Must Be
        Searched By Unique ID). ``id`` (the UUID primary key) is used
        as the identifier, not username/email -- see the diagnosis
        given before implementation: it's the only field this schema
        actually calls "id", it's globally unique by construction
        (Postgres primary key), and unlike username/email it reveals
        nothing about the person from the string alone.

        D2 -- Server-Side API / Authentication Migration: this used to
        be a direct client-side DB read via UserRepository; it is now
        the first operation migrated onto a server request/response
        pair (user_lookup_request/user_lookup_result -- see
        server/client_handler.py::handle_user_lookup()), using D1's
        send_request() for the correlation and blocking. The
        signature, return shape, and every existing behavior below are
        unchanged -- gui/find_user_dialog.py needed no changes for
        this migration. A lookup still grants no privilege of its own;
        sending to or opening a conversation with the found user still
        goes through the server's existing sender-authentication and
        group-membership checks, completely unchanged.

        Returns a dict with only {"user_id", "username",
        "display_name"} -- deliberately not the full User row (no
        email, no password hash, no internal flags) -- to avoid
        exposing more than a lookup-by-ID needs to. Returns None for a
        malformed ID or one that matches nobody -- both are reported
        identically ("not found") so a caller can't distinguish a
        malformed guess from a well-formed-but-nonexistent one; the
        malformed case is still short-circuited client-side, before
        any request is sent, exactly as before. Raises
        PermissionError if this session itself isn't authenticated
        yet, mirroring login()'s existing use of that exception for
        the same kind of guard. Raises
        utils.request_registry.RequestTimeoutError if the server
        doesn't respond in time -- a genuinely new failure mode this
        method didn't have as a local DB read, deliberately left
        uncaught here rather than folded into the "not found" result,
        since a timeout and a definitive "no such user" are not the
        same thing.
        """

        if not self.user_id:
            raise PermissionError(
                "You must be logged in to search for users."
            )

        try:
            uuid.UUID(user_id_str)
        except (ValueError, AttributeError, TypeError):
            return None

        response = self.send_request(
            create_user_lookup_request_packet(user_id=user_id_str)
        )

        if not response.get("user_id"):
            return None

        return {
            "user_id": response["user_id"],
            "username": response["username"],
            "display_name": response["display_name"],
        }

    def _build_latest_message_preview(self, conversation_id, latest_message_row):
        """
        Build the sidebar MessagePreview for one conversation's latest
        stored message (Phase 8 -- File & Image Transfer extends this
        beyond TEXT). A FILE/IMAGE preview never touches blob storage
        at all -- MessagePreview.render() only needs payload_type and
        content_metadata (e.g. filename) to show "\U0001F4C4 report.pdf",
        not the decrypted bytes themselves, so the sidebar stays cheap
        regardless of attachment size.
        """

        payload_type = latest_message_row.payload_type or PayloadType.TEXT

        text = (
            self._decrypt_history_message(
                conversation_id,
                latest_message_row.ciphertext,
                epoch=latest_message_row.epoch or 1,
            )
            if payload_type == PayloadType.TEXT
            else None
        )

        return MessagePreview(
            payload_type=payload_type,
            text=text,
            timestamp=latest_message_row.timestamp,
            content_metadata=latest_message_row.content_metadata or {},
        )

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
                        latest_message = self._build_latest_message_preview(
                            conversation_id, preview.latest_message
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
                    latest_message = self._build_latest_message_preview(
                        str(preview.conversation.id), preview.latest_message
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

        D1 -- Request/Response Infrastructure: a packet carrying a
        request_id that matches an in-flight send_request() call is a
        correlated response, not an independent notification -- it is
        delivered straight to whichever thread is blocked in
        PendingRequestRegistry.wait() and never reaches the type-based
        dispatch below. A request_id that matches nothing pending
        (unknown, already timed out, or simply absent -- every packet
        type before D1 has no request_id at all) falls through to
        normal dispatch unchanged, so this is a no-op for every
        existing packet type today.
        """

        if self._pending_requests.resolve(packet.get("request_id"), packet):
            return

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

        elif packet_type == "group_member_left":
            self.handle_group_member_left(packet)

        elif packet_type == "group_key_rotation_required":
            self.handle_group_key_rotation_required(packet)

        elif packet_type == "group_members_added":
            self.handle_group_members_added(packet)

        elif packet_type == "read_receipt_notification":
            self.handle_read_receipt_notification(packet)

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

        # Phase 7 -- Group Membership Management: decrypt using
        # exactly the epoch this packet says encrypted it, never
        # "whatever this client's current key is" -- a receiver that
        # is mid-rotation, or that never received a later epoch (e.g.
        # a departed member), must not conflate the two.
        epoch = packet.get("epoch") or 1

        session_key = None

        for _ in range(10):

            session_key = self.key_manager.get_key(
                key_conversation_id,
                epoch=epoch,
            )

            if session_key is not None:
                break

            time.sleep(0.1)

        if session_key is None:

            self.logger.warning(
                f"No AES session key for {identity_key} (epoch {epoch})"
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

        decrypted_content = self._adapter_for(envelope.payload_type).decrypt(envelope, aes)

        timestamp = self._parse_incoming_timestamp(packet.get("timestamp"))

        if envelope.payload_type == PayloadType.TEXT:

            self.logger.info(
                f"RECEIVED: {sender}: {decrypted_content}"
            )

            self.conversation_store.record_message(
                identity_key,
                MessagePreview(
                    payload_type=PayloadType.TEXT,
                    text=decrypted_content,
                    timestamp=timestamp,
                ),
                is_own=False,
                is_online=(False if is_group else sender in self.online_users),
            )

            self.message_received.emit(
                identity_key,
                sender,
                decrypted_content
            )

            return

        # Binary payload (Phase 8 -- File & Image Transfer):
        # decrypted_content is raw bytes (FilePayloadAdapter ->
        # crypto/payload_cipher.py's generic passthrough) -- never
        # routed through message_received, a fixed Signal(str, str,
        # str) that cannot carry bytes. See payload_message_received's
        # declaration for the full rationale.
        self.logger.info(
            f"RECEIVED ({envelope.payload_type}): {sender}: "
            f"{len(decrypted_content)} bytes"
        )

        self.conversation_store.record_message(
            identity_key,
            MessagePreview(
                payload_type=envelope.payload_type,
                text=None,
                timestamp=timestamp,
                content_metadata=envelope.content_metadata,
            ),
            is_own=False,
            is_online=(False if is_group else sender in self.online_users),
        )

        self.payload_message_received.emit(
            identity_key,
            sender,
            envelope.payload_type,
            decrypted_content,
            envelope.content_metadata,
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

        ``epoch`` (key-desynchronization fix): the epoch the sender
        reserved for this key (see establish_session_key()'s
        docstring). Stored under that exact epoch -- never assumed to
        be 1 -- so a key established after the sender's own restart
        lands in a fresh, never-before-seen epoch slot instead of
        being silently dropped by KeyManager.store_key()'s existing
        no-overwrite guarantee for an epoch this client already has.
        Defaults to 1 for a packet that omits it (none do today, but
        this mirrors every other epoch-aware packet's backward-
        compatible default).
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

        epoch = packet.get("epoch") or 1

        self.key_manager.store_key(
            conversation_id,
            session_key,
            epoch=epoch
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

    def _distribute_group_key(self, conversation_id, group_key, epoch, recipients):
        """
        Wrap ``group_key`` (already stored locally under ``epoch``) for
        each of ``recipients`` and send it -- see
        crypto/key_manager.py::wrap_key_for_member() for the
        KEM-then-DEM composition. Shared by both initial group
        creation (epoch 1) and Phase 7's post-leave rotation (epoch
        N > 1) so the wrap-and-send loop exists exactly once. A
        recipient with no cached public key (never online this
        session) does not receive it; retroactive delivery to a
        late-joining or previously-offline member is out of scope.
        """

        for member in recipients:

            if self.key_manager.get_public_key(member) is None:

                self.logger.warning(
                    f"No public key for {member}; cannot distribute "
                    f"group key for {conversation_id} epoch {epoch}."
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
                epoch=epoch,
            )

            send_message(
                self.client_socket,
                packet
            )

    def _create_and_distribute_group_key(self, conversation_id, participants):
        """
        Generate the group's first key (epoch 1) and deliver it to
        every other member whose public key is already known.
        """

        group_key = os.urandom(32)

        self.key_manager.store_key(conversation_id, group_key, epoch=1)

        self._distribute_group_key(conversation_id, group_key, 1, participants)

        self.logger.info(
            f"Distributed group key for {conversation_id} to {participants}"
        )

    def handle_group_key_distribution(self, packet):
        """
        Recover this client's wrapped copy of a group key -- see
        crypto/key_manager.py::unwrap_received_key(). Uses only this
        client's own private key material; nothing from the sender is
        needed beyond the packet's opaque fields.

        ``epoch`` (Phase 7 -- Group Membership Management): stored
        under the epoch the packet declares, defaulting to 1 for
        compatibility with a sender that predates this field.
        KeyManager.store_key() never overwrites an existing epoch with
        a different key, so a redundant/duplicate delivery of the same
        epoch is always safe.
        """

        if packet.get("recipient") != self.username:
            return

        conversation_id = packet["conversation_id"]
        epoch = packet.get("epoch") or 1

        group_key = self.key_manager.unwrap_received_key(
            packet["encapsulation"], packet["wrapped_key"]
        )

        self.key_manager.store_key(conversation_id, group_key, epoch=epoch)

        self.logger.info(
            f"Group key established for conversation {conversation_id} "
            f"(epoch {epoch})"
        )

    def handle_group_member_left(self, packet):
        """
        A group conversation this user belongs to lost a member (Phase
        7 -- Group Membership Management) -- one packet, two
        interpretations depending on whose username left:

        If it was this client's own username, the leave this client
        itself requested (leave_group_conversation()) has been
        confirmed by the server -- this is the only acknowledgment
        that ever arrives for it, matching every other conversation-
        store change in this codebase being server-confirmed rather
        than optimistic. The conversation is removed from this
        client's own view.

        Otherwise, a different member left -- this client is still in
        the group, so its participant list is refreshed to the
        server-provided remaining-members list. No key-rotation action
        is taken here: rotation is entirely server-initiated (see
        handle_group_key_rotation_required()), never self-elected.
        """

        conversation_id = packet["conversation_id"]
        departed_username = packet["username"]
        members = packet.get("members", [])

        if departed_username == self.username:

            self.conversation_store.remove_conversation(conversation_id)

            self.logger.info(
                f"Left group {conversation_id}"
            )

            return

        self.conversation_store.update_group_participants(conversation_id, members)

        self.logger.info(
            f"{departed_username} left group {conversation_id} "
            f"(remaining: {members})"
        )

    def handle_group_key_rotation_required(self, packet):
        """
        The server has selected this client to establish a group
        conversation's next key epoch (Phase 7 -- Group Membership
        Management) -- either right after a member left, or as
        reconnect-triggered catch-up for a rotation an earlier
        initiator never finished distributing.

        Reuses an already-stored key for this exact epoch rather than
        generating a new one -- see KeyManager.store_key()'s no-
        overwrite guarantee -- so a retry (this client being asked
        again for an epoch it already generated) redistributes the
        SAME key instead of creating a second, conflicting one. This
        is what makes recovery from a partial-distribution failure
        safe: whichever client ends up finishing the job always
        produces the identical epoch key every other recipient
        already has or will receive.
        """

        conversation_id = packet["conversation_id"]
        epoch = packet["epoch"]
        recipients = [
            member for member in packet.get("members", [])
            if member != self.username
        ]

        if self.key_manager.has_key(conversation_id, epoch=epoch):
            group_key = self.key_manager.get_key(conversation_id, epoch=epoch)
        else:
            group_key = os.urandom(32)
            self.key_manager.store_key(conversation_id, group_key, epoch=epoch)

        self._distribute_group_key(conversation_id, group_key, epoch, recipients)

        send_message(
            self.client_socket,
            create_group_key_rotation_complete_packet(
                conversation_id=conversation_id,
                epoch=epoch,
            ),
        )

        self.logger.info(
            f"Rotated group key for {conversation_id} to epoch {epoch} "
            f"({recipients})"
        )

    def handle_group_members_added(self, packet):
        """
        A group conversation this user belongs to gained one or more
        members (Issue 2 fix -- Add Members After Group Creation).
        Sent to every current active member, old and new alike --
        add_or_update_group() is already safe to call either way (see
        create_group_members_added_packet()'s docstring), so this
        handler needs no branch for "am I new here or not". Key
        material for any genuinely new member arrives separately, via
        the existing handle_group_key_rotation_required() path (the
        add reuses a key-epoch rotation, exactly like a leave does).
        """

        conversation_id = packet["conversation_id"]
        name = packet["name"]
        members = packet.get("members", [])

        participants = [m for m in members if m != self.username]

        self.conversation_store.add_or_update_group(conversation_id, name, participants)

        self.logger.info(
            f"Group {conversation_id} members updated: {members}"
        )

    def handle_read_receipt_notification(self, packet):
        """
        Another active member of a conversation has read up to now
        (C2 -- Read Receipts). Purely a live-update hint for a
        conversation the GUI currently has open -- re-emitted as a Qt
        signal rather than acted on here directly, since ClientSession
        has no reference to which message bubbles are currently on
        screen (gui/chat_window.py's connected slot does). Never
        touches decryption, message delivery, or persistence -- this
        packet carries no message content, and the authoritative read
        status is always re-derived from the database the next time
        load_conversation_history() runs regardless of whether this
        notification ever arrives.
        """

        conversation_id = packet.get("conversation_id")
        reader = packet.get("reader")

        if not conversation_id or not reader:
            return

        self.read_receipt_updated.emit(conversation_id, reader)

    def mark_conversation_read(self, conversation_id):
        """
        Tell the server every currently-unread message in this
        conversation has now been read (C2 -- Read Receipts). Only
        ever called when the user actually opens the conversation
        (see gui/chat_window.py::open_conversation()) -- never merely
        on reconnect/login, so an offline (C1) message stays QUEUED
        until the recipient genuinely opens the conversation, not just
        because they came back online. Carries no reader/user identity
        of its own -- the server derives that exclusively from this
        socket's authenticated session (see server/client_handler.py::
        handle_read_receipt()); there is nothing here for a malicious
        client to forge.

        A no-op if there's no real conversation_id yet (e.g. a direct
        partner who has never been messaged, so no conversation exists
        to mark).
        """

        if not conversation_id:
            return

        packet = create_read_receipt_packet(conversation_id=conversation_id)

        send_message(
            self.client_socket,
            packet
        )

    def add_group_members(self, conversation_id, member_usernames):
        """
        Ask the server to add one or more users to an existing group
        conversation (Issue 2 fix -- Add Members After Group
        Creation). The result (participant-list refresh for everyone,
        and key material for the new member(s)) arrives asynchronously
        via handle_group_members_added() / handle_group_key_rotation_required()
        -- there is no optimistic local update, matching every other
        conversation-store change.
        """

        packet = create_group_add_members_packet(
            sender=self.username,
            conversation_id=conversation_id,
            member_usernames=member_usernames,
        )

        send_message(
            self.client_socket,
            packet
        )

    def leave_group_conversation(self, conversation_id):
        """
        Ask the server to remove this client from a group conversation
        (Phase 7 -- Group Membership Management). The result (removing
        the conversation from this client's own view, and notifying
        remaining members) arrives asynchronously via
        handle_group_member_left() -- there is no optimistic local
        update, matching every other conversation-store change.
        """

        packet = create_group_leave_packet(
            sender=self.username,
            conversation_id=conversation_id,
        )

        send_message(
            self.client_socket,
            packet
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