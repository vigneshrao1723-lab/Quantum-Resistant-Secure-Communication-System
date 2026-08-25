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
    HANDSHAKE_TIMEOUT_SECONDS,
    MAX_ATTACHMENT_SIZE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    SERVER_HOST,
    SERVER_PORT,
)
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from storage.secure_key_store import (
    KeyStoreError,
    KeyStoreLocked,
    SecureKeyStore,
)
from domain.conversation_summary import ConversationSummary, MessagePreview
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import (
    BLOB_STORAGE_PAYLOAD_TYPES,
    PayloadType,
    classify_attachment,
)
from logger_config import setup_logger
from payload.file_adapter import FilePayloadAdapter
from payload.text_adapter import TextPayloadAdapter
from security.phone_number import is_valid_phone_number
from security.tls import build_client_context
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_blob_download_request_packet,
    create_conversation_list_request_packet,
    create_direct_conversation_request_packet,
    create_direct_key_recovery_request_packet,
    create_epoch_reservation_request_packet,
    create_group_add_members_packet,
    create_group_create_packet,
    create_group_key_distribution_packet,
    create_group_key_rotation_complete_packet,
    create_group_leave_packet,
    create_login_request_packet,
    create_logout_request_packet,
    create_message_history_request_packet,
    create_payload_packet,
    create_public_key_packet,
    create_read_receipt_packet,
    create_register_request_packet,
    create_session_key_packet,
    create_user_lookup_by_phone_request_packet,
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

        # BUG 7 (7.5) -- the identifier others search by, so the user
        # needs to be able to read it off their own screen and share
        # it. Populated at login from the authenticated account.
        self.phone_number = ""
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

        # BUG 1 -- local encrypted key store, opened at login.
        # None until unlocked (or if unlocking failed); key_store_error
        # carries a user-presentable reason in that case.
        self.key_store = None
        self.key_store_error = None

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

        # D8 / L-3 -- bound the connect and the TLS handshake.
        # A server that accepts the TCP connection and then
        # never completes the handshake would otherwise hang
        # the GUI thread indefinitely, with no way to cancel.
        raw_socket.settimeout(HANDSHAKE_TIMEOUT_SECONDS)

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

        # Clear the connect/handshake deadline now that the connection
        # is established, returning the socket to blocking reads.
        #
        # This previously installed a long stall timeout here instead.
        # That exact line was NOT shown to cause the server-side
        # regression -- the reproducer drives raw sockets and never
        # reaches ClientSession -- but it is the same unvalidated
        # post-setup timeout pattern on the same read path, and there
        # is no evidence justifying keeping it. The deadline above
        # still bounds connect() and the TLS handshake, which is what
        # stops the GUI hanging on a dead or non-TLS server.
        try:
            self.client_socket.settimeout(None)
        except OSError:
            pass

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

        # BUG 1 -- unlock the local encrypted key store here, the one
        # moment where BOTH the password and a verified user_id are
        # available. The password is used only to derive the storage
        # key and is never stored on the session, never logged, and
        # never sent anywhere; only the derived key is retained, inside
        # the store object.
        if response.get("success") and response.get("user_id"):
            self._unlock_key_store(response["user_id"], password)

        return AuthenticationResult(
            success=bool(response.get("success")),
            message=response.get("message") or "Authentication failed.",
            user_id=response.get("user_id"),
            # BUG 7 (7.5) -- the authenticated user's OWN identifier,
            # so the UI can show it back to them to share.
            phone_number=response.get("phone_number"),
            username=response.get("username"),
            role=response.get("role"),
            session_id=response.get("session_id"),
            token_pair=token_pair,
            errors=response.get("errors"),
        )

    def _unlock_key_store(self, user_id, password):
        """
        Open this user's local encrypted key store and restore any
        conversation keys it holds (BUG 1).

        Failure is never fatal to login. A missing store is simply a
        fresh installation; a store that cannot be authenticated (wrong
        password, corruption) is reported through key_store_error and
        left untouched on disk -- never deleted, never overwritten, and
        never replaced with fabricated keys. In both cases the session
        continues with whatever keys it can still obtain through the
        existing peer-recovery mechanism.
        """

        self.key_store = None
        self.key_store_error = None

        try:
            store = SecureKeyStore(user_id)
            restored = store.unlock(password)
        except KeyStoreLocked as error:
            self.key_store_error = str(error)
            self.logger.warning(f"Local key store not unlocked: {error}")
            return
        except KeyStoreError as error:
            self.key_store_error = str(error)
            self.logger.warning(f"Local key store unavailable: {error}")
            return

        count = self.key_manager.import_conversation_keys(restored)

        self.key_store = store

        # Persist from here on, whenever a genuinely new epoch arrives.
        self.key_manager.on_change = self._persist_conversation_keys

        self.logger.info(
            f"Local key store unlocked; restored {count} conversation "
            f"key epoch(s)"
        )

    def _persist_conversation_keys(self):
        """
        Write the current conversation keys back to the local store
        (BUG 1). Invoked by KeyManager whenever a new epoch is stored.

        A write failure must never break messaging -- the key is
        already usable in memory and the only cost is that this
        session's history may not survive a restart -- so it is logged
        rather than raised into the receiver thread.
        """

        if self.key_store is None:
            return

        try:
            # Snapshot and write are atomic because this runs from
            # inside KeyManager.store_key()'s lock (see
            # KeyManager.on_change): no other thread can add an epoch
            # between the export below and the write it feeds, since
            # adding one requires that same lock.
            #
            # Deliberately NOT done by handing the store a provider to
            # call under ITS lock -- that would make the store acquire
            # KeyManager's lock from inside its own, closing a cycle in
            # the lock-order graph.
            self.key_store.save(self.key_manager.export_conversation_keys())
        except (KeyStoreError, OSError) as error:
            self.logger.warning(f"Could not persist conversation keys: {error}")

    def _lock_key_store(self):
        """
        Drop the derived storage key and the in-memory conversation
        keys on logout (BUG 1).

        The FILE is deliberately kept: logging out and back in must not
        cost the user their history. What is discarded is the decrypted
        material in RAM, which has no reason to outlive the session.
        """

        self.key_manager.on_change = None

        if self.key_store is not None:
            self.key_store.lock()
            self.key_store = None

        self.key_manager.keys = {}
        self.key_manager._current_epoch = {}

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
        phone_number,
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
                phone_number=phone_number,
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

        # BUG 1 -- clear decrypted key material from memory on the way
        # out. The encrypted file stays: logging out and back in must
        # not cost the user their history.
        self._lock_key_store()

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
        "epoch 1"), via the same current_key_epoch counter Phase 7
        already uses for group-key rotation. D4.1 -- Message/History
        Operations Migration: the reservation itself is now a server
        request/response (epoch_reservation_request/result, via D1's
        send_request()) rather than a direct, local
        ConversationRepository.reserve_next_epoch() call -- the server
        reuses that exact same repository method unchanged, now behind
        an authorization check (the caller must be a member of the
        conversation) this direct-DB path never had. This is what
        fixes the one-sided-restart bug: previously, a client
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

        response = self.send_request(
            create_epoch_reservation_request_packet(conversation_id)
        )

        error = response.get("error")

        if error:
            raise ValueError(error)

        epoch = response.get("epoch")

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
        but reads the ciphertext from a blob rather than
        Message.ciphertext -- the exact mirror of where
        persist_message() decided to write it.

        D4.3 -- Message/History Operations Migration (Option A -- lazy
        blob delivery): ``message`` is now the server-supplied dict
        from a message_history_result packet's per-message entry (see
        load_conversation_history()), never a live Message ORM row.
        Its ``blob_ref`` was already sent alongside the rest of the
        history -- only the actual encrypted bytes are fetched here,
        on demand, via a separate blob_download_request/send_request()
        round trip. This is the last remaining place anywhere in this
        class that used to read local storage directly; it now reads
        it through the server instead, exactly like every other piece
        of history.

        Returns the decrypted bytes, or None if this client never
        received this epoch's key, the blob is missing/inaccessible,
        or decryption fails -- the binary equivalent of
        _UNDECRYPTABLE_PLACEHOLDER (callers render their own
        placeholder for None; a text placeholder string cannot stand
        in for missing bytes here).
        """

        if not message.get("blob_ref"):
            return None

        session_key = self.key_manager.get_key(conversation_id, epoch=epoch)

        if session_key is None:
            return None

        try:
            response = self.send_request(
                create_blob_download_request_packet(message_id=message["message_id"])
            )

            if response.get("error"):
                return None

            payload_type = message.get("payload_type") or PayloadType.TEXT

            envelope = PayloadEnvelope(
                payload_type=payload_type,
                ciphertext=response.get("ciphertext"),
                content_metadata=message.get("content_metadata") or {},
            )

            return self._adapter_for(payload_type).decrypt(envelope, AESCipher(session_key))
        except Exception:
            return None

    def load_conversation_history(self, key, is_group=False):
        """
        Load and best-effort decrypt the stored conversation history
        for a direct partner (``key`` = username, the default) or a
        group (``key`` = conversation_id, Phase 4 -- Secure Group
        Messaging Foundation).

        Returns a plain list of dicts, ordered chronologically exactly
        as stored:
            {"sender": str, "text": str, "timestamp": datetime,
             "is_own": bool, "message_id": str,
             "read_status": bool | None}

        D4.3 -- Message/History Operations Migration (final slice):
        resolved via a server request/response
        (message_history_request/result, via D1's send_request())
        rather than direct, local MessageRepository/
        ConversationRepository/UserRepository reads -- the last
        remaining client-side database access for message content
        anywhere in this class. ``read_status`` (C2 -- Read Receipts)
        now arrives pre-computed from the server, not derived
        locally -- see server/client_handler.py::
        handle_message_history_request()'s ported copy of what this
        class's own _read_status_for_own_message() used to compute;
        it is still only ever meaningful for ``is_own`` rows, always
        None for a received message.

        Relies on self.current_conversation_id already being resolved
        -- true for the one real caller (gui/chat_window.py::
        open_conversation() always calls set_current_chat() first,
        which is what populates it, for a direct conversation via
        D3.3's server-side get-or-create) -- rather than resolving a
        direct partner's conversation_id itself, since the wire
        protocol now addresses history explicitly by conversation_id,
        never by username. ``key`` is kept as a parameter purely for
        call-site stability (unchanged from before this migration);
        it is no longer used internally, since sender-name resolution
        also now happens entirely server-side. No conversation_id yet
        (e.g. a direct partner never opened via set_current_chat())
        returns an empty list without sending anything, mirroring the
        prior "unknown partner" short-circuit.

        No pagination -- the complete history is returned in one
        response, matching this codebase's existing behavior exactly
        (see create_message_history_request_packet()'s docstring).
        """

        if self.current_conversation_id is None:
            return []

        response = self.send_request(
            create_message_history_request_packet(
                conversation_id=self.current_conversation_id,
                is_group=is_group,
            )
        )

        messages = response.get("messages") or []

        history = []

        for entry in messages:

            payload_type = entry.get("payload_type") or PayloadType.TEXT
            epoch = entry.get("epoch") or 1

            # Phase 8 -- File & Image Transfer: TEXT keeps using the
            # existing inline-ciphertext path unchanged; a blob-stored
            # payload_type (BLOB_STORAGE_PAYLOAD_TYPES) fetches its
            # ciphertext lazily via _load_blob_history_content()
            # instead -- entry["ciphertext"] is None for those rows
            # (see handle_message_history_request()), so it must
            # never be passed to _decrypt_history_message() for them.
            if payload_type in BLOB_STORAGE_PAYLOAD_TYPES:
                text = None
                content = self._load_blob_history_content(
                    self.current_conversation_id, entry, epoch
                )
            else:
                text = self._decrypt_history_message(
                    self.current_conversation_id,
                    entry.get("ciphertext"),
                    epoch=epoch,
                )
                content = None

            history.append({
                "sender": entry.get("sender"),
                "text": text,
                "timestamp": self._parse_incoming_timestamp(entry.get("timestamp")),
                "is_own": entry.get("is_own", False),
                "message_id": entry.get("message_id"),
                "read_status": entry.get("read_status"),
                "payload_type": payload_type,
                "content": content,
                "content_metadata": entry.get("content_metadata") or {},
            })

        return history

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

    def find_user_by_phone_number(self, phone_number):
        """
        Look up a user by their phone number (BUG 7 -- phone-based
        user discovery).

        The phone number is what this application shows people as
        "your ID", so it is the identifier the Find User dialog sends.
        find_user_by_id() above is unchanged and still resolves by
        UUID for internal callers.

        Returns the same minimal dict find_user_by_id() returns --
        {user_id, username, display_name}, deliberately never email,
        password state, or internal flags -- or None when nothing
        matches. A malformed number is short-circuited here, before a
        request is sent, and reported identically to a well-formed
        number that matches nobody, so a caller cannot distinguish the
        two. The server normalises independently, so this local check
        is a convenience, never the security boundary.

        Discovery is a pure database lookup: an OFFLINE user is found
        exactly like an online one. Presence and discovery are
        unrelated.
        """

        if not self.access_token:
            raise PermissionError(
                "Not authenticated. Please log in first."
            )

        if not is_valid_phone_number(phone_number):
            return None

        response = self.send_request(
            create_user_lookup_by_phone_request_packet(
                phone_number=phone_number
            )
        )

        if not response.get("user_id"):
            return None

        return {
            "user_id": response["user_id"],
            "username": response["username"],
            "display_name": response["display_name"],
        }

    def _build_latest_message_preview(self, conversation_id, latest_message):
        """
        Build the sidebar MessagePreview for one conversation's latest
        stored message (Phase 8 -- File & Image Transfer extends this
        beyond TEXT). A FILE/IMAGE preview never touches blob storage
        at all -- MessagePreview.render() only needs payload_type and
        content_metadata (e.g. filename) to show "\U0001F4C4 report.pdf",
        not the decrypted bytes themselves, so the sidebar stays cheap
        regardless of attachment size.

        D4.2 -- Message/History Operations Migration: ``latest_message``
        is now the server-supplied dict from a conversation_list_result
        packet's per-conversation entry (see load_conversations()),
        never a live Message ORM row -- every field this method reads
        was already opaque/non-secret to begin with (payload_type,
        epoch, timestamp, content_metadata, and TEXT's own already-
        encrypted ciphertext), so nothing about what is exposed
        changes, only where it comes from.
        """

        payload_type = latest_message.get("payload_type") or PayloadType.TEXT

        text = (
            self._decrypt_history_message(
                conversation_id,
                latest_message.get("ciphertext"),
                epoch=latest_message.get("epoch") or 1,
            )
            if payload_type == PayloadType.TEXT
            else None
        )

        return MessagePreview(
            payload_type=payload_type,
            text=text,
            timestamp=self._parse_incoming_timestamp(latest_message.get("timestamp")),
            content_metadata=latest_message.get("content_metadata") or {},
        )

    def load_conversations(self):
        """
        Load this user's conversations into conversation_store -- the
        single source of truth for sidebar state (see
        client/conversation_store.py). Called once, at chat startup;
        from then on the store is updated incrementally by
        send_chat_message(), handle_chat(), and handle_user_list(),
        never by another full reload.

        D4.2 -- Message/History Operations Migration: resolved via a
        server request/response (conversation_list_request/result,
        via D1's send_request()) rather than a direct, local
        ConversationRepository.get_conversation_previews_for_user()
        call -- the last remaining client-side database read for the
        sidebar's initial population. The server reuses that exact
        same repository method unchanged, already scoped to the
        authenticated connection's own user.id; there is no
        client-supplied identity for a malicious client to forge here
        (create_conversation_list_request_packet() carries no fields
        at all).

        Reuses the existing best-effort decrypt helper
        (_decrypt_history_message) -- no new cryptography.
        """

        response = self.send_request(create_conversation_list_request_packet())

        conversations = response.get("conversations") or []

        summaries = []

        for conversation in conversations:

            latest_message_data = conversation.get("latest_message")

            if conversation.get("is_group"):

                conversation_id = conversation["conversation_id"]
                participant_usernames = conversation.get("participants") or []

                latest_message = None

                if latest_message_data is not None:
                    latest_message = self._build_latest_message_preview(
                        conversation_id, latest_message_data
                    )

                summaries.append(
                    ConversationSummary(
                        conversation_id=conversation_id,
                        username=None,
                        is_online=False,
                        latest_message=latest_message,
                        is_group=True,
                        group_name=conversation.get("group_name"),
                        participants=participant_usernames,
                    )
                )

                continue

            participants = conversation.get("participants") or []
            partner_username = participants[0] if participants else None

            if partner_username is None:
                continue

            latest_message = None

            if latest_message_data is not None:

                # The real conversation_id, already known from this
                # response -- the KeyManager identity (Phase 5), not
                # the partner's username.
                latest_message = self._build_latest_message_preview(
                    conversation["conversation_id"], latest_message_data
                )

            summaries.append(
                ConversationSummary(
                    conversation_id=conversation["conversation_id"],
                    username=partner_username,
                    is_online=partner_username in self.online_users,
                    latest_message=latest_message,
                )
            )

        self.conversation_store.set_initial(summaries)

        # BUG 8 -- presence must survive the initial load.
        #
        # set_initial() replaces the whole store, and ``summaries``
        # above is built purely from the server's conversation list:
        # online_users only decides is_online for partners already
        # conversed with, so a peer never messaged before is not in it
        # at all. handle_user_list() runs on the receiver thread and
        # may therefore have recorded presence moments BEFORE this
        # method replaced the store, in which case those entries were
        # silently discarded and the sidebar stayed stale until the
        # next broadcast -- which only happens when somebody else
        # connects or disconnects. That is what made presence
        # asymmetric: the client that connected first was already past
        # its own startup, so it kept every later broadcast, while a
        # later joiner threw its copy away.
        #
        # Re-applying the presence this session already knows about
        # closes that window, in the one place the store is wholesale
        # replaced. It is idempotent, and safe whichever order the two
        # threads happen to run in: update_online_status() only adds
        # missing peers and flips is_online, it never drops rows.
        self.conversation_store.update_online_status(self.online_users)

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

        elif packet_type == "message_queued":
            self.handle_message_queued(packet)

        elif packet_type == "direct_key_recovery_available":
            self.handle_direct_key_recovery_available(packet)

        elif packet_type == "direct_key_redelivery_required":
            self.handle_direct_key_redelivery_required(packet)

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
        identity -- always the real conversation_id.

        D3.2 -- Conversation Operations Migration: for a direct
        message, key_conversation_id now comes straight from
        direct_conversation_id, resolved server-side before this
        packet was ever relayed (see server/client_handler.py --
        the server derives it from the authenticated sender and the
        matched recipient, never from anything client-supplied). This
        runs on the receiver thread, so it must never call
        ConversationStore.ensure_direct_conversation_id() (a database
        round trip) -- that's exactly the deadlock risk this migration
        removes; only the DB-free ConversationStore.
        record_direct_conversation_id() is used here, to keep the
        sidebar's cached id in sync with what the server already
        resolved. The group case (conversation_id already present on
        the packet) is completely unchanged.
        """

        sender = packet["sender"]

        conversation_id = packet.get("conversation_id")

        is_group = bool(conversation_id)

        identity_key = conversation_id if is_group else sender

        if is_group:

            key_conversation_id = conversation_id

        else:

            key_conversation_id = packet.get("direct_conversation_id")

            if not key_conversation_id:

                self.logger.error(
                    f"No direct_conversation_id supplied by the server "
                    f"for a direct chat packet from {sender} -- this is "
                    f"a protocol/server problem, not a missing key; "
                    f"treating it like an undecryptable message rather "
                    f"than resolving the conversation locally."
                )

            else:

                self.conversation_store.record_direct_conversation_id(
                    sender, key_conversation_id
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

    def handle_message_queued(self, packet):
        """
        The recipient was offline, and the server has safely persisted
        this message's ciphertext for them (BUG 4 -- Fix A).

        A success path, so deliberately NOT error_occurred: this is
        the packet that used to be delivery_failure, and emitting an
        error here would reproduce the exact bug -- the GUI showing
        "could not deliver" for a message that was stored correctly.
        The message is already in this client's own conversation store
        from send time, so there is nothing to add or correct locally;
        the server's answer only decides whether the user is alarmed.
        """

        receiver = packet.get("receiver")

        self.logger.info(
            f"Message to {receiver} queued for delivery (recipient offline)"
        )

    # ----------------------------------------------------------

    def handle_direct_key_recovery_available(self, packet):
        """
        The server has listed which direct conversations this client
        can read and which key epochs their stored messages are
        encrypted under (BUG 4 -- Fix B). Ask for the epochs this
        client is actually missing -- and only those.

        This filtering has to happen here, on the client, because the
        client is the only party that knows what it holds: the server
        stores no keys. A client whose KeyManager survived (a brief
        disconnect rather than a restart) finds nothing missing and
        sends nothing at all, so a routine reconnect costs one packet
        in and none back out. A genuinely restarted client has an
        empty key store and asks for everything it needs.

        Requests one packet per conversation, carrying that
        conversation's missing epochs together, rather than one per
        epoch.

        Deliberately send_message(), not send_request(): this runs on
        the receiver thread, and send_request() waits for a response
        that only the receiver thread can deliver -- calling it here
        would deadlock. Nothing needs a reply anyway; the keys arrive
        later as their own packets.
        """

        conversations = packet.get("conversations") or []

        for entry in conversations:

            conversation_id = entry.get("conversation_id")
            epochs = entry.get("epochs") or []

            if not conversation_id:
                continue

            missing = [
                epoch
                for epoch in epochs
                if not self.key_manager.has_key(conversation_id, epoch=epoch)
            ]

            if not missing:
                # Nothing lost for this conversation -- asking anyway
                # would make the partner wrap keys this client already
                # has.
                continue

            send_message(
                self.client_socket,
                create_direct_key_recovery_request_packet(
                    conversation_id=conversation_id,
                    epochs=missing,
                ),
            )

            self.logger.info(
                f"Requested recovery of {conversation_id} epochs {missing}"
            )

    # ----------------------------------------------------------

    def handle_direct_key_redelivery_required(self, packet):
        """
        A direct partner has reconnected holding queued messages
        encrypted under ``epoch``, and the server has asked this
        client -- who may still hold that epoch's key -- to hand them
        a wrapped copy (BUG 4 -- Fix B).

        Redelivers an EXISTING key or does nothing at all. There is
        deliberately no os.urandom() fallback of the kind
        handle_group_key_rotation_required() has: that handler's job
        is to establish a NEW epoch, where generating the key is the
        whole point, whereas this one's job is to make already-
        existing ciphertext readable. A newly generated key cannot
        decrypt a message that was encrypted under the old one, so
        inventing a key here would not recover anything -- it would
        hand the partner a key that authenticates nothing, and, since
        KeyManager tracks the current epoch with max(), would corrupt
        both sides' notion of the current key on top of that. If this
        client no longer has the epoch, the correct outcome is that
        the messages stay queued until a client that does have it
        reconnects.

        Wraps with crypto/key_manager.py::wrap_key_for_member() -- the
        same primitive group key distribution already uses, and the
        right one here precisely because it transports a CHOSEN key
        rather than deriving a fresh one the way
        encapsulate_session_key() does.
        """

        conversation_id = packet.get("conversation_id")
        epoch = packet.get("epoch") or 1
        recipient = packet.get("recipient")

        if not conversation_id or not recipient:
            return

        if not self.key_manager.has_key(conversation_id, epoch=epoch):

            self.logger.info(
                f"Cannot redeliver key for {conversation_id} epoch {epoch} "
                f"to {recipient}: this client does not hold that epoch"
            )

            return

        session_key = self.key_manager.get_key(conversation_id, epoch=epoch)

        try:
            encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(
                recipient, session_key
            )
        except (ValueError, TypeError) as error:

            # Narrow, and the only expected failure: the partner's
            # public key is missing or unusable (wrap_key_for_member()
            # raises ValueError for exactly that). Their messages stay
            # queued and recovery is retried on their next reconnect
            # -- nothing is lost, so this must not take down the
            # receiver thread.
            self.logger.warning(
                f"Could not wrap key for {recipient} "
                f"({conversation_id} epoch {epoch}): {error}"
            )

            return

        send_message(
            self.client_socket,
            create_group_key_distribution_packet(
                sender=self.username,
                conversation_id=conversation_id,
                recipient=recipient,
                encapsulation=encapsulation,
                wrapped_key=wrapped_key,
                epoch=epoch,
            ),
        )

        self.logger.info(
            f"Redelivered direct key for {conversation_id} epoch {epoch} "
            f"to {recipient}"
        )

    # ----------------------------------------------------------

    def handle_public_key(self, packet):
        """
        Cache another client's public key, as relayed by the server.

        D6.5 -- Public-Key Input Validation: the key is validated by
        KeyManager.add_public_key() -> KyberKEM/RSAEncryption.
        import_public_key() before it is stored, so malformed key
        material is rejected here rather than cached and left to fail
        later during key wrapping. A rejection is logged and the packet
        dropped: nothing is stored, and the "secure session established"
        style confirmation below is deliberately not emitted, since no
        usable key was actually obtained.

        Only ValueError/TypeError are caught -- the two data errors
        import_public_key() documents for untrusted input. Anything
        else propagates to the receiver loop as before, so a genuine
        bug is never disguised as a bad peer key.
        """

        username = packet["username"]

        algorithm = packet["algorithm"]

        public_key = packet["public_key"]

        try:
            self.key_manager.add_public_key(
                username,
                public_key
            )
        except (ValueError, TypeError) as error:

            self.logger.warning(
                f"Rejected malformed {algorithm} public key from "
                f"{username}: {error}"
            )

            return

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
        conversation_id. Decryption/decapsulation itself is unrelated
        to conversation identity and unchanged.

        D3.2 -- Conversation Operations Migration: conversation_id now
        comes straight from the packet -- resolved server-side before
        relay, from the authenticated sender and the matched
        recipient, never from anything client-supplied (see
        server/client_handler.py). This runs on the receiver thread,
        so it must never call ConversationStore.
        ensure_direct_conversation_id() (a database round trip) --
        that's exactly the deadlock risk this migration removes.
        record_direct_conversation_id() (DB-free) keeps the sidebar's
        cached id in sync with what the server already resolved.

        A missing conversation_id is treated as an invalid server
        response, not a locally-recoverable condition: logged clearly
        and the packet discarded before any decapsulation/decryption
        work happens or anything is stored under a useless key --
        there is no equivalent of handle_chat()'s "no session key yet,
        retry" path here, since establishing a key is exactly what
        this method exists to do.

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

        conversation_id = packet.get("conversation_id")

        if not conversation_id:

            self.logger.error(
                f"No conversation_id supplied by the server for a "
                f"session_key packet from {sender} -- this is a "
                f"protocol/server problem; discarding the packet "
                f"rather than resolving the conversation locally."
            )

            return

        self.conversation_store.record_direct_conversation_id(
            sender, conversation_id
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

        Every recipient is handled independently (D6 -- Group Key
        Distribution Robustness): one member's unusable key material
        must never stop the members after them in ``recipients`` from
        receiving the key. Previously an unusable key raised straight
        out of this loop, so a single bad key silently truncated
        distribution -- leaving the remaining members permanently
        unable to decrypt this epoch, with the rotation still reported
        as complete.

        Only ValueError/TypeError are caught, and only around the
        wrapping call itself: those are the failures that mean "this
        peer's key material is unusable", never a bug in this code.
        Anything else (AttributeError, KeyError, ...) is a programming
        error and is deliberately left to propagate.

        Still required after D6.5 -- Public-Key Input Validation, which
        made import_public_key() reject non-Base64 and wrong-length key
        material at handle_public_key() time. Length validation cannot
        be completeness validation: a key of exactly the right length
        whose contents are not a well-formed ML-KEM encapsulation key
        still passes import and is only rejected later, here, by
        ML-KEM's own modulus check ("t_hat does not encode correctly",
        raised as ValueError). D6.5 shrinks the set of keys that can
        reach this point; it does not empty it. The two layers are
        complementary: reject early where the format is knowable,
        contain the failure per-recipient where it is not.

        The send itself is intentionally NOT wrapped: a send_message()
        failure is a connection-level problem, not a per-recipient
        one, and continuing the loop over a dead socket would be
        pointless -- that behavior is unchanged from before.
        """

        for member in recipients:

            if self.key_manager.get_public_key(member) is None:

                self.logger.warning(
                    f"No public key for {member}; cannot distribute "
                    f"group key for {conversation_id} epoch {epoch}."
                )

                continue

            try:
                encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(
                    member, group_key
                )
            except (ValueError, TypeError) as error:

                self.logger.warning(
                    f"Unusable public key for {member}; cannot distribute "
                    f"group key for {conversation_id} epoch {epoch}: {error}"
                )

                continue

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

    def _resolve_direct_conversation_id(self, username):
        """
        Ask the server to get-or-create the direct conversation with
        ``username`` (D3.3 -- Conversation Operations Migration), via
        D1's send_request(). This is the one remaining case that
        needed a database round trip anywhere in ClientSession: every
        other former caller of ConversationStore.
        ensure_direct_conversation_id() either already has the id from
        a relayed packet (D3.2) or is migrated in a later slice
        (load_conversation_history(), still direct-DB for now -- see
        that method's own docstring). Only ever called from the GUI
        thread (set_current_chat(), below) -- send_request() would
        deadlock if ever called from the receiver thread.

        Caches the result via ConversationStore.
        record_direct_conversation_id() (DB-free) -- the same caching
        step ensure_direct_conversation_id() itself still performs for
        its own remaining caller, so both paths leave the sidebar in
        an identical state.

        Raises ValueError (matching ensure_direct_conversation_id()'s
        existing contract exactly) if the server reports the username
        doesn't resolve to a real user.
        """

        response = self.send_request(
            create_direct_conversation_request_packet(username)
        )

        error = response.get("error")

        if error:
            raise ValueError(error)

        conversation_id = response.get("conversation_id")

        self.conversation_store.record_direct_conversation_id(
            username, conversation_id
        )

        return conversation_id

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
        conversation with no cached id yet, it's resolved via
        _resolve_direct_conversation_id() (D3.3 -- Conversation
        Operations Migration: a server request/response, which may
        create the conversation server-side for one with no messages
        yet -- never a direct database lookup here).
        """

        self.current_chat = summary.key
        self.current_chat_is_group = summary.is_group

        if summary.is_group or summary.conversation_id is not None:
            self.current_conversation_id = summary.conversation_id
        else:
            self.current_conversation_id = self._resolve_direct_conversation_id(
                summary.username
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