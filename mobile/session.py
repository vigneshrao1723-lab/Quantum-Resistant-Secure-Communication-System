"""
Phase 19 -- Mobile Client Session.

MobileClientSession mirrors web/client/app.js::WebClientSession's own
method names, call order, and security ordering EXACTLY (the Phase
18/18.5 web implementation is this project's own designated reference
for mobile -- see docs/architecture/mobile_client.md) -- but, being
Python like the desktop client, imports and reuses the REAL crypto/
protocol/storage modules directly instead of porting them to a second
language: crypto.kyber, crypto.ml_dsa, crypto.aes, crypto.key_manager,
crypto.identity_protocol, crypto.message_protocol,
crypto.group_key_protocol, crypto.device_protocol, utils.protocol,
utils.network, storage.secure_key_store, payload.text_adapter,
payload.file_adapter, domain.payload_envelope, domain.payload_type,
security.tls are all used completely unchanged. This is a STRONGER
interoperability guarantee than the web client has (which needed a
byte-exact JS port, proven in tests/test_web_client_crypto_interop.py)
-- there is nothing to prove byte-exact here; it is the same Python
bytecode desktop already uses.

client/session.py::ClientSession is NOT reused directly: it subclasses
PySide6.QtCore.QObject and uses Qt Signal for its events, and PySide6
is not deployable to Android. This class uses a tiny, dependency-free
_Signal shim with the same connect()/emit() surface instead, so it (and
every test in this file's own test suite) runs with neither Kivy nor
PySide6 installed -- only mobile/app.py's UI layer needs Kivy, and only
to marshal a background-thread signal onto Kivy's main thread via
kivy.clock.Clock (see that file's own comment).

Deliberately scoped like WebClientSession, not the full ~5,400-line
ClientSession: Kyber/ML-KEM only (no RSA comparison-mode fallback --
this project's own PQC default, matching the web client's identical
choice), no group leave/add-members/rotation (Phase 19's own explicit
scope per the project's Phase 18 precedent), peer-verification state is
session-local (matches the web client's OWN pre-Phase-17 baseline,
before it grew local persistence) while identity keypairs/device_id ARE
persisted via storage.secure_key_store.SecureKeyStore, unchanged --
stronger than the web client's own persistence in that one respect.
"""

import base64
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from auth.schemas import AuthenticationResult, RegistrationResult, TokenPair
from client.receiver import receive_messages
from config import (
    HANDSHAKE_TIMEOUT_SECONDS,
    MAX_ATTACHMENT_SIZE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    SERVER_HOST,
    SERVER_PORT,
)
from crypto.aes import AESCipher
from crypto.device_protocol import (
    canonical_device_authorization_payload,
    canonical_device_enrollment_payload,
    canonical_device_key_sync_payload,
    canonical_device_revocation_payload,
    canonical_device_session_binding_payload,
    sign_device_payload,
    verify_device_payload,
)
from crypto.group_key_protocol import sign_group_key_payload, verify_group_key_payload
from crypto.identity_protocol import sign_identity_payload, verify_identity_payload
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from crypto.message_protocol import (
    EDIT_PAYLOAD_PURPOSE,
    MESSAGE_PAYLOAD_PURPOSE,
    REACTION_PAYLOAD_PURPOSE,
    sign_message_payload,
    verify_message_payload,
)
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import BLOB_STORAGE_PAYLOAD_TYPES, PayloadType, classify_attachment
from logger_config import setup_logger
from payload.file_adapter import FilePayloadAdapter
from payload.reaction_adapter import ReactionPayloadAdapter
from payload.text_adapter import TextPayloadAdapter
from security.phone_number import is_valid_phone_number
from security.tls import build_client_context
from storage.secure_key_store import (
    KeyStoreError,
    KeyStoreLocked,
    PEER_STATE_UNVERIFIED,
    PEER_STATE_VERIFIED,
    SecureKeyStore,
)
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_blob_download_request_packet,
    create_block_user_request_packet,
    create_blocked_users_list_request_packet,
    create_change_password_request_packet,
    create_unblock_user_request_packet,
    create_bio_request_packet,
    create_last_seen_request_packet,
    create_change_bio_request_packet,
    create_change_username_request_packet,
    create_conversation_list_request_packet,
    create_device_authorize_packet,
    create_device_enroll_request_packet,
    create_device_key_sync_packet,
    create_device_list_request_packet,
    create_device_revoke_packet,
    create_device_session_bind_packet,
    create_direct_conversation_request_packet,
    create_direct_key_recovery_request_packet,
    create_epoch_reservation_request_packet,
    create_group_add_members_packet,
    create_group_create_packet,
    create_group_key_distribution_packet,
    create_group_key_rotation_complete_packet,
    create_group_remove_member_packet,
    create_inbox_list_request_packet,
    create_inbox_response_packet,
    create_login_request_packet,
    create_logout_request_packet,
    create_message_delete_for_everyone_packet,
    create_message_delete_for_me_packet,
    create_message_edit_packet,
    create_message_history_request_packet,
    create_message_pin_packet,
    create_message_unpin_packet,
    create_payload_packet,
    create_profile_picture_request_packet,
    create_profile_picture_upload_request_packet,
    create_public_key_packet,
    create_reaction_add_packet,
    create_reaction_remove_packet,
    create_read_receipt_packet,
    create_register_request_packet,
    create_typing_indicator_packet,
    create_user_lookup_by_phone_request_packet,
    create_verification_request_packet,
)
from utils.request_registry import PendingRequestRegistry, RequestTimeoutError

PEER_KEY_STATE_CHANGED = "KEY_CHANGED"

# Placeholder for a historical message this client cannot decrypt
# (the epoch's key was never received/cached) -- mirrors client/
# session.py's own _UNDECRYPTABLE_PLACEHOLDER exactly.
_UNDECRYPTABLE_PLACEHOLDER = "Message unavailable (encrypted in a previous session)"


class PeerNotVerifiedError(ValueError):
    """Raised by establish_session_key() when the peer's cached public
    key exists but is not VERIFIED -- mirrors client/session.py's own
    exception of the same name and purpose exactly."""

    def __init__(self, username, state):
        self.username = username
        self.state = state
        if state == PEER_KEY_STATE_CHANGED:
            message = "This contact's security identity has changed. Verify the new fingerprint before continuing."
        else:
            message = "Secure messaging is unavailable until you verify this contact."
        super().__init__(message)


class _Signal:
    """Minimal Qt-Signal-alike: connect(callback) + emit(*args), no Qt
    or Kivy dependency. A UI layer's connected callback is responsible
    for its own thread-marshalling (this class's emit() runs on
    whichever thread calls it -- the receiver thread, for every
    incoming-packet signal below) -- see mobile/app.py's own comment
    for how the Kivy UI does this via kivy.clock.Clock."""

    def __init__(self):
        self._callbacks = []

    def connect(self, callback):
        self._callbacks.append(callback)

    def emit(self, *args):
        for callback in list(self._callbacks):
            callback(*args)


class MobileClientSession:
    """
    A single mobile client session -- connects to the REAL server over
    the REAL TLS+TCP protocol (no gateway needed; unlike a browser,
    Python has raw socket access), authenticates, and provides the
    same functional surface as WebClientSession: direct messaging,
    groups, file/image transfer, history recovery with dedup, read
    receipts, and multi-device identity linking.
    """

    def __init__(self, storage_dir=None):
        self.client_socket = None
        self.connected = False
        self.receiver_thread = None

        self.user_id = None
        self.username = ""
        self.access_token = None
        self.online_users = []

        # Phase 19.24 -- Block User: local cache mirroring client/
        # session.py::ClientSession's identical field exactly.
        self.blocked_usernames = set()

        self.logger = setup_logger("mobile_client_logger", "mobile_client.log")

        self.key_manager = KeyManager()
        self.device_id = None
        self.key_store = None
        self.key_store_error = None
        self._storage_dir = storage_dir

        # In-memory peer trust, keyed by username OR device_id (device-
        # peer trust reuses this SAME store, exactly like desktop/web
        # both do -- see observe_device_peer_identity() below):
        # {key: {"kem_wire": str, "signing_key": bytes, "state": str,
        #        "fingerprint": str}}. Session-local only (see this
        # file's own module docstring on why -- the identity KEYPAIR
        # itself persists via SecureKeyStore regardless).
        self.peers = {}

        # Conversation/group keys themselves are NOT tracked in a
        # second, separate dict here (unlike WebClientSession's own
        # sessionKeys Map) -- self.key_manager (crypto.key_manager.
        # KeyManager) is used directly everywhere below, exactly like
        # ClientSession does, since it is ALSO what SecureKeyStore
        # persists/restores across a restart (see _unlock_key_store()
        # above) -- a separate dict would silently diverge from what
        # actually survives a reconnect. See _has_conversation_key()/
        # _conversation_key_info()/_store_conversation_key() below.

        # peer username -> conversation_id
        self.direct_conversation_ids = {}

        # {sender_username: [(conversation_id, epoch), ...]} -- mirrors
        # client/session.py's identically-named dict exactly: a key
        # distribution rejected purely because ``sender`` was not yet
        # VERIFIED (see _handle_group_key_distribution()'s "if not
        # self._peer_key_is_verified(sender)" branch). The sender is
        # never told a redelivery attempt failed, so once this client
        # later verifies them there is otherwise nothing to prompt a
        # retry -- confirm_peer_verified() drains this for the peer it
        # just verified and re-sends the same direct_key_recovery_
        # request handle_direct_key_recovery_available() already sends
        # on reconnect. Makes "verify late, on either side, in either
        # order" work without requiring a manual reconnect.
        self._pending_key_requests_awaiting_verification = {}

        # {recipient_username: [(conversation_id, epoch), ...]} -- the
        # other half of the same gap: _handle_direct_key_redelivery_
        # required() silently declines to redeliver a key to
        # ``recipient`` when THIS client has not verified THEM yet.
        # Recorded here so confirm_peer_verified() can retry the exact
        # same redelivery once this client verifies ``recipient``,
        # instead of leaving it stuck until their next reconnect.
        self._declined_redeliveries_awaiting_verification = {}
        # conversation_id -> {"name": str, "members": [str]}
        self.groups = {}
        # message_id -> True, for history/live dedup (Phase 18.5 Step 6
        # semantics, reused here unchanged).
        # Phase 19.17C -- keyed by real conversation_id (not a flat,
        # cross-conversation set): open_chat() rebuilds its message
        # widget from scratch on every open (mobile/app.py), so this
        # must be forgettable per-conversation (see
        # forget_rendered_history() below) without losing the
        # legitimate same-open live+history overlap protection this
        # was originally built for.
        self._rendered_message_ids = {}

        self._payload_adapters = {
            PayloadType.TEXT: TextPayloadAdapter(),
            PayloadType.FILE: FilePayloadAdapter(PayloadType.FILE),
            PayloadType.IMAGE: FilePayloadAdapter(PayloadType.IMAGE),
            # Phase 19.24 -- Message Lifecycle Events.
            PayloadType.REACTION: ReactionPayloadAdapter(),
            # Phase 19.24 -- Voice/Video Messages: mirrors client/
            # session.py's identical addition -- the same generic raw-
            # bytes adapter FILE/IMAGE already use.
            PayloadType.VOICE: FilePayloadAdapter(PayloadType.VOICE),
            PayloadType.VIDEO: FilePayloadAdapter(PayloadType.VIDEO),
        }

        self._pending_requests = PendingRequestRegistry()

        # Events -- see _Signal's own docstring. Mirrors client/
        # session.py::ClientSession's Signal inventory (names/arg
        # shapes), minus what this scope does not implement (group
        # leave/rotation, RSA).
        self.message_received = _Signal()          # (identity_key, sender, text, historical: bool, status: str|None -- Phase 19.23, historical own messages only)
        self.payload_message_received = _Signal()  # (identity_key, sender, payload_type, bytes, content_metadata, historical: bool, status: str|None -- Phase 19.23, historical own messages only)
        self.users_updated = _Signal()              # (list[str])
        self.error_occurred = _Signal()              # (str)
        self.connection_changed = _Signal()          # (bool)
        self.read_receipt_updated = _Signal()        # (conversation_id, reader)
        self.public_key_received = _Signal()         # (username)
        self.security_rejection = _Signal()          # (reason, sender, conversation_id)
        self.group_created = _Signal()               # (conversation_id, name, members)
        self.inbox_updated = _Signal()               # (notification dict) -- Phase 19.13
        # (receiver_username, status) where status is "delivered" |
        # "queued" | "failed" -- Phase 19.14 -- Message Status Ticks.
        # No message_id is usable here: _send_payload() never learns
        # its own message's server-assigned id (fire-and-forget, see
        # its own docstring) -- the UI correlates by FIFO order per
        # receiver instead (real send order, not a fake/timed guess;
        # see mobile/app.py::ChatScreen._pending_send_status).
        self.message_status_updated = _Signal()

        # Phase 19.24 -- Message Lifecycle Events. Every signal below
        # carries only ALREADY-DECRYPTED content, exactly like message_
        # received/payload_message_received above.
        self.message_edited_received = _Signal()    # (conversation_id, message_id, new_text, editor, edited_at, edit_version)
        self.message_deleted_received = _Signal()    # (conversation_id, message_id, deleted_by, deleted_at)
        self.reaction_updated_received = _Signal()   # (conversation_id, message_id, actor, action, reaction_or_empty)
        self.message_pinned_received = _Signal()     # (conversation_id, message_id, pinned_by, pinned_at) -- Phase 19.24
        self.message_unpinned_received = _Signal()   # (conversation_id, message_id, unpinned_by) -- Phase 19.24

        # Phase 19.24 (continued) -- mirrors gui/chat_window.py's
        # identical Desktop signals (client/session.py's own_message_id_
        # resolved/message_id_received declarations carry the full
        # rationale, unchanged here): a live-sent bubble has no server-
        # assigned message_id until message_delivered/message_queued
        # first reveals it (own_message_id_resolved, (receiver_username,
        # message_id), direct-only); a live-RECEIVED bubble's id is
        # withheld from message_received/payload_message_received
        # (widening either -- a bare, non-Qt _Signal(), so nothing
        # enforces arity -- would still silently break the many fixed-
        # arity lambdas already connected to them across mobile/app.py
        # and this project's tests) and delivered one signal later
        # instead (message_id_received, (identity_key, message_id)).
        self.own_message_id_resolved = _Signal()
        self.message_id_received = _Signal()

        # Phase 19.24 (continued) -- mobile's history replay is signal-
        # driven (load_history() emits message_received/payload_
        # message_received per historical row -- there is no separate
        # "return a list" API to extend the way Desktop's
        # ClientSession.load_conversation_history() was extended).
        # This is the mobile equivalent of that extension: one
        # additional signal per row (historical OR live) that actually
        # has a message_id, carrying whatever reply/edit/delete/
        # reaction state that message has right now. (identity_key,
        # message_id, reply_to_message_id_or_none, is_deleted,
        # edit_version, reactions -- a list of {"user", "reaction"}
        # dicts, already decrypted/verified exactly like reaction_
        # updated_received's own "add" case).
        self.message_lifecycle_state_received = _Signal()

        # Phase 19.24 -- Typing Indicator. Purely a live, ephemeral
        # hint -- never persisted, never replayed via history, mirrors
        # client/session.py's identical desktop signal exactly.
        # (conversation_id, username, is_typing). Never emitted for
        # this session's own typing (server/client_handler.py::
        # handle_typing_indicator() excludes the actor's own socket
        # from the relay).
        self.typing_indicator_received = _Signal()

    def _adapter_for(self, payload_type):
        return self._payload_adapters[payload_type]

    # ---- self.key_manager-backed conversation-key helpers (see
    # __init__'s own comment on why there is no separate dict) ----

    def _has_conversation_key(self, conversation_id):
        return self.key_manager.has_key(conversation_id)

    def _conversation_key_info(self, conversation_id):
        """Returns {"key": bytes, "epoch": int} for this conversation's
        CURRENT epoch, or None if no key is held at all."""

        epoch = self.key_manager.current_epoch(conversation_id)
        if epoch is None:
            return None
        key_bytes = self.key_manager.get_key(conversation_id, epoch=epoch)
        if key_bytes is None:
            return None
        return {"key": key_bytes, "epoch": epoch}

    def _store_conversation_key(self, conversation_id, key_bytes, epoch):
        self.key_manager.store_key(conversation_id, key_bytes, epoch=epoch)

    # ==========================================================
    # Connection lifecycle -- identical logic to ClientSession.connect()
    # ==========================================================

    def connect(self):
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
        raw_socket.connect((SERVER_HOST, SERVER_PORT))

        tls_context = build_client_context()
        try:
            self.client_socket = tls_context.wrap_socket(raw_socket, server_hostname=SERVER_HOST)
        except Exception:
            raw_socket.close()
            raise

        try:
            self.client_socket.settimeout(None)
        except OSError:
            pass

        self.connected = True
        self.connection_changed.emit(True)
        self.logger.info(
            f"Connected to server ({SERVER_HOST}:{SERVER_PORT}) over TLS ({self.client_socket.version()})"
        )

    def send_request(self, packet, timeout=REQUEST_TIMEOUT_SECONDS):
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
            self.logger.warning(f"Timed out waiting for a response to {packet.get('type')!r} (request_id={request_id})")
            raise

    def authenticate_credentials(self, identifier, password):
        self.connect()
        try:
            packet = create_login_request_packet(identifier=identifier, password=password)
            packet["request_id"] = str(uuid.uuid4())
            send_message(self.client_socket, packet)
            response = receive_message(self.client_socket)
        finally:
            self.disconnect()

        if not isinstance(response, dict) or response.get("type") != "login_result":
            raise ConnectionError("Server did not respond to the login request.")

        token_pair = None
        if response.get("access_token") and response.get("refresh_token"):
            token_pair = TokenPair(
                access_token=response["access_token"],
                refresh_token=response["refresh_token"],
                expires_in=response.get("expires_in"),
                token_type=response.get("token_type") or "Bearer",
            )

        if response.get("success") and response.get("user_id"):
            self._unlock_key_store(response["user_id"], password)

        return AuthenticationResult(
            success=bool(response.get("success")),
            message=response.get("message") or "Authentication failed.",
            user_id=response.get("user_id"),
            phone_number=response.get("phone_number"),
            username=response.get("username"),
            role=response.get("role"),
            session_id=response.get("session_id"),
            token_pair=token_pair,
            errors=response.get("errors"),
        )

    def register(self, full_name, username, email, phone_number, password, confirm_password):
        self.connect()
        try:
            packet = create_register_request_packet(
                full_name=full_name, username=username, email=email,
                phone_number=phone_number, password=password, confirm_password=confirm_password,
            )
            packet["request_id"] = str(uuid.uuid4())
            send_message(self.client_socket, packet)
            response = receive_message(self.client_socket)
        finally:
            self.disconnect()

        if not isinstance(response, dict) or response.get("type") != "register_result":
            raise ConnectionError("Server did not respond to the registration request.")

        return RegistrationResult(
            success=bool(response.get("success")),
            message=response.get("message") or "Registration failed.",
            user_id=response.get("user_id"),
            errors=response.get("errors"),
        )

    def _unlock_key_store(self, user_id, password):
        """Mirrors ClientSession._unlock_key_store() exactly -- opens
        the SAME on-disk encrypted store format (storage_dir points at
        a mobile-appropriate app-private directory; see mobile/app.py)."""

        self.key_store = None
        self.key_store_error = None

        try:
            store = SecureKeyStore(user_id, storage_dir=self._storage_dir)
            restored = store.unlock(password)
        except KeyStoreLocked as error:
            self.key_store_error = str(error)
            self.logger.warning(f"Local key store not unlocked: {error}")
            return
        except KeyStoreError as error:
            self.key_store_error = str(error)
            self.logger.warning(f"Local key store unavailable: {error}")
            return

        try:
            self.key_manager.load_or_create_kyber_keypair(store)
        except (KeyStoreError, OSError) as error:
            self.logger.warning(f"Could not load or persist own Kyber keypair: {error}")

        try:
            self.key_manager.load_or_create_signing_keypair(store)
        except (ValueError, KeyStoreError, OSError) as error:
            self.logger.warning(f"Could not load or persist own signing keypair: {error}")

        try:
            self.device_id = store.get_device_id()
        except (KeyStoreError, OSError):
            self.device_id = None

        count = self.key_manager.import_conversation_keys(restored)
        self.key_store = store
        self.key_manager.on_change = self._persist_conversation_keys
        self._rehydrate_peers_from_key_store()
        self.logger.info(f"Local key store unlocked; restored {count} conversation key epoch(s)")

    def _rehydrate_peers_from_key_store(self):
        """
        Phase 19.23 -- Issue 1: seed self.peers from every peer this
        device's SecureKeyStore already knows about, so get_peer_
        verification_state()/is_peer_verified() correctly report a
        peer VERIFIED in an earlier session even before this session
        happens to observe their key live again (e.g. they are
        currently offline). See SecureKeyStore.get_all_peer_
        verifications()'s docstring for why self.peers otherwise has
        this gap and ClientSession (Desktop) does not.

        Never overwrites an entry this session has already observed
        live (there is nothing to rehydrate into then, and a live
        observation is always at least as current as the persisted
        one). ``kem_wire`` -- the actual raw KEM public-key bytes
        needed to encrypt TO this peer -- is deliberately left None:
        SecureKeyStore never persists it (only the fingerprint derived
        from it), and establishing a session key already requires
        observing it live at send time regardless, unchanged by this
        method. This only makes VERIFIED status (and a verified peer's
        entry existing at all) visible immediately after login; it
        grants no new ability to encrypt to anyone.
        """

        if self.key_store is None:
            return

        for username, entry in self.key_store.get_all_peer_verifications().items():

            if username in self.peers:
                continue

            self.peers[username] = {
                "kem_wire": None,
                "signing_key": entry.get("signing_public_key"),
                "state": entry["state"],
                "fingerprint": entry["fingerprint"],
            }

    def _persist_conversation_keys(self):
        if self.key_store is None:
            return
        try:
            self.key_store.save(self.key_manager.export_conversation_keys())
        except (KeyStoreError, OSError) as error:
            self.logger.warning(f"Could not persist conversation keys: {error}")

    def login(self, username):
        username = (username or "").strip() or "Anonymous"
        self.username = username

        if not self.access_token:
            raise PermissionError("No access token available. Please log in again.")

        send_message(self.client_socket, create_auth_packet(self.access_token))
        self.logger.info("Sent authentication request to server.")

        response = receive_message(self.client_socket)
        if not isinstance(response, dict) or response.get("type") != "auth_result":
            raise PermissionError("Server did not respond to the authentication request.")
        if not response.get("success"):
            raise PermissionError(response.get("message") or "Authentication failed.")

        server_username = response.get("username")
        if server_username:
            self.username = server_username

        self.logger.info(f"Authenticated as {self.username}.")

    def logout(self):
        response = self.send_request(create_logout_request_packet())
        self._lock_key_store()
        return bool(response.get("success"))

    def _lock_key_store(self):
        self.key_manager.on_change = None
        if self.key_store is not None:
            self.key_store.lock()
            self.key_store = None
        self.key_manager.keys = {}
        self.key_manager._current_epoch = {}

    def send_public_key(self):
        algorithm = self.key_manager.algorithm
        kem_public_key_wire = self.key_manager.public_key.decode("utf-8")
        signing_public_key = self.key_manager.ml_dsa.export_public_key()

        signature = sign_identity_payload(self.key_manager.ml_dsa, self.username, kem_public_key_wire, signing_public_key)

        packet = create_public_key_packet(
            username=self.username,
            algorithm=algorithm,
            public_key=kem_public_key_wire,
            signing_public_key=base64.b64encode(signing_public_key).decode("ascii"),
            identity_signature=base64.b64encode(signature).decode("ascii"),
            device_id=self.device_id,
        )
        send_message(self.client_socket, packet)
        self.logger.info(f"{algorithm} public key sent to server (ML-DSA signed).")

    def start_receiver(self):
        if self.receiver_thread is not None:
            return
        self.receiver_thread = threading.Thread(target=receive_messages, args=(self,), daemon=True)
        self.receiver_thread.start()
        self.logger.info("Receiver thread started.")

    def disconnect(self):
        self.logger.info("Closing connection...")
        self.connected = False
        self.connection_changed.emit(False)

        if self.client_socket is not None:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.client_socket.close()
            self.client_socket = None

        if self.receiver_thread is not None:
            self.receiver_thread.join(timeout=2)
            self.receiver_thread = None

        self.logger.info("Disconnected.")

    # ==========================================================
    # Incoming packet dispatch -- receive_messages() (client/
    # receiver.py, reused unchanged) calls this by name.
    # ==========================================================

    def handle_packet(self, packet):
        if self._pending_requests.resolve(packet.get("request_id"), packet):
            return

        packet_type = packet.get("type")

        if packet_type == "user_list":
            self.online_users = packet.get("users", [])
            self.users_updated.emit(self.online_users)
        elif packet_type == "chat":
            self._handle_chat(packet)
        elif packet_type == "key_exchange" and packet.get("operation") == "public_key":
            self._handle_signed_public_key(packet)
        elif packet_type == "group_create_result":
            self._handle_group_create_result(packet)
        elif packet_type == "group_members_added":
            self._handle_group_members_added(packet)
        elif packet_type == "group_member_left":
            self._handle_group_member_left(packet)
        elif packet_type == "inbox_notification":
            self.inbox_updated.emit(packet.get("notification") or {})
        elif packet_type == "inbox_response_result":
            notification = packet.get("notification") or {}
            self._complete_requester_side_verification(notification)
            self.inbox_updated.emit(notification)
        elif packet_type == "group_key_distribution":
            self._handle_group_key_distribution(packet)
        elif packet_type == "group_key_rotation_required":
            self._handle_group_key_rotation_required(packet)
        elif packet_type == "direct_key_recovery_available":
            self.handle_direct_key_recovery_available(packet)
        elif packet_type == "direct_key_redelivery_required":
            self._handle_direct_key_redelivery_required(packet)
        elif packet_type == "device_key_sync":
            self._handle_device_key_sync(packet)
        elif packet_type == "read_receipt_notification":
            conversation_id = packet.get("conversation_id")
            reader = packet.get("reader")
            if conversation_id and reader:
                self.read_receipt_updated.emit(conversation_id, reader)
        elif packet_type == "typing_indicator_notification":
            conversation_id = packet.get("conversation_id")
            username = packet.get("username")
            if conversation_id and username:
                self.typing_indicator_received.emit(
                    conversation_id, username, bool(packet.get("is_typing"))
                )
        elif packet_type == "message_edited":
            self._handle_message_edited(packet)
        elif packet_type == "message_deleted":
            self._handle_message_deleted(packet)
        elif packet_type == "reaction_updated":
            self._handle_reaction_updated(packet)
        elif packet_type == "message_pinned":
            self._handle_message_pinned(packet)
        elif packet_type == "message_unpinned":
            self._handle_message_unpinned(packet)
        elif packet_type == "message_delivered":
            receiver = packet.get("receiver")
            if receiver:
                self.message_status_updated.emit(receiver, "delivered")
                # Phase 19.24 (continued) -- see own_message_id_resolved's
                # own declaration for why this, not the fire-and-forget
                # send itself, is the first place a sender learns a
                # just-sent (direct) message's real id.
                message_id = packet.get("message_id")
                if message_id:
                    self.own_message_id_resolved.emit(receiver, message_id)
        elif packet_type == "message_queued":
            receiver = packet.get("receiver")
            if receiver:
                self.message_status_updated.emit(receiver, "queued")
                message_id = packet.get("message_id")
                if message_id:
                    self.own_message_id_resolved.emit(receiver, message_id)
        elif packet_type == "delivery_failure":
            receiver = packet.get("receiver")
            if receiver:
                self.message_status_updated.emit(receiver, "failed")
            self.logger.warning(f"delivery_failure: {packet}")
        elif packet_type in ("join", "leave"):
            self.logger.info(f"{packet_type}: {packet}")
        else:
            self.logger.warning(f"Unhandled packet type: {packet_type}")

    # ==========================================================
    # Peer identity: observe + human-verify (mirrors
    # WebClientSession's _handlePeerPublicKey/_upsertPeerObservation/
    # confirmPeerVerified exactly).
    # ==========================================================

    def _handle_signed_public_key(self, packet):
        username = packet.get("username")
        kem_wire = packet.get("public_key")
        signing_key_b64 = packet.get("signing_public_key")
        signature_b64 = packet.get("identity_signature")

        if not username or username == self.username or not kem_wire:
            return
        if not signing_key_b64 or not signature_b64:
            self.logger.info(f"Ignoring legacy, unsigned public-key packet from {username}.")
            return

        try:
            signing_key = base64.b64decode(signing_key_b64, validate=True)
            signature = base64.b64decode(signature_b64, validate=True)
        except (TypeError, ValueError):
            self.logger.warning(f"SECURITY: rejected malformed signed identity packet for {username}.")
            return

        if not verify_identity_payload(username, kem_wire, signing_key, signature):
            self.logger.warning(f"SECURITY: ML-DSA signature verification FAILED for identity packet from {username}.")
            return

        try:
            self.key_manager.add_public_key(username, kem_wire)
        except (ValueError, TypeError) as error:
            self.logger.warning(f"Rejected malformed public key from {username}: {error}")
            return

        peer = self._upsert_peer_observation(username, kem_wire, signing_key)
        self.public_key_received.emit(username)
        self.logger.info(f"Observed {username} (state: {peer['state']}).")

    def _upsert_peer_observation(self, key, kem_wire, signing_key):
        """
        Phase 19.19 -- Android peer-verification persistence. Mirrors
        client/session.py's exact pattern: self.peers stays the
        session-local cache of the raw wire key material (needed for
        actual crypto operations, same role as KeyManager.public_keys
        on Desktop), but VERIFIED state is now sourced from --  and
        always written through to -- the SAME SecureKeyStore Desktop
        already uses (storage/secure_key_store.py), not invented as a
        second trust store.

        Before this phase, self.peers started empty on every fresh
        MobileClientSession (app relaunch), so a peer verified in a
        PRIOR run always came back as UNVERIFIED here regardless of
        what SecureKeyStore already had on file. Now: the first
        observation of a peer this session (``existing`` is None)
        consults the persisted record -- fingerprint_matches_verified()
        promotes straight to VERIFIED (never a blind trust: it
        independently re-derives and compares the fingerprint just
        computed above against the one actually on file, exactly the
        hardening confirm_peer_verification() already applies on
        Desktop), a persisted VERIFIED record for a DIFFERENT
        fingerprint correctly becomes KEY_CHANGED (the identity change
        happened while this session/app was closed -- it must not be
        silently swallowed into looking like a fresh, ordinary
        UNVERIFIED peer), and no persisted record at all is UNVERIFIED
        exactly as before.
        """
        existing = self.peers.get(key)
        fingerprint = fingerprint_combined_identity(kem_wire, signing_key)

        if existing and existing["state"] == PEER_STATE_VERIFIED and existing["fingerprint"] != fingerprint:
            self.peers[key] = {"kem_wire": kem_wire, "signing_key": signing_key, "state": PEER_KEY_STATE_CHANGED, "fingerprint": fingerprint}
            self.logger.warning(f"SECURITY: {key}'s identity changed since it was verified -- re-verification required.")
        elif not existing:
            state = PEER_STATE_UNVERIFIED
            if self.key_store is not None:
                if self.key_store.fingerprint_matches_verified(key, fingerprint):
                    state = PEER_STATE_VERIFIED
                elif self.key_store.has_verified_fingerprint(key):
                    state = PEER_KEY_STATE_CHANGED
                    self.logger.warning(
                        f"SECURITY: {key}'s identity differs from the "
                        f"previously verified one on file -- re-verification required."
                    )
            self.peers[key] = {"kem_wire": kem_wire, "signing_key": signing_key, "state": state, "fingerprint": fingerprint}
        else:
            existing["kem_wire"] = kem_wire
            existing["signing_key"] = signing_key
            existing["fingerprint"] = fingerprint

        # Unconditionally safe -- record_observed_peer_fingerprint()
        # itself refuses to touch an existing VERIFIED entry (see its
        # own docstring); this only ever records/refreshes an
        # UNVERIFIED observation, never demotes a verified one.
        if self.key_store is not None:
            self.key_store.record_observed_peer_fingerprint(key, fingerprint, signing_public_key=signing_key)

        return self.peers[key]

    def observe_peer_identity(self, username, kem_wire, signing_key):
        peer = self._upsert_peer_observation(username, kem_wire, signing_key)
        self.public_key_received.emit(username)
        return peer

    def confirm_peer_verified(self, username, confirmed_fingerprint):
        peer = self.peers.get(username)
        if not peer:
            raise ValueError(f"No observed identity for {username} yet.")
        if peer["fingerprint"] != confirmed_fingerprint:
            raise ValueError("Fingerprint does not match the currently observed identity.")
        peer["state"] = PEER_STATE_VERIFIED
        # Phase 19.19 -- write through to the persisted store (mirrors
        # client/session.py::confirm_peer_verification() wrapping
        # SecureKeyStore.verify_peer_fingerprint() exactly) so this
        # survives logout/login, force-stop/relaunch, and a normal
        # reconnect, not just the remainder of this process's memory.
        if self.key_store is not None:
            self.key_store.verify_peer_fingerprint(
                username, confirmed_fingerprint, signing_public_key=peer.get("signing_key")
            )
        self._retry_pending_key_requests(username)
        self._retry_declined_redeliveries(username)

    def _retry_pending_key_requests(self, sender):
        """Re-requests every (conversation_id, epoch) rejected from
        ``sender`` solely for being unverified at the time -- see
        _pending_key_requests_awaiting_verification's own comment.
        Mirrors client/session.py's identically-named method exactly,
        using the same create_direct_key_recovery_request_packet()
        handle_direct_key_recovery_available() already sends on an
        ordinary reconnect."""

        pending = self._pending_key_requests_awaiting_verification.pop(sender, None)
        if not pending or not self.client_socket:
            return

        for conversation_id, epoch in pending:
            if self.key_manager.has_key(conversation_id, epoch=epoch):
                continue
            # Best-effort -- see client/session.py's identically-named
            # method for the real, physically-reproduced regression
            # (test_attack_d_forged_packet_no_longer_wins_the_race_
            # against_the_real_key) this guards against: self.
            # client_socket being truthy does not guarantee it is still
            # connected, and a failed opportunistic send here must
            # never break the confirm_peer_verified() call that
            # triggered it. Nothing is lost -- see this method's own
            # docstring.
            try:
                send_message(self.client_socket, create_direct_key_recovery_request_packet(
                    conversation_id=conversation_id, epochs=[epoch],
                ))
            except Exception as error:  # noqa: BLE001
                self.logger.warning(
                    f"Failed to re-request recovery of {conversation_id} "
                    f"epoch {epoch} from {sender}: {error}"
                )
                continue
            self.logger.info(
                f"Re-requested recovery of {conversation_id} epoch {epoch} "
                f"from {sender} now that they are verified"
            )

    def _retry_declined_redeliveries(self, recipient):
        """The other half of "verify late, in either order": retries
        every (conversation_id, epoch) this client itself declined to
        REDELIVER to ``recipient`` -- _handle_direct_key_redelivery_
        required()'s own "SECURITY: refusing to redeliver" branch --
        purely for not having verified ``recipient`` yet at the time.
        Mirrors client/session.py's identically-named method exactly:
        re-runs that same handler with a reconstructed packet so every
        one of its checks applies fresh."""

        pending = self._declined_redeliveries_awaiting_verification.pop(recipient, None)
        if not pending:
            return

        for conversation_id, epoch in pending:
            # Best-effort -- see client/session.py's identically-named
            # method for why this must not let a send failure escape.
            try:
                self._handle_direct_key_redelivery_required({
                    "conversation_id": conversation_id,
                    "epoch": epoch,
                    "recipient": recipient,
                })
            except Exception as error:  # noqa: BLE001
                self.logger.warning(
                    f"Failed to retry declined redelivery of {conversation_id} "
                    f"epoch {epoch} to {recipient}: {error}"
                )

    def get_peer_verification_state(self, key):
        peer = self.peers.get(key)
        return peer["state"] if peer else None

    def get_peer_fingerprint_for_verification(self, key):
        peer = self.peers.get(key)
        return peer["fingerprint"] if peer else None

    def _peer_key_is_verified(self, key):
        peer = self.peers.get(key)
        return bool(peer and peer["state"] == PEER_STATE_VERIFIED)

    def is_peer_verified(self, key):
        return self._peer_key_is_verified(key)

    def _report_security_rejection(self, reason, sender, conversation_id):
        self.logger.warning(f"SECURITY: rejected ({reason}) for conversation {conversation_id}, claimed sender {sender}.")
        self.security_rejection.emit(reason, sender, conversation_id)

    # ==========================================================
    # User discovery (mirrors client/session.py::
    # find_user_by_phone_number() exactly -- the same server-side
    # user_lookup_by_phone_request/handle_user_lookup() desktop's own
    # Find User / Create Group / Add Members dialogs already use.
    # mobile/session.py never had a client-side method for it before
    # Phase 19's UI redesign; nothing server-side changed to add this.
    # ==========================================================

    def find_user_by_phone_number(self, phone_number):
        if not self.access_token:
            raise PermissionError("Not authenticated. Please log in first.")
        if not is_valid_phone_number(phone_number):
            return None
        response = self.send_request(create_user_lookup_by_phone_request_packet(phone_number=phone_number))
        if not response.get("user_id"):
            return None
        return {
            "user_id": response["user_id"],
            "username": response["username"],
            "display_name": response["display_name"],
        }

    # ==========================================================
    # Key establishment (mirrors WebClientSession.
    # openDirectConversation()/establishSessionKey() exactly).
    # ==========================================================

    def open_direct_conversation(self, peer_username):
        if peer_username in self.direct_conversation_ids:
            return self.direct_conversation_ids[peer_username]
        response = self.send_request(create_direct_conversation_request_packet(peer_username))
        if response.get("error"):
            raise ValueError(response["error"])
        self.direct_conversation_ids[peer_username] = response["conversation_id"]
        return response["conversation_id"]

    def establish_session_key(self, peer_username):
        if not self._peer_key_is_verified(peer_username):
            raise PeerNotVerifiedError(peer_username, self.get_peer_verification_state(peer_username))

        conversation_id = self.open_direct_conversation(peer_username)
        existing = self._conversation_key_info(conversation_id)
        if existing is not None:
            return existing

        reservation = self.send_request(create_epoch_reservation_request_packet(conversation_id))
        if reservation.get("error"):
            raise ValueError(reservation["error"])
        epoch = reservation["epoch"]

        session_key = os.urandom(32)
        self._store_conversation_key(conversation_id, session_key, epoch)

        peer = self.peers[peer_username]
        encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(peer_username, session_key) \
            if self.key_manager.get_public_key(peer_username) is not None else (None, None)

        if encapsulation is None and wrapped_key is None:
            # KYBER always returns a real (encapsulation, wrapped_key) pair
            # once a public key exists; None/None here means no public key
            # was cached at all -- defer delivery, mirroring
            # WebClientSession's identical "no peer public key yet" path.
            self.logger.info(f"Deferring key delivery to {peer_username}: no public key available yet.")
            return self._conversation_key_info(conversation_id)

        signature = sign_group_key_payload(
            self.key_manager.ml_dsa, self.username, conversation_id, peer_username, encapsulation, wrapped_key, epoch,
        )
        send_message(self.client_socket, create_group_key_distribution_packet(
            sender=self.username, conversation_id=conversation_id, recipient=peer_username,
            encapsulation=encapsulation, wrapped_key=wrapped_key, epoch=epoch,
            group_key_signature=base64.b64encode(signature).decode("ascii"),
        ))
        self.logger.info(f"Generated AES session key for {peer_username} (epoch {epoch})")
        return self._conversation_key_info(conversation_id)

    # ==========================================================
    # Groups (mirrors WebClientSession.createGroup()/
    # _handleGroupCreateResult()/_createAndDistributeGroupKey()).
    # ==========================================================

    def create_group(self, name, member_usernames):
        send_message(self.client_socket, create_group_create_packet(sender=self.username, name=name, member_usernames=member_usernames))

    def add_group_members(self, conversation_id, member_usernames):
        """Ask the server to add one or more users to an existing
        group conversation -- mirrors client/session.py::
        add_group_members() exactly. The result (participant-list
        refresh for everyone, and key material for the new member(s))
        arrives asynchronously via _handle_group_members_added()/
        _handle_group_key_rotation_required() (Phase 19.10's own fix,
        reused unchanged -- the server dispatches a new member's key
        the same way it dispatches recovery for a reconnecting one)."""

        send_message(self.client_socket, create_group_add_members_packet(
            sender=self.username, conversation_id=conversation_id, member_usernames=member_usernames,
        ))

    def _handle_group_members_added(self, packet):
        """A group conversation this user belongs to gained one or
        more members. Sent to every current active member, old and new
        alike, so this needs no branch for "am I new here or not".
        Key material for any genuinely new member arrives separately
        via _handle_group_key_rotation_required()."""

        conversation_id = packet["conversation_id"]
        name = packet["name"]
        members = packet.get("members", [])

        if conversation_id in self.groups:
            self.groups[conversation_id]["members"] = members
        else:
            # admin unknown from this packet alone (Phase 19.13) --
            # left None until this client learns it some other way
            # (load_conversations()/_handle_group_create_result()).
            self.groups[conversation_id] = {"name": name, "members": members, "admin": None}
        self.group_created.emit(conversation_id, name, members)
        self.logger.info(f"Group {conversation_id} members updated: {members}")

    def _handle_group_member_left(self, packet):
        """A member left (self-service) or was removed by the group
        admin (Phase 19.13 -- Group Admin) -- same wire packet either
        way, see server/client_handler.py::handle_group_remove_member()
        's own docstring. Updates the member list this client already
        tracks; preserves whatever admin this client already knows for
        this group (this packet carries no admin field of its own)."""

        conversation_id = packet["conversation_id"]
        members = packet.get("members", [])

        if conversation_id in self.groups:
            self.groups[conversation_id]["members"] = members
        else:
            self.groups[conversation_id] = {"name": conversation_id, "members": members, "admin": None}

        self.group_created.emit(conversation_id, self.groups[conversation_id]["name"], members)
        self.logger.info(f"Group {conversation_id} members now: {members}")

    def _handle_group_create_result(self, packet):
        conversation_id = packet["conversation_id"]
        name = packet["name"]
        members = packet.get("members", [])
        creator = packet.get("creator")

        self.groups[conversation_id] = {"name": name, "members": members, "admin": creator}
        self.group_created.emit(conversation_id, name, members)
        self.logger.info(f"Group '{name}' ({conversation_id}) ready -- members: {members}")

        if creator == self.username:
            participants = [m for m in members if m != self.username]
            self._create_and_distribute_group_key(conversation_id, participants)

    def remove_group_member(self, conversation_id, target_username):
        """Ask the server to remove ``target_username`` from a group
        (Phase 19.13 -- Group Admin). Admin-only, server-enforced --
        mirrors client/session.py::remove_group_member() exactly,
        including using send_request() (not fire-and-forget) so the
        caller gets the definite success/error immediately."""

        return self.send_request(create_group_remove_member_packet(
            conversation_id=conversation_id, target_username=target_username,
        ))

    # ==========================================================
    # Inbox: verification requests + group member-add approval
    # (Phase 19.13 -- mirrors client/session.py's identically-named
    # methods exactly; see their docstrings for the full security
    # reasoning, unchanged here.)
    # ==========================================================

    def request_verification(self, target_username):
        send_message(self.client_socket, create_verification_request_packet(target_username))

    def load_inbox(self):
        response = self.send_request(create_inbox_list_request_packet())
        return response.get("notifications") or []

    def respond_to_inbox(self, notification, approve):
        """Approve/deny one pending inbox notification. Security --
        verification_request: approving here is the ONLY place that
        Approve is allowed to take effect, and it does so by calling
        THIS client's own already-existing confirm_peer_verified()
        with the fingerprint already observed for the requester --
        never a value from the notification itself. Raises ValueError
        (confirm_peer_verified()'s own contract -- "No observed
        identity yet") if nothing has been observed, exactly as the
        existing Verify Identity flow would; the caller (UI) must
        catch this as a friendly "cannot verify them yet" and MUST
        NOT send approve=True in that case -- this method sends
        nothing to the server until the local verification call
        below has already succeeded."""

        if approve and notification.get("type") == "verification_request":

            requester_username = notification.get("requester_username")

            fingerprint = self.get_peer_fingerprint_for_verification(requester_username)

            if fingerprint is None:
                raise ValueError(
                    f"No observed identity for {requester_username} yet; "
                    f"cannot verify them until they are online and you "
                    f"have exchanged keys."
                )

            self.confirm_peer_verified(requester_username, fingerprint)

        send_message(self.client_socket, create_inbox_response_packet(
            notification_id=notification.get("notification_id"), approve=approve,
        ))

    def _complete_requester_side_verification(self, notification):
        """Phase 19.22B -- mirrors client/session.py's identically-
        named method exactly. respond_to_inbox()'s approve path above
        already promotes the APPROVER's own identity for the requester
        to VERIFIED before it ever sends approve=True; nothing
        completed the mirror half on the REQUESTER's side, so only one
        of the two participants ever left the async Inbox-mediated
        flow actually VERIFIED. Runs only when THIS user is the
        original requester (never the recipient/approver -- they
        already confirmed their own half above) and the resolution is
        an approval, through the same fail-closed get_peer_
        fingerprint_for_verification() + confirm_peer_verified() gate
        as every other verification path -- never a blind trust of
        anything in the notification itself. A failure here (this
        client has not yet observed the approver's identity) is
        swallowed exactly like every other fail-closed gate already
        does -- the user can still finish manually via Verify
        Identity."""

        if notification.get("type") != "verification_request":
            return
        if notification.get("status") != "approved":
            return
        if notification.get("requester_username") != self.username:
            return

        approver_username = notification.get("recipient_username")

        if not approver_username:
            return

        try:
            fingerprint = self.get_peer_fingerprint_for_verification(approver_username)
            if fingerprint is None:
                return
            self.confirm_peer_verified(approver_username, fingerprint)
        except Exception as error:  # noqa: BLE001
            self.logger.warning(
                f"Could not auto-complete verification with {approver_username} "
                f"after their approval: {error}"
            )

    # ==========================================================
    # Settings (Phase 19.14): change username/password, profile
    # picture upload/fetch. All four are simple request/response --
    # send_request() (not fire-and-forget), so the caller (UI) gets
    # the definite success/error to show immediately.
    # ==========================================================

    def change_username(self, new_username):
        response = self.send_request(create_change_username_request_packet(new_username))
        if response.get("success"):
            self.username = new_username
        return response

    def change_password(self, current_password, new_password, confirm_password):
        return self.send_request(create_change_password_request_packet(
            current_password=current_password, new_password=new_password, confirm_password=confirm_password,
        ))

    # ------------------------------------------------------------------
    # Phase 19.24 -- Block User: mirrors client/session.py::
    # ClientSession's identical methods exactly -- see its own
    # docstring for the full server-side enforcement scope.
    # ------------------------------------------------------------------

    def block_user(self, target_username):
        response = self.send_request(create_block_user_request_packet(target_username))
        if response.get("success"):
            self.blocked_usernames.add(target_username)
        return response

    def unblock_user(self, target_username):
        response = self.send_request(create_unblock_user_request_packet(target_username))
        if response.get("success"):
            self.blocked_usernames.discard(target_username)
        return response

    def get_blocked_users(self):
        """Mirrors client/session.py::ClientSession.get_blocked_
        users()'s identical local-cache contract -- see its own
        docstring."""

        response = self.send_request(create_blocked_users_list_request_packet())
        usernames = response.get("usernames") or []
        self.blocked_usernames = set(usernames)
        return usernames

    def is_user_blocked(self, username):
        return username in self.blocked_usernames

    def upload_profile_picture(self, image_bytes, content_type="image/png"):
        image_base64 = base64.b64encode(image_bytes).decode("ascii")
        return self.send_request(create_profile_picture_upload_request_packet(
            image_base64=image_base64, content_type=content_type,
        ))

    def fetch_profile_picture(self, username):
        """Returns the raw image bytes for ``username``'s current
        profile picture, or None if they have none set (see server/
        client_handler.py::handle_profile_picture_request()'s own
        docstring on why "not found" and "no picture set" are
        deliberately indistinguishable here)."""

        response = self.send_request(create_profile_picture_request_packet(username))
        if not response.get("found"):
            return None
        try:
            return base64.b64decode(response["image_base64"], validate=True)
        except (TypeError, ValueError, KeyError):
            return None

    def change_bio(self, bio):
        """Phase 19.22 -- Settings: mirrors client/session.py::
        change_bio() exactly."""
        return self.send_request(create_change_bio_request_packet(bio))

    def fetch_bio(self, username):
        """Returns ``username``'s current bio, or "" if none set or
        the account does not exist -- mirrors client/session.py::
        fetch_bio() exactly."""
        response = self.send_request(create_bio_request_packet(username))
        if not response.get("found"):
            return ""
        return response.get("bio") or ""

    def fetch_last_seen(self, username):
        """Phase 19.24 -- Presence/Last Seen: mirrors client/session.py
        ::fetch_last_seen() exactly -- None covers "blocked in either
        direction", "account not found", and "no last-seen information
        yet" alike."""
        response = self.send_request(create_last_seen_request_packet(username))
        if not response.get("found") or not response.get("last_seen_at"):
            return None
        try:
            return datetime.fromisoformat(response["last_seen_at"])
        except (TypeError, ValueError):
            return None

    def _distribute_group_key(self, conversation_id, group_key, epoch, recipients):
        """Wrap ``group_key`` (already stored locally under ``epoch``)
        for each of ``recipients`` and send it -- mirrors client/
        session.py::_distribute_group_key() exactly, including its
        per-recipient robustness (D6 -- Group Key Distribution
        Robustness): one member's missing/unverified/unusable key must
        never stop delivery to the members after them. Shared by
        initial group creation (epoch 1), Phase 19.10's reconnect-
        triggered rotation-required handler (epoch N), and is the same
        wire shape (group_key_distribution) direct-key redelivery
        reuses too."""

        for member in recipients:
            if self.key_manager.get_public_key(member) is None:
                self.logger.warning(f"No public key for {member}; cannot distribute group key for {conversation_id} epoch {epoch}.")
                continue
            if not self._peer_key_is_verified(member):
                self.logger.warning(f"SECURITY: {member} is not VERIFIED; skipping group key distribution for {conversation_id} epoch {epoch}.")
                continue

            try:
                encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(member, group_key)
            except (ValueError, TypeError) as error:
                self.logger.warning(f"Unusable public key for {member}; cannot distribute group key for {conversation_id} epoch {epoch}: {error}")
                continue

            signature = sign_group_key_payload(
                self.key_manager.ml_dsa, self.username, conversation_id, member, encapsulation, wrapped_key, epoch,
            )
            send_message(self.client_socket, create_group_key_distribution_packet(
                sender=self.username, conversation_id=conversation_id, recipient=member,
                encapsulation=encapsulation, wrapped_key=wrapped_key, epoch=epoch,
                group_key_signature=base64.b64encode(signature).decode("ascii"),
            ))

    def _create_and_distribute_group_key(self, conversation_id, participants):
        group_key = os.urandom(32)
        epoch = 1
        self._store_conversation_key(conversation_id, group_key, epoch)
        self._distribute_group_key(conversation_id, group_key, epoch, participants)

    def _handle_group_key_rotation_required(self, packet):
        """The server has asked this client to (re)distribute a
        group's key epoch to one or more members -- either fresh
        rotation after a membership change, or Phase 19.10's fix for
        the previously undelivered-key desync bug: on every login,
        the server now also runs this same mechanism to catch up any
        reconnecting member whose KeyManager is empty (see server/
        client_handler.py::_ensure_group_keys_current_for_reconnecting_
        user()). Mirrors client/session.py::
        handle_group_key_rotation_required() exactly: reuse an
        existing stored key for this exact epoch rather than
        generating a new one (KeyManager.store_key() never overwrites),
        so redelivering to a still-missing member is always the SAME
        key every other recipient already has."""

        conversation_id = packet["conversation_id"]
        epoch = packet["epoch"]
        recipients = [member for member in packet.get("members", []) if member != self.username]

        if self.key_manager.has_key(conversation_id, epoch=epoch):
            group_key = self.key_manager.get_key(conversation_id, epoch=epoch)
        else:
            group_key = os.urandom(32)
            self._store_conversation_key(conversation_id, group_key, epoch)

        self._distribute_group_key(conversation_id, group_key, epoch, recipients)

        send_message(self.client_socket, create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=epoch,
        ))
        self.logger.info(f"Rotated group key for {conversation_id} to epoch {epoch} ({recipients}).")

    def _handle_group_key_distribution(self, packet):
        if packet.get("recipient") != self.username:
            return

        sender = packet.get("sender")
        conversation_id = packet.get("conversation_id")
        encapsulation = packet.get("encapsulation")
        wrapped_key = packet.get("wrapped_key")
        epoch = packet.get("epoch") or 1

        if not conversation_id or not sender:
            self._report_security_rejection("malformed_packet", sender, conversation_id)
            return

        if not self._peer_key_is_verified(sender):
            # See _pending_key_requests_awaiting_verification's own
            # comment: remembered so confirm_peer_verified() can ask
            # ``sender`` to redeliver this once this client verifies
            # them, instead of silently requiring a manual reconnect.
            self._pending_key_requests_awaiting_verification.setdefault(
                sender, []
            ).append((conversation_id, epoch))
            reason = "key_changed" if self.get_peer_verification_state(sender) == PEER_KEY_STATE_CHANGED else (
                "unknown_sender" if sender not in self.peers else "unverified_sender"
            )
            self._report_security_rejection(reason, sender, conversation_id)
            return

        peer = self.peers[sender]
        signature_b64 = packet.get("group_key_signature")
        if not signature_b64:
            self._report_security_rejection("missing_signature", sender, conversation_id)
            return

        try:
            signature = base64.b64decode(signature_b64, validate=True)
            verified = verify_group_key_payload(
                sender, conversation_id, self.username, encapsulation, wrapped_key, epoch, signature, peer["signing_key"],
            )
        except (TypeError, ValueError):
            self._report_security_rejection("malformed_packet", sender, conversation_id)
            return

        if not verified:
            self._report_security_rejection("invalid_signature", sender, conversation_id)
            return

        try:
            group_key = self.key_manager.unwrap_received_key(encapsulation, wrapped_key)
        except (ValueError, TypeError):
            self._report_security_rejection("decryption_failure", sender, conversation_id)
            return

        self._store_conversation_key(conversation_id, group_key, epoch)
        if conversation_id not in self.groups:
            self.direct_conversation_ids[sender] = conversation_id
        self.logger.info(f"Installed a group/session key for {sender} (epoch {epoch}).")

    # ==========================================================
    # Direct-key desync recovery (Phase 19.10 fix -- mirrors client/
    # session.py::handle_direct_key_recovery_available()/
    # handle_direct_key_redelivery_required() exactly; previously
    # missing from this module entirely, which was the confirmed root
    # cause of the physically-reproduced "sender has key, recipient
    # never gets it" bug for both direct and group messaging (the
    # group half is _handle_group_key_rotation_required() above).
    #
    # Root cause: establish_session_key()/_create_and_distribute_
    # group_key() always store the newly generated key locally FIRST,
    # then attempt delivery only if the recipient's public key is
    # already cached -- if it is not, delivery is silently skipped
    # with no error and no retry from the sender's side. The server
    # has always had a matching recovery mechanism for this (BUG 4 --
    # Fix B in client/session.py's own history): on every login, it
    # announces which of a user's direct conversations might need
    # recovery (direct_key_recovery_available), the client asks back
    # for exactly the epochs it's missing (direct_key_recovery_
    # request), and the server relays that ask to a currently-
    # connected partner as direct_key_redelivery_required. The desktop
    # client has always implemented both halves of this; mobile/
    # session.py never did, so the mechanism the server already runs
    # on every single login was a complete no-op for every mobile
    # client. No server or protocol change is needed -- only these two
    # handlers were missing.
    # ==========================================================

    def handle_direct_key_recovery_available(self, packet):
        """The server has listed which direct conversations this
        client can read and which key epochs their stored messages
        are encrypted under. Ask for the epochs this client is
        actually missing -- and only those, so a routine reconnect
        that lost nothing costs zero follow-up packets."""

        conversations = packet.get("conversations") or []

        for entry in conversations:
            conversation_id = entry.get("conversation_id")
            epochs = entry.get("epochs") or []
            if not conversation_id:
                continue

            missing = [epoch for epoch in epochs if not self.key_manager.has_key(conversation_id, epoch=epoch)]
            if not missing:
                continue

            send_message(self.client_socket, create_direct_key_recovery_request_packet(
                conversation_id=conversation_id, epochs=missing,
            ))
            self.logger.info(f"Requested recovery of {conversation_id} epochs {missing}.")

    def _handle_direct_key_redelivery_required(self, packet):
        """A direct partner has reconnected missing a key epoch this
        client may still hold, and the server has asked this client to
        hand them a wrapped copy. Redelivers an EXISTING key or does
        nothing at all -- never invents one (a freshly generated key
        cannot decrypt ciphertext encrypted under the old one). Wire
        shape is the same group_key_distribution packet/handler
        initial establishment and group keys already use."""

        conversation_id = packet.get("conversation_id")
        epoch = packet.get("epoch") or 1
        recipient = packet.get("recipient")

        if not conversation_id or not recipient:
            return

        if not self.key_manager.has_key(conversation_id, epoch=epoch):
            self.logger.info(f"Cannot redeliver key for {conversation_id} epoch {epoch} to {recipient}: this device does not hold that epoch.")
            return

        if self.key_manager.get_public_key(recipient) is not None and not self._peer_key_is_verified(recipient):
            self.logger.warning(
                f"SECURITY: refusing to redeliver key for {conversation_id} epoch {epoch} to {recipient}: "
                f"peer is not verified ({self.get_peer_verification_state(recipient)})."
            )
            self._declined_redeliveries_awaiting_verification.setdefault(
                recipient, []
            ).append((conversation_id, epoch))
            return

        session_key = self.key_manager.get_key(conversation_id, epoch=epoch)

        try:
            encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(recipient, session_key)
        except (ValueError, TypeError) as error:
            self.logger.warning(f"Could not wrap key for {recipient} ({conversation_id} epoch {epoch}): {error}")
            return

        signature = sign_group_key_payload(
            self.key_manager.ml_dsa, self.username, conversation_id, recipient, encapsulation, wrapped_key, epoch,
        )
        send_message(self.client_socket, create_group_key_distribution_packet(
            sender=self.username, conversation_id=conversation_id, recipient=recipient,
            encapsulation=encapsulation, wrapped_key=wrapped_key, epoch=epoch,
            group_key_signature=base64.b64encode(signature).decode("ascii"),
        ))
        self.logger.info(f"Redelivered direct key for {conversation_id} epoch {epoch} to {recipient}.")

    # ==========================================================
    # Messaging (mirrors WebClientSession.sendMessage()/
    # sendGroupMessage()/sendAttachment()/_handleChat() exactly).
    # ==========================================================

    def send_message(self, peer_username, text, reply_to_message_id=None, client_message_id=None):
        conversation_id = self.open_direct_conversation(peer_username)
        if not self._has_conversation_key(conversation_id):
            raise RuntimeError("No session key established for this conversation yet.")
        return self._send_payload(
            peer_username, None, conversation_id, PayloadType.TEXT, text, None,
            reply_to_message_id=reply_to_message_id, client_message_id=client_message_id,
        )

    def send_group_message(self, conversation_id, text, reply_to_message_id=None, client_message_id=None):
        if not self._has_conversation_key(conversation_id):
            raise RuntimeError("No group key established for this conversation yet.")
        return self._send_payload(
            None, conversation_id, conversation_id, PayloadType.TEXT, text, None,
            reply_to_message_id=reply_to_message_id, client_message_id=client_message_id,
        )

    def send_attachment(self, peer_username, conversation_id, data_bytes, filename, mime_type):
        """``peer_username`` XOR ``conversation_id`` -- exactly one
        addressing mode, mirroring send_message()/send_group_message()
        above and create_payload_packet()'s own contract."""

        if len(data_bytes) > MAX_ATTACHMENT_SIZE_BYTES:
            raise ValueError(f"Attachment exceeds the {MAX_ATTACHMENT_SIZE_BYTES}-byte limit.")

        payload_type = classify_attachment(filename)
        content_metadata = {"filename": filename, "mime_type": mime_type, "size_bytes": len(data_bytes)}

        if conversation_id is not None:
            if not self._has_conversation_key(conversation_id):
                raise RuntimeError("No group key established for this conversation yet.")
            return self._send_payload(None, conversation_id, conversation_id, payload_type, data_bytes, content_metadata)

        real_conversation_id = self.open_direct_conversation(peer_username)
        if not self._has_conversation_key(real_conversation_id):
            raise RuntimeError("No session key established for this conversation yet.")
        return self._send_payload(peer_username, None, real_conversation_id, payload_type, data_bytes, content_metadata)

    def _send_payload(
        self, receiver, addressed_conversation_id, key_conversation_id, payload_type, content, content_metadata,
        reply_to_message_id=None, client_message_id=None,
    ):
        session_info = self._conversation_key_info(key_conversation_id)
        aes = AESCipher(session_info["key"])
        envelope = self._adapter_for(payload_type).encrypt(content, aes, content_metadata=content_metadata)

        message_signature = sign_message_payload(
            self.key_manager.ml_dsa, self.username, receiver, addressed_conversation_id,
            envelope.payload_type, envelope.ciphertext, envelope.content_metadata, session_info["epoch"],
        )
        # Phase 19.24 -- Message Retry idempotency: a caller-supplied
        # id (a retry, reusing the value from its own failed attempt)
        # or, if none given, a fresh one generated here -- mirrors
        # client/session.py::_send_encrypted_payload()'s identical
        # contract exactly.
        client_message_id = client_message_id or str(uuid.uuid4())
        packet = create_payload_packet(
            sender=self.username, envelope=envelope, receiver=receiver, conversation_id=addressed_conversation_id,
            epoch=session_info["epoch"], message_signature=base64.b64encode(message_signature).decode("ascii"),
            sender_device_id=self.device_id,
            reply_to_message_id=reply_to_message_id, client_message_id=client_message_id,
        )
        send_message(self.client_socket, packet)
        return client_message_id

    # ==================================================================
    # Phase 19.24 -- Message Lifecycle Events (edit/delete/reactions).
    # Mirrors client/session.py's identical methods exactly -- same
    # scope (edit is TEXT-only), same authorization model (server-
    # enforced, never merely a client-side choice not to offer a
    # button).
    # ==================================================================

    def edit_message(self, conversation_id, message_id, new_text, expected_edit_version):
        session_info = self._conversation_key_info(conversation_id)
        if session_info is None:
            raise RuntimeError(f"No encryption key for conversation {conversation_id}")

        aes = AESCipher(session_info["key"])
        envelope = self._adapter_for(PayloadType.TEXT).encrypt(new_text, aes, content_metadata=None)

        message_signature = sign_message_payload(
            self.key_manager.ml_dsa, self.username, None, conversation_id,
            envelope.payload_type, envelope.ciphertext, envelope.content_metadata, session_info["epoch"],
            purpose=EDIT_PAYLOAD_PURPOSE,
        )

        send_message(
            self.client_socket,
            create_message_edit_packet(
                message_id=message_id, envelope=envelope, epoch=session_info["epoch"],
                message_signature=base64.b64encode(message_signature).decode("ascii"),
                expected_edit_version=expected_edit_version,
            ),
        )

    def delete_message_for_me(self, message_id):
        send_message(self.client_socket, create_message_delete_for_me_packet(message_id=message_id))

    def delete_message_for_everyone(self, message_id):
        send_message(self.client_socket, create_message_delete_for_everyone_packet(message_id=message_id))

    def add_reaction(self, conversation_id, message_id, reaction):
        session_info = self._conversation_key_info(conversation_id)
        if session_info is None:
            raise RuntimeError(f"No encryption key for conversation {conversation_id}")

        aes = AESCipher(session_info["key"])
        envelope = self._adapter_for(PayloadType.REACTION).encrypt(reaction, aes, content_metadata=None)

        message_signature = sign_message_payload(
            self.key_manager.ml_dsa, self.username, None, conversation_id,
            envelope.payload_type, envelope.ciphertext, envelope.content_metadata, session_info["epoch"],
            purpose=REACTION_PAYLOAD_PURPOSE,
        )

        send_message(
            self.client_socket,
            create_reaction_add_packet(
                message_id=message_id, envelope=envelope, epoch=session_info["epoch"],
                message_signature=base64.b64encode(message_signature).decode("ascii"),
            ),
        )

    def remove_reaction(self, message_id):
        send_message(self.client_socket, create_reaction_remove_packet(message_id=message_id))

    def pin_message(self, message_id):
        """Pin ``message_id`` for every member of its conversation
        (Phase 19.24 -- Pinned Messages). Mirrors client/session.py::
        pin_message() exactly -- no content to encrypt, see database/
        models/message.py::pinned_at's own trust-model docstring."""

        send_message(self.client_socket, create_message_pin_packet(message_id=message_id))

    def unpin_message(self, message_id):
        """Unpin ``message_id``, if currently pinned. Idempotent."""

        send_message(self.client_socket, create_message_unpin_packet(message_id=message_id))

    def forward_message(self, peer_username, conversation_id, payload_type, content, content_metadata=None):
        """Forward already-decrypted local content as a genuinely NEW,
        independently encrypted message to a different recipient/
        conversation -- mirrors client/session.py::forward_message()
        exactly. ``peer_username`` XOR ``conversation_id``, exactly
        like send_message()/send_group_message()/send_attachment()."""

        forward_metadata = dict(content_metadata or {})
        forward_metadata["forwarded"] = True

        if conversation_id is not None:
            if not self._has_conversation_key(conversation_id):
                raise RuntimeError("No group key established for this conversation yet.")
            return self._send_payload(
                None, conversation_id, conversation_id, payload_type, content, forward_metadata,
            )

        real_conversation_id = self.open_direct_conversation(peer_username)
        if not self._has_conversation_key(real_conversation_id):
            raise RuntimeError("No session key established for this conversation yet.")
        return self._send_payload(
            peer_username, None, real_conversation_id, payload_type, content, forward_metadata,
        )

    def _decrypt_lifecycle_event_content(self, conversation_id, payload_type, ciphertext, epoch):
        """Mirrors client/session.py's identical method exactly."""

        key_bytes = self.key_manager.get_key(conversation_id, epoch=epoch or 1)
        if key_bytes is None:
            return _UNDECRYPTABLE_PLACEHOLDER
        try:
            envelope = PayloadEnvelope(payload_type=payload_type, ciphertext=ciphertext, content_metadata={})
            return self._adapter_for(payload_type).decrypt(envelope, AESCipher(key_bytes))
        except Exception:  # noqa: BLE001
            return _UNDECRYPTABLE_PLACEHOLDER

    def _verify_lifecycle_event_signature(
        self, actor, conversation_id, payload_type, ciphertext, content_metadata, epoch,
        signature_b64, purpose, event_label,
    ):
        """Mirrors client/session.py's identical method, adapted to
        mobile's simpler peer-signing-key lookup (self.peers[actor]
        ["signing_key"] -- the same source _handle_chat() already
        trusts for ordinary messages, never anything from the packet
        itself)."""

        if not signature_b64:
            self.logger.warning(
                f"SECURITY: rejected unsigned {event_label} claiming to be from {actor}."
            )
            return False

        # Phase 19.24 (continued) -- BUG FIX: the server broadcasts an
        # edit/reaction notification to EVERY conversation member,
        # including the ORIGINATING actor themselves (server/client_
        # handler.py::_broadcast_to_conversation_members() is never
        # given exclude_socket for these -- see handle_message_edit()/
        # handle_reaction_add()'s own docstrings), so THIS client's own
        # just-sent edit/reaction always echoes back to itself too --
        # exactly what lets a sender's own bubble update without a
        # history reload. self.peers, however, only ever caches OTHER
        # accounts' observed identities (nobody "observes" their own
        # public key over the wire), so a naive self.peers.get(actor)
        # lookup for actor == self.username always misses, incorrectly
        # rejecting a sender's OWN, perfectly genuine signature as
        # unverifiable. Resolved from this session's own KeyManager
        # instead for that one case -- mirrors load_history()'s
        # identical is_own branch just above, and is exactly as safe:
        # this is still cryptographic verification against a real
        # public key this client unquestionably controls the private
        # half of, never a bypass.
        if actor == self.username:
            signing_public_key = self.key_manager.ml_dsa.export_public_key()
        else:
            peer = self.peers.get(actor)
            signing_public_key = peer.get("signing_key") if peer else None

        if signing_public_key is None:
            self.logger.warning(
                f"SECURITY: rejected {event_label} from {actor}: no ML-DSA "
                f"identity observed for them."
            )
            return False

        try:
            signature = base64.b64decode(signature_b64, validate=True)
            verified = verify_message_payload(
                actor, None, conversation_id, payload_type, ciphertext,
                content_metadata, epoch, signature, signing_public_key,
                purpose=purpose,
            )
        except (TypeError, ValueError) as error:
            self.logger.warning(f"SECURITY: rejected malformed {event_label} from {actor}: {error}")
            return False

        if not verified:
            self.logger.warning(f"SECURITY: signature verification FAILED for {event_label} from {actor}.")
            return False

        return True

    def _handle_message_edited(self, packet):
        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")
        ciphertext = packet.get("ciphertext")
        editor = packet.get("editor") or ""
        if not message_id or not conversation_id or not ciphertext or not editor:
            return
        if not self._verify_lifecycle_event_signature(
            editor, conversation_id, PayloadType.TEXT, ciphertext,
            packet.get("content_metadata"), packet.get("epoch"),
            packet.get("message_signature"), EDIT_PAYLOAD_PURPOSE, "message edit",
        ):
            return
        new_text = self._decrypt_lifecycle_event_content(
            conversation_id, PayloadType.TEXT, ciphertext, packet.get("epoch"),
        )
        self.message_edited_received.emit(
            conversation_id, message_id, new_text,
            editor, packet.get("edited_at") or "",
            int(packet.get("edit_version") or 0),
        )

    def _handle_message_deleted(self, packet):
        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")
        if not message_id or not conversation_id:
            return
        self.message_deleted_received.emit(
            conversation_id, message_id,
            packet.get("deleted_by") or "", packet.get("deleted_at") or "",
        )

    def _handle_reaction_updated(self, packet):
        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")
        action = packet.get("action")
        actor = packet.get("actor") or ""
        if not message_id or not conversation_id or action not in ("add", "remove") or not actor:
            return
        reaction = ""
        if action == "add":
            ciphertext = packet.get("ciphertext")
            if not ciphertext:
                return
            if not self._verify_lifecycle_event_signature(
                actor, conversation_id, PayloadType.REACTION, ciphertext,
                None, packet.get("epoch"),
                packet.get("message_signature"), REACTION_PAYLOAD_PURPOSE, "reaction",
            ):
                return
            reaction = self._decrypt_lifecycle_event_content(
                conversation_id, PayloadType.REACTION, ciphertext, packet.get("epoch"),
            )
        self.reaction_updated_received.emit(
            conversation_id, message_id, actor, action, reaction,
        )

    def _handle_message_pinned(self, packet):
        """Mirrors client/session.py::handle_message_pinned() exactly
        -- no decryption/verification needed (see message_pinned_
        received's own trust-model note above)."""

        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")
        pinned_by = packet.get("pinned_by") or ""
        if not message_id or not conversation_id or not pinned_by:
            return
        self.message_pinned_received.emit(
            conversation_id, message_id, pinned_by, packet.get("pinned_at") or "",
        )

    def _handle_message_unpinned(self, packet):
        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")
        unpinned_by = packet.get("unpinned_by") or ""
        if not message_id or not conversation_id or not unpinned_by:
            return
        self.message_unpinned_received.emit(conversation_id, message_id, unpinned_by)

    def _handle_chat(self, packet):
        sender = packet.get("sender")
        signature_b64 = packet.get("message_signature")
        if not signature_b64:
            self._report_security_rejection("missing_signature", sender, packet.get("conversation_id"))
            return

        peer = self.peers.get(sender)
        if not peer:
            self._report_security_rejection("unknown_sender", sender, packet.get("conversation_id"))
            return

        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (TypeError, ValueError):
            self._report_security_rejection("malformed_packet", sender, packet.get("conversation_id"))
            return

        receiver = packet.get("receiver")
        conversation_id = packet.get("conversation_id")
        ciphertext = packet.get("message")
        payload_type = packet.get("payload_type") or PayloadType.TEXT
        content_metadata = packet.get("content_metadata") or {}
        epoch = packet.get("epoch") or 1

        verified = verify_message_payload(
            sender, receiver, conversation_id, payload_type, ciphertext, content_metadata, epoch, signature, peer["signing_key"],
        )
        if not verified:
            self._report_security_rejection("invalid_signature", sender, conversation_id)
            return

        key_conversation_id = conversation_id or packet.get("direct_conversation_id") or self.direct_conversation_ids.get(sender)
        key_bytes = self.key_manager.get_key(key_conversation_id, epoch=epoch) if key_conversation_id else None
        if key_bytes is None:
            self._report_security_rejection("decryption_failure", sender, conversation_id)
            return
        session_info = {"key": key_bytes, "epoch": epoch}

        identity_key = conversation_id or sender

        message_id = packet.get("message_id")
        if message_id:
            seen = self._rendered_message_ids.setdefault(key_conversation_id, set())
            if message_id in seen:
                return
            seen.add(message_id)

        try:
            envelope = PayloadEnvelope(payload_type=payload_type, ciphertext=ciphertext, content_metadata=content_metadata)
            decoded = self._adapter_for(payload_type).decrypt(envelope, AESCipher(session_info["key"]))
        except Exception:
            self._report_security_rejection("decryption_failure", sender, conversation_id)
            return

        # Phase 19.23 -- Issue 3: trailing None (never a real status --
        # a status only ever comes from history's own delivery_status
        # field, see load_history() above) keeps every emit() call for
        # these two signals at the same, fixed argument count
        # regardless of call site, so a connected callback need not
        # special-case which one it was called from.
        if payload_type == PayloadType.TEXT:
            self.message_received.emit(identity_key, sender, decoded, False, None)
        else:
            self.payload_message_received.emit(identity_key, sender, payload_type, decoded, content_metadata, False, None)

        # Phase 19.24 (continued) -- see message_id_received's/message_
        # lifecycle_state_received's own declarations. A brand-new live
        # message cannot already be edited/deleted/reacted-to, so those
        # fields are always the "never happened yet" defaults here --
        # reply_to_message_id is the one piece of lifecycle state a
        # live "chat" packet CAN carry (server/client_handler.py's
        # relay branch forwards the sender's original packet, reply_to_
        # message_id included, unchanged, before merely adding
        # message_id to it).
        if message_id:
            self.message_id_received.emit(identity_key, message_id)
            self.message_lifecycle_state_received.emit(
                identity_key, message_id, packet.get("reply_to_message_id"), False, 0, [],
                # Phase 19.24 -- Pinned Messages: same "never happened
                # yet" defaults as is_deleted/edit_version/reactions
                # just above -- a brand-new live message cannot already
                # be pinned.
                False, None,
            )

    # ==========================================================
    # Conversation list (Phase 19.13 -- mobile never had an
    # equivalent of client/session.py::load_conversations(), which is
    # the confirmed root cause of "chat list is empty after logout
    # then login again": direct_conversation_ids/groups are plain
    # in-memory dicts on this session object, populated ONLY as a
    # side effect of live traffic during the CURRENT process (opening
    # a chat, an incoming message, a group-create/add-members
    # result). A fresh login is a fresh MobileClientSession with both
    # dicts empty, and nothing ever repopulated them from the server
    # -- so a real, already-populated account looked exactly like a
    # brand new one until new live messages arrived. Mirrors client/
    # session.py::load_conversations() exactly: same request packet,
    # same response shape, reusing the server's existing
    # conversation_list_request/handle_conversation_list_request()
    # (no server change). Adapted to mobile's simpler data model --
    # direct_conversation_ids/groups dicts instead of a
    # ConversationStore object -- and returns a plain list the caller
    # (mobile/app.py's ChatScreen) uses to seed its own preview/
    # unread state, since mobile owns that presentation state itself
    # rather than through a shared store class.
    # ==========================================================

    def load_conversations(self):
        """
        Populate direct_conversation_ids/groups from the server's
        authoritative list (BUG -- Mobile Conversation Persistence).
        Call once, right after login/start_receiver() -- exactly
        where client/session.py's own load_conversations() is called
        at chat startup.

        Returns a list of plain dicts, one per conversation:
        {conversation_id, is_group, name, last_message (decrypted
        best-effort, or None), timestamp, unread_count} -- everything
        mobile/app.py's ChatScreen needs to seed self.conversations
        without this method needing to know anything about Kivy
        widgets.
        """

        response = self.send_request(create_conversation_list_request_packet())

        conversations = []

        for conversation in response.get("conversations") or []:

            conversation_id = conversation["conversation_id"]
            is_group = bool(conversation.get("is_group"))
            participants = conversation.get("participants") or []

            if is_group:
                name = conversation.get("group_name") or "Group"
                # Phase 19.16 -- Blocker 2: get_conversation_previews_
                # for_user()'s own "participants" field is documented
                # (database/repositories/conversation_repository.py)
                # as the OTHER participant(s) -- correct for a direct
                # chat's display name, but reused unchanged for groups
                # here, so a login-time refresh silently dropped this
                # user from their own group's roster while every LIVE
                # group event (_handle_group_members_added/_member_left/
                # _handle_group_create_result) already sends the full,
                # self-inclusive roster. Normalizing here, at the one
                # place that reads the self-exclusive field, keeps
                # every consumer of self.groups[...]["members"]
                # (Groups list, chat header, Members dialog) consistent
                # without touching the shared server query at all.
                members = list(participants)
                if self.username and self.username not in members:
                    members.append(self.username)
                self.groups[conversation_id] = {
                    "name": name, "members": members,
                    "admin": conversation.get("admin_username"),
                }
                identity_key = conversation_id
            else:
                partner_username = participants[0] if participants else None
                if partner_username is None:
                    continue
                self.direct_conversation_ids[partner_username] = conversation_id
                name = partner_username
                identity_key = partner_username

            last_message = None
            timestamp = None
            latest = conversation.get("latest_message")

            if latest is not None:
                timestamp = latest.get("timestamp")
                if (latest.get("payload_type") or PayloadType.TEXT) == PayloadType.TEXT:
                    last_message = self._decrypt_preview_message(
                        conversation_id, latest.get("ciphertext"), epoch=latest.get("epoch") or 1,
                    )
                else:
                    last_message = "[Attachment]"

            conversations.append({
                "conversation_id": conversation_id,
                "identity_key": identity_key,
                "is_group": is_group,
                "name": name,
                "participants": participants,
                "last_message": last_message,
                "timestamp": timestamp,
                "unread_count": conversation.get("unread_count") or 0,
            })

        return conversations

    def _decrypt_preview_message(self, conversation_id, ciphertext, epoch=1):
        """
        Best-effort AES decryption of a stored historical message, for
        a sidebar preview only -- mirrors client/session.py::
        _decrypt_history_message()'s reuse-cached-key/never-raise
        contract, but deliberately NOT its placeholder text: an
        undecryptable message here returns "" (Phase 19 manual
        acceptance defect fix -- a real physical-device test found
        _UNDECRYPTABLE_PLACEHOLDER's internal diagnostic string
        ("Message unavailable (encrypted in a previous session)")
        leaking into the chat-list sidebar preview row, visually
        overlapping the unread-count indicator). This is the ONLY
        caller of this method (see load_conversations() above) --
        load_history()'s own per-message rendering (the real, opened-
        conversation message list) never calls this at all; it skips
        an undecryptable message outright rather than showing any
        placeholder text (see load_history()'s own "continue" on a
        decryption failure), so genuine history recovery/display is
        completely unaffected by this change. An empty string flows
        into mobile/app.py's existing "No messages yet" (direct) /
        "N member(s)" (group) fallback exactly like a conversation
        with no messages at all -- no new UI text invented.
        """

        session_key = self.key_manager.get_key(conversation_id, epoch=epoch)

        if session_key is None or ciphertext is None:
            return ""

        try:
            envelope = PayloadEnvelope(payload_type=PayloadType.TEXT, ciphertext=ciphertext, content_metadata={})
            return self._adapter_for(PayloadType.TEXT).decrypt(envelope, AESCipher(session_key))
        except Exception:
            return ""

    # ==========================================================
    # Message history (mirrors WebClientSession.loadHistory() exactly,
    # including Step 6/7's dedup + blob-download closure-audit fixes).
    # ==========================================================

    def forget_rendered_history(self, conversation_id):
        """
        Clears this ONE conversation's render-dedup memory (Phase
        19.17C). mobile/app.py::open_chat() rebuilds its message
        widget from scratch every time a conversation is opened --
        including reopening one already visited earlier in this same
        app run -- and calls this right before its own load_history()
        call. Without it, messages this session already emitted once
        (into a widget that no longer exists, discarded when the user
        left the chat) would be silently skipped as "already
        rendered" by the dedup check below, leaving the new widget
        empty -- messages that were never actually gone, just never
        re-shown. Scoped to one conversation_id so a conversation NOT
        being reopened keeps its own genuine same-open live+history
        overlap protection intact.
        """

        self._rendered_message_ids.pop(conversation_id, None)

    def load_history(self, conversation_id, is_group=False):
        result = self.send_request(create_message_history_request_packet(conversation_id=conversation_id, is_group=is_group))
        if result.get("error"):
            raise ValueError(result["error"])

        seen = self._rendered_message_ids.setdefault(conversation_id, set())

        loaded_count = 0
        for entry in result.get("messages") or []:
            message_id = entry.get("message_id")
            if message_id and message_id in seen:
                continue

            payload_type = entry.get("payload_type") or PayloadType.TEXT
            is_blob_stored = payload_type in BLOB_STORAGE_PAYLOAD_TYPES

            # Phase 19.24 (continued) -- Message Lifecycle Events: a
            # real delete-for-everyone has ALREADY nulled ciphertext/
            # blob_ref/message_signature server-side (see server/
            # client_handler.py::handle_message_delete_for_everyone()),
            # so there is genuinely nothing left to fetch/verify/
            # decrypt -- checked first, before any of that is even
            # attempted, exactly like client/session.py::load_
            # conversation_history()'s identical guard for Desktop.
            # Rendered as an empty TEXT row; the ChatScreen slot
            # (mobile/app.py) renders "Message deleted" for ANY payload
            # type once message_lifecycle_state_received's is_deleted
            # flag says so, regardless of what it originally was.
            is_deleted = bool(entry.get("deleted_at"))

            if is_deleted:
                decoded = ""
                is_blob_stored = False
                payload_type = PayloadType.TEXT
                content_metadata = {}
            else:
                ciphertext = entry.get("ciphertext")

                if is_blob_stored:
                    if not entry.get("blob_ref"):
                        continue
                    blob_result = self.send_request(create_blob_download_request_packet(message_id=message_id))
                    if blob_result.get("error") or not blob_result.get("ciphertext"):
                        continue
                    ciphertext = blob_result["ciphertext"]

                signing_key = self.key_manager.ml_dsa.export_public_key() if entry.get("is_own") else (
                    self.peers.get(entry.get("sender"), {}).get("signing_key")
                )
                if not signing_key or not entry.get("message_signature"):
                    continue

                # BUG FIX (continued Phase 19.24): mirrors client/
                # session.py::_verify_history_message_signature()'s
                # identical fix -- an EDITED message's stored message_
                # signature is the EDIT's own signature (EDIT_PAYLOAD_
                # PURPOSE, addressed as (receiver=None, conversation_id=
                # <real conversation_id>) -- see edit_message()'s own
                # docstring), not the original send's. Verifying it
                # under the ordinary purpose/addressing always failed,
                # silently dropping the row (`continue`, never even a
                # placeholder) from every reload after the first edit.
                history_edit_version = entry.get("edit_version") or 0

                if history_edit_version:
                    verify_receiver = None
                    verify_conversation_id = conversation_id
                    verify_purpose = EDIT_PAYLOAD_PURPOSE
                else:
                    verify_receiver = entry.get("receiver")
                    verify_conversation_id = entry.get("conversation_id")
                    verify_purpose = MESSAGE_PAYLOAD_PURPOSE

                try:
                    signature = base64.b64decode(entry["message_signature"], validate=True)
                    verified = verify_message_payload(
                        entry.get("sender"), verify_receiver, verify_conversation_id, payload_type,
                        ciphertext, entry.get("content_metadata"), entry.get("epoch") or 1, signature, signing_key,
                        purpose=verify_purpose,
                    )
                except (TypeError, ValueError):
                    verified = False
                if not verified:
                    continue

                entry_epoch = entry.get("epoch") or 1
                key_bytes = self.key_manager.get_key(conversation_id, epoch=entry_epoch)
                if key_bytes is None:
                    continue

                try:
                    envelope = PayloadEnvelope(payload_type=payload_type, ciphertext=ciphertext, content_metadata=entry.get("content_metadata") or {})
                    decoded = self._adapter_for(payload_type).decrypt(envelope, AESCipher(key_bytes))
                except Exception:
                    continue

                content_metadata = entry.get("content_metadata") or {}

            if message_id:
                seen.add(message_id)

            # Phase 19.23 -- Issue 3: carry this own message's tick
            # state (Sent/Delivered/Read) through history reload too,
            # not just a live message_delivered/read_receipt packet
            # this client might have missed entirely (e.g. it was
            # offline at the time). Uses the server's additive
            # "delivery_status" field exactly like Desktop's
            # load_history() now does (gui/chat_window.py) -- None for
            # a message this user did not send, or for one with no
            # receipt data at all (legacy/pre-C2).
            status = None
            if entry.get("is_own"):
                read_status = entry.get("read_status")
                if read_status is True:
                    status = "Read"
                elif read_status is False:
                    status = "Delivered" if entry.get("delivery_status") == "delivered" else "Sent"

            if is_blob_stored:
                self.payload_message_received.emit(conversation_id, entry.get("sender"), payload_type, decoded, content_metadata, True, status)
            else:
                self.message_received.emit(conversation_id, entry.get("sender"), decoded, True, status)

            # Phase 19.24 (continued) -- see message_id_received's/
            # message_lifecycle_state_received's own declarations.
            # Reactions are verified/decrypted the same way _handle_
            # reaction_updated()'s "add" case does for a LIVE one --
            # history recovery applies the identical receiver-side
            # trust check, never merely trusting the server relayed the
            # right ciphertext/reactor pairing. A reaction that fails
            # verification is silently dropped, not fatal to the rest
            # of history.
            if message_id:

                reactions = []

                if not is_deleted:
                    for reaction_entry in entry.get("reactions") or []:
                        reactor = reaction_entry.get("user") or ""
                        reaction_ciphertext = reaction_entry.get("ciphertext")
                        if not reactor or not reaction_ciphertext:
                            continue
                        if not self._verify_lifecycle_event_signature(
                            reactor, conversation_id, PayloadType.REACTION,
                            reaction_ciphertext, None, reaction_entry.get("epoch"),
                            reaction_entry.get("message_signature"), REACTION_PAYLOAD_PURPOSE,
                            "reaction (history)",
                        ):
                            continue
                        reactions.append({
                            "user": reactor,
                            "reaction": self._decrypt_lifecycle_event_content(
                                conversation_id, PayloadType.REACTION,
                                reaction_ciphertext, reaction_entry.get("epoch"),
                            ),
                        })

                self.message_id_received.emit(conversation_id, message_id)
                self.message_lifecycle_state_received.emit(
                    conversation_id, message_id, entry.get("reply_to_message_id"),
                    is_deleted, int(entry.get("edit_version") or 0), reactions,
                    # Phase 19.24 -- Pinned Messages: recovered on every
                    # history load exactly like edit/delete/reaction
                    # state above.
                    bool(entry.get("pinned_at")), entry.get("pinned_by"),
                )

            loaded_count += 1

        self.logger.info(f"Loaded {loaded_count} historical message(s) for {conversation_id}.")
        return loaded_count

    # ==========================================================
    # Read receipts (deliberately unsigned -- see docs/architecture/
    # web_interoperability.md's Phase 18.5 Step 8 for the full,
    # codebase-wide reasoning this mirrors unchanged).
    # ==========================================================

    def mark_read(self, conversation_id):
        if not conversation_id:
            return
        send_message(self.client_socket, create_read_receipt_packet(conversation_id=conversation_id))

    def send_typing_indicator(self, conversation_id, is_typing):
        """
        Tell the server this account is (or has just stopped) typing
        in ``conversation_id`` (Phase 19.24 -- Typing Indicator).
        Fire-and-forget, mirrors client/session.py's identical method
        exactly -- see its own docstring for the full debounce-
        ownership and safe-after-disconnect contract (self.connected
        guards the identical race there: a timer/Clock callback that
        legitimately can still fire after this session has already
        disconnected).
        """

        if not conversation_id or not self.connected:
            return

        send_message(
            self.client_socket,
            create_typing_indicator_packet(conversation_id=conversation_id, is_typing=is_typing),
        )

    # ==========================================================
    # Multi-device identity (mirrors WebClientSession's Step 8 methods
    # exactly -- same packets, same canonical payloads, imported
    # directly rather than ported).
    # ==========================================================

    def enroll_device(self, device_name=None, platform=None):
        newly_resolved = self.device_id is None
        if newly_resolved:
            self.device_id = str(uuid.uuid4())
            if self.key_store is not None:
                try:
                    self.key_store.save_device_id(self.device_id)
                except (KeyStoreError, OSError):
                    pass
            if self.client_socket is not None:
                self.send_public_key()

        kem_public_key_wire = self.key_manager.public_key.decode("utf-8")
        ml_dsa_public_key = self.key_manager.ml_dsa.export_public_key()

        payload = canonical_device_enrollment_payload(
            self.username, self.device_id, kem_public_key_wire, ml_dsa_public_key, device_name, platform,
        )
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)

        return self.send_request(create_device_enroll_request_packet(
            device_id=self.device_id, device_name=device_name, platform=platform,
            kem_public_key=kem_public_key_wire,
            ml_dsa_public_key=base64.b64encode(ml_dsa_public_key).decode("ascii"),
            enrollment_signature=base64.b64encode(signature).decode("ascii"),
        ))

    def bind_device_session(self):
        if self.device_id is None:
            raise ValueError("No device_id -- call enroll_device() first.")
        session_nonce = uuid.uuid4().hex
        payload = canonical_device_session_binding_payload(self.username, self.device_id, session_nonce)
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)
        return self.send_request(create_device_session_bind_packet(
            device_id=self.device_id, session_nonce=session_nonce,
            binding_signature=base64.b64encode(signature).decode("ascii"),
        ))

    def list_devices(self):
        response = self.send_request(create_device_list_request_packet())
        return response.get("devices", [])

    def observe_device_peer_identity(self, device_id, kem_public_key_wire, ml_dsa_public_key_b64):
        ml_dsa_public_key = base64.b64decode(ml_dsa_public_key_b64)
        peer = self._upsert_peer_observation(device_id, kem_public_key_wire, ml_dsa_public_key)
        self.key_manager.add_public_key(device_id, kem_public_key_wire)
        return peer

    def confirm_device_peer_verified(self, device_id, fingerprint):
        self.confirm_peer_verified(device_id, fingerprint)

    def authorize_device(self, target_device_id, target_fingerprint):
        payload = canonical_device_authorization_payload(self.username, target_device_id, target_fingerprint, self.device_id)
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)
        return self.send_request(create_device_authorize_packet(
            target_device_id=target_device_id, target_fingerprint=target_fingerprint,
            authorizer_device_id=self.device_id, authorization_signature=base64.b64encode(signature).decode("ascii"),
        ))

    def revoke_device(self, target_device_id):
        payload = canonical_device_revocation_payload(self.username, target_device_id, self.device_id)
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)
        return self.send_request(create_device_revoke_packet(
            target_device_id=target_device_id, revoker_device_id=self.device_id,
            revocation_signature=base64.b64encode(signature).decode("ascii"),
        ))

    def sync_conversation_key_to_device(self, target_device_id, conversation_id, package_type="direct"):
        if not self._peer_key_is_verified(target_device_id):
            raise PeerNotVerifiedError(target_device_id, self.get_peer_verification_state(target_device_id))
        session_info = self._conversation_key_info(conversation_id)
        if session_info is None:
            raise ValueError(f"No key held for conversation {conversation_id} to synchronize.")

        target_peer = self.peers[target_device_id]
        target_fingerprint = target_peer["fingerprint"]
        encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(target_device_id, session_info["key"])

        payload = canonical_device_key_sync_payload(
            self.username, self.device_id, target_device_id, target_fingerprint,
            conversation_id, session_info["epoch"], package_type, encapsulation, wrapped_key,
        )
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)

        return self.send_request(create_device_key_sync_packet(
            target_device_id=target_device_id, target_fingerprint=target_fingerprint,
            conversation_id=conversation_id, epoch=session_info["epoch"], package_type=package_type,
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        ))

    def _handle_device_key_sync(self, packet):
        if packet.get("target_device_id") != self.device_id:
            return

        source_device_id = packet.get("source_device_id")
        conversation_id = packet.get("conversation_id")
        encapsulation = packet.get("encapsulation")
        wrapped_key = packet.get("wrapped_key")
        epoch = packet.get("epoch") or 1

        if not source_device_id or not conversation_id:
            self._report_security_rejection("malformed_packet", source_device_id, conversation_id)
            return

        if not self._peer_key_is_verified(source_device_id):
            self._report_security_rejection("unverified_sender", source_device_id, conversation_id)
            return

        peer = self.peers[source_device_id]
        signature_b64 = packet.get("sync_signature")
        if not signature_b64:
            self._report_security_rejection("missing_signature", source_device_id, conversation_id)
            return

        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (TypeError, ValueError):
            self._report_security_rejection("malformed_packet", source_device_id, conversation_id)
            return

        payload = canonical_device_key_sync_payload(
            packet.get("sender"), source_device_id, self.device_id, packet.get("target_fingerprint"),
            conversation_id, epoch, packet.get("package_type"), encapsulation, wrapped_key,
        )
        if not verify_device_payload(payload, signature, peer["signing_key"]):
            self._report_security_rejection("invalid_signature", source_device_id, conversation_id)
            return

        try:
            key_bytes = self.key_manager.unwrap_received_key(encapsulation, wrapped_key)
        except (ValueError, TypeError):
            self._report_security_rejection("decryption_failure", source_device_id, conversation_id)
            return

        self._store_conversation_key(conversation_id, key_bytes, epoch)

    # ------------------------------------------------------------------
    # Phase 19.24 -- Mute: local-only, per-conversation. Affects
    # notifications (mobile/app.py's own chat/group list preview --
    # this client has no OS notification/sound system in this codebase
    # to suppress either), never delivery. Thin wrappers over self.
    # key_store (storage/secure_key_store.py's conversation_prefs
    # section, shared byte-for-byte with client/session.py::
    # ClientSession's identical methods -- this is the SAME storage
    # module, not a mobile-specific reimplementation).
    # ------------------------------------------------------------------

    MUTE_DURATIONS = {
        "1h": timedelta(hours=1),
        "8h": timedelta(hours=8),
        "1w": timedelta(weeks=1),
    }

    def mute_conversation(self, key, duration):
        """Mute conversation ``key`` (a username for direct, a
        conversation_id for group). ``duration`` is one of
        MUTE_DURATIONS's keys ("1h", "8h", "1w") or "forever"."""

        if self.key_store is None:
            return

        if duration == "forever":
            muted_until = "forever"
        else:
            delta = self.MUTE_DURATIONS.get(duration)
            if delta is None:
                raise ValueError(f"Unknown mute duration: {duration!r}")
            muted_until = (datetime.now(timezone.utc) + delta).isoformat()

        self.key_store.set_conversation_muted_until(key, muted_until)

    def unmute_conversation(self, key):
        """Clear conversation ``key``'s mute state, if any."""

        if self.key_store is None:
            return

        self.key_store.set_conversation_muted_until(key, None)

    def is_conversation_muted(self, key):
        """True if conversation ``key`` is currently muted (an already-
        expired timed mute reads as False)."""

        if self.key_store is None:
            return False

        return self.key_store.is_conversation_muted(key)

    # ------------------------------------------------------------------
    # Phase 19.24 -- Archive: local-only, per-conversation. Retains
    # history -- never deletes or hides anything server-side. Thin
    # wrappers over self.key_store, same shape as the Mute wrappers
    # above and as client/session.py::ClientSession's identical
    # methods.
    # ------------------------------------------------------------------

    def archive_conversation(self, key):
        if self.key_store is None:
            return
        self.key_store.set_conversation_archived(key, True)

    def unarchive_conversation(self, key):
        if self.key_store is None:
            return
        self.key_store.set_conversation_archived(key, False)

    def is_conversation_archived(self, key):
        if self.key_store is None:
            return False
        return self.key_store.is_conversation_archived(key)

    # ------------------------------------------------------------------
    # Phase 19.24 -- Chat Wallpaper: mirrors client/session.py::
    # ClientSession's identical methods exactly.
    # ------------------------------------------------------------------

    def get_conversation_wallpaper(self, key):
        if self.key_store is None:
            return None
        return self.key_store.get_conversation_wallpaper(key)

    def set_conversation_wallpaper(self, key, wallpaper_id):
        if self.key_store is None:
            return
        self.key_store.set_conversation_wallpaper(key, wallpaper_id)
