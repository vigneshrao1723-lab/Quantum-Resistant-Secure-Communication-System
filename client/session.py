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
from datetime import datetime, timedelta, timezone
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
from crypto.identity_protocol import sign_identity_payload, verify_identity_payload
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
from crypto.session_key_protocol import (
    sign_rsa_session_key_payload,
    verify_rsa_session_key_payload,
)
from domain.security_rejection_reason import SecurityRejectionReason
from crypto.message_protocol import (
    EDIT_PAYLOAD_PURPOSE,
    MESSAGE_PAYLOAD_PURPOSE,
    REACTION_PAYLOAD_PURPOSE,
    sign_message_payload,
    verify_message_payload,
)
from crypto.key_manager import (
    KeyManager,
    fingerprint_combined_identity,
    fingerprint_public_key,
)
from storage.secure_key_store import (
    KeyStoreError,
    KeyStoreLocked,
    PEER_STATE_UNVERIFIED,
    PEER_STATE_VERIFIED,
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
from payload.reaction_adapter import ReactionPayloadAdapter
from payload.text_adapter import TextPayloadAdapter
from security.phone_number import is_valid_phone_number
from security.tls import build_client_context
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_blob_download_request_packet,
    create_block_user_request_packet,
    create_blocked_users_list_request_packet,
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
    create_group_leave_packet,
    create_group_remove_member_packet,
    create_inbox_list_request_packet,
    create_inbox_response_packet,
    create_bio_request_packet,
    create_change_bio_request_packet,
    create_login_request_packet,
    create_logout_request_packet,
    create_message_delete_for_everyone_packet,
    create_message_delete_for_me_packet,
    create_message_edit_packet,
    create_message_history_request_packet,
    create_message_pin_packet,
    create_message_unpin_packet,
    create_last_seen_request_packet,
    create_change_password_request_packet,
    create_change_username_request_packet,
    create_payload_packet,
    create_reaction_add_packet,
    create_reaction_remove_packet,
    create_profile_picture_request_packet,
    create_profile_picture_upload_request_packet,
    create_public_key_packet,
    create_read_receipt_packet,
    create_register_request_packet,
    create_session_key_packet,
    create_unblock_user_request_packet,
    create_typing_indicator_packet,
    create_user_lookup_by_phone_request_packet,
    create_user_lookup_request_packet,
    create_verification_request_packet,
)
from utils.request_registry import PendingRequestRegistry, RequestTimeoutError

# Placeholder shown for a historical message that cannot be decrypted
# with the currently cached AES session key (e.g. it was encrypted in
# a previous run, under a key that no longer exists in memory).
_UNDECRYPTABLE_PLACEHOLDER = "Message unavailable (encrypted in a previous session)"

# Server-Untrusted Identity Verification, Stage 2: a purely in-memory,
# session-local peer-verification state, layered on top of
# storage.secure_key_store's persisted PEER_STATE_UNVERIFIED/
# PEER_STATE_VERIFIED. Never written to the key store -- it describes
# "the most recently observed key disagreed with the locally VERIFIED
# one", not new evidence about what should be considered VERIFIED, so
# it belongs to this session's lifetime only (see ClientSession.
# _evaluate_peer_key_verification()'s docstring).
PEER_KEY_STATE_CHANGED = "KEY_CHANGED"


class PeerNotVerifiedError(ValueError):
    """
    Server-Untrusted Identity Verification, Stage 3: raised by
    establish_session_key() when the current direct chat partner's
    cached public key exists but is not PEER_STATE_VERIFIED (either
    PEER_STATE_UNVERIFIED -- first contact or never verified -- or
    PEER_KEY_STATE_CHANGED -- a previously VERIFIED key was just
    replaced by a different one).

    A ValueError subclass so it is caught for free by every existing
    generic exception handler around send_chat_message()/
    send_attachment() in the GUI (e.g. gui/chat_window.py's existing
    "except (OSError, ValueError)" around send_attachment()) even
    before any Stage-3-specific handling is added there -- this
    exists to be LOUD, never to be silently swallowed. ``username``
    and ``state`` let a caller build the exact, state-specific message
    text and offer a direct path to verification, rather than a bare
    string a user has to parse.
    """

    def __init__(self, username, state):
        self.username = username
        self.state = state

        if state == PEER_KEY_STATE_CHANGED:
            message = (
                f"This contact's security identity has changed. "
                f"Verify the new fingerprint before continuing."
            )
        else:
            message = (
                f"Secure messaging is unavailable until you verify "
                f"this contact."
            )

        super().__init__(message)


class PeerVerificationMismatchError(KeyStoreError):
    """
    Server-Untrusted Identity Verification hardening: raised by
    confirm_peer_verification() when there is no currently observed
    public key for the peer to verify against at all, or when the
    caller-supplied fingerprint does not match the fingerprint
    independently re-derived from that currently observed key.

    A KeyStoreError subclass -- not because this is a storage failure,
    but so gui/verify_identity_dialog.py's existing
    "except KeyStoreError" handler already reports it correctly with
    no GUI code change: from the user's point of view this is the same
    "verification could not be saved" failure surface, just with one
    more, independent reason it can now occur.
    """


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

    # Phase 19.23 -- Issue 3 (real DELIVERED signal): conversation_id,
    # receiver username. server/client_handler.py has sent this live
    # "message_delivered" packet since Phase 19.14; this client simply
    # never had a signal/handler consuming it until now (mirrors
    # read_receipt_updated's identical "live hint only, history is
    # authoritative" contract -- see handle_message_delivered()).
    message_delivered_updated = Signal(str, str)

    # Phase 19.24 (continued) -- Message Lifecycle Events UI. A live-
    # sent bubble is tracked under a "live-N" placeholder id until this
    # client learns the real, server-assigned one -- see gui/message_
    # widget.py::MessageWidget._add_bubble()'s own docstring. message_
    # delivered/message_queued are the FIRST packets that ever tell
    # the sender what that real id is (a fire-and-forget "chat" send
    # gets no synchronous ack carrying it). (conversation_id,
    # message_id) -- emitted from BOTH handle_message_delivered() and
    # handle_message_queued(), since either is the sender's first
    # chance to learn the id, whichever happens to arrive.
    own_message_id_resolved = Signal(str, str)

    # Phase 19.24 -- Message Lifecycle Events. Every signal below
    # carries only ALREADY-DECRYPTED content (edited text, reaction
    # string), exactly like message_received/payload_message_received
    # already do -- the GUI never touches ciphertext.
    #
    # (conversation_id, message_id, new_text, editor, edited_at, edit_version)
    message_edited_received = Signal(str, str, str, str, str, int)
    # (conversation_id, message_id, deleted_by, deleted_at)
    message_deleted_received = Signal(str, str, str, str)
    # (conversation_id, message_id, actor, action, reaction_or_empty)
    reaction_updated_received = Signal(str, str, str, str, str)

    # Phase 19.24 -- Pinned Messages. No decrypted content to carry --
    # unlike reaction_updated_received above, pin/unpin has no
    # ciphertext of its own; see database/models/message.py::
    # pinned_at's own trust-model docstring.
    # (conversation_id, message_id, pinned_by, pinned_at)
    message_pinned_received = Signal(str, str, str, str)
    # (conversation_id, message_id, unpinned_by)
    message_unpinned_received = Signal(str, str, str)

    # Phase 19.24 (continued) -- purely additive (see message_received's
    # own "Qt signals are fixed-type" note just above -- widening it to
    # also carry message_id would break every existing 3-arg connection
    # across desktop/mobile/tests). Emitted immediately after message_
    # received/payload_message_received, in the same call, for a "chat"
    # packet the server already stamped with its real, persisted
    # message_id (server/client_handler.py's relay branch sets
    # packet["message_id"] = str(message.id) before ever sending it) --
    # this is what lets a RECEIVED bubble's Reply/React/Delete-for-me/
    # Forward context-menu actions become available the instant the
    # message arrives, not only after the conversation is reopened and
    # rebuilt from history (which already carries message_id). (identity_
    # key, message_id).
    message_id_received = Signal(str, str)

    # Phase 19.24 -- Typing Indicator. Purely a live, ephemeral hint --
    # never persisted, never replayed via history. (conversation_id,
    # username, is_typing). Never emitted for this session's own typing
    # (server/client_handler.py::handle_typing_indicator() excludes the
    # actor's own socket from the relay).
    typing_indicator_received = Signal(str, str, bool)

    # BUG -- Public-Key Availability: another client's public key was
    # just received and cached (see handle_public_key()) -- username.
    # Purely a live-update hint for a composer that might currently be
    # waiting on exactly this key; the authoritative check is always
    # KeyManager.get_public_key(partner) itself (see gui/chat_window.py
    # ::_update_composer_availability()), so a client that never
    # receives this signal (e.g. no conversation with them is open) is
    # not out of sync -- it just sees the key next time it checks.
    public_key_received = Signal(str)

    # Server-Untrusted Identity Verification, Stage 2: emitted --
    # username only -- the moment a received public key's fingerprint
    # is found to disagree with a fingerprint this user previously,
    # explicitly VERIFIED for that peer (see
    # _evaluate_peer_key_verification()). Never emitted for a brand
    # new, never-verified peer (that is the ordinary UNVERIFIED case,
    # not a change from anything). A later GUI layer (Stage 3) is the
    # intended consumer; nothing in this stage reacts to it itself.
    peer_key_changed = Signal(str)

    # Phase 13.7 -- Key-Establishment Rejection Observability & State
    # Integrity: emitted whenever handle_group_key_distribution()
    # (KYBER/group-key) or handle_session_key() (RSA) rejects a
    # key-establishment packet for a security reason -- never for the
    # ordinary "not addressed to me" routing case, which is normal,
    # frequent, non-malicious traffic, not a security event (see
    # _report_security_rejection()'s own docstring). Args: (reason --
    # a domain.security_rejection_reason.SecurityRejectionReason
    # value, sender, conversation_id). No GUI consumes this yet (that
    # remains Phase 14's job -- this phase exposes the signal only, no
    # dialog/badge/UI change); it exists so a future GUI layer -- or a
    # test -- has something deterministic to react to without parsing
    # log text. Only non-sensitive fields: never a signature, key
    # material, or any other private value -- see
    # _report_security_rejection()'s own docstring.
    security_rejection = Signal(str, str, str)

    # Phase 19.13 -- Inbox: fires whenever this client's inbox state
    # changed -- a brand-new notification arrived (handle_inbox_
    # notification()) or one of THIS user's own earlier requests was
    # just approved/denied (handle_inbox_response_result()). Arg: the
    # single notification dict (see create_inbox_list_result_packet()'s
    # docstring for its shape) -- the GUI's Inbox screen re-fetches
    # the full list via load_inbox() on this signal rather than trying
    # to patch one row in place, exactly like every other "something
    # changed, go reload" signal in this class.
    inbox_updated = Signal(dict)

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
        # Block User (Phase 19.24) -- local cache of usernames THIS
        # account has blocked, refreshed once at startup (see get_
        # blocked_users()'s own docstring) and updated optimistically
        # by block_user()/unblock_user() themselves.
        # ---------------------------------

        self.blocked_usernames = set()

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
            # Phase 19.24 -- Message Lifecycle Events.
            PayloadType.REACTION: ReactionPayloadAdapter(),
            # Phase 19.24 -- Voice/Video Messages: the SAME generic
            # raw-bytes adapter FILE/IMAGE already use -- see domain/
            # payload_type.py's own module docstring for why voice/
            # video need no adapter of their own.
            PayloadType.VOICE: FilePayloadAdapter(PayloadType.VOICE),
            PayloadType.VIDEO: FilePayloadAdapter(PayloadType.VIDEO),
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

        # Multi-Device Identity (Phase 16) -- this device's own
        # account-management identity, lazily generated by
        # enroll_device() -- see that method's own docstring for why
        # this is session-local, not yet persisted.
        self.device_id = None

        # BUG 1 -- local encrypted key store, opened at login.
        # None until unlocked (or if unlocking failed); key_store_error
        # carries a user-presentable reason in that case.
        self.key_store = None
        self.key_store_error = None

        # Server-Untrusted Identity Verification, Stage 2: usernames
        # whose most recently received public key disagreed with their
        # locally VERIFIED fingerprint. Session-local only -- reset on
        # every login/lock (see _lock_key_store()), never persisted;
        # see _evaluate_peer_key_verification()'s docstring.
        self._peer_keys_changed = set()

        # Server-Untrusted Identity Verification, Stage 3: {username:
        # fingerprint} for the NEW (rejected, not cached, not
        # persisted) key that triggered PEER_KEY_STATE_CHANGED for
        # that username -- see _flag_peer_key_changed(). Needed so a
        # verification dialog can show the user what to compare
        # against: SecureKeyStore still holds only the OLD VERIFIED
        # fingerprint (Stage 2 deliberately never stores or caches the
        # substituted key), so the new key's fingerprint has nowhere
        # else to live. Exactly as session-local as
        # _peer_keys_changed, for the same reason -- reset on every
        # login/lock, never persisted.
        self._pending_key_changed_fingerprints = {}

        # Server-Untrusted Identity Verification hardening: {username:
        # raw_public_key_bytes} for the same pending NEW key as above
        # -- kept alongside its already-computed fingerprint so
        # confirm_peer_verification() can independently re-derive and
        # check that fingerprint itself, rather than trusting a
        # caller-supplied string. Same session-local lifetime.
        self._pending_key_changed_raw_keys = {}

        # Server-Untrusted Identity Verification hardening: {username:
        # raw_public_key_bytes} exactly as received on the wire for
        # the CURRENT, legitimately-imported key -- i.e. the same raw
        # value _record_peer_key_observation() already fingerprints
        # for SecureKeyStore. KeyManager.public_keys[username] is NOT
        # equivalent to this: KeyManager stores each algorithm's own
        # parsed/decoded form (e.g. Kyber's import_public_key()
        # returns raw-decoded bytes, not the original base64 wire
        # value fingerprint_public_key() was computed from elsewhere),
        # so re-fingerprinting from KeyManager would silently produce
        # a DIFFERENT digest than the one already on file. Kept here,
        # deliberately mirroring _pending_key_changed_raw_keys, so
        # confirm_peer_verification() always re-derives from the exact
        # bytes every other fingerprint in this system was computed
        # from. Not reset on lock -- same lifetime as KeyManager.
        # public_keys itself, which _lock_key_store() does not clear
        # either.
        self._observed_peer_raw_public_keys = {}

        # ML-DSA identity/key-persistence foundation phase: the
        # signing-key counterparts of the two dicts immediately above,
        # kept as SEPARATE dicts (not merged into them) so this phase's
        # new combined-identity methods (_record_peer_identity_
        # observation(), _flag_peer_identity_changed(),
        # observe_peer_identity() below) can be added, tested, and
        # reasoned about independently of the existing single-key
        # (KEM-only) methods above, which remain completely unmodified
        # and unused by these new methods -- no network packet carries
        # a peer's signing key yet (Phase 11's explicit scope
        # boundary), so nothing currently populates these except direct
        # calls to observe_peer_identity() itself (e.g. from tests).
        # Same lifetime rules as their KEM counterparts: _observed_
        # peer_signing_public_keys is NOT reset on lock (mirrors
        # _observed_peer_raw_public_keys); _pending_key_changed_
        # signing_raw_keys IS reset on lock (mirrors _pending_key_
        # changed_raw_keys) -- see _lock_key_store().
        self._observed_peer_signing_public_keys = {}
        self._pending_key_changed_signing_raw_keys = {}

        # {username: device_id} -- records the most recent device_id a
        # signed identity-announcement for this username carried (see
        # _handle_signed_public_key()'s "device_id (Phase 16D)" note).
        # Every enrolled mobile device includes one on every
        # announcement, which means _record_peer_identity_observation()
        # only ever populates the DEVICE-SCOPED slot for such a peer,
        # never the plain account-level one -- but every ordinary
        # trust-consuming call site (the GUI's Verify Identity flow,
        # the group-key/session-key VERIFIED gates) looks the peer up
        # with device_id=None (the account-level slot), so it would
        # find nothing there, forever. _effective_peer_identity_key()
        # uses this purely-in-memory redirect so those callers land on
        # the one slot that was actually populated, without changing
        # what gets written or how often (no new store/dict writes on
        # the receive path -- this line is the only addition there).
        # Same lifetime as _observed_peer_raw_public_keys above: not
        # reset on lock.
        self._device_scoped_identity_keys = {}

        # {sender_username: [(conversation_id, epoch), ...]} -- a key
        # distribution this client received and rejected purely
        # because ``sender`` was not yet VERIFIED (see handle_group_
        # key_distribution()/handle_session_key()'s "if not self.
        # _peer_key_is_verified(sender)" branches). The sender is never
        # told a redelivery attempt failed (SECURITY: rejections are
        # never observable to the sender, by design -- see
        # _report_security_rejection()), so once THIS side later
        # verifies them there is otherwise nothing to prompt a retry:
        # the sender believes delivery already succeeded, and the
        # server has no reason to ask again on its own. confirm_peer_
        # verification()/confirm_combined_peer_verification() drain
        # this for the peer they just verified and re-request each
        # pending (conversation_id, epoch) -- the exact same request
        # handle_direct_key_recovery_available() already sends on
        # reconnect, just re-triggered by verification instead of by a
        # fresh connection. Makes "verify late, on either side, in
        # either order" work without requiring a manual reconnect.
        # Session-local by nature (nothing to redeliver survives a
        # restart that a normal reconnect wouldn't already re-announce
        # anyway) -- not reset on lock is irrelevant since login()
        # rebuilds a fresh ClientSession object.
        self._pending_key_requests_awaiting_verification = {}

        # {recipient_username: [(conversation_id, epoch), ...]} -- the
        # OTHER half of the same "verify late, in either order" gap:
        # handle_direct_key_redelivery_required() silently declines to
        # redeliver a key to ``recipient`` when THIS client has not
        # verified THEM yet (its own "SECURITY: refusing to redeliver"
        # branch) -- silently, by design, since there is no requester-
        # visible failure to report for a background, server-triggered
        # handler. Recorded here so that once this client verifies
        # ``recipient``, confirm_peer_verification()/confirm_combined_
        # peer_verification() can retry the exact same redelivery
        # instead of leaving it stuck until the recipient's next
        # reconnect re-announces it.
        self._declined_redeliveries_awaiting_verification = {}

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
        Authenticate a phone number + password against the server (UI
        Finalization -- Login Identifier: phone number is now the only
        accepted login identifier -- see AuthenticationService.
        authenticate_user(); this method itself stays identifier-agnostic,
        exactly as it already was) (D2 -- Server-Side API / Authentication
        Migration; final slice,
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

        Server-Untrusted Identity Verification, Stage 2.5: also the
        earliest point this user's own Kyber keypair can be made
        persistent -- self.key_manager already exists (built in
        __init__(), before any password was known) with an ephemeral
        keypair, and this is the first moment a password-derived store
        to load-or-persist it into becomes available. If the store
        fails to unlock above, this step is simply never reached, and
        the session keeps that ephemeral keypair for its own lifetime
        (exactly today's pre-Stage-2.5 behavior) -- never a new,
        silently-persisted identity minted on top of a store that just
        failed to authenticate.
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

        try:
            self.key_manager.load_or_create_kyber_keypair(store)
        except (KeyStoreError, OSError) as error:
            # Same "never fatal" posture as _persist_conversation_keys():
            # the store itself did unlock, so it stays usable for
            # conversation-key persistence below; only this session's
            # own keypair fails to become persistent, and it keeps the
            # ephemeral one __init__() already generated.
            self.logger.warning(
                f"Could not load or persist own Kyber keypair: {error}"
            )

        try:
            self.key_manager.load_or_create_signing_keypair(store)
        except (ValueError, KeyStoreError, OSError) as error:
            # Same "never fatal" posture as the Kyber keypair block
            # above, kept in its own try/except so a failure in one
            # keypair's persistence can never prevent the other's --
            # the store itself did unlock, so it stays usable for
            # conversation-key persistence below; only this session's
            # own signing keypair fails to become persistent, and it
            # keeps the ephemeral one __init__() already generated.
            # ValueError is included alongside KeyStoreError/OSError
            # because load_or_create_signing_keypair() raises plain
            # ValueError (not KeyStoreError) for its own public/private
            # consistency check -- see that method's docstring.
            self.logger.warning(
                f"Could not load or persist own signing keypair: {error}"
            )

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

        # Server-Untrusted Identity Verification, Stage 2: this
        # session-local state has no meaning without the key store
        # that VERIFIED/UNVERIFIED records live in.
        self._peer_keys_changed = set()

        # Server-Untrusted Identity Verification, Stage 3: same
        # reasoning -- a pending new-key fingerprint has no meaning
        # once the key store it would be verified against is locked.
        self._pending_key_changed_fingerprints = {}

        self._pending_key_changed_raw_keys = {}

        self._pending_key_changed_signing_raw_keys = {}

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

    def change_username(self, new_username):
        """
        Phase 19.18 -- L-5/Desktop-parity closure: mirrors
        MobileClientSession.change_username() exactly, same
        already-existing, already-tested server-side handler
        (AuthenticationService.change_username(), unchanged).
        """

        response = self.send_request(create_change_username_request_packet(new_username))

        if response.get("success"):
            self.username = new_username

        return response

    def change_password(self, current_password, new_password, confirm_password):
        """Mirrors MobileClientSession.change_password() exactly."""

        return self.send_request(create_change_password_request_packet(
            current_password=current_password, new_password=new_password, confirm_password=confirm_password,
        ))

    # ------------------------------------------------------------------
    # Phase 19.24 -- Block User. Server-side and persisted (database/
    # models/blocked_user.py) -- real enforcement across DMs,
    # verification, presence, typing, group creation/adding, and
    # search (server/client_handler.py's own enforcement points), not
    # a local-only preference like Mute/Archive. Mirrors
    # MobileClientSession's identical methods exactly.
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
        """Returns the list of usernames this account has blocked, and
        refreshes self.blocked_usernames (the local cache is_user_
        blocked() reads -- a network round trip on every sidebar
        render would be wasteful, so this is called once at startup
        and updated optimistically by block_user()/unblock_user()
        themselves; a block made from a SECOND device is not reflected
        here until the next login, the same documented limitation
        change_username_request's own docstring already accepts for
        other clients' stale local state)."""

        response = self.send_request(create_blocked_users_list_request_packet())
        usernames = response.get("usernames") or []
        self.blocked_usernames = set(usernames)
        return usernames

    def is_user_blocked(self, username):
        return username in self.blocked_usernames

    def upload_profile_picture(self, image_bytes, content_type="image/png"):
        """
        Upload/replace this account's profile picture (Phase 19.17C --
        mirrors MobileClientSession.upload_profile_picture() exactly;
        Mobile already had a full, working client for this feature,
        Desktop had none, despite the backend already fully supporting
        it). Deliberately NOT end-to-end encrypted -- a profile
        picture is meant to be visible to any other user who looks
        this account up, unlike message attachments -- still travels
        only over this connection's TLS channel. Runs on the already-
        authenticated, already-connected session via send_request(),
        same as every other post-login request.
        """

        image_base64 = base64.b64encode(image_bytes).decode("ascii")

        return self.send_request(create_profile_picture_upload_request_packet(
            image_base64=image_base64, content_type=content_type,
        ))

    def fetch_profile_picture(self, username):
        """
        Returns the raw image bytes for ``username``'s current profile
        picture, or None if they have none set (see server/
        client_handler.py::handle_profile_picture_request()'s own
        docstring on why "not found" and "no picture set" are
        deliberately indistinguishable here). Mirrors
        MobileClientSession.fetch_profile_picture() exactly.
        """

        response = self.send_request(create_profile_picture_request_packet(username))

        if not response.get("found"):
            return None

        try:
            return base64.b64decode(response["image_base64"], validate=True)
        except (TypeError, ValueError, KeyError):
            return None

    def change_bio(self, bio):
        """
        Phase 19.22 -- Settings: set/replace this account's own bio.
        Mirrors change_username() exactly; the User.bio column has
        existed since the initial migration but had no client method
        at all until now.
        """

        return self.send_request(create_change_bio_request_packet(bio))

    def fetch_bio(self, username):
        """
        Returns ``username``'s current bio, or "" if they have none
        set or the account does not exist (Phase 19.22 -- mirrors
        fetch_profile_picture()'s "not found" and "no bio set" being
        deliberately indistinguishable, same account-enumeration
        guard).
        """

        response = self.send_request(create_bio_request_packet(username))

        if not response.get("found"):
            return ""

        return response.get("bio") or ""

    def fetch_last_seen(self, username):
        """
        Phase 19.24 -- Presence/Last Seen: returns ``username``'s last-
        seen timestamp as a naive UTC datetime, or None -- covering
        "blocked in either direction", "account not found", and "no
        last-seen information yet" alike (server/client_handler.py::
        handle_last_seen_request()'s own docstring for why those three
        are deliberately indistinguishable to this account). Only ever
        meaningful to call for a peer this account's own online_users
        already reports as offline.
        """

        response = self.send_request(create_last_seen_request_packet(username))

        if not response.get("found") or not response.get("last_seen_at"):
            return None

        return self._parse_incoming_timestamp(response["last_seen_at"])

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

        Protocol-Level ML-DSA Origin Authentication: also attaches this
        client's persistent ML-DSA public key and an ML-DSA signature
        over crypto/identity_protocol.py::canonical_identity_payload()
        binding this exact (username, KEM public key, signing public
        key) triple together. self.key_manager.ml_dsa is the SAME
        persistent signer Phase (identity/key-persistence foundation)
        already loads/persists through SecureKeyStore -- its private
        key never leaves that in-memory object; sign_identity_payload()
        only ever calls its .sign() method and returns signature bytes.
        The KEM public key signed here is the exact wire string sent
        below, not KeyManager's internal parsed form -- the same
        representation handle_public_key() will reconstruct on the
        receiving end.
        """

        algorithm = self.key_manager.algorithm

        kem_public_key_wire = self.key_manager.public_key.decode("utf-8")
        signing_public_key = self.key_manager.ml_dsa.export_public_key()

        signature = sign_identity_payload(
            self.key_manager.ml_dsa,
            self.username,
            kem_public_key_wire,
            signing_public_key,
        )

        public_key_packet = create_public_key_packet(
            username=self.username,
            algorithm=algorithm,
            public_key=kem_public_key_wire,
            signing_public_key=base64.b64encode(signing_public_key).decode("ascii"),
            identity_signature=base64.b64encode(signature).decode("ascii"),
            device_id=self.device_id,
        )

        send_message(
            self.client_socket,
            public_key_packet
        )

        self.logger.info(
            f"{algorithm} public key sent to server (ML-DSA signed)."
        )

    # ==========================================================
    # Multi-Device Identity (Phase 16)
    # ==========================================================
    #
    # This device's own account-management identity: a self-generated,
    # session-local device_id (docs/architecture/multi_device_
    # identity.md's own "Known limitations" -- NOT yet persisted
    # across restarts the way the KEM/ML-DSA keypair themselves already
    # are via SecureKeyStore; a restart re-enrolls under a fresh
    # device_id today). This does not weaken any of enrollment/
    # authorization/revocation's actual security properties -- it only
    # means today's device_id is not yet stable across app restarts.

    def enroll_device(self, device_name=None, platform=None):
        """
        Self-sign and send this device's own enrollment request
        (crypto/device_protocol.py::canonical_device_enrollment_
        payload()), signed with THIS device's own ML-DSA private key
        -- proves possession of the advertised keys, not authorization
        by itself (server/device_handler.py::handle_device_enroll_
        request() decides PENDING vs. bootstrap-AUTHORIZED).

        Phase 16B -- Multi-Device Identity persistence: device_id is
        read from the local, encrypted SecureKeyStore
        (get_device_id()) if this installation already enrolled once
        before (across a restart -- the exact same file the KEM/ML-DSA
        keypair themselves are already persisted in, not a second
        store); generated once and persisted (save_device_id()) only
        the very first time. This is what makes a second call to this
        method, from a fresh ClientSession representing the SAME
        installation, resolve to the SAME device_id -- and therefore
        the SAME server-side row -- instead of silently minting a new
        device on every restart.

        Requires start_receiver() to already be running (send_request()
        does). Returns the device_enroll_result packet.
        """

        newly_resolved_device_id = self.device_id is None

        if self.device_id is None:
            persisted_device_id = self.key_store.get_device_id() if self.key_store else None

            if persisted_device_id is not None:
                self.device_id = persisted_device_id
            else:
                self.device_id = str(uuid.uuid4())
                if self.key_store is not None:
                    self.key_store.save_device_id(self.device_id)

        if newly_resolved_device_id and self.client_socket is not None:
            # Phase 16D -- Device-Aware Peer Identity: send_public_key()
            # is normally called once, automatically, right after login
            # -- BEFORE this method has ever resolved self.device_id
            # (enroll_device() is an explicit, later, app-level action).
            # Without this, every already-connected peer would have
            # cached this identity under the plain-username slot only
            # (device_id was still None at broadcast time), so any
            # chat message this device sends AFTER enrolling -- which
            # now carries sender_device_id -- would fail to resolve a
            # trusted signing key under the (username, device_id)
            # composite slot and be rejected. Re-broadcasting here,
            # exactly once, the moment self.device_id first becomes
            # known, keeps the two in sync. Harmless if a peer has
            # already VERIFIED the plain-username slot from the
            # earlier broadcast: this is a NEW, distinct (username,
            # device_id) identity slot to them (see _peer_identity_
            # key()), recorded as its own fresh UNVERIFIED observation
            # -- never a KEY_CHANGED against the existing VERIFIED
            # plain-username record, which is untouched.
            self.send_public_key()

        kem_public_key_wire = self.key_manager.public_key.decode("utf-8")
        ml_dsa_public_key = self.key_manager.ml_dsa.export_public_key()

        payload = canonical_device_enrollment_payload(
            self.username, self.device_id, kem_public_key_wire,
            ml_dsa_public_key, device_name, platform,
        )
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)

        packet = create_device_enroll_request_packet(
            device_id=self.device_id,
            device_name=device_name,
            platform=platform,
            kem_public_key=kem_public_key_wire,
            ml_dsa_public_key=base64.b64encode(ml_dsa_public_key).decode("ascii"),
            enrollment_signature=base64.b64encode(signature).decode("ascii"),
        )

        return self.send_request(packet)

    def bind_device_session(self):
        """
        Prove to the server that THIS connection is genuinely operated
        by the party holding the private ML-DSA key for this device
        (Phase 16B -- Device Authentication Binding, Step 3), signing
        crypto/device_protocol.py::canonical_device_session_binding_
        payload() with this device's own ML-DSA private key. Requires
        self.device_id to already be set (call enroll_device() first,
        at least once ever, on this installation).

        Once bound, server-side relay paths that opt into device-state
        enforcement (server/client_handler.py::
        handle_group_key_distribution(), currently -- see this phase's
        own report for the exact list) will re-check this device's
        live AUTHORIZED/REVOKED state on every subsequent packet on
        this connection.
        """

        if self.device_id is None:
            raise ValueError("No device_id -- call enroll_device() first.")

        session_nonce = uuid.uuid4().hex

        payload = canonical_device_session_binding_payload(
            self.username, self.device_id, session_nonce,
        )
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)

        packet = create_device_session_bind_packet(
            device_id=self.device_id,
            session_nonce=session_nonce,
            binding_signature=base64.b64encode(signature).decode("ascii"),
        )

        return self.send_request(packet)

    def list_devices(self):
        """Return this account's device_list_result packet's ``devices`` list."""

        response = self.send_request(create_device_list_request_packet())
        return response.get("devices", [])

    def authorize_device(self, target_device_id, target_fingerprint):
        """
        Vouch for a PENDING device as this (already-AUTHORIZED)
        device, signing crypto/device_protocol.py::
        canonical_device_authorization_payload() with THIS device's
        own ML-DSA private key. The caller is responsible for having
        actually compared ``target_fingerprint`` against the target
        device's displayed fingerprint out-of-band FIRST -- this
        method performs no verification of its own; it only signs what
        it is told to (mirrors ClientSession.confirm_combined_peer_
        verification()'s identical division of responsibility between
        human judgment and the signing call itself).
        """

        payload = canonical_device_authorization_payload(
            self.username, target_device_id, target_fingerprint, self.device_id,
        )
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)

        packet = create_device_authorize_packet(
            target_device_id=target_device_id,
            target_fingerprint=target_fingerprint,
            authorizer_device_id=self.device_id,
            authorization_signature=base64.b64encode(signature).decode("ascii"),
        )

        return self.send_request(packet)

    def revoke_device(self, target_device_id):
        """Revoke a device (possibly this one) as this AUTHORIZED device."""

        payload = canonical_device_revocation_payload(
            self.username, target_device_id, self.device_id,
        )
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)

        packet = create_device_revoke_packet(
            target_device_id=target_device_id,
            revoker_device_id=self.device_id,
            revocation_signature=base64.b64encode(signature).decode("ascii"),
        )

        return self.send_request(packet)

    # ==========================================================
    # Cross-Device Key Synchronization (Phase 16C)
    # ==========================================================
    #
    # Device-peer trust is EXPLICITLY the same VERIFIED/UNVERIFIED/
    # KEY_CHANGED machinery ordinary peer verification already uses
    # (storage/secure_key_store.py), applied to a device_id string
    # instead of a username -- reused, not reimplemented, and
    # deliberately NOT automatic just because two devices share an
    # account (Step 16 of this phase's own instructions). A human
    # still has to compare the fingerprint (trivial in practice, since
    # both devices belong to the same person) and explicitly confirm
    # it, exactly like verifying a different person.

    def observe_device_peer_identity(self, device_id, kem_public_key_wire, ml_dsa_public_key):
        """Observe one of this account's OTHER devices (from
        list_devices()'s own kem_public_key/ml_dsa_public_key fields)
        as a device-peer -- UNVERIFIED until explicitly confirmed
        (confirm_device_peer_verification()). Also registers the KEM
        public key with KeyManager (add_public_key()) so wrap_key_
        for_member()/encapsulation can target this device_id, exactly
        like an ordinary peer's public key already is registered by
        handle_public_key()."""

        self.observe_peer_identity(device_id, kem_public_key_wire, ml_dsa_public_key)
        self.key_manager.add_public_key(device_id, kem_public_key_wire)

    def confirm_device_peer_verification(self, device_id, fingerprint):
        self.confirm_combined_peer_verification(device_id, fingerprint)

    def sync_conversation_key_to_device(self, target_device_id, conversation_id, package_type="direct"):
        """
        Wrap this client's own current key for ``conversation_id`` for
        delivery to ``target_device_id`` (one of this SAME account's
        other devices) and send it. Reuses KeyManager.
        wrap_key_for_member() completely unchanged -- the identical
        KEM-then-DEM (ML-KEM encapsulate + AES-256-GCM) composition
        ordinary group-key distribution already uses; no new
        cryptographic construction. Requires the target device to
        already be device-peer VERIFIED (see class docstring above) --
        raises PeerNotVerifiedError otherwise, mirroring establish_
        session_key()'s identical guard for ordinary peers.
        """

        if not self._peer_key_is_verified(target_device_id):
            raise PeerNotVerifiedError(
                target_device_id, self.get_peer_verification_state(target_device_id)
            )

        epoch = self.key_manager.current_epoch(conversation_id)
        key_bytes = self.key_manager.get_key(conversation_id, epoch=epoch)

        if key_bytes is None:
            raise ValueError(f"No key held for conversation {conversation_id} to synchronize.")

        target_fingerprint = self.get_peer_fingerprint_for_verification(target_device_id)

        encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(target_device_id, key_bytes)

        payload = canonical_device_key_sync_payload(
            self.username, self.device_id, target_device_id, target_fingerprint,
            conversation_id, epoch, package_type, encapsulation, wrapped_key,
        )
        signature = sign_device_payload(self.key_manager.ml_dsa, payload)

        packet = create_device_key_sync_packet(
            target_device_id=target_device_id,
            target_fingerprint=target_fingerprint,
            conversation_id=conversation_id,
            epoch=epoch,
            package_type=package_type,
            encapsulation=encapsulation,
            wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        )

        return self.send_request(packet)

    def handle_device_key_sync(self, packet):
        """
        Receive wrapped conversation/group key material from another
        of THIS account's own devices. Mandatory order (identical
        shape to handle_group_key_distribution()'s own, unmodified,
        established ordering): resolve source device + require device-
        peer VERIFIED -> resolve trusted signing key (from THIS
        receiver's own local device-peer state, never from the packet)
        -> verify signature (binding conversation_id/epoch/wrapped
        material) -> THEN decapsulate/decrypt -> install. Any failure
        returns before KeyManager.store_key() is ever reached, and is
        routed through the existing _report_security_rejection()
        exactly like every other key-establishment rejection in this
        codebase -- no second, parallel rejection-reporting path.

        Returns None on success, or the domain.security_rejection_
        reason.SecurityRejectionReason that caused rejection --
        matching handle_group_key_distribution()'s own contract.
        """

        source_device_id = packet.get("source_device_id")
        conversation_id = packet.get("conversation_id")

        if not source_device_id or not conversation_id:
            self._report_security_rejection(
                SecurityRejectionReason.MALFORMED_PACKET, source_device_id, conversation_id
            )
            return SecurityRejectionReason.MALFORMED_PACKET

        if not self._peer_key_is_verified(source_device_id):
            reason = self._sender_trust_rejection_reason(source_device_id)
            self._report_security_rejection(reason, source_device_id, conversation_id)
            return reason

        signing_public_key = self._resolve_trusted_signing_key(source_device_id)
        signature_b64 = packet.get("sync_signature")

        if signature_b64 is None:
            self._report_security_rejection(
                SecurityRejectionReason.MISSING_SIGNATURE, source_device_id, conversation_id
            )
            return SecurityRejectionReason.MISSING_SIGNATURE

        target_device_id = packet.get("target_device_id")
        target_fingerprint = packet.get("target_fingerprint")
        epoch = packet.get("epoch") or 1
        package_type = packet.get("package_type")
        encapsulation = packet.get("encapsulation")
        wrapped_key = packet.get("wrapped_key")

        try:
            signature = base64.b64decode(signature_b64, validate=True)

            payload = canonical_device_key_sync_payload(
                self.username, source_device_id, target_device_id, target_fingerprint,
                conversation_id, epoch, package_type, encapsulation, wrapped_key,
            )

            verified = verify_device_payload(payload, signature, signing_public_key)
        except (TypeError, ValueError):
            self._report_security_rejection(
                SecurityRejectionReason.MALFORMED_PACKET, source_device_id, conversation_id
            )
            return SecurityRejectionReason.MALFORMED_PACKET

        if not verified:
            self._report_security_rejection(
                SecurityRejectionReason.INVALID_SIGNATURE, source_device_id, conversation_id
            )
            return SecurityRejectionReason.INVALID_SIGNATURE

        # Only reached once verification has succeeded -- see this
        # method's own docstring.
        try:
            key_bytes = self.key_manager.unwrap_received_key(encapsulation, wrapped_key)
            self.key_manager.store_key(conversation_id, key_bytes, epoch=epoch)
        except (ValueError, TypeError):
            self._report_security_rejection(
                SecurityRejectionReason.DECRYPTION_FAILURE, source_device_id, conversation_id
            )
            return SecurityRejectionReason.DECRYPTION_FAILURE

        self.logger.info(
            f"Synchronized conversation key for {conversation_id} (epoch {epoch}) "
            f"from device {source_device_id}"
        )

        return None

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
        Generate, and -- when currently possible -- deliver, an AES
        session key for the currently selected direct partner (BUG --
        Offline First Contact).

        The AES key is now ALWAYS generated locally first, via
        os.urandom(32), independent of the recipient's Kyber/RSA
        public key and of which algorithm is active. This is required
        because ML-KEM (Kyber) is a KEM, not a public-key encryption
        scheme: encapsulate() always derives its OWN fresh shared
        secret from the recipient's public key (see crypto/kyber.py)
        -- there is no operation that encrypts a caller-chosen 32
        bytes. A key that must exist before the recipient's public key
        is known -- e.g. the very first message to someone who has
        never connected while this client was online -- can therefore
        only ever come from independent generation, never from Kyber
        encapsulation itself.

        The key is stored (KeyManager.store_key(), under a freshly
        RESERVED epoch, exactly as before) BEFORE any delivery is
        attempted, so _send_encrypted_payload() can always encrypt and
        persist a message immediately, regardless of whether the
        recipient's public key has ever been seen. Previously this
        method raised ValueError("No public key found for <user>")
        at the point of generation itself, before any key existed to
        encrypt with at all -- that was the root cause of a brand-new
        conversation with a currently offline recipient being unusable.

        Delivery, when the recipient's public key IS available, is
        algorithm-dependent:

        KYBER now uses KeyManager.wrap_key_for_member() -- the same
        KEM-then-DEM hybrid wrap already used for group key
        distribution and for direct key redelivery (see
        handle_direct_key_redelivery_required()) -- sent as a
        group_key_distribution packet, instead of the old KEM-direct
        encapsulate_session_key()/session_key-packet pair (which
        cannot wrap this independently-generated key at all -- see
        above). This is a deliberate unification, not a new
        construction: wrap_key_for_member() already accepts an
        arbitrary, caller-chosen key, so first establishment and later
        redelivery of that exact same key now share one wire shape
        and one server-side authorization path -- membership in
        conversation_id, epoch bounded by the server-reserved counter
        (server/client_handler.py::handle_group_key_distribution()) --
        already proven safe and already exercised today for direct
        redelivery.

        RSA is UNCHANGED: encrypt_session_key() is true public-key
        encryption, so it already wraps a caller-chosen key directly
        -- it never had the Kyber problem above, since RSA-OAEP can
        encrypt any 32 bytes handed to it, generated independently or
        not. Its wire packet (session_key, algorithm="RSA") stays
        exactly as it was; changing it was never necessary and would
        only have broken existing protocol-shape coverage (see
        tests/test_rsa_key_exchange_integration.py) for no benefit.

        When the recipient's public key is NOT available, delivery is
        simply deferred: no exception, no error packet, nothing sent.
        The key already stored above is entirely sufficient for this
        client's own outgoing messages. Getting the recipient a
        wrapped copy is left to the existing membership/epoch-driven
        recovery mechanism
        (_ensure_group_keys_current_for_reconnecting_user() /
        handle_direct_key_redelivery_required(), unchanged), which
        already announces and redelivers exactly this epoch's key the
        next time the recipient connects -- it has never required a
        key to have been previously delivered, only that the epoch
        exists on a persisted message.

        Key-desynchronization fix (unchanged): every key established
        here is stamped with a freshly RESERVED epoch (never an
        assumed "epoch 1"), via the same current_key_epoch counter
        Phase 7 already uses for group-key rotation. D4.1 -- Message/
        History Operations Migration: the reservation itself is a
        server request/response (epoch_reservation_request/result, via
        D1's send_request()) rather than a direct, local
        ConversationRepository.reserve_next_epoch() call -- the server
        reuses that exact same repository method unchanged, behind an
        authorization check (the caller must be a member of the
        conversation) this direct-DB path never had. Reserving via the
        server-persisted counter (not a purely local guess) is what
        keeps this safe even when BOTH sides have lost their cached
        key at once: the counter itself survives any number of client
        restarts, so it can never replay an epoch either side has
        already used.
        """

        if self.current_chat is None:
            raise ValueError(
                "No active chat partner selected."
            )

        receiver = self.current_chat
        conversation_id = self.current_conversation_id

        # Server-Untrusted Identity Verification, Stage 3: checked
        # FIRST, before the has_key() short-circuit below, and on
        # EVERY call -- not only the one that first creates this
        # conversation's key. Without that ordering, a first blocked
        # attempt would still reach store_key() further down on a
        # later call once has_key() started returning True, silently
        # letting a second send attempt through with no further check.
        #
        # `is not None` is the deliberate distinction from a missing
        # key entirely (see this method's own docstring on Offline
        # First Contact): a peer whose key has never even been
        # observed is not "unverified" in any meaningful sense yet --
        # that case falls through unchanged to the deferred-delivery
        # branch below, exactly as before Stage 3.
        if (
            self.key_manager.get_public_key(receiver) is not None
            and not self._peer_key_is_verified(receiver)
        ):
            raise PeerNotVerifiedError(
                receiver, self.get_peer_verification_state(receiver)
            )

        if self.key_manager.has_key(conversation_id):
            return

        response = self.send_request(
            create_epoch_reservation_request_packet(conversation_id)
        )

        error = response.get("error")

        if error:
            raise ValueError(error)

        epoch = response.get("epoch")

        session_key = os.urandom(32)

        self.key_manager.store_key(
            conversation_id,
            session_key,
            epoch=epoch
        )

        self.logger.info(
            f"Generated AES session key for {receiver} (epoch {epoch})"
        )

        if self.key_manager.get_public_key(receiver) is None:

            # BUG -- Offline First Contact: nothing to deliver to yet.
            # The key above is already stored and already usable for
            # this client's own outgoing messages; delivery to
            # receiver happens later via the existing recovery path
            # (see docstring) once they connect and the server
            # observes their membership + this epoch's persisted
            # message.
            self.logger.info(
                f"Deferring key delivery to {receiver} for "
                f"{conversation_id} epoch {epoch}: no public key "
                f"available yet."
            )

            return

        algorithm = self.key_manager.algorithm

        if algorithm == "KYBER":

            try:
                encapsulation, wrapped_key = self.key_manager.wrap_key_for_member(
                    receiver, session_key
                )
            except (ValueError, TypeError) as wrap_error:

                # Narrow, and the only expected failure: the public
                # key just checked as present turns out to be unusable
                # to wrap_key_for_member() (e.g. a race with it being
                # replaced). Not fatal -- the key is already stored,
                # so delivery simply falls back to the same recovery
                # path used when no public key was available at all.
                self.logger.warning(
                    f"Could not wrap session key for {receiver} "
                    f"({conversation_id} epoch {epoch}): {wrap_error}"
                )

                return

            # Group-Key-Distribution ML-DSA Origin Authentication:
            # this "group_key_distribution" packet also carries a
            # direct conversation's initial session key (see this
            # method's own docstring/module history) -- signed exactly
            # like a genuine group delivery, since handle_group_key_
            # distribution() on the receiving end is the SAME handler
            # either way and now requires a valid signature from a
            # VERIFIED sender unconditionally.
            group_key_signature = sign_group_key_payload(
                self.key_manager.ml_dsa,
                self.username,
                conversation_id,
                receiver,
                encapsulation,
                wrapped_key,
                epoch,
            )

            send_message(
                self.client_socket,
                create_group_key_distribution_packet(
                    sender=self.username,
                    conversation_id=conversation_id,
                    recipient=receiver,
                    encapsulation=encapsulation,
                    wrapped_key=wrapped_key,
                    epoch=epoch,
                    group_key_signature=base64.b64encode(group_key_signature).decode("ascii"),
                ),
            )

        else:

            # RSA: unchanged wrapping (see docstring); wire construction
            # now also carries an ML-DSA signature -- RSA Direct-
            # Session-Key ML-DSA Origin Authentication (Phase 13.6).
            try:
                encrypted_key = self.key_manager.encrypt_session_key(
                    receiver,
                    session_key
                )
            except ValueError as wrap_error:

                self.logger.warning(
                    f"Could not wrap session key for {receiver} "
                    f"({conversation_id} epoch {epoch}): {wrap_error}"
                )

                return

            encrypted_key = base64.b64encode(
                encrypted_key
            ).decode("utf-8")

            # RSA Direct-Session-Key ML-DSA Origin Authentication
            # (Phase 13.6): signed with this client's own persistent
            # ML-DSA signer (the same one already used for identity
            # announcements, messages, and group-key distribution)
            # over the canonical envelope crypto/session_key_protocol.py
            # defines -- AFTER encryption already produced
            # encrypted_key, and BEFORE the packet is ever sent. The
            # private key never leaves self.key_manager.ml_dsa; only
            # the resulting signature bytes are put on the wire.
            session_key_signature = sign_rsa_session_key_payload(
                self.key_manager.ml_dsa,
                self.username,
                receiver,
                conversation_id,
                algorithm,
                encrypted_key,
                epoch,
            )

            send_message(
                self.client_socket,
                create_session_key_packet(
                    sender=self.username,
                    receiver=receiver,
                    algorithm=algorithm,
                    encrypted_key=encrypted_key,
                    epoch=epoch,
                    conversation_id=conversation_id,
                    session_key_signature=base64.b64encode(
                        session_key_signature
                    ).decode("ascii"),
                ),
            )

        self.logger.info(
            f"Secure session established with {receiver}"
        )

        time.sleep(0.2)

    def send_chat_message(self, message, reply_to_message_id=None, client_message_id=None):
        """
        Encrypt and send a text message to the currently open
        conversation -- direct or group (Phase 4 -- Secure Group
        Messaging Foundation). A thin, TEXT-specific wrapper around
        _send_encrypted_payload() (Phase 8 -- File & Image Transfer):
        signature and behavior are unchanged from before Phase 8.

        ``reply_to_message_id`` (Phase 19.24 -- Message Lifecycle
        Events, Reply): optional, the real message_id (as returned by
        history/live receipt) this send is a reply to. None for an
        ordinary send -- every pre-existing caller is unaffected.

        ``client_message_id`` (Phase 19.24 -- Message Retry
        idempotency): pass the SAME value a previous, failed call to
        this method returned to make a retry of the exact same content
        idempotent -- see _send_encrypted_payload()'s own docstring.
        None (the default) generates a fresh one, correct for a
        brand-new send.

        Returns the client_message_id actually used, so a caller that
        might need to retry this exact send later (gui/chat_window.py::
        send_message()'s failure path) can capture and re-supply it.
        """

        return self._send_encrypted_payload(
            PayloadType.TEXT,
            message,
            content_metadata=None,
            preview_text=message,
            reply_to_message_id=reply_to_message_id,
            client_message_id=client_message_id,
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

    def _send_encrypted_payload(
        self, payload_type, content, content_metadata, preview_text,
        reply_to_message_id=None, client_message_id=None,
    ):
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

        Phase 19.24 -- Message Retry idempotency: every send carries a
        client_message_id -- a caller-supplied one (a retry, reusing
        the value captured from the ORIGINAL attempt BEFORE it was
        made, so it survives even if that attempt raised before ever
        returning anything -- see gui/chat_window.py::send_message()'s
        own comment) or, if none is given, a fresh one generated here
        for an ordinary first send. Either way, persist_message() on
        the server treats a second arrival of the SAME client_message_
        id as the SAME message, never a duplicate -- see server/
        client_handler.py::persist_message()'s own docstring. Returns
        the id actually used so a caller that did NOT pre-generate one
        (send_attachment() et al.) can still capture it if it wants
        retry-safety for a later call.
        """

        client_message_id = client_message_id or str(uuid.uuid4())

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

        # Message-Level ML-DSA Origin Authentication: signed with this
        # client's own persistent ML-DSA signer (the same one Phase 11
        # already uses for the identity-announcement packet) over the
        # canonical envelope crypto/message_protocol.py defines --
        # AFTER encryption already produced envelope.ciphertext, and
        # BEFORE the packet is ever sent. The private key never leaves
        # self.key_manager.ml_dsa; only the resulting signature bytes
        # are put on the wire. receiver/conversation_id are passed
        # exactly as they will appear on the packet below -- whichever
        # one is None here is also None there, so the receiver
        # reconstructs the identical canonical payload.
        receiver = self.current_chat if not self.current_chat_is_group else None
        conversation_id = self.current_chat if self.current_chat_is_group else None

        message_signature = sign_message_payload(
            self.key_manager.ml_dsa,
            self.username,
            receiver,
            conversation_id,
            envelope.payload_type,
            envelope.ciphertext,
            envelope.content_metadata,
            epoch,
        )

        if self.current_chat_is_group:

            packet = create_payload_packet(
                sender=self.username,
                envelope=envelope,
                timestamp=sent_at.isoformat(),
                conversation_id=self.current_chat,
                epoch=epoch,
                message_signature=base64.b64encode(message_signature).decode("ascii"),
                sender_device_id=self.device_id,
                reply_to_message_id=reply_to_message_id,
                client_message_id=client_message_id,
            )

        else:

            packet = create_payload_packet(
                sender=self.username,
                envelope=envelope,
                timestamp=sent_at.isoformat(),
                receiver=self.current_chat,
                epoch=epoch,
                message_signature=base64.b64encode(message_signature).decode("ascii"),
                sender_device_id=self.device_id,
                reply_to_message_id=reply_to_message_id,
                client_message_id=client_message_id,
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
            # This is the first time ConversationStore may ever learn
            # of a fresh direct conversation -- set_current_chat()
            # deliberately left it uncached (see
            # _resolve_direct_conversation_id()'s docstring). Ignored
            # by record_message() if an entry already exists.
            conversation_id=self.current_conversation_id,
        )

        return client_message_id

    # ==================================================================
    # Phase 19.24 -- Message Lifecycle Events (edit/delete/reactions).
    #
    # Edit is scoped to PayloadType.TEXT messages only -- re-encrypting
    # a FILE/IMAGE's binary content in place is out of scope for this
    # phase (there is no UI to produce new binary content for an
    # "edit"; the mandate's own examples are text-only). Reactions
    # apply to any message kind.
    # ==================================================================

    def edit_message(self, conversation_id, message_id, new_text, expected_edit_version):
        """
        Re-encrypt ``message_id``'s content as ``new_text`` (Phase
        19.24). Only the original sender can succeed -- enforced
        server-side (server/client_handler.py::handle_message_edit()),
        never merely by this client choosing not to offer the button;
        a forged request from a non-sender is rejected there
        regardless of what this method sends.

        ``expected_edit_version``: this client's last-known edit_
        version for the message (0 for never-edited) -- the caller
        (GUI) is expected to pass back whatever it currently has
        displayed, so a stale edit (based on an outdated view of the
        message) is rejected server-side rather than silently
        clobbering a newer one.

        ``conversation_id`` is required explicitly (unlike a fresh
        send, which addresses whatever self.current_chat is) --
        editing/reacting to a message the user can already see does
        not require that conversation to be the one currently open,
        and this client already holds its key (it decrypted the
        original message to display it), so no establish_session_key()
        round trip is needed or attempted here.

        Signed with EDIT_PAYLOAD_PURPOSE (continued Phase 19.24 --
        receiver-side verification), addressed by the real
        conversation_id alone (never receiver/None-conversation_id
        direct-vs-group branching an ordinary send needs) -- a
        deliberately simpler canonical shape than a fresh chat send,
        since by the time a client is editing a message it already
        knows exactly which conversation it belongs to.
        """

        session_key = self.key_manager.get_key(conversation_id)

        if session_key is None:
            raise RuntimeError(f"No encryption key for conversation {conversation_id}")

        aes = AESCipher(session_key)

        envelope = self._adapter_for(PayloadType.TEXT).encrypt(
            new_text, aes, content_metadata=None
        )

        epoch = self.key_manager.current_epoch(conversation_id) or 1

        message_signature = sign_message_payload(
            self.key_manager.ml_dsa,
            self.username,
            None,
            conversation_id,
            envelope.payload_type,
            envelope.ciphertext,
            envelope.content_metadata,
            epoch,
            purpose=EDIT_PAYLOAD_PURPOSE,
        )

        send_message(
            self.client_socket,
            create_message_edit_packet(
                message_id=message_id,
                envelope=envelope,
                epoch=epoch,
                message_signature=base64.b64encode(message_signature).decode("ascii"),
                expected_edit_version=expected_edit_version,
            ),
        )

    def delete_message_for_me(self, message_id):
        """
        Hide ``message_id`` from this account's own view only, on
        every one of this account's authorized devices (Phase 19.24).
        Fire-and-forget, like send_chat_message() -- there is no
        failure mode meaningful to surface synchronously beyond a
        socket-level exception, which propagates to the caller exactly
        like every other send_* method here.
        """

        send_message(
            self.client_socket,
            create_message_delete_for_me_packet(message_id=message_id),
        )

    def delete_message_for_everyone(self, message_id):
        """
        Request REAL, authorized global deletion of ``message_id``
        (Phase 19.24). Only the original sender can succeed --
        enforced server-side (server/client_handler.py::handle_
        message_delete_for_everyone()), never merely by this client
        choosing not to offer the button.
        """

        send_message(
            self.client_socket,
            create_message_delete_for_everyone_packet(message_id=message_id),
        )

    def add_reaction(self, conversation_id, message_id, reaction):
        """
        Set/replace this account's reaction on ``message_id`` (Phase
        19.24). ``reaction`` is a short string (typically a single
        emoji) -- E2E encrypted under the message's own conversation
        key, exactly like a text message; the server never learns
        which reaction was chosen (payload/reaction_adapter.py).

        ``conversation_id`` is required explicitly -- see edit_
        message()'s identical docstring note for why (reacting to a
        message does not require that conversation to be the one
        currently open).
        """

        session_key = self.key_manager.get_key(conversation_id)

        if session_key is None:
            raise RuntimeError(f"No encryption key for conversation {conversation_id}")

        aes = AESCipher(session_key)

        envelope = self._adapter_for(PayloadType.REACTION).encrypt(
            reaction, aes, content_metadata=None
        )

        epoch = self.key_manager.current_epoch(conversation_id) or 1

        # Continued Phase 19.24 -- receiver-side verification: signed
        # exactly like edit_message(), with its own distinct purpose
        # tag so an edit and a reaction (or an ordinary chat message)
        # can never be confused for one another.
        message_signature = sign_message_payload(
            self.key_manager.ml_dsa,
            self.username,
            None,
            conversation_id,
            envelope.payload_type,
            envelope.ciphertext,
            envelope.content_metadata,
            epoch,
            purpose=REACTION_PAYLOAD_PURPOSE,
        )

        send_message(
            self.client_socket,
            create_reaction_add_packet(
                message_id=message_id, envelope=envelope, epoch=epoch,
                message_signature=base64.b64encode(message_signature).decode("ascii"),
            ),
        )

    def remove_reaction(self, message_id):
        """Remove this account's reaction from ``message_id``, if any
        (Phase 19.24). Idempotent -- a no-op server-side if there was
        nothing to remove."""

        send_message(
            self.client_socket,
            create_reaction_remove_packet(message_id=message_id),
        )

    def pin_message(self, message_id):
        """
        Pin ``message_id`` for every member of its conversation (Phase
        19.24 -- Pinned Messages). No content to encrypt -- see
        database/models/message.py::pinned_at's own trust-model
        docstring for why this needs no envelope/signature, unlike
        add_reaction()/edit_message() just above.
        """

        send_message(
            self.client_socket,
            create_message_pin_packet(message_id=message_id),
        )

    def unpin_message(self, message_id):
        """Unpin ``message_id``, if currently pinned (Phase 19.24).
        Idempotent -- a no-op server-side if it was already unpinned."""

        send_message(
            self.client_socket,
            create_message_unpin_packet(message_id=message_id),
        )

    def forward_message(self, target_chat, target_is_group, payload_type, content, content_metadata=None):
        """
        Forward already-decrypted local content to a DIFFERENT
        recipient/conversation (Phase 19.24). Deliberately reuses the
        NORMAL send pipeline end to end -- this method only swaps
        self.current_chat/self.current_chat_is_group/self.current_
        conversation_id to the forward TARGET first, exactly like
        opening that conversation and composing fresh content into it,
        restoring the caller's original open chat afterward regardless
        of outcome.

        This produces a genuinely NEW, independently encrypted message
        under the TARGET conversation's own key -- never a reuse of
        the original message's ciphertext (which was encrypted for a
        different key/recipient entirely and is meaningless outside
        that context). ``content_metadata`` carries {"forwarded": True}
        forward, additively, alongside whatever the payload type's own
        metadata already is (e.g. filename/mime_type for an
        attachment) -- purely a client-side UI hint ("Forwarded"
        label), never trusted for anything security-relevant.

        BUG FIX (continued Phase 19.24): self.current_conversation_id
        MUST also be swapped to the target's real conversation_id, not
        merely self.current_chat/self.current_chat_is_group.
        establish_session_key() (called by _send_encrypted_payload()
        below for a direct target) addresses its "has a key already
        been generated for this?"/"which conversation_id do I store
        this new key under?" checks ENTIRELY via self.current_
        conversation_id, never by re-deriving it from self.current_chat
        -- left stale (still pointing at whatever conversation was
        open before this call), a forward whose ORIGINAL conversation
        already had an established key would silently reuse THAT
        conversation's key for the target instead of generating (or
        reusing) the TARGET's own, making the forwarded message
        undecryptable by its actual recipient (or, worse, decryptable
        under a key some other, unrelated conversation's members also
        hold). A group target's conversation_id is already known
        (target_chat itself, by the same convention ConversationSummary.
        key uses); a direct target's is resolved via the same server
        get-or-create request set_current_chat() itself would use.

        Returns the client_message_id used, exactly like send_chat_
        message()/send_attachment(), for retry-safety.
        """

        original_chat = self.current_chat
        original_is_group = self.current_chat_is_group
        original_conversation_id = self.current_conversation_id

        try:
            self.current_chat = target_chat
            self.current_chat_is_group = target_is_group
            self.current_conversation_id = (
                target_chat if target_is_group
                else self._resolve_direct_conversation_id(target_chat)
            )

            forward_metadata = dict(content_metadata or {})
            forward_metadata["forwarded"] = True

            return self._send_encrypted_payload(
                payload_type,
                content,
                content_metadata=forward_metadata,
                preview_text=content if payload_type == PayloadType.TEXT else None,
            )
        finally:
            self.current_chat = original_chat
            self.current_chat_is_group = original_is_group
            self.current_conversation_id = original_conversation_id

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

            fetched_ciphertext = response.get("ciphertext")

            # Message-Level ML-DSA Origin Authentication: verified here,
            # now that the real ciphertext is finally available (it was
            # never inline in ``message`` -- see load_conversation_
            # history()'s own comment on why blob-stored payload types
            # are verified in this method instead of there).
            if not self._verify_history_message_signature(message, fetched_ciphertext):
                return None

            payload_type = message.get("payload_type") or PayloadType.TEXT

            envelope = PayloadEnvelope(
                payload_type=payload_type,
                ciphertext=fetched_ciphertext,
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

            # Phase 19.24 -- Message Lifecycle Events: a real delete-
            # for-everyone has ALREADY nulled ciphertext/blob_ref/
            # content_metadata/message_signature server-side (see
            # handle_message_delete_for_everyone()) -- there is
            # genuinely nothing left to verify or decrypt, and
            # attempting either would misreport this row as merely
            # "undecryptable" rather than deleted. Checked first, before
            # any verify/decrypt/blob-fetch is even attempted.
            is_deleted = bool(entry.get("deleted_at"))

            if is_deleted:
                text = ""
                content = None

            # Message-Level ML-DSA Origin Authentication: verified
            # BEFORE any decryption is attempted, for own messages and
            # received ones alike -- a signature is exactly as required
            # for offline/persisted history as it is on the live "chat"
            # packet (see _verify_chat_message_signature()'s docstring
            # for the shared trust-boundary rationale). A message that
            # fails verification is never decrypted -- it is reported
            # exactly like an undecryptable one, never distinguished in
            # a way that would let a forged entry be told apart from a
            # genuinely-lost key by anything reading this method's
            # return value.
            #
            # Phase 8 -- File & Image Transfer: TEXT's ciphertext is
            # inline in ``entry`` (verified here, directly); a blob-
            # stored payload_type's ciphertext is NOT (entry["ciphertext"]
            # is None -- see handle_message_history_request()) -- it is
            # fetched lazily, on demand, by _load_blob_history_content(),
            # which is where THAT ciphertext's signature is verified
            # instead (the exact bytes to verify do not exist here yet).
            elif payload_type in BLOB_STORAGE_PAYLOAD_TYPES:
                text = None
                content = self._load_blob_history_content(
                    self.current_conversation_id, entry, epoch
                )
            elif not self._verify_history_message_signature(
                entry, entry.get("ciphertext")
            ):
                text = _UNDECRYPTABLE_PLACEHOLDER
                content = None
            else:
                text = self._decrypt_history_message(
                    self.current_conversation_id,
                    entry.get("ciphertext"),
                    epoch=epoch,
                )
                content = None

            # Phase 19.24 -- Message Lifecycle Events: reactions are
            # verified/decrypted the same way handle_reaction_updated()
            # verifies/decrypts a LIVE one (_verify_lifecycle_event_
            # signature()/_decrypt_lifecycle_event_content()) -- history
            # recovery must apply the identical receiver-side trust
            # check, not merely trust the server relayed the right
            # ciphertext/reactor pairing. A reaction that fails
            # verification is silently dropped from the rendered list
            # (never shown, never fatal to the rest of history), exactly
            # like an unverifiable edit/reaction is dropped live.
            reactions = []

            for reaction_entry in entry.get("reactions") or []:

                reactor = reaction_entry.get("user") or ""
                reaction_ciphertext = reaction_entry.get("ciphertext")

                if not reactor or not reaction_ciphertext:
                    continue

                if not self._verify_lifecycle_event_signature(
                    reactor, self.current_conversation_id, PayloadType.REACTION,
                    reaction_ciphertext, None, reaction_entry.get("epoch"),
                    reaction_entry.get("message_signature"), REACTION_PAYLOAD_PURPOSE,
                    "reaction (history)",
                ):
                    continue

                reactions.append({
                    "user": reactor,
                    "reaction": self._decrypt_lifecycle_event_content(
                        self.current_conversation_id, PayloadType.REACTION,
                        reaction_ciphertext, reaction_entry.get("epoch"),
                    ),
                })

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
                "reply_to_message_id": entry.get("reply_to_message_id"),
                "is_deleted": is_deleted,
                "edit_version": int(entry.get("edit_version") or 0),
                "reactions": reactions,
                # Phase 19.24 -- Pinned Messages: recovered on every
                # history load exactly like edit/delete/reaction state
                # above (server/client_handler.py::handle_message_
                # history_request()'s own identical comment).
                "is_pinned": bool(entry.get("pinned_at")),
                "pinned_by": entry.get("pinned_by"),
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

        # Phase 19 manual acceptance defect fix: a real physical-device
        # test found _UNDECRYPTABLE_PLACEHOLDER's internal diagnostic
        # string leaking into the sidebar preview row, overlapping the
        # unread indicator. _decrypt_history_message() is intentionally
        # NOT changed -- gui/chat_window.py's open-conversation history
        # rendering (the OTHER, legitimate caller, load_conversation_
        # history() above) still shows that exact placeholder as a real
        # message bubble for a genuinely undecryptable historical
        # message, which is correct and must not change. Only THIS
        # sidebar-preview call site substitutes None, which
        # MessagePreview.render()'s "self.text or ''" already turns
        # into an empty string -- gui/conversation_list_widget.py's
        # existing "No messages yet" fallback only fires when
        # summary.latest_message itself is None (a conversation with
        # zero messages), so an undecryptable-but-real latest message
        # now shows a blank preview line instead -- the same "no
        # preview text" neutral state, not a new one.
        if text == _UNDECRYPTABLE_PLACEHOLDER:
            text = None

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

        Also seeds unread_counts from each conversation's server-
        reported unread_count (BUG -- Offline Unread/Notification),
        via set_unread_count() -- an absolute value, never
        increment_unread(), which remains exclusively for a live
        message arriving after this point. This is what makes a
        conversation's unread state correct the moment a user logs
        in, including for messages that arrived entirely while they
        were offline: previously unread_counts started empty here and
        was populated only by live arrivals, so nothing sent while
        this client was disconnected ever showed as unread.
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
                        admin=conversation.get("admin_username"),
                    )
                )

                # BUG -- Offline Unread/Notification: seed the count
                # from the server's authoritative value, not the
                # live-arrival-only increment_unread() path -- see
                # set_unread_count()'s docstring.
                self.set_unread_count(
                    conversation_id, conversation.get("unread_count") or 0
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

            # BUG -- Offline Unread/Notification: see the identical
            # call in the group branch above.
            self.set_unread_count(
                partner_username, conversation.get("unread_count") or 0
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

        elif packet_type == "message_delivered":
            self.handle_message_delivered(packet)

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

        elif packet_type == "device_key_sync":
            self.handle_device_key_sync(packet)

        elif packet_type == "group_member_left":
            self.handle_group_member_left(packet)

        elif packet_type == "group_key_rotation_required":
            self.handle_group_key_rotation_required(packet)

        elif packet_type == "group_members_added":
            self.handle_group_members_added(packet)

        elif packet_type == "read_receipt_notification":
            self.handle_read_receipt_notification(packet)

        # Phase 19.24 -- Message Lifecycle Events.
        elif packet_type == "message_edited":
            self.handle_message_edited(packet)

        elif packet_type == "message_deleted":
            self.handle_message_deleted(packet)

        elif packet_type == "reaction_updated":
            self.handle_reaction_updated(packet)

        elif packet_type == "message_pinned":
            self.handle_message_pinned(packet)

        elif packet_type == "message_unpinned":
            self.handle_message_unpinned(packet)

        elif packet_type == "typing_indicator_notification":
            self.handle_typing_indicator_notification(packet)

        elif packet_type == "inbox_notification":
            self.inbox_updated.emit(packet.get("notification") or {})

        elif packet_type == "inbox_response_result":
            notification = packet.get("notification") or {}
            self._complete_requester_side_verification(notification)
            self.inbox_updated.emit(notification)

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

        # UI Finalization Decision (internal message cleanup): this is
        # connection/presence state, not a user-authored message -- it
        # no longer surfaces as a chat bubble. Still fully logged
        # above for debugging; nothing about join handling itself
        # changed.

    # ----------------------------------------------------------

    def handle_leave(self, packet):

        username = packet["username"]

        self.logger.info(
            f"{username} left"
        )

        # UI Finalization Decision (internal message cleanup): see
        # handle_join()'s identical note -- presence state, logged,
        # not shown as a chat bubble.

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

        # Message-Level ML-DSA Origin Authentication: verified FIRST,
        # from the packet's own raw fields, before anything else in
        # this method runs -- no conversation-store caching, no
        # session-key lookup, no decryption. See _verify_chat_message_
        # signature()'s own docstring for the full trust-boundary
        # rationale (in particular: the verification key is resolved
        # from THIS receiver's own peer-identity state, never from
        # anything inside the packet).
        if not self._verify_chat_message_signature(packet):
            return

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

            # Phase 19.24 (continued) -- see message_id_received's own
            # declaration. A relayed packet always carries message_id
            # (server/client_handler.py stamps it before sending), but
            # the guard keeps this additive-only in case of a malformed
            #/legacy packet.
            message_id = packet.get("message_id")

            if message_id:
                self.message_id_received.emit(identity_key, message_id)

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

        # Phase 19.24 (continued) -- see message_id_received's own
        # declaration, and the identical emission on the TEXT branch
        # above.
        message_id = packet.get("message_id")

        if message_id:
            self.message_id_received.emit(identity_key, message_id)

    # Phase 16D -- Multi-Device Security Hardening + Device-Aware Peer
    # Identity: every peer-trust-state method below (_resolve_trusted_
    # signing_key, get_peer_verification_state, _peer_key_is_verified,
    # _sender_trust_rejection_reason, _is_verified_identity_mismatch,
    # _flag_peer_identity_changed, _record_peer_identity_observation,
    # _currently_observed_peer_identity, get_peer_fingerprint_for_
    # verification, confirm_peer_verification,
    # confirm_combined_peer_verification, observe_peer_identity) takes
    # an OPTIONAL trailing ``device_id`` parameter and, as its very
    # first step, rewrites its own ``username`` argument through this
    # helper before doing anything else. Every one of these methods
    # already treats "username" as a fully opaque string key into a
    # dict or into SecureKeyStore (Phase 16C already proved this by
    # passing a bare device_id in as the "username" argument for
    # device-peer trust, with zero changes needed) -- so composing the
    # key here, once, is sufficient to make the WHOLE existing trust
    # machinery (VERIFIED/UNVERIFIED/KEY_CHANGED, unchanged) track a
    # SPECIFIC (account, device) pair instead of colliding every
    # device of the same account into one slot, without duplicating or
    # rewriting a single line of the state machine itself.
    #
    # device_id defaults to None everywhere a caller does not pass it
    # (every pre-existing call site, and every one of the 122 baseline
    # regression tests) -- in that case this returns ``username``
    # completely unchanged, so behavior is byte-for-byte identical to
    # before this phase. Only a caller that is genuinely device-aware
    # (the identity-broadcast path once self.device_id is set, and the
    # ordinary chat-message path once a packet carries a
    # sender_device_id) ever passes a real device_id, and only then
    # does a second, independently-tracked device identity slot come
    # into existence for that (username, device_id) pair -- this is
    # the "logical account identity vs. cryptographic device identity"
    # split docs/architecture/multi_device_identity.md's Phase 16D
    # section describes.
    #
    # Deliberately NOT applied to KeyManager.public_keys (the KEM
    # encryption-target cache) -- that remains a single, account-level
    # "most recently observed key for this username" convenience slot,
    # exactly as before. Splitting THAT by device as well would change
    # which key ordinary establish_session_key()/wrap_key_for_member()
    # calls encrypt to, a materially larger behavior change than this
    # phase's "smallest architecture necessary" scope calls for; the
    # dedicated device_key_sync protocol (Phase 16C) already exists for
    # the case where a SPECIFIC device needs to be the encryption
    # target.
    _DEVICE_IDENTITY_KEY_SEPARATOR = "\x1f"

    def _peer_identity_key(self, username, device_id=None):
        if device_id:
            return f"{username}{self._DEVICE_IDENTITY_KEY_SEPARATOR}{device_id}"

        return username

    def _effective_peer_identity_key(self, username, device_id=None):
        """
        Same as _peer_identity_key(), except a caller that does not
        know a specific device_id (device_id=None -- every ordinary
        "do I trust this account" caller: get_peer_verification_state,
        _resolve_trusted_signing_key, _currently_observed_peer_public_
        key/_currently_observed_peer_identity, confirm_peer_
        verification/confirm_combined_peer_verification) is redirected
        to whatever device-scoped slot _device_scoped_identity_keys
        last recorded for this username, but ONLY when the plain
        account-level key has no record of its own -- checked first,
        against every source get_peer_verification_state()/
        _currently_observed_peer_public_key() themselves already read.

        This ordering matters: a peer can legitimately have BOTH a
        plain-key record (e.g. observe_peer_identity() called directly
        with no device_id, or a genuinely non-device-announced
        contact) and a stale/unrelated device-scoped record (e.g. a
        one-off device_id-carrying announcement from earlier in this
        peer's connection history). The plain key, when present, is
        always this account's current, authoritative identity -- never
        shadowed by a same-username device-scoped slot that some other
        call path happened to populate. The redirect exists solely for
        the case the plain key was NEVER populated at all (every
        enrolled mobile device's ordinary announcement, which is the
        gap this method exists to close).

        A caller that DOES pass a real device_id is never redirected
        -- this only ever changes the device_id=None case.
        """

        if device_id:
            return self._peer_identity_key(username, device_id)

        has_plain_record = (
            username in self._pending_key_changed_raw_keys
            or username in self._observed_peer_raw_public_keys
            or username in self._peer_keys_changed
            or (
                self.key_store is not None
                and self.key_store.get_peer_verification(username) is not None
            )
        )

        if has_plain_record:
            return username

        fallback_device_id = self._device_scoped_identity_keys.get(username)

        if fallback_device_id:
            return self._peer_identity_key(username, fallback_device_id)

        return username

    def _resolve_trusted_signing_key(self, username, device_id=None):
        """
        Returns the raw ML-DSA public-key bytes this RECEIVER currently
        trusts/observes for ``username``, or None if nothing is known
        yet -- the CRITICAL TRUST RULE for message authentication (see
        crypto/message_protocol.py's own docstring): the verification
        key always comes from THIS session's own peer-identity state
        (populated exclusively by _handle_signed_public_key(), which
        already required an ML-DSA signature to accept it in the first
        place -- Phase 11/12A), never from anything inside the message
        packet being verified. A message packet carries no signing-key
        field at all for a malicious sender to substitute one into.

        Same pending-first precedence as _currently_observed_peer_
        identity()'s signing half: if this peer currently has a
        pending KEY_CHANGED, that (new, disputed) key is what a
        message claiming to be from them right now must verify under
        -- never a stale, no-longer-current key left over from before
        the change.

        Falls back to SecureKeyStore.get_peer_signing_public_key() when
        the session-local cache has nothing: that cache is populated
        only by a live signed public-key packet actually arriving this
        session, which never happens for a peer who is not currently
        online (e.g. right after THIS session's own restart, before
        they reconnect) -- without this fallback, offline/history
        verification of an already-legitimately-observed-or-VERIFIED
        peer's past messages would be permanently impossible after
        every restart. A pending KEY_CHANGED is deliberately NOT
        persisted (see _flag_peer_identity_changed()) and so is never
        found here -- only the still-trusted, previously-recorded key
        is.

        ``device_id`` (Phase 16D): see this class's _peer_identity_key()
        for the composite-key convention this optionally routes
        through.
        """

        username = self._effective_peer_identity_key(username, device_id)

        if username in self._pending_key_changed_signing_raw_keys:
            return self._pending_key_changed_signing_raw_keys[username]

        cached = self._observed_peer_signing_public_keys.get(username)

        if cached is not None:
            return cached

        if self.key_store is None:
            return None

        return self.key_store.get_peer_signing_public_key(username)

    def _verify_chat_message_signature(self, packet):
        """
        Message-Level ML-DSA Origin Authentication: verifies that
        ``packet`` (a "chat" packet -- direct or group) was genuinely
        produced by whoever this receiver currently trusts/observes as
        holding ``packet["sender"]``'s ML-DSA private key. Called FIRST
        by handle_chat(), before any decryption, display, storage, or
        conversation-store side effect.

        There is no legacy unsigned message path (unlike the identity-
        announcement packet's deliberately-preserved defense-in-depth
        legacy branch, see client/session.py::handle_public_key()'s own
        docstring): a message packet never establishes trust the way an
        identity packet's mismatch-detection does, so an unsigned one
        has no legitimate function to preserve. A missing or malformed
        message_signature, an unresolvable verification key (this
        receiver has never observed ANY ML-DSA identity for this
        sender), or a signature that simply does not verify are all
        rejected identically: the message is dropped, logged, and
        never reaches decryption -- fail closed, never fatal to the
        receiver thread.

        Reconstructs the canonical payload from the packet's OWN raw
        "receiver"/"conversation_id" fields (not the locally-resolved
        identity_key/key_conversation_id computed later in handle_
        chat() -- those incorporate server-added bookkeeping like
        direct_conversation_id that the sender never signed over).

        Returns True only if the signature verified successfully.
        """

        sender = packet["sender"]

        signature_b64 = packet.get("message_signature")

        if signature_b64 is None:
            self.logger.warning(
                f"SECURITY: rejected unsigned chat message claiming to "
                f"be from {sender}; ML-DSA message signature is "
                f"required."
            )
            return False

        # Phase 16D -- Device-Aware Peer Identity: sender_device_id is
        # unsigned transport metadata (see create_payload_packet()'s
        # own comment) -- it only SELECTS which trust-state slot to
        # check; the ML-DSA signature below is still verified against
        # whatever key that resolves to, so a tampered/forged value
        # can only cause a fail-closed rejection, never a false accept.
        sender_device_id = packet.get("sender_device_id")

        signing_public_key = self._resolve_trusted_signing_key(
            sender, device_id=sender_device_id
        )

        if signing_public_key is None:
            self.logger.warning(
                f"SECURITY: rejected chat message from {sender}: no "
                f"ML-DSA identity has ever been observed for them; "
                f"cannot verify origin."
            )
            return False

        try:
            signature = base64.b64decode(signature_b64, validate=True)

            verified = verify_message_payload(
                sender,
                packet.get("receiver"),
                packet.get("conversation_id"),
                packet.get("payload_type") or PayloadType.TEXT,
                packet.get("message"),
                packet.get("content_metadata"),
                packet.get("epoch"),
                signature,
                signing_public_key,
            )

        except (TypeError, ValueError) as error:
            # Malformed base64, wrong-length signature/key, or a
            # structurally invalid field -- a data error describing
            # untrusted network input, never a bug in this codebase
            # (mirrors crypto/identity_protocol.py's own established
            # convention). Rejected the same way an outright invalid
            # signature is below.
            self.logger.warning(
                f"SECURITY: rejected malformed signed chat message "
                f"from {sender}: {error}"
            )
            return False

        if not verified:
            self.logger.warning(
                f"SECURITY: ML-DSA signature verification FAILED for "
                f"a chat message claiming to be from {sender}; "
                f"rejecting -- message not decrypted, displayed, or "
                f"stored."
            )
            return False

        return True

    def _verify_history_message_signature(self, entry, ciphertext):
        """
        The offline/persisted-history counterpart of
        _verify_chat_message_signature() -- verifies one
        load_conversation_history() entry (as returned by server/
        client_handler.py::handle_message_history_request(), which now
        carries message_signature/receiver/conversation_id alongside
        every stored message -- see that function's own comment)
        against the SAME canonical construction the original sender
        signed at send time. Proves the signature "traveled with the
        authenticated message data" through offline storage and later
        delivery, exactly as required: the server only ever stores and
        relays this column unchanged, never inspecting or needing the
        private key that produced it.

        ``ciphertext`` is passed explicitly rather than read from
        ``entry["ciphertext"]`` because that field is None for a
        blob-stored payload type (Option A -- lazy blob delivery) --
        the caller (_load_blob_history_content()) only has the real
        ciphertext bytes after its own fetch, and passes those in.

        Own messages (entry["is_own"] is True) are a special case:
        this session never "observes" its OWN ML-DSA identity the way
        it observes a peer's (there is no incoming public-key packet
        for oneself), so the verification key here is this session's
        own persistent self.key_manager.ml_dsa public key instead of a
        peer-resolved one -- otherwise every message this user ever
        sent would fail its own signature check the moment it was
        loaded back from history, which would be a bug, not security.

        Returns True only if the signature verified successfully.
        """

        sender = entry.get("sender")

        signature_b64 = entry.get("message_signature")

        if signature_b64 is None:
            self.logger.warning(
                f"SECURITY: rejected unsigned historical message "
                f"claiming to be from {sender}; ML-DSA message "
                f"signature is required."
            )
            return False

        if entry.get("is_own"):
            signing_public_key = self.key_manager.ml_dsa.export_public_key()
        else:
            signing_public_key = self._resolve_trusted_signing_key(sender)

        if signing_public_key is None:
            self.logger.warning(
                f"SECURITY: rejected historical message from {sender}: "
                f"no ML-DSA identity has ever been observed for them; "
                f"cannot verify origin."
            )
            return False

        # BUG FIX (continued Phase 19.24): an EDITED message's stored
        # message_signature column was overwritten by apply_edit() with
        # the EDIT's own signature (server/client_handler.py::handle_
        # message_edit() persists exactly the signature edit_message()
        # produced, under EDIT_PAYLOAD_PURPOSE and edit_message()'s own
        # simpler (receiver=None, conversation_id=<real conversation_id>)
        # addressing -- see its docstring) -- NOT the original send's
        # ordinary-purpose signature, which no longer exists anywhere.
        # Verifying such a row under the ordinary MESSAGE_PAYLOAD_
        # PURPOSE (and the history row's own receiver/conversation_id
        # fields, which reflect the ORIGINAL message's addressing, not
        # the edit's) always failed, silently turning every edited
        # message into "undecryptable" (or, on mobile, into a message
        # that vanishes from history entirely) on every reload after
        # the first edit -- a real bug, not a security finding: the
        # signature is genuinely valid, just under a different,
        # entirely legitimate canonical construction this check never
        # tried.
        edit_version = entry.get("edit_version") or 0

        if edit_version:
            receiver = None
            conversation_id = self.current_conversation_id
            purpose = EDIT_PAYLOAD_PURPOSE
        else:
            receiver = entry.get("receiver")
            conversation_id = entry.get("conversation_id")
            purpose = MESSAGE_PAYLOAD_PURPOSE

        try:
            signature = base64.b64decode(signature_b64, validate=True)

            verified = verify_message_payload(
                sender,
                receiver,
                conversation_id,
                entry.get("payload_type") or PayloadType.TEXT,
                ciphertext,
                entry.get("content_metadata"),
                entry.get("epoch"),
                signature,
                signing_public_key,
                purpose=purpose,
            )

        except (TypeError, ValueError) as error:
            self.logger.warning(
                f"SECURITY: rejected malformed signed historical "
                f"message from {sender}: {error}"
            )
            return False

        if not verified:
            self.logger.warning(
                f"SECURITY: ML-DSA signature verification FAILED for "
                f"a historical message claiming to be from {sender}; "
                f"rejecting -- message not decrypted or displayed."
            )
            return False

        return True

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

        conversation_id = packet.get("conversation_id")
        message_id = packet.get("message_id")

        if conversation_id and message_id:
            self.own_message_id_resolved.emit(conversation_id, message_id)

    # ----------------------------------------------------------

    def handle_message_delivered(self, packet):
        """
        Phase 19.23 -- Issue 3: the live relay just reached one of
        ``receiver``'s connected devices (server/client_handler.py's
        existing Phase 19.14 "message_delivered" packet). Purely a
        live-update hint, exactly like read_receipt_updated -- the
        authoritative status is always re-derived from history's own
        new "delivery_status" field (see server/client_handler.py::
        _delivery_status_for_own_message()), so a client that never
        receives this signal (conversation not open, or this client
        was offline) is not out of sync; it just sees the correct
        status next time it loads history.
        """

        conversation_id = packet.get("conversation_id")
        receiver = packet.get("receiver")

        if conversation_id and receiver:
            self.message_delivered_updated.emit(conversation_id, receiver)

        message_id = packet.get("message_id")

        if conversation_id and message_id:
            self.own_message_id_resolved.emit(conversation_id, message_id)

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

        # Server-Untrusted Identity Verification, Stage 3: this
        # handler is fully automatic and server-triggered, on the
        # receiver thread -- there is no user action here to raise a
        # PeerNotVerifiedError against (unlike establish_session_key()).
        # Silently declining is the correct outcome, exactly like the
        # has_key() check just above: the recipient's queued messages
        # stay queued, and this same redelivery is retried on their
        # next reconnect -- once verified, that later attempt succeeds
        # with no other change. The user still learns about this
        # peer's state proactively, from the conversation's own
        # verification badge, not from this background handler.
        #
        # `is not None` -- same distinction as establish_session_key():
        # a recipient with no cached public key at all falls through
        # unchanged to wrap_key_for_member()'s own existing
        # ValueError/"no public key" handling below, exactly as before
        # Stage 3. This check only ever fires for a key that IS cached
        # but is not currently PEER_STATE_VERIFIED.
        if (
            self.key_manager.get_public_key(recipient) is not None
            and not self._peer_key_is_verified(recipient)
        ):

            self.logger.warning(
                f"SECURITY: refusing to redeliver key for "
                f"{conversation_id} epoch {epoch} to {recipient}: "
                f"peer is not verified "
                f"({self.get_peer_verification_state(recipient)})."
            )

            # See _declined_redeliveries_awaiting_verification's own
            # comment: retried once this client verifies ``recipient``.
            self._declined_redeliveries_awaiting_verification.setdefault(
                recipient, []
            ).append((conversation_id, epoch))

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

        # Group-Key-Distribution ML-DSA Origin Authentication: signed
        # for the same reason as establish_session_key()'s identical
        # call -- this redelivery goes through the exact same
        # handle_group_key_distribution() on the receiving end.
        group_key_signature = sign_group_key_payload(
            self.key_manager.ml_dsa,
            self.username,
            conversation_id,
            recipient,
            encapsulation,
            wrapped_key,
            epoch,
        )

        send_message(
            self.client_socket,
            create_group_key_distribution_packet(
                sender=self.username,
                conversation_id=conversation_id,
                recipient=recipient,
                encapsulation=encapsulation,
                wrapped_key=wrapped_key,
                epoch=epoch,
                group_key_signature=base64.b64encode(group_key_signature).decode("ascii"),
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

        Server-Untrusted Identity Verification, Stage 2 ENFORCEMENT
        (revised after a security-correctness audit found the first
        version detected a mismatch but never actually stopped it: an
        earlier design ran the fingerprint comparison AFTER
        KeyManager.add_public_key() had already overwritten
        KeyManager.public_keys[username] unconditionally -- so a
        server-substituted key was cached and immediately usable by
        establish_session_key()/wrap_key_for_member()/
        handle_direct_key_redelivery_required() regardless of the
        KEY_CHANGED flag, empirically confirmed to let a malicious
        server extract an already-established AES session key with no
        user interaction at all).

        _is_verified_key_mismatch() now runs FIRST, computed from the
        packet's raw bytes -- before add_public_key() is ever called.
        If it reports a mismatch against a VERIFIED fingerprint, this
        method returns immediately: add_public_key() never runs, so
        KeyManager.public_keys[username] is never touched and keeps
        whatever key was already trusted. Fail closed, not
        detect-then-allow. This is the single point every peer public
        key this client will ever use (direct or group; the server
        relays both through this same packet type) passes through, so
        it is the smallest integration point that covers
        establish_session_key(), wrap_key_for_member(), and every
        reconnect/key-recovery caller that later reads KeyManager.
        get_public_key() -- none of which needed to change themselves.

        Protocol-Level ML-DSA Origin Authentication: a packet carrying
        "signing_public_key" is the AUTHENTICATED identity format --
        routed entirely to _handle_signed_public_key() instead, which
        requires a valid ML-DSA signature before anything below this
        point ever runs. This branch is checked FIRST, before any of
        the legacy logic below, so a packet that declares itself
        authenticated can never fall back to the unsigned path (that
        would let an attacker strip the signature to downgrade a
        packet into the weaker legacy trust level).

        Phase 12A security audit (downgrade attack): a packet with NO
        "signing_public_key" at all is no longer trusted to establish
        OR update ANY identity that is not already VERIFIED. Before
        this audit, an unsigned packet with no existing record at all
        (true first contact) was silently ACCEPTED and installed as a
        new UNVERIFIED observation -- exactly like every packet was
        before Phase 11 ever existed. Since send_public_key() has
        signed unconditionally since Phase 11, no legitimate client
        ever produces an unsigned packet any more; a malicious relay
        could therefore trivially neutralize 100% of Phase 11's
        protection for any never-before-seen peer simply by never
        including the two new fields -- an attacker who controls the
        server (this project's entire threat model) is never forced to
        prove ML-DSA possession at all, defeating the stated purpose of
        Phase 11 outright. See this phase's audit report for the full
        traced control flow.

        The fix: an unsigned packet may now ONLY ever be evaluated as a
        potential mismatch against an EXISTING VERIFIED record (still
        valuable defense-in-depth -- see _is_verified_key_mismatch()/
        _flag_peer_key_changed() below, unchanged) or silently ignored
        as a genuine no-op when it happens to match an existing record
        exactly (nothing to protect, nothing gained by rejecting a
        pointless re-observation). It can never again create a new
        peer-identity record, and can never again update an existing
        UNVERIFIED one -- both of those require cryptographic proof of
        ML-DSA possession now, i.e. going through
        _handle_signed_public_key() instead. Every legitimate
        production flow already satisfies this (send_public_key()
        always signs); only hand-crafted attack-simulation packets in
        this test suite ever construct an unsigned one on purpose.
        """

        if "signing_public_key" in packet:
            self._handle_signed_public_key(packet)
            return

        username = packet["username"]

        public_key = packet["public_key"]

        if self._is_verified_key_mismatch(username, public_key):

            # Fail closed: KeyManager.add_public_key() below is
            # skipped entirely -- the substituted key is never
            # imported or cached, so the trusted key already in
            # KeyManager.public_keys[username] (if any) remains in
            # effect for every cryptographic operation that reads it.
            self._flag_peer_key_changed(username, public_key)

            return

        self.logger.warning(
            f"SECURITY: rejected unsigned public-key packet for "
            f"{username}; ML-DSA-signed identity is required to "
            f"establish or update peer identity state. If this "
            f"disagrees with an already-cached key, nothing changed; "
            f"if this is a genuinely new peer, their key was not "
            f"installed."
        )

    def _handle_signed_public_key(self, packet):
        """
        The AUTHENTICATED counterpart of handle_public_key()'s legacy
        branch (Protocol-Level ML-DSA Origin Authentication) -- handles
        a public-key packet that advertises a "signing_public_key". A
        valid ML-DSA signature is mandatory for every packet reaching
        this method: handle_public_key() only routes here when that
        field is present, and once here, ANY failure (missing
        signature, malformed base64/key/signature, or a well-formed
        signature that simply does not verify) rejects the ENTIRE
        packet -- the KEM key is never installed into KeyManager, the
        signing key is never treated as trusted, and no peer
        fingerprint is recorded. There is deliberately no fallback to
        the legacy unsigned path from here: a packet that already
        declared itself authenticated by including a signing key must
        prove it, never quietly degrade to weaker trust.

        Verification happens BEFORE anything else -- before the
        combined-identity state machine and before KeyManager.
        add_public_key() -- so an invalid signature can never insert
        attacker-controlled key material into either.

        A signature verifying successfully proves only that whoever
        sent this packet controls the private key matching the
        advertised ML-DSA public key -- it does NOT establish that this
        is the claimed human peer (see crypto/identity_protocol.py's
        module docstring). That determination is entirely the combined-
        identity state machine's job (_is_verified_identity_mismatch()/
        _flag_peer_identity_changed()/_record_peer_identity_observation(),
        the same building blocks observe_peer_identity() itself is
        built from -- called directly here, rather than through that
        wrapper, purely to interleave KeyManager.add_public_key() at
        the same point in the sequence handle_public_key()'s legacy
        branch already uses, so state and installed key are never
        observably out of step). Unchanged from the identity/key-
        persistence foundation phase: first contact still becomes
        UNVERIFIED, not VERIFIED; a mismatch against an existing
        VERIFIED identity still becomes KEY_CHANGED, never silently
        replacing the trusted record. This method only decides whether
        the packet is authentic enough to be WORTH handing to that
        state machine at all.
        """

        username = packet["username"]
        algorithm = packet["algorithm"]
        kem_public_key = packet["public_key"]
        signing_public_key_b64 = packet["signing_public_key"]

        # Phase 16D -- Device-Aware Peer Identity: transport metadata
        # only (see create_public_key_packet()'s own comment) -- not
        # part of the ML-DSA-signed identity payload, so it plays no
        # role in verify_identity_payload() below and cannot be used to
        # forge a signature. It only selects WHICH (username, device_id)
        # trust-state slot this identity is recorded under once the
        # signature has already been proven valid.
        device_id = packet.get("device_id")
        signature_b64 = packet.get("identity_signature")

        try:
            if signature_b64 is None:
                raise ValueError("Missing identity_signature.")

            signing_public_key = base64.b64decode(
                signing_public_key_b64, validate=True
            )
            signature = base64.b64decode(signature_b64, validate=True)

            verified = verify_identity_payload(
                username, kem_public_key, signing_public_key, signature
            )

        except (TypeError, ValueError) as error:
            # Covers: missing/malformed base64, wrong-length signing
            # key or signature, a structurally invalid ML-DSA public
            # key -- every case verify_identity_payload()/
            # MLDSASigner.verify() document as a data error rather than
            # "the signature was merely wrong" (base64.b64decode's
            # binascii.Error is itself a ValueError subclass). Any of
            # these means the packet cannot even be evaluated as a
            # signature, let alone trusted -- rejected the same way an
            # outright invalid signature is below.
            self.logger.warning(
                f"SECURITY: rejected malformed signed identity packet "
                f"for {username}: {error}"
            )
            return

        if not verified:
            self.logger.warning(
                f"SECURITY: ML-DSA signature verification FAILED for "
                f"identity packet from {username}; rejecting -- no key "
                f"material installed."
            )
            return

        # Signature verified: this packet genuinely originated from
        # whoever controls signing_public_key's private key. From here
        # the ordering deliberately mirrors handle_public_key()'s
        # legacy branch exactly -- fail-closed mismatch check (a pure
        # predicate, no state mutated yet) FIRST, then KeyManager
        # installation, then peer-identity-state recording LAST -- so
        # that by the time any caller can observe
        # get_peer_verification_state() reflecting this packet,
        # KeyManager.get_public_key() is already usable too (the two
        # were previously updated in the opposite order, which raced:
        # a caller polling for the state to become UNVERIFIED could
        # observe it before the KEM key was actually installed).
        if self._is_verified_identity_mismatch(
            username, kem_public_key, signing_public_key, device_id=device_id
        ):
            # Fail closed: KeyManager.add_public_key() below is skipped
            # entirely -- the substituted identity is never imported or
            # cached, so the trusted key already in KeyManager.
            # public_keys[username] (if any) remains in effect.
            self._flag_peer_identity_changed(
                username, kem_public_key, signing_public_key, device_id=device_id
            )
            return

        try:
            self.key_manager.add_public_key(username, kem_public_key)
        except (ValueError, TypeError) as error:
            self.logger.warning(
                f"Rejected malformed {algorithm} public key from "
                f"{username} after signature verification: {error}"
            )
            return

        self.logger.info(
            f"Stored ML-DSA-authenticated {algorithm} public key for "
            f"{username}"
        )

        # Route through the SAME combined-identity state machine the
        # identity/key-persistence foundation phase already built and
        # tested (tests/test_peer_identity_state_transitions.py) --
        # records the observation as UNVERIFIED (or a no-op if already
        # VERIFIED with matching keys); never promotes to VERIFIED.
        self._record_peer_identity_observation(
            username, kem_public_key, signing_public_key, device_id=device_id
        )

        # See _device_scoped_identity_keys' own comment: a plain dict
        # assignment, not a new store write, so _effective_peer_
        # identity_key() can redirect device_id=None callers to the
        # slot this announcement actually populated above.
        if device_id:
            self._device_scoped_identity_keys[username] = device_id

        self.public_key_received.emit(username)

    def _is_verified_key_mismatch(self, username, raw_public_key):
        """
        True only if this user has an existing VERIFIED fingerprint
        for ``username`` AND the key just received on the wire
        disagrees with it (Server-Untrusted Identity Verification,
        Stage 2 enforcement).

        Deliberately a pure predicate -- no side effects, nothing
        written anywhere -- called from handle_public_key() BEFORE
        KeyManager.add_public_key(), so its answer decides whether
        that call happens at all. Fingerprinted from ``raw_public_key``
        exactly as received on the wire (a base64 string for Kyber,
        PEM text for RSA) via crypto/key_manager.py::
        fingerprint_public_key(), which already accepts either str or
        bytes directly -- the RAW wire value, not whatever
        algorithm-specific object add_public_key() would have parsed
        it into, both because that keeps this algorithm-agnostic with
        no special-casing, and because it is exactly the value a
        malicious server would have to substitute to mount the attack
        this method exists to catch.

        False (never a mismatch) whenever there is nothing VERIFIED to
        compare against: no local key store (this session never
        authenticated with a password), no record at all, or an
        UNVERIFIED one. A first-contact or still-unverified peer's key
        is never blocked here -- Stage 3's future explicit
        verification step is what decides whether the FIRST key ever
        seen for a peer should be trusted, not this method.
        """

        if self.key_store is None:
            return False

        entry = self.key_store.get_peer_verification(username)

        if entry is None or entry["state"] != PEER_STATE_VERIFIED:
            return False

        return entry["fingerprint"] != fingerprint_public_key(raw_public_key)

    def _flag_peer_key_changed(self, username, raw_public_key):
        """
        Record, session-locally only, that the most recently OBSERVED
        key for ``username`` disagreed with their VERIFIED fingerprint
        (Server-Untrusted Identity Verification, Stage 2) -- never
        written to SecureKeyStore (see PEER_KEY_STATE_CHANGED's module
        docstring: this describes a disagreement, not new evidence
        about what should be trusted). Called only from
        handle_public_key(), after it has already decided -- via
        _is_verified_key_mismatch() -- NOT to call KeyManager.
        add_public_key() at all, so by the time this runs the
        substituted key has already been kept out of KeyManager
        entirely; this method only ever records the fact and notifies,
        it never itself touches any key material.

        ``raw_public_key`` is the REJECTED key's raw wire bytes -- the
        same value _is_verified_key_mismatch() just compared, before
        this method is called. Kept in _pending_key_changed_raw_keys
        (session-local, same lifetime as _peer_keys_changed), and its
        fingerprint additionally cached in
        _pending_key_changed_fingerprints, so a verification dialog has
        something to show the user: the rejected key itself was never
        imported or cached anywhere else, so this is the only place it
        (and its fingerprint) can still be read from -- for the user to
        compare and, if they confirm it, re-verify against (see
        get_peer_fingerprint_for_verification()/
        confirm_peer_verification(), the latter of which independently
        re-derives the fingerprint from _pending_key_changed_raw_keys
        rather than trusting a caller-supplied string).

        Protocol-Level ML-DSA Origin Authentication: also clears any
        stale _pending_key_changed_signing_raw_keys entry for
        ``username``. This flag describes a LEGACY (unsigned) packet's
        disagreement -- it carries no signing key at all -- so a
        signing key left over from an EARLIER, unrelated pending
        combined-identity change must not linger and be mistaken by
        confirm_peer_verification() for part of THIS pending change
        (which would silently combine two unrelated observations into
        one nonsensical fingerprint that could never be confirmed).
        """

        self._peer_keys_changed.add(username)

        self._pending_key_changed_fingerprints[username] = (
            fingerprint_public_key(raw_public_key)
        )

        self._pending_key_changed_raw_keys[username] = raw_public_key

        self._pending_key_changed_signing_raw_keys.pop(username, None)

        self.logger.warning(
            f"SECURITY: public key received for {username} does not "
            f"match the previously verified fingerprint -- the new "
            f"key was NOT imported into KeyManager, and the trusted "
            f"key already cached (if any) remains in effect. Treating "
            f"as KEY_CHANGED."
        )

        self.peer_key_changed.emit(username)

    def _record_peer_key_observation(self, username, raw_public_key):
        """
        Record this newly received key's fingerprint (Server-Untrusted
        Identity Verification, Stage 2) -- called only AFTER
        KeyManager.add_public_key() has already accepted it, so a key
        reaching this point has definitely not been rejected as a
        mismatch against a VERIFIED entry (handle_public_key() already
        returned before add_public_key() ran, in that case -- see
        _is_verified_key_mismatch()/_flag_peer_key_changed()).

        Unconditionally calls SecureKeyStore.
        record_observed_peer_fingerprint() -- safe to do so
        unconditionally here specifically because that method already
        refuses, on its own, to touch an existing VERIFIED entry; the
        two remaining possibilities it may actually act on are "no
        local record, or only an UNVERIFIED one" (records the
        observation; the peer remains UNVERIFIED -- observing a key is
        never verifying it) and "a VERIFIED record whose fingerprint
        matches" (a true no-op write, but still clears any stale
        same-session KEY_CHANGED flag below -- e.g. a key that changed
        earlier in this session and has now changed back to the
        trusted one).

        Never required for existing messaging: if the local key store
        is unavailable, this is a silent no-op, exactly like
        _persist_conversation_keys()'s own "if self.key_store is None:
        return". Peer-verification state is a new, additive layer; it
        is never a precondition for establish_session_key()/
        wrap_key_for_member() or anything else already reading
        KeyManager.get_public_key().

        IMPORTANT -- what this method deliberately does NOT do: it
        never calls verify_peer_fingerprint(), the only method allowed
        to set PEER_STATE_VERIFIED (see storage/secure_key_store.py).
        Nothing here ever promotes a key to VERIFIED; that remains
        exclusively a future, explicit user action.

        Also unconditionally refreshes _observed_peer_raw_public_keys
        (Server-Untrusted Identity Verification hardening) -- before
        the key-store-availability check below, since which raw bytes
        were actually observed is a pure in-memory fact, independent
        of whether there happens to be a local key store to persist a
        fingerprint into this session.

        Protocol-Level ML-DSA Origin Authentication: also drops any
        stale _observed_peer_signing_public_keys entry for ``username``.
        This LEGACY observation carries no signing key at all, so a
        signing key left over from an EARLIER, unrelated combined-
        identity observation of this same username must not linger and
        be mistaken by confirm_peer_verification() for part of THIS
        (legacy, KEM-only) observation.
        """

        self._observed_peer_raw_public_keys[username] = raw_public_key
        self._observed_peer_signing_public_keys.pop(username, None)

        if self.key_store is None:
            return

        fingerprint = fingerprint_public_key(raw_public_key)

        self.key_store.record_observed_peer_fingerprint(
            username, fingerprint
        )

        self._peer_keys_changed.discard(username)

        self._pending_key_changed_fingerprints.pop(username, None)

        self._pending_key_changed_raw_keys.pop(username, None)
        self._pending_key_changed_signing_raw_keys.pop(username, None)

    def get_peer_verification_state(self, username, device_id=None):
        """
        Returns this user's current knowledge of ``username``'s
        identity-key verification (Server-Untrusted Identity
        Verification, Stage 2): PEER_STATE_VERIFIED,
        PEER_STATE_UNVERIFIED, PEER_KEY_STATE_CHANGED, or None if
        nothing has ever been recorded (or the local key store is
        unavailable).

        KEY_CHANGED -- session-local -- takes precedence over
        whatever SecureKeyStore itself reports: it means the most
        recent observation disagreed with the still-intact VERIFIED
        record underneath it (see _evaluate_peer_key_verification()).

        ``device_id`` (Phase 16D): see _peer_identity_key().
        """

        username = self._effective_peer_identity_key(username, device_id)

        if username in self._peer_keys_changed:
            return PEER_KEY_STATE_CHANGED

        if self.key_store is None:
            return None

        entry = self.key_store.get_peer_verification(username)

        return entry["state"] if entry is not None else None

    def _peer_key_is_verified(self, username, device_id=None):
        """
        True only if ``username``'s CURRENT verification state is
        exactly PEER_STATE_VERIFIED (Server-Untrusted Identity
        Verification, Stage 3). False for PEER_STATE_UNVERIFIED,
        PEER_KEY_STATE_CHANGED, and None (nothing recorded, or no
        local key store this session) alike -- all three mean the
        same thing to a caller deciding whether it is safe to
        establish protected communication: there is no confirmed
        binding between this key and this peer right now. The
        difference between them only matters for what the UI tells
        the user, never for this decision -- see
        establish_session_key(), handle_direct_key_redelivery_
        required(), and _distribute_group_key(), the three (and only
        three) places KeyManager.wrap_key_for_member() is ever called.

        ``device_id`` (Phase 16D): see _peer_identity_key().
        """

        return self.get_peer_verification_state(username, device_id) == PEER_STATE_VERIFIED

    def _sender_trust_rejection_reason(self, sender, device_id=None):
        """
        Phase 13.7: distinguishes WHY _peer_key_is_verified(sender)
        returned False, using only state this receiver already has
        locally -- no new lookup, no network round trip. Called only
        after _peer_key_is_verified() itself has already returned
        False; never promotes, demotes, or otherwise touches the
        sender's trust state -- purely a read of
        get_peer_verification_state()'s existing return value.

        Returns SecurityRejectionReason.KEY_CHANGED if this receiver's
        last observation of ``sender`` disagreed with a previously
        VERIFIED identity (PEER_KEY_STATE_CHANGED); UNVERIFIED_SENDER
        if ``sender`` has been observed but never explicitly VERIFIED;
        UNKNOWN_SENDER if nothing has ever been recorded for
        ``sender`` at all (state is None -- never observed, or no
        local key store this session).

        ``device_id`` (Phase 16D): see _peer_identity_key().
        """

        state = self.get_peer_verification_state(sender, device_id)

        if state == PEER_KEY_STATE_CHANGED:
            return SecurityRejectionReason.KEY_CHANGED

        if state == PEER_STATE_UNVERIFIED:
            return SecurityRejectionReason.UNVERIFIED_SENDER

        return SecurityRejectionReason.UNKNOWN_SENDER

    def _report_security_rejection(self, reason, sender, conversation_id):
        """
        Phase 13.7 -- Key-Establishment Rejection Observability &
        State Integrity: the ONE place handle_group_key_distribution()
        (KYBER/group-key) and handle_session_key() (RSA) report a
        security rejection through, so both stay consistent and
        neither hand-rolls its own logging/signal shape.

        Logs a single WARNING line identifying the security event --
        reason, claimed sender, conversation_id -- and nothing else.
        Deliberately never logs: signatures, encrypted/wrapped key
        material, decrypted session keys, ML-DSA or RSA private
        material, passwords, or tokens (none of those are parameters
        here at all, so there is nothing for a future call site to
        accidentally pass through). ``sender``/``conversation_id`` are
        untrusted, attacker-influenceable strings -- logged as an f-
        string argument (not interpolated into a format string the
        attacker controls), and never as raw packet bytes/base64
        blobs, so there is no log-injection surface beyond what any
        other username-bearing log line in this codebase already
        accepts.

        Emits security_rejection(reason, sender, conversation_id) --
        the reason as its plain string value (SecurityRejectionReason
        is a StrEnum), so a listener never needs to import this
        module's enum just to compare against it. No GUI is connected
        to this signal yet (Phase 14's job); this call is the entire
        "GUI boundary" this phase exposes.

        Never raises: a security rejection must never itself become a
        new failure mode for the receiver thread.
        """

        self.logger.warning(
            f"SECURITY: rejected key establishment ({reason}) for "
            f"conversation {conversation_id}, claimed sender {sender}."
        )

        self.security_rejection.emit(
            reason.value if isinstance(reason, SecurityRejectionReason) else str(reason),
            sender or "",
            conversation_id or "",
        )

    def get_peer_fingerprint_for_verification(self, username, device_id=None):
        """
        Returns the fingerprint a verification dialog should display
        and, on explicit user confirmation, pass to
        confirm_peer_verification() (Server-Untrusted Identity
        Verification, Stage 3).

        For PEER_KEY_STATE_CHANGED, this is the NEW key's fingerprint
        -- the one that triggered the mismatch, held only in
        _pending_key_changed_fingerprints, since Stage 2 deliberately
        never imports or persists the rejected key itself anywhere
        else. For PEER_STATE_UNVERIFIED or PEER_STATE_VERIFIED, this
        is whatever SecureKeyStore already has on file for username --
        first-contact verification and re-confirming an already-
        VERIFIED key both compare against the same, currently-active
        fingerprint. None if nothing has ever been recorded, or the
        local key store is unavailable this session.

        ``device_id`` (Phase 16D): see _peer_identity_key().
        """

        username = self._effective_peer_identity_key(username, device_id)

        if username in self._pending_key_changed_fingerprints:
            return self._pending_key_changed_fingerprints[username]

        if self.key_store is None:
            return None

        entry = self.key_store.get_peer_verification(username)

        return entry["fingerprint"] if entry is not None else None

    def _currently_observed_peer_public_key(self, username, device_id=None):
        """
        Returns the raw public-key bytes confirm_peer_verification()
        must independently derive ``username``'s fingerprint from
        right now (Server-Untrusted Identity Verification hardening)
        -- the exact same key get_peer_fingerprint_for_verification()
        already sources its displayed fingerprint from, so the two
        always agree for the one legitimate caller
        (VerifyIdentityDialog, which only ever displays a fingerprint
        it got from that method and only ever confirms the exact same
        value back).

        For a pending PEER_KEY_STATE_CHANGED, this is the NEW
        (rejected, never imported into KeyManager) key's raw bytes,
        held in _pending_key_changed_raw_keys -- see
        _flag_peer_key_changed(). Otherwise, it is whatever
        _observed_peer_raw_public_keys currently holds for username --
        the exact raw wire bytes of the key handle_public_key() last
        legitimately imported, which is also what SecureKeyStore's own
        observed/verified fingerprint was computed from at the time.

        Deliberately NOT KeyManager.public_keys[username]: KeyManager
        stores each algorithm's own parsed/decoded form (e.g. Kyber's
        import_public_key() returns raw-decoded bytes, not the
        original base64 wire value), which is a DIFFERENT byte
        sequence than the raw wire value every other fingerprint in
        this system is computed from -- fingerprinting that form here
        would silently disagree with the fingerprint already on file
        for the exact same logical key, breaking every legitimate
        verification. _observed_peer_raw_public_keys exists
        specifically to avoid that trap.

        None if nothing has ever been observed for this peer at all --
        there is nothing to verify against.

        ``device_id`` (Phase 16D): see _peer_identity_key().
        """

        username = self._effective_peer_identity_key(username, device_id)

        if username in self._pending_key_changed_raw_keys:
            return self._pending_key_changed_raw_keys[username]

        return self._observed_peer_raw_public_keys.get(username)

    def _retry_pending_key_requests(self, sender):
        """
        Re-requests every (conversation_id, epoch) this client
        received from ``sender`` and rejected only because ``sender``
        was not yet VERIFIED (recorded in _pending_key_requests_
        awaiting_verification -- see its own comment). Called after
        confirm_peer_verification()/confirm_combined_peer_
        verification() successfully promotes a peer to VERIFIED, using
        the SAME request handle_direct_key_recovery_available() sends
        on an ordinary reconnect (create_direct_key_recovery_request_
        packet) -- this only ever asks again for something already
        legitimately offered once; it grants no new access and skips
        anything already installed by the time this runs (e.g. a later
        reconnect already recovered it).

        No-op if this client never rejected anything from ``sender``,
        or is not currently connected -- exactly the same "nothing
        lost, nothing to do" outcome as any other missed redelivery.

        Accepts either a plain username or an already device-scoped
        key (see _peer_identity_key()) and always reduces to the
        plain username before looking anything up -- _pending_key_
        requests_awaiting_verification is keyed by the raw "sender"
        field of a rejected network packet, which is never device-
        scoped, regardless of which form a caller (confirm_peer_
        verification()/confirm_combined_peer_verification(), which
        may reach this having already resolved a device-scoped key)
        happens to hold at the point it calls this.
        """

        sender = sender.split(self._DEVICE_IDENTITY_KEY_SEPARATOR, 1)[0]

        pending = self._pending_key_requests_awaiting_verification.pop(sender, None)

        if not pending or self.client_socket is None:
            return

        for conversation_id, epoch in pending:

            if self.key_manager.has_key(conversation_id, epoch=epoch):
                continue

            # Best-effort, exactly like the "not connected" no-op above:
            # self.client_socket being non-None does not guarantee it is
            # still a live, connected socket (a real, physically-
            # reproduced regression -- test_attack_d_forged_packet_no_
            # longer_wins_the_race_against_the_real_key -- found this
            # raising OSError and aborting confirm_combined_peer_
            # verification() itself, which must never fail just because
            # this opportunistic re-request could not be sent). A failed
            # send here loses nothing new: the same redelivery this
            # would have asked for early still happens on the recipient's
            # next ordinary reconnect, per this method's own docstring.
            try:
                send_message(
                    self.client_socket,
                    create_direct_key_recovery_request_packet(
                        conversation_id=conversation_id,
                        epochs=[epoch],
                    ),
                )
            except Exception as error:  # noqa: BLE001
                self.logger.warning(
                    f"Failed to re-request recovery of {conversation_id} "
                    f"epoch {epoch} from {sender}: {error}"
                )
                continue

            self.logger.info(
                f"Re-requested recovery of {conversation_id} epoch "
                f"{epoch} from {sender} now that they are verified"
            )

    def _retry_declined_redeliveries(self, recipient):
        """
        The other half of "verify late, in either order": re-attempts
        every (conversation_id, epoch) this client itself declined to
        REDELIVER to ``recipient`` -- handle_direct_key_redelivery_
        required()'s own "SECURITY: refusing to redeliver" branch --
        purely because this client had not yet verified ``recipient``
        at the time. Re-runs that exact same handler with a
        reconstructed packet, so every one of its checks (still holds
        the key, ``recipient`` is now verified, wrap/sign/send) apply
        fresh -- this grants nothing that handler would not have
        already granted the first time, had verification simply
        happened a moment sooner.

        See _retry_pending_key_requests()'s docstring for the
        device_id-key-reduction and no-op conditions -- identical
        here, since both draw from the same _effective_peer_identity_
        key()-resolved ``username``.
        """

        recipient = recipient.split(self._DEVICE_IDENTITY_KEY_SEPARATOR, 1)[0]

        pending = self._declined_redeliveries_awaiting_verification.pop(recipient, None)

        if not pending:
            return

        for conversation_id, epoch in pending:
            # Best-effort, same reasoning as _retry_pending_key_
            # requests()'s own try/except just above: this handler's
            # OTHER call site (a live inbound packet, on the receiver
            # thread) can reasonably let a send failure propagate
            # because the connection is already known-live at that
            # point; called from here, as a side effect of a purely
            # local confirm_peer_verification(), that guarantee does
            # not hold, and a failed opportunistic send must not break
            # the verification call itself. Nothing is lost either way
            # -- see this method's own docstring.
            try:
                self.handle_direct_key_redelivery_required({
                    "conversation_id": conversation_id,
                    "epoch": epoch,
                    "recipient": recipient,
                })
            except Exception as error:  # noqa: BLE001
                self.logger.warning(
                    f"Failed to retry declined redelivery of {conversation_id} "
                    f"epoch {epoch} to {recipient}: {error}"
                )

    def confirm_peer_verification(self, username, fingerprint, device_id=None):
        """
        The ONLY method the GUI should ever call to promote a peer to
        PEER_STATE_VERIFIED (Server-Untrusted Identity Verification,
        Stage 3) -- called ONLY after the user has explicitly
        confirmed, through their own independent out-of-band
        comparison, that ``fingerprint`` (as obtained from
        get_peer_fingerprint_for_verification()) is correct. Never
        called automatically, never called speculatively, never called
        on a dialog merely being opened or cancelled.

        Hardening: no longer a blind pass-through of ``fingerprint``.
        Independently re-derives the fingerprint from
        _currently_observed_peer_public_key(username) -- the actual,
        currently cached (or pending KEY_CHANGED) raw key bytes -- and
        refuses (PeerVerificationMismatchError) unless the supplied
        ``fingerprint`` matches that independently-derived value
        exactly, or there is no observed key to verify against at all.
        This closes the gap where any caller-supplied string could
        previously be accepted and persisted as VERIFIED regardless of
        whether it corresponded to anything real: the value actually
        persisted below is always the independently-derived one, never
        the caller-supplied string itself. The legitimate caller
        (VerifyIdentityDialog) is unaffected -- it only ever passes
        back the exact value get_peer_fingerprint_for_verification()
        handed it, which is already derived from the same observed key
        this method re-derives from, so the two always agree.

        Wraps SecureKeyStore.verify_peer_fingerprint() -- the only
        method allowed to set PEER_STATE_VERIFIED, unchanged since
        Stage 1 -- and additionally clears this username's
        session-local PEER_KEY_STATE_CHANGED bookkeeping
        (_peer_keys_changed/_pending_key_changed_fingerprints/
        _pending_key_changed_raw_keys), which verify_peer_fingerprint()
        itself has no reason to know about: KEY_CHANGED is deliberately
        session-local (see PEER_KEY_STATE_CHANGED's module docstring),
        so without this second step get_peer_verification_state() would
        keep reporting KEY_CHANGED for the rest of this session even
        after the store underneath it correctly says VERIFIED -- it
        checks the session-local flag first, by design (Stage 2).

        Raises KeyStoreError if the local key store is unavailable
        this session -- there is nothing to persist the verification
        into, and silently accepting it in memory only would make
        VERIFIED here mean something different than VERIFIED
        everywhere else this state is checked (all of which read
        SecureKeyStore).

        Protocol-Level ML-DSA Origin Authentication: gui/verify_
        identity_dialog.py calls only this ONE method (never
        confirm_combined_peer_verification() directly), and this
        phase's own send_public_key()/handle_public_key() wiring now
        makes the COMBINED-identity path the default for every real
        peer. Rather than changing the GUI's call site, this method
        detects which convention applies to whatever is CURRENTLY being
        confirmed for ``username`` and dispatches accordingly.

        The check uses the same pending-first precedence
        _currently_observed_peer_public_key() itself already uses --
        deliberately NOT "was a signing key ever observed for this
        username at any point" (that broader check is wrong: it would
        also fire for a peer whose combined identity was flagged
        KEY_CHANGED by a subsequent LEGACY, unsigned packet -- see
        _flag_peer_key_changed()'s docstring -- where the CURRENT
        pending change carries no signing key at all, even though an
        OLDER, no-longer-current combined observation of this same
        username still does):

        * A pending KEY_CHANGED exists (username in
          _pending_key_changed_raw_keys): dispatch is combined only if
          THAT pending change itself included a signing key
          (_pending_key_changed_signing_raw_keys) -- _flag_peer_key_
          changed()/_flag_peer_identity_changed() each populate exactly
          one of the two signing dicts for their own pending change,
          never both.
        * No pending change: dispatch is combined only if the peer's
          currently ACTIVE (non-pending) observation included a signing
          key (_observed_peer_signing_public_keys) --
          _record_peer_key_observation()/_record_peer_identity_
          observation() each keep exactly this invariant.

        A peer only ever reached through the legacy unsigned path falls
        through to the unchanged single-key logic below.

        ``device_id`` (Phase 16D): see _peer_identity_key(). Applied
        once, here, before any of the pending/observed-dict checks
        below -- the recursive call into confirm_combined_peer_
        verification() below passes the already-composed key with no
        device_id of its own, which is safe/idempotent (composing an
        already-composite key with device_id=None returns it
        unchanged).
        """

        if self.key_store is None:
            raise KeyStoreError(
                "The local key store is not available; identity "
                "verification cannot be saved."
            )

        username = self._effective_peer_identity_key(username, device_id)

        if username in self._pending_key_changed_raw_keys:
            use_combined = username in self._pending_key_changed_signing_raw_keys
        else:
            use_combined = username in self._observed_peer_signing_public_keys

        if use_combined:
            self.confirm_combined_peer_verification(username, fingerprint)
            return

        observed_key = self._currently_observed_peer_public_key(username)

        if observed_key is None:
            raise PeerVerificationMismatchError(
                f"No observed public key for {username}; there is "
                f"nothing to verify."
            )

        derived_fingerprint = fingerprint_public_key(observed_key)

        if derived_fingerprint != fingerprint:
            raise PeerVerificationMismatchError(
                "The supplied fingerprint does not match the "
                "currently observed public key; verification was "
                "refused."
            )

        self.key_store.verify_peer_fingerprint(username, derived_fingerprint)

        self._peer_keys_changed.discard(username)

        self._pending_key_changed_fingerprints.pop(username, None)

        self._pending_key_changed_raw_keys.pop(username, None)

        self._retry_pending_key_requests(username)
        self._retry_declined_redeliveries(username)

    # ----------------------------------------------------------
    # ML-DSA identity/key-persistence foundation phase: combined
    # (ML-KEM + ML-DSA) peer identity.
    #
    # A peer's identity is BOTH keys together, as ONE fingerprint and
    # ONE verification state -- never two independent trust states for
    # the same peer (see crypto/key_manager.py::
    # fingerprint_combined_identity()'s docstring). The five methods
    # below are the combined-identity counterparts of
    # _is_verified_key_mismatch()/_flag_peer_key_changed()/
    # _record_peer_key_observation()/handle_public_key() above, built
    # to the same shape and reusing the SAME SecureKeyStore._peers
    # storage and the SAME record_observed_peer_fingerprint()/
    # verify_peer_fingerprint() methods -- no new storage schema, no
    # new independent trust state.
    #
    # Deliberately NOT wired into handle_public_key() or any other
    # existing method, and not connected to any network packet handler
    # -- the wire protocol does not carry a peer's signing key yet.
    # observe_peer_identity() is a freestanding entry point, callable
    # directly (by tests now, and by a future protocol-integration
    # phase once a packet actually carries both keys).
    # ----------------------------------------------------------

    def _compute_combined_fingerprint(self, kem_public_key, signing_public_key):
        """
        Thin wrapper around crypto.key_manager.
        fingerprint_combined_identity() -- kept as a method (not called
        directly by every caller below) so this is the one place that
        would need to change if this session ever needed to adapt the
        raw key bytes before fingerprinting them.
        """

        return fingerprint_combined_identity(kem_public_key, signing_public_key)

    def _is_verified_identity_mismatch(
        self, username, kem_public_key, signing_public_key, device_id=None
    ):
        """
        True only if this user has an existing VERIFIED combined-
        identity fingerprint for ``username`` AND the (KEM, signing)
        key pair just observed disagrees with it -- the combined-
        identity counterpart of _is_verified_key_mismatch().

        False (never a mismatch) whenever there is nothing VERIFIED to
        compare against: no local key store, no record at all, or an
        UNVERIFIED one -- a first-contact or still-unverified peer's
        identity is never blocked here, exactly like the single-key
        version.

        ``device_id`` (Phase 16D): see _peer_identity_key(). This is
        the mechanism that lets a second device belonging to the SAME
        account be recorded as its own distinct, independently-tracked
        identity rather than colliding with (and potentially flagging
        KEY_CHANGED against) a different, already-VERIFIED device of
        that same account.
        """

        username = self._peer_identity_key(username, device_id)

        if self.key_store is None:
            return False

        entry = self.key_store.get_peer_verification(username)

        if entry is None or entry["state"] != PEER_STATE_VERIFIED:
            return False

        return entry["fingerprint"] != self._compute_combined_fingerprint(
            kem_public_key, signing_public_key
        )

    def _flag_peer_identity_changed(
        self, username, kem_public_key, signing_public_key, device_id=None
    ):
        """
        Record, session-locally only, that the most recently observed
        (KEM, signing) identity for ``username`` disagreed with their
        VERIFIED combined fingerprint -- the combined-identity
        counterpart of _flag_peer_key_changed(). Never written to
        SecureKeyStore: this describes a disagreement, not new evidence
        about what should be trusted, exactly like the single-key
        version.

        Reuses the SAME _peer_keys_changed/_pending_key_changed_
        fingerprints/_pending_key_changed_raw_keys bookkeeping the
        single-key path already uses -- one identity, one set of
        pending-change state -- and additionally stashes the rejected
        signing key's raw bytes in _pending_key_changed_signing_raw_
        keys, since neither of the existing dicts has room for a
        second key.

        ``device_id`` (Phase 16D): see _peer_identity_key(). Only a
        DEVICE-SCOPED mismatch (the composite key's own prior VERIFIED
        record disagreeing with what was just observed for that SAME
        device_id) ever reaches this method when the caller is device-
        aware -- a different device_id belonging to the same account
        producing a different key is a NEW, distinct identity slot
        (handled by _record_peer_identity_observation() instead), never
        a KEY_CHANGED event against an unrelated device's slot.
        """

        username = self._peer_identity_key(username, device_id)

        self._peer_keys_changed.add(username)

        combined_fingerprint = self._compute_combined_fingerprint(
            kem_public_key, signing_public_key
        )

        self._pending_key_changed_fingerprints[username] = combined_fingerprint
        self._pending_key_changed_raw_keys[username] = kem_public_key
        self._pending_key_changed_signing_raw_keys[username] = signing_public_key

        self.logger.warning(
            f"SECURITY: combined (KEM + signing) identity received for "
            f"{username} does not match the previously verified "
            f"fingerprint -- the new identity was NOT recorded, and the "
            f"trusted identity already on file (if any) remains in "
            f"effect. Treating as KEY_CHANGED."
        )

        self.peer_key_changed.emit(username)

    def _record_peer_identity_observation(
        self, username, kem_public_key, signing_public_key, device_id=None
    ):
        """
        Record this newly observed (KEM, signing) identity's combined
        fingerprint -- the combined-identity counterpart of
        _record_peer_key_observation(). Called only when
        _is_verified_identity_mismatch() has already found no conflict
        with an existing VERIFIED identity.

        Unconditionally calls SecureKeyStore.
        record_observed_peer_fingerprint() with the COMBINED
        fingerprint -- safe to do so unconditionally here for exactly
        the same reason as the single-key version: that method already
        refuses, on its own, to touch an existing VERIFIED entry. No
        new logic is needed here to satisfy "a changed key must not
        overwrite a VERIFIED identity while VERIFIED" -- that guarantee
        already lives in SecureKeyStore, reused as-is.

        Never promotes a peer to VERIFIED -- that remains exclusively
        confirm_peer_verification(), a future explicit user action.

        ``device_id`` (Phase 16D): see _peer_identity_key(). This is
        what lets a second, third, ... device of the same account each
        get recorded as its own UNVERIFIED entry, independently of
        whatever is on file for any other device_id of that account.
        """

        username = self._peer_identity_key(username, device_id)

        self._observed_peer_raw_public_keys[username] = kem_public_key
        self._observed_peer_signing_public_keys[username] = signing_public_key

        if self.key_store is None:
            return

        combined_fingerprint = self._compute_combined_fingerprint(
            kem_public_key, signing_public_key
        )

        # Message-Level ML-DSA Origin Authentication: the raw signing
        # key is persisted here too (not just cached in the session-
        # local dict above), so a later restart's history-loading
        # verification can still resolve it even if this peer never
        # comes back online to re-broadcast it -- see
        # SecureKeyStore.get_peer_signing_public_key()'s own docstring.
        self.key_store.record_observed_peer_fingerprint(
            username, combined_fingerprint, signing_public_key=signing_public_key
        )

        self._peer_keys_changed.discard(username)

        self._pending_key_changed_fingerprints.pop(username, None)
        self._pending_key_changed_raw_keys.pop(username, None)
        self._pending_key_changed_signing_raw_keys.pop(username, None)

    def observe_peer_identity(
        self, username, kem_public_key, signing_public_key, device_id=None
    ):
        """
        Top-level entry point for observing a peer's combined (ML-KEM +
        ML-DSA) identity -- the combined-identity counterpart of
        handle_public_key()'s decision logic, minus the packet parsing
        and KeyManager.add_public_key() call (there is no wire packet
        carrying a signing key yet for this to unpack).

        Fail-closed, exactly like handle_public_key(): if the observed
        identity disagrees with an existing VERIFIED one, it is flagged
        as KEY_CHANGED and NOTHING is recorded as the new observed
        identity -- the previously trusted identity remains in effect
        and recoverable. Only when there is no such conflict is the
        observation recorded.

        ``device_id`` (Phase 16D): see _peer_identity_key(). Passed
        straight through, unmodified, to every helper below -- this
        method itself does not need to compose the key, since each of
        those already does. observe_device_peer_identity() (Phase 16C)
        continues to call this with device_id omitted and ``device_id``
        (the parameter named that in THIS method's own signature)
        passed positionally as ``username`` instead -- unaffected by
        this addition, since a plain string with no device_id kwarg
        composes to itself.
        """

        if self._is_verified_identity_mismatch(
            username, kem_public_key, signing_public_key, device_id=device_id
        ):
            self._flag_peer_identity_changed(
                username, kem_public_key, signing_public_key, device_id=device_id
            )
            return

        self._record_peer_identity_observation(
            username, kem_public_key, signing_public_key, device_id=device_id
        )

    def _currently_observed_peer_identity(self, username, device_id=None):
        """
        Returns ``(kem_public_key, signing_public_key)`` raw bytes --
        the combined-identity counterpart of
        _currently_observed_peer_public_key(). Either element is None
        if nothing has ever been observed for that half.

        For a pending KEY_CHANGED, these are the NEW (rejected, never
        recorded) identity's raw bytes, held in
        _pending_key_changed_raw_keys / _pending_key_changed_signing_
        raw_keys -- see _flag_peer_identity_changed(). Otherwise,
        whatever _observed_peer_raw_public_keys /
        _observed_peer_signing_public_keys currently hold -- the last
        identity _record_peer_identity_observation() recorded.

        ``device_id`` (Phase 16D): see _peer_identity_key().
        """

        username = self._effective_peer_identity_key(username, device_id)

        if username in self._pending_key_changed_raw_keys:
            kem_public_key = self._pending_key_changed_raw_keys[username]
        else:
            kem_public_key = self._observed_peer_raw_public_keys.get(username)

        if username in self._pending_key_changed_signing_raw_keys:
            signing_public_key = self._pending_key_changed_signing_raw_keys[username]
        else:
            signing_public_key = self._observed_peer_signing_public_keys.get(username)

        return kem_public_key, signing_public_key

    def has_observed_combined_identity(self, username, device_id=None):
        """
        True only if this session currently holds BOTH halves of
        ``username``'s combined identity in memory -- the exact
        precondition confirm_combined_peer_verification() requires
        before it will independently re-derive and accept a
        fingerprint (Phase 19.22).

        A read-only query, not a new trust decision: the actual
        security gate is entirely unchanged and lives only in
        confirm_combined_peer_verification()/_currently_observed_peer_
        identity() below. This exists so a caller (the Inbox Approve
        handler) can wait for a fresh, in-progress identity exchange
        to land before attempting verification, instead of racing it
        and surfacing a fail-closed error for an ordinary timing
        window where both users are, in fact, online.
        """

        kem_public_key, signing_public_key = self._currently_observed_peer_identity(
            username, device_id=device_id
        )
        return kem_public_key is not None and signing_public_key is not None

    def confirm_combined_peer_verification(self, username, fingerprint, device_id=None):
        """
        The combined-identity counterpart of confirm_peer_verification()
        -- the ONLY method that should ever promote a peer's COMBINED
        (ML-KEM + ML-DSA) identity to PEER_STATE_VERIFIED. Not yet
        called from anywhere (no GUI wiring this phase); exists so
        Phase 9/10's key-change security tests have a real "explicit
        human verification" action to call, exactly as
        confirm_peer_verification() already is for the single-key path.

        Same hardening posture as confirm_peer_verification(): never a
        blind pass-through of ``fingerprint``. Independently re-derives
        the combined fingerprint from
        _currently_observed_peer_identity(username) -- the actual,
        currently cached (or pending KEY_CHANGED) (KEM, signing) pair
        -- and refuses (PeerVerificationMismatchError) unless the
        supplied ``fingerprint`` matches that independently-derived
        value exactly. The value actually persisted below is always
        the independently-derived one, never the caller-supplied
        string itself.

        Raises PeerVerificationMismatchError if either half of the
        identity has never been observed, or if ``fingerprint`` does
        not match. Raises KeyStoreError if the local key store is
        unavailable this session.

        ``device_id`` (Phase 16D): see _peer_identity_key(). Composed
        once, here, at the top -- confirm_peer_verification() may also
        reach this method having already composed the key itself and
        calling with device_id omitted; re-composing an already-
        composite key with device_id=None is a no-op, so this is safe
        either way. confirm_device_peer_verification() (Phase 16C)
        continues to call this with device_id omitted and its own
        device_id passed positionally as ``username`` instead --
        unaffected by this addition for the same reason.
        """

        if self.key_store is None:
            raise KeyStoreError(
                "The local key store is not available; identity "
                "verification cannot be saved."
            )

        username = self._effective_peer_identity_key(username, device_id)

        kem_public_key, signing_public_key = self._currently_observed_peer_identity(
            username
        )

        if kem_public_key is None or signing_public_key is None:
            raise PeerVerificationMismatchError(
                f"No observed combined identity for {username}; there "
                f"is nothing to verify."
            )

        derived_fingerprint = self._compute_combined_fingerprint(
            kem_public_key, signing_public_key
        )

        if derived_fingerprint != fingerprint:
            raise PeerVerificationMismatchError(
                "The supplied fingerprint does not match the "
                "currently observed combined identity; verification "
                "was refused."
            )

        # Message-Level ML-DSA Origin Authentication: persisted here
        # too, for the same reason as _record_peer_identity_
        # observation() -- so history-loading verification of this
        # now-VERIFIED peer's messages can still resolve their signing
        # key after a restart, even if they are not currently online.
        self.key_store.verify_peer_fingerprint(
            username, derived_fingerprint, signing_public_key=signing_public_key
        )

        # Bug fix (Phase 16C -- discovered while testing device-key
        # sync, but not specific to devices: this is the general
        # VERIFIED -> KEY_CHANGED -> re-confirm sequence for any
        # peer). _resolve_trusted_signing_key()/_currently_observed_
        # peer_identity() both check _pending_key_changed_*_raw_keys
        # FIRST, then fall back to _observed_peer_*_public_keys -- but
        # until this fix, confirming a KEY_CHANGED identity cleared the
        # pending dicts above WITHOUT promoting the newly-confirmed
        # (kem_public_key, signing_public_key) into the fallback caches,
        # which still held the OLD, now-superseded identity. The next
        # signature verification for this username would then resolve
        # the WRONG (stale) trusted key and incorrectly reject a
        # genuine, freshly-VERIFIED sender's messages -- a false
        # rejection of legitimate traffic, never a false acceptance;
        # fixing it makes verification MORE correct, not weaker.
        self._observed_peer_raw_public_keys[username] = kem_public_key
        self._observed_peer_signing_public_keys[username] = signing_public_key

        self._peer_keys_changed.discard(username)

        self._pending_key_changed_fingerprints.pop(username, None)
        self._pending_key_changed_raw_keys.pop(username, None)
        self._pending_key_changed_signing_raw_keys.pop(username, None)

        self._retry_pending_key_requests(username)
        self._retry_declined_redeliveries(username)

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

        RSA Direct-Session-Key ML-DSA Origin Authentication (Phase
        13.6): before this phase, the RSA (non-KYBER) branch below
        installed ``encrypted_key`` with NO check of any kind on the
        packet's claimed sender -- RSA-OAEP is true public-key
        encryption, so ANYONE holding this client's PUBLIC RSA key
        (broadcast to every connected client by design, exactly like
        the ML-KEM public key Phase 13 already protected) could
        encrypt an arbitrary session key of their own choosing and
        have it installed. Phase 13.5's independent audit proved this
        empirically. This mirrors Phase 13's handle_group_key_
        distribution() fix exactly, for the same reason and with the
        same mandatory installation order (never reordered): receive
        -> parse/validate structure -> resolve sender identity (and
        require VERIFIED -- symmetric with the sending side's own
        pre-existing gate in establish_session_key(), and with
        handle_group_key_distribution()'s KYBER-mode rule, so there is
        no algorithm-dependent trust bypass) -> verify ML-DSA signature
        -> decrypt (RSA private-key operation) -> install -> use. The
        RSA private-key decryption never runs before the signature is
        verified -- verifying first, on the ciphertext itself (bound
        into the signed payload, no decryption needed to check it),
        avoids spending a private-key operation on unauthenticated
        network input.

        Phase 13.8A -- KYBER Session-Key Forgery Remediation: the
        "KYBER branch" below used to decapsulate and install a session
        key completely unauthenticated, on the theory that it was
        dead/legacy code -- no production CLIENT ever constructs a
        "session_key" packet with algorithm="KYBER" (establish_
        session_key()'s KYBER branch sends group_key_distribution
        instead, authenticated since Phase 13). That was true and
        irrelevant: this project's entire threat model is a MALICIOUS
        SERVER/RELAY, which does not need a legitimate client's
        cooperation to construct one. Phase 13.8's audit proved this
        empirically -- an attacker holding nothing but a victim's
        already-public ML-KEM key could forge exactly this packet
        shape (no signature needed, since this branch never checked
        for one) and have an attacker-known session key installed
        against a completely ordinary, default (KYBER-mode) receiver,
        for the exact same reason the pre-Phase-13.6 RSA branch was
        vulnerable: encapsulation is confidentiality, never
        authenticity.

        Traced exhaustively before this fix (Phase 13.8A, Parts 1-2):
        create_session_key_packet() has exactly one production caller
        anywhere in this codebase (establish_session_key()'s RSA
        branch, which always passes algorithm="RSA") and the server
        never constructs one server-side, only relays/hardens an
        already-client-built one -- so a legitimate algorithm="KYBER"
        session_key packet never exists in production at all. The only
        two tests that ever construct one operate on raw sockets
        (tests/test_direct_conversation_relay_resolution.py,
        tests/test_chat_encryption_integration.py) to exercise SERVER-
        side relay hardening or raw KEM round-tripping -- neither ever
        calls this method. Nothing legitimate depends on this branch
        accepting anything.

        Remediation: unconditional rejection (no decapsulation, no key
        installation, no state mutation of any kind) rather than
        retrofitting authentication onto a path with zero legitimate
        use -- the same choice Part 3 of this phase's task explicitly
        prefers when a path is genuinely obsolete. No existing
        SecurityRejectionReason member describes "this operation/
        algorithm combination is not a supported production path"
        precisely (WRONG_ALGORITHM already means "the packet's
        declared algorithm disagrees with mine", which is not this
        case -- both agree the algorithm is KYBER; what's wrong is
        using this packet TYPE for it at all) -- OTHER_SECURITY_
        REJECTION is used rather than inventing a new enum member for
        one obsolete-protocol-operation case.

        Phase 13.7 -- Key-Establishment Rejection Observability &
        State Integrity: returns None on success, or the
        domain.security_rejection_reason.SecurityRejectionReason that
        caused rejection -- every rejection branch below (including
        the pre-existing malformed/missing-conversation_id and
        algorithm-label-mismatch checks, both unrelated to Phase 13.6
        but folded into the same reporting mechanism for consistency)
        reports through _report_security_rejection() (log +
        security_rejection Signal).
        """

        sender = packet.get("sender")
        conversation_id = packet.get("conversation_id")

        if not sender or not conversation_id:
            self._report_security_rejection(
                SecurityRejectionReason.MALFORMED_PACKET, sender, conversation_id
            )
            return SecurityRejectionReason.MALFORMED_PACKET

        epoch = packet.get("epoch") or 1

        self.conversation_store.record_direct_conversation_id(
            sender, conversation_id
        )

        # Hardening: the server relays this packet and can rewrite any
        # field in it, including ``algorithm`` -- it must never be the
        # thing that decides which decrypt routine (KYBER decapsulate
        # vs. RSA-OAEP decrypt) runs. This client always uses its own
        # locally configured self.key_manager.algorithm; a packet that
        # explicitly declares a DIFFERENT one is a mismatch worth
        # rejecting outright and loudly, rather than silently letting
        # network input steer which private key material gets used.
        # (RSA-OAEP decrypt would simply fail closed on the wrong
        # ciphertext regardless -- but KYBER decapsulation does NOT:
        # it deterministically returns SOME shared secret for any
        # well-formed-length ciphertext, never raising, so silently
        # taking the KYBER branch on forged input could install a
        # bogus key via store_key() below for an epoch that has not
        # been established yet. Rejecting on the label mismatch,
        # before any decrypt/decapsulate call, closes that regardless
        # of which direction the mismatch runs.)
        packet_algorithm = packet.get("algorithm")

        if packet_algorithm is not None and packet_algorithm != self.key_manager.algorithm:
            self._report_security_rejection(
                SecurityRejectionReason.WRONG_ALGORITHM, sender, conversation_id
            )
            return SecurityRejectionReason.WRONG_ALGORITHM

        algorithm = self.key_manager.algorithm

        if algorithm == "KYBER":

            # Phase 13.8A: no legitimate producer of this packet shape
            # exists (see this method's own docstring) -- reject
            # unconditionally, before any decapsulation is attempted,
            # rather than authenticate a path nothing real ever uses.
            self._report_security_rejection(
                SecurityRejectionReason.OTHER_SECURITY_REJECTION, sender, conversation_id
            )
            return SecurityRejectionReason.OTHER_SECURITY_REJECTION

        else:

            if not self._peer_key_is_verified(sender):
                reason = self._sender_trust_rejection_reason(sender)
                self._report_security_rejection(reason, sender, conversation_id)
                return reason

            signing_public_key = self._resolve_trusted_signing_key(sender)

            signature_b64 = packet.get("session_key_signature")

            if signature_b64 is None:
                self._report_security_rejection(
                    SecurityRejectionReason.MISSING_SIGNATURE, sender, conversation_id
                )
                return SecurityRejectionReason.MISSING_SIGNATURE

            if signing_public_key is None:
                self._report_security_rejection(
                    SecurityRejectionReason.UNKNOWN_SENDER, sender, conversation_id
                )
                return SecurityRejectionReason.UNKNOWN_SENDER

            try:
                signature = base64.b64decode(signature_b64, validate=True)

                verified = verify_rsa_session_key_payload(
                    sender, self.username, conversation_id, algorithm,
                    packet["encrypted_key"], epoch,
                    signature, signing_public_key,
                )

            except (TypeError, ValueError):
                # Malformed base64, wrong-length signature/key, or a
                # structurally invalid field -- a data error describing
                # untrusted network input, never a bug in this
                # codebase (mirrors crypto/group_key_protocol.py's own
                # established convention). The exception message
                # itself is never logged -- it can embed attacker-
                # controlled bytes (Part 5: no attacker-controlled
                # payload logged verbatim).
                self._report_security_rejection(
                    SecurityRejectionReason.MALFORMED_PACKET, sender, conversation_id
                )
                return SecurityRejectionReason.MALFORMED_PACKET

            if not verified:
                self._report_security_rejection(
                    SecurityRejectionReason.INVALID_SIGNATURE, sender, conversation_id
                )
                return SecurityRejectionReason.INVALID_SIGNATURE

            # Phase 13.7: the packet is now fully authenticated -- see
            # handle_group_key_distribution()'s identical reasoning.
            if self.key_manager.has_key(conversation_id, epoch=epoch):
                self._report_security_rejection(
                    SecurityRejectionReason.DUPLICATE_OR_STALE_KEY, sender, conversation_id
                )

            try:
                encrypted_key = base64.b64decode(
                    packet["encrypted_key"]
                )

                session_key = (
                    self.key_manager.decrypt_session_key(
                        encrypted_key
                    )
                )
            except (ValueError, TypeError):
                # Defense in depth only: signature verification above
                # already guarantees encrypted_key is exactly what the
                # VERIFIED sender produced, so this should be
                # unreachable for any real attacker-controlled input --
                # kept narrow and non-crashing regardless.
                self._report_security_rejection(
                    SecurityRejectionReason.DECRYPTION_FAILURE, sender, conversation_id
                )
                return SecurityRejectionReason.DECRYPTION_FAILURE

        self.key_manager.store_key(
            conversation_id,
            session_key,
            epoch=epoch
        )

        self.logger.info(
            f"Session key established with {sender}"
        )

        # UI Finalization Decision (internal message cleanup): session
        # establishment is an internal protocol event, not a
        # user-authored message -- no longer surfaced as a chat
        # bubble. The actual key storage above (key_manager.store_key())
        # is unchanged; still fully logged for debugging.

        return None

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
            conversation_id, name, participants, admin=creator
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

            # Server-Untrusted Identity Verification, Stage 3: same
            # per-recipient skip-and-continue shape as the "no public
            # key" case just above -- one unverified member never
            # blocks the group key from reaching everyone else (D6 --
            # Group Key Distribution Robustness already established
            # this independence for unusable keys; verification status
            # is just one more reason a given member may be skipped).
            # Once that member is verified, the next rotation/
            # reconnect-triggered redelivery for them succeeds with no
            # other change -- there is no separate retry path to add.
            if not self._peer_key_is_verified(member):

                self.logger.warning(
                    f"SECURITY: {member} is not verified; skipping "
                    f"group key distribution for {conversation_id} "
                    f"epoch {epoch} to this member "
                    f"({self.get_peer_verification_state(member)})."
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

            # Group-Key-Distribution ML-DSA Origin Authentication:
            # signed with this client's own persistent ML-DSA signer
            # (the same one already used for identity announcements and
            # messages) over the canonical envelope crypto/
            # group_key_protocol.py defines -- AFTER wrapping already
            # produced encapsulation/wrapped_key, and BEFORE the packet
            # is ever sent. The private key never leaves
            # self.key_manager.ml_dsa; only the resulting signature
            # bytes are put on the wire.
            group_key_signature = sign_group_key_payload(
                self.key_manager.ml_dsa,
                self.username,
                conversation_id,
                member,
                encapsulation,
                wrapped_key,
                epoch,
            )

            packet = create_group_key_distribution_packet(
                sender=self.username,
                conversation_id=conversation_id,
                recipient=member,
                encapsulation=encapsulation,
                wrapped_key=wrapped_key,
                epoch=epoch,
                group_key_signature=base64.b64encode(group_key_signature).decode("ascii"),
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
        crypto/key_manager.py::unwrap_received_key().

        Group-Key-Distribution ML-DSA Origin Authentication (Phase 13):
        before this phase, this method's own docstring said outright
        "Uses only this client's own private key material; nothing
        from the sender is needed beyond the packet's opaque fields"
        -- which was true, and was exactly the vulnerability: ML-KEM-
        then-DEM (crypto/key_manager.py::wrap_key_for_member()) gives
        CONFIDENTIALITY (only this client's private key can ever
        recover the wrapped key) but no AUTHENTICITY at all -- ANYONE
        holding this client's PUBLIC ML-KEM key (broadcast to every
        connected client by design) could independently encapsulate a
        fresh secret and AES-GCM-wrap an arbitrary key of their own
        choosing, and unwrap_received_key() would happily recover it.
        A malicious server (this project's entire threat model) did
        not even need to intercept a real packet -- it could fabricate
        one from scratch. See this phase's own audit/final report for
        the full trace.

        Mandatory installation order (never reordered):
            receive -> parse/validate structure -> resolve sender
            identity (and require VERIFIED -- see below) -> verify
            ML-DSA signature -> decrypt/unseal -> install -> use.
        The group key becomes active (store_key()) ONLY after every
        prior step succeeds; any failure returns before store_key() is
        ever reached, so an attacker can never race a real delivery by
        having their forged one merely arrive first and get installed
        before rejection catches up.

        VERIFIED, not merely signature-valid: unlike ordinary message
        authentication (Phase 12B), which accepts a signature from a
        merely-UNVERIFIED-but-cryptographically-consistent sender,
        group-key distribution requires the sender to be VERIFIED from
        THIS receiver's own peer-identity state
        (_peer_key_is_verified()). This mirrors the SENDING side's own
        pre-existing rule (_distribute_group_key() already skips any
        recipient who is not VERIFIED, from the sender's point of
        view) -- applied symmetrically here to the sender, from the
        receiver's point of view, since group-key material is higher-
        stakes than a single message: it seeds trust for an entire
        conversation's future traffic, not one already-displayed
        message. _peer_key_is_verified() already returns False for
        PEER_KEY_STATE_CHANGED (unchanged, existing behavior), so a
        sender whose identity has changed since this receiver last
        verified them is rejected here too, automatically -- a new
        group key is never silently accepted as though it still came
        from the old, previously-trusted identity.

        The verification key itself is resolved via _resolve_trusted_
        signing_key() -- this receiver's own already-established peer-
        identity state -- never from anything inside this packet (it
        carries no ML-DSA public-key field at all for an attacker to
        substitute one into).

        Any failure (unverified/unknown sender, missing/malformed
        signature, or a signature that does not verify) is rejected
        with a logged warning; the group key is never unwrapped or
        installed, and this client's currently active key/epoch for
        the conversation (if any) is left completely untouched.

        ``epoch`` (Phase 7 -- Group Membership Management): stored
        under the epoch the packet declares, defaulting to 1 for
        compatibility with a sender that predates this field.
        KeyManager.store_key() never overwrites an existing epoch with
        a different key, so a redundant/duplicate delivery of the same
        epoch is always safe (replay of an identical valid packet is a
        harmless no-op).

        Phase 13.7 -- Key-Establishment Rejection Observability &
        State Integrity: returns None on success, or the
        domain.security_rejection_reason.SecurityRejectionReason that
        caused rejection -- every rejection branch now also reports
        through _report_security_rejection() (log + security_rejection
        Signal), except the very first ("not addressed to me") check,
        which is ordinary routing noise every member's client sees
        constantly for a group broadcast to OTHER members, never a
        security event. No rejection branch below was reordered, and
        none now does more work than it already did -- this only makes
        the SAME fail-closed decisions observable, not different ones.
        """

        if packet.get("recipient") != self.username:
            return None

        conversation_id = packet.get("conversation_id")
        sender = packet.get("sender")

        if not conversation_id or not sender:
            self._report_security_rejection(
                SecurityRejectionReason.MALFORMED_PACKET, sender, conversation_id
            )
            return SecurityRejectionReason.MALFORMED_PACKET

        epoch = packet.get("epoch") or 1
        encapsulation = packet.get("encapsulation")
        wrapped_key = packet.get("wrapped_key")

        if not self._peer_key_is_verified(sender):
            # See _pending_key_requests_awaiting_verification's own
            # comment: remembered so confirm_peer_verification()/
            # confirm_combined_peer_verification() can ask ``sender``
            # to redeliver this once this client verifies them,
            # instead of silently requiring a manual reconnect.
            self._pending_key_requests_awaiting_verification.setdefault(
                sender, []
            ).append((conversation_id, epoch))
            reason = self._sender_trust_rejection_reason(sender)
            self._report_security_rejection(reason, sender, conversation_id)
            return reason

        signing_public_key = self._resolve_trusted_signing_key(sender)

        signature_b64 = packet.get("group_key_signature")

        if signature_b64 is None:
            self._report_security_rejection(
                SecurityRejectionReason.MISSING_SIGNATURE, sender, conversation_id
            )
            return SecurityRejectionReason.MISSING_SIGNATURE

        if signing_public_key is None:
            self._report_security_rejection(
                SecurityRejectionReason.UNKNOWN_SENDER, sender, conversation_id
            )
            return SecurityRejectionReason.UNKNOWN_SENDER

        try:
            signature = base64.b64decode(signature_b64, validate=True)

            verified = verify_group_key_payload(
                sender, conversation_id, self.username, encapsulation,
                wrapped_key, epoch, signature, signing_public_key,
            )

        except (TypeError, ValueError):
            # Malformed base64, wrong-length signature/key, or a
            # structurally invalid field -- a data error describing
            # untrusted network input, never a bug in this codebase
            # (mirrors crypto/identity_protocol.py's/crypto/
            # message_protocol.py's own established convention). The
            # exception message itself is never logged here -- it can
            # embed attacker-controlled bytes (Part 5: no attacker-
            # controlled payload logged verbatim); the reason label
            # alone is enough to act on.
            self._report_security_rejection(
                SecurityRejectionReason.MALFORMED_PACKET, sender, conversation_id
            )
            return SecurityRejectionReason.MALFORMED_PACKET

        if not verified:
            self._report_security_rejection(
                SecurityRejectionReason.INVALID_SIGNATURE, sender, conversation_id
            )
            return SecurityRejectionReason.INVALID_SIGNATURE

        # Phase 13.7: the packet is now fully authenticated. A key
        # already on file for this exact epoch means store_key() below
        # is about to be a harmless no-op (KeyManager.store_key()'s
        # pre-existing no-overwrite guarantee, unmodified) -- reported
        # as DUPLICATE_OR_STALE_KEY rather than silently treated the
        # same as a fresh installation, so a redundant/stale-but-
        # authentic redelivery is observably distinct from a genuinely
        # new key taking effect. Not a security violation -- the
        # authenticated sender genuinely sent this -- just not new.
        if self.key_manager.has_key(conversation_id, epoch=epoch):
            self._report_security_rejection(
                SecurityRejectionReason.DUPLICATE_OR_STALE_KEY, sender, conversation_id
            )

        try:
            group_key = self.key_manager.unwrap_received_key(
                encapsulation, wrapped_key
            )
        except (ValueError, TypeError):
            # Defense in depth only: signature verification above
            # already guarantees encapsulation/wrapped_key are exactly
            # what the VERIFIED sender produced, so this should be
            # unreachable for any real attacker-controlled input --
            # kept narrow and non-crashing regardless.
            self._report_security_rejection(
                SecurityRejectionReason.DECRYPTION_FAILURE, sender, conversation_id
            )
            return SecurityRejectionReason.DECRYPTION_FAILURE

        self.key_manager.store_key(conversation_id, group_key, epoch=epoch)

        self.logger.info(
            f"Group key established for conversation {conversation_id} "
            f"(epoch {epoch}), authenticated from {sender}"
        )

        return None

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

    def handle_typing_indicator_notification(self, packet):
        """
        Another active member of a conversation has started (or
        stopped) typing (Phase 19.24 -- Typing Indicator). Purely a
        live-update hint, exactly like handle_read_receipt_
        notification() above -- re-emitted as a Qt signal, never
        persisted, never affects message delivery or history in any
        way. A missing/malformed field is silently ignored rather than
        raising -- this is best-effort UI decoration, not a security-
        or correctness-relevant packet.
        """

        conversation_id = packet.get("conversation_id")
        username = packet.get("username")

        if not conversation_id or not username:
            return

        self.typing_indicator_received.emit(
            conversation_id, username, bool(packet.get("is_typing"))
        )

    def _decrypt_lifecycle_event_content(self, conversation_id, payload_type, ciphertext, epoch):
        """
        Shared best-effort decryption for a Phase 19.24 lifecycle
        event's content (an edit's new text, a reaction's emoji
        string) -- mirrors _decrypt_history_message()'s exact fail-
        soft contract (never raises; returns a placeholder if this
        client has no key for that epoch, or if AES-GCM authentication
        fails) but generalized to any PayloadAdapter-registered
        payload_type, since a reaction is PayloadType.REACTION, not
        TEXT.
        """

        session_key = self.key_manager.get_key(conversation_id, epoch=epoch or 1)

        if session_key is None:
            return _UNDECRYPTABLE_PLACEHOLDER

        try:
            envelope = PayloadEnvelope(
                payload_type=payload_type, ciphertext=ciphertext, content_metadata={}
            )
            return self._adapter_for(payload_type).decrypt(envelope, AESCipher(session_key))
        except Exception:  # noqa: BLE001
            return _UNDECRYPTABLE_PLACEHOLDER

    def _verify_lifecycle_event_signature(
        self, actor, conversation_id, payload_type, ciphertext, content_metadata, epoch,
        signature_b64, purpose, event_label,
    ):
        """
        Continued Phase 19.24 -- receiver-side verification. Mirrors
        _verify_chat_message_signature()'s exact trust model (resolve
        the CLAIMED actor's trusted signing key from THIS client's own
        already-established peer state, never from anything inside the
        packet; verify; fail closed) for the edit/reaction event
        types, distinguished from an ordinary chat message and from
        each other by ``purpose`` (EDIT_PAYLOAD_PURPOSE/REACTION_
        PAYLOAD_PURPOSE). This is what makes this client's trust in
        ``actor`` independent of merely trusting the server relayed it
        correctly -- the same reason ordinary chat messages carry a
        signature at all.

        Returns True only if the signature verified. A missing
        signature, an unresolvable signing key, or a failed
        verification are all rejected identically -- logged, never
        fatal to the receiver thread, exactly like an ordinary chat
        message's identical three failure modes.
        """

        if not signature_b64:
            self.logger.warning(
                f"SECURITY: rejected unsigned {event_label} claiming to be "
                f"from {actor}; ML-DSA signature is required."
            )
            return False

        # BUG FIX (continued Phase 19.24): the server broadcasts an
        # edit/reaction notification to EVERY conversation member,
        # including the ORIGINATING actor themselves (server/client_
        # handler.py's handle_message_edit()/handle_reaction_add()
        # never pass exclude_socket to _broadcast_to_conversation_
        # members() for these) -- exactly what lets a sender's own
        # bubble update in place without a history reload. But
        # _resolve_trusted_signing_key() only ever caches OTHER
        # accounts' OBSERVED identities (nobody "observes" their own
        # public key arriving over the wire -- it never does), so
        # actor == self.username always missed there, incorrectly
        # rejecting a sender's own, perfectly genuine signature as
        # unverifiable. Resolved from this session's own KeyManager
        # instead for that one case -- mirrors load_conversation_
        # history()'s identical is_own branch, and is exactly as safe:
        # this is still real cryptographic verification against a
        # public key this client unquestionably controls the private
        # half of, never a bypass.
        if actor == self.username:
            signing_public_key = self.key_manager.ml_dsa.export_public_key()
        else:
            signing_public_key = self._resolve_trusted_signing_key(actor)

        if signing_public_key is None:
            self.logger.warning(
                f"SECURITY: rejected {event_label} from {actor}: no ML-DSA "
                f"identity has ever been observed for them; cannot verify origin."
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
            self.logger.warning(
                f"SECURITY: rejected malformed signed {event_label} from "
                f"{actor}: {error}"
            )
            return False

        if not verified:
            self.logger.warning(
                f"SECURITY: ML-DSA signature verification FAILED for a "
                f"{event_label} claiming to be from {actor}; rejecting."
            )
            return False

        return True

    def handle_message_edited(self, packet):
        """
        Another of this conversation's participants (or this
        account's OWN other device) successfully edited a message
        (Phase 19.24). Decrypts the new content here -- the GUI never
        touches ciphertext, exactly like message_received/payload_
        message_received. ``editor``/``edited_at``/``edit_version`` are
        the server's own authenticated answer for AUTHORIZATION
        (server/client_handler.py already confirmed editor == the
        message's real sender before ever broadcasting this); the
        ML-DSA signature below is verified independently so this
        client's trust in ``editor`` does not rest on the server alone.
        """

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
            conversation_id,
            message_id,
            new_text,
            editor,
            packet.get("edited_at") or "",
            int(packet.get("edit_version") or 0),
        )

    def handle_message_deleted(self, packet):
        """
        A message was deleted for everyone (Phase 19.24). Carries no
        content to decrypt -- the server already nulled it server-side
        before sending this notification at all (server/client_
        handler.py::handle_message_delete_for_everyone()).
        """

        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")

        if not message_id or not conversation_id:
            return

        self.message_deleted_received.emit(
            conversation_id,
            message_id,
            packet.get("deleted_by") or "",
            packet.get("deleted_at") or "",
        )

    def handle_reaction_updated(self, packet):
        """
        A reaction was added or removed on a message this account can
        see (Phase 19.24). Decrypts the reaction string for "add"
        (empty string for "remove" -- there is nothing to decrypt).
        """

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

    def handle_message_pinned(self, packet):
        """A message was pinned (Phase 19.24 -- Pinned Messages). No
        decryption/verification needed -- see message_pinned_received's
        own docstring for the trust-model note."""

        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")
        pinned_by = packet.get("pinned_by") or ""

        if not message_id or not conversation_id or not pinned_by:
            return

        self.message_pinned_received.emit(
            conversation_id, message_id, pinned_by, packet.get("pinned_at") or "",
        )

    def handle_message_unpinned(self, packet):
        """A message was unpinned (Phase 19.24 -- Pinned Messages)."""

        message_id = packet.get("message_id")
        conversation_id = packet.get("conversation_id")
        unpinned_by = packet.get("unpinned_by") or ""

        if not message_id or not conversation_id or not unpinned_by:
            return

        self.message_unpinned_received.emit(conversation_id, message_id, unpinned_by)

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

    def send_typing_indicator(self, conversation_id, is_typing):
        """
        Tell the server this account is (or has just stopped) typing
        in ``conversation_id`` (Phase 19.24 -- Typing Indicator).
        Fire-and-forget, like mark_conversation_read() -- carries no
        sender identity of its own; the server derives that exclusively
        from this socket's authenticated session. A no-op if there's no
        real conversation_id yet, for the identical reason mark_
        conversation_read() already has one.

        The caller (GUI) owns ALL debounce/timeout decisions -- when to
        send is_typing=True (e.g. on the first keystroke after being
        idle), when to send is_typing=False (idle timeout, or the
        message was actually sent) -- this method only ever puts
        exactly the packet it's asked for on the wire, never inferring
        timing on its own.

        Safe to call after disconnect() -- a no-op rather than an
        AttributeError on a None client_socket. Unlike an ordinary
        user-initiated send (send_chat_message() et al., where a
        failure is real, actionable information the GUI surfaces),
        this one is reached from a QTimer callback that can legitimately
        still be armed and fire well after the window/session it
        belongs to has already been torn down (the idle-typing timer
        does not know or care whether anyone is still listening) -- see
        gui/chat_window.py::_on_composer_text_changed()'s own debounce
        contract. There is nothing for a caller to react to either way:
        a typing hint that never arrives changes nothing but a cosmetic
        indicator on the other end.
        """

        if not conversation_id or not self.connected:
            return

        packet = create_typing_indicator_packet(
            conversation_id=conversation_id, is_typing=is_typing
        )

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

    def remove_group_member(self, conversation_id, target_username):
        """
        Ask the server to remove ``target_username`` from a group
        (Phase 19.13 -- Group Admin). Admin-only, server-enforced --
        see server/client_handler.py::handle_group_remove_member()'s
        own docstring; this call raises nothing locally and performs
        no local authorization check of its own (the GUI hiding the
        Remove Member button for a non-admin is a convenience, not the
        enforcement). Unlike add/leave/create above, this uses
        send_request() rather than fire-and-forget: the caller needs
        the definite success/error (e.g. "you are not the admin") to
        show immediately, not only the eventual group_member_left
        broadcast every other member also receives.
        """

        return self.send_request(
            create_group_remove_member_packet(
                conversation_id=conversation_id, target_username=target_username,
            )
        )

    # ==========================================================
    # Inbox: verification requests + group member-add approval
    # (Phase 19.13 -- User Manual Feedback Implementation)
    # ==========================================================

    def request_verification(self, target_username):
        """
        Ask ``target_username`` to verify this account's identity --
        creates a pending verification_request inbox notification on
        the server for them to Approve/Deny (server/client_handler.py
        ::handle_verification_request()). Performs no cryptography
        itself: this is only the "ask" half. The actual verification
        happens on the OTHER side when they approve (see
        respond_to_inbox()'s own docstring) -- exactly the same
        confirm_combined_peer_verification() call the existing Verify
        Identity dialog already makes, just triggered from the Inbox
        instead of that dialog.
        """

        send_message(
            self.client_socket,
            create_verification_request_packet(target_username),
        )

    def load_inbox(self):
        """
        Fetch every inbox notification (pending or resolved) where
        this account is either the recipient or the original
        requester -- mirrors load_conversations()'s request/response
        shape exactly (conversation_list_request -> here, inbox_list_
        request). Returns the raw list of notification dicts; the
        caller (GUI) renders it, there is no local cache to keep in
        sync -- inbox_updated only ever signals "go call this again".
        """

        response = self.send_request(create_inbox_list_request_packet())

        return response.get("notifications") or []

    def respond_to_inbox(self, notification, approve):
        """
        Approve or deny one pending inbox notification (Phase 19.13).

        Security -- verification_request: approving here is the ONLY
        place a verification_request's Approve button is allowed to
        take effect, and it does so by calling THIS client's own
        already-existing, unweakened confirm_combined_peer_
        verification() with the fingerprint THIS client has already
        independently observed for the requester -- never a value
        taken from the notification itself (which carries no key
        material at all). If nothing has been observed yet for the
        requester (they have never been online since this client last
        restarted, or never sent a signed identity packet at all),
        PeerVerificationMismatchError propagates to the caller exactly
        as it would from the existing Verify Identity dialog -- the
        GUI is expected to show it as a friendly "cannot verify them
        yet" message, same as everywhere else that error already
        surfaces, and MUST NOT send approve=True to the server in that
        case (a caught exception here means this method returns
        without sending anything). Denying, or a group_add_request
        either way, performs no cryptography -- only the server-side
        record + (if approved) the existing add-member path runs.
        """

        if approve and notification.get("type") == "verification_request":

            requester_username = notification.get("requester_username")

            fingerprint = self.get_peer_fingerprint_for_verification(requester_username)

            if fingerprint is None:
                raise PeerVerificationMismatchError(
                    f"No observed identity for {requester_username} yet; "
                    f"cannot verify them until they are online and you "
                    f"have exchanged keys."
                )

            self.confirm_combined_peer_verification(requester_username, fingerprint)

        send_message(
            self.client_socket,
            create_inbox_response_packet(
                notification_id=notification.get("notification_id"), approve=approve,
            ),
        )

    def _complete_requester_side_verification(self, notification):
        """
        Phase 19.22B -- respond_to_inbox()'s approve path already
        promotes the APPROVER's own combined identity for the
        requester to VERIFIED before it ever sends approve=True.
        Nothing completed the mirror half on the REQUESTER's side:
        this client sent the original verification_request and then
        just... waited, so only one of the two participants ever left
        the async Inbox-mediated flow actually VERIFIED, despite Approve
        having succeeded. Runs only when THIS user is the original
        requester (never the recipient/approver -- they already
        confirmed their own half inside respond_to_inbox()) and the
        resolution is an approval, using the exact same fail-closed
        get_peer_fingerprint_for_verification() + confirm_combined_
        peer_verification() gate as every other verification path --
        never a blind trust of anything in the notification itself,
        which carries no key material at all. A failure here (this
        client has not yet observed the approver's identity) is
        swallowed exactly like every other fail-closed gate already
        does -- the user can still finish manually via Verify Identity.
        """

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
            self.confirm_combined_peer_verification(approver_username, fingerprint)
        except Exception as error:  # noqa: BLE001
            self.logger.warning(
                f"Could not auto-complete verification with {approver_username} "
                f"after their approval: {error}"
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

        Deliberately does NOT cache the result into ConversationStore.
        Opening a chat is not activity -- see conversation_store.py's
        docstring -- so resolving/creating the id here must not make
        an empty conversation sidebar-visible. The caller
        (set_current_chat()) keeps the id on self.current_conversation_id
        for addressing/key-manager purposes regardless; the store only
        learns about this conversation if a message actually gets
        sent (send_chat_message() -> _send_encrypted_payload() passes
        this same id to ConversationStore.record_message() on first
        send) or received (handle_chat()/handle_session_key() already
        cache it themselves, from real incoming activity).

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

        return response.get("conversation_id")

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

    def set_unread_count(self, key, count):
        """
        Set the absolute unread count for a conversation (BUG --
        Offline Unread/Notification).

        Unlike increment_unread() -- which reacts to one live message
        arriving -- this sets a count already known in full, from
        load_conversations()'s server-reported unread_count per
        conversation. ``key`` is the same addressing identity
        increment_unread()/clear_unread()/get_unread_count() already
        use (ConversationSummary.key: conversation_id for a group,
        username for a direct conversation).
        """
        self.unread_counts[key] = count

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

    # ------------------------------------------------------------------
    # Phase 19.24 -- Mute: local-only, per-conversation. Affects
    # notifications (the sidebar's unread badge -- the only "notify the
    # user" surface this desktop client actually has; there is no OS
    # toast/sound system in this codebase to suppress), never delivery
    # -- a muted conversation's messages still arrive, decrypt, persist,
    # and mark read exactly as before. Thin wrappers over self.key_store
    # (storage/secure_key_store.py's own new conversation_prefs
    # section) -- gui/ code goes through these, never self.key_store
    # directly, mirroring every other local-preference access in this
    # class.
    # ------------------------------------------------------------------

    MUTE_DURATIONS = {
        "1h": timedelta(hours=1),
        "8h": timedelta(hours=8),
        "1w": timedelta(weeks=1),
    }

    def mute_conversation(self, key, duration):
        """
        Mute conversation ``key`` (a username for direct, a
        conversation_id for group -- same identity ConversationStore
        already uses). ``duration`` is one of MUTE_DURATIONS's keys
        ("1h", "8h", "1w") or the literal string "forever".
        """

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
        expired timed mute reads as False -- see SecureKeyStore.
        is_conversation_muted()'s own docstring)."""

        if self.key_store is None:
            return False

        return self.key_store.is_conversation_muted(key)

    # ------------------------------------------------------------------
    # Phase 19.24 -- Archive: local-only, per-conversation. Retains
    # history -- archiving never deletes or hides anything server-side,
    # purely a "don't show this in my main list" local preference. Thin
    # wrappers over self.key_store, same shape as the Mute wrappers
    # above.
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
    # Phase 19.24 -- Chat Wallpaper: local-only, per-conversation, same
    # shape as Mute/Archive above -- never sent to or stored by the
    # server.
    # ------------------------------------------------------------------

    def get_conversation_wallpaper(self, key):
        if self.key_store is None:
            return None
        return self.key_store.get_conversation_wallpaper(key)

    def set_conversation_wallpaper(self, key, wallpaper_id):
        if self.key_store is None:
            return
        self.key_store.set_conversation_wallpaper(key, wallpaper_id)