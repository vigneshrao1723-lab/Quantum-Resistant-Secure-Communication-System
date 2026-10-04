// Phase 15 -- Web Interoperability, Stage 1.
//
// Orchestration for the minimal web client. Mirrors client/session.py
// ::ClientSession's own method names and call order so the mapping to
// the existing desktop implementation is traceable line-by-line -- see
// docs/architecture/web_interoperability.md's protocol-mapping table.
//
// Security invariant this file exists to uphold (same as client/
// session.py's own handle_group_key_distribution()/handle_chat()):
// EVERY incoming signed packet is verified BEFORE its cryptographic
// payload is ever decapsulated/decrypted. A verification failure never
// throws past this file uncaught -- it is always routed through
// reportSecurityRejection(), which never installs anything and never
// crashes the WebSocket connection, exactly like ClientSession's own
// fail-closed, receiver-stays-alive contract.

import * as C from "./crypto.js";
import * as P from "./protocol.js";
import * as S from "./storage.js";

const KEY_EXCHANGE_ALGORITHM = "KYBER"; // this client only ever speaks Kyber/ML-KEM

// Phase 17 -- Web Persistence + Reconnect: bounded exponential backoff
// defaults for automatic reconnect after an UNEXPECTED WebSocket close
// (network blip, gateway restart, server restart -- see this file's
// own _handleSocketClosed()/_scheduleReconnect()). Overridable via the
// constructor options (tests use short delays; production uses these
// defaults). Capped attempt count -- never an infinite tight retry
// loop -- after which reconnecting is abandoned and a clear terminal
// "disconnected" state is reported via onConnectionState().
const DEFAULT_RECONNECT_BASE_DELAY_MS = 1000;
const DEFAULT_RECONNECT_MAX_DELAY_MS = 30000;
const DEFAULT_RECONNECT_MAX_ATTEMPTS = 8;

// Phase 18 -- File & Image Transfer: mirrors config.py::
// MAX_ATTACHMENT_SIZE_BYTES's own default (25 MiB) -- the existing
// wire framing holds a whole message in memory with no chunking/
// streaming, on either side, so the same cap applies here for the
// same reason it does on the desktop.
const MAX_ATTACHMENT_SIZE_BYTES = 25 * 1024 * 1024;

// Mirrors domain/payload_type.py::classify_attachment() -- by
// filename extension (never a client-claimed MIME type), matching the
// desktop's own classification exactly: anything recognized as an
// image extension is PayloadType.IMAGE, everything else is
// PayloadType.FILE. Small, fixed extension set (not the Python
// standard library's full mimetypes table) -- sufficient for this
// client's own classification decision, which affects only which
// payload_type label this client itself chooses, not correctness or
// interoperability of the encryption/signature pipeline either way.
const IMAGE_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "tif", "tiff", "ico",
]);

// Phase 19.24 -- Voice/Video Messages: NOT a new payload pipeline --
// see domain/payload_type.py's own module docstring (this is this
// client's own equivalent of classify_attachment()). A recorded clip
// is just another local attachment pushed through sendAttachment()
// unchanged; only this classification decision (which payload_type
// label a receiver renders a play control for) needed extending.
function classifyAttachment(filename, mimeType) {
  if (mimeType) {
    if (mimeType.startsWith("audio/")) return "voice";
    if (mimeType.startsWith("video/")) return "video";
    if (mimeType.startsWith("image/")) return "image";
  }
  const ext = (filename.split(".").pop() || "").toLowerCase();
  return IMAGE_EXTENSIONS.has(ext) ? "image" : "file";
}

const SECURITY_REJECTION_MESSAGES = {
  unknown_sender: "it claimed to be from an unknown sender",
  unverified_sender: "it claimed to be from a sender you have not verified",
  key_changed: "the sender's identity key has changed and has not been re-verified",
  missing_signature: "it was missing required authentication",
  invalid_signature: "it failed authentication",
  malformed_packet: "it was malformed",
  decryption_failure: "it could not be processed safely",
  other_security_rejection: "it failed a security check",
};

export class WebClientSession {
  constructor({
    gatewayUrl, onLog, onSecurityWarning, onMessage, onPeerObserved, onConnectionState,
    onAttachment, onGroupCreated, onReadReceipt, onHistoryLoaded, onOnlineUsersChanged,
    onInboxUpdated, onMessageDelivered, onMessageQueued,
    onMessageEdited, onMessageDeleted, onReactionUpdated, onTypingIndicator,
    onMessagePinned, onMessageUnpinned,
    reconnectBaseDelayMs, reconnectMaxDelayMs, reconnectMaxAttempts,
  }) {
    this.gatewayUrl = gatewayUrl;
    this.onLog = onLog || (() => {});
    this.onSecurityWarning = onSecurityWarning || (() => {});
    this.onMessage = onMessage || (() => {});
    this.onPeerObserved = onPeerObserved || (() => {});
    this.onConnectionState = onConnectionState || (() => {});
    // Phase 18 -- Web UX + Feature Completion.
    this.onAttachment = onAttachment || (() => {}); // (identityKey, sender, payloadType, bytes, contentMetadata)
    this.onGroupCreated = onGroupCreated || (() => {}); // (conversationId, name, members)
    this.onReadReceipt = onReadReceipt || (() => {}); // (conversationId, reader)
    // Phase 19.23 -- Issue 3: server/client_handler.py has sent these
    // live packets since Phase 19.14 (message_delivered) and always
    // (message_queued); this client simply never had a callback
    // consuming either one until now (mirrors onReadReceipt's own
    // "live hint only" contract -- see loadHistory()'s own additive
    // delivery_status handling for what makes DELIVERED durable across
    // reconnect, not just this live signal).
    this.onMessageDelivered = onMessageDelivered || (() => {}); // (conversationId, receiver)
    this.onMessageQueued = onMessageQueued || (() => {}); // (conversationId, receiver)
    // Phase 19.24 -- Message Lifecycle Events. Every callback below
    // receives only ALREADY-DECRYPTED content, exactly like onMessage/
    // onAttachment already do.
    this.onMessageEdited = onMessageEdited || (() => {}); // (conversationId, messageId, newText, editor, editedAt, editVersion)
    this.onMessageDeleted = onMessageDeleted || (() => {}); // (conversationId, messageId, deletedBy, deletedAt)
    this.onReactionUpdated = onReactionUpdated || (() => {}); // (conversationId, messageId, actor, action, reaction)
    // Phase 19.24 -- Pinned Messages. No decrypted content -- pin/
    // unpin has no ciphertext of its own, see database/models/
    // message.py::pinned_at's own trust-model docstring.
    this.onMessagePinned = onMessagePinned || (() => {}); // (conversationId, messageId, pinnedBy, pinnedAt)
    this.onMessageUnpinned = onMessageUnpinned || (() => {}); // (conversationId, messageId, unpinnedBy)
    // Phase 19.24 -- Typing Indicator. Live hint only, never persisted
    // or replayed on history reload -- mirrors onReadReceipt's own
    // contract exactly.
    this.onTypingIndicator = onTypingIndicator || (() => {}); // (conversationId, username, isTyping)
    this.onHistoryLoaded = onHistoryLoaded || (() => {}); // (conversationId, count)
    this.onInboxUpdated = onInboxUpdated || (() => {}); // (notification)
    this.onOnlineUsersChanged = onOnlineUsersChanged || (() => {}); // (Set<username>)

    this.reconnectBaseDelayMs = reconnectBaseDelayMs || DEFAULT_RECONNECT_BASE_DELAY_MS;
    this.reconnectMaxDelayMs = reconnectMaxDelayMs || DEFAULT_RECONNECT_MAX_DELAY_MS;
    this.reconnectMaxAttempts = reconnectMaxAttempts || DEFAULT_RECONNECT_MAX_ATTEMPTS;

    this.username = null;
    this.accessToken = null;
    this.ws = null;

    // In-memory only, for the lifetime of this page -- NEVER persisted
    // (see storage.js's own module docstring for why: persisting a
    // login password or a live bearer token at rest is a security
    // trade-off this phase deliberately does not make). Needed here so
    // an automatic reconnect (same page, same tab, dropped socket) can
    // re-authenticate without re-prompting; a genuine page reload
    // clears this along with everything else in memory and DOES
    // require re-entering credentials -- see connectAndLogin()'s own
    // comment.
    this._phoneNumber = null;
    this._password = null;

    this.kemKeypair = null; // { publicKey, secretKey } (Uint8Array)
    this.signingKeypair = null; // { publicKey, secretKey }

    // In-memory peer-trust state, mirroring storage/secure_key_store.py's
    // PEER_STATE_UNVERIFIED / PEER_STATE_VERIFIED / PEER_KEY_STATE_CHANGED.
    // Phase 17: also persisted (encrypted, see storage.js) so a page
    // reload restores it rather than losing it -- see _persistState()/
    // _restoreState() below and docs/architecture/web_interoperability.md's
    // Phase 17 section for exactly what is and is not persisted.
    this.peers = new Map(); // username -> { kemWire, signingKey, state, fingerprint }

    // Per-conversation AES session key + epoch, mirroring
    // crypto/key_manager.py::KeyManager.keys. Phase 17: also persisted,
    // same as this.peers above.
    this.sessionKeys = new Map(); // conversationId -> { key, epoch }
    this.directConversationIds = new Map(); // peer username -> conversationId
    this._restoredDirectPeers = []; // Phase 19.23 -- Issue 1: set by loadConversations() at login

    // Phase 18 -- groups: conversationId -> { name, members: [usernames] }.
    // Membership in this map is also what _handleGroupKeyDistribution()
    // uses to tell a group key delivery apart from a direct one (see
    // that method's own comment) -- populated by _handleGroupCreateResult()
    // BEFORE the creator ever sends the first group_key_distribution for
    // a brand-new group (both happen in reaction to the same server
    // broadcast, group_create_result, which every member -- including
    // the creator -- receives before the creator's own reaction fires).
    this.groups = new Map();

    // Mirrors client/session.py's self.online_users -- refreshed wholesale
    // on every user_list broadcast, read-only presence info for rendering
    // (never used for any authorization/crypto decision).
    this.onlineUsers = new Set();

    // Phase 18.5 -- Step 6 (History Deduplication): message_id-keyed,
    // in-memory-only (never persisted -- a genuine page reload clears
    // the DOM and legitimately starts over, which is not a duplicate;
    // see storage.js's own scope for what IS persisted). Populated by
    // BOTH a live "chat" packet's message_id (server/client_handler.py
    // now attaches one to every relayed direct AND group message) and
    // a loadHistory() entry's own message_id -- so the SAME logical
    // message is never rendered twice regardless of which path
    // rendered it first.
    //
    // Phase 19.17C -- Map<conversationId, Set<messageId>>, not one
    // flat cross-conversation Set: main.js's openDirectChat()/
    // openGroupChat() re-fetch a conversation's history every time
    // it's opened (including reopening one already visited this tab
    // session), via forgetRenderedHistory() below -- that must be
    // able to forget ONE conversation's dedup memory without losing
    // every other conversation's genuine same-open live+history
    // overlap protection.
    this._renderedMessageIds = new Map();

    // Phase 18 Step 8 -- Web Multi-Device Identity: this browser's own
    // device-management identity, mirroring ClientSession.device_id
    // (client/session.py) -- generated once (enrollDevice()) and
    // persisted the same way the KEM/ML-DSA keypair themselves are, so
    // a restored session resolves to the SAME device_id rather than
    // minting a new device every login.
    this.deviceId = null;

    // Phase 19.24 -- Mute: conversationId -> {mutedUntil: string|null}
    // (an ISO-8601 UTC timestamp, or the literal "forever"). LOCAL
    // preference only, persisted the same encrypted-at-rest way as
    // everything else in this section (see _serializeState()/
    // _applyRestoredState() below) -- mirrors storage/secure_key_
    // store.py's conversation_prefs section field-for-field.
    this.conversationPrefs = new Map();

    // Phase 19.24 -- Block User: local cache mirroring client/
    // session.py::ClientSession.blocked_usernames exactly.
    this.blockedUsernames = new Set();

    this._pendingRequests = new Map(); // request_id -> {resolve, reject}
    this._typeWaiters = new Map(); // packet.type -> [resolve, ...]

    // Phase 17 -- reconnect state machine (see _handleSocketClosed()/
    // _scheduleReconnect()/_attemptReconnect() below).
    this._intentionalDisconnect = false;
    this._reconnectAttempt = 0;
    this._reconnectTimer = null;
    this._connectionState = "disconnected"; // "disconnected" | "connecting" | "connected" | "reconnecting"
  }

  // One-time wait for the next packet of a given `type` -- used only
  // for the two packet types that carry no request_id (auth_result,
  // login_result is handled separately over its own short-lived
  // socket). Does NOT prevent the same packet from also reaching its
  // normal handler in _handleIncoming()'s switch below, so a
  // concurrently-arriving, unrelated broadcast is never misread as
  // the awaited response (the race _sendAndReceiveOnce() alone would
  // have on an already-dispatching socket).
  _waitForPacketType(type) {
    return new Promise((resolve) => {
      const waiters = this._typeWaiters.get(type) || [];
      waiters.push(resolve);
      this._typeWaiters.set(type, waiters);
    });
  }

  _resolveTypeWaiters(packet) {
    const waiters = this._typeWaiters.get(packet.type);
    if (!waiters || waiters.length === 0) return;
    this._typeWaiters.set(packet.type, []);
    for (const resolve of waiters) resolve(packet);
  }

  log(...args) {
    this.onLog(args.map(String).join(" "));
  }

  // -------------------------------------------------------------
  // Connection lifecycle
  // -------------------------------------------------------------

  async _openGatewaySocket() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.gatewayUrl);
      ws.addEventListener("open", () => resolve(ws), { once: true });
      ws.addEventListener("error", () => reject(new Error("WebSocket connection failed")), { once: true });
    });
  }

  async _sendAndReceiveOnce(ws, packet) {
    return new Promise((resolve, reject) => {
      const handleMessage = (event) => {
        ws.removeEventListener("message", handleMessage);
        try {
          resolve(JSON.parse(event.data));
        } catch (error) {
          reject(error);
        }
      };
      ws.addEventListener("message", handleMessage, { once: true });
      ws.send(JSON.stringify(packet));
    });
  }

  // Mirrors ClientSession.authenticate_credentials(): a short-lived
  // connection that only exchanges login_request/login_result, then
  // is torn down -- the real, persistent session connects separately
  // afterward (see connectAndLogin()).
  async authenticateCredentials(phoneNumber, password) {
    const ws = await this._openGatewaySocket();
    let response;
    try {
      // server/client_handler.py::handle_login_request() silently
      // drops any login_request with no request_id (`if not
      // request_id: return`) -- mirrors ClientSession.
      // authenticate_credentials()'s own
      // packet["request_id"] = str(uuid.uuid4()) line exactly. Found
      // by real-browser execution during Phase 15B: without this, the
      // packet is accepted by the gateway and the server, but the
      // server never replies, and this method hangs forever awaiting
      // a response that was never going to come.
      const packet = P.createLoginRequestPacket(phoneNumber, password);
      packet.request_id = crypto.randomUUID();
      response = await this._sendAndReceiveOnce(ws, packet);
    } finally {
      ws.close();
    }

    if (!response || response.type !== "login_result" || !response.success) {
      throw new Error((response && response.message) || "Authentication failed.");
    }

    this.accessToken = response.access_token;

    // Phase 17: remembered in memory only (never persisted -- see the
    // constructor's own comment) so an automatic reconnect can obtain
    // a fresh access token without re-prompting the user.
    this._phoneNumber = phoneNumber;
    this._password = password;

    return response;
  }

  // Mirrors ClientSession.register(): same short-lived-connection
  // pattern as authenticateCredentials() above -- open, exchange
  // register_request/register_result, close. All validation (password
  // policy, username/email/phone uniqueness) is still performed
  // entirely server-side by the same, unchanged
  // AuthenticationService.register_user() every other client already
  // uses -- nothing here duplicates or second-guesses it.
  async register(fullName, username, email, phoneNumber, password, confirmPassword) {
    const ws = await this._openGatewaySocket();
    let response;
    try {
      const packet = P.createRegisterRequestPacket(fullName, username, email, phoneNumber, password, confirmPassword);
      packet.request_id = crypto.randomUUID();
      response = await this._sendAndReceiveOnce(ws, packet);
    } finally {
      ws.close();
    }

    if (!response || response.type !== "register_result" || !response.success) {
      const errors = response && response.errors;
      const detail = errors ? Object.values(errors).flat().join(" ") : null;
      throw new Error((response && response.message) || detail || "Registration failed.");
    }

    return response;
  }

  // Mirrors ClientSession.connect() + .login(username) + .send_public_key()
  // + .start_receiver(), on the persistent connection. Public entry
  // point for a FIRST connection (a fresh page load that just called
  // authenticateCredentials()) -- resets the reconnect state machine,
  // then delegates to _connectAndLoginInternal(), which is also what
  // _attemptReconnect() below calls for an automatic reconnect. Kept
  // as two methods (not one) so a caller reconnecting never
  // accidentally resets _reconnectAttempt back to 0 mid-backoff.
  async connectAndLogin(username) {
    this._intentionalDisconnect = false;
    this._reconnectAttempt = 0;
    await this._connectAndLoginInternal(username);
  }

  async _connectAndLoginInternal(username) {
    this._setConnectionState("connecting");

    this.ws = await this._openGatewaySocket();

    // Race guard (found via a real, reproducible failure while testing
    // Phase 18's offline-recovery scenario): _openGatewaySocket() above
    // awaits the WebSocket "open" event, a real gap during which an
    // explicit disconnect() (e.g. the user clicking logout right as an
    // automatic reconnect attempt happens to be in flight) can run to
    // completion and null out this.ws. Without this check, the code
    // below would still send on a by-then-stale or null socket --
    // observed as an uncaught "Cannot read properties of null (reading
    // 'send')". Checked again further below, after the OTHER await
    // points in this same method, for the identical reason.
    if (this._intentionalDisconnect) {
      try { this.ws.close(); } catch { /* already closing/closed */ }
      this.ws = null;
      throw new Error("Connection aborted: disconnect() was called.");
    }

    this.ws.addEventListener("message", (event) => this._handleIncoming(event));
    // Phase 17: the ONE place an unexpected disconnect is detected --
    // fires for a network blip, a gateway restart, a server restart,
    // or this browser's own explicit disconnect()/logout() alike; the
    // handler below is what tells those apart (_intentionalDisconnect).
    this.ws.addEventListener("close", () => this._handleSocketClosed());

    const authResultPromise = this._waitForPacketType("auth_result");
    this.ws.send(JSON.stringify(P.createAuthPacket(this.accessToken)));
    const authResult = await authResultPromise;

    if (this._intentionalDisconnect) {
      throw new Error("Connection aborted: disconnect() was called.");
    }

    if (!authResult || !authResult.success) {
      throw new Error((authResult && authResult.message) || "Server rejected authentication.");
    }

    this.username = authResult.username || username;

    // Phase 17: restore this browser's own previously-persisted
    // cryptographic identity + peer-trust + session-key state BEFORE
    // (re)announcing a public key -- if found, _sendPublicKey() below
    // reuses it instead of generating a fresh one, which is what keeps
    // this browser's identity (and therefore its fingerprint, and
    // therefore every peer's existing VERIFIED trust of it) stable
    // across a page reload. A no-op if this.kemKeypair is already set
    // (e.g. an in-tab reconnect that never lost JS memory in the first
    // place -- nothing to restore, the state was never gone).
    if (!this.kemKeypair) {
      await this._restoreState();
    }

    if (this._intentionalDisconnect || !this.ws) {
      throw new Error("Connection aborted: disconnect() was called.");
    }

    await this._sendPublicKey();
    await this._persistState();

    // Phase 19.23 -- Issue 1: restore the sidebar's direct-chat list
    // from the server, exactly where Desktop/Android call their own
    // load_conversations() at this same point in login. Best-effort:
    // a failure here must not fail the login itself (the user can
    // still open any chat manually), mirroring how this method
    // already treats every other post-auth step as non-fatal.
    try {
      this._restoredDirectPeers = await this.loadConversations();
    } catch (error) {
      this.log(`Could not load saved conversations: ${error.message}`);
      this._restoredDirectPeers = [];
    }

    this._setConnectionState("connected");
    this.log(`Connected and authenticated as ${this.username}.`);
  }

  // -------------------------------------------------------------
  // Phase 17 -- reconnect state machine.
  //
  // A dropped WebSocket has no lower-level "resume this exact prior
  // session" concept anywhere in the existing protocol (the gateway is
  // a pure per-connection bridge -- see web/gateway/gateway.py's own
  // module docstring -- and a fresh TCP connection to the real server
  // is always a fresh login, exactly like restarting the desktop
  // client). "Reconnect" here is therefore exactly that: redo the
  // real login sequence, using the SAME in-memory credentials and the
  // SAME (restored-if-needed) cryptographic identity -- never a new,
  // separate protocol.
  // -------------------------------------------------------------

  _setConnectionState(state) {
    this._connectionState = state;
    this.onConnectionState(state);
  }

  _handleSocketClosed() {
    this.ws = null;

    if (this._intentionalDisconnect) {
      this._setConnectionState("disconnected");
      return;
    }

    this._setConnectionState("reconnecting");
    this._scheduleReconnect();
  }

  _scheduleReconnect() {
    // Never a duplicate/overlapping timer -- one pending retry at a
    // time, and no reconnect at all once the user has explicitly
    // disconnected/logged out.
    if (this._reconnectTimer !== null || this._intentionalDisconnect) return;

    if (this._reconnectAttempt >= this.reconnectMaxAttempts) {
      this._setConnectionState("disconnected");
      this.log(`Gateway reconnect abandoned after ${this._reconnectAttempt} attempt(s).`);
      return;
    }

    const delay = Math.min(
      this.reconnectBaseDelayMs * Math.pow(2, this._reconnectAttempt),
      this.reconnectMaxDelayMs
    );
    this._reconnectAttempt += 1;

    this.log(
      `Connection lost -- reconnecting in ${delay}ms `
      + `(attempt ${this._reconnectAttempt}/${this.reconnectMaxAttempts}).`
    );

    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      this._attemptReconnect();
    }, delay);
  }

  async _attemptReconnect() {
    if (this._intentionalDisconnect) return;

    // No duplicate active connections: if something else already
    // re-established an open socket (should not happen given the
    // single-timer guard above, but checked defensively), do nothing.
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return;

    try {
      // A fresh access token every reconnect attempt, rather than
      // reusing a possibly-expired one -- the safe choice given this
      // client has no visibility into the JWT's remaining lifetime.
      await this.authenticateCredentials(this._phoneNumber, this._password);
      await this._connectAndLoginInternal(this.username);

      // Re-checked AFTER the awaits above, not just at entry: an
      // explicit disconnect() during this in-flight reconnect attempt
      // must still win -- otherwise a logout could be silently
      // "undone" by a reconnect that happened to complete moments
      // later, resurrecting a connection after the user asked to be
      // logged out.
      if (this._intentionalDisconnect) {
        this.disconnect();
        return;
      }

      this._reconnectAttempt = 0; // backoff resets only on a genuine success
      this.log("Reconnected.");
    } catch (error) {
      this.log(`Reconnect attempt failed: ${error.message}`);
      this._setConnectionState("reconnecting");
      this._scheduleReconnect();
    }
  }

  // -------------------------------------------------------------
  // Phase 17 -- local persistence (see storage.js for the storage
  // medium/encryption and its own documented security model).
  // -------------------------------------------------------------

  _serializeState() {
    return {
      kemKeypair: this.kemKeypair && {
        publicKey: C.bytesToBase64(this.kemKeypair.publicKey),
        secretKey: C.bytesToBase64(this.kemKeypair.secretKey),
      },
      signingKeypair: this.signingKeypair && {
        publicKey: C.bytesToBase64(this.signingKeypair.publicKey),
        secretKey: C.bytesToBase64(this.signingKeypair.secretKey),
      },
      peers: Array.from(this.peers.entries()).map(([username, peer]) => [
        username,
        {
          kemWire: peer.kemWire,
          signingKey: C.bytesToBase64(peer.signingKey),
          state: peer.state,
          fingerprint: peer.fingerprint,
        },
      ]),
      sessionKeys: Array.from(this.sessionKeys.entries()).map(([conversationId, info]) => [
        conversationId,
        { key: C.bytesToBase64(info.key), epoch: info.epoch },
      ]),
      directConversationIds: Array.from(this.directConversationIds.entries()),
      groups: Array.from(this.groups.entries()),
      deviceId: this.deviceId,
      conversationPrefs: Array.from(this.conversationPrefs.entries()),
    };
  }

  _applyRestoredState(stateObject) {
    if (stateObject.kemKeypair) {
      this.kemKeypair = {
        publicKey: C.base64ToBytes(stateObject.kemKeypair.publicKey),
        secretKey: C.base64ToBytes(stateObject.kemKeypair.secretKey),
      };
    }
    if (stateObject.signingKeypair) {
      this.signingKeypair = {
        publicKey: C.base64ToBytes(stateObject.signingKeypair.publicKey),
        secretKey: C.base64ToBytes(stateObject.signingKeypair.secretKey),
      };
    }
    this.peers = new Map(
      (stateObject.peers || []).map(([username, peer]) => [
        username,
        {
          kemWire: peer.kemWire,
          signingKey: C.base64ToBytes(peer.signingKey),
          state: peer.state,
          fingerprint: peer.fingerprint,
        },
      ])
    );
    this.sessionKeys = new Map(
      (stateObject.sessionKeys || []).map(([conversationId, info]) => [
        conversationId,
        { key: C.base64ToBytes(info.key), epoch: info.epoch },
      ])
    );
    this.directConversationIds = new Map(stateObject.directConversationIds || []);
    this.groups = new Map(stateObject.groups || []);
    this.deviceId = stateObject.deviceId || null;
    // Absent, not required: a state object persisted before Phase
    // 19.24 existed has no "conversationPrefs" section -- that
    // honestly means "no local preferences set yet", not a malformed
    // record (mirrors storage/secure_key_store.py::unlock()'s
    // identical "absent, not required" handling for its own
    // conversation_prefs section).
    this.conversationPrefs = new Map(stateObject.conversationPrefs || []);
  }

  async _restoreState() {
    if (!this.username || !this._password) return false;
    try {
      const stateObject = await S.loadEncryptedState(this.username, this._password);
      if (!stateObject) return false;
      this._applyRestoredState(stateObject);
      this.log("Restored this browser's persisted identity and trust state.");
      return true;
    } catch (error) {
      this.log(`Could not restore persisted state: ${error.message}`);
      return false;
    }
  }

  // Best-effort -- persistence failing (e.g. a private/incognito
  // context with IndexedDB disabled) must never block messaging or
  // any other real protocol operation, so every caller fire-and-
  // forgets this with .catch(), never awaits it on a critical path.
  async _persistState() {
    if (!this.username || !this._password) return;
    try {
      await S.saveEncryptedState(this.username, this._password, this._serializeState());
    } catch (error) {
      this.log(`Could not persist local state: ${error.message}`);
    }
  }

  async _sendPublicKey() {
    if (!this.kemKeypair) this.kemKeypair = C.generateKemKeypair();
    if (!this.signingKeypair) this.signingKeypair = C.generateSigningKeypair();

    const kemPublicKeyWire = C.bytesToBase64(this.kemKeypair.publicKey);

    const identityPayload = C.canonicalIdentityPayload(
      this.username, kemPublicKeyWire, this.signingKeypair.publicKey
    );
    const identitySignature = C.signPayload(this.signingKeypair.secretKey, identityPayload);

    const packet = P.createPublicKeyPacket(
      this.username,
      KEY_EXCHANGE_ALGORITHM,
      kemPublicKeyWire,
      C.bytesToBase64(this.signingKeypair.publicKey),
      C.bytesToBase64(identitySignature)
    );

    this.ws.send(JSON.stringify(packet));
  }

  // -------------------------------------------------------------
  // Request/response correlation for packets sent on the
  // persistent connection AFTER the receiver loop has started
  // (mirrors ClientSession.send_request()/PendingRequestRegistry).
  // -------------------------------------------------------------

  _sendRequest(packet) {
    const requestId = crypto.randomUUID();
    packet.request_id = requestId;
    return new Promise((resolve, reject) => {
      this._pendingRequests.set(requestId, { resolve, reject });
      this.ws.send(JSON.stringify(packet));
    });
  }

  // -------------------------------------------------------------
  // Incoming packet dispatch
  // -------------------------------------------------------------

  _handleIncoming(event) {
    let packet;
    try {
      packet = JSON.parse(event.data);
    } catch {
      this.log("Ignored a malformed (non-JSON) server message.");
      return;
    }

    if (packet && packet.request_id && this._pendingRequests.has(packet.request_id)) {
      const { resolve } = this._pendingRequests.get(packet.request_id);
      this._pendingRequests.delete(packet.request_id);
      resolve(packet);
      return;
    }

    if (!packet || typeof packet !== "object") return;

    this._resolveTypeWaiters(packet);

    switch (packet.type) {
      case "key_exchange":
        // Fire-and-forget (async): .catch() prevents an unhandled
        // promise rejection from surfacing as a spurious console
        // error for what is always a handled, logged failure path
        // (see _handlePeerPublicKey()'s own reject/log branches).
        if (packet.operation === "public_key") {
          this._handlePeerPublicKey(packet).catch((error) => this.log(`ERROR: ${error.message}`));
        }
        break;
      case "group_key_distribution":
        this._handleGroupKeyDistribution(packet).catch((error) => this.log(`ERROR: ${error.message}`));
        break;
      case "chat":
        this._handleChat(packet);
        break;
      case "user_list":
        this.onlineUsers = new Set(packet.users || []);
        this.log(`Online users: ${(packet.users || []).join(", ")}`);
        this.onOnlineUsersChanged(this.onlineUsers);
        break;
      // Phase 19.18 -- L-5 closure: a brand-new pushed notification, or
      // the resolution of one of THIS account's own earlier requests
      // (mirrors client/session.py's inbox_updated signal -- same two
      // packet types, same "go re-fetch the list" semantics).
      case "inbox_notification":
      case "inbox_response_result":
        this.onInboxUpdated(packet.notification || {});
        break;
      // Phase 19.18 -- Group Info remove-member closure: mirrors
      // client/session.py::handle_group_member_left() -- the server's
      // existing broadcast to every FORMER member (the removed one
      // included) whenever handle_group_remove_member()/
      // handle_group_leave() runs, regardless of which client
      // performed the removal. `members` is the complete, authoritative
      // remaining list -- replaced wholesale, never patched.
      case "group_member_left":
        if (this.groups.has(packet.conversation_id)) {
          this.groups.get(packet.conversation_id).members = packet.members || [];
          this.onGroupCreated(); // reuses the existing "groups changed, re-render" signal
        }
        break;
      case "group_create_result":
        // Fire-and-forget (async): distributing the group key on
        // creation is a real network operation -- see
        // _handleGroupCreateResult().
        this._handleGroupCreateResult(packet).catch((error) => this.log(`ERROR: ${error.message}`));
        break;
      case "read_receipt_notification":
        this.onReadReceipt(packet.conversation_id, packet.reader);
        this.log(`${packet.reader} has read up to now in ${packet.conversation_id}.`);
        break;
      case "typing_indicator_notification":
        // Phase 19.24 -- Typing Indicator. Never signature-verified --
        // same as read_receipt_notification above, this carries no
        // sensitive claim (unlike edit/delete/reaction/forward), just a
        // transient UI hint the server itself derived the sender for.
        if (packet.conversation_id && packet.username) {
          this.onTypingIndicator(packet.conversation_id, packet.username, Boolean(packet.is_typing));
        }
        break;
      case "message_delivered":
        // Phase 19.24 (continued) -- message_id is the FIRST thing
        // that ever tells a sender their own just-sent message's real,
        // server-assigned id (a fire-and-forget "chat" send gets no
        // synchronous ack carrying it) -- mirrors client/session.py's
        // own_message_id_resolved/mobile/session.py's identical
        // addition. Added as a 3rd argument -- safe by construction:
        // unlike Desktop's fixed-arity Qt Signal or mobile's plain-
        // function _Signal, a JS callback simply ignores an argument
        // it never declared a parameter for, so no existing onMessage
        // Delivered/onMessageQueued caller can break from this.
        this.onMessageDelivered(packet.conversation_id, packet.receiver, packet.message_id);
        break;
      case "message_queued":
        this.onMessageQueued(packet.conversation_id, packet.receiver, packet.message_id);
        break;
      // Phase 19.24 -- Message Lifecycle Events.
      case "message_edited": {
        const { message_id: messageId, conversation_id: conversationId, ciphertext } = packet;
        const editor = packet.editor || "";
        if (!messageId || !conversationId || !ciphertext || !editor) break;
        if (!this._verifyLifecycleEventSignature(
          editor, conversationId, "text", ciphertext, packet.content_metadata, packet.epoch,
          packet.message_signature, C.EDIT_PAYLOAD_PURPOSE, "message edit",
        )) break;
        const newText = this._decryptLifecycleEventContent(conversationId, ciphertext);
        this.onMessageEdited(
          conversationId, messageId, newText,
          editor, packet.edited_at || "", packet.edit_version || 0,
        );
        break;
      }
      case "message_deleted": {
        const { message_id: messageId, conversation_id: conversationId } = packet;
        if (!messageId || !conversationId) break;
        this.onMessageDeleted(conversationId, messageId, packet.deleted_by || "", packet.deleted_at || "");
        break;
      }
      case "reaction_updated": {
        const { message_id: messageId, conversation_id: conversationId, action } = packet;
        const actor = packet.actor || "";
        if (!messageId || !conversationId || (action !== "add" && action !== "remove") || !actor) break;
        let reaction = "";
        if (action === "add") {
          if (!packet.ciphertext) break;
          if (!this._verifyLifecycleEventSignature(
            actor, conversationId, "reaction", packet.ciphertext, null, packet.epoch,
            packet.message_signature, C.REACTION_PAYLOAD_PURPOSE, "reaction",
          )) break;
          reaction = this._decryptLifecycleEventContent(conversationId, packet.ciphertext);
        }
        this.onReactionUpdated(conversationId, messageId, actor, action, reaction);
        break;
      }
      case "message_pinned": {
        const { message_id: messageId, conversation_id: conversationId } = packet;
        const pinnedBy = packet.pinned_by || "";
        if (!messageId || !conversationId || !pinnedBy) break;
        this.onMessagePinned(conversationId, messageId, pinnedBy, packet.pinned_at || "");
        break;
      }
      case "message_unpinned": {
        const { message_id: messageId, conversation_id: conversationId } = packet;
        const unpinnedBy = packet.unpinned_by || "";
        if (!messageId || !conversationId || !unpinnedBy) break;
        this.onMessageUnpinned(conversationId, messageId, unpinnedBy);
        break;
      }
      case "device_key_sync":
        this._handleDeviceKeySync(packet).catch((error) => this.log(`ERROR: ${error.message}`));
        break;
      default:
        break; // presence/etc packets -- out of this client's scope
    }
  }

  // -------------------------------------------------------------
  // Peer identity: observe + human-verify (mirrors
  // ClientSession.handle_public_key()/observe_peer_identity()/
  // confirm_combined_peer_verification()).
  // -------------------------------------------------------------

  async _handlePeerPublicKey(packet) {
    const { username, public_key: kemWire, signing_public_key: signingKeyB64, identity_signature: sigB64 } = packet;

    if (!username || username === this.username || !kemWire) return;

    if (!signingKeyB64 || !sigB64) {
      this.log(`Ignoring legacy, unsigned public-key packet from ${username}.`);
      return;
    }

    const signingKey = C.base64ToBytes(signingKeyB64);
    const signature = C.base64ToBytes(sigB64);
    const payload = C.canonicalIdentityPayload(username, kemWire, signingKey);

    if (!C.verifyPayload(signature, payload, signingKey)) {
      this.log(`Rejected a public-key announcement from ${username}: signature did not verify.`);
      return;
    }

    const peer = await this._upsertPeerObservation(username, kemWire, signingKey);
    this.onPeerObserved(username, peer.fingerprint, peer.state);
  }

  // Shared upsert into this.peers (keyed by username for ordinary
  // peers, or by device_id for this account's OWN other devices --
  // see observeDevicePeerIdentity()/syncConversationKeyToDevice() --
  // both reuse this SAME VERIFIED/UNVERIFIED/KEY_CHANGED trust store,
  // exactly like ClientSession.observe_device_peer_identity() reusing
  // observe_peer_identity() unchanged). Factored out of
  // _handlePeerPublicKey() so both callers share one implementation of
  // the state-transition rule below.
  async _upsertPeerObservation(key, kemWire, signingKey) {
    const existing = this.peers.get(key);
    const fingerprint = await C.fingerprintCombinedIdentity(kemWire, signingKey);

    if (existing && existing.state === "VERIFIED" && existing.fingerprint !== fingerprint) {
      this.peers.set(key, { kemWire, signingKey, state: "KEY_CHANGED", fingerprint });
      this.log(`SECURITY: ${key}'s identity changed since it was verified -- re-verification required.`);
    } else if (!existing) {
      this.peers.set(key, { kemWire, signingKey, state: "UNVERIFIED", fingerprint });
    } else {
      existing.kemWire = kemWire;
      existing.signingKey = signingKey;
      existing.fingerprint = fingerprint;
    }

    this._persistState().catch((error) => this.log(`ERROR: ${error.message}`));
    return this.peers.get(key);
  }

  // Explicit, human confirmation -- the ONLY way a peer ever becomes
  // VERIFIED, exactly mirroring ClientSession.confirm_combined_peer_
  // verification()'s own "never automatic" invariant.
  confirmPeerVerified(username, confirmedFingerprint) {
    const peer = this.peers.get(username);
    if (!peer) throw new Error(`No observed identity for ${username} yet.`);
    if (peer.fingerprint !== confirmedFingerprint) {
      throw new Error("Fingerprint does not match the currently observed identity.");
    }
    peer.state = "VERIFIED";
    // Phase 17: persisted immediately -- a reload right after
    // verifying a peer must not lose that verification and force the
    // human to re-verify (fire-and-forget, matches this file's
    // existing async-call-from-a-sync-method convention).
    this._persistState().catch((error) => this.log(`ERROR: ${error.message}`));
  }

  isPeerVerified(username) {
    return this.peers.get(username)?.state === "VERIFIED";
  }

  // -------------------------------------------------------------
  // Key establishment (mirrors ClientSession.establish_session_key()
  // + _distribute_group_key(), Kyber/group_key_distribution path only).
  // -------------------------------------------------------------

  // Phase 19.23 -- Issue 1: mirrors client/session.py::
  // load_conversations() (Desktop) and mobile/session.py::
  // load_conversations() (Android) exactly -- the SAME already-
  // existing conversation_list_request/handle_conversation_list_
  // request() server round trip, previously never called from the web
  // client at all (main.js's own sidebar was built entirely from
  // knownDirectPeers, a page-local Set with no server backing -- see
  // its own comment). Populates directConversationIds/groups from the
  // server's authoritative list and returns the plain list of direct
  // peer usernames to seed the sidebar with, so a conversation with
  // real message history survives a login on a fresh browser/session
  // the same way it already does on Desktop and Android.
  //
  // Server-side, a direct conversation with zero messages is excluded
  // from this list on purpose (database/repositories/conversation_
  // repository.py::get_conversation_previews_for_user()'s own
  // documented reason). A peer who is VERIFIED but has no message
  // history yet is therefore ALSO included here, from this.peers --
  // itself already durable across a page reload via Phase 17's
  // _restoreState()/storage.js, not a new persistence mechanism --
  // exactly mirroring mobile/app.py's identical addition for the same
  // reason. Never a fake/fabricated conversation: every username
  // returned here is either a real, message-bearing server conversation,
  // or a real, mutually-verified trust relationship this browser
  // already has on file.
  async loadConversations() {
    const response = await this._sendRequest(P.createConversationListRequestPacket());
    const directPeers = [];

    for (const conversation of response.conversations || []) {
      const participants = conversation.participants || [];
      if (conversation.is_group) {
        const members = participants.includes(this.username) ? participants : [...participants, this.username];
        this.groups.set(conversation.conversation_id, {
          name: conversation.group_name || "Group",
          members,
        });
      } else {
        const partnerUsername = participants[0];
        if (!partnerUsername) continue;
        this.directConversationIds.set(partnerUsername, conversation.conversation_id);
        directPeers.push(partnerUsername);
      }
    }

    for (const [username, peer] of this.peers) {
      if (peer.state === "VERIFIED" && !directPeers.includes(username)) {
        directPeers.push(username);
      }
    }

    return directPeers;
  }

  async openDirectConversation(peerUsername) {
    if (this.directConversationIds.has(peerUsername)) {
      return this.directConversationIds.get(peerUsername);
    }
    const result = await this._sendRequest(P.createDirectConversationRequestPacket(peerUsername));
    if (result.error) throw new Error(result.error);
    this.directConversationIds.set(peerUsername, result.conversation_id);
    return result.conversation_id;
  }

  async establishSessionKey(peerUsername) {
    if (!this.isPeerVerified(peerUsername)) {
      throw new Error(`${peerUsername} is not VERIFIED -- cannot establish a session key.`);
    }

    const conversationId = await this.openDirectConversation(peerUsername);

    if (this.sessionKeys.has(conversationId)) {
      return this.sessionKeys.get(conversationId);
    }

    const reservation = await this._sendRequest(P.createEpochReservationRequestPacket(conversationId));
    if (reservation.error) throw new Error(reservation.error);
    const epoch = reservation.epoch;

    const sessionKey = C.randomAesKey();
    this.sessionKeys.set(conversationId, { key: sessionKey, epoch });

    const peer = this.peers.get(peerUsername);
    const peerKemPublicKeyRaw = C.base64ToBytes(peer.kemWire);

    const { cipherText, sharedSecret } = C.kemEncapsulate(peerKemPublicKeyRaw);
    const encapsulationB64 = C.bytesToBase64(cipherText);
    const wrappedKeyB64 = C.encryptForWire(sharedSecret, C.bytesToBase64(sessionKey));

    const groupKeyPayload = C.canonicalGroupKeyPayload(
      this.username, conversationId, peerUsername, encapsulationB64, wrappedKeyB64, epoch
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, groupKeyPayload);

    this.ws.send(JSON.stringify(P.createGroupKeyDistributionPacket(
      this.username, conversationId, peerUsername,
      encapsulationB64, wrappedKeyB64, epoch, C.bytesToBase64(signature)
    )));

    await this._persistState();

    return { key: sessionKey, epoch };
  }

  // -------------------------------------------------------------
  // Phase 18 -- group conversations (mirrors ClientSession.
  // create_group_conversation()/handle_group_create_result()/
  // _create_and_distribute_group_key()/_distribute_group_key()).
  // Reuses the EXACT same group_key_distribution packet/canonical
  // payload/KEM-then-DEM wrap as direct session-key establishment
  // above -- a group key is just that same mechanism fanned out to N
  // recipients instead of one; no second, weaker, web-only group
  // encryption scheme.
  // -------------------------------------------------------------

  async createGroup(name, memberUsernames) {
    this.ws.send(JSON.stringify(P.createGroupCreatePacket(this.username, name, memberUsernames)));
  }

  // Sent to every currently-connected member INCLUDING the creator
  // (mirrors server/client_handler.py::handle_group_create() and
  // ClientSession.handle_group_create_result() exactly) -- this is
  // how EVERY member, not just the creator, learns conversationId is
  // a group (recorded in this.groups BEFORE the creator's own
  // resulting key-distribution packets can arrive -- see
  // _handleGroupKeyDistribution()'s own comment on why that ordering
  // matters).
  async _handleGroupCreateResult(packet) {
    const { conversation_id: conversationId, name, creator, members } = packet;

    this.groups.set(conversationId, { name, members: members || [], admin: creator || null });
    this.onGroupCreated(conversationId, name, members || []);
    this.log(`Group '${name}' (${conversationId}) ready -- members: ${(members || []).join(", ")}`);

    await this._persistState();

    if (creator === this.username) {
      const participants = (members || []).filter((m) => m !== this.username);
      await this._createAndDistributeGroupKey(conversationId, participants);
    }
  }

  async _createAndDistributeGroupKey(conversationId, participants) {
    const groupKey = C.randomAesKey();
    const epoch = 1;
    this.sessionKeys.set(conversationId, { key: groupKey, epoch });

    for (const member of participants) {
      const peer = this.peers.get(member);

      // Mirrors ClientSession._distribute_group_key()'s own D6 --
      // Group Key Distribution Robustness: one member with no known
      // public key, or not yet VERIFIED, is skipped -- it never stops
      // the OTHER members in the loop from receiving the key.
      if (!peer) {
        this.log(`No observed identity for ${member}; cannot distribute the group key yet.`);
        continue;
      }
      if (peer.state !== "VERIFIED") {
        this.log(`SECURITY: ${member} is not VERIFIED; skipping group key distribution for them.`);
        continue;
      }

      const peerKemPublicKeyRaw = C.base64ToBytes(peer.kemWire);
      const { cipherText, sharedSecret } = C.kemEncapsulate(peerKemPublicKeyRaw);
      const encapsulationB64 = C.bytesToBase64(cipherText);
      const wrappedKeyB64 = C.encryptForWire(sharedSecret, C.bytesToBase64(groupKey));

      const groupKeyPayload = C.canonicalGroupKeyPayload(
        this.username, conversationId, member, encapsulationB64, wrappedKeyB64, epoch
      );
      const signature = C.signPayload(this.signingKeypair.secretKey, groupKeyPayload);

      this.ws.send(JSON.stringify(P.createGroupKeyDistributionPacket(
        this.username, conversationId, member,
        encapsulationB64, wrappedKeyB64, epoch, C.bytesToBase64(signature)
      )));
    }

    await this._persistState();
  }

  async sendGroupMessage(conversationId, text, replyToMessageId, clientMessageId, contentMetadata = null) {
    if (!this.sessionKeys.has(conversationId)) {
      throw new Error("No group key established for this conversation yet.");
    }

    const sessionInfo = this.sessionKeys.get(conversationId);
    const ciphertext = C.encryptForWire(sessionInfo.key, text);

    const messagePayload = C.canonicalMessagePayload(
      this.username, null, conversationId, "text", ciphertext, contentMetadata, sessionInfo.epoch
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, messagePayload);

    // Phase 19.24 -- Message Retry idempotency: a caller-supplied id
    // (a retry) or a fresh one generated here for an ordinary send.
    const finalClientMessageId = clientMessageId || crypto.randomUUID();

    this.ws.send(JSON.stringify(P.createPayloadPacket(
      this.username, null, conversationId, ciphertext, sessionInfo.epoch, C.bytesToBase64(signature),
      "text", contentMetadata, replyToMessageId, finalClientMessageId
    )));

    return finalClientMessageId;
  }

  // Mandatory order (mirrors ClientSession.handle_group_key_distribution()
  // exactly): resolve sender + require VERIFIED -> resolve trusted
  // signing key (LOCAL state only) -> verify signature -> THEN
  // decapsulate -> install. Any failure returns before decapsulation
  // is ever reached.
  async _handleGroupKeyDistribution(packet) {
    if (packet.recipient !== this.username) return; // routing noise, not a security event

    const { sender, conversation_id: conversationId, encapsulation, wrapped_key: wrappedKeyB64, epoch } = packet;

    if (!conversationId || !sender) {
      this._reportSecurityRejection("malformed_packet", sender, conversationId);
      return;
    }

    const peer = this.peers.get(sender);
    if (!peer || peer.state !== "VERIFIED") {
      this._reportSecurityRejection(
        !peer ? "unknown_sender" : peer.state === "KEY_CHANGED" ? "key_changed" : "unverified_sender",
        sender, conversationId
      );
      return;
    }

    const signatureB64 = packet.group_key_signature;
    if (!signatureB64) {
      this._reportSecurityRejection("missing_signature", sender, conversationId);
      return;
    }

    let signature;
    try {
      signature = C.base64ToBytes(signatureB64);
    } catch {
      this._reportSecurityRejection("malformed_packet", sender, conversationId);
      return;
    }

    const payload = C.canonicalGroupKeyPayload(
      sender, conversationId, this.username, encapsulation, wrappedKeyB64, epoch
    );

    if (!C.verifyPayload(signature, payload, peer.signingKey)) {
      this._reportSecurityRejection("invalid_signature", sender, conversationId);
      return;
    }

    // Only reached once verification has succeeded -- see this
    // method's own docstring above.
    try {
      const sharedSecret = C.kemDecapsulate(C.base64ToBytes(encapsulation), this.kemKeypair.secretKey);
      const sessionKeyB64 = C.decryptFromWire(sharedSecret, wrappedKeyB64);
      const sessionKey = C.base64ToBytes(sessionKeyB64);
      this.sessionKeys.set(conversationId, { key: sessionKey, epoch });
      // Phase 18: a GROUP key delivery must never be recorded as "my
      // direct conversation with `sender`" -- `sender` here is the
      // group's key-distributing member, not necessarily someone this
      // client will ever have a direct conversation with, and
      // overwriting a real future/existing direct mapping with a
      // group's conversation_id would misroute every later direct
      // message to `sender`. this.groups is populated by
      // _handleGroupCreateResult() before any member's key
      // distribution for a brand-new group can arrive (both react to
      // the same group_create_result broadcast).
      if (!this.groups.has(conversationId)) {
        this.directConversationIds.set(sender, conversationId);
      }
      this.log(`Installed a group/session key for ${sender} (epoch ${epoch}).`);
      await this._persistState();
    } catch {
      this._reportSecurityRejection("decryption_failure", sender, conversationId);
    }
  }

  _reportSecurityRejection(reason, sender, conversationId) {
    this.log(`SECURITY: rejected key establishment (${reason}) for conversation ${conversationId}, claimed sender ${sender}.`);
    const message = SECURITY_REJECTION_MESSAGES[reason] || "it failed a security check";
    if (reason === "duplicate_or_stale_key") return; // not an attack -- see gui/chat_window.py's identical exclusion
    this.onSecurityWarning(
      `Security warning: an incoming packet was rejected -- ${message}. No trusted key or identity state was changed.`
    );
  }

  // -------------------------------------------------------------
  // Messaging (mirrors ClientSession.send_chat_message()/handle_chat()).
  // -------------------------------------------------------------

  async sendMessage(peerUsername, text, replyToMessageId, clientMessageId, contentMetadata = null) {
    const conversationId = await this.openDirectConversation(peerUsername);
    const sessionInfo = this.sessionKeys.get(conversationId);
    if (!sessionInfo) {
      throw new Error("No session key established for this conversation yet.");
    }

    const ciphertext = C.encryptForWire(sessionInfo.key, text);

    const messagePayload = C.canonicalMessagePayload(
      this.username, peerUsername, null, "text", ciphertext, contentMetadata, sessionInfo.epoch
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, messagePayload);

    const finalClientMessageId = clientMessageId || crypto.randomUUID();

    this.ws.send(JSON.stringify(P.createPayloadPacket(
      this.username, peerUsername, null, ciphertext, sessionInfo.epoch, C.bytesToBase64(signature),
      "text", contentMetadata, replyToMessageId, finalClientMessageId
    )));

    return finalClientMessageId;
  }

  // ---------------------------------------------------------------
  // Phase 19.24 -- Message Lifecycle Events (edit/delete/reactions).
  // Mirrors client/session.py's identical methods exactly. Edit is
  // TEXT-only, same scope as Desktop/Android.
  // ---------------------------------------------------------------

  async editMessage(conversationId, messageId, newText, expectedEditVersion) {
    const sessionInfo = this.sessionKeys.get(conversationId);
    if (!sessionInfo) {
      throw new Error("No session key established for this conversation yet.");
    }

    const ciphertext = C.encryptForWire(sessionInfo.key, newText);
    const messagePayload = C.canonicalMessagePayload(
      this.username, null, conversationId, "text", ciphertext, null, sessionInfo.epoch,
      C.EDIT_PAYLOAD_PURPOSE
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, messagePayload);

    this.ws.send(JSON.stringify(P.createMessageEditPacket(
      messageId, ciphertext, null, sessionInfo.epoch, C.bytesToBase64(signature), expectedEditVersion
    )));
  }

  deleteMessageForMe(messageId) {
    this.ws.send(JSON.stringify(P.createMessageDeleteForMePacket(messageId)));
  }

  deleteMessageForEveryone(messageId) {
    this.ws.send(JSON.stringify(P.createMessageDeleteForEveryonePacket(messageId)));
  }

  addReaction(conversationId, messageId, reaction) {
    const sessionInfo = this.sessionKeys.get(conversationId);
    if (!sessionInfo) {
      throw new Error("No session key established for this conversation yet.");
    }
    const ciphertext = C.encryptForWire(sessionInfo.key, reaction);
    const reactionPayload = C.canonicalMessagePayload(
      this.username, null, conversationId, "reaction", ciphertext, null, sessionInfo.epoch,
      C.REACTION_PAYLOAD_PURPOSE
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, reactionPayload);
    this.ws.send(JSON.stringify(P.createReactionAddPacket(
      messageId, ciphertext, sessionInfo.epoch, C.bytesToBase64(signature)
    )));
  }

  removeReaction(messageId) {
    this.ws.send(JSON.stringify(P.createReactionRemovePacket(messageId)));
  }

  pinMessage(messageId) {
    this.ws.send(JSON.stringify(P.createMessagePinPacket(messageId)));
  }

  unpinMessage(messageId) {
    this.ws.send(JSON.stringify(P.createMessageUnpinPacket(messageId)));
  }

  // Forward: reuses the NORMAL sendMessage()/sendGroupMessage()/
  // sendAttachment() pipeline against the TARGET conversation's own
  // key -- never a reuse of the original ciphertext (encrypted for a
  // different key entirely). ``contentMetadata`` carries {forwarded:
  // true} additively, a client-side UI hint only.
  async forwardTextMessage(target, text) {
    const forwardMetadata = { forwarded: true };
    if (target.conversationId) {
      return this.sendGroupMessage(target.conversationId, text, undefined, undefined, forwardMetadata);
    }
    return this.sendMessage(target.peerUsername, text, undefined, undefined, forwardMetadata);
  }

  // Forward, attachment case (image/file/voice/video) -- same reuse
  // principle as forwardTextMessage() above: goes through the NORMAL
  // sendAttachment() pipeline against the target's own key, never a
  // reuse of the original ciphertext. A direct target's session key is
  // established first if it does not already exist (mirrors mobile/
  // app.py::ChatScreen._forward_bubble_to()'s identical establish-
  // first step, added for the same reason: forwarding to someone you
  // have not yet messaged must not throw an unhandled "no session key"
  // error).
  async forwardAttachment(target, fileBytes, filename, mimeType) {
    if (!target.conversationId) {
      await this.establishSessionKey(target.peerUsername);
    }
    return this.sendAttachment(target, fileBytes, filename, mimeType, { forwarded: true });
  }

  _decryptLifecycleEventContent(conversationId, ciphertext) {
    const sessionInfo = this.sessionKeys.get(conversationId);
    if (!sessionInfo) return "Message unavailable (encrypted in a previous session)";
    try {
      return C.decryptFromWire(sessionInfo.key, ciphertext);
    } catch {
      return "Message unavailable (encrypted in a previous session)";
    }
  }

  // Continued Phase 19.24 -- receiver-side verification. Mirrors
  // ClientSession._verify_lifecycle_event_signature() exactly: the
  // claimed actor's trusted signing key comes ONLY from this.peers
  // (this client's own already-established peer state), never from
  // the packet; purpose distinguishes an edit/reaction from an
  // ordinary chat message and from each other.
  _verifyLifecycleEventSignature(actor, conversationId, payloadType, ciphertext, contentMetadata, epoch, signatureB64, purpose, eventLabel) {
    if (!signatureB64) {
      this.log(`SECURITY: rejected unsigned ${eventLabel} claiming to be from ${actor}.`);
      return false;
    }
    // BUG FIX (continued Phase 19.24): the server broadcasts an edit/
    // reaction notification to EVERY conversation member, including
    // the ORIGINATING actor themselves (server/client_handler.py's
    // handle_message_edit()/handle_reaction_add() never pass
    // exclude_socket to _broadcast_to_conversation_members() for
    // these) -- exactly what lets a sender's own bubble update in
    // place without a history reload. this.peers, however, only ever
    // caches OTHER accounts' OBSERVED identities (nobody "observes"
    // their own public key arriving over the wire), so actor ===
    // this.username always missed there, incorrectly rejecting a
    // sender's own, perfectly genuine signature as unverifiable.
    // Resolved from this client's own signing keypair instead for
    // that one case -- still real cryptographic verification against
    // a public key this client unquestionably controls the private
    // half of, never a bypass.
    const signingKey = actor === this.username
      ? (this.signingKeypair && this.signingKeypair.publicKey)
      : (this.peers.get(actor) && this.peers.get(actor).signingKey);
    if (!signingKey) {
      this.log(`SECURITY: rejected ${eventLabel} from ${actor}: no ML-DSA identity observed for them.`);
      return false;
    }
    try {
      const signature = C.base64ToBytes(signatureB64);
      const payload = C.canonicalMessagePayload(
        actor, null, conversationId, payloadType, ciphertext, contentMetadata, epoch, purpose
      );
      if (!C.verifyPayload(signature, payload, signingKey)) {
        this.log(`SECURITY: signature verification FAILED for ${eventLabel} from ${actor}.`);
        return false;
      }
      return true;
    } catch (error) {
      this.log(`SECURITY: rejected malformed ${eventLabel} from ${actor}: ${error.message}`);
      return false;
    }
  }

  // Phase 18 -- File & Image Transfer. Mirrors ClientSession.send_
  // attachment()/payload/file_adapter.py::FilePayloadAdapter.encrypt()
  // EXACTLY: the raw bytes are base64-encoded into an ASCII string
  // FIRST, and THAT string is what AES-256-GCM-encrypts (via the SAME
  // encryptForWire() text messages already use) -- never a second,
  // binary-specific encryption path. content_metadata (filename,
  // mime_type, size_bytes) travels as a separate, unencrypted wire
  // field, exactly like the desktop.
  //
  // `target` is either { peerUsername } for a direct conversation or
  // { conversationId } for a group -- callers use openDirectConversation()
  // themselves for the direct case (mirrors sendMessage()'s own shape).
  async sendAttachment(target, fileBytes, filename, mimeType, extraMetadata = null) {
    if (fileBytes.byteLength > MAX_ATTACHMENT_SIZE_BYTES) {
      throw new Error(
        `'${filename}' is ${fileBytes.byteLength.toLocaleString()} bytes, which exceeds the `
        + `maximum attachment size of ${MAX_ATTACHMENT_SIZE_BYTES.toLocaleString()} bytes.`
      );
    }

    const payloadType = classifyAttachment(filename, mimeType);
    // extraMetadata (Phase 19.24 -- Forward) merges additively, same
    // as sendMessage()/sendGroupMessage()'s own contentMetadata param
    // -- forwardAttachment() below is the one caller that uses it, to
    // add {forwarded: true} without inventing a second send path.
    const contentMetadata = { filename, mime_type: mimeType, size_bytes: fileBytes.byteLength, ...extraMetadata };

    let conversationId;
    let receiver = null;
    if (target.conversationId) {
      conversationId = target.conversationId;
    } else {
      receiver = target.peerUsername;
      conversationId = await this.openDirectConversation(receiver);
    }

    const sessionInfo = this.sessionKeys.get(conversationId);
    if (!sessionInfo) {
      throw new Error("No session key established for this conversation yet.");
    }

    const base64File = C.bytesToBase64(fileBytes);
    const ciphertext = C.encryptForWire(sessionInfo.key, base64File);

    const messagePayload = C.canonicalMessagePayload(
      this.username, receiver, target.conversationId ? conversationId : null,
      payloadType, ciphertext, contentMetadata, sessionInfo.epoch
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, messagePayload);

    this.ws.send(JSON.stringify(P.createPayloadPacket(
      this.username, receiver, target.conversationId ? conversationId : null,
      ciphertext, sessionInfo.epoch, C.bytesToBase64(signature),
      payloadType, contentMetadata
    )));
  }

  // Signature verified BEFORE decryption -- mirrors client/session.py::
  // handle_chat()'s own explicit ordering (_verify_chat_message_signature()
  // runs first, from the packet's own raw fields). Generalized (Phase
  // 18) to any payload_type -- the verification/decryption pipeline
  // was already payload-type-agnostic in the desktop; the Stage-1 web
  // client had simply never exercised anything but "text".
  _handleChat(packet) {
    const {
      sender, receiver, conversation_id: conversationId, message: ciphertext, epoch,
      message_signature: sigB64, payload_type: payloadType, content_metadata: contentMetadata,
    } = packet;

    if (!sigB64) {
      this._reportSecurityRejection("missing_signature", sender, conversationId);
      return;
    }

    const peer = this.peers.get(sender);
    if (!peer) {
      this._reportSecurityRejection("unknown_sender", sender, conversationId);
      return;
    }

    let signature;
    try {
      signature = C.base64ToBytes(sigB64);
    } catch {
      this._reportSecurityRejection("malformed_packet", sender, conversationId);
      return;
    }

    const payload = C.canonicalMessagePayload(
      sender, receiver, conversationId, payloadType || "text", ciphertext, contentMetadata, epoch
    );

    if (!C.verifyPayload(signature, payload, peer.signingKey)) {
      this._reportSecurityRejection("invalid_signature", sender, conversationId);
      return;
    }

    // Phase 18: a GROUP message already carries its own real
    // conversation_id (the KeyManager lookup key) directly -- only a
    // DIRECT message needs the direct_conversation_id/local-mapping
    // fallback, mirroring client/session.py::handle_chat()'s own
    // identity_key/key_conversation_id split exactly.
    const sessionConversationId = conversationId || packet.direct_conversation_id || this.directConversationIds.get(sender);
    const sessionInfo = this.sessionKeys.get(sessionConversationId);
    if (!sessionInfo) {
      this._reportSecurityRejection("decryption_failure", sender, conversationId);
      return;
    }

    const identityKey = conversationId || sender;

    // Phase 18.5 -- Step 6 (History Deduplication): server/
    // client_handler.py now attaches message_id to every relayed
    // direct AND group "chat" packet (additive metadata only, never
    // part of the ML-DSA-signed payload above). Recorded here so a
    // LATER loadHistory() call recognizes this same message and skips
    // re-rendering it. A live packet legitimately has no message_id
    // only if it somehow originated from a server build that predates
    // this addition -- rendered normally either way, just not tracked
    // for dedup.
    if (packet.message_id) {
      let seen = this._renderedMessageIds.get(sessionConversationId);
      if (!seen) { seen = new Set(); this._renderedMessageIds.set(sessionConversationId, seen); }
      if (seen.has(packet.message_id)) return;
      seen.add(packet.message_id);
    }

    try {
      const decoded = C.decryptFromWire(sessionInfo.key, ciphertext);
      // Phase 19.24 (continued) -- messageId/replyToMessageId are the
      // one piece of lifecycle state a live "chat" packet can carry
      // (server/client_handler.py's relay branch forwards the sender's
      // original packet, reply_to_message_id included, unchanged,
      // before merely adding message_id to it); a brand-new message
      // cannot already be edited/deleted/reacted-to.
      const options = {
        messageId: packet.message_id, replyToMessageId: packet.reply_to_message_id,
        isDeleted: false, editVersion: 0, reactions: [],
      };
      if (!payloadType || payloadType === "text") {
        this.onMessage(identityKey, sender, decoded, options);
      } else {
        const fileBytes = C.base64ToBytes(decoded);
        this.onAttachment(identityKey, sender, payloadType, fileBytes, contentMetadata || {}, options);
      }
    } catch {
      this._reportSecurityRejection("decryption_failure", sender, conversationId);
    }
  }

  // -------------------------------------------------------------
  // Phase 18 -- message history recovery (mirrors ClientSession.
  // load_conversation_history()/_verify_history_message_signature()).
  // Addresses Phase 17's own named limitation: messages sent while
  // this browser was disconnected/reloaded were not recoverable.
  // Reuses the EXISTING server-side history mechanism
  // (message_history_request/result -- utils/protocol.py) unchanged;
  // no second, web-only history store.
  //
  // Phase 18.5 -- Step 6 (History Deduplication) + Step 7 (File/Image
  // History): both closed together here, since both changes touch the
  // same per-entry loop. Deduplication uses entry.message_id against
  // this._renderedMessageIds (shared with _handleChat()'s own live-
  // message tracking -- see that method's own comment). File/image
  // recovery reuses the EXISTING server-side blob_download_request/
  // result mechanism (Option A -- lazy blob delivery), the exact same
  // one ClientSession._load_blob_history_content() already uses -- no
  // new server endpoint, no new storage format, no fabricated history
  // entry: an attachment whose blob cannot actually be fetched/
  // decrypted is skipped, never rendered as if it existed.
  // -------------------------------------------------------------

  // Phase 19.17C -- see this._renderedMessageIds' own comment for why
  // this exists: main.js calls it right before every loadHistory(),
  // so a conversation being (re)opened is never wrongly treated as
  // "nothing new to show" just because it was rendered once already,
  // into DOM content that's since been cleared.
  forgetRenderedHistory(conversationId) {
    this._renderedMessageIds.delete(conversationId);
  }

  async loadHistory(conversationId, isGroup) {
    const result = await this._sendRequest(P.createMessageHistoryRequestPacket(conversationId, isGroup));
    if (result.error) throw new Error(result.error);

    const messages = result.messages || [];
    let loadedCount = 0;
    let seen = this._renderedMessageIds.get(conversationId);
    if (!seen) { seen = new Set(); this._renderedMessageIds.set(conversationId, seen); }

    for (const entry of messages) {
      // Step 6 -- a message already rendered (live, or by an earlier
      // loadHistory() call) is never rendered a second time.
      if (entry.message_id && seen.has(entry.message_id)) continue;

      // Phase 19.24 (continued) -- Message Lifecycle Events: a real
      // delete-for-everyone has ALREADY nulled ciphertext/blob_ref/
      // message_signature server-side (see server/client_handler.py::
      // handle_message_delete_for_everyone()) -- there is genuinely
      // nothing left to fetch/verify/decrypt. Mirrors client/session.py
      // ::load_conversation_history()'s / mobile/session.py::
      // load_history()'s identical guard, checked first.
      const isDeleted = Boolean(entry.deleted_at);

      let decoded = "";
      // BUG FIX (found during this phase's Forward-media work): this
      // list was never updated when Voice/Video shipped -- both are
      // ALSO in domain/payload_type.py::BLOB_STORAGE_PAYLOAD_TYPES
      // (server/client_handler.py never inlines their ciphertext in a
      // message_history_result entry, only blob_ref), so treating them
      // as non-blob-stored here skipped the blob-fetch step entirely
      // and left ciphertext null/undefined -- a voice/video message
      // silently failed to recover on history reload (and, since this
      // same method is what a freshly (re)connected client's own
      // conversation view resolves through, could leave even a LIVE
      // send looking like it never arrived once this path ran).
      const isBlobStored = ["file", "image", "voice", "video"].includes(entry.payload_type);

      if (!isDeleted) {
        let ciphertext = entry.ciphertext;

        if (isBlobStored) {
          // Step 7 -- the message_history_result entry itself never
          // carries FILE/IMAGE/VOICE/VIDEO content inline (only
          // blob_ref, metadata pointing at it) -- fetched here, lazily,
          // on demand, exactly where ClientSession._load_blob_history_
          // content() fetches it.
          if (!entry.blob_ref) continue; // no attachment actually stored -- nothing to recover
          try {
            const blobResult = await this._sendRequest(P.createBlobDownloadRequestPacket(entry.message_id));
            if (blobResult.error || !blobResult.ciphertext) continue; // not recoverable -- never render a misleading placeholder
            ciphertext = blobResult.ciphertext;
          } catch {
            continue;
          }
        }

        const signingPublicKey = entry.is_own
          ? this.signingKeypair.publicKey
          : this.peers.get(entry.sender)?.signingKey;

        if (!signingPublicKey || !entry.message_signature) continue; // cannot authenticate -- skip, never render unauthenticated

        // BUG FIX (continued Phase 19.24): mirrors client/session.py::
        // _verify_history_message_signature()'s / mobile/session.py::
        // load_history()'s identical fix -- an EDITED message's stored
        // message_signature is the EDIT's own signature (EDIT_PAYLOAD_
        // PURPOSE, addressed as receiver=null, conversation_id=<the real
        // conversation_id> -- see client/session.py::edit_message()'s
        // docstring, which this web client's own editMessage() mirrors),
        // not the original send's ordinary-purpose one. Verifying it
        // under the ordinary purpose/addressing always failed, silently
        // dropping the row from every history reload after the first
        // edit.
        const editVersion = entry.edit_version || 0;
        const verifyReceiver = editVersion ? null : entry.receiver;
        const verifyConversationId = editVersion ? conversationId : entry.conversation_id;
        const verifyPurpose = editVersion ? C.EDIT_PAYLOAD_PURPOSE : undefined;

        let verified;
        try {
          const signature = C.base64ToBytes(entry.message_signature);
          const payload = verifyPurpose
            ? C.canonicalMessagePayload(
                entry.sender, verifyReceiver, verifyConversationId,
                entry.payload_type || "text", ciphertext, entry.content_metadata, entry.epoch,
                verifyPurpose
              )
            : C.canonicalMessagePayload(
                entry.sender, verifyReceiver, verifyConversationId,
                entry.payload_type || "text", ciphertext, entry.content_metadata, entry.epoch
              );
          verified = C.verifyPayload(signature, payload, signingPublicKey);
        } catch {
          verified = false;
        }
        if (!verified) continue;

        const sessionInfo = this.sessionKeys.get(conversationId);
        if (!sessionInfo) continue; // stale/missing session key -- never guess, skip

        try {
          decoded = C.decryptFromWire(sessionInfo.key, ciphertext);
        } catch {
          continue; // undecryptable (stale epoch) -- skip, never guess
        }
      }

      if (entry.message_id) seen.add(entry.message_id);

      // Phase 19.23 -- Issue 3: carry this own message's tick state
      // (Sent/Delivered/Read) through history reload too, using the
      // server's additive "delivery_status" field -- mirrors
      // gui/chat_window.py (Desktop) and mobile/session.py::
      // load_history() (Android) exactly. Undefined for a message
      // this user did not send, or one with no receipt data at all.
      let status;
      if (entry.is_own) {
        if (entry.read_status === true) status = "read";
        else if (entry.read_status === false) status = entry.delivery_status === "delivered" ? "delivered" : "sent";
      }

      // Phase 19.24 (continued) -- reactions are verified/decrypted the
      // same way _handleReactionUpdated()'s "add" case does for a LIVE
      // one (this._verifyLifecycleEventSignature()) -- history recovery
      // applies the identical receiver-side trust check. A reaction
      // that fails verification is silently dropped from the list, not
      // fatal to the rest of history.
      const reactions = [];
      if (!isDeleted) {
        for (const reactionEntry of entry.reactions || []) {
          const reactor = reactionEntry.user;
          const reactionCiphertext = reactionEntry.ciphertext;
          if (!reactor || !reactionCiphertext) continue;
          if (!this._verifyLifecycleEventSignature(
            reactor, conversationId, "reaction", reactionCiphertext, null,
            reactionEntry.epoch, reactionEntry.message_signature,
            C.REACTION_PAYLOAD_PURPOSE, "reaction (history)"
          )) continue;
          const sessionInfo = this.sessionKeys.get(conversationId);
          if (!sessionInfo) continue;
          try {
            reactions.push({ user: reactor, reaction: C.decryptFromWire(sessionInfo.key, reactionCiphertext) });
          } catch {
            continue;
          }
        }
      }

      const options = {
        historical: true, timestamp: entry.timestamp, status,
        messageId: entry.message_id, replyToMessageId: entry.reply_to_message_id,
        isDeleted, editVersion: entry.edit_version || 0, reactions,
        // Phase 19.24 -- Pinned Messages: recovered on every history
        // load exactly like edit/delete/reaction state above.
        isPinned: !!entry.pinned_at, pinnedBy: entry.pinned_by || null,
      };

      if (isBlobStored) {
        const fileBytes = isDeleted ? new Uint8Array(0) : C.base64ToBytes(decoded);
        this.onAttachment(
          conversationId, entry.sender, entry.payload_type, fileBytes, entry.content_metadata || {},
          options
        );
      } else {
        this.onMessage(conversationId, entry.sender, decoded, options);
      }
      loadedCount += 1;
    }

    this.onHistoryLoaded(conversationId, loadedCount);
    this.log(`Loaded ${loadedCount} historical message(s) for ${conversationId}.`);
    return loadedCount;
  }

  // -------------------------------------------------------------
  // Phase 18 -- read receipts (mirrors ClientSession.mark_read()/
  // handle_read_receipt_notification()). Deliberately unsigned, exactly
  // like the desktop: create_read_receipt_packet()'s own docstring
  // states the server derives the reader from the authenticated
  // connection, never from anything client-supplied -- there is no
  // ML-DSA signature to reconstruct here, unlike every message/key/
  // identity packet above.
  // -------------------------------------------------------------

  markRead(conversationId) {
    this.ws.send(JSON.stringify(P.createReadReceiptPacket(conversationId)));
  }

  // -------------------------------------------------------------
  // Phase 19.24 -- Typing Indicator. Mirrors client/session.py::
  // send_typing_indicator()/mobile/session.py's identical method: a
  // safe no-op (never throws) if called after the socket has already
  // closed -- a debounce timer legitimately can fire after that.
  // Deliberately unsigned, exactly like markRead() above -- the server
  // derives who from the authenticated connection, never from anything
  // client-supplied, and it is a live hint only, never persisted or
  // replayed on history reload.
  // -------------------------------------------------------------

  sendTypingIndicator(conversationId, isTyping) {
    if (!conversationId || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    this.ws.send(JSON.stringify(P.createTypingIndicatorPacket(conversationId, isTyping)));
  }

  // -------------------------------------------------------------
  // Phase 19.24 -- Mute: local-only, per-conversation. Affects
  // notifications (this client's own unread-badge-equivalent
  // rendering in main.js -- there is no browser Notification API
  // wiring in this codebase to suppress either), never delivery --
  // mirrors client/session.py::ClientSession.mute_conversation()/
  // mobile/session.py::MobileClientSession's identical methods
  // field-for-field, just persisted via storage.js instead of
  // storage/secure_key_store.py.
  // -------------------------------------------------------------

  static MUTE_DURATIONS_MS = {
    "1h": 60 * 60 * 1000,
    "8h": 8 * 60 * 60 * 1000,
    "1w": 7 * 24 * 60 * 60 * 1000,
  };

  // A conversationPrefs entry can carry BOTH mutedUntil and archived
  // together -- every setter below merges into a copy of the existing
  // entry (never replaces the whole thing wholesale), mirroring
  // storage/secure_key_store.py's identical "dict(get(key, {}))" merge
  // pattern for the exact same reason: setting one field must never
  // silently erase the other.
  _updateConversationPrefs(conversationId, patch) {
    const entry = { ...(this.conversationPrefs.get(conversationId) || {}), ...patch };
    if (entry.mutedUntil === null || entry.mutedUntil === undefined) delete entry.mutedUntil;
    if (entry.archived !== true) delete entry.archived;
    if (!entry.wallpaper) delete entry.wallpaper;
    if (Object.keys(entry).length > 0) {
      this.conversationPrefs.set(conversationId, entry);
    } else {
      this.conversationPrefs.delete(conversationId);
    }
    this._persistState().catch((error) => this.log(`Could not persist conversation preferences: ${error.message}`));
  }

  muteConversation(conversationId, duration) {
    if (!conversationId) return;
    let mutedUntil;
    if (duration === "forever") {
      mutedUntil = "forever";
    } else {
      const ms = WebClientSession.MUTE_DURATIONS_MS[duration];
      if (ms === undefined) throw new Error(`Unknown mute duration: ${duration}`);
      mutedUntil = new Date(Date.now() + ms).toISOString();
    }
    this._updateConversationPrefs(conversationId, { mutedUntil });
  }

  unmuteConversation(conversationId) {
    if (!conversationId) return;
    this._updateConversationPrefs(conversationId, { mutedUntil: null });
  }

  isConversationMuted(conversationId) {
    const entry = this.conversationPrefs.get(conversationId);
    if (!entry || !entry.mutedUntil) return false;
    if (entry.mutedUntil === "forever") return true;
    const deadline = new Date(entry.mutedUntil);
    if (Number.isNaN(deadline.getTime())) return false;
    return Date.now() < deadline.getTime();
  }

  // -------------------------------------------------------------
  // Phase 19.24 -- Archive: local-only, per-conversation. Retains
  // history -- never deletes or hides anything server-side, purely a
  // "don't show this in my main list" local preference, exactly like
  // Mute above. Mirrors client/session.py::ClientSession.archive_
  // conversation()/mobile/session.py::MobileClientSession's identical
  // methods field-for-field.
  // -------------------------------------------------------------

  archiveConversation(conversationId) {
    if (!conversationId) return;
    this._updateConversationPrefs(conversationId, { archived: true });
  }

  unarchiveConversation(conversationId) {
    if (!conversationId) return;
    this._updateConversationPrefs(conversationId, { archived: false });
  }

  isConversationArchived(conversationId) {
    return Boolean(this.conversationPrefs.get(conversationId)?.archived);
  }

  // -------------------------------------------------------------
  // Phase 19.24 -- Chat Wallpaper: local-only, per-conversation, same
  // conversationPrefs entry as Mute/Archive above -- never sent to or
  // stored by the server. A PRESET id (one of main.js's own WALLPAPER_
  // PRESETS keys), never arbitrary image bytes.
  // -------------------------------------------------------------

  setConversationWallpaper(conversationId, wallpaperId) {
    if (!conversationId) return;
    this._updateConversationPrefs(conversationId, { wallpaper: wallpaperId || undefined });
  }

  getConversationWallpaper(conversationId) {
    return this.conversationPrefs.get(conversationId)?.wallpaper || null;
  }

  // -------------------------------------------------------------
  // Phase 18 Step 8 -- Web Multi-Device Identity.
  //
  // Mirrors ClientSession's own device methods (client/session.py)
  // name-for-name and step-for-step: self-signed enrollment -> PENDING
  // until an already-AUTHORIZED device vouches for it (out-of-band
  // fingerprint comparison, exactly like ordinary peer verification --
  // never automatic just because two devices share an account) ->
  // AUTHORIZED devices can then synchronize already-established
  // conversation/group keys to each other. No new packet type, no new
  // cryptographic construction: the SAME device_enroll_request/
  // device_list_request/device_authorize/device_revoke/
  // device_key_sync wire packets utils/protocol.py already defines for
  // the desktop client, the SAME crypto/device_protocol.py canonical
  // payloads (ported byte-for-byte to crypto.js, proven interoperable
  // in tests/test_web_client_crypto_interop.py), the SAME server-side
  // server/device_handler.py -- reached unmodified through
  // web/gateway/gateway.py's own packet-type-agnostic relay (see that
  // file's own docstring: it never inspects a packet's `type` field at
  // all). Device-peer trust reuses this.peers (keyed by device_id
  // instead of username) rather than a second trust store, exactly
  // like ClientSession.observe_device_peer_identity() reusing
  // observe_peer_identity() unchanged.
  //
  // this.deviceId is generated once and persisted (see
  // _serializeState()/_applyRestoredState()) the same way the KEM/
  // ML-DSA keypair themselves already are -- a second enrollDevice()
  // call from a restored session resolves to the SAME device_id, and
  // therefore the SAME server-side row, rather than minting a new
  // device on every login. No dedicated UI panel is added for this
  // beyond what index.html already exposes (a plain enroll/list/
  // authorize/sync form) -- consistent with the desktop client itself,
  // which also exposes this only at the ClientSession/API layer with
  // no gui/ wiring of its own (verified by inspection: no gui/*.py
  // file references any of these methods).
  // -------------------------------------------------------------

  async enrollDevice(deviceName, platform) {
    if (!this.kemKeypair) this.kemKeypair = C.generateKemKeypair();
    if (!this.signingKeypair) this.signingKeypair = C.generateSigningKeypair();

    const newlyResolvedDeviceId = this.deviceId === null;
    if (newlyResolvedDeviceId) {
      this.deviceId = crypto.randomUUID();
      await this._persistState();
    }

    const kemPublicKeyWire = C.bytesToBase64(this.kemKeypair.publicKey);
    const mlDsaPublicKey = this.signingKeypair.publicKey;

    const payload = C.canonicalDeviceEnrollmentPayload(
      this.username, this.deviceId, kemPublicKeyWire, mlDsaPublicKey, deviceName, platform
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, payload);

    const result = await this._sendRequest(P.createDeviceEnrollRequestPacket(
      this.deviceId, deviceName || "", platform || "",
      kemPublicKeyWire, C.bytesToBase64(mlDsaPublicKey), C.bytesToBase64(signature)
    ));
    if (!result.success) throw new Error(result.error || "Device enrollment failed.");
    this.log(`Device enrolled: ${this.deviceId} (state: ${result.state}).`);
    return result;
  }

  // Proves THIS connection is genuinely operated by the party holding
  // the private ML-DSA key for this.deviceId (Phase 16B -- Device
  // Authentication Binding). Requires enrollDevice() to have already
  // resolved this.deviceId, and the device to already be AUTHORIZED
  // server-side. Once bound, server-side relay paths that opt into
  // device-state enforcement (currently: device_key_sync's own sender/
  // target checks -- see server/device_handler.py::
  // is_device_bound_and_authorized()) re-check this connection's live
  // AUTHORIZED/REVOKED state on every subsequent packet.
  async bindDeviceSession() {
    if (!this.deviceId) throw new Error("No deviceId -- call enrollDevice() first.");

    const sessionNonce = crypto.randomUUID();
    const payload = C.canonicalDeviceSessionBindingPayload(this.username, this.deviceId, sessionNonce);
    const signature = C.signPayload(this.signingKeypair.secretKey, payload);

    const result = await this._sendRequest(P.createDeviceSessionBindPacket(
      this.deviceId, sessionNonce, C.bytesToBase64(signature)
    ));
    if (!result.success) throw new Error(result.error || "Device session binding failed.");
    this.log(`Bound this connection to device ${this.deviceId}.`);
    return result;
  }

  async listDevices() {
    const result = await this._sendRequest(P.createDeviceListRequestPacket());
    return result.devices || [];
  }

  // Phase 19.18 -- L-5 closure: mirrors ClientSession.
  // request_verification()/load_inbox()/respond_to_inbox() exactly --
  // same already-existing, already-tested server-side handlers
  // Desktop/Mobile already use, not a second, weaker implementation.
  async requestVerification(targetUsername) {
    this.ws.send(JSON.stringify(P.createVerificationRequestPacket(targetUsername)));
  }

  async loadInbox() {
    const result = await this._sendRequest(P.createInboxListRequestPacket());
    return result.notifications || [];
  }

  // Security: approving a verification_request is the ONLY place that
  // can happen from here, and it does so by calling THIS client's own
  // already-existing, unweakened confirmPeerVerified() with the
  // fingerprint THIS client has already independently observed for
  // the requester -- never a value taken from the notification itself
  // (which carries no key material at all). If nothing has been
  // observed yet, this throws and MUST NOT send approve=true to the
  // server -- mirrors ClientSession.respond_to_inbox()'s own docstring
  // exactly, including that guarantee.
  async respondToInbox(notification, approve) {
    if (approve && notification.type === "verification_request") {
      const requesterUsername = notification.requester_username;
      const peer = this.peers.get(requesterUsername);
      if (!peer || !peer.fingerprint) {
        throw new Error(
          `No observed identity for ${requesterUsername} yet; cannot verify them until they are online and you have exchanged keys.`
        );
      }
      this.confirmPeerVerified(requesterUsername, peer.fingerprint);
    }
    this.ws.send(JSON.stringify(P.createInboxResponsePacket(notification.notification_id, approve)));
  }

  // Phase 19.18 -- L-Group-Info closure: mirrors ClientSession.
  // remove_group_member() exactly -- server re-derives the admin from
  // the database on every call, never trusts this request or whether
  // the UI happened to show a Remove button.
  async removeGroupMember(conversationId, targetUsername) {
    return this._sendRequest(P.createGroupRemoveMemberPacket(conversationId, targetUsername));
  }

  // Phase 19.17C -- mirrors MobileClientSession.change_username()/change_password() exactly,
  // same already-existing, already-tested server-side handlers.
  async changeUsername(newUsername) {
    const response = await this._sendRequest(P.createChangeUsernameRequestPacket(newUsername));
    if (response.success) this.username = newUsername;
    return response;
  }

  async changePassword(currentPassword, newPassword, confirmPassword) {
    return this._sendRequest(P.createChangePasswordRequestPacket(currentPassword, newPassword, confirmPassword));
  }

  // -------------------------------------------------------------
  // Phase 19.24 -- Block User: mirrors client/session.py::
  // ClientSession's identical methods exactly, including the same
  // local blockedUsernames cache contract (see its own docstring) --
  // real server-side enforcement, never a local-only preference like
  // Mute/Archive.
  // -------------------------------------------------------------

  async blockUser(targetUsername) {
    const response = await this._sendRequest(P.createBlockUserRequestPacket(targetUsername));
    if (response.success) this.blockedUsernames.add(targetUsername);
    return response;
  }

  async unblockUser(targetUsername) {
    const response = await this._sendRequest(P.createUnblockUserRequestPacket(targetUsername));
    if (response.success) this.blockedUsernames.delete(targetUsername);
    return response;
  }

  async getBlockedUsers() {
    const response = await this._sendRequest(P.createBlockedUsersListRequestPacket());
    const usernames = response.usernames || [];
    this.blockedUsernames = new Set(usernames);
    return usernames;
  }

  isUserBlocked(username) {
    return this.blockedUsernames.has(username);
  }

  // Phase 19.24 -- Presence/Last Seen: mirrors client/session.py::
  // fetch_last_seen()/mobile/session.py's identical method exactly --
  // null covers "blocked in either direction", "account not found",
  // and "no last-seen information yet" alike (server/client_handler.py
  // ::handle_last_seen_request()'s own docstring).
  async fetchLastSeen(username) {
    const response = await this._sendRequest(P.createLastSeenRequestPacket(username));
    if (!response.found || !response.last_seen_at) return null;
    return new Date(response.last_seen_at + "Z");
  }

  // Phase 19.17C -- mirrors MobileClientSession.upload_profile_picture()/
  // fetch_profile_picture() exactly: same request/response packets,
  // same server-side handlers (server/client_handler.py::handle_
  // profile_picture_upload_request()/handle_profile_picture_request()),
  // reused unchanged. Not end-to-end encrypted by design -- see
  // createProfilePictureUploadRequestPacket()'s own comment.
  async uploadProfilePicture(imageBytes, contentType) {
    const imageBase64 = C.bytesToBase64(imageBytes);
    const result = await this._sendRequest(P.createProfilePictureUploadRequestPacket(imageBase64, contentType));
    if (!result.success) throw new Error(result.error || "Profile picture upload failed.");
    return result;
  }

  async fetchProfilePicture(username) {
    const result = await this._sendRequest(P.createProfilePictureRequestPacket(username));
    if (!result.found) return null;
    return { bytes: C.base64ToBytes(result.image_base64), contentType: result.content_type };
  }

  // Observe another of THIS account's own devices (from listDevices()'s
  // own kem_public_key/ml_dsa_public_key fields) as a device-peer --
  // UNVERIFIED until explicitly confirmed via confirmDevicePeerVerified().
  // ml_dsa_public_key is base64 on the wire (see server/device_handler.py::
  // handle_device_list_request()) -- decoded to raw bytes here, matching
  // what canonicalDeviceEnrollmentPayload()/fingerprintCombinedIdentity()
  // both expect.
  async observeDevicePeerIdentity(deviceId, kemPublicKeyWire, mlDsaPublicKeyB64) {
    const mlDsaPublicKey = C.base64ToBytes(mlDsaPublicKeyB64);
    const peer = await this._upsertPeerObservation(deviceId, kemPublicKeyWire, mlDsaPublicKey);
    this.log(`Observed device ${deviceId} (state: ${peer.state}).`);
    return peer;
  }

  confirmDevicePeerVerified(deviceId, confirmedFingerprint) {
    this.confirmPeerVerified(deviceId, confirmedFingerprint);
  }

  // Vouch for a PENDING device as this (already-AUTHORIZED) device --
  // the caller is responsible for having compared targetFingerprint
  // against the target device's displayed fingerprint out-of-band
  // FIRST (mirrors ClientSession.authorize_device()'s identical
  // division of responsibility between human judgment and signing).
  async authorizeDevice(targetDeviceId, targetFingerprint) {
    const payload = C.canonicalDeviceAuthorizationPayload(
      this.username, targetDeviceId, targetFingerprint, this.deviceId
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, payload);

    const result = await this._sendRequest(P.createDeviceAuthorizePacket(
      targetDeviceId, targetFingerprint, this.deviceId, C.bytesToBase64(signature)
    ));
    if (!result.success) throw new Error(result.error || "Device authorization failed.");
    this.log(`Authorized device ${targetDeviceId}.`);
    return result;
  }

  async revokeDevice(targetDeviceId) {
    const payload = C.canonicalDeviceRevocationPayload(this.username, targetDeviceId, this.deviceId);
    const signature = C.signPayload(this.signingKeypair.secretKey, payload);

    const result = await this._sendRequest(P.createDeviceRevokePacket(
      targetDeviceId, this.deviceId, C.bytesToBase64(signature)
    ));
    if (!result.success) throw new Error(result.error || "Device revocation failed.");
    this.log(`Revoked device ${targetDeviceId}.`);
    return result;
  }

  // Wrap THIS client's own current key for `conversationId` for
  // delivery to `targetDeviceId` (one of this SAME account's other
  // devices) and send it. Reuses the exact same KEM-encapsulate-then-
  // AES-256-GCM-wrap composition ordinary group-key distribution
  // already uses (kemEncapsulate/encryptForWire) -- no new
  // cryptographic construction. Requires the target device to already
  // be device-peer VERIFIED, mirroring establishSessionKey()'s
  // identical guard for ordinary peers.
  async syncConversationKeyToDevice(targetDeviceId, conversationId, packageType) {
    if (!this.isPeerVerified(targetDeviceId)) {
      throw new Error(`Device ${targetDeviceId} is not VERIFIED -- cannot synchronize a key to it.`);
    }
    const sessionInfo = this.sessionKeys.get(conversationId);
    if (!sessionInfo) throw new Error(`No key held for conversation ${conversationId} to synchronize.`);

    const targetPeer = this.peers.get(targetDeviceId);
    const targetFingerprint = targetPeer.fingerprint;

    const targetKemPublicKeyRaw = C.base64ToBytes(targetPeer.kemWire);
    const { cipherText, sharedSecret } = C.kemEncapsulate(targetKemPublicKeyRaw);
    const encapsulationB64 = C.bytesToBase64(cipherText);
    const wrappedKeyB64 = C.encryptForWire(sharedSecret, C.bytesToBase64(sessionInfo.key));

    const payload = C.canonicalDeviceKeySyncPayload(
      this.username, this.deviceId, targetDeviceId, targetFingerprint,
      conversationId, sessionInfo.epoch, packageType || "direct", encapsulationB64, wrappedKeyB64
    );
    const signature = C.signPayload(this.signingKeypair.secretKey, payload);

    const result = await this._sendRequest(P.createDeviceKeySyncPacket(
      targetDeviceId, targetFingerprint, conversationId, sessionInfo.epoch,
      packageType || "direct", encapsulationB64, wrappedKeyB64, C.bytesToBase64(signature)
    ));
    if (!result.success) throw new Error(result.error || "Device key sync failed.");
    this.log(`Synchronized conversation ${conversationId} to device ${targetDeviceId}.`);
    return result;
  }

  // Receive wrapped conversation/group key material pushed from
  // another of THIS account's own devices. Mandatory order (identical
  // shape to _handleGroupKeyDistribution() above, and to
  // ClientSession.handle_device_key_sync()): require source device-
  // peer VERIFIED -> resolve trusted signing key from LOCAL state
  // only -> verify signature -> THEN decapsulate/decrypt -> install.
  async _handleDeviceKeySync(packet) {
    if (packet.target_device_id !== this.deviceId) return; // routing noise, not a security event

    const { source_device_id: sourceDeviceId, conversation_id: conversationId, encapsulation, wrapped_key: wrappedKeyB64, epoch } = packet;

    if (!sourceDeviceId || !conversationId) {
      this._reportSecurityRejection("malformed_packet", sourceDeviceId, conversationId);
      return;
    }

    const peer = this.peers.get(sourceDeviceId);
    if (!peer || peer.state !== "VERIFIED") {
      this._reportSecurityRejection(
        !peer ? "unknown_sender" : peer.state === "KEY_CHANGED" ? "key_changed" : "unverified_sender",
        sourceDeviceId, conversationId
      );
      return;
    }

    const signatureB64 = packet.sync_signature;
    if (!signatureB64) {
      this._reportSecurityRejection("missing_signature", sourceDeviceId, conversationId);
      return;
    }

    let signature;
    try {
      signature = C.base64ToBytes(signatureB64);
    } catch {
      this._reportSecurityRejection("malformed_packet", sourceDeviceId, conversationId);
      return;
    }

    // packet.sender is the SERVER-authenticated source username,
    // injected by server/device_handler.py::handle_device_key_sync()
    // when relaying (relay_packet["sender"] = user.username) -- never
    // client-claimed. Structurally always equal to this.username in
    // practice (device_key_sync is only ever relayed between two
    // devices of the SAME account -- the server itself enforces
    // target_device.user_id == user.id), but read from the packet
    // rather than assumed, exactly like every other sender field this
    // client verifies.
    const payload = C.canonicalDeviceKeySyncPayload(
      packet.sender, sourceDeviceId, this.deviceId, packet.target_fingerprint,
      conversationId, epoch, packet.package_type, encapsulation, wrappedKeyB64
    );

    if (!C.verifyPayload(signature, payload, peer.signingKey)) {
      this._reportSecurityRejection("invalid_signature", sourceDeviceId, conversationId);
      return;
    }

    try {
      const sharedSecret = C.kemDecapsulate(C.base64ToBytes(encapsulation), this.kemKeypair.secretKey);
      const sessionKeyB64 = C.decryptFromWire(sharedSecret, wrappedKeyB64);
      const sessionKey = C.base64ToBytes(sessionKeyB64);
      this.sessionKeys.set(conversationId, { key: sessionKey, epoch });
      this.log(`Installed a synced key for conversation ${conversationId} from device ${sourceDeviceId}.`);
      await this._persistState();
    } catch {
      this._reportSecurityRejection("decryption_failure", sourceDeviceId, conversationId);
    }
  }

  // The ONE explicit "I'm done" entry point (used for both an
  // ordinary disconnect and a user-initiated logout -- there is no
  // separate logout() method: every existing caller of disconnect(),
  // including this project's own tests, already means "tear this
  // down for good," so that is what this now guarantees). Sets
  // _intentionalDisconnect BEFORE closing the socket, so the "close"
  // listener installed in _connectAndLoginInternal() -- which is what
  // decides whether to schedule a reconnect -- sees it and does
  // nothing. Cancels any pending reconnect timer outright, so a
  // logout mid-backoff cannot still silently reconnect moments later.
  disconnect() {
    this._intentionalDisconnect = true;

    if (this._reconnectTimer !== null) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    this._setConnectionState("disconnected");
  }
}
