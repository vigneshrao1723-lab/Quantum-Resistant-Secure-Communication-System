# Web Interoperability (Phase 15, Stage 1)

Proves that a browser can speak this project's real protocol,
end-to-end, against the real, unmodified server -- without changing
the server, the wire protocol, or the cryptographic architecture. See
[System Architecture](system_architecture.md) and
[Security Architecture](security/security_architecture.md) for the
desktop-side design this extends; nothing there changed.

This document also records, precisely and without overstatement, what
was and was not dynamically executed while building this -- see
"What was and was not dynamically executed" below before citing any
claim from this document elsewhere.

## Why a browser needs a gateway at all

A browser cannot open the raw TCP socket the existing desktop protocol
requires (`security/tls.py` + `utils/network.py`'s 4-byte-length-
prefixed JSON framing) -- confirmed in Phase 14.5's audit. The minimum
bridge:

```
Browser (WebSocket, ws://.../wss://)
        |
        v
web/gateway/gateway.py   (new, this phase)
        |  opens its own ordinary TLS+TCP connection to the real
        |  server, using the SAME security.tls.build_client_context()
        |  and the SAME utils.network.send_message()/receive_message()
        |  framing every desktop client already uses
        v
server/server.py   (completely unmodified)
```

`web/gateway/gateway.py` is one asyncio process; one WebSocket
connection maps to exactly one TLS+TCP connection to the server, for
that connection's whole lifetime (mirrors `ClientSession`'s own
one-socket-per-session model).

## Trust boundary

**The gateway is a transport bridge, not a cryptographic endpoint.**
It re-frames already-opaque JSON packets between a WebSocket text
frame and the server's TCP frame -- it never inspects, decrypts,
decodes, or modifies a packet's cryptographic fields (`message`,
`wrapped_key`, `encapsulation`, any `*_signature` field). Confirmed
both by code (there is no AES/Kyber/ML-DSA/RSA import anywhere in
`web/gateway/gateway.py`) and by test
(`tests/test_web_gateway_interop.py::
test_gateway_relays_public_key_packet_byte_for_byte`, and the
Desktop↔Web test below, both confirm an opaque marker value survives
the WS↔TCP round trip byte-for-byte).

This is the exact same relationship the existing server already has
to message content (see
[Security Architecture](security/security_architecture.md)'s
"server is a relay, not a key holder") -- the gateway adds a second
relay hop, not a second party that must be trusted with plaintext.

**End-to-end confidentiality and authenticity remain entirely between
the two session endpoints** (a desktop `ClientSession` and this repo's
web client) -- exactly as before this phase. The gateway never
possesses any session/group AES key, any ML-DSA private key, or any
ML-KEM/RSA private key, because those never leave the browser or the
desktop client in the first place.

**Malformed/oversized frames fail closed at the gateway**, before ever
reaching the server: a non-JSON WebSocket text frame is logged and
dropped (the connection stays usable); an oversized frame is rejected
by `websockets`' own `max_size` (set to `config.MAX_FRAME_BYTES`, the
same limit the TCP protocol already enforces -- not a second,
independently-chosen limit). Both proven in
`tests/test_web_gateway_interop.py`.

## Protocol mapping

Every packet shape below is copied field-for-field from
`utils/protocol.py` -- none invented. See `web/client/protocol.js`.

| Existing Python packet | Web client (`protocol.js`) | Purpose |
|---|---|---|
| `create_login_request_packet()` | `createLoginRequestPacket()` | phone+password -> JWT (short-lived connection, mirrors `ClientSession.authenticate_credentials()`) |
| `create_auth_packet()` | `createAuthPacket()` | JWT -> authenticated persistent connection (mirrors `ClientSession.login()`) |
| `create_public_key_packet()` | `createPublicKeyPacket()` | ML-KEM public key + ML-DSA identity announcement (mirrors `ClientSession.send_public_key()`) |
| `create_direct_conversation_request_packet()` | `createDirectConversationRequestPacket()` | resolve/create a direct conversation id |
| `create_epoch_reservation_request_packet()` | `createEpochReservationRequestPacket()` | reserve a fresh key epoch before establishing a session key |
| `create_group_key_distribution_packet()` | `createGroupKeyDistributionPacket()` | deliver a wrapped AES session/group key (Kyber KEM-then-DEM path -- the only path this client uses, matching the project's own default algorithm) |
| `create_payload_packet()` (text) | `createPayloadPacket()` | signed, encrypted chat message |

No RSA session-key packet, file/image payload, group-membership, or
read-receipt packet is built by this Stage-1 client -- explicitly out
of the "first milestone" scope this phase was given.

## Cryptography

| Primitive | Desktop (Python) | Web client (JS) | Interoperability proof |
|---|---|---|---|
| ML-KEM-768 | `crypto/kyber.py` (`kyber-py`) | `@noble/post-quantum` `ml-kem.js` | `tests/test_web_client_crypto_interop.py` TEST A (both directions, real `kyber-py` ↔ real `noble`) |
| ML-DSA-65 | `crypto/ml_dsa.py` (`cryptography`) | `@noble/post-quantum` `ml-dsa.js` | Same file, TEST B/C (both directions, correct signing context, tamper-rejection proven) |
| AES-256-GCM | `crypto/aes.py` (PyCryptodome) | `@noble/ciphers` `aes.js` | Same file, TEST D/E (both directions, tamper-rejection proven) |
| Canonical signed-payload byte encoding | `crypto/identity_protocol.py`, `crypto/group_key_protocol.py`, `crypto/message_protocol.py` | `web/client/crypto.js` | Same file, `test_canonical_*_payload_matches_python_byte_for_byte` -- the REAL, shipped `crypto.js` (not a reimplementation) evaluated in a real JS engine and diffed byte-for-byte against the real Python functions |

All four vendored libraries are real, independently published,
MIT-licensed, standards-compliant implementations by the same author
(Paul Miller) -- see `web/client/vendor/VENDOR.md` for exact versions
and provenance. **Nothing cryptographic was implemented from scratch**
for this phase.

## Running it

```bash
# 1. The existing server, unmodified
python -m server.server

# 2. The new gateway
python -m web.gateway.gateway --host 127.0.0.1 --port 8765

# 3. The web client -- open web/client/index.html directly in a
#    browser, or serve the directory with any static file server
#    (needed only because some browsers restrict `fetch`/module
#    loading from a bare file:// URL; a plain static server is enough,
#    no build step):
python -m http.server 8080 --directory web/client
```

Then, in the browser UI: authenticate (phone number + password),
connect, observe a peer's identity announcement, compare the displayed
fingerprint out-of-band and click "Confirm fingerprint matches",
establish a session key, and send/receive text messages with a
desktop `ClientSession` (or a second browser tab) on the other end.

## What was and was not dynamically executed

Being explicit about this distinction matters more than the headline
result -- see the project's own Step 13 rule ("accuracy is more
important than impressive wording"). Updated in Phase 15B (see
`tests/test_web_browser_e2e.py`), which closed the one gap Phase 15
Stage 1 had left open.

**Dynamically executed and proven, with real code, in this
environment:**
- Every cryptographic primitive the web client uses (ML-KEM-768,
  ML-DSA-65, AES-256-GCM), run via a real JavaScript engine
  (`quickjs`, embedded from Python), cross-checked byte-for-byte
  against the real Python implementations, in both directions,
  including negative/tamper-detection cases
  (`tests/test_web_client_crypto_interop.py`).
- The REAL, shipped `web/client/crypto.js`'s own canonical-payload
  functions (not a reimplementation), executed the same way, byte-for-
  byte identical to the real Python canonical-payload functions.
- The REAL, shipped `web/gateway/gateway.py`, bridging a real
  `websockets` client through to the real, unmodified server and a
  real desktop `ClientSession` (`tests/test_web_gateway_interop.py`).
- **The REAL, shipped `web/client/index.html` +
  `main.js`/`app.js`/`protocol.js`/`crypto.js`, running inside an
  actual browser** (Chromium/Google Chrome, driven via Playwright --
  the system's already-installed Chrome, not a Playwright-managed
  download) end to end: real browser login through the real HTML
  form, real in-browser ML-KEM-768/ML-DSA-65 key generation, a real
  identity announcement reaching a real desktop `ClientSession`, real
  fingerprint verification through the real "Confirm fingerprint
  matches" button, real session-key establishment (real ML-KEM
  encapsulation + real ML-DSA signature, verified and installed by the
  real, unmodified `ClientSession.handle_group_key_distribution()`),
  and a real encrypted text message in each direction -- **"Hello from
  the browser" decrypted correctly by the desktop client, and "Hello
  from desktop" decrypted correctly and displayed by the browser** --
  with zero unexplained browser console/page errors
  (`tests/test_web_browser_e2e.py::
  test_real_browser_end_to_end_desktop_and_browser_messaging`).
- The browser's own security-rejection logic
  (`_handleGroupKeyDistribution()`), reacting to a genuinely forged
  packet inside the real, running browser session and correctly
  displaying the non-blocking security warning without altering peer
  state (`test_real_browser_rejects_tampered_group_key_signature`),
  and a wrong-password login being rejected through the real browser
  UI (`test_real_browser_login_rejected_with_wrong_password`).

**Not dynamically executed:**
- File/image/group/read-receipt flows through the browser (out of
  Stage 1's own scope, unchanged from before).
- A literal third, independent attacker *process* actively splicing
  itself into live Browser↔Gateway↔Server↔Desktop traffic in real
  time (the forged-packet test above drives the browser's own already-
  loaded, real verification method directly, which is real browser
  code execution, not a live network attacker -- see that test's own
  docstring for the distinction, consistent with
  `docs/demo/security_rejection_demo.md`'s identical honesty note for
  the desktop-only demo).

## Known limitations (Stage 1, deliberately out of scope)

- ~~No same-user multi-device identity linking~~ **Partially closed by
  Phase 18** -- enrollment/authorization/key-sync are implemented (see
  that section below); a browser device and a desktop device of the
  same account remain, correctly, two separately-verified device-peer
  identities until a human explicitly authorizes one from the other,
  exactly like ordinary peer verification -- this was never "weakened
  away," only made reachable from the web client.
- ~~No files/images, group messaging, read receipts, or offline-recovery
  packets in this web client~~ **Closed by Phase 18** -- see that
  section below.
- ~~No persistence: reloading the page loses all peer-verification
  state and session keys~~ **Closed by Phase 17** -- see that section
  below.
- ~~The gateway does not implement reconnection/backoff~~ **Closed by
  Phase 17** (client-side, not gateway-side -- see below for why).

## Phase 17 — Web Persistence + Reconnect

Upgrades the Stage-1 web client from "a page reload regenerates a
brand-new cryptographic identity" (which any peer who had already
`VERIFIED` this browser would correctly, but disruptively, see as
`KEY_CHANGED`) to persistent, reconnect-capable operation -- without
adding a new cryptographic protocol, without changing the server, and
without changing the gateway's own trust boundary (still never sees
plaintext or key material -- see this document's own trust-boundary
section above, untouched).

### Persistence model

New file `web/client/storage.js`. Persists, per username, in
**IndexedDB** (same-origin-isolated by the browser), encrypted at rest
with **AES-256-GCM** using a key derived via WebCrypto's native
**PBKDF2-SHA256** (210000 iterations) from the SAME password the user
already types to log in:

- This browser's own ML-KEM-768 keypair (public + **private**) and
  ML-DSA-65 signing keypair (public + **private**) -- what makes the
  identity/fingerprint STABLE across a reload, the actual gap this
  phase closes.
- Peer-trust state (`peers` Map: kemWire, signingKey, `VERIFIED`/
  `UNVERIFIED`/`KEY_CHANGED`, fingerprint) -- a reload no longer forces
  re-verifying every peer.
- Established session keys (`sessionKeys` Map: AES-256-GCM key +
  epoch, per conversation).
- `directConversationIds` (peer username -> conversation_id).

**Deliberately, permanently NOT persisted anywhere**: the login
password itself (used once, in memory, only to derive the wrapping
key); the server access token/JWT (see "Session restoration" below for
why this is a deliberate trade-off, not an oversight).

**Security model -- do not overstate this**: this is explicitly **not
equivalent** to the desktop's `storage/secure_key_store.py`. IndexedDB
isolation stops a *different website's* JavaScript from reading this
store; it does **not** stop malicious JavaScript already running on
*this exact page* (an XSS vulnerability here could call the same
WebCrypto APIs this module calls, and observe the password the same
way any same-origin script already can). The desktop store's threat
model is stronger: compromising a whole native app process is a
materially higher bar than compromising one page's script context.
Deriving the wrapping key from the login password (rather than
inventing a second, separate local passphrase) mirrors the desktop
store's own choice in that one specific respect -- and only that
respect; storage medium, OS-level protection, and the underlying
primitives all differ, and this is never described as "the browser's
secure key store" anywhere in code or docs, only as what it actually
is. See `web/client/storage.js`'s own module docstring for the full
writeup this summarizes.

### Session/authentication restoration

A page reload still requires **re-entering the password** -- exactly
like the desktop client already requires on every launch (there is no
"remember me" token persistence on the desktop either). This was a
deliberate choice, not a shortcut: persisting a live JWT access token
at rest would let anyone who obtains the persisted store (e.g. via the
XSS scenario above, or physical/malware access to the browser profile)
resume a live authenticated session without ever knowing the password
-- a real increase in blast radius for pure convenience, which the
task's own instructions explicitly cautioned against ("do not weaken
security merely to make browser persistence easier").

What DOES survive a reload, and is the part that actually matters
cryptographically: the moment the user re-enters their password and
reconnects, their SAME ML-KEM/ML-DSA identity, SAME peer-trust state,
and SAME session keys are restored (`_restoreState()`), not
regenerated -- so no peer ever needs to re-verify this browser after a
routine reload, and messaging in an already-established conversation
continues immediately.

### Reconnect state machine (client-side only)

The gateway (`web/gateway/gateway.py`) needed **zero changes** for
this: it is a pure one-WebSocket-to-one-TCP-connection bridge with no
session state of its own to resume (a new WebSocket connection is
always a brand-new TCP connection to the real server, exactly like
restarting the desktop client -- see the gateway's own module
docstring, unchanged). "Reconnect" is therefore entirely a
`WebClientSession` (`web/client/app.js`) concern: redo the real login
sequence automatically.

State machine (`_connectionState`): `disconnected` -> `connecting` ->
`connected` -> (unexpected close) -> `reconnecting` -> `connected`, or
`reconnecting` -> `disconnected` after the bounded attempt cap.

- **Detection**: a `"close"` listener on the live WebSocket
  (`_handleSocketClosed()`) -- fires identically for a genuine network
  drop, a gateway restart, a server restart, or this browser's own
  explicit `disconnect()`; `_intentionalDisconnect` is what
  distinguishes "reconnect" from "stay disconnected."
- **Backoff**: exponential, `1000ms * 2^attempt`, capped at `30000ms`,
  capped at `8` attempts total (`_scheduleReconnect()`) -- never an
  infinite tight retry loop; production defaults, overridable via the
  constructor (tests use short delays).
- **Re-authentication**: a reconnect attempt gets a FRESH access token
  (`authenticateCredentials()` again, using the in-memory password --
  never persisted, cleared when the page/tab closes) rather than
  reusing a possibly-expired one.
- **Identity continuity**: since the in-tab reconnect never lost the
  in-memory `kemKeypair`/`signingKeypair`, `_sendPublicKey()` re-
  broadcasts the SAME identity rather than generating a new one --
  the exact same principle Phase 16D's desktop-side device re-
  broadcast fix already established for a second device's first
  broadcast.
- **No duplicate connections**: a single reconnect timer at a time;
  `_attemptReconnect()` no-ops if a socket is already OPEN, and
  re-checks `_intentionalDisconnect` again after its own awaits
  complete (an in-flight reconnect racing an explicit logout must
  still lose).
- **Logout**: `disconnect()` is the one explicit "stop" entry point --
  sets `_intentionalDisconnect` before closing the socket, cancels any
  pending reconnect timer, and is never followed by a reconnect.

### Message/history consistency

Within this phase's actual scope: no duplicate live-message
processing is introduced (no message buffering/replay mechanism
exists to duplicate); no message is misrouted to the wrong conversation
after reconnect (restored crypto state is exact, never partially
applied -- AES-GCM's own tag verification in `storage.js` guarantees a
decrypt is all-or-nothing); no peer identity is silently reset on
reconnect (persisted trust state is loaded, never cleared, except by
an explicit user action).

**Honest, explicit limitation**: this phase does **not** implement
fetching missed message history for messages sent while the browser
was disconnected/reloaded (the web client has never implemented the
`message_history_request` packet type -- still true after Phase 17;
see the `_handleIncoming()` switch's own `default: break` comment,
unchanged). A message genuinely sent while this browser was offline is
genuinely not delivered retroactively. Implementing that is real,
additional scope (a new packet handler, historical-message rendering,
pagination) that belongs to a later, dedicated phase, not folded
silently into "persistence + reconnect."

### Testing

`tests/test_web_persistence_reconnect.py` (real Playwright/Chrome, no
mocking) proves: page reload restores identity/trust/session-key
state and messaging continues without re-verification; a force-closed
WebSocket (indistinguishable, from the browser's own API, from a real
network drop) triggers detection, bounded backoff, and a real
automatic reconnect that resumes messaging without human action or
lost state; an explicit logout is never followed by a reconnect.
`tests/test_web_client_crypto_interop.py` (13/13, unaffected --
`crypto.js`/`protocol.js` were not touched) and
`tests/test_web_browser_e2e.py` (3/3, unaffected -- re-verified after
this phase's `app.js` changes) both continue to pass unmodified.

### Remaining limitations (after Phase 17)

- Same-user multi-device identity linking for the web client is still
  not implemented (a browser session and a desktop session for the
  same person remain separately-verified identities) -- unchanged from
  Stage 1, out of this phase's scope.
- No message-history recovery for messages sent while disconnected
  (see "Message/history consistency" above).
- No files/images, group messaging, or read receipts in the web
  client -- unchanged from Stage 1.
- The browser-side persistence store's threat model is weaker than the
  desktop's `storage/secure_key_store.py` in the specific way
  documented above (same-origin JS, not a second local secret,
  protects it) -- this is stated as a property, not treated as a bug
  to silently work around.
- Reconnect always re-authenticates with a fresh access token; this
  client has no visibility into (and does not attempt to reason about)
  the JWT's actual remaining lifetime.

## Phase 18 — Web UX + Feature Completion

Brings the web client to functional parity with the desktop client for
every feature the existing server/protocol already supports without a
new cryptographic construction: group messaging, file/image transfer,
message-history recovery, read receipts, and (Step 8) multi-device
identity linking. No second, web-only security scheme anywhere below
-- every mechanism reuses the exact wire packets, canonical payloads,
and KEM-then-DEM composition the desktop client already uses, ported
to `crypto.js`/`protocol.js` and proven byte-exact against their
Python originals in `tests/test_web_client_crypto_interop.py`.

### Feature matrix

| Feature | Desktop | Web (after Phase 18) | Mechanism reused |
|---|---|---|---|
| Direct text messaging | Yes | Yes (Phase 15) | `chat` packet, `canonicalMessagePayload` |
| Group messaging | Yes | **Yes** | `group_create`/`group_key_distribution`, same group-key fan-out `_distribute_group_key()` uses |
| File transfer | Yes | **Yes** | Same `chat` packet, `payload_type="file"`, base64-then-AES-GCM encoding `payload/file_adapter.py` already uses |
| Image transfer | Yes | **Yes** | Same as file transfer, `payload_type="image"`, classified by extension like `domain/payload_type.py::classify_attachment()` |
| Message-history recovery | Yes | **Yes** | `message_history_request`/`result`, per-entry signature reverification |
| Read receipts | Yes | **Yes** | `read_receipt`/`read_receipt_notification`, deliberately unsigned (server derives reader from the authenticated connection) |
| Multi-device enrollment/authorization | Yes | **Yes** | `device_enroll_request`, `device_authorize`, `device_list_request` |
| Multi-device key sync | Yes | **Yes** | `device_key_sync`, same KEM-encapsulate-then-AES-wrap as group-key distribution |
| Persistence/reconnect | N/A (always-on) | Yes (Phase 17) | `storage.js`, bounded-backoff reconnect |

### Groups

`app.js::createGroup()`/`_handleGroupCreateResult()`/
`_createAndDistributeGroupKey()`/`sendGroupMessage()` mirror
`ClientSession.create_group_conversation()`/
`handle_group_create_result()`/`_distribute_group_key()` exactly: the
creator's client (desktop OR web, whichever created it) generates one
fresh AES-256-GCM key and fans it out, ML-KEM-wrapped and ML-DSA-signed
per member, via the SAME `group_key_distribution` packet direct
session-key establishment already uses -- a group is, cryptographically,
just that same mechanism addressed to more than one recipient. No
web-only group key derivation exists anywhere.

**Security review (per the task's own checklist)**:
- *Group-key authenticity*: every `group_key_distribution` packet is
  ML-DSA-signature-verified against the sender's already-VERIFIED
  signing key before decapsulation is ever attempted
  (`_handleGroupKeyDistribution()`) -- unverified senders are rejected,
  never silently accepted.
- *Member authorization*: group membership and message relay
  authorization are entirely server-side
  (`ConversationRepository.get_member_user_ids()`,
  `server/client_handler.py::handle_group_chat_delivery()`), unchanged
  by this phase -- the web client never enforces its own, weaker
  membership check.
- *Stale/replayed keys*: epoch is bound into the signed payload
  (`canonicalGroupKeyPayload`); `KeyManager`-equivalent `sessionKeys`
  storage keeps the key/epoch pair together, so an old epoch's key can
  never be silently used for a newer message.
- *Removed-member access*: unchanged from the desktop's own documented
  behavior -- group-key rotation on membership change is a
  pre-existing, out-of-this-phase's-scope server/desktop property; the
  web client participates in whatever rotation the server already
  triggers, it does not invent a separate one.

### File & image transfer

`sendAttachment()`/`_handleChat()` (generalized) mirror
`ClientSession.send_attachment()`/`payload/file_adapter.py` exactly:
raw bytes are base64-encoded to an ASCII string FIRST, and that string
is what `encryptForWire()` (the SAME function text messages already
use) AES-256-GCM-encrypts -- never a second cipher path. `payload_type`
is classified client-side by filename extension
(`classifyAttachment()`, mirroring `domain/payload_type.py::
classify_attachment()`'s own MIME-from-extension approach, never a
client-claimed MIME type) and bound into the signed canonical payload
(`canonicalMessagePayload`'s own `payload_type`/`content_metadata`
fields), so a receiver cannot be tricked into treating a signed FILE as
an IMAGE or vice versa. `MAX_ATTACHMENT_SIZE_BYTES` (25 MiB) mirrors
`config.py`'s own default -- this project's wire framing holds a whole
message in memory with no chunking, on either side, so the cap applies
here for the identical reason.

**Security review**: encryption/integrity is exactly the message
pipeline's own AES-256-GCM (tamper-evident, all-or-nothing decrypt);
authorization is the same signed-sender-identity check every chat
message gets (`_handleChat()`'s `peer` lookup + signature
verification); size validation happens before any encryption work is
done (`sendAttachment()` rejects oversized files client-side; the
server's own existing frame-size limits are the authoritative,
enforced bound regardless); no plaintext ever reaches `IndexedDB` or
`localStorage` -- attachments are rendered from an in-memory
`Blob`/`URL.createObjectURL()`, never persisted by `storage.js` (only
identity/trust/session-key state is).

### Message-history recovery

`loadHistory(conversationId, isGroup)` closes Phase 17's own explicitly
named limitation ("this phase does **not** implement fetching missed
message history"). Reuses `message_history_request`/`result`
unchanged; each recovered entry is independently signature-reverified
(own signing key for `is_own` entries, cached peer key otherwise)
before decryption, exactly like a live message -- a historical entry
gets no weaker trust check than a live one. File/image historical
entries are explicitly skipped (lazy blob-fetch by reference is a
server-side, Option-A design this phase does not implement client-side
fetching for) -- documented, not silently dropped.

**Security review**: authorization is entirely server-side (the
`message_history_request` handler only returns messages for
conversations the authenticated account is actually a member of, the
same membership check group/device relay already uses); replay is not
a concern for read-only history retrieval; duplicate/ordering:
`loadHistory()` renders in the order the server returns (already
chronological), and calling it twice legitimately re-renders (the web
client does not deduplicate DOM rendering across repeated calls -- see
"Remaining limitations" below) but never changes or grows the
underlying recovered set on its own; stale state: a historical entry
whose epoch's key this client no longer holds is skipped, never
guessed at.

### Read receipts

`markRead(conversationId)` is deliberately **unsigned**, mirroring
`create_read_receipt_packet()`'s own documented design: the server
derives the reader from the authenticated connection, never from
anything client-supplied, so there is no signature to construct or
verify here, unlike every other packet this phase adds.

### Step 8 — Web multi-device identity

**Audited, found feasible without protocol redesign, and
implemented** (per this phase's own explicit instruction to implement
if the existing architecture supports it cleanly, or stop and document
a blocker otherwise -- the latter did not apply here).

**Why it was feasible**: `web/gateway/gateway.py` is a fully
packet-type-agnostic relay (confirmed by reading it -- it JSON-decodes
a frame only to reject malformed/non-object input, and never inspects
`packet["type"]` at all), so every `device_*` packet type already
reaches the existing, unmodified server through it with zero gateway
changes. `crypto/device_protocol.py`'s five canonical payloads use the
identical length-prefixed framing convention `crypto/
identity_protocol.py`/`crypto/group_key_protocol.py` already use,
which `crypto.js` had already ported for those two -- porting the
remaining five (`canonicalDeviceEnrollmentPayload`,
`canonicalDeviceAuthorizationPayload`,
`canonicalDeviceRevocationPayload`,
`canonicalDeviceSessionBindingPayload`,
`canonicalDeviceKeySyncPayload`) was mechanical, not a redesign, and is
proven byte-exact against the Python originals in
`tests/test_web_client_crypto_interop.py` (5 new tests). `server/
device_handler.py` required **zero changes**. Note, for scope honesty:
even the desktop client itself exposes this only at the
`ClientSession`/API layer -- no `gui/*.py` file references any of
these methods -- so the web client's own equivalent (`enrollDevice()`,
`listDevices()`, `authorizeDevice()`, `revokeDevice()`,
`bindDeviceSession()`, `syncConversationKeyToDevice()`, plus the
`device_key_sync` receive handler) is likewise exposed at the
`WebClientSession` layer, reachable via `window.__session` (the same
test-and-programmatic access pattern every other production method in
this file already uses), rather than a dedicated GUI panel neither
client actually has.

**What was implemented** (`web/client/{crypto,protocol,app}.js`):
- `enrollDevice(name, platform)` -- self-signed enrollment; resolves
  to the account's bootstrap-AUTHORIZED first device, or PENDING for a
  second+ device, mirroring `ClientSession.enroll_device()` exactly.
  `this.deviceId` persists across a reload the same way the KEM/ML-DSA
  keypair themselves already do (`storage.js`).
- `listDevices()` / `observeDevicePeerIdentity()` /
  `confirmDevicePeerVerified()` -- device-peer trust reuses the SAME
  `this.peers` VERIFIED/UNVERIFIED/KEY_CHANGED store ordinary peer
  trust uses, keyed by `device_id` instead of username -- never a
  second trust store, exactly like `ClientSession.
  observe_device_peer_identity()` reusing `observe_peer_identity()`
  unchanged. Never automatic: a human (or, in the test proving this,
  an independently-computed fingerprint comparison standing in for
  one) must explicitly confirm before authorization proceeds.
- `authorizeDevice()` / `revokeDevice()` -- an already-AUTHORIZED
  device vouching for (or revoking) another, ML-DSA-signed.
- `bindDeviceSession()` -- proves live possession of the device's
  private key over the CURRENT connection (Phase 16B's own device
  authentication binding); required before `device_key_sync` will be
  sent or accepted for that connection, on both the sending and
  receiving device (`server/device_handler.py::
  is_device_bound_and_authorized()`, unmodified).
- `syncConversationKeyToDevice()` / `_handleDeviceKeySync()` -- wraps
  and delivers an already-established conversation/group key to
  another of the account's own AUTHORIZED, bound devices, using the
  identical KEM-encapsulate-then-AES-wrap `establishSessionKey()`/
  `_createAndDistributeGroupKey()` already use; the receiving side
  enforces the mandatory order Phase 16C established (source
  device-peer VERIFIED -> resolve trusted signing key from LOCAL state
  only -> verify signature -> only then decapsulate/install).

**Proof** (`tests/test_web_feature_completion_e2e.py::
test_web_multi_device_enrollment_authorization_and_key_sync`, real
browser + real desktop + real server, no mocking): Carol's desktop
enrolls (bootstrap-AUTHORIZED) and binds; Carol's browser -- the SAME
account's second device -- enrolls PENDING; the desktop discovers,
verifies, and authorizes it; the browser binds; Carol's desktop
establishes an ordinary direct conversation with Dave (a third
account) and receives a message BEFORE the browser device existed; the
desktop then syncs that conversation's real key to the browser, and
the **exact same key bytes** are verified installed
(`browser_key_hex == desktop_key_hex`); the browser then recovers a
second, post-sync message via `loadHistory()`, decrypted using ONLY
the synced key -- proving the sync is actually useful, not merely
installed.

**Discovered, pre-existing, out-of-scope limitation**: while building
this test, `server/client_handler.py`'s live `"chat"` relay for a
DIRECT message was found to deliver to only the **first** of an
account's currently-connected sockets it matches in `state.clients`
(an unconditional `break` after the first match) -- so a *live*
message sent while both of an account's devices are simultaneously
connected reaches only one of them today. This applies equally to two
DESKTOP clients of the same account and predates this phase entirely;
it is not something Step 8 introduced, and fixing it means changing
the one relay path every direct message in the whole system goes
through -- exactly the kind of shared, load-bearing code change this
phase's own instructions said to document rather than risk. The test
above is deliberately structured around `loadHistory()` (a real,
already-shipped recovery path) rather than live fan-out, which is both
an honest reflection of current behavior and arguably the more
realistic use case for a newly-linked device catching up.

### Testing

`tests/test_web_feature_completion_e2e.py` (5/5, real Playwright/
Chrome, real server, no mocking): group messaging (desktop creates,
web participates, both directions), file transfer (byte-exact
integrity), image transfer (byte-exact, renders), offline-history
recovery (no duplicates, correct order, via the same proven
`page.reload()` mechanic Phase 17's own suite established), and
Step 8's multi-device enrollment/authorization/key-sync scenario above.
`tests/test_web_client_crypto_interop.py` (23/23) and
`tests/test_web_persistence_reconnect.py` + `tests/
test_web_browser_e2e.py` (9/9) were re-run after every `app.js`/
`crypto.js`/`protocol.js` change in this phase and remain fully
passing -- zero regression from Phase 17 or Stage-1 behavior.

### Remaining limitations (after Phase 18)

- No dedicated multi-device UI panel -- Step 8's capability is reached
  via `window.__session` (the same programmatic access every other
  production method in this file already exposes to tests), consistent
  with the desktop client itself, which also has no `gui/*.py` wiring
  for device enrollment/authorization/sync.
- The web client's own ordinary (non-device) peer identity does not
  yet participate in Phase 16D's device-aware composite `(username,
  device_id)` identity key -- `createPublicKeyPacket()` was not
  extended with a `device_id` field this phase. This does not affect
  Step 8's own device-to-device trust (a fully separate mechanism,
  keyed by `device_id` directly), only the unrelated case of a third
  party distinguishing which of a peer's several devices sent an
  ordinary chat message.
- ~~`loadHistory()` does not deduplicate DOM rendering across repeated
  calls~~ **Closed by Phase 18.5, Step 6** -- see that section below.
- ~~File/image historical entries are skipped by `loadHistory()`~~
  **Closed by Phase 18.5, Step 7** -- see that section below.
- ~~The live direct-message relay's single-socket delivery
  limitation~~ **Fixed by Phase 18.5, Step 3** -- see that section
  below.
- ~~No dedicated multi-device UI panel~~ **Closed by Phase 18.5,
  Step 5** -- see that section below.

## Phase 18.5 — Closure Audit

A short, targeted hardening pass over the six limitations Phase 18's
own documentation named, run before Phase 19 (mobile) begins. Not a
rebuild -- Phases 16D/16E/17/18 stand as they were tested (29/29 web
tests passing going in). Every one of the six items below was actually
investigated by reading the real code before any fix was written; two
turned out to be genuine, fixable bugs; one turned out to be a
deliberate, evidence-backed architectural boundary rather than an
oversight; the rest were closed as originally scoped. See tests/
test_same_account_multi_device_routing.py and the five new tests
tests/test_web_feature_completion_e2e.py gained this phase for the
real, passing proof behind every claim below.

### Six-issue audit table

| # | Issue | Severity | Security impact | Functional impact | Mobile impact | Fixed? | Reason |
|---|---|---|---|---|---|---|---|
| 1 | No dedicated device-linking UI | Low | None | Real, only reachable via `window.__session` | None | **Yes** | Backend was already complete; a minimal panel makes it demonstrable by a real user (Step 5) |
| 2 | Ordinary peer identity not device-aware | Medium | None directly, but masks #5's root cause | A 3rd party sees one peer identity per username, not per device | Relevant, deferred | **No** (documented) | Fixing it means every peer's KEM public-key cache (`KeyManager.public_keys`) becoming multi-device-aware -- a cross-cutting change to session-key establishment used by every conversation in the system; genuinely a "substantial redesign," not a narrow fix (Step 4) |
| 3 | Direct-chat relay delivers to only the first matching socket | **High** | None (no unauthorized access), but silently dropped messages for a legitimately-connected, legitimately-keyed second device | Real -- a synced key (Step 8) was previously useless for LIVE messages | **High** -- directly blocks "same account, multiple devices, all get live messages" | **Yes** | Safe, narrow, precedented: made to match `handle_group_chat_delivery()`'s own already-shipped per-socket fan-out exactly (Step 3) |
| 4 | Same-account multi-device routing (the broader question) | Medium | See #2 -- a second device's own public-key broadcast correctly triggers `KEY_CHANGED` for a third party who already verified the first device | A real user must re-verify after linking a second device before a third party's NEXT send succeeds | Relevant, deferred | **Partially** (routing fixed, identity recognition deferred) | The routing half was safe to fix now; reconciling "several devices, one identity" from a third party's view is the harder, separate problem #2 already names |
| 5 | `loadHistory()` does not deduplicate | Medium | None | Real -- became more visible once #3 was fixed (a live-delivered message and a later history load could show it twice) | Relevant | **Yes** | Server now attaches `message_id` to every relayed "chat" packet (live, direct AND group) -- additive metadata, not part of any signed payload; the web client tracks rendered ids in memory (Step 6) |
| 6 | File/image history entries skipped | Low-Medium | None | Real gap -- a real attachment was invisible after reconnect | Relevant | **Yes** | The server-side `blob_download_request`/`result` mechanism (Option A -- lazy blob delivery) already existed and is already used by the desktop client; the web client just never called it (Step 7) |
| 7 | Read receipts deliberately unsigned | Low | Real, but narrow: a malicious/compromised SERVER could fabricate a `read_receipt_notification` with no cryptographic binding to a genuine read action | None (UI-only "seen" indicator) | None | **No** (documented, deliberate) | Consistent with an existing, codebase-wide boundary -- see Step 8 below |

(Numbering above follows this section's own Step numbers 3-8, plus
Step 5; #4 is Step 3's own broader framing, not a separate fix.)

### Step 3 — Same-Account Multi-Device Routing

**The bug, traced end to end.** `server/client_handler.py`'s live
`"chat"` handler, for a DIRECT message (`receiver` set, no
`conversation_id`), iterated `state.clients.items()` looking for a
socket whose `username` matched the receiver, relayed to the FIRST
match, and `break`. Two currently-connected sockets for the same
account (desktop + browser, or desktop + desktop) meant only whichever
one happened to be earlier in Python's dict iteration order ever
received a live direct message -- the other was silently skipped, with
no error, no log visible to the user, nothing. `handle_group_chat_
delivery()` (the GROUP message path) never had this bug -- read
side-by-side before writing the fix, it already fans out to every
connected socket whose `user_id` is a conversation member, with no
`break` at all.

**Why "just remove the break" would have been wrong.** The relay loop
was structurally a `for...else`: the `else` clause (offline
persistence, `message_queued`/`delivery_failure` bookkeeping) ran only
when the loop completed WITHOUT `break`. Deleting `break` alone would
have made that `else` branch run unconditionally after every send --
persisting the message a SECOND time (a duplicate row) and sending the
sender a contradictory second response, every single time. The relay
was restructured instead: the receiver is resolved once up front
(regardless of connection state), the message is persisted exactly
once, then relayed to every currently-matching socket in a loop with
no `break`, `message_id` attached once before the loop -- mirroring
`handle_group_chat_delivery()`'s own already-correct shape, not
inventing a new one. `_mark_recipients_delivered()` still only ever
promotes ONE `MessageRecipient` row per account (never per device) --
read receipts and delivery status stay account-level, exactly as
before.

**Whether decryptability follows the routing fix.** It does not,
automatically -- a device that had no key for a conversation before
this fix still has none after it; the fix only ensures a packet
actually REACHES every connected device of the recipient account, not
that every device can decrypt it. What makes a SECOND device able to
decrypt is entirely the EXISTING `device_key_sync` mechanism (Phase
16C/18 Step 8) -- this fix is what makes that mechanism's result
actually USEFUL for live messages, not merely for `loadHistory()`
catch-up, which is exactly what it was limited to before.

**What remains genuinely unsolved (Issue #2/#4).** A third party (e.g.
Alice) messaging an account with two devices still sees ONE peer-trust
slot for that account's username (`KeyManager.public_keys` and
`storage/secure_key_store.py`'s trust state are both keyed by
username). The SECOND device's own public-key broadcast is correctly,
safely flagged `KEY_CHANGED` against whatever the first device's
identity Alice already verified (crypto/identity_protocol.py's
fail-closed behavior, unmodified) -- and, a genuine finding from
writing this phase's own test (`tests/test_same_account_multi_device_
routing.py`), `establish_session_key()`'s Server-Untrusted Identity
Verification Stage-3 check re-verifies "is this peer currently
VERIFIED" on EVERY send, not only the one that first creates a
conversation's key -- so Alice's very next message to that account
after the second device connects is correctly BLOCKED
(`PeerNotVerifiedError`) until she re-verifies the (now-changed)
fingerprint. This is intentional, fail-closed, already-existing
identity-layer behavior, not a routing bug -- and reconciling "a third
party recognizing several of one account's devices as one identity" is
a genuinely separate, harder problem this phase does not attempt to
solve (it would mean `KeyManager.public_keys` and the ordinary
peer-trust store becoming multi-device-aware, touching the session-key
establishment path every conversation in the system uses). `tests/
test_same_account_multi_device_routing.py` proves the routing fix on
its own terms by having the sender re-verify -- exactly what a real
user does when prompted -- rather than trying to silently route around
this separate limitation.

**A second, unrelated bug found and fixed while auditing this area.**
`server/server_state.py::set_public_key()` (the Phase 16D "device-aware
peer identity" `device_id` field, relayed from an ordinary, UNVERIFIED
`key_exchange`/`public_key` packet) and `server/device_handler.py::
handle_device_session_bind()` (a CRYPTOGRAPHICALLY VERIFIED device
binding, proven by an ML-DSA signature) were both writing to the exact
SAME `ServerState.clients[socket]["device_id"]` dict key. Since a
`key_exchange`/`public_key` packet can be sent by any authenticated
connection at any time (the Phase 16D main-loop re-broadcast path),
and its `device_id` field is never signed or verified (confirmed by
reading `crypto/identity_protocol.py::canonical_identity_payload()` --
`device_id` is not among its signed fields), ANY connection could have
silently overwritten its own already-verified device binding just by
sending one more, otherwise perfectly ordinary, validly-signed
public-key re-announcement with a different `device_id` claim --
undermining what `is_device_bound_and_authorized()`/
`_find_socket_for_bound_device()`/`handle_device_key_sync()`'s source-
device resolution all assumed was a proven binding. Fixed by giving the
unverified value its own key, `announced_device_id` -- nothing
security-relevant reads it; `server/broadcaster.py`'s two callers
updated to read the new name. Proven by `tests/
test_device_key_sync_hardening.py::test_unverified_public_key_
reannouncement_cannot_spoof_bound_device_id`, which sends exactly that
spoofed-but-validly-signed packet and confirms the verified binding
(and a subsequent real `device_key_sync`) is completely unaffected.

### Step 4 — Device Identity Audit

Audited without redesigning anything: `username` uniquely identifies
an account; `device_id` uniquely identifies one device (a UUID,
account-scoped); device-peer trust records (`observe_device_peer_
identity()`/`this.peers` keyed by `device_id`) are genuinely
device-level, not account-level -- confirmed by reading `client/
session.py::observe_device_peer_identity()` and its web mirror,
neither of which ever conflates two devices of the same account into
one trust slot. Fingerprints are device-specific (`fingerprint_
combined_identity()` over that device's own KEM+ML-DSA public keys).

**Revoked devices and stale local trust.** A device's `REVOKED` state
is authoritative server-side and re-checked LIVE on every relevant
packet (`is_device_bound_and_authorized()`'s own docstring: "re-checks
the CURRENT database state on every call rather than trusting a cached
flag from bind time"). A peer's LOCAL cache of that device's trust
state (e.g. `VERIFIED`, set before revocation) does NOT automatically
flip when the device is later revoked -- there is no push notification
for it. Audited and found to be **low severity, not a security
bypass**: `handle_device_key_sync()`'s own server-side checks
(`target_device.state != DEVICE_STATE_AUTHORIZED`, `source_device_state
is not True`) independently re-verify AUTHORIZED status from the
database on every packet, regardless of what either endpoint's local
cache believes -- a revoked device cannot successfully send OR receive
`device_key_sync` material even if the other side's local state is
stale. The only consequence of the staleness is a wasted attempt (a
server-side rejection) -- never a security bypass. Documented here as a
deliberately deferred UX polish item (a future push notification on
revocation), not a fix -- see "Remaining limitations" below.

The identity model as it stands is safe for Phase 19: `username`
(account) / `device_id` (device) / device-scoped fingerprints compose
cleanly for a third platform (mobile) the same way they already do for
desktop and web -- no redesign needed for mobile to participate in
enrollment/authorization/key-sync exactly as the web client now does.

### Step 5 — Device-Linking UI

The backend (Phase 18 Step 8) was already complete, so a minimal,
functional panel was added -- `index.html`'s new "5. Device identity"
fieldset, wired in `main.js` with no new session logic (every button
calls an existing `WebClientSession` method unchanged from Step 8):
current device identity display, enroll, bind, list devices (with
state/fingerprint), observe + show a target device's fingerprint,
authorize (after confirming the fingerprint), and revoke. Proven by a
real, click-driven E2E test (`tests/test_web_feature_completion_e2e.py
::test_device_linking_ui_enroll_bind_authorize_revoke`) that enrolls a
third device via the API, then uses ONLY real button clicks on the
browser's own panel to list it, observe its fingerprint, authorize it,
and revoke it -- with the AUTHORIZED/REVOKED state changes confirmed
server-side via the API afterward, not merely a UI log line. Kept
intentionally plain, consistent with the rest of this UI and with the
desktop client itself, which still has no GUI wiring for this feature
at all (confirmed by inspection -- no `gui/*.py` file references any of
these methods, before or after this phase).

### Step 6 — History Deduplication

`server/client_handler.py` now attaches `message_id` (the same stable
id `message_history_result` already reports for a stored row) to every
relayed live `"chat"` packet -- both the direct-message and
group-message relay paths, added right after `persist_message()`/
`persist_group_message()` returns. Purely additive metadata: `message_
id` was never part of `canonical_message_payload()`'s signed fields on
either side, so this changes nothing about what was already signed or
how it verifies. `WebClientSession._renderedMessageIds` (a `Set`, in-
memory only -- never persisted, since a genuine page reload clears the
DOM and legitimately starts over) is populated by both `_handleChat()`
(live) and `loadHistory()` (recovered) -- whichever path renders a
given `message_id` first wins; the other silently skips it. Proven by
`test_web_multi_device_enrollment_authorization_and_key_sync`'s own
extended scenario: a message sent after a device-key sync now arrives
LIVE (thanks to Step 3's routing fix) and a subsequent `loadHistory()`
call correctly does NOT re-render it a second time -- and by `test_
offline_file_history_recovery_byte_exact`'s own repeated-`loadHistory()`
check for a blob-stored (file) entry.

### Step 7 — File/Image History

The server-side mechanism already existed and was already in
production use by the desktop client (`blob_download_request`/
`blob_download_result`, `server/client_handler.py::handle_blob_
download_request()`, Option A -- lazy blob delivery: `message_history_
result` reports a FILE/IMAGE entry's `blob_ref` metadata only, never
its content). The web client simply never called it. Fixed by adding
`createBlobDownloadRequestPacket()` (`protocol.js`) and extending
`loadHistory()` to, for a `payload_type` of `file`/`image` with a
`blob_ref`, fetch the real ciphertext via that request BEFORE
signature verification (mirroring `ClientSession._load_blob_history_
content()`'s own ordering exactly -- the entry's inline `ciphertext`
field is `None` for a blob-stored type, so there is nothing to verify
until the fetch completes), then decrypt and render exactly like a
live attachment. A blob that cannot be fetched or decrypted is skipped
entirely -- never rendered as a misleading placeholder claiming
content exists when it cannot actually be recovered. Proven byte-exact
by `test_offline_file_history_recovery_byte_exact`: a file sent while
the browser was genuinely offline is recovered, after reconnect, with
every one of its 1024 bytes intact.

### Step 8 — Read Receipt Security

Audited against this project's own, actual, already-established
threat model -- not treated as an isolated question. `create_read_
receipt_packet()`'s existing docstring already explains its one
design goal: prevent a malicious CLIENT from forging a receipt for a
DIFFERENT user (achieved -- the packet carries no reader field at all;
the server derives it exclusively from the authenticated connection).
What that docstring does not address, and what this audit specifically
checked, is whether a malicious or compromised SERVER could fabricate
a `read_receipt_notification` out of thin air, with no cryptographic
binding to a genuine read action by the claimed reader. It can --
confirmed by reading `handle_read_receipt()`: the notification is
server-authored, unsigned, and nothing about it proves the claimed
reader's device ever produced it.

**Decision: intentionally left transport-authenticated (TLS), not
E2E-signed -- and this is a codebase-wide, consistent boundary, not an
oversight specific to receipts.** Verified by reading `utils/
protocol.py`'s other server-authored notification packets:
`create_user_list_packet()` (online presence), `create_message_
queued_packet()` and `create_delivery_failure_packet()` (delivery
status) -- NONE of them carry a signature field either, and none of
their docstrings claim E2E authentication. This project draws a
consistent line: message CONTENT and IDENTITY claims are always
ML-DSA-signed and verified peer-to-peer (chat messages, group keys,
device enrollment/authorization/key-sync, identity announcements) --
the server is never trusted for those. DELIVERY/PRESENCE/READ STATUS
metadata has never been claimed to be E2E-authenticated anywhere in
this codebase; it is server-authoritative, protected only by TLS
against a network attacker, consistently, across every status packet
type. Signing read receipts alone, while leaving `user_list`/`message_
queued`/`delivery_failure` unsigned, would be an inconsistent, partial
fix that does not actually close "can a malicious server lie about
account activity" (it already can, via those other packets) --
while a fully consistent fix (signing every status/presence packet)
is a genuinely large, cross-cutting protocol change, well beyond a
short closure pass, and not what this specific, narrow finding
justifies on its own. The actual blast radius of a forged read receipt
is a false "seen" UI indicator only -- it cannot affect message
confidentiality, integrity, or identity authentication, all of which
remain fully E2E-protected regardless. This is now an explicit,
evidence-backed, documented decision rather than an unexamined default.

### Remaining limitations (after Phase 18.5)

- Issue #2/#4 (ordinary peer identity is account-level, not
  device-level, from a third party's perspective) remains open --
  genuinely out of scope for a closure pass; a real architectural
  project for a future phase (see Step 3's own writeup above for
  exactly what it would require: `KeyManager.public_keys` and the
  ordinary peer-trust store becoming multi-device-aware).
- Revoked-device local trust-cache staleness (Step 4) is not pushed to
  peers automatically -- server-side enforcement already prevents any
  actual security consequence; a future phase could add a push
  notification so a peer's local `VERIFIED` label updates promptly
  too, purely as UX polish.
- Read receipts remain transport-authenticated only, by the explicit,
  now-documented design decision in Step 8 above -- consistent with
  every other status/presence packet in this codebase, not a gap
  unique to receipts.
- The device-linking UI (Step 5) is intentionally plain and has no
  polling/auto-refresh for the device list (a user must click "List
  devices" again to see a state change) -- consistent with this
  client's existing "deliberately plain" design philosophy throughout.
