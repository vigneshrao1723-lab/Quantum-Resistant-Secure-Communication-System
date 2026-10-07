# Quantum-Resistant Secure Communication System

A multi user, server-mediated secure communication system developed as a Final Year Project in Python. The system combines classical cryptography with Post-Quantum Cryptography (PQC) for client-side session key exchange, and uses a PostgreSQL-backed server as the authority for authentication, conversation state, message persistence, and file/image blob storage.

---

## Overview

The system is a client-server chat application. Multiple clients connect to a central server over a TLS-secured TCP socket, authenticate with a username/password (JWT-based session), and exchange direct and group messages, files, and images. The server persists all conversation, message, and membership state in a PostgreSQL database and stores file/image ciphertext on disk as encrypted blobs.

Message *content* is encrypted client-side at the payload level using AES-256-GCM, with per-conversation session keys established via client-side Kyber (ML-KEM-768) or RSA key exchange — the server never holds the AES session keys and cannot decrypt message bodies or blob contents. Key-establishment packets, identity announcements, and messages are additionally origin-authenticated client-side with ML-DSA-65 signatures, verified against a locally-held, explicitly human-verified peer identity — the server relays this traffic but cannot forge it, substitute a signing key, or install a key at a receiver (see [Security Model](#security-model)). The server is fully trusted with connection metadata (who is talking to whom, when, message sizes, filenames, and group membership) and mediates key *distribution*, but is not trusted as a cryptographic authority for key *establishment*. See [Security Model](#security-model) below for the exact boundary of what the server can and cannot see and do.

Development has proceeded through a sequence of server-migration and hardening slices (documented under [Current Implementation Status](#current-implementation-status)) that moved conversation resolution, key epoch management, conversation-list loading, message history, and blob retrieval from local client-side storage to authenticated server-side request/response operations, followed by security-hardening and reliability work through slice D8 and subsequent origin-authentication hardening. See that section, and [Testing](#testing), for current status.

---

## Key Features

The following are implemented and covered by the automated test suite (`tests/`):

- **Multi-user client-server communication** over TCP sockets, with a dedicated server process handling many concurrent client connections.
- **TLS-secured transport**: all client-server traffic runs over TLS 1.2+ (`security/tls.py`), enforced on both the server and client socket contexts.
- **Authentication**: username/password registration and login, with Argon2 password hashing (`security/password_handler.py`) and JWT (HS256) access/refresh tokens (`security/jwt_handler.py`, `config_server.py`) issued and validated per connection.
- **Direct messaging** between two users, with server-side resolution/creation of the direct conversation.
- **Group communication**: group creation, adding members, and group messaging.
- **Conversation management**: conversation list loading and direct-conversation resolution are performed by the server on behalf of the authenticated client (not derived from local client state).
- **Message persistence and history**: messages are persisted server-side (`database/repositories/message_repository.py`) and historical message pages are fetched from the server via an explicit request/response exchange rather than a local cache.
- **Read receipts**: delivery/read status tracking per message recipient (`database/models/message_recipient.py`).
- **File and image transfer**: binary payloads are encrypted client-side (AES-256-GCM, `crypto/payload_cipher.py`) and the resulting ciphertext blob is uploaded to the server, which stores it on disk (`storage/encrypted_blob_store.py`) and serves it back on request.
- **Reconnection and history recovery**: a client that reconnects (including after a restart) can re-request conversation lists, key epoch state, and message history from the server rather than relying on anything cached locally.
- **Session and key management**: each client session generates or loads a Kyber (ML-KEM-768) identity keypair and a persistent ML-DSA-65 signing keypair (`crypto/key_manager.py`). RSA identity keypairs (comparison mode only) remain fresh per session, unchanged. Kyber and ML-DSA private keys, and per-conversation AES session keys, are persisted to disk **encrypted at rest** under the user's own account password (`storage/secure_key_store.py`) — see [Local Key Storage](#local-key-storage) below for exactly what is stored and how it is protected.
- **Key epoch handling**: AES session keys for a conversation are scoped by `(conversation_id, epoch)`, with epoch reservation now performed via a server request rather than client-local bookkeeping.
- **Post-quantum key exchange (Kyber / ML-KEM-768)**: `crypto/kyber.py` implements Kyber768 (via the `kyber-py` library, the FIPS 203 ML-KEM-768 parameter set) as the **default and active** key-exchange algorithm (`config.py: KEY_EXCHANGE_ALGORITHM = "KYBER"`), used to establish the AES session key between clients. Classical RSA-2048 (OAEP/SHA-256, `crypto/rsa.py`) is also implemented and selectable, primarily for comparison purposes. Both key-establishment paths (Kyber-based group/direct-key distribution and RSA session-key establishment) are origin-authenticated with ML-DSA-65 signatures before a received key is ever installed — see [Security Model](#security-model).
- **ML-DSA-65 origin authentication** (`crypto/ml_dsa.py`, `crypto/identity_protocol.py`, `crypto/message_protocol.py`, `crypto/group_key_protocol.py`, `crypto/session_key_protocol.py`): a persistent, per-user ML-DSA-65 signing identity authenticates public-identity announcements, chat messages, Kyber group/direct-key distribution, and RSA session-key delivery — each with its own domain-separated signed envelope, so a signature valid for one purpose can never be replayed as another. Signature verification always resolves the trusted signing key from this receiver's own, locally held peer-identity state — never from a field inside the packet being verified — and always completes before any corresponding key or message content is installed, decrypted, or displayed.
- **Explicit peer identity verification**: a peer's identity is first *observed* automatically (not trusted) the moment their signed public-key announcement arrives; it becomes *verified* only through an explicit, human, out-of-band fingerprint confirmation (`ClientSession.confirm_peer_verification()`). A later identity that disagrees with an already-verified one is flagged `KEY_CHANGED` and never silently substituted for the trusted one. This is not trust-on-first-use: unverified-but-observed identities are not treated as trusted for key-establishment purposes.
- **Server-side request/response architecture**: client-originated operations that need server authority (conversation resolution, key epoch reservation, conversation list loading, message history, blob download) go through a correlated request/response protocol (`utils/request_registry.py`, `ClientSession.send_request()`) rather than ad hoc client-local logic.
- **Phone-number-based user discovery**: an authenticated user can look up another registered user by phone number to start a direct conversation (`security/phone_number.py`, server-side lookup handler in `server/client_handler.py`, `gui/find_user_dialog.py`).

---

## Architecture

```
 ┌────────────┐          TLS 1.2+ (TCP)          ┌────────────┐
 │   Client    │ ───────────────────────────────▶ │   Server    │
 │ (PySide6 GUI│ ◀─────────────────────────────── │ (multi-     │
 │  + session) │      JSON-framed request/         │  threaded)  │
 └────────────┘        response packets            └─────┬──────┘
                                                           │
                                          ┌────────────────┼────────────────┐
                                          ▼                                 ▼
                                ┌──────────────────┐              ┌──────────────────┐
                                │   PostgreSQL       │              │  Encrypted blob    │
                                │   (SQLAlchemy ORM,  │              │  store (local       │
                                │   Alembic migrations)│              │  filesystem)        │
                                └──────────────────┘              └──────────────────┘
```

- **Client** (`client/`, `gui/`): PySide6 desktop application. Handles UI, local AES/Kyber/RSA cryptographic operations (`crypto/`), and communicates with the server exclusively over the TLS socket via `ClientSession` (`client/session.py`). Holds no independent database connection — all persistence goes through the server.
- **Server** (`server/`): accepts TLS connections, authenticates clients (JWT), dispatches request packets to handlers (`server/client_handler.py`), broadcasts presence/user-list updates (`server/broadcaster.py`), and is the sole process with a PostgreSQL connection and blob-store filesystem access.
- **Database** (`database/`): PostgreSQL accessed through SQLAlchemy models (`database/models/`) and repository classes (`database/repositories/`), with schema migrations managed by Alembic (`alembic/`).
- **Storage** (`storage/encrypted_blob_store.py`): server-local filesystem store for file/image ciphertext blobs, rooted at `FILE_STORAGE_ROOT` (`config_server.py`).
- **Cryptographic layer** (`crypto/`): AES-256-GCM (payload/session encryption), RSA-2048-OAEP and Kyber768/ML-KEM-768 (session key exchange), and ML-DSA-65 (origin authentication of identity announcements, messages, and both key-establishment paths) — all executed client-side only.
- **Protocol / request-response layer** (`utils/protocol.py`, `utils/request_registry.py`): defines the JSON packet schema and correlates outgoing client requests with server responses by `request_id`.

For the full layered breakdown (GUI → session → security/protocol → TLS → server relay → database/storage) and component responsibility table, see [System Architecture](docs/architecture/system_architecture.md).

---

## Security Model

Detailed documentation: [Security Architecture](docs/architecture/security/security_architecture.md) (property-by-layer map, domain-separated signing purposes, trust state machine) · [Threat Model](docs/architecture/security/threat_model.md) (attacker capabilities, honest scope limitation) · [Key Establishment Flow](docs/architecture/security/key_establishment_flow.md) (exact packet fields and verification order) · [Attack → Rejection → Recovery](docs/architecture/security/attack_rejection_recovery.md) (the full sequence, FYP-viva-ready).

### Threat model: the server is an untrusted relay for cryptographic origin authentication

The server is trusted with connection metadata and is the sole process with database/filesystem access, but it is **not** trusted as a cryptographic authority. Concretely, the server:

**May:**
- Authenticate the transport (TLS) and each connection (JWT).
- Route and relay packets, including cryptographic ones (identity announcements, message ciphertext, key-establishment packets).
- Enforce group-membership/routing rules (e.g. rejecting a key-distribution relay to a non-member).
- Observe the metadata listed below.

**Must not be able to (and, per the current implementation, cannot):**
- Forge a client's ML-DSA signing identity or produce a valid signature on its behalf — it never holds any client's private key material.
- Substitute its own signing/encryption key in place of a real peer's and have it accepted — the receiver only ever resolves a verification key from its own, locally held peer-identity state, never from anything inside a packet.
- Cause a receiver to install an attacker-chosen session or group key — every key-establishment path (Kyber group/direct-key distribution, RSA session-key delivery) requires a valid ML-DSA signature, verified against the receiver's locally trusted key, *before* the corresponding key is ever decapsulated/decrypted or installed. A forged or unsigned key-establishment packet is rejected before any of that happens.
- Decrypt message bodies or blob contents — it never holds an AES session key.

This is enforced client-side, independent of server behavior: a malicious or compromised server can drop, delay, reorder, or relay-with-tampering any packet, but cannot make a receiver accept forged cryptographic material as authentic. An earlier wire-protocol packet shape for RSA/Kyber session-key delivery predated this authentication layer; the Kyber variant of that legacy shape is no longer used for key establishment at all — a client encountering it now rejects it outright, before any decryption is attempted, rather than accepting it as a valid (but unauthenticated) key delivery.

**What the server cannot see:**
- Plaintext message bodies — messages are AES-256-GCM encrypted client-side before transmission, using a session key the server never possesses.
- Plaintext file/image contents — blob payloads are encrypted client-side (`crypto/payload_cipher.py`) before upload; the server stores and serves ciphertext only. This is confirmed by inspection: no AES/Kyber/RSA/ML-DSA cipher or key-manager code exists anywhere in `server/`.

**What the server can see (and is trusted with, as metadata — not as a cryptographic authority):**
- Connection-level metadata: which authenticated user is connected, and when.
- Message metadata: sender, recipient(s)/group, conversation ID, timestamps, payload type (text/file/image), and for file/image messages, content metadata such as filename and size.
- Group and conversation membership.
- Presence (online/offline / user list broadcasts).
- The distribution of public keys and key-establishment packets: `server/broadcaster.py`'s `distribute_public_keys()` relays each client's self-submitted public key material, and the server relays key-establishment packets between clients. The server can observe these fields but — per the threat model above — cannot forge, substitute, or tamper with them in a way a receiver will accept: identity announcements are ML-DSA-signed (rejecting a mismatched or unsigned one), and key-establishment packets are ML-DSA-signed and verified against the receiver's own trusted state before installation.

### Peer identity verification

Trusting a peer's identity is an explicit, local, per-user decision — never automatic, and never made by the server:

1. **First contact**: the moment a peer's signed public-key announcement is received, that identity is *observed* and recorded as `UNVERIFIED`. It is not yet trusted for key establishment.
2. **Verification**: a human explicitly compares the displayed fingerprint against the peer's out-of-band, and confirms it (`ClientSession.confirm_peer_verification()`/`confirm_combined_peer_verification()`) — the only code paths that can ever set a peer's state to `VERIFIED`. No signature, message, or key packet can promote a peer to `VERIFIED` by itself.
3. **Key establishment** (Kyber group/direct-key distribution and RSA session-key delivery) requires the sender to be `VERIFIED`, symmetrically, on both the sending and receiving side.
4. **Key change**: if a peer's observed identity later disagrees with an already-`VERIFIED` one, it is flagged `KEY_CHANGED` — the previously verified identity is *not* silently overwritten or replaced, and no key is accepted from the new, unconfirmed identity until a human re-verifies it.

This model is **not** trust-on-first-use: an unverified peer's key material is not treated as trusted for establishing new session/group keys, even though it has been observed. (Ordinary message-level authentication is deliberately less strict — a signed message from an already-key-established but not-yet-`VERIFIED` sender is still accepted, since it proves possession of the signing key, not human trust; see `crypto/message_protocol.py`.)

**Other known limitations (not yet addressed):**
- No traffic/metadata privacy — the server necessarily observes who is communicating with whom, and how often.
- No message/blob deletion lifecycle — `encrypted_blob_store.delete_blob()` exists but has no production call site; stored blobs are not currently purged.
- `JWT_SECRET_KEY` defaults to a development placeholder in `config_server.py` and must be overridden via environment variable for any non-development deployment.
- Non-repudiation is not claimed as a product guarantee merely because ML-DSA signatures exist — no key-revocation, certificate-transparency-style, or dispute-resolution mechanism is implemented around them.
- Forward secrecy is not claimed beyond whatever AES-GCM's own per-message properties provide; there is no ratcheting or ephemeral-per-message key mechanism.

Given these properties, this system should be described as providing **client-side, ML-DSA-origin-authenticated payload encryption with post-quantum (Kyber/ML-KEM-768) or classical (RSA, comparison mode) key establishment**, relayed but not cryptographically mediated by the server. Transport security (TLS) is classical, not post-quantum — post-quantum protection in this system is specifically the Kyber/ML-KEM-768 key-establishment layer, not the transport layer.

### Local Key Storage

Identity and conversation keys are persisted **encrypted at rest**, not held only in memory:

- **What is persisted**: this client's own Kyber (ML-KEM-768) keypair, its own persistent ML-DSA-65 signing keypair, per-conversation AES session/group keys (keyed by `(conversation_id, epoch)`), and locally recorded peer-verification fingerprints/state (`storage/secure_key_store.py`). RSA identity keypairs (comparison mode) are intentionally *not* persisted — a fresh RSA keypair is generated every session, unchanged from earlier behavior.
- **Where**: one encrypted file per user, under `KEY_STORE_DIR` (`config.py`) — never transmitted to the server; only the corresponding *public* keys ever go over the wire.
- **Protection at rest**: the storage key is derived from the user's own account password with **Argon2id** (a real password-hashing KDF, not a bare digest), using a random 16-byte salt generated per store. The payload is encrypted with the same **AES-256-GCM** primitive used for messages, with a fresh random 12-byte nonce per write; a wrong password, corrupted file, or tampered file all fail closed (via GCM's own authentication tag) rather than returning partial or attacker-chosen key material. A failed unlock never deletes or overwrites the existing file.
- **If the store is unavailable** (e.g. wrong password, first run before any password is known): the session degrades gracefully to an ephemeral in-memory keypair rather than failing outright — persistence is an additive property, never a hard precondition for messaging to function at all.
- **Stated threat model**: an attacker who obtains *both* the encrypted key-store file and the user's account password can read that user's key material; the server itself never holds it and cannot decrypt it.

---

## Technology Stack

### Language
- Python 3.12 (developed and tested against 3.12.10)

### GUI
- PySide6 (Qt for Python) — `gui/`, `main.py`

### Networking / Transport
- Python `socket` (TCP), multi-threaded server (`server/`)
- TLS 1.2+ via `ssl` (`security/tls.py`)

### Cryptography

**Post-quantum / quantum-resistant:**
- Kyber768 / ML-KEM-768 (post-quantum key encapsulation) — `kyber-py` (`crypto/kyber.py`) — the default key-establishment algorithm.
- ML-DSA-65 (post-quantum digital signature, FIPS 204) — `crypto/ml_dsa.py` — origin-authenticates identity announcements, messages, and both key-establishment paths (Kyber and RSA).

**Classical:**
- AES-256-GCM (authenticated symmetric encryption) — PyCryptodome (`crypto/aes.py`, `crypto/payload_cipher.py`) — protects message/blob content and the local encrypted key store; not itself post-quantum, but not the component this project's "quantum-resistant" claim rests on either.
- RSA-2048 (OAEP, SHA-256) — `cryptography` library (`crypto/rsa.py`) — an alternative, selectable key-establishment algorithm kept for classical-vs-post-quantum comparison; **not** post-quantum.
- Argon2id password hashing / key derivation — `argon2-cffi` (`security/password_handler.py`, `storage/secure_key_store.py`).
- JWT (HS256) — `PyJWT` (`security/jwt_handler.py`) — session authentication only, unrelated to message/key cryptography.
- TLS 1.2+ (`security/tls.py`) — classical transport security; does not itself provide post-quantum protection or application-level message authentication (see [Security Model](#security-model)).

### Database & Persistence
- PostgreSQL
- SQLAlchemy (ORM) — `database/models/`, `database/repositories/`
- Alembic (migrations) — `alembic/`
- `psycopg2-binary` (driver)

### Testing
- `pytest`

### Other
- `python-dotenv` (environment configuration)

---

## Project Structure

```
Quantum-Resistant-Secure-Communication-System/
│
├── client/                  # Client-side session, sender/receiver, conversation store
│   ├── client.py
│   ├── session.py
│   ├── sender.py
│   ├── receiver.py
│   └── conversation_store.py
│
├── server/                  # Server process, request handlers, presence broadcast
│   ├── server.py
│   ├── server_state.py
│   ├── client_handler.py
│   └── broadcaster.py
│
├── crypto/                  # Client-side cryptography
│   ├── aes.py
│   ├── rsa.py
│   ├── kyber.py
│   ├── key_manager.py
│   └── payload_cipher.py
│
├── auth/                    # Registration / login / authentication services
├── database/                 # SQLAlchemy models and repositories
│   ├── connection.py
│   ├── models/
│   └── repositories/
│
├── alembic/                  # Database schema migrations
├── storage/                  # Server-side encrypted blob store
├── security/                  # TLS context, JWT handling, password hashing
├── domain/                   # Payload/message domain types and serialization
├── payload/                   # File/text payload adapters
├── utils/                    # Wire protocol, request/response registry, helpers
├── gui/                      # PySide6 windows/widgets (chat, login, dialogs)
├── scripts/                  # Dev tooling (e.g. certificate generation)
├── certs/                     # Development TLS certificates
├── benchmark/                 # Performance benchmarking scripts
├── docs/                      # Project documentation
├── tests/                     # Automated test suite (pytest)
│
├── config.py                  # Client-side configuration
├── config_server.py            # Server-side configuration (JWT, storage root, etc.)
├── logger_config.py
├── main.py                     # GUI application entry point
├── requirements.txt             # Runtime dependencies
├── requirements-dev.txt          # Test + benchmark dependencies
├── README.md
└── .gitignore
```

`client/client.py`, `client/sender.py`, `utils/console_ui.py`, and `utils/terminal_ui.py` are an earlier, terminal-based client prototype that predates the PySide6 GUI; `main.py` (the current entry point) does not import them. See `tests/terminal_ui_test.py` for their only remaining test coverage.

---

## Current Implementation Status

The project has completed a multi-slice migration moving client-local database/storage responsibilities to authenticated, server-mediated request/response operations, followed by further hardening and reliability slices. As of this document, git history includes committed work through **D8**; see the note below the table for D8's current status.

| Slice | Description |
|-------|-------------|
| D3.1 | Direct conversation resolution moved to the server (server resolves/creates the direct conversation for two users, rather than the client deriving it locally). |
| D3.2 | Server-side request/response infrastructure (`ClientSession.send_request()`, `PendingRequestRegistry`) added to correlate client requests with server responses by `request_id`. |
| D3.3 | Direct conversation resolution fully routed through the D3.2 request/response mechanism. |
| D4.1 | Key epoch reservation moved behind an authenticated server request, replacing client-local epoch bookkeeping. |
| D4.2 | Conversation list loading moved behind the server; the client requests its conversation list from the server on session start rather than reading it from local state. |
| D4.3 | Message history retrieval and file/image blob download moved behind server request/response operations. |
| D6 | Hardened key management and distribution security. |
| D7 | Removed client dependency on server-side packages. |
| D8 | Security hardening (network framing/connection limits, production TLS enforcement, attachment/blob handling, Qt rich-text injection hardening) and UI reliability improvements (delivery/read/failure indicators and retry, image rendering constraints, group/member selection). |

Earlier foundational work (multi-client TCP communication, username-based sessions, AES/RSA/Kyber cryptography, PostgreSQL-backed persistence, TLS transport, JWT authentication) predates and underlies this migration series and remains in place.

**D8 status note**: the D8 commit is on `master` but, as of this document, `master` has not been pushed to `origin`, and there are further uncommitted, in-progress changes on top of it to `client/session.py`, `server/client_handler.py`, and `tests/tls_test_support.py` addressing an intermittent TLS test-harness instability. Treat D8 as committed but not yet fully closed out.

**Origin-authentication hardening (post-D8, in progress on top of the same branch)**: subsequent work added ML-DSA-65 origin authentication across the protocol — public-identity announcements, chat messages, Kyber group/direct-key distribution, and RSA session-key delivery each now require a valid signature, verified against a locally held, explicitly human-verified peer identity, before being trusted or installed. This also closed a confirmed vulnerability in which an unauthenticated legacy Kyber session-key packet shape could have been used by a malicious server to install an attacker-chosen key (`client/session.py::handle_session_key()`; that packet shape is now rejected outright, before any decryption). This work is committed on top of D8 but predates any formal slice numbering in this table — see [Security Model](#security-model) for what it actually provides.

---

## Testing

The suite currently collects **1,541 tests** across 120 files (`pytest --collect-only -q`, reconfirmed during Phase 19.17 — all 1,541 pass). This count changes as work continues — treat it as a snapshot, not a maintained guarantee; run `pytest --collect-only -q` yourself for the exact current figure rather than trusting this number indefinitely.

Tests require a running local PostgreSQL instance and a `DATABASE_URL` pointing at it (see [Installation / Setup](#installation--setup)) — `tests/conftest.py` wraps each test in a transaction that's rolled back on teardown, so no test data persists, but a real database connection is required for the suite to run at all (SQLite is not supported).

Install the test dependencies (see below) and run the suite with:

```bash
pytest -q
```

Performance measurements for the ML-DSA-65 signature primitive (key generation/signing/verification) are documented separately — see [ML-DSA Benchmark](docs/benchmark/ml_dsa_benchmark.md). For a reproducible walkthrough of the malicious-relay/security-rejection defense (and an FYP presentation guide built on it), see [Security Rejection Demonstration](docs/demo/security_rejection_demo.md) and [FYP Presentation Guide](docs/demo/fyp_presentation_guide.md).

---

## Installation / Setup

Clone the repository:

```bash
git clone https://github.com/vigneshrao1723-lab/Quantum-Resistant-Secure-Communication-System.git
cd Quantum-Resistant-Secure-Communication-System
```

Create and activate a virtual environment (Python 3.12):

```bash
python -m venv venv
venv\Scripts\activate        # Windows
```

Install runtime dependencies, and — if you'll be running tests or the benchmark — the development dependencies too:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt   # tests (pytest) + benchmark; skip for a pure runtime install
```

### PostgreSQL

The server requires a running local PostgreSQL instance — SQLite is not supported (`config_server.py` rejects a `sqlite` URL at startup). Install PostgreSQL 17 (or another recent PostgreSQL version), then create an empty database for the project:

```sql
CREATE DATABASE qrscs;
```

### Environment configuration

Copy the template and fill in real local values — **`.env` holds real database credentials and the JWT signing secret and must never be committed** (it's already covered by `.gitignore`):

```bash
cp .env.example .env
```

At minimum, set `DATABASE_URL` to point at the database you just created, e.g.:

```
DATABASE_URL=postgresql+psycopg2://<user>:<password>@localhost:5432/qrscs
```

and set `JWT_SECRET_KEY` to a real random value (see the generation command inside `.env.example`) — the server refuses to start with the built-in development placeholder.

### Database schema

Apply the Alembic migrations to the database you just created:

```bash
alembic upgrade head
```

### TLS certificates

Development TLS certificates are generated locally and are **not committed** (`certs/` is gitignored — see `docs/architecture/tls_transport.md`):

```bash
python scripts/generate_dev_certs.py
```

---

## Running the Application

Start the server (must be run as a module from the repository root, due to its internal package-relative imports):

```bash
python -m server.server
```

Start the client GUI (from the repository root):

```bash
python main.py
```

Multiple client instances can be run concurrently against the same server for multi-user testing.

### Android

Building the Android APK requires WSL2 (Buildozer/python-for-android have no native Windows target). From inside an already-provisioned WSL2 environment (see `docs/architecture/mobile_client.md`'s "Phase 19.7" section for the one-time SDK/NDK/JDK setup):

```bash
scripts/build_android_apk.sh debug
```

This swaps in the Android entrypoint (`mobile/android_main.py`), runs Buildozer, restores the desktop `main.py` afterward regardless of outcome, and prints the resulting `.apk`'s path and SHA-256. See `docs/architecture/mobile_client.md` for the full build history and physical-device validation record.

---

## Database

- **Engine**: PostgreSQL, accessed via SQLAlchemy (`database/connection.py`) with Alembic-managed schema migrations (`alembic/`).
- **Persisted data** (see `database/models/`): users and credentials (`user.py`), sessions (`session.py`), conversations (`conversation.py`) and their membership (`conversation_member.py`), messages (`message.py`), and per-recipient delivery/read status (`message_recipient.py`).
- Message and file/image *content* is stored encrypted: message bodies as persisted ciphertext, and file/image payloads as encrypted blobs on the server filesystem (`storage/encrypted_blob_store.py`, rooted at `FILE_STORAGE_ROOT`) with the database holding references/metadata rather than plaintext content.

---

## Future Work

Message-level digital signatures and explicit (non-TOFU) out-of-band peer verification, previously listed here as gaps, are now implemented — see [Security Model](#security-model). The following remain known, unaddressed gaps in the current implementation (not a committed roadmap):

- A GUI surface for the backend's peer-verification and security-rejection state (fingerprint dialogs, verification badges, rejection notifications) — the backend exposes this (`ClientSession.security_rejection`, `confirm_peer_verification()`), but no UI consumes it yet.
- Non-repudiation as a stronger guarantee than "a valid signature proves possession of the signing key" — no revocation or dispute-resolution mechanism exists around ML-DSA signatures.
- A message/blob deletion lifecycle (`encrypted_blob_store.delete_blob()` exists but is currently unused in any production code path).
- Traffic/metadata privacy protections.
- Post-quantum-secure transport (current TLS transport layer is classical; post-quantum protection in this system is the Kyber/ML-KEM-768 key-establishment layer, not TLS).
- Forward secrecy beyond AES-GCM's own per-message properties (no ratcheting or ephemeral-per-message key mechanism).

No further slice beyond D8 is currently defined in project documentation; the origin-authentication hardening described above is committed on top of D8 without its own slice label.

---

## Project Status

The D-series work through D8 (see [Current Implementation Status](#current-implementation-status)) plus subsequent origin-authentication hardening is committed on the local `master` branch; `master` is currently ahead of `origin/master` (not yet pushed). This section does not claim the project is production- or deployment-ready — see [Future Work](#future-work) for known gaps.

Functionally, the system supports multi-user direct and group messaging, file/image transfer, read receipts, phone-number-based user discovery, and reconnection/history recovery, all mediated by an authenticated, TLS-secured server backed by PostgreSQL, with client-side AES-256-GCM payload encryption, Kyber768 (ML-KEM-768) as the default post-quantum key-exchange algorithm, and ML-DSA-65 origin authentication of identity, message, and key-establishment traffic against explicitly human-verified peer identities (see [Security Model](#security-model)).

---

## Author

**Vignesh T**

Bachelor of Engineering (Computer Science & Engineering)

Acharya Institute of Technology

Bengaluru, India

---

## License

This project is developed for educational and research purposes as part of a Final Year Engineering Project.
