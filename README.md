# Quantum-Resistant Secure Communication System

A multi-user, server-mediated secure communication system developed as a Final Year Project in Python. The system combines classical cryptography with Post-Quantum Cryptography (PQC) for client-side session key exchange, and uses a PostgreSQL-backed server as the authority for authentication, conversation state, message persistence, and file/image blob storage.

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
├── web/                      # Website: client/ (static HTML/JS) and gateway/ (WebSocket -> server bridge)
├── scripts/                  # Dev tooling (e.g. certificate generation)
├── certs/                     # Development TLS certificates
├── benchmark/                 # Performance benchmarking scripts
├── docs/                      # Project documentation
├── tests/                     # Automated test suite (pytest)
│
├── config.py                  # Client-side configuration
├── config_server.py            # Server-side configuration (JWT, storage root, etc.)
├── logger_config.py
├── main.py                     # Desktop application entry point
├── run.py                      # Combined launcher: server + gateway + Website + Desktop
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

**D8 status note**: D8 and everything after it, through Phase 19.24 (the Desktop/Website completion work), is merged into `master` (pull request #1, merge commit `8f376f4`) and pushed to `origin`. The earlier intermittent TLS test-harness instability was addressed by the Phase 19.24 work. See [`PROJECT_STATE.md`](PROJECT_STATE.md) for the current branch heads and verification record.

**Origin-authentication hardening (post-D8, complete)**: subsequent work added ML-DSA-65 origin authentication across the protocol — public-identity announcements, chat messages, Kyber group/direct-key distribution, and RSA session-key delivery each now require a valid signature, verified against a locally held, explicitly human-verified peer identity, before being trusted or installed. This also closed a confirmed vulnerability in which an unauthenticated legacy Kyber session-key packet shape could have been used by a malicious server to install an attacker-chosen key (`client/session.py::handle_session_key()`; that packet shape is now rejected outright, before any decryption). This work is committed on top of D8 but predates any formal slice numbering in this table — see [Security Model](#security-model) for what it actually provides.

---

## Testing

The most recent complete run of the regression runner (`python scripts/run_regression_batches.py`, 15 batches, owner's machine, 2026-10-22) passed **2,188 tests**, and the Desktop-executable + Website acceptance suite passed 33 (see [`PROJECT_STATE.md`](PROJECT_STATE.md)). Treat these as a dated snapshot; `pytest --collect-only -q` gives the current count.

Tests require a running local PostgreSQL instance and a `DATABASE_URL` pointing at it (see [Getting Started on Windows](#getting-started-on-windows)) — `tests/conftest.py` wraps each test in a transaction that's rolled back on teardown, so no test data persists, but a real database connection is required for the suite to run at all (SQLite is not supported).

Install `requirements-dev.txt` and follow [Running tests](#running-tests) (focused commands and the batch runner). Do not run one bare `pytest` over the whole tree on Windows.

Performance measurements for the ML-DSA-65 signature primitive (key generation/signing/verification) are documented separately — see [ML-DSA Benchmark](docs/benchmark/ml_dsa_benchmark.md). For a reproducible walkthrough of the malicious-relay/security-rejection defense (and an FYP presentation guide built on it), see [Security Rejection Demonstration](docs/demo/security_rejection_demo.md) and [FYP Presentation Guide](docs/demo/fyp_presentation_guide.md).

---

## Getting Started on Windows

This is the one supported setup path for **Windows 10/11 (64-bit)**. Commands are for **PowerShell** run from the repository root. The steps were followed from a fresh clone of `master` (results and exact versions: [`PROJECT_STATE.md`](PROJECT_STATE.md)).

### What you need installed first

| Requirement | Version | Notes |
|---|---|---|
| Python | **3.12.x** (tested 3.12.10) | Install from python.org with the *py launcher*. **Not 3.13 / 3.14**: the dependencies are pinned for 3.12 (e.g. PySide6 6.9.1). |
| PostgreSQL | **17** (tested 17.11) | Includes `psql`. Remember the password you give the `postgres` user. The server does **not** work with SQLite. |
| Git | any recent | |
| Google Chrome | optional | Only for the Website browser tests / acceptance suite. The Website itself is plain HTML/JS. |

Things that are deliberately **not in the repository** and must be created on every machine: PostgreSQL itself and its database, `.env` (secrets), `certs/` (TLS keys), the virtual environment `venv/`, the built executable `dist/`, and each user's key store under `%LOCALAPPDATA%\QuantumResistantSecureComms`. No external service, FFmpeg, Node.js or system certificate tool is needed (audio/video playback uses the FFmpeg plugin bundled inside PySide6).

### 1. Clone

```powershell
git clone https://github.com/vigneshrao1723-lab/Quantum-Resistant-Secure-Communication-System.git
cd Quantum-Resistant-Secure-Communication-System
```

`master` is the default branch. (The remote also has an old, unrelated `main` branch — ignore it.)

### 2. Virtual environment and dependencies

```powershell
py -3.12 -m venv venv
venv\Scripts\Activate.ps1
python --version                       # must print Python 3.12.x
python -m pip install -r requirements.txt -r requirements-dev.txt
```

* `requirements.txt` = everything needed to **run** the server, gateway, Website and Desktop. `requirements-dev.txt` adds the test tools, Playwright (browser tests), PyInstaller (executable build) and Kivy (mobile unit tests only). Install both unless you only want to run the application.
* If PowerShell refuses to run `Activate.ps1`: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, or use `venv\Scripts\activate.bat` from cmd.
* Open a new terminal later? Activate the venv again. Every command below uses the `python` of the activated venv.

### 3. Create the database

```powershell
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -c "CREATE DATABASE qrscs;"
```

(`psql` asks for the `postgres` password; you can type just `psql` if PostgreSQL's `bin` folder is on your PATH.)

### 4. Create `.env` (local secrets — never commit it)

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Open `.env` in an editor and set:

* `JWT_SECRET_KEY` — the random value just printed (the server refuses to start with the placeholder).
* `DATABASE_URL` — the **administrator** login for this one-time setup: `postgresql+psycopg2://postgres:<postgres-password>@localhost:5432/qrscs` (percent-encode special characters in the password, e.g. `@` → `%40`).

Leave the rest as it is; `MIGRATION_DATABASE_URL` stays commented out. `.env` is covered by `.gitignore`.

### 5. TLS certificates (local development CA)

```powershell
python scripts/generate_dev_certs.py
```

Creates `certs/dev/` (`ca.crt`, `ca.key`, `server.crt`, `server.key`; SANs `127.0.0.1` and `localhost`, gitignored). Re-run it to renew. To reach the server from another computer, set `TLS_CERT_SANS` (see `.env.example`) before generating. Details: [TLS transport](docs/architecture/tls_transport.md).

### 6. Create the database schema

```powershell
python -m alembic upgrade head
python -m alembic current              # should end with: e8c2a6d4f1b9 (head)
```

Run this **before** step 7 (still as the administrator login from step 4). It applies all 17 migrations to the empty database.

### 7. Least-privilege database roles

```powershell
python scripts/setup_database_roles.py
```

The server never runs as a superuser. This creates `qrscs_app` (runtime: read/write on the application tables, no schema changes) and `qrscs_migrator` (owns the schema; used by Alembic), rewrites `DATABASE_URL` / `MIGRATION_DATABASE_URL` in `.env` with their random passwords, moves the administrator login to `%USERPROFILE%\.qrscs\admin.env` (outside the repository), and prints a `[PASS]` line for each permission check. It stops without changing anything if step 6 was skipped, and is safe to re-run (`--rotate` issues new passwords). Future schema upgrades: `python -m alembic upgrade head` again (it now uses the migrator role).

### 8. Start everything

```powershell
python run.py
```

`run.py` is the supported combined launcher. It checks `.env`, the certificates and the ports first, then starts, in order:

| Component | Command it runs | Address |
|---|---|---|
| Secure chat server (TLS) | `python -m server.server` | `127.0.0.1:5000` (`SERVER_PORT` in `.env`) |
| Web gateway (WebSocket → server) | `python -m web.gateway.gateway` | `ws://127.0.0.1:8765` |
| Website (static files) | `python -m http.server 8000 --directory web/client` | **http://127.0.0.1:8000** |
| Desktop application | `python main.py` | a window |

Press **Ctrl+C** in that terminal to stop everything. Options: `--no-desktop` (no Desktop window), `--web-port N`, `--gateway-port N` (when 8000 / 8765 are taken; the Website address is then printed with a `?gateway=ws://127.0.0.1:N` suffix). To run the pieces yourself, start the first three commands in separate activated terminals, then `python main.py`.

### 9. Create two accounts and send a message

1. In the Desktop window (or the Website) choose **Create an account** and enter a display name, a **phone number** (7–15 digits, e.g. `+91 98765 43210` — this is what you sign in with) and a password of at least 12 characters with upper-case, lower-case, a digit and a special character. Create a second account the same way.
2. **Second Desktop instance:** open another activated terminal and run `python main.py` (not `run.py`, which would try to start a second server). Sign in with the *other* account — two windows signed in as the *same* account share one key file. For a second Website user use another browser profile or a private window.
3. In one window search for the other person (phone number or @handle) and open the chat. Both sides compare the **safety number** and confirm it, then press **Establish key**. Messaging is intentionally blocked until the identity is verified. Send a message each way.

The full owner checklist is in [`docs/owner_manual_test_checklist.md`](docs/owner_manual_test_checklist.md) and [`docs/manual_acceptance_checklist.md`](docs/manual_acceptance_checklist.md).

### Running tests

All tests use the real PostgreSQL from your `.env` (each test is rolled back); SQLite is not supported. Start small:

```powershell
python -m pytest tests/test_aes.py tests/test_kyber.py tests/test_ml_dsa.py -q          # pure crypto, no database
python -m pytest tests/test_user_repository.py tests/test_database_least_privilege.py -q # needs the database and step 7
python -m pytest tests/test_configuration_separation.py -q
```

The whole regression suite (15 curated batches, several minutes to an hour; the Website batches need Chrome, the `mobile` batch needs Kivy from `requirements-dev.txt`):

```powershell
python scripts/run_regression_batches.py            # all batches, with counts
python scripts/run_regression_batches.py --list     # show the batches
python scripts/run_regression_batches.py --batch crypto_unit
```

Do not run a bare `pytest` over everything in one process on Windows; the batch runner exists because that is unreliable (see [testing strategy](docs/architecture/testing_strategy.md)). The acceptance suite is described under [Acceptance tests](#acceptance-tests-separate-from-the-regression-batches).

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `DATABASE_URL must be set…` or `JWT_SECRET_KEY must be set…` | No `.env`, or the placeholder is still there. Repeat step 4. Run commands from the repository root. |
| `ModuleNotFoundError` for PySide6, sqlalchemy, kyber_py, websockets… | The venv is not activated, or the install was skipped / used another Python. Check `python --version` (3.12.x) and `python -c "import sys; print(sys.prefix)"` (must be the `venv` folder), then re-run step 2. |
| `password authentication failed` / `connection refused` on port 5432 | Wrong password in `DATABASE_URL`, PostgreSQL service not running (`Get-Service postgresql*`), or a different port. Percent-encode `@`, `:`, `/`, `#`, `%` in the password. |
| `relation "users" does not exist` | Migrations not applied: `python -m alembic upgrade head`. |
| `setup_database_roles.py`: "no application schema yet" | Run step 6 first. |
| `setup_database_roles.py`: "not a superuser" or WARNING about the role | `DATABASE_URL` in `.env` is not the administrator login. Put it back (step 4), or set `QRSCS_ADMIN_DATABASE_URL`; use `--rotate` if roles exist from an earlier attempt. |
| `FileNotFoundError` for `server.crt` / "TLS … not found" | Run step 5. |
| TLS certificate verify failed / hostname mismatch | The address in `SERVER_HOST` is not in the certificate's SANs: set `TLS_CERT_SANS`, regenerate, restart. After regenerating, rebuild the executable (it bundles `ca.crt`). |
| `Port 5000 … already in use` | Another program or an earlier run holds it. Stop it, set another `SERVER_PORT` in `.env`, or use `run.py --web-port` / `--gateway-port` for the Website ports. Find the owner: `Get-NetTCPConnection -LocalPort 5000 -State Listen`. |
| Website says it cannot connect | The gateway is not running, or the page's *Connection settings* gateway address differs from the gateway's port. |
| Windows blocks `QRSCS-Desktop.exe` ("Windows protected your PC", Smart App Control, Application Control) | The executable is **unsigned**. Choose *More info → Run anyway*, retry once (a freshly built file was blocked once and ran on the next attempt), or run the Desktop from source with `python main.py`. |
| Two Desktop windows fail to rebuild the executable | Windows locks files of a running executable; close all `QRSCS-Desktop` windows before `python scripts/build_desktop_exe.py`. |

### Packaging a source archive

Do not zip the project folder by hand — `.env` and the private TLS keys live in it. Build the archive with:

```bash
python scripts/package_release.py          # -> dist/qrscs-source-YYYYMMDD.zip
python scripts/package_release.py --verify some.zip
```

It archives only what Git considers part of the project (so everything in `.gitignore` is left out), refuses secret-shaped files regardless, and then validates the finished archive: no `.env`/key/database files, no private-key blocks, tokens or credentials in any file, and none of this machine's own secret values anywhere. A failed check deletes the archive and exits non-zero.

---

### Windows Desktop executable

Build the Desktop client into a one-folder Windows application (inside the activated Python 3.12 virtual environment, with `requirements-dev.txt` installed, after step 5 so `certs/dev/ca.crt` exists; close any running `QRSCS-Desktop` window first):

```bash
python scripts/build_desktop_exe.py
```

The result is `dist/desktop/QRSCS-Desktop/QRSCS-Desktop.exe`; distribute the whole `QRSCS-Desktop` folder. It contains only the client: no `.env`, no private keys, no database or server code. The public CA certificate it trusts is bundled (`--ca-cert PATH` selects another one). To point it at a different server, copy the generated `.env.example` in that folder to `.env` next to the executable and set `SERVER_HOST` / `SERVER_PORT` (the host must appear in the server certificate's subject alternative names). Per-user keys and logs are stored under `%LOCALAPPDATA%\QuantumResistantSecureComms`. The build script validates its own output and fails (removing it) if it finds a secret-like file or a configured live secret value.

### Acceptance tests (separate from the regression batches)

`tests/acceptance/` drives the **built executable** and the **Website in Chrome** through their real user interfaces against an isolated PostgreSQL database (`qrscs_accept`, created by `scripts/acceptance_db.py` with the roles from step 7 and the administrator login that step saved in `%USERPROFILE%\.qrscs\admin.env`). Needs Chrome. Build the executable first, then:

```bash
python -m pytest tests/acceptance -p no:cacheprovider
```

### Android (paused)

**Android/APK work is paused**: the sources under `mobile/` and the Buildozer files are preserved unchanged (also on the `preservation/android-desktop-web-baseline-2026-10-20` branch) and nothing in the Desktop/Website setup above needs them.

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

- (Resolved) The peer-verification and security-rejection state now has a GUI on both Desktop and Website (safety-number dialogs, verification badges, rejection notices).
- Non-repudiation as a stronger guarantee than "a valid signature proves possession of the signing key" — no revocation or dispute-resolution mechanism exists around ML-DSA signatures.
- A message/blob deletion lifecycle (`encrypted_blob_store.delete_blob()` exists but is currently unused in any production code path).
- Traffic/metadata privacy protections.
- Post-quantum-secure transport (current TLS transport layer is classical; post-quantum protection in this system is the Kyber/ML-KEM-768 key-establishment layer, not TLS).
- Forward secrecy beyond AES-GCM's own per-message properties (no ratcheting or ephemeral-per-message key mechanism).

No further slice beyond D8 is currently defined in project documentation; the origin-authentication hardening described above is committed on top of D8 without its own slice label.

---

## Project Status

The current engineering state — branches, what has been verified and how, open items and next actions — is kept in [`PROJECT_STATE.md`](PROJECT_STATE.md); the per-feature, per-platform audit is [`docs/architecture/feature_parity_matrix.md`](docs/architecture/feature_parity_matrix.md), and the multi-user acceptance suite is described in [`docs/architecture/acceptance_testing.md`](docs/architecture/acceptance_testing.md). This section does not claim the project is production- or deployment-ready — see [Future Work](#future-work) for known gaps.

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
