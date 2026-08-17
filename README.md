# Quantum-Resistant Secure Communication System

A multi-user, server-mediated secure communication system developed as a Final Year Project in Python. The system combines classical cryptography with Post-Quantum Cryptography (PQC) for client-side session key exchange, and uses a PostgreSQL-backed server as the authority for authentication, conversation state, message persistence, and file/image blob storage.

---

## Overview

The system is a client-server chat application. Multiple clients connect to a central server over a TLS-secured TCP socket, authenticate with a username/password (JWT-based session), and exchange direct and group messages, files, and images. The server persists all conversation, message, and membership state in a PostgreSQL database and stores file/image ciphertext on disk as encrypted blobs.

Message *content* is encrypted client-side at the payload level using AES-256-GCM, with per-conversation session keys established via client-side Kyber (ML-KEM-768) or RSA key exchange — the server never holds the AES session keys and cannot decrypt message bodies or blob contents. The server is, however, fully trusted with connection metadata (who is talking to whom, when, message sizes, filenames, and group membership), and it also mediates key distribution. See [Security Model](#security-model) below for the exact boundary of what the server can and cannot see.

Development has proceeded through a sequence of server-migration slices (documented under [Current Implementation Status](#current-implementation-status)) that moved conversation resolution, key epoch management, conversation-list loading, message history, and blob retrieval from local client-side storage to authenticated server-side request/response operations. As of this document, that migration series (through slice D4.3) is complete, and the full automated test suite passes.

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
- **Session and key management**: each client session generates fresh Kyber and RSA identity key pairs at login (`crypto/key_manager.py`); these are never persisted to disk.
- **Key epoch handling**: AES session keys for a conversation are scoped by `(conversation_id, epoch)`, with epoch reservation now performed via a server request rather than client-local bookkeeping.
- **Post-quantum key exchange (Kyber / ML-KEM-768)**: `crypto/kyber.py` implements Kyber768 (via the `kyber-py` library, the FIPS 203 ML-KEM-768 parameter set) as the **default and active** key-exchange algorithm (`config.py: KEY_EXCHANGE_ALGORITHM = "KYBER"`), used to establish the AES session key between clients. Classical RSA-2048 (OAEP/SHA-256, `crypto/rsa.py`) is also implemented and selectable, primarily for comparison purposes.
- **Server-side request/response architecture**: client-originated operations that need server authority (conversation resolution, key epoch reservation, conversation list loading, message history, blob download) go through a correlated request/response protocol (`utils/request_registry.py`, `ClientSession.send_request()`) rather than ad hoc client-local logic.

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
- **Cryptographic layer** (`crypto/`): AES-256-GCM (payload/session encryption), RSA-2048-OAEP and Kyber768/ML-KEM-768 (session key exchange), all executed client-side only.
- **Protocol / request-response layer** (`utils/protocol.py`, `utils/request_registry.py`): defines the JSON packet schema and correlates outgoing client requests with server responses by `request_id`.

---

## Security Model

**What the server cannot see:**
- Plaintext message bodies — messages are AES-256-GCM encrypted client-side before transmission, using a session key the server never possesses.
- Plaintext file/image contents — blob payloads are encrypted client-side (`crypto/payload_cipher.py`) before upload; the server stores and serves ciphertext only. This is confirmed by inspection: no AES/Kyber/RSA cipher or key-manager code exists anywhere in `server/`.

**What the server can see (and must be trusted with):**
- Connection-level metadata: which authenticated user is connected, and when.
- Message metadata: sender, recipient(s)/group, conversation ID, timestamps, payload type (text/file/image), and for file/image messages, content metadata such as filename and size.
- Group and conversation membership.
- Presence (online/offline / user list broadcasts).
- The distribution of public keys during key exchange: `server/broadcaster.py`'s `distribute_public_keys()` relays each client's self-submitted Kyber/RSA public key to peers. There is currently no out-of-band or trust-on-first-use verification of these keys, so the security model assumes the server (or a party controlling it) does not tamper with key distribution — a compromised server could attempt a man-in-the-middle substitution of public keys at exchange time.

**Other known limitations (not yet addressed):**
- No message-level digital signatures or non-repudiation mechanism exists in the codebase.
- No traffic/metadata privacy — the server necessarily observes who is communicating with whom, and how often.
- No message/blob deletion lifecycle — `encrypted_blob_store.delete_blob()` exists but has no production call site; stored blobs are not currently purged.
- `JWT_SECRET_KEY` defaults to a development placeholder in `config_server.py` and must be overridden via environment variable for any non-development deployment.

Given these properties, this system should be described as providing **client-side payload encryption with server-mediated key exchange**. Transport security (TLS) is classical, not post-quantum.

---

## Technology Stack

### Language
- Python 3.13

### GUI
- PySide6 (Qt for Python) — `gui/`, `main.py`

### Networking / Transport
- Python `socket` (TCP), multi-threaded server (`server/`)
- TLS 1.2+ via `ssl` (`security/tls.py`)

### Cryptography
- AES-256-GCM — PyCryptodome (`crypto/aes.py`, `crypto/payload_cipher.py`)
- RSA-2048 (OAEP, SHA-256) — `cryptography` library (`crypto/rsa.py`)
- Kyber768 / ML-KEM-768 (post-quantum KEM) — `kyber-py` (`crypto/kyber.py`)
- Argon2 password hashing — `argon2-cffi` (`security/password_handler.py`)
- JWT (HS256) — `PyJWT` (`security/jwt_handler.py`)

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
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Current Implementation Status

The project has completed a multi-slice migration moving client-local database/storage responsibilities to authenticated, server-mediated request/response operations. As of this document, the migration series through **D4.3** is complete, the working tree is clean, and the full test suite passes.

| Slice | Description |
|-------|-------------|
| D3.1 | Direct conversation resolution moved to the server (server resolves/creates the direct conversation for two users, rather than the client deriving it locally). |
| D3.2 | Server-side request/response infrastructure (`ClientSession.send_request()`, `PendingRequestRegistry`) added to correlate client requests with server responses by `request_id`. |
| D3.3 | Direct conversation resolution fully routed through the D3.2 request/response mechanism. |
| D4.1 | Key epoch reservation moved behind an authenticated server request, replacing client-local epoch bookkeeping. |
| D4.2 | Conversation list loading moved behind the server; the client requests its conversation list from the server on session start rather than reading it from local state. |
| D4.3 | Message history retrieval and file/image blob download moved behind server request/response operations. |

Earlier foundational work (multi-client TCP communication, username-based sessions, AES/RSA/Kyber cryptography, PostgreSQL-backed persistence, TLS transport, JWT authentication) predates and underlies this migration series and remains in place.

---

## Testing

The full automated test suite currently passes in its entirety:

```
549 passed, 0 failed, 0 skipped, 1 warning in 200.69s (0:03:20)
```

The single warning is a pre-existing `DeprecationWarning: ssl.TLSVersion.TLSv1_1 is deprecated`, emitted by `tests/test_tls_transport.py::test_tls_minimum_version_rejects_older_client`, which intentionally constructs a legacy TLS 1.1 context to verify the server rejects it. It is unrelated to the D-series migration work.

Run the suite with:

```bash
pytest -q
```

---

## Installation / Setup

Clone the repository:

```bash
git clone https://github.com/vigneshrao1723-lab/Quantum-Resistant-Secure-Communication-System.git
cd Quantum-Resistant-Secure-Communication-System
```

Create and activate a virtual environment:

```bash
python -m venv venv
venv\Scripts\activate        # Windows
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure environment variables (database connection string, `JWT_SECRET_KEY`, etc.) — see `.env.example` for the required keys, and create your own `.env` accordingly.

Set up the PostgreSQL database schema:

```bash
alembic upgrade head
```

Development TLS certificates can be generated with:

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

---

## Database

- **Engine**: PostgreSQL, accessed via SQLAlchemy (`database/connection.py`) with Alembic-managed schema migrations (`alembic/`).
- **Persisted data** (see `database/models/`): users and credentials (`user.py`), sessions (`session.py`), conversations (`conversation.py`) and their membership (`conversation_member.py`), messages (`message.py`), and per-recipient delivery/read status (`message_recipient.py`).
- Message and file/image *content* is stored encrypted: message bodies as persisted ciphertext, and file/image payloads as encrypted blobs on the server filesystem (`storage/encrypted_blob_store.py`, rooted at `FILE_STORAGE_ROOT`) with the database holding references/metadata rather than plaintext content.

---

## Future Work

The following are known, unaddressed gaps in the current implementation (not a committed roadmap):

- Message-level digital signatures / non-repudiation.
- Out-of-band or trust-on-first-use verification of distributed public keys, to mitigate server-side key-substitution risk.
- A message/blob deletion lifecycle (`encrypted_blob_store.delete_blob()` exists but is currently unused in any production code path).
- Traffic/metadata privacy protections.
- Post-quantum-secure transport (current TLS transport layer is classical).

No further server-migration slice beyond D4.3 is currently defined in project documentation.

---

## Project Status

The D-series server-migration work (D3.1 through D4.3) is implemented and complete on the current local `master` branch (verified in sync with `origin/master`). The full automated test suite (549 tests) passes with 0 failures. The system supports multi-user direct and group messaging, file/image transfer, read receipts, and reconnection/history recovery, all mediated by an authenticated, TLS-secured server backed by PostgreSQL, with client-side AES-256-GCM payload encryption and Kyber768 (ML-KEM-768) as the default post-quantum key-exchange algorithm.

---

## Author

**Vignesh T**

Bachelor of Engineering (Computer Science & Engineering)

Acharya Institute of Technology

Bengaluru, India

---

## License

This project is developed for educational and research purposes as part of a Final Year Engineering Project.
