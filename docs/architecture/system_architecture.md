# System Architecture

FYP-level overview of how the pieces fit together, written to be read
alongside — not instead of — the more detailed documents it links to:
[Security Architecture](security/security_architecture.md),
[Threat Model](security/threat_model.md),
[Key Establishment Flow](security/key_establishment_flow.md),
[Secure Message Flow](message_flow.md),
[Attack → Rejection → Recovery](security/attack_rejection_recovery.md),
[TLS Transport](tls_transport.md),
[Message Storage](storage.md),
[Server Architecture](server_architecture.md),
[Desktop GUI Architecture](desktop_gui_architecture.md),
[Key Management Lifecycle](key_management_lifecycle.md),
[Database Architecture](database_architecture.md),
[Authentication Flow](authentication_flow.md),
[Multi-Device Identity](multi_device_identity.md),
[Testing Strategy](testing_strategy.md),
[Web Interoperability](web_interoperability.md), and
[Security Matrix](security/security_matrix.md).

## Layered view

```
 ┌───────────────────────────────────────────────────────────────┐
 │  Client GUI                              gui/, main.py         │
 │  PySide6 windows/widgets — ChatWindow, LoginWindow,             │
 │  VerifyIdentityDialog, StatusBarWidget                          │
 └───────────────────────────┬───────────────────────────────────┘
                              │ Qt Signals (thread-safe GUI updates)
 ┌───────────────────────────▼───────────────────────────────────┐
 │  Client application / session layer        client/session.py   │
 │  ClientSession — the ONE object owning this client's           │
 │  connection, key state, and peer-trust state. Everything        │
 │  below this line is invoked BY ClientSession, never directly    │
 │  by the GUI.                                                    │
 └───────────────────────────┬───────────────────────────────────┘
                              │
 ┌───────────────────────────▼───────────────────────────────────┐
 │  Security / protocol layer                        crypto/,     │
 │  Packet construction (utils/protocol.py), canonical signing     │
 │  payloads + ML-DSA signatures (crypto/identity_protocol.py,     │
 │  crypto/message_protocol.py, crypto/group_key_protocol.py,      │
 │  crypto/session_key_protocol.py), key management                │
 │  (crypto/key_manager.py), AES-256-GCM (crypto/aes.py,           │
 │  crypto/payload_cipher.py), Kyber/ML-KEM (crypto/kyber.py),     │
 │  RSA (crypto/rsa.py), ML-DSA (crypto/ml_dsa.py)                  │
 └───────────────────────────┬───────────────────────────────────┘
                              │ already-encrypted, already-signed
                              │ opaque byte fields
 ┌───────────────────────────▼───────────────────────────────────┐
 │  TLS transport                              security/tls.py     │
 │  ssl.SSLContext wrapping every client↔server socket — see       │
 │  tls_transport.md for the full connection-flow detail            │
 └───────────────────────────┬───────────────────────────────────┘
                              │ TLS 1.2+ (TCP), JSON-framed packets
 ┌───────────────────────────▼───────────────────────────────────┐
 │  Server relay                    server/, utils/protocol.py     │
 │  server/client_handler.py — authenticates (JWT), routes/relays  │
 │  packets, enforces group-membership rules. server/broadcaster.py│
 │  — presence + public-key distribution. Never decrypts message    │
 │  bodies, never signs on a client's behalf, never holds a         │
 │  client's private key.                                           │
 └───────────────────────────┬───────────────────────────────────┘
                              │
 ┌───────────────────────────▼───────────────────────────────────┐
 │  Database / storage                    database/, storage/,     │
 │  PostgreSQL (SQLAlchemy models/repositories, Alembic             │
 │  migrations) — conversation/message/user metadata + ciphertext.  │
 │  storage/encrypted_blob_store.py — large file/image ciphertext   │
 │  blobs on the server filesystem. storage/secure_key_store.py —   │
 │  CLIENT-side only, encrypted-at-rest key/identity persistence     │
 │  (never reaches the server).                                     │
 └───────────────────────────────────────────────────────────────┘
```

This is the exact chain the task specification asked for
(`Client GUI → Client session → Security/protocol → TLS transport →
Server relay → Database/storage`), confirmed against the actual
imports and call graph in `client/session.py`, `server/
client_handler.py`, and `crypto/`.

## The one architectural fact that matters most

**The server is a relay, not a key holder.** Every operation that
needs a *private* key — key generation, encryption, decryption, and
producing a signature — happens inside a `ClientSession` on a client
machine; `server/` holds no private key of any kind (confirmed by
inspection, not assumed — see
[Security Architecture](security/security_architecture.md) and the
README's own "Security Model" section). One narrow exception:
`server/device_handler.py` does import `crypto.ml_dsa`/
`crypto.device_protocol` to *verify* — never produce — a device's own
ML-DSA self-signature on enrollment/authorization/revocation
requests, using only that device's already-on-file *public* key
(see [Multi-Device Identity](multi_device_identity.md)). This is
still authentication of *identity possession*, not of message
content: `server/` never verifies a chat/group-key signature, never
runs AES-GCM, and never touches a Kyber/RSA private key. The server's
job is authentication of the *transport, the connection, and device
identity* (TLS, JWT, device self-signatures), plus routing,
persistence, and membership enforcement — never decryption or
authentication of *message content*. That distinction is the basis
for the entire threat model (see
[Threat Model](security/threat_model.md)).

## Major components and responsibilities

| Component | Responsibility | Does NOT do |
|---|---|---|
| `gui/` (`ChatWindow`, `LoginWindow`, `VerifyIdentityDialog`, `StatusBarWidget`) | Renders state, collects user input/confirmation, displays non-blocking security notices (Phase 14.1) | Never makes a trust or cryptographic decision — see [Security Architecture](security/security_architecture.md)'s "GUI is a consumer, not an authority" note |
| `client/session.py` (`ClientSession`) | Owns the socket/TLS connection, drives the whole client-side protocol, holds peer-trust state, emits Qt Signals (`security_rejection`, `peer_key_changed`, etc.) | Never persists anything server-side; holds no independent DB connection |
| `crypto/` | All cryptographic primitives and the per-protocol canonical-signing/verification helpers | Never performs network I/O |
| `security/tls.py` | Builds the one authoritative `ssl.SSLContext` for client and server | Provides no application-level (message) authentication — see `tls_transport.md` |
| `server/client_handler.py`, `server/broadcaster.py` | Authenticates connections (JWT), routes/relays packets, enforces group-membership rules, broadcasts presence | Never decrypts message/blob content, never signs on a client's behalf |
| `database/` | Persists user/session/conversation/message metadata and ciphertext via SQLAlchemy + Alembic | Never stores plaintext message content |
| `storage/encrypted_blob_store.py` | Server-local ciphertext blob storage for files/images | Never decrypts what it stores |
| `storage/secure_key_store.py` | Client-local, password-derived, encrypted-at-rest persistence of this user's own keys and peer-verification state | Never transmitted to the server |

## Terminology

This document uses only names already established in the source and
prior documentation: **ClientSession**, **ML-KEM-768 / Kyber768**,
**ML-DSA-65**, **AES-256-GCM**, **TLS**, **VERIFIED / UNVERIFIED /
KEY_CHANGED** peer-trust states, and **security_rejection**. No new
component or terminology is introduced.
