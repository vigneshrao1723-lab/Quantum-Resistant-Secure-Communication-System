# Security Architecture

This document maps every security property this system provides to
the *specific* primitive/layer that actually provides it. The
recurring mistake this document exists to prevent is attributing a
property to the wrong layer (e.g. assuming TLS provides message
authentication, or that ML-KEM/RSA key exchange provides origin
authentication on its own — it does not; see
[Threat Model](threat_model.md)). Every claim below is drawn from the
actual implementation, cross-checked against the test suite that
proves it (Phase 13 and Phase 13.5–13.9 audits).

Read together with [System Architecture](../system_architecture.md),
[Threat Model](threat_model.md), and
[Key Establishment Flow](key_establishment_flow.md).

## Property-by-layer map

| Property | Provided by | NOT provided by |
|---|---|---|
| **Transport security** (confidentiality/integrity of the socket itself, server authentication) | TLS 1.2+ (`security/tls.py`) | Application-layer crypto has no dependency on this being present for its own guarantees — see "Layering" below |
| **Message confidentiality** | AES-256-GCM (`crypto/aes.py`, `crypto/payload_cipher.py`), keyed by a session/group key established via ML-KEM or RSA | TLS (TLS protects the wire hop only; the server would see plaintext if AES-GCM were absent, even under TLS) |
| **Key establishment** (agreeing a shared AES key) | ML-KEM-768 / Kyber768 (`crypto/kyber.py`, default) or RSA-2048-OAEP (`crypto/rsa.py`, classical comparison mode) | Neither KEM nor RSA-OAEP alone proves *who* the key came from — see next row |
| **Origin authentication of identity announcements, messages, and key-establishment packets** | ML-DSA-65 (FIPS 204) signatures (`crypto/ml_dsa.py`) over per-protocol canonical payloads (`crypto/identity_protocol.py`, `crypto/message_protocol.py`, `crypto/group_key_protocol.py`, `crypto/session_key_protocol.py`) | The KEM/PKE step itself — this is the exact gap Phase 13/13.5/13.6 closed |
| **Message integrity** | AES-GCM's own authentication tag (tamper detection on ciphertext) **and** the ML-DSA signature over the message's canonical payload (proves the signed fields, including ciphertext, are unmodified) | — |
| **Identity / trust** | Locally held peer-verification state (`storage/secure_key_store.py`: `PEER_STATE_UNVERIFIED` / `PEER_STATE_VERIFIED` / `PEER_KEY_STATE_CHANGED`), promoted to `VERIFIED` only by explicit human confirmation | Never the server; never automatic on receipt of a signed packet |
| **Failure handling / observability** | `SecurityRejectionReason` enum (`domain/security_rejection_reason.py`), `ClientSession.security_rejection` Signal, GUI notice (Phase 14.1) | — |

## Why the distinction matters: KEM/PKE ≠ authentication

ML-KEM and RSA-OAEP are confidentiality primitives: anyone holding a
recipient's *public* key (broadcast to every connected client by
design — see `server/broadcaster.py::distribute_public_keys()`) can
encapsulate/encrypt a session key that only that recipient can decrypt.
That is exactly their job, and exactly why they alone cannot prove
*who* produced a given key-establishment packet — a malicious relay
holding nobody's private key can still forge one from scratch. This
was the precise vulnerability class found and fixed across Phase 13.5
(RSA path) and Phase 13.8/13.8A (legacy KYBER `session_key` path,
now unconditionally rejected — see `client/session.py::
handle_session_key()`'s own docstring). ML-DSA signatures close that
gap by proving the packet's producer held a specific, locally-trusted
private signing key — a property KEM/PKE never claimed to provide.

## Domain-separated signing purposes

Four independent, non-colliding signing contexts, each in its own
module — a signature valid for one can never be replayed as valid for
another:

| Purpose constant | Value | Module | Signs |
|---|---|---|---|
| `IDENTITY_PAYLOAD_PURPOSE` | `qrscs-public-identity-v1` | `crypto/identity_protocol.py` | Identity/public-key announcements |
| `MESSAGE_PAYLOAD_PURPOSE` | `qrscs-message-v1` | `crypto/message_protocol.py` | Chat/file/image message payloads |
| `GROUP_KEY_PAYLOAD_PURPOSE` | `qrscs-group-key-v1` | `crypto/group_key_protocol.py` | Group-key distribution packets |
| `RSA_SESSION_KEY_PAYLOAD_PURPOSE` | `qrscs-rsa-session-key-v1` | `crypto/session_key_protocol.py` | RSA-mode direct session-key packets |

Every one of these is a length-prefixed (4-byte big-endian), canonical
byte encoding, verified this session to be pairwise non-colliding.
ML-DSA itself additionally binds every signature to a single, fixed
signing context (`crypto/ml_dsa.py::_CONTEXT = b"qrscs-key-distribution-v1"`),
independent of the four purposes above.

## Trust state machine

```
   observe_peer_identity()
          │
          ▼
   ┌─────────────┐   confirm_peer_verification() /       ┌───────────┐
   │ UNVERIFIED   │───confirm_combined_peer_verification()▶│ VERIFIED  │
   └─────────────┘   (explicit human action only)          └─────┬─────┘
                                                                  │ identity
                                                                  │ disagrees
                                                                  ▼
                                                          ┌───────────────┐
                                                          │ KEY_CHANGED    │
                                                          │ (old identity  │
                                                          │  preserved,    │
                                                          │  NOT trusted)  │
                                                          └───────────────┘
```

`_peer_key_is_verified()` returns `True` only for exactly `VERIFIED`.
Key establishment (both Kyber and RSA paths) requires the sender to be
`VERIFIED`; ordinary message authentication is deliberately less
strict (a signed message from an already-key-established but
not-yet-`VERIFIED` sender is still accepted — it proves possession of
the signing key, not human trust). `_resolve_trusted_signing_key()`
always resolves the verification key from this *local* state, never
from anything inside the packet being verified.

## GUI is a consumer, not an authority (Phase 14.1)

```
security validation (ClientSession, entirely pre-GUI)
        │
        ▼
ClientSession.security_rejection  Signal(reason, sender, conversation_id)
        │
        ▼
ChatWindow.handle_security_rejection()
        │
        ▼
StatusBarWidget.set_security_notice()   non-blocking, self-clearing
```

The GUI never re-implements or second-guesses the accept/reject
decision — it only renders a decision `ClientSession` already made.
See [Attack → Rejection → Recovery](attack_rejection_recovery.md) for
the full sequence this diagram is the tail end of.

## Mandatory installation order (both key-establishment paths)

```
receive → parse/validate structure → resolve sender + require VERIFIED
   → resolve trusted signing key (LOCAL state, never from packet)
   → verify ML-DSA signature → THEN decrypt/decapsulate → install
```

Never reordered — a key is installed (`KeyManager.store_key()`) only
after every prior step succeeds; any failure returns before that call
is ever reached. This ordering is what makes the rejection path in
[Key Establishment Flow](key_establishment_flow.md) safe against a
forged packet racing a real one.

## Known, documented limitations

Carried over from the README's own "Security Model" section (not
duplicated in full here — see README for the authoritative list): no
traffic/metadata privacy, no message/blob deletion lifecycle, no
forward secrecy beyond AES-GCM's own per-message properties, no
non-repudiation guarantee, and TLS transport security is classical
(not post-quantum) — this system's post-quantum protection is
specifically the Kyber/ML-KEM-768 key-establishment layer.
