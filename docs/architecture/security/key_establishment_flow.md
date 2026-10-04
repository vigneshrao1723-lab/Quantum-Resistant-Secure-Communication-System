# Key Establishment Flow

There are two key-establishment paths in this system — **Kyber/
ML-KEM-768 group-key distribution** (the default) and **RSA-2048
direct session-key delivery** (classical comparison mode,
`config.KEY_EXCHANGE_ALGORITHM == "RSA"`). Both are documented here
because both share the exact same authentication shape; only the KEM
step itself differs. Field names below are taken directly from
`utils/protocol.py`, not invented.

See [Security Architecture](security_architecture.md) for why
signatures are required at all, and
[Threat Model](threat_model.md) for the attacker this defends against.

## 1. Identity / public-key information (prerequisite)

Before any key establishment, both parties must have each other's
public key material. `create_public_key_packet()` (`utils/
protocol.py`) carries:

```
type: "key_exchange", operation: "public_key"
algorithm, username, public_key
signing_public_key   (this sender's ML-DSA public key, base64)
identity_signature   (ML-DSA signature over crypto/identity_protocol.py
                       ::canonical_identity_payload(username, public_key,
                       signing_public_key))
```

`ClientSession.handle_public_key()` verifies `identity_signature`
against `signing_public_key` itself (self-consistency — this packet
is how a signing key is first introduced) before recording the peer
as `observe_peer_identity()`'d, `UNVERIFIED` by default. A legacy
packet with no `signing_public_key` is handled via the pre-existing,
unsigned KEM-only path — documented, not silently dropped.

## 2. The authenticated key-establishment message

**Kyber / group-key path** — `create_group_key_distribution_packet()`:

```
type: "group_key_distribution"
sender, conversation_id, recipient
encapsulation, wrapped_key, epoch
group_key_signature   (base64 ML-DSA signature over
                        crypto/group_key_protocol.py::
                        canonical_group_key_payload(sender,
                        conversation_id, recipient, encapsulation,
                        wrapped_key, epoch))
```

**RSA path** — `create_session_key_packet()`:

```
type: "key_exchange", operation: "session_key"
algorithm, sender, receiver, encrypted_key, epoch, conversation_id
session_key_signature   (base64 ML-DSA signature over
                          crypto/session_key_protocol.py::
                          canonical_rsa_session_key_payload(sender,
                          receiver, conversation_id, algorithm,
                          encrypted_key, epoch))
```

Both signatures are produced with the sender's ML-DSA private key
(`crypto/key_manager.py::KeyManager.ml_dsa`) — the same persistent
signer used for identity announcements and messages, kept behind its
own domain-separated purpose constant (see
[Security Architecture](security_architecture.md#domain-separated-signing-purposes)).

## 3. Signature / authentication verification (receiver side)

`ClientSession.handle_group_key_distribution()` /
`handle_session_key()` — mandatory order, never reordered:

```
1. packet.recipient == self.username?           (routing filter only —
                                                   not a security event)
2. conversation_id / sender present?             else MALFORMED_PACKET
3. sender is VERIFIED (_peer_key_is_verified())? else UNKNOWN_SENDER /
                                                   UNVERIFIED_SENDER /
                                                   KEY_CHANGED
4. resolve trusted signing key — LOCAL peer-identity
   state ONLY, never from the packet
   (_resolve_trusted_signing_key())
5. signature field present?                      else MISSING_SIGNATURE
6. verify ML-DSA signature over the canonical
   payload, under the LOCAL trusted key           else INVALID_SIGNATURE
        │
        ▼  (only reached if every check above passed)
7. ML-KEM/Kyber decapsulation (or RSA decryption)
   of the session/group key
8. KeyManager.store_key() — key becomes active
```

## 4. Decision tree

```
VALID
 │
 ├─▶ verify authenticated origin (steps 3–6 above)
 │
 ├─▶ accept: decapsulate/decrypt, install key (steps 7–8)
 │
 └─▶ continue communication


INVALID
 │
 ├─▶ reject (return the specific SecurityRejectionReason)
 │
 ├─▶ emit security_rejection Signal(reason, sender, conversation_id)
 │     (client/session.py::_report_security_rejection())
 │
 ├─▶ do NOT install key (steps 7–8 are never reached)
 │
 ├─▶ preserve trust state (no VERIFIED record is downgraded or
 │     overwritten by a rejection)
 │
 ├─▶ notify GUI (ChatWindow.handle_security_rejection() →
 │     StatusBarWidget.set_security_notice() — Phase 14.1)
 │
 └─▶ continue/recover (receiver thread stays alive; the next,
       legitimate packet is processed normally)
```

## 5. Rejection reasons actually reachable on this path

From `domain/security_rejection_reason.py`'s `SecurityRejectionReason`:
`UNKNOWN_SENDER`, `UNVERIFIED_SENDER`, `KEY_CHANGED`,
`MISSING_SIGNATURE`, `INVALID_SIGNATURE`, `MALFORMED_PACKET`,
`DUPLICATE_OR_STALE_KEY` (informational — an already-trusted sender
re-sent a key this client already has; not treated as an attack, and
deliberately produces no GUI warning — see
`gui/chat_window.py::handle_security_rejection()`), and
`OTHER_SECURITY_REJECTION` (used by the legacy-KYBER-`session_key`
unconditional-rejection branch below). Not every member of the enum
has a distinguishable code path on every handler — see each handler's
own docstring in `client/session.py` for exactly which reasons it can
return.

## 6. The one deliberately-dead legacy path

`handle_session_key()`'s `algorithm == "KYBER"` branch **unconditionally
rejects** with `OTHER_SECURITY_REJECTION`, before any decapsulation is
attempted. This is not an oversight: an earlier wire-protocol shape
sent Kyber session keys through this packet type; Phase 13.8/13.8A
found and fixed the fact that shape had no authenticated producer at
all (anyone holding a client's public Kyber key could forge one — see
[Threat Model](threat_model.md)), and confirmed no legitimate code path
in this codebase still produces it. Current production Kyber key
establishment always goes through
`group_key_distribution`/`group_key_signature` instead, even for a
two-person "group" (a direct conversation's key is distributed the
same way). See `client/session.py::handle_session_key()`'s own
docstring for the full trace.
