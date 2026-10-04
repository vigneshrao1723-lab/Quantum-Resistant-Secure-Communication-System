# Threat Model

This document describes the threat this system's cryptographic design
actually defends against, drawn from the implementation and the test
suite that proves it (`tests/test_key_establishment_rejection_
observability.py`, `tests/test_rsa_session_key_authentication.py`,
`tests/test_kyber_session_key_forgery_remediation.py`,
`tests/test_group_key_authentication.py`, `tests/test_peer_key_
verification.py`, and others). See also
[Security Architecture](security_architecture.md) for the property-by-
layer breakdown this threat model is built on, and
[Attack → Rejection → Recovery](attack_rejection_recovery.md) for a
step-by-step trace of the defense in action.

## The threat: a malicious or compromised relay

The server sits between every pair of communicating clients and — per
this project's own design (see README's "Threat Model" subsection
under Security Model) — is trusted with connection metadata and
routing, but explicitly **not** trusted as a cryptographic authority.
This document treats the server itself (or anything positioned where
the server is: a compromised server process, or a network position
able to modify what the server relays) as the attacker.

```
  Alice
    │
    │  authenticated/signed packet
    │  (identity announcement, message,
    │   key-establishment packet)
    ▼
  Malicious relay  (the untrusted server, or anything
    │               positioned at the same point)
    │
    │  forged/modified packet
    ▼
  Bob
```

## What the attacker can and cannot do

1. **The attacker may control or modify relay-delivered packet
   contents.** It can drop, delay, reorder, or rewrite any field in
   any packet it relays — this is assumed, not merely possible.
2. **The attacker does not possess Alice's ML-DSA private signing
   key.** No private key material for any client is ever transmitted
   to or held by the server (confirmed by inspection — no signing/
   decryption key ever leaves `storage/secure_key_store.py`'s
   client-local, encrypted-at-rest store).
3. **Bob validates the authenticated origin/signature** of every
   identity announcement, message, and key-establishment packet
   before trusting its content — `ClientSession.handle_group_key_
   distribution()` / `handle_session_key()` / `handle_chat()` /
   `handle_public_key()`, each verifying an ML-DSA signature against
   Bob's own *locally held* trusted key, never a key carried in the
   packet.
4. **A forged packet is rejected** — signature verification fails,
   and the handler returns a `SecurityRejectionReason` instead of
   proceeding.
5. **A forged key is not installed** — per the mandatory ordering in
   [Security Architecture](security_architecture.md#mandatory-installation-order-both-key-establishment-paths),
   decryption/decapsulation and `KeyManager.store_key()` are never
   reached once verification has failed.
6. **Trust state is not corrupted** — an already-`VERIFIED` peer
   record is never overwritten by a rejected packet; `KEY_CHANGED`
   (when it does occur, for a *different* reason — a genuine identity
   disagreement) preserves the old identity rather than silently
   replacing it.
7. **The receiver continues operating** — rejection is a normal
   return path, not an exception that could kill the receiver thread;
   `bob.is_connected()` and `bob.receiver_thread.is_alive()` both
   remain true after a rejected attack (proven in
   `test_malicious_relay_group_key_receiver_survives_and_recovers`).
8. **Legitimate communication can continue** — the same test proves a
   genuine message sent immediately after a rejected forgery is
   delivered normally, with no reconnect or re-verification step
   required.

## Honest scope limitation

This project does **not** claim to demonstrate a fully general network
attacker capable of:

- Breaking TLS itself (no TLS downgrade, certificate-forgery, or
  cryptanalytic attack is implemented or claimed to be defended
  against beyond what `security/tls.py`'s configuration already
  provides).
- Compromising an endpoint (a client machine with malware reading
  memory, or an unlocked/extracted `secure_key_store.py` file
  combined with the account password, is out of scope — see the
  README's own "Local Key Storage" stated threat model for that
  specific, narrower boundary).
- Stealing a client's private ML-DSA/Kyber/RSA key material through
  any channel this system doesn't already document (network capture,
  server compromise, or database compromise all still leave private
  keys unreadable, since they are never transmitted or stored
  server-side — but a stolen client device combined with a known
  key-store password is not defended against by this design).

The threat model here is specifically and only: **can a party that
controls message relay, but not any client's private signing key,
successfully impersonate a client or corrupt what a client trusts?**
The answer, per the implementation and its test suite, is no — and
this document, together with
[Attack → Rejection → Recovery](attack_rejection_recovery.md), is the
demonstration of exactly that claim, no broader one.

## Attacker capability summary

| Capability | Attacker has it? |
|---|---|
| Observe relayed packet metadata (sender, recipient, timestamps) | Yes |
| Modify/drop/reorder/replay relayed packets | Yes |
| Hold any client's ML-DSA/Kyber/RSA private key | No |
| Forge a valid ML-DSA signature for a client it doesn't control | No |
| Decrypt AES-GCM message/blob ciphertext | No (never holds the session key) |
| Break TLS itself | Out of scope |
| Compromise a client endpoint directly | Out of scope |

## Worked example: read receipts (L-2, re-examined Phase 19.19)

A concrete case study applying the threat model above to one specific
feature, rather than leaving it as an abstract claim — the mandate for
this phase explicitly asked whether read receipts should be
cryptographically signed (ML-DSA, like every message/key/identity
packet) or whether the existing, deliberately unsigned design is
actually sufficient. Re-derived from the real code (`server/
client_handler.py::handle_read_receipt()`), not assumed unchanged from
an earlier audit.

**What a malicious CLIENT can and cannot do**: `create_read_receipt_
packet()` (`utils/protocol.py`) carries no reader/recipient/user field
at all — the "who read this" fact is derived exclusively from `user.id`,
the identity `authenticate_connection()` already resolved from the
JWT for this socket, before `handle_read_receipt()` ever runs. There
is therefore no field in the packet a malicious client could forge to
mark a DIFFERENT user's messages read, or to falsely claim they read
something they didn't — `MessageRepository.mark_conversation_read()`
is scoped to exactly `user.id`, and a non-member of the conversation
is rejected outright (`get_member_user_ids()` check). A cryptographic
signature would authenticate a claim that literally is not made
anywhere in the wire format — there is nothing here for ML-DSA to add
over what JWT+TLS already guarantee for this specific packet.

**What it does NOT protect against**: the OTHER members' `read_
receipt_notification` (`reader=user.username`, populated server-side,
`handle_read_receipt()`) is trusted by receiving clients on the same
basis every other server-relayed administrative fact is trusted (a
user-list broadcast, a `group_member_left` notification, presence) —
a compromised or malicious SERVER could fabricate a false "X read
this" notification, or suppress a true one, without a receiving client
able to detect it independently. This is a real, honestly-stated gap,
not a hidden one.

**Why independent cryptographic signing is intentionally not added
for this**: the gap above is not unique to read receipts — it is the
SAME trust boundary this project already accepts for every relay-
authored notification, and closing it for read receipts alone would
not close it for the others, while adding a new signed-payload type,
a new domain-separation purpose, and a new verification path on every
client for a threat that is (a) low severity (a spoofed/suppressed
read receipt affects a UX status indicator, never message
confidentiality, integrity, or authenticity — no ciphertext, key
material, or origin-authentication is at stake) and (b) not the
worst thing available to a server already willing to lie to clients
(a Byzantine relay can simply not deliver messages at all, which no
per-packet signature scheme defends against — see "Honest scope
limitation" above). Signing would be complexity spent re-deriving a
guarantee (server honesty about relay-authored metadata) this
document already scopes as out of bounds everywhere else, not a
genuine new security property.

**Conclusion**: KEPT unsigned, deliberately, on re-examination — not
merely carried forward unchanged from an earlier audit. If a future
phase decides relay-authored metadata integrity matters enough to
close everywhere (read receipts, presence, membership-change
notifications alike), that is a threat-model *expansion* — a new
decision to make explicitly, not a gap specific to read receipts to
patch in isolation.
