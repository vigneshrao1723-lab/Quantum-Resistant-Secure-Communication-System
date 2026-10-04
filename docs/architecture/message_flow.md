# Secure Message Flow

How one chat message actually travels from Alice's GUI to Bob's GUI,
naming the real function/class at each hop. See
[System Architecture](system_architecture.md) for the layered
component view this flow moves through, and
[Security Architecture](security/security_architecture.md) for why
each cryptographic step exists.

## The chain

```
 Sender GUI (gui/chat_window.py — user types a message)
        │
        ▼
 ClientSession.send_chat_message()           client/session.py
        │  resolves key_conversation_id, current epoch
        ▼
 crypto/message_protocol.py::sign_message_payload()
        │  ML-DSA signature over canonical_message_payload(
        │  sender, receiver, conversation_id, payload_type,
        │  ciphertext, content_metadata, epoch)
        ▼
 crypto/payload_cipher.py / crypto/aes.py    AES-256-GCM encryption
        │  using the already-established session/group key
        │  for (key_conversation_id, epoch)
        ▼
 utils/protocol.py::create_payload_packet()
        │  { type: "chat", sender, receiver, conversation_id,
        │    message (ciphertext), payload_type, content_metadata,
        │    timestamp, epoch, message_signature }
        ▼
 TLS transport (security/tls.py)             see tls_transport.md
        │
        ▼
 Server relay (server/client_handler.py)
        │  authenticates the connection, resolves routing
        │  (direct_conversation_id, membership), relays the
        │  packet's opaque fields unchanged — never decrypts
        │  `message`, never re-signs, never inspects `message_
        │  signature`'s validity
        ▼
 TLS transport
        │
        ▼
 Receiving ClientSession.handle_chat()        client/session.py
        │
        ▼
 STEP 1 — verify FIRST, before anything else:
 _verify_chat_message_signature(packet)
        │  ML-DSA-verifies message_signature against the
        │  trusted signing key resolved from THIS receiver's own
        │  peer-identity state (never from the packet) — happens
        │  before any conversation-store lookup, session-key
        │  lookup, or decryption. A failure returns silently here;
        │  nothing past this point is ever reached.
        ▼
 STEP 2 — resolve session key for (key_conversation_id, epoch)
        │  from crypto/key_manager.py — the exact epoch the
        │  packet declares, never "whatever key is current"
        ▼
 STEP 3 — AES-256-GCM decrypt (crypto/aes.py)
        │  GCM's own authentication tag independently guards
        │  against ciphertext tampering, on top of the ML-DSA
        │  signature already checked in Step 1
        ▼
 Receiver GUI (gui/chat_window.py — bubble rendered)
```

## What the server relay does and does not do

The server (`server/client_handler.py`) resolves *routing* metadata
server-side and hardens it before relay — e.g. `direct_conversation_id`
is always the server's own resolution from the authenticated sender
and matched recipient, never trusted from the client (D3.1/D3.2
hardening, unchanged by this phase). What it never does: decrypt
`message`, evaluate `message_signature`, or make any accept/reject
decision based on cryptographic content — that entire judgment happens
only inside the receiving `ClientSession`. This is the same "relay,
not authority" principle documented in
[System Architecture](system_architecture.md#the-one-architectural-fact-that-matters-most).

## Why signature verification happens before decryption

Verifying `message_signature` first, from the packet's own raw fields,
means a message whose claimed origin cannot be authenticated is never
even decrypted — no session-key lookup, no AES-GCM call, no chance for
a malformed or malicious ciphertext to reach the decryption routine at
all. This mirrors the same ordering principle used for key
establishment (see
[Key Establishment Flow](security/key_establishment_flow.md)'s
"mandatory order"), applied here to ordinary messages instead of
key-establishment packets.

## Message authentication is intentionally less strict than key establishment

A signed message from a sender who is merely key-established (has
exchanged Kyber/RSA material) but not yet human-`VERIFIED` is still
accepted — the ML-DSA signature proves possession of the claimed
signing key, which is sufficient for message-level authenticity. Key
establishment itself requires the stronger `VERIFIED` state (see
[Security Architecture](security/security_architecture.md#trust-state-machine)),
because it seeds trust for an entire conversation's future traffic,
not one already-displayed message. This asymmetry is deliberate, not
an oversight — see the README's own "Peer identity verification"
section for the same statement in narrative form.
