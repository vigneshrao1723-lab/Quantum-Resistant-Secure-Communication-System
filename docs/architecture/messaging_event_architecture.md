# Messaging Event Architecture (Phase 19.24)

Protocol/event taxonomy for the Message Lifecycle Events added in
Phase 19.24: Reply, Edit, Delete For Me, Delete For Everyone, Forward,
Copy, Reactions, Retry idempotency, and (added later in the same
phase) Pinned Messages. This document describes what was actually
implemented and shipped this phase — not an aspirational design for
features scoped out of it (see `message_lifecycle.md` for the
explicit scope boundary).

## Design principle: reuse, never duplicate

Every event below reuses the existing wire/crypto architecture exactly
as `utils/protocol.py`, `crypto/key_manager.py`, and `payload/
adapter.py` already established, rather than inventing a parallel
mechanism:

- Addressing is always by `message_id` (server resolves
  `message_id -> conversation_id -> membership` itself), the same
  pattern `create_blob_download_request_packet()` already used —
  never a client-claimed `conversation_id`/`receiver` pairing for an
  event about an *existing* message.
- Encryption is always the conversation's existing per-epoch AES-256-
  GCM key (`KeyManager.get_key(conversation_id, epoch)`), the same key
  every ordinary chat message already uses. No new key store, no new
  KEM/wrapping mechanism.
- Authorization is always re-derived server-side from the
  authenticated socket (`user.id`) and the stored `Message` row —
  never trusted from a client-supplied field. Mirrors
  `handle_read_receipt()`'s and `handle_group_remove_member()`'s
  existing pattern exactly (see `server/client_handler.py`, the
  Phase 19.24 handlers' own docstrings).

## Event taxonomy

| Packet type | Direction | Purpose |
|---|---|---|
| `chat` (extended) | C → S | Now optionally carries `reply_to_message_id` and `client_message_id` (both additive — see `create_payload_packet()`). |
| `message_edit` | C → S | Re-encrypt an existing message's content in place. |
| `message_edited` | S → C (all members) | The accepted result of an edit — new ciphertext, `editor`, `edited_at`, `edit_version`. |
| `message_delete_for_me` | C → S | Hide a message from the requester's own view/devices only. No broadcast. |
| `message_delete_for_everyone` | C → S | Request real, authorized global deletion. |
| `message_deleted` | S → C (all members) | The accepted result of a delete-for-everyone — no content, only `deleted_by`/`deleted_at`. |
| `reaction_add` | C → S | Set/replace the requester's reaction on a message. |
| `reaction_remove` | C → S | Remove the requester's reaction, if any. |
| `reaction_updated` | S → C (all members) | The accepted result of an add/remove — `actor`, `action`, ciphertext (add only). |
| `message_pin` | C → S | Pin a message for every conversation member. |
| `message_unpin` | C → S | Unpin a message. |
| `message_pinned` | S → C (all members) | The accepted result of a pin — `pinned_by`, `pinned_at`. |
| `message_unpinned` | S → C (all members) | The accepted result of an unpin — `unpinned_by`. |

Every request packet above carries **no actor/editor/deleted_by
field** — the server always derives the actor from `user.id`
(dispatch's own authenticated-socket lookup). Every notification
packet's actor field is the server's own answer, never echoed from a
client.

### Forward and Copy

Neither introduces a new packet type. **Forward** re-uses the normal
send pipeline (`send_chat_message`/`send_attachment`/`send_message`/
`send_group_message`) against the **target** conversation's own key —
it is a genuinely new, independently encrypted message, never a reuse
of the original ciphertext (which was encrypted for a different
key/recipient context and is meaningless outside it). A
`{"forwarded": true}` flag rides in the existing `content_metadata`
JSONB field, purely a client-side UI hint, never trusted for anything
security-relevant. **Copy** is 100% client-side (already-decrypted
plaintext already in memory/rendered on screen → OS clipboard); it
never touches the wire at all.

### Retry idempotency

Every live send now carries a client-generated `client_message_id`
(UUID4). `server/client_handler.py::persist_message()` uses
`MessageRepository.save_message_idempotent()`: a UNIQUE constraint on
`messages.client_message_id` means a second arrival of the same id
returns the already-persisted row instead of creating a duplicate. The
GUI layer (`gui/chat_window.py::send_message()`) generates the id
*before* the risky network call — not from the call's return value —
specifically so it survives to the exception handler and can be reused
verbatim by `_retry_failed_message()`.

## Reactions and the E2E boundary

A reaction (e.g. a single emoji) gets the **same E2E treatment as a
text message** — no "it's just metadata" exception. `payload/
reaction_adapter.py` (`PayloadType.REACTION`) AES-256-GCM-encrypts the
reaction string under the conversation's current epoch key, exactly
like `TextPayloadAdapter`. `database/models/message_reaction.py`
stores only `ciphertext`/`epoch` — the server never learns which
reaction was chosen, only who reacted to what message and when. One
row per `(message_id, user_id)` — adding a new reaction **replaces**
the previous one for that user (never stacks).

## Pinned Messages (added later in Phase 19.24)

Unlike Edit/Delete-for-everyone (sender-only authorization), pin/unpin
authorization is **"any currently active member of the message's
conversation"** — deliberately broader, mirroring ordinary messenger
convention (any participant can pin in a direct chat) rather than
restricting to the sender or a group-admin role the mandate's own
phrasing ("group admin behavior *if applicable*") did not require.
`database/models/message.py::pinned_at`/`pinned_by` are two plain,
nullable, **overwritten** columns on the existing `messages` row — not
a new table, not a new adapter, and (unlike Reactions) not encrypted:
pin state carries no content of its own to protect, so it gets exactly
the same trust treatment `deleted_at`/`deleted_by` already have —
`pinned_by` is always the server's own authenticated-socket answer
(`user.username`), never a client-supplied field, and it is **not**
independently ML-DSA-signed, for the same reason `deleted_by` isn't:
there is no ciphertext-bearing content here for a compromised relay to
forge, only server-derived attribution the client already trusts the
connection itself for. Recovered on every `message_history_request`
alongside edit/delete/reaction state, so a client that missed a live
`message_pinned`/`message_unpinned` (offline, or a newly-authorized
device with no prior live traffic at all) still ends up with the
current pinned set on its next history load.

## Multi-device and revocation

`server/client_handler.py::_broadcast_to_conversation_members()` is
the single fan-out helper every lifecycle-event handler above shares
(edit, delete, reaction add/remove, and pin/unpin). Unlike
`handle_read_receipt()`'s own broadcast (which deliberately excludes
the reader — there's no reason to tell yourself you read something),
lifecycle-event broadcasts **include the actor's own other
authorized devices** — an edit/delete/reaction/pin must reach every
one of the actor's other logged-in sessions, not just the other
participants. Every candidate socket is checked with the existing
`is_device_bound_and_authorized()` (the L-1 mechanism, unchanged) —
an already-connected but since-revoked device is silently skipped,
exactly like the ordinary chat-relay path already does. Preserved,
not re-implemented.

**Documented trust-model asymmetry (pre-existing, not introduced by
Phase 19.24's own additions):** the check above covers the
*receiving* side of every lifecycle-event broadcast. None of these
handlers (edit, delete, reaction add/remove, pin/unpin) re-check
`is_device_bound_and_authorized()` on the *sending* socket before
accepting the request — only the ordinary `chat`/attachment relay
path (the L-1 closure, `server/client_handler.py`'s own "Rejected
chat from ... sender's bound device is not AUTHORIZED" check) gates
the sender side. In practice this means a revoked-but-still-connected
device cannot send or receive ordinary protected message content
(chat/voice/video — the properties L-1 exists to protect), and cannot
*receive* a lifecycle-event notification either, but a request to
edit/delete/react-to/pin a message it can still name would still be
accepted and persisted server-side, purely on its still-valid account-
level JWT authentication. This is consistent across every lifecycle-
event handler (not something Pinned Messages introduced), and is
judged acceptable because none of these actions expose new
ciphertext, new key material, or new message content the way ordinary
chat delivery does — the properties L-1 was built to close. Voice/
Video Messages (below) needed no equivalent note: they are ordinary
attachments sent through the exact same `chat` relay path the L-1 fix
already covers, so they inherit that sender-side check for free (see
`tests/test_device_identity.py::test_revoked_device_cannot_send_a_
voice_message` for the proof).

The receiving-side half of this asymmetry — that a revoked device
correctly does NOT receive a live lifecycle-event broadcast even
though the broadcasting REQUEST itself was accepted from an unrelated,
still-authorized sender — is proven directly (not just inherited by
description) by `tests/test_device_identity.py::test_revoked_device_
does_not_receive_pin_notification`. It exercises Pin specifically, but
since Pin shares `_broadcast_to_conversation_members()` verbatim with
Edit/Delete/Reaction, it is a regression test for the shared helper
itself, not a Pin-only property.

## Offline / reconnect / history recovery

`handle_message_history_request()` was extended (additively — see
`create_message_history_result_packet()`'s per-entry shape) to return,
for every message: `reply_to_message_id`, `edited_at`, `edit_version`,
`deleted_at`, `deleted_by`, `client_message_id`, and a batched
`reactions: [{user, ciphertext, epoch}, ...]` list. A message hidden
via "delete for me" is filtered out of the result entirely, server-
side, before the payload is even built
(`MessageRepository.get_hidden_message_ids_for_user()`) — so it never
reaches any of that user's devices again, on any future reconnect.

A message deleted for everyone already has `ciphertext`/
`content_metadata`/`message_signature`/`blob_ref` NULL by the time
history reports it (the deletion is real, not a flag layered on top —
see `message_lifecycle.md`) — `deleted_at` is what tells a client to
render "Message deleted" instead of attempting to decrypt null
content.

## What is explicitly NOT implemented this phase

See `message_lifecycle.md`'s "Known limitations" section and the
40-item acceptance matrix (`docs/architecture/security/
feature_security_matrix.md`) for the authoritative, itemized list.
