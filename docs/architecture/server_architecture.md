# Server Architecture

Written Phase 19.18, closing the documentation gap Limitation L-8
named ("B. Server architecture — Thin"; the audit's own recommendation
was "viva-readiness on server internals specifically"). Describes
`server/` as it actually exists — every claim below is a file:function
citation, not a description of intent.

## 1. What the server is

A single-process, multi-threaded TCP server (`server/server.py`), one
thread per connected TLS socket, dispatching JSON packets by `type`
through one large `while True` receive loop per connection
(`server/client_handler.py::handle_client()`). No async framework, no
worker pool — deliberately simple, matching the project's own
"server never holds key material" design: there is nothing on this
side computationally expensive enough to need one.

The server is a **relay and an authorization gate, never a crypto
party**. It never holds a private key, a group key, or plaintext
message content for any client-to-client payload (message/attachment
ciphertext is opaque to it; it only ever verifies ML-DSA *signatures*
using public keys, e.g. `server/device_handler.py` importing
`crypto.ml_dsa` to check device self-signatures — confirmed in the
Phase 19.17 audit as the one place `server/` touches crypto code at
all, and only to verify, never to produce).

## 2. Module map

| Module | Owns |
|---|---|
| `server/server.py` | Socket accept loop, TLS wrapping, spawns one handler thread per connection |
| `server/client_handler.py` | The packet-type dispatch table and every handler function — by far the largest module; direct chat, group chat, conversation resolution, epoch reservation, inbox, change-username/password, profile picture |
| `server/device_handler.py` | Device enrollment/authorization/revocation/session-bind, `is_device_bound_and_authorized()` |
| `server/broadcaster.py` | `distribute_public_keys()` (new-client-joins catch-up sync), `broadcast_user_list()` |
| `server/client_state.py` (referenced as `state` throughout) | The live, in-memory table of currently-connected sockets — `state.clients`, `state.get_client()` — never persisted, rebuilt from nothing on every server restart |

## 3. Connection lifecycle

1. TLS handshake (server-side context built once, shared across
   connections — see `security/tls.py`).
2. `auth` packet carrying a JWT access token → `create_auth_result_packet`.
   Server-side identity for the rest of this connection is fixed here,
   from the validated token, never re-derived from anything the client
   sends later (see `packet["sender"] = username` overwrite pattern
   throughout `client_handler.py` — the authenticated identity, never
   a packet field, is what every handler trusts).
3. `join`/user-list broadcast to every other connected client.
4. The dispatch loop: one `receive_message(client_socket,
   allow_idle=True)` per iteration, `parse_packet()`, then a long
   `if/elif` chain on `packet["type"]` routing to the specific handler.
5. Disconnect: socket close detected by a failed/empty read, state
   removed from `state.clients`, a fresh user-list broadcast.

## 4. Authorization model — what's checked, and where

**Conversation membership** (who may send/receive a given
`conversation_id`): `ConversationRepository.get_member_user_ids()`,
re-queried from the database on every group operation — never cached
across calls, never trusted from the packet. `handle_group_chat_
delivery()` (line 402) checks the *sender* is a current member before
anything else runs; `_perform_group_add_members()`/
`handle_group_remove_member()` similarly re-derive the admin from the
database, never from whether the requesting client's own UI happened
to show an admin-only button.

**Device authorization** (Phase 16 series): `is_device_bound_and_
authorized()` (`server/device_handler.py:49`) — a live DB re-query
returning a tristate (`True` authorized / `False` revoked / `None`
never opted into per-device identity at all, deliberately not a
rejection — see that function's own docstring). Originally checked
only at the group-key-distribution and device-key-sync relay points;
Phase 19.18 (Limitation L-1) extended the identical check to the
ordinary chat-relay path too, both sender- and per-recipient-socket
side, for both direct and group chat (`client_handler.py`, the three
new call sites immediately after the packet's `sender` field is
overwritten with the authenticated identity, and inside each fan-out
loop).

**Epoch authority**: an epoch is reserved server-side
(`ConversationRepository.reserve_next_epoch()`) before any key
rotation is allowed to proceed — the server is authoritative for
*which epoch number is next*, purely as a monotonic counter/ordering
mechanism; it never sees the key material for that epoch. This
prevents two clients racing to create epoch N twice for the same
conversation, without the server needing to understand what an epoch
*is* cryptographically.

**Package/domain separation**: `crypto/`, `client/`, `mobile/`,
`web/client/`, `gui/`, `server/`, `database/`, `domain/`, `utils/` are
each a distinct top-level package with a one-directional dependency
shape — `server/` imports `database/`, `domain/`, `utils/`, and
(verify-only) `crypto/`, but nothing in `crypto/`, `database/`, or
`domain/` imports `server/`; `client/`/`mobile/`/`web/client/` each
depend on `crypto/`/`utils/`/`domain/` but never on each other. This
is what makes "the same protocol, three independent client
implementations" actually true rather than aspirational — there is no
shared client-side module any two of Desktop/Mobile/Web secretly both
import that could let one client's bug silently become another's.

## 5. Concurrency / race guarantees

- **One thread per connection**, so two packets from the *same*
  client are always processed in the order they arrive on that
  socket — no explicit locking needed for single-connection ordering.
- **Two different clients racing on the same resource** (e.g. two
  members both trying to add the same third member to a group at
  once): serialized at the database layer via the repository methods'
  own transactional writes (`ConversationRepository`,
  `InboxRepository`) — `InboxRepository.create_group_add_request()`'s
  own duplicate-protection (returns the existing pending row instead
  of inserting a second one) is the concrete example the Inbox
  workflow doc already covers.
- **`state.clients`** (the live in-memory connection table) is a plain
  dict mutated from multiple handler threads; existing code always
  snapshots via `list(state.clients.items())` before iterating a
  fan-out loop specifically so a socket disconnecting mid-broadcast
  (mutating the dict from a different thread) can't raise a
  "dictionary changed size during iteration" error — visible in every
  fan-out loop this document's own Section 4 cites.

## 6. What the server deliberately does not do

No message content inspection, no group-key computation, no identity
verification decision (that's always local-only, client-side, per
`docs/architecture/security/security_architecture.md`), no automatic
trust of any kind — "same account, different device" is authorized
exactly the same way "different account" is: explicitly, by a human,
never because a device happens to share a username with an
already-trusted one.
