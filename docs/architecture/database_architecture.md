# Database Architecture

Written Phase 19.19, closing the documentation gap Limitation L-8
named ("J. Database architecture — Thin"). Describes `database/` as
it actually exists — every table/column named below is a real
`Column(...)` in the current codebase, not an aspirational schema.

## 1. Purpose and the one property that shapes everything else

PostgreSQL, accessed through SQLAlchemy models (`database/models/`)
and a repository-per-table layer (`database/repositories/`) — never
raw SQL scattered through handler code. The property that shapes every
table below: **the database stores no plaintext message content and
no private key material, ever.** A message row's `ciphertext` column
is exactly what a client encrypted; the database has no way to know
what it says, and no code path anywhere decrypts it server-side (see
`docs/architecture/server_architecture.md` §1 and `docs/architecture/
security/security_architecture.md`).

## 2. Table map

| Table (model) | Purpose |
|---|---|
| `users` (`user.py`) | Account identity: username, email, phone_number (all unique-constrained), Argon2-hashed password. |
| `sessions` (`session.py`) | One row per login — JWT refresh-token hash, device_name/platform/app_version metadata, `is_active`/`revoked`/`expires_at`. Ephemeral, per-login — NOT a device's cryptographic identity (see `devices` below and `key_management_lifecycle.md` §7 for that distinction). |
| `devices` (`device.py`) | Phase 16 — one row per enrolled device: `device_id` (client-generated UUID), owning `user_id`, `kem_public_key`/`ml_dsa_public_key` (PUBLIC halves only — no private-key column exists anywhere in this table, by construction, not by convention), `fingerprint`, `state` (PENDING/AUTHORIZED/REVOKED), `authorized_by_device_id`. |
| `conversations` (`conversation.py`) | One row per direct OR group conversation — `type` (direct/group), `name` (group only), `current_key_epoch`/`confirmed_key_epoch` (the server's own epoch-ordering counters — see below). |
| `conversation_members` (`conversation_member.py`) | Membership: `conversation_id` + `user_id` + `role` (member/admin) + `joined_at`/`left_at` (a departed member's row is never deleted, only closed with `left_at` — see §5). |
| `messages` (`message.py`) | One row per sent message — `ciphertext` (opaque, or NULL for a FILE/IMAGE payload — see below), `blob_ref`, `payload_type`, `content_metadata` (JSONB, non-secret descriptors only), `message_signature` (the ML-DSA origin-authentication signature, opaque to the server), `timestamp` (client-supplied), `created_at` (server-assigned — see Phase 19.18's ordering fix below). |
| `message_recipients` (`message_recipient.py`) | Per-recipient delivery state (QUEUED/DELIVERED/READ) — kept in its own table, not a column on `messages`, specifically so one message can carry N independent delivery states (group messaging) without N copies of the content. |
| `inbox_notifications` (`inbox_notification.py`) | Verification requests and group-add approval requests — `type`, `status` (pending/approved/denied), `recipient_user_id`, `requester_user_id`, `candidate_user_id` (group-add only), `conversation_id` (group-add only). |

## 3. What the database is never asked to do

- **Never decrypts.** No stored procedure, trigger, or application
  code path calls any `crypto.*` decryption function against a
  `messages.ciphertext` value.
- **Never holds a private key.** `devices.kem_public_key`/`ml_dsa_
  public_key` are exactly that — public. The device's actual private
  keys live only in that device's own local `SecureKeyStore` file
  (`key_management_lifecycle.md` §7), never transmitted, never stored
  server-side in any table.
- **Never trusts a client-supplied identity for a write.** Every
  repository method that mutates state on someone's behalf takes the
  actor's identity as a plain argument (a `user.id` already resolved
  from the authenticated JWT by the calling handler) — no repository
  method reads `request.json["username"]` or equivalent; there is no
  such thing to read at this layer.

## 4. Authorization re-derivation, not caching

Every authorization-sensitive read is re-run against the live tables
on every relevant packet — never cached, never trusted from a prior
check:

- **Conversation membership**: `ConversationRepository.
  get_member_user_ids()`, queried fresh for every group operation
  (`server_architecture.md` §4).
- **Device authorization**: `DeviceRepository` rows read live by
  `server/device_handler.py::is_device_bound_and_authorized()` on
  every packet on a bound connection (Phase 19.18's L-1 fix extended
  this to ordinary chat relay, not just key-distribution).
- **Group admin**: `ConversationRepository.get_admin_user_id()`,
  re-derived server-side on every admin-gated action
  (`handle_group_remove_member()`) — never trusted from whether the
  requesting client's own UI happened to show an admin-only button
  (`desktop_gui_architecture.md` §5).

## 5. Departed members are closed, not deleted

`conversation_members.left_at` being set (rather than the row being
deleted) is what lets `messages` sent before someone left stay
attributable and readable in history for members who were present at
the time, while `get_member_user_ids()` (which filters
`left_at IS NULL`) correctly excludes them from anything happening
NOW — group re-add (`tests/test_group_re_add_membership.py`) relies on
this: a re-added member gets a fresh membership row (or the same row
reopened), never confused with their earlier departure.

## 6. Epoch authority vs. epoch content

`conversations.current_key_epoch`/`confirmed_key_epoch` are pure
integers the server increments via `ConversationRepository.reserve_
next_epoch()` — the server is authoritative for *which epoch number is
next* (preventing two clients racing to both claim epoch N), but has
no notion of what that epoch's actual AES-256-GCM key IS. That key
never reaches the database in any form. See `key_management_lifecycle.md`
§5 for the client-side epoch/rotation model this counter feeds.

## 7. A real bug this project's own history found here

Phase 19.18 traced a genuine message-reordering defect to this layer:
`MessageRepository.get_conversation()`/`get_group_conversation()`
originally ordered history strictly by `messages.timestamp` — a
**client-supplied** field (`server/client_handler.py::_parse_message_
timestamp()` parses it straight from the packet) — with no
tiebreaker. Two messages sent in close succession could round-trip
with an identical or out-of-order client timestamp, leaving tied rows
in an undefined database order. Fixed by adding `messages.created_at`
(always server-assigned at persist time, never client-suppliable) as
a secondary `ORDER BY` key in both methods, plus the identical fix to
`ConversationRepository`'s sidebar latest-message-preview window
function — both proven via 141 passing repository/integration tests
with zero regression, and the specific reordering symptom reproduced
and fixed before this phase's other work continued. This is the kind
of defect that is invisible at the model-definition level (both
columns look reasonable in isolation) and only surfaces by tracing
what a real client can supply versus what the server itself assigns —
worth recording here as the concrete reason this document insists on
citing which column is client- vs. server-controlled throughout.

## 8. Migrations

Alembic (`alembic/versions/`) — every schema change in this project's
history is a real, applied migration file, not a hand-edited
production database. Not otherwise expanded here; the migration
files themselves, and their own messages, are the authoritative record
of schema evolution.
