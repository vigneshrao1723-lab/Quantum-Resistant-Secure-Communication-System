# Inbox Approval Workflow

Phase 19.13 introduced the first persisted, cross-session "thing a
user must see and act on later" in this schema. Before it, peer
verification was always independent/local on each side, and group
membership changes were always immediate, self-service actions with
no approval step. `InboxNotification` (`database/models/
inbox_notification.py`) backs two workflows with one shape, both
gated through the same recipient-only approve/deny path.

See [Security Architecture](security/security_architecture.md) for
how peer verification itself works, and
[Multi-Device Identity](multi_device_identity.md) for device
authorization, which this workflow does not touch.

## 1. The two request types

| Field | `verification_request` | `group_add_request` |
|---|---|---|
| `requester_user_id` | person asking to be verified | non-admin member who wants to add someone |
| `recipient_user_id` | person being asked to verify them | the group's admin |
| `conversation_id` | `NULL` | the target group |
| `candidate_user_id` | `NULL` | the user proposed for membership |

`status` transitions exactly once, `pending → approved` or `pending →
denied` (`InboxRepository.resolve()`, `database/repositories/
inbox_repository.py`). `resolve()` only ever updates a still-pending
row and returns `None` otherwise — this is what makes a second
Approve/Deny on the same notification a safe no-op rather than a
repeat action, without any extra idempotency-key bookkeeping.

Duplicate-request protection lives in the repository's create
methods, not the server handler: `create_verification_request()`
returns the existing pending row for the same (requester, recipient)
pair instead of inserting a second one; `create_group_add_request()`
does the same keyed on (conversation, candidate) regardless of who
asked — there is never a need for two simultaneous pending requests
to add the same person to the same group.

## 2. Where a notification comes from

**Verification request** — `server/client_handler.py::
handle_verification_request()` (line 938) calls `InboxRepository.
create_verification_request()` and pushes it to the recipient if
they're currently connected (`_push_inbox_notification()`).

**Group-add request** — `server/client_handler.py::
handle_group_add_members()` (line 1698) first re-derives the caller's
admin status server-side via `ConversationRepository.
get_admin_user_id()` (never trusted from the packet). If the caller
*is* the admin, the add happens immediately through
`_perform_group_add_members()` (line 1633) — no inbox entry at all.
If the caller is **not** the admin, no membership change happens yet;
instead `create_group_add_request()` is called (line 1772) and the
admin receives a notification.

## 3. Resolving a notification

`server/client_handler.py::handle_inbox_response()` (line 1037) is
the single enforcement point for both types. The notification and
"whose decision this is" are always re-derived from the authenticated
socket plus the notification's own stored `recipient_user_id` — never
trusted from anything else in the packet. A caller who is *not* the
recipient gets exactly the same outcome as a bogus `notification_id`
(silently returns, no membership/verification hint leaked either
way). This means a `group_add_request` cannot be approved by anyone
but the actual admin, and a `verification_request` cannot be answered
by anyone but the person who was asked.

**What approval actually authorizes differs by type:**

- `group_add_request`, `approve=True` → runs
  `_perform_group_add_members()` (line 1134) — the *exact same*
  server-side path an admin's own direct "Add Members" already uses,
  not a reimplementation. This is genuine, server-enforced
  authorization: the candidate is only added to
  `conversation_members` and only receives group-key distribution
  after this call succeeds.
- `verification_request`, `approve=True` → **bookkeeping only**. The
  server performs no cryptographic verification here — see
  `handle_verification_request()`'s own docstring. The recipient's
  client is trusted to have already run
  `ClientSession.confirm_combined_peer_verification()` (desktop) /
  `MobileClientSession.confirm_peer_verified()`
  (`mobile/session.py:649`) locally, using a fingerprint it already
  observed, *before* sending `approve=True` — exactly the same local
  action the existing "Verify Identity" dialog performs; the inbox
  response only records the outcome and notifies the requester. A
  malicious client could send `approve=True` without genuinely
  comparing fingerprints, but this only affects that client's own
  local trust state and the requester's notification outcome — it
  grants no server-side privilege and cannot forge a third party's
  cryptographic trust in anyone else.

Either way, `_push_inbox_notification(..., is_response=True)` notifies
the original requester of the outcome if they're online; `get_for_
user()` (`inbox_repository.py`) also lets a client fetch its full
inbox — pending items to act on, and past requests it sent, so an
outcome that arrived while offline is visible on reconnect.

## 4. Client entry points

- Requesting: `mobile/session.py::request_verification()` (line 918)
  sends a `verification_request` packet; the group-add case is
  triggered from `_open_add_members_dialog()`
  (`mobile/app.py`) when the acting user isn't the group's admin.
- Responding: `mobile/session.py::respond_to_inbox()` (line 925) —
  for `verification_request`, this raises before sending anything if
  the local client has no observed fingerprint for that peer yet,
  preventing an "approve" the client can't actually back up.
- Desktop mirrors the same two calls on `ClientSession`.

**Not implemented on the web client** — `web/client/` has no `inbox`
references at all. A web-client user can still be the *target* of a
verification or group-add request (the request itself is server/
desktop/mobile-driven), but cannot see or act on their own inbox from
the browser. This asymmetry is a known limitation, not a bug — see
the project's Known Limitations section.

## 5. What this workflow is not

It does not perform cryptography itself (verification is always a
separate, local, fingerprint-based client action; group-key
distribution is always the same path a direct admin add already
uses) and it does not gate ordinary messaging in any way — a group
member added via this path is a completely normal member afterward,
indistinguishable from one an admin added directly.
