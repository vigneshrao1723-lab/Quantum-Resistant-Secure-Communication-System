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

**Web client** — out of date in earlier versions of this document: the Website has an Inbox tab
(`web/client/main.js::renderInboxCard()`), can send a verification request (`requestVerification()`), and
approves or denies from the same cards. Its approve path (`respondToInbox()`) mirrors the Desktop's.

## 4b. What follows an approval (2026-10-22)

Approval used to stop at "bookkeeping", and two things were missing, which together made a person added to a
group before anyone had verified anyone unable to read it:

1. **The requester's half.** The Desktop already completed it (`ClientSession._complete_requester_side_verification()`);
   the Website did not. `WebClientSession._completeRequesterSideVerification()` now does the same, from the identity the
   Website has itself observed (never from the notification, which carries no key material), and then secures the direct
   connection (`secureDirectConnection()` → `establishSessionKey()`), reporting `establishing` / `ready` / `failed` as it
   happens. **Both clients refuse to do it for a KEY_CHANGED identity**, and both clients now refuse to *approve* a
   requester whose identity changed (the approve path would otherwise verify a never-compared key).
2. **A group key skipped because its recipient was not verified was forgotten.** `_distribute_group_key()` /
   `_distributeGroupKey()` skip such a member on purpose (a key is only ever wrapped for, and accepted from, a VERIFIED
   identity). The skip is now remembered (`_skipped_group_key_distributions` / `_skippedGroupKeys`) and retried when that
   member is verified (`_after_peer_verified()` / `_afterPeerVerified()`, called only from the explicit, fingerprint-checked
   confirm methods) or, if they were already verified, when their identity is first seen.
3. **The other order.** A member who verifies the key holder *after* the key was sent (and rejected as coming from an
   unverified sender) now asks again with a new, thin packet: `group_key_request` → `handle_group_key_request()`. It checks
   the requester is an ACTIVE member, then reuses the existing `group_key_rotation_required` instruction for the current
   epoch with the requester as the only recipient. It asks the group's **admin** (who created the key); if the admin is
   offline and the requester is not the admin, nothing is sent, because any other member might not hold the key and the
   rotation instruction makes a member without the epoch create a new one. No key passes through the server.

Policy (changed again 2026-10-22, see §4c): nobody becomes a member of a group by being added. Each person is INVITED and
joins only by approving the invitation in their own Inbox; a non-admin's request needs the admin's approval and then the
person's.

On the Desktop the direct session key is created at the first message (existing design), so there is no "Establish key"
step to automate there; on the Website it is established automatically after an approved request and is otherwise still
the explicit **Establish key** button.

## 4c. Joining a group by invitation (2026-10-22)

Requested by the owner: when an admin creates a group or adds people, each person must get a notice in their Inbox saying who
wants to add them to which group, and **only the people who approve are added**; after that they chat normally and the key
establishment and secure connection happen by themselves.

| Step | What happens | Where |
|---|---|---|
| Create / add | The Desktop and Website create the group with `consent_invitations` set: the group exists with only its creator, and the server records one `group_invitation` per person (recipient = the invitee, requester = the inviter, plus the group) and pushes it to those online. Unknown people and people blocked either way are skipped silently; a repeat is the same single pending item | `handle_group_create()`, `handle_group_add_members()`, `_invite_candidates()` |
| Non-admin asks | Their request goes to the admin as before; when the admin approves with `consent_invitations`, the candidate is **invited** instead of added | `handle_inbox_response()` |
| Invitee approves | Only the recipient can decide (anyone else is rejected exactly like a bogus id). The invitation must still be valid: not older than 14 days, and the inviter still an active member; otherwise it becomes `expired` and nobody is added. A block in either direction is re-checked at approval. A valid approval runs `_perform_group_add_members()` as the inviter, so the group's "added" event names the real actor | `handle_inbox_response()` |
| Trust | The invitee's client verifies the inviter from the identity **it has itself observed** before it sends the approval (and refuses for a changed key, or an inviter it has not observed). The inviter's client verifies the invitee the same way when the approval arrives. This is the same rule a verification request already uses | `respond_to_inbox()`, `_complete_requester_side_verification()` and the Website's equivalents |
| Key | The new epoch's key is distributed by the group's **admin** (the server now asks the admin first), who now trusts the new member and is trusted by them; keys the admin held back are sent as soon as the verification completes (§4b). No one presses "Establish key" | `_dispatch_pending_rotation_if_needed()`, `_after_peer_verified()` |
| Decline / ignore | A denial adds nobody, verifies nobody and sends no key; the inviter is told. An unanswered invitation stays pending (and expires after 14 days) | |

Members need not verify one another: messages are authenticated by each sender's observed signing identity, and the key comes
from the admin, whom each member verified at approval. Group info shows, on both clients, who is still deciding.

Older clients (Android, and any client that does not send `consent_invitations`) keep the original immediate add. An Android
person who is *invited* sees the item in their Inbox as a group request and can approve it, but Android does not verify the
inviter on approval, so they would need to verify by hand before the key reaches them. Android was not changed or validated.

## 5. What this workflow is not

It does not perform cryptography itself (verification is always a
separate, local, fingerprint-based client action; group-key
distribution is always the same path a direct admin add already
uses) and it does not gate ordinary messaging in any way — a group
member added via this path is a completely normal member afterward,
indistinguishable from one an admin added directly.
