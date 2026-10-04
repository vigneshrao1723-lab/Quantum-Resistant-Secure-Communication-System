# Desktop GUI Architecture

Written Phase 19.19, closing the documentation gap Limitation L-8
named ("C. Desktop GUI architecture — Missing"). Describes `gui/` as
it actually exists — every claim below is a file:class citation, not a
description of intent.

## 1. Purpose

`gui/` is the PySide6 (Qt6) presentation layer for the Desktop client.
It owns no cryptography, no protocol framing, and no persistence
logic of its own — every dialog and window is a thin, presentational
wrapper around `client/session.py::ClientSession`, which does the real
work (connecting, encrypting, signing, sending). A dialog's job is
almost always: call a `ClientSession` method, and render the
`{success, error}`/return value it gets back.

## 2. Component map

| File | Owns |
|---|---|
| `gui/main_window.py` | `MainWindow(QMainWindow)` — the single top-level window for the app's whole lifetime. Owns the one `ClientSession` instance, swaps its `centralWidget` between `LoginWindow` and `ChatWindow`. |
| `gui/login_window.py` | `LoginWindow` — phone number + password (login) or full registration form, emits `login_requested`/`register_requested` signals `MainWindow` connects to. |
| `gui/chat_window.py` | `ChatWindow` — by far the largest file; the whole authenticated-session UI: sidebar (`ConversationListWidget`), message panel (`MessageWidget`), composer (`InputBar`), and every header button that opens one of the dialogs below. |
| `gui/conversation_list_widget.py` | The sidebar's own list rendering (direct + group rows, unread badges, online dots). |
| `gui/message_widget.py` | The open conversation's scrollable message/bubble list. |
| `gui/input_bar.py` | The composer: text entry, send button, attach-file button. |
| `gui/online_users_widget.py` | The "who's online" panel `ChatWindow` embeds. |
| `gui/status_bar.py` | Connection-state indicator at the window's edge. |
| `gui/styles.py` | The single shared QSS stylesheet + color/token constants (`COLOR_*`) every other file in this package imports from — no per-dialog ad-hoc styling, so a new dialog inherits the existing look for free by using plain `QPushButton`/`QLabel`/etc. |
| `gui/find_user_dialog.py` | Phone-number user lookup, to start a new direct conversation. |
| `gui/create_group_dialog.py` / `gui/add_members_dialog.py` | Group creation / adding members to an existing group. |
| `gui/group_info_dialog.py` | Phase 19.18 — member list + admin-only Remove, for a group. |
| `gui/inbox_dialog.py` | Verification-request / group-add-request approve-or-deny queue. |
| `gui/verify_identity_dialog.py` | Fingerprint comparison + explicit VERIFIED confirmation for a peer. |
| `gui/account_settings_dialog.py` | Phase 19.18 — Change Username / Change Password. |
| `gui/profile_picture_dialog.py` | Phase 19.17C — own picture view/upload; Phase 19.19 — read-only peer-picture viewing (same class, `target_username=`). |
| `gui/device_management_dialog.py` | Phase 19.19 — device list, lazy self-enrollment, Authorize/Revoke. |

## 3. Data flow

```
User action (click/type)
    -> Qt signal/slot (a QPushButton.clicked, a QLineEdit.returnPressed)
    -> a plain Python method on the dialog/window (never a Qt override
       doing real work directly)
    -> ClientSession method call (may block briefly: send_request()
       waits for a correlated server response on the receiver thread)
    -> {success, error} dict or a return value
    -> dialog updates its own QLabel/QListWidget from that result
```

Nothing in `gui/` talks to the network or the database directly.
Every real side effect — sending a packet, persisting a key, decrypting
a message — happens inside `client/session.py`, `client/
conversation_store.py`, or `storage/secure_key_store.py`. This is what
lets the same session object be driven identically by a real test (as
this project's own `tests/test_device_management.py`,
`tests/test_desktop_settings.py`, etc. do — constructing a dialog
directly, never simulating clicks through a headless display) and by a
real user's mouse.

## 4. State ownership

- **`ClientSession`** (one instance, owned by `MainWindow`, handed to
  every dialog its constructor is given): the account's identity,
  connection, keys, and every server-facing method.
- **`ConversationStore`** (`session.conversation_store`, one instance
  per session): the sidebar's read model — `ConversationSummary`
  objects, updated incrementally by `ClientSession`'s own packet
  handlers, emits `conversations_changed` (a Qt signal) whenever it
  changes. `ChatWindow` and `GroupInfoDialog` both subscribe to this
  signal rather than polling.
- **Dialogs own no state that outlives themselves.** A `QDialog`
  subclass here is always transient: constructed when opened,
  destroyed when closed, and re-reads whatever it needs (the device
  list, the group's members, the peer's picture) fresh from the
  session on open — never a cache a later reopen might serve stale.

## 5. Security boundary

The GUI enforces **nothing**. Every button that looks admin-gated
(Group Info's Remove, Device Management's Authorize/Revoke) hides
itself for a non-privileged viewer purely as a convenience — the
actual authorization decision is always re-derived server-side (see
`server/device_handler.py`, `server/client_handler.py::
handle_group_remove_member()`), exactly as `docs/architecture/
multi_device_identity.md`'s own "Defense in depth" section already
establishes for the account/device model generally. A modified or
compromised GUI could show every button to every user and it would
change nothing about who can actually authorize or remove anyone.

Peer verification (`VerifyIdentityDialog`) is the one place a human
decision made in the GUI has real cryptographic consequence — clicking
"Confirm" is what calls `ClientSession.confirm_peer_verification()`,
promoting a peer to `PEER_STATE_VERIFIED`. Every other dialog's
"confirm"/"submit" button is a convenience over an already-enforced
server decision, not a security decision of its own.

## 6. Persistence

`gui/` persists nothing directly. Whatever a dialog appears to
"remember" (the device list, group membership, peer verification
state) is actually `ClientSession`'s or `SecureKeyStore`'s state,
reloaded fresh on each dialog open — see `docs/architecture/
key_management_lifecycle.md` for what `SecureKeyStore` itself persists
and how.

## 7. Failure / rejection behavior

Every dialog follows the same pattern, established first by
`AccountSettingsDialog` (Phase 19.18) and reused unmodified by every
dialog since: wrap the `ClientSession` call in `try/except Exception`,
show `result.get("error")` (or the exception's `str()`) in a status
`QLabel`, never crash the dialog, never leave the window in an
ambiguous "did it work?" state. `ProfilePictureDialog` viewing a peer's
picture goes one step further (Phase 19.19): it never surfaces the raw
exception text to a viewer looking at someone ELSE's picture, only a
generic "Could not load this profile picture." — consistent with
`fetch_profile_picture()`'s own "not found and no picture set are
indistinguishable" design (`client/session.py`).

## 8. Relationship to Web and Android

Desktop, Web (`web/client/`), and Android (`mobile/`) are three
independent presentation layers over the same protocol and, for
Desktop and Android, literally the same `crypto/`/`client/`-adjacent
Python modules (Android's `mobile/session.py` mirrors `client/
session.py` method-for-method; Web ports the same logic to
JavaScript — see `docs/architecture/web_interoperability.md`). A
feature landing in `gui/` does not imply it exists elsewhere, and vice
versa — Phase 19.18/19.19's own closure work (Desktop Settings,
Device Management, Group Info, peer-picture viewing) is precisely the
history of Desktop catching up to functionality the backend/protocol,
and often Android, already had.

## 9. Testing

Every dialog above has at least one real, non-mocked test that
constructs it directly against a real `ClientSession` and a real
in-process TLS test server (never `QTest.mouseClick()` against a
rendered, visible window) — see `tests/test_device_management.py`,
`tests/test_desktop_settings.py`, `tests/test_peer_profile_picture_
viewing.py`, and the pre-existing `test_*_gui.py`/`test_*_dialog*.py`
files this project's own `scripts/run_regression_batches.py`
`desktop_gui` batch groups together. `QT_QPA_PLATFORM=offscreen` (set
at the top of every such test file) lets these run on a CI/headless
machine with no real display attached — the widgets are still fully
real, constructed, and laid out; only the final pixel presentation is
skipped.
