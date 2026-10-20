# Feature Parity Matrix — Android / Desktop / Web

Audit date: 2026-10-19. Android is the reference. For every row the user path
was traced through the UI, the client session, the wire protocol and the server
handler (not just "a method exists"); the Evidence column names the automated
tests that exercise it. Statuses: **PASS** (implemented and covered by an
automated test on that platform), **PARTIAL**, **MISSING**, **BLOCKED**
(depends on something this environment cannot provide), **N/A** (not
applicable to that platform). "Manual" means a person using the real UI; no
row below claims manual or physical-device validation that did not happen.

## Result of the audit

Before this pass Web was missing six capabilities Android has (bio, peer
profile, leave group, add members to an existing group, `group_members_added`
handling, and the group key-rotation initiator) and had no automated test of
registration/login; the audit found no capability missing from Desktop. The
six Web gaps are now implemented with the same protocol packets and server
handlers the other clients use, and the registration/login flow is tested.
Several rows remain PARTIAL, MISSING or BLOCKED (group pictures exist on no platform; Android lacks Leave group and is
unvalidated on hardware) — see "Remaining gaps".

## Accounts and identity

| Feature | Android | Desktop | Web | Evidence (automated) | Notes |
|---|---|---|---|---|---|
| Registration | PASS | PASS | PASS | `test_registration_integration.py`, `test_login_logout_integration.py`, `test_mobile_client_session.py`, **`test_web_registration_and_login_ui.py` (new, 6)** | Web covers valid, mismatched password, weak password, duplicate username, form toggle, unreachable gateway |
| Login / logout | PASS | PASS | PASS | `test_login_logout_integration.py`, `test_web_browser_e2e.py`, `test_web_registration_and_login_ui.py` | |
| Session persistence / reconnect | PASS | PASS | PASS | `test_web_persistence_reconnect.py`, `test_group_history_reconnect_recovery.py`, `test_offline_*` | |
| Change username / password | PASS | PASS | PASS | `test_desktop_settings.py`, `test_mobile_settings.py`, `test_web_settings_and_inbox.py` | |
| Profile picture (set, view, crop) | PASS | PASS | PASS | `test_mobile_settings.py` (Android); **`test_desktop_profile_picture_dialog.py` (new, 6: real crop canvas → square PNG → server → another user fetches it; cancel picker/crop, unreadable file and server refusal change nothing)**; **`test_web_messenger_layout_and_parity.py` (new: Web upload visible to Desktop; over-limit refused)** | Not E2E-encrypted by design (documented). Desktop test stubs only the OS file picker and the modal `exec()` |
| **Bio — edit own, view peer's** | PASS | PASS | **PASS (new)** | `test_desktop_settings.py`, `test_mobile_settings.py`, **`test_web_messenger_layout_and_parity.py`** (edit, server limit, peer profile) | Web: Settings → Bio; chat header → Profile |
| Peer profile view | PASS | PASS | **PASS (new)** | as above | |
| Find user by phone number | PASS | PASS | PASS | `test_phone_number_discovery.py`, `test_find_user_dialog_gui.py` | |
| Peer identity verification (safety number) | PASS | PASS | PASS | `test_first_contact_verification.py`, `test_peer_key_verification.py`, `test_mobile_peer_verification_persistence.py`, `test_web_browser_e2e.py` | fail-closed on key change on all three |
| Inbox + verification requests | PASS | PASS | PASS | `test_group_admin_and_inbox.py`, `test_web_settings_and_inbox.py` | Desktop shows a pending-request badge on the rail (new) |
| Device list / enroll / authorize / revoke | PASS | PASS | PASS | `test_device_identity.py`, `test_device_management.py`, `test_web_feature_completion_e2e.py` | revoked devices fail closed (`test_device_security` batch) |
| Cross-device key sync | PASS | PASS | PASS | `test_device_key_sync*.py`, `test_mobile_device_key_sync.py` | |
| Block / unblock / blocked list | PASS | PASS | PASS | `test_phase19_24_block_user_security.py`, `..._desktop_block.py`, `..._mobile_block.py`, `test_web_phase19_24_lifecycle_ui.py` | blocking never reveals itself to the blocked sender (asserted) |
| Presence / last seen | PASS | PASS | PASS | `test_phase19_24_presence_last_seen.py`, `..._mobile_presence_last_seen.py`, web lifecycle suite | |

## Direct messaging

| Feature | Android | Desktop | Web | Evidence | Notes |
|---|---|---|---|---|---|
| Send / receive / history | PASS | PASS | PASS | `test_private_messaging_integration.py`, `test_message_persistence_integration.py`, `test_web_browser_e2e.py` | |
| Multi-line messages | PASS | **PASS (new)** | **PASS (new)** | `test_desktop_chat_layout.py`, `test_web_messenger_layout_and_parity.py` | Enter sends, Shift+Enter inserts a line break; composers grow then scroll |
| Reply / edit / delete for me / delete for everyone | PASS | PASS | PASS | `test_phase19_24_message_lifecycle_security.py`, `..._desktop_ui_wiring.py`, `..._mobile_lifecycle_wiring.py`, `test_web_phase19_24_lifecycle_ui.py` | server-mediated and signed, not cosmetic |
| Forward (text/image/file/voice/video) | PASS | PASS | PASS | `test_phase19_24_mobile_forward_media.py`, desktop forward tests, `test_web_phase19_24_lifecycle_ui.py` | re-encrypted for the target |
| Copy | PASS | PASS | PASS | lifecycle suites | client-side only |
| Reactions | PASS | PASS | PASS | lifecycle suites | |
| Delivery / read receipts | PASS | PASS | PASS | `test_read_receipts_*`, `test_message_status_indicators.py` | |
| Typing indicator | PASS | PASS | PASS | `test_phase19_24_typing_indicator.py`, `..._mobile_typing_indicator.py`, web lifecycle suite | |
| In-conversation search | PASS | PASS | PASS | `..._desktop_message_search.py`, `..._mobile_message_search.py`, web lifecycle suite | |
| **Conversation list search / filter** | PARTIAL | **PASS (new)** | **PASS (new)** | `test_desktop_chat_layout.py`, `test_web_messenger_layout_and_parity.py` | Android has no list filter. Desktop: search box + All/Unread/Direct/Groups. Web: name search (shared with the "start a chat" box, applied conservatively) + Unread toggle |
| Pin / unpin | PASS | PASS | PASS | `..._desktop_pinned_messages.py`, `..._mobile_pinned_messages.py`, web lifecycle suite | server-synchronised |
| Drafts | PASS | PASS | PASS | `..._mobile_drafts.py`, `..._desktop_ui_wiring.py`, web lifecycle suite | |
| Mute / archive | PASS | PASS | PASS | `..._desktop_mute.py`, `..._desktop_archive.py`, mobile equivalents, web lifecycle suite | local, encrypted store |
| Retry failed send | PASS | PASS | PASS | `..._mobile_retry.py`, `test_message_status_indicators.py`, web lifecycle suite | idempotent via `client_message_id` |
| Wallpaper | PASS | PASS | PASS | `..._wallpaper.py` (desktop/mobile), web lifecycle suite | presets only |
| Duplicate-message prevention, offline recovery | PASS | PASS | PASS | `test_offline_*`, `test_message_routing_security.py` | |

## Groups

| Feature | Android | Desktop | Web | Evidence | Notes |
|---|---|---|---|---|---|
| Create group | PASS | PASS | PASS | `test_group_creation_multi_member.py`, `test_create_group_dialog_gui.py`, `test_web_feature_completion_e2e.py` | |
| Group messaging (history, replies, edits, deletes, reactions, forwards) | PASS | PASS | PASS | `test_group_messaging_integration.py`, lifecycle suites | |
| Member list / group info | PASS | PASS | PASS | `test_group_admin_and_inbox.py`, web e2e | |
| Remove member (admin) | PASS | PASS | PASS | `test_group_membership_integration.py` | server re-derives the admin on every call |
| **Add members to an existing group** (admin adds directly; others via admin approval) | PASS | PASS | **PASS (new)** | `test_group_add_members_integration.py`, `test_group_admin_and_inbox.py`, **web: non-admin request → admin Inbox → approval adds the member** | Web: Group info → Add members |
| **Leave group** | **MISSING** | PASS | **PASS (new)** | `test_group_membership_integration.py`, **web: leave + confirm + server removes; cancel keeps membership** | Android has no Leave action (not changed in this pass) |
| `group_members_added` live update | PASS | PASS | **PASS (new)** | web approval test above | |
| Group key distribution / re-keying on membership change | PASS | PASS | **PASS (new — rotation initiator)** | `test_group_key_*`, **web: rotated key installed by the Desktop member; malformed/foreign requests ignored** | Web previously never answered a `group_key_rotation_required` order, which could leave a group waiting on an epoch |
| Group mute / archive / media / search / pins | PASS | PASS | PASS | as direct | |
| Group picture / avatar | MISSING | MISSING | MISSING | — | Not started, deliberately. Needs (1) a migration adding a picture reference to `conversations`, (2) new set/get packets in `utils/protocol.py`, (3) admin-only authorization + size/type limits in `server/client_handler.py`, (4) UI on all three clients, (5) tests. That is a schema and wire-protocol change, not a UI change; a partial version would give groups a picture on one platform only |

## Attachments and media

| Feature | Android | Desktop | Web | Evidence | Notes |
|---|---|---|---|---|---|
| Image / file send, view, save | PASS | PASS | PASS | `test_file_image_transfer_integration.py`, `test_image_viewing.py`, `test_web_feature_completion_e2e.py` | size limits: `test_attachment_hardening.py` |
| Media gallery | PASS | PASS | PASS | `..._desktop_media_gallery.py`, `..._mobile_media_gallery.py`, web lifecycle suite | |
| Voice message record + playback | BLOCKED (recording unverified on hardware) | PASS | PASS | `..._desktop_voice_video.py`, `..._mobile_voice_video.py`, web lifecycle suite | Android code-complete; physical validation outstanding |
| Video message record + playback | BLOCKED (recording/playback unverified on hardware) | PASS | PASS | same | |
| Attachment menu | PASS | PASS | PASS | `test_attachment_gui.py`, per-platform menu tests | |
| Voice / video **calls** | N/A | N/A | N/A | — | No calling feature exists on any platform; no UI control for it is shown |

## Interface

| Feature | Android | Desktop | Web | Notes |
|---|---|---|---|---|
| Navigation | bottom nav | **left rail (new)** | **left rail; bottom bar on phones (new)** | Desktop rail: Chats, Archived, Inbox (with badge), Devices, Settings. Web rail: Chats, Groups, Inbox, Settings, Log out |
| Light / dark theme | light | light | light + dark (+ system) | Desktop has no dark theme; unchanged |
| Responsive layout | phone | desktop window | desktop → tablet → phone (320–1280 px tested) | `test_web_messenger_layout_and_parity.py` |
| Safety-number banner on small screens | n/a | n/a | **compact for a verified peer, full when action is needed (new)** | the number, the three actions and a toggle remain reachable |
| Keyboard focus | n/a | focus styles on rail/header/composer | focus-visible throughout | |
| Contrast | n/a | n/a | placeholders, bubble timestamps and dark-mode accent text raised to ≥ 4.5:1 | |

## Remaining gaps (not hidden)

1. **Group picture / avatar — MISSING on all platforms.** Needs a new protocol
   message, a database column and a migration.
2. **Android "Leave group" — MISSING.** Desktop and Web have it; adding it to
   Android is source work that cannot be validated here (no device).
3. **Android voice/video recording and video playback — BLOCKED on hardware.**
   Implemented; not validated on a physical device.
4. **Web group key history.** The Web client keeps one key per conversation
   (the newest epoch); messages from earlier epochs are skipped as
   undecryptable, never guessed. Desktop and Android keep every epoch. This is
   a pre-existing design difference, not introduced here, and means Web
   cannot show pre-rotation group history after a rotation.
5. **Desktop has no dark theme.**

## Continuation checkpoint (2026-10-20)

Last good state: official suite 1919 passed / 0 failed / 0 skipped (12 batches);
see the 2026-10-20 addendum in `security/feature_security_matrix.md` for the
per-batch table and the interruptions. Nothing is staged or committed.

Next actions, in priority order:

1. **Android (needs a physical device):** install `qrscs_mobile-0.1.0-arm64-v8a-debug.apk`
   rebuilt on 2026-10-19 (see `mobile_client.md`), then validate voice/video
   recording and playback; add Leave group to the Android app.
2. **Web long-run timing sensitivity (unresolved):** if it must be closed,
   instrument the gateway↔server socket lifecycle inside one long run (log every
   connect/close with a timestamp and reason) instead of rerunning the suite.
3. **Group pictures:** design the migration + protocol first (see the row above).
4. Resume the regression with
   `python scripts/run_regression_batches.py --batch web_a` (then `web_b`) on the
   Python 3.12 virtualenv, with the machine held awake.
