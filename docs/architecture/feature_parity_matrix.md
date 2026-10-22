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
| **View own safety number** | MISSING (paused) | **PASS (new)** | **PASS (new)** | `test_own_safety_number.py` (4): the number each client shows for the user equals what the other client observed for them | Moved 2026-10-21: no longer a standing panel in Settings. Desktop: Verify Identity window → "Show my safety number"; Website: verification details → "Show my safety number". Before this, verification asked people to read their number to the other side but neither client could show it. Android not changed (paused) |
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

## Desktop executable and accessibility (added 2026-10-21)

| Capability | Desktop | Website | Evidence | Notes |
|---|---|---|---|---|
| Windows executable | **PASS (built, launched, exercised)** | n/a | `scripts/build_desktop_exe.py`; `tests/acceptance/test_desktop_exe_roundtrip.py`, `test_pairs.py`, `test_population.py`; `tests/test_desktop_exe_build.py` | One-folder PyInstaller build, no secrets or server code bundled. Exercised on this machine only; not yet code-signed, not tried on a clean machine |
| Screen-reader / automation access to message rows | **PASS (new)** | PASS (DOM) | `test_desktop_message_accessibility.py` (5) | Message and conversation rows are `setItemWidget()` widgets that assistive technology could not read; each row now carries "who, text, time" / "name, preview, N unread". Edits and deletions update it |
| Named login fields | **PASS (new)** | PASS | `test_login_window_phone_identifier.py`, acceptance suite | |
| First request after connect is always answered | PASS | **PASS (fixed)** | `test_web_gateway_first_request.py` (2) | A TLS 1.3 session-ticket race lost ~0.5% of first requests (browser registration/login timeouts). Server now issues no tickets; see the 2026-10-21 security-matrix addendum |
| Logout / closing the page ends the server connection | PASS | **PASS (fixed)** | `test_web_gateway_teardown.py` (2); acceptance `test_social.py::test_presence_...` | The gateway used to keep the server-side connection (and so the user's "online" state) after a clean browser close |
| Connection-loss behaviour | **PASS (new banner)** | **PASS (fixed)** | Desktop: `test_desktop_chat_layout.py` (2); Website: `test_web_reconnect_after_outage.py`; both: acceptance `test_reconnect.py` | Desktop shows a banner "Connection to the server was lost…" with **Sign in again** (previously only the word "Disconnected"); it does not reconnect by itself (it does not keep the password). Website reconnects by itself with back-off for about two minutes; before the fix a failed attempt hung forever and it never recovered |
| Repeated send (same `client_message_id`) delivers once | PASS | PASS | `test_message_replay_idempotency.py` (3) | The server used to deliver it twice (direct) or break the sender's connection (group) |
| Login does not reveal whether a phone number exists | PASS | PASS | `test_login_logout_integration.py::test_a_wrong_password_and_an_unknown_phone_number_look_identical` | Wire-level fix; Android shares the server and benefits unchanged. Locked/inactive accounts and login timing are not covered |
| Group history across key rotations | PASS | **PASS (new)** | `test_web_group_key_history.py` (3) | The Web client keeps every epoch and persists them; a newly linked browser device still only receives the current key |
| Desktop header fits the default window (unverified contact, groups) | **PASS (fixed)** | n/a | `test_desktop_chat_layout.py` | Found from a real screenshot: buttons and the badge were clipped; the profile action is now an icon and the name elides |
| Desktop Settings reachable on a small screen | **PASS (fixed)** | n/a | `test_own_safety_number.py` | Sections scroll; Logout/Close stay pinned |

## Desktop / Website UI parity, chat media and group events (added 2026-10-21, Phase 19.24 cycle)

The per-requirement map (20 items, files, tests) is `ui_parity_requirement_map.md`. Rows here are the user-visible behaviours.
All are covered by automated tests; none has had manual acceptance yet.

| Capability | Android | Desktop | Website | Evidence | Notes |
|---|---|---|---|---|---|
| Display names need not be unique; the phone number is | unchanged (shares the server) | PASS | PASS | `test_duplicate_display_names.py`, `test_desktop_display_names.py` | Routing, keys and authorization use the internal handle/user id, never the display name. Namesakes are told apart by `@handle`. Android keeps showing handles |
| Registration with an existing phone number: one clear message | unchanged | PASS | PASS | `test_registration_integration.py`, `test_web_registration_and_login_ui.py` | Login replies stay generic |
| Chat settings (header icon): contact info, search, pins, media, wallpaper, mute/archive/block, group members | — | PASS | PASS | `test_desktop_chat_settings.py`, `test_web_chat_settings_and_recorder.py` | Verification status and the group Members control stay in the header |
| Header avatar opens an enlarged picture (placeholder if none) | — | PASS | PASS | `test_desktop_chat_settings.py`, `test_web_messenger_layout_and_parity.py` | |
| Own profile row opens the enlarged picture; "Change picture" only there | — | PASS | PASS | `test_desktop_profile_picture_dialog.py`, `test_web_messenger_layout_and_parity.py` | |
| Website profile-picture upload with crop/zoom; server validates type, size, dimensions | — | views it | PASS | `test_profile_picture_validation.py`, `test_web_messenger_layout_and_parity.py` | Server check applies to every client |
| Concise "Verified" + Re-verify; key change ends "verified" at once | unchanged | PASS | PASS (also refuses to send until re-verified) | `test_web_messenger_layout_and_parity.py`, `test_desktop_chat_settings.py` | |
| Search never creates a conversation | — | n/a | PASS | `test_web_messenger_layout_and_parity.py` | Enter / "Start chat" opens the person; a row appears after the first message |
| Replies: right author, safe excerpt or media label, jump to original, deleted/unavailable | unchanged | PASS | PASS | `test_reply_reference_integrity.py`, `test_desktop_reply_reactions.py`, `test_web_reply_and_reactions.py` | Resolved by stable message id inside the same conversation; the server drops cross-conversation references |
| Reactions on every message kind, one pill per emoji, survive reload | PASS (pre-existing) | PASS | PASS | `test_desktop_reply_reactions.py`, `test_web_reply_and_reactions.py` | |
| Desktop voice/video cards (play, progress, duration, size, Save, time, receipts) | — | PASS | PASS (reference) | `test_phase19_24_desktop_voice_video.py`, `test_media_playback_interop.py` | Real Chrome clips decoded by Qt and real Qt clips decoded by Chrome, across the server; undecodable media fails gracefully |
| Website voice recorder modal (timer, preview, Record again / Cancel / Send) | — | Desktop recorder follows the same flow | PASS | `test_web_chat_settings_and_recorder.py` | Fake Chrome devices only; no real microphone used |
| Gateway address | — | n/a | collapsed under "Connection settings"; `?gateway=` accepted | `test_web_chat_settings_and_recorder.py` | Kept because a different gateway host needs it |
| Group membership events (added / left / removed) | unchanged | PASS | PASS | `test_group_membership_events.py`, `test_desktop_group_events.py`, `test_web_group_attachments_and_events.py` | Server-written from authenticated identities; members only, from their join time; once; in order |
| Group attachments (file, image, voice, video) | unchanged | PASS | **PASS (new)** | `test_group_attachments.py`, `test_desktop_group_attachments_gui.py`, `test_web_group_attachments_and_events.py` | One stored message + one delivery row per member; removed members and non-members cannot fetch or decrypt |

### How to read the evidence column

"Acceptance" means `tests/acceptance/` — the built Desktop executable and Chrome driven through the real UIs against an
isolated deployment (see `acceptance_testing.md`). Everything else is the regression suite (in-process clients, real
server, real database; Playwright for the Website). A **manual** result exists only where this document says so; none is
claimed yet — the manual acceptance checklist is `docs/manual_acceptance_checklist.md`.

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
6. **Desktop dialogs with buttons inside list rows** (Devices, Inbox, group members) are unreachable for assistive
   technology and for UI Automation. They work by mouse and keyboard and are covered by widget-level tests, not by the
   UI-driven acceptance suite.
7. **Desktop does not reconnect by itself** after losing the server; it offers "Sign in again".
8. **Account enumeration** is closed for wrong-password versus unknown-number replies only; locked/inactive accounts and
   login timing still differ.
9. **The executable is unsigned** and has only been run on the development machine.

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
