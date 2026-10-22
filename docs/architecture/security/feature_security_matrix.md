# Feature Security Matrix — Phase 19.24 40-Item Acceptance

The canonical, evidence-cited status of every item in Phase 19.24's
required feature list. No row claims "implemented" without a code
citation; no row claims "tested" without a currently-passing test; no
row claims "physically validated" without an actual, described
physical/manual check performed this phase. Where a claim cannot be
backed by evidence, the row says so plainly rather than rounding up.

**Revision note**: an earlier version of this matrix, written midway
through Phase 19.24, marked rows 17–25 and 28 "NOT IMPLEMENTED" — true
at that point, but all of those features (plus Presence/Last Seen
enhancement, row 29, and Voice/Video, rows 13/14/37/38) were
implemented, with real UI on Desktop/Mobile/Web and dedicated passing
tests, in the remainder of the same phase. This revision reflects that
current, verified state.

Legend: **Impl** = implementation status. **Arch** = architecture
designed/documented. **Sec** = security review done. **Test** =
automated test exists and passes. **And/Web/Desk** = per-platform
status. **Limitation** = what is honestly missing.

| # | Feature | Impl | Arch | Sec | Test | Android | Desktop | Web | Limitation |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Text | PRESERVED | ✓ (existing) | ✓ (existing) | PASS | unchanged | unchanged | unchanged | None |
| 2 | Direct messaging | PRESERVED | ✓ | ✓ | PASS | unchanged | unchanged | unchanged | None |
| 3 | Groups | PRESERVED | ✓ | ✓ | PASS (`messaging_groups` batch) | unchanged | unchanged | unchanged | None |
| 4 | Reply | IMPLEMENTED | ✓ `messaging_event_architecture.md` | ✓ message_id-addressed, membership-checked | PASS | real UI (long-press → reply preview) | real UI (context menu → composer preview bar) | real UI (context menu → composer preview) | None |
| 5 | Edit | IMPLEMENTED | ✓ | ✓ sender-only, stale-version rejected, blocked after delete | PASS ×4 | real UI | real UI | real UI | Receive-side ML-DSA verification of edit purpose is implemented (`EDIT_PAYLOAD_PURPOSE`); see row 32 |
| 6 | Delete For Me | IMPLEMENTED | ✓ | ✓ per-viewer only, membership-checked | PASS ×2 | real UI | real UI | real UI | None |
| 7 | Delete For Everyone | IMPLEMENTED | ✓ | ✓ sender-only, real data minimization, idempotent | PASS ×3 (+3 confirmation-dialog files, 2026-09-21) | real UI, incl. Yes/No confirmation | real UI, incl. Yes/No confirmation | real UI, incl. Yes/No confirmation | None |
| 8 | Forward | IMPLEMENTED (text + image/file/voice/video, all 3 platforms) | ✓ genuinely re-encrypted for the target, never ciphertext reuse | ✓ | PASS (`test_web_forward_*`, `test_web_forwarding_a_voice_message_preserves_its_payload_type`, Desktop forward-dialog tests, `test_forwarding_a_voice_message_preserves_its_payload_type`, `test_phase19_24_mobile_forward_media.py` ×2 — all added/fixed 2026-09-21) | real UI, image/file/voice/video (Bubble now retains attachment bytes, previously TEXT-only) | real UI, image/file/voice/video (`gui/forward_dialog.py`; fixed a real bug where a forwarded voice/video bubble was silently reclassified as a generic file) | real UI, image/file/voice/video (`forwardAttachment()`; bubbles now retain attachment bytes, previously TEXT-only) | None |
| 9 | Copy | IMPLEMENTED | n/a (client-side only, no wire exposure) | n/a | PASS | real UI (long-press → Copy) | real UI (context menu → Copy) | real UI (context menu → Copy, clipboard API) | None — plaintext never leaves the device for this action |
| 10 | Reactions | IMPLEMENTED | ✓ | ✓ E2E encrypted (server cannot read reaction), membership-checked, replace-not-stack | PASS ×3 | real UI | real UI | real UI | None |
| 11 | Images | PRESERVED | ✓ (existing) | ✓ (existing) | PASS | unchanged | unchanged | unchanged | None |
| 12 | Files | PRESERVED | ✓ | ✓ | PASS | unchanged | unchanged | unchanged | None |
| 13 | Voice messages | IMPLEMENTED (Desktop/Web); Android recording code-complete, physically unverified | ✓ `media_security_architecture.md` | ✓ reuses FILE's AES-256-GCM/ML-DSA/blob pipeline unchanged; device revocation explicitly proven for both send and receive (`test_revoked_device_cannot_send_a_voice_message`, `test_revoked_device_cannot_receive_a_voice_or_video_message`) | PASS (`test_phase19_24_desktop_voice_video.py` incl. a REAL microphone recording; `test_phase19_24_mobile_voice_video.py`; `test_web_phase19_24_lifecycle_ui.py`'s voice test incl. a REAL browser recording reaching a real Desktop peer) | playback real (SoundLoader, confirmed-working backend); recording is now REAL code — `android.media.MediaRecorder` via pyjnius (`mobile/app.py::_open_media_recorder_popup()`), requests RECORD_AUDIO at runtime, wired into the real attachment menu and the real encrypt/send pipeline, and the APK builds successfully with it included — physical hardware IS now available and was used (2026-09-26/28: real registration/login/TOFU-verification/E2E encrypted text messaging all confirmed on-device), but the voice-recording UI specifically was not reached before the session's wireless ADB connection dropped; see Limitation column | full (QtMultimedia, real mic recording confirmed) | full (`getUserMedia`/`MediaRecorder`, confirmed via Chromium's fake-device flags) | Android recording is implemented and the app itself is now physically confirmed to run/message correctly, but the voice-record flow specifically is UNVERIFIED — blocked by a wireless-ADB connection drop mid-session (network-layer, not hardware-access); see `mobile_client.md`'s "2026-09-26/28" section |
| 14 | Video messages | IMPLEMENTED (Desktop/Web); Android recording AND in-app playback code-complete, physically unverified | ✓ | ✓ same reuse as row 13; device revocation explicitly proven for both send and receive (`test_revoked_device_cannot_send_a_video_message`, `test_revoked_device_cannot_receive_a_voice_or_video_message`); native playback never bypasses decryption/authorization — it plays the same already-decrypted plaintext bytes the Save button already writes, from a private temp file deleted on completion/error/close, never a permanent copy | PASS (same test files as row 13) | recording is REAL code — `MediaRecorder` with `VideoSource.CAMERA` + a native `android.view.SurfaceView` attached to the activity for camera preview, requests CAMERA+RECORD_AUDIO at runtime. Playback is now REAL code too (2026-09-22, this closure pass) — this Kivy build's OWN video-decode backend is still `null`/unavailable, so instead of a fake in-Kivy player, `mobile/app.py::_play_video_android()` bridges to Android's native `android.widget.VideoView`+`MediaController` via pyjnius (same `addContentView()`-alongside-Kivy's-GL-surface technique already used for the camera preview), writing the decrypted bytes to a private temp file once and deleting it on completion/error/close. The APK builds successfully with both included — hardware is now available and the app itself is confirmed running/messaging on it, but the video-record/playback flows specifically were not reached before the session's connection dropped | full (QtMultimedia, real camera recording confirmed, in-app player) | full (`getUserMedia`/`MediaRecorder`, in-app `<video>` player) | Android recording AND playback are both implemented, and the app is now physically confirmed to run correctly, but the video-specific flows are UNVERIFIED — same wireless-ADB connection-drop limitation as row 13, not a missing-code gap |
| 15 | Media gallery | IMPLEMENTED (all 3 platforms) | ✓ | ✓ operates only on already-decrypted, already-rendered bubbles — no second history fetch, no server exposure, on all 3 clients | PASS (`test_phase19_24_desktop_media_gallery.py`; `test_phase19_24_mobile_media_gallery.py` ×5, new this closure pass; `test_web_media_gallery_lists_a_received_image_and_voice_message`, new this closure pass) | real UI — header button opens a grouped grid (Photos & Videos) + list (Voice/Files), tap-to-view/scroll reuses the real inline bubble widgets | full (thumbnail grid + voice/file list, real Save/viewer/player reuse) | real UI — `#galleryBtn`/`#groupGalleryBtn` open a modal grouped the same way, tap opens the image full-size or scrolls to the real inline voice/video/file bubble | None |
| 16 | View/save controls | PRESERVED | ✓ (existing) | ✓ (existing) | PASS | unchanged | unchanged | unchanged | None |
| 17 | Chat wallpapers | IMPLEMENTED | ✓ | ✓ local-only, never sent to or stored by the server | PASS (`test_phase19_24_desktop_wallpaper.py`, `test_phase19_24_mobile_wallpaper.py`, Web wallpaper test) | real UI | real UI | real UI | Preset-only (no custom image upload), by design |
| 18 | Typing indicator | IMPLEMENTED | ✓ | ✓ ephemeral, never persisted | PASS | real UI | real UI | real UI | None |
| 19 | Message search | IMPLEMENTED | ✓ | ✓ operates only on already-decrypted, already-rendered bubbles — the query text is never sent to the server | PASS (`test_phase19_24_desktop_message_search.py`, `test_phase19_24_mobile_message_search.py`, Web search test) | real UI | real UI | real UI | None |
| 20 | Pinned messages | IMPLEMENTED | ✓ `messaging_event_architecture.md`'s own Pinned Messages section (trust model documented) | ✓ real server-synchronized state, any-active-member authorization, recovered on every history reload | PASS (`test_phase19_24_message_lifecycle_security.py` ×6 security-negative + happy-path, `test_phase19_24_desktop_pinned_messages.py`, `test_phase19_24_mobile_pinned_messages.py`, Web pin test) | real UI | real UI | real UI | None — a real protocol/database feature, not a local-only button |
| 21 | Draft messages | IMPLEMENTED | ✓ | ✓ local-only | PASS | real UI | real UI | real UI | None |
| 22 | Mute | IMPLEMENTED | ✓ | ✓ local-only, encrypted local storage | PASS | real UI | real UI | real UI | None |
| 23 | Archive | IMPLEMENTED | ✓ | ✓ local-only, shares Mute's storage mechanism | PASS | real UI | real UI | real UI | None |
| 24 | Message retry | IMPLEMENTED | ✓ | ✓ client_message_id, server-side UNIQUE-constraint dedup | PASS | real UI | real UI | real UI | None |
| 25 | Proper attachment menu | IMPLEMENTED | ✓ | ✓ | PASS (`test_attachment_gui.py`'s attachment-menu tests, plus every platform's own voice/video menu tests) | real UI (Photo/File, Voice, Video choices) | real UI (Photo/File, Voice, Video choices) | real UI (Photo/File, Voice, Video choices) | None |
| 26 | Verification | PRESERVED | ✓ (existing) | ✓ (existing) | PASS | unchanged | unchanged | unchanged | None |
| 27 | Device management | PRESERVED | ✓ | ✓ | PASS | unchanged | unchanged | unchanged | None |
| 28 | Block user | IMPLEMENTED | ✓ | ✓ real server-side enforcement across DM relay, verification requests, presence, typing indicators, search, group membership | PASS (`test_phase19_24_block_user_security.py`, 14 security-negative tests; +2 confirmation-dialog files, 2026-09-21) | real UI, incl. Yes/No confirmation | real UI, incl. Yes/No confirmation | real UI, incl. Yes/No confirmation | None |
| 29 | Presence/last seen | IMPLEMENTED (last-seen enhancement added) | ✓ | ✓ `last_seen_at` hidden in either direction a block exists, same rule as the online/offline signal; single overwritten timestamp, not a history log | PASS (`test_phase19_24_presence_last_seen.py` ×6, `test_phase19_24_mobile_presence_last_seen.py` ×3, Web presence test) | real UI (existing Online/Offline label extended to show "Last seen ...") | real UI (new presence subtitle in the chat header — Desktop previously had none at all) | real UI (new `#peerPresence` subtitle) | None |
| 30 | Profile/settings | PRESERVED | ✓ | ✓ | PASS | unchanged | unchanged | unchanged | None |
| 31 | ML-KEM-768 | PRESERVED, unchanged | ✓ | ✓ | PASS | unchanged | unchanged | unchanged | None |
| 32 | ML-DSA-65 | PRESERVED; extended to sign edit/reaction sends | ✓ | ✓ send-side and receive-side verification both implemented for edit/reaction (`_verify_lifecycle_event_signature`) | PASS | n/a | n/a | n/a | Pin/unpin and last-seen carry no signature of their own — documented, intentional (see `messaging_event_architecture.md`'s Pinned Messages section): no ciphertext-bearing content exists for either to protect, same trust boundary `deleted_by` already has |
| 33 | AES-256-GCM | PRESERVED; reused for edit/reaction/voice/video content | ✓ | ✓ fresh nonce per encryption, reaction ciphertext confirmed to never contain plaintext | PASS | n/a | n/a | n/a | None |
| 34 | Argon2id | PRESERVED, untouched | ✓ (existing) | ✓ (existing) | PASS | unchanged | unchanged | unchanged | None |
| 35 | Device authorization | PRESERVED | ✓ | ✓ every new handler's membership check reuses `ConversationRepository.get_member_user_ids()` unchanged | PASS | unchanged | unchanged | unchanged | None |
| 36 | Device revocation | PRESERVED; explicitly re-tested against a new payload type AND against the lifecycle-event broadcast path this phase | ✓ `_broadcast_to_conversation_members()`'s `is_device_bound_and_authorized()` gate (receiving side); L-1's own sender-side chat-relay check (inherited by voice/video, since they use the same relay path) | ✓ mechanism unchanged from the already-tested L-1 fix | PASS `test_device_identity.py::test_revoked_device_cannot_send_a_voice_message` and `::test_revoked_device_does_not_receive_pin_notification` (both new this phase, 21/21 in the file passing) plus the pre-existing L-1 suite (chat/group-key), all passing | unchanged | unchanged | unchanged | Documented asymmetry: lifecycle-event handlers (edit/delete/react/pin) do not independently re-check the SENDER's device-binding state (only the receiving broadcast does) — pre-existing across all of them, not introduced by any Phase 19.24 feature; `test_revoked_device_does_not_receive_pin_notification` proves BOTH halves at once (Bob's pin request is accepted despite Alice's device being revoked; Alice's revoked device never receives the live broadcast) — see `messaging_event_architecture.md` for the full reasoning |
| 37 | E2E encrypted voice | IMPLEMENTED (Desktop/Web); Android code-complete, physically unverified | ✓ | ✓ same AES-256-GCM/ML-DSA pipeline as row 13; revoked device explicitly proven unable to send OR receive | PASS (row 13's own tests) | recording code-complete, unverified on hardware; playback real | full | full | Android recording — see row 13 |
| 38 | E2E encrypted video | IMPLEMENTED (Desktop/Web); Android code-complete, physically unverified | ✓ | ✓ same pipeline as row 14; revoked device explicitly proven unable to send OR receive | PASS (row 14's own tests) | recording AND in-app playback both code-complete, unverified on hardware | full | full | Android — see row 14 |
| 39 | Secure deletion semantics | IMPLEMENTED | ✓ `message_lifecycle.md`, full honest limitations statement | ✓ real data minimization, not a flag; honest about backup/screenshot/offline-cache limits | PASS | real UI | real UI | real UI | None |
| 40 | Secure edit/forward/reaction protocol events | IMPLEMENTED (edit/reaction/pin); forward inherits the send pipeline's own security | ✓ full taxonomy in `messaging_event_architecture.md` | ✓ authorization/replay/duplicate/multi-device/revocation all addressed | PASS | real UI | real UI | real UI | None |

## Android build, SHA-256, and physical-validation status

The current, up-to-date debug APK (rebuilt from source a seventh time
on 2026-09-26, a clean rebuild that resolved the native startup crash
tracked since 2026-09-22 — see the resolution below — supersedes the
phase's six earlier builds):

- **Path**: `bin/qrscs_mobile-0.1.0-arm64-v8a-debug.apk`
- **Package**: `org.qrscs.qrscs_mobile`
- **versionName / versionCode**: `0.1.0` / `1024100`
- **targetSdkVersion / minSdk**: `36` / `24`
- **ABI**: `arm64-v8a`
- **Size**: 29,893,161 bytes
- **SHA-256**: `428515501b0fd89c9744ec927905afbf8cd29ca6267a5006c89282108d01aa17`
- **Permissions**: `INTERNET`, `RECORD_AUDIO`, `CAMERA`

Same source tree and `buildozer.spec` as the prior (crashing) build —
only the build artifact itself changed via a clean rebuild. A full
content audit of the extracted `assets/private.tar` (no `.key`/`.pem`/
`.env` files anywhere, `certs/dev/` has only the public `ca.crt`,
bundled app data is compiled `.pyc` bytecode with no `.py` source, and
a full string scan of every bundled `.pyc` file found no hardcoded
database connection strings, no cloud credential patterns, and no
tool/vendor-name or agent-description strings — see this doc's
attribution scan below) found nothing exploitable bundled into the
distributable APK.

**Physical-device install/launch was genuinely attempted this pass —
hardware became available and a real device-compatibility defect was
found.** A real Vivo V2036 (Android 13/API 33, Qualcomm "bengal",
Adreno 610) connected via USB, authorized, and confirmed via
`adb devices -l`. `adb install -r` succeeded and `dumpsys package`
confirmed the installed version matched exactly. Launching the app
reproduced a 100%-deterministic native crash (`SIGSEGV` in ART's
`Jit thread pool`, inside Kivy/SDL2's own native bootstrap, before any
of this project's own Python code runs) across the first 2 attempts.
`android:vmSafeMode="true"` (Android's own standard flag disabling
JIT/AOT compilation — a runtime execution-mode setting with no effect
on any cryptography or security code path) was added and the APK
rebuilt; this confirmably improved the situation (the app now
progresses much further into real CPython startup before failing) but
did not fully resolve it — across 13 total launch attempts on this
specific physical unit, the app never reached a stable, visible UI
state.

**A follow-up controlled experiment (2026-09-24) reclassified the root
cause.** Rather than repeat more identical launches, a minimal Kivy
"hello world" app (no cryptography/pynacl/argon2-cffi/pycryptodome/
sqlalchemy/pydantic/kyber-py — only bare Kivy) was built with the
identical toolchain (same NDK, same `android.api=36`, same
`vmSafeMode`) and installed on the SAME Vivo V2036. **It reached a
stable, rendered UI** (screenshot evidence) — ruling out generic
device/ROM/GPU/Kivy incompatibility. The failure is specific to
something in the real project's own additional native dependencies
(most likely `cryptography`'s Rust extension) interacting with this
device's old Adreno 610 driver/JIT, not this project's own Python
application code (the crash is still beneath `mobile/app.py`). Further
bisection (adding one dependency at a time) was not completed this
pass — the device's battery reached a critical 2% during testing and
further on-device work was stopped to avoid losing the device
mid-experiment. See `mobile_client.md`'s "2026-09-24" section for the
complete evidence trail.

**RESOLVED 2026-09-26 — the native startup crash itself is fixed.**
With wireless ADB available, a controlled dependency bisection (adding
`cryptography` with a real ML-DSA import, then the full remaining
requirement set with real imports matching this project's own exact
import paths, then matching `RECORD_AUDIO`/`CAMERA` permissions) found
every actually-used dependency imports cleanly and none reproduce the
crash; `sqlalchemy`/`pydantic` each have a real but non-fatal Python
import error, and neither is ever imported by the mobile client's own
code (dead weight in `buildozer.spec`, not a runtime defect). The
decisive step was rebuilding the REAL project itself (via `mobile/
android_main.py` swapped in as the entrypoint, `scripts/
build_android_apk.sh`'s own established mechanism) from a clean
state: **4/4 consecutive launches succeeded**, each alive 15-30
seconds and showing the app's real onboarding screen (screenshot
evidence). The exact mechanism distinguishing the crashing build from
the working one was not isolated further (identical source and
config) — most likely a stale artifact in the specific old build
rather than a reproducible source/config defect, since a clean rebuild
of byte-identical source now launches reliably. New SHA-256:
`428515501b0fd89c9744ec927905afbf8cd29ca6267a5006c89282108d01aa17`
(29,893,161 bytes), promoted to `bin/qrscs_mobile-0.1.0-arm64-v8a-
debug.apk`.

**A second, separate limitation (`adb shell input tap`/`swipe`/
`monkey` producing no effect over wireless ADB, proven device-wide via
a control test against the OS launcher) was resolved by using a human
operator's real finger for physical taps, with wireless ADB used only
for screenshots/logcat/state verification** — exactly the "physical
interaction strategy" this closure pass's own mandate specified.

**RESOLVED-IN-PART, 2026-09-26/28 — real physical registration, login,
TOFU verification, and a genuine Android→Desktop E2E encrypted text
message, all human-touch-confirmed.** With the human operator tapping
the physical screen and a real Desktop peer driven programmatically
(the project's own real `ClientSession`, no mock), the following were
observed live on the physical Vivo V2036: real registration and login
through the real onboarding UI; a real, *correct* security rejection
("A message from an unverified contact was blocked") before
verification; real mutual TOFU verification (Desktop side via the
real `confirm_peer_verification()`, Android side via the human
operator tapping "Verify Identity", which changed to "Re-verify");
and a real Android→Desktop encrypted text message — "hello", typed on
the physical keyboard, arriving at the Desktop peer's real
`load_conversation_history()` as genuinely decrypted plaintext. This
proves the full pipeline (ML-KEM-768 session establishment, ML-DSA-65
identity, AES-256-GCM message encryption, real TLS transport, real
server relay, real decryption) end-to-end on physical Android hardware
for text messaging — the same pipeline voice/video reuses.

**What remains PARTIAL and why:** voice recording, video recording,
voice/video playback, and voice/video E2E (rows 13, 14, 37, 38
specifically) were not reached — the wireless ADB connection dropped
during a long idle gap between coordination steps, and re-pairing
subsequently failed at the network layer (`ping` to the phone's
newly-assigned address showed 100% packet loss — the computer and
phone were no longer on a mutually routable network, not an ADB or
application problem). This is real, substantial, evidence-backed
progress short of the specific voice/video validation those four rows
require — not converted to PASS without that evidence. See
`mobile_client.md`'s "2026-09-26/28" section for the complete evidence
trail, screenshots, and exact resume point.

The same toolchain previously produced a working, physically-validated
APK on a *different* device (Infinix X6711, Android 14/API 34, Phase
19.7) — see `mobile_client.md`. Every row above whose Android column
claims real, working UI is supported by this project's own passing
`mobile` regression batch (Kivy widget/logic tests running against the
real `mobile/app.py`/`mobile/session.py` code, not a mock) — that is
automated-test evidence; the 2026-09-26/28 session above is genuine
physical on-device evidence for text messaging specifically, and this
document does not conflate the two or overstate one as the other.

## Summary

25 rows are IMPLEMENTED, 15 rows are PRESERVED (verified by a direct
count of this table's own Impl column, not by memory) — 40 total:

- **Implemented this phase or newly real-UI this phase**: rows 4–10,
  13–15, 17–25, 28–29, 37–40 (25 items). One of these carries an
  explicit per-platform caveat rather than being uniformly complete:
  row 14/38 (Video — Desktop/Web full; Android recording and in-app
  playback are both real, complete code, but neither is physically
  hardware-verified in this environment).
- **Preserved unchanged or lightly extended from before this phase**:
  rows 1–3, 11–12, 16, 26–27, 30–36 (15 items). Two of these carry a
  documented note rather than being a bare no-op: row 32 (ML-DSA —
  extended to sign edit/reaction, with one documented deliberate
  non-requirement for Pin/last-seen) and row 36 (device revocation —
  preserved mechanism, explicitly re-tested against voice/video and
  against the Pin broadcast path this phase, with one documented
  pre-existing trust-model asymmetry).

The only remaining gap left in this matrix is native Android voice/
video RECORDING's PHYSICAL VERIFICATION (rows 13/14/37/38's Android
column) — every other row that was previously "NOT IMPLEMENTED" in an
earlier revision of this document, including this one, has since
shipped with real UI, a real protocol, and a passing test. Android
voice/video recording itself is no longer unattempted: real
`android.media.MediaRecorder` code (via pyjnius, mirroring this
project's own established Android-bridging conventions) now exists,
is wired into the real attachment menu and the real encrypt/send
pipeline, and builds successfully into a real, installable APK. What
remains is purely the physical-hardware verification step, which this
development environment cannot provide (no device or emulator
attached — checked repeatedly and directly, not assumed). See `docs/
architecture/media_security_architecture.md` for the full design and
its own explicit, honest verification-status statement.

## Final acceptance status (PASS / PARTIAL / BLOCKED / NOT IMPLEMENTED)

One line per requirement, in the mandate's own vocabulary. "PASS" means
implemented with real UI on every platform where it applies and a
passing automated test. "PARTIAL" names the exact missing platform/
capability. "BLOCKED" is reserved for physical-validation-only gaps
(the implementation itself is not in question). No row here is more
favorable than the detailed row above it.

| # | Feature | Status |
|---|---|---|
| 1 | Text | PASS |
| 2 | Direct messaging | PASS |
| 3 | Groups | PASS |
| 4 | Reply | PASS |
| 5 | Edit | PASS |
| 6 | Delete for Me | PASS |
| 7 | Delete for Everyone | PASS |
| 8 | Forward | PASS — now forwards text, image, file, voice, and video on all 3 platforms (was PARTIAL — Web/Mobile were text-only; Desktop silently downgraded voice/video to a generic file — both fixed 2026-09-21) |
| 9 | Copy | PASS |
| 10 | Reactions | PASS |
| 11 | Images | PASS |
| 12 | Files | PASS |
| 13 | Voice messages | PARTIAL — Android recording is real, complete code (builds into the APK successfully); physical hardware IS available and the app is now confirmed running/messaging on it (2026-09-26/28), but the voice-record flow specifically is UNVERIFIED (wireless ADB connection dropped mid-session); Desktop/Web record+playback and Android playback are all PASS |
| 14 | Video messages | PARTIAL — Android recording AND in-app playback (native VideoView/MediaController via pyjnius, added 2026-09-22) are both real, complete code; physical hardware IS available and the app is now confirmed running/messaging on it, but the video-specific flows are UNVERIFIED (same connection-drop limitation); Desktop/Web PASS |
| 15 | Media gallery | PASS — real UI on all 3 platforms |
| 16 | View/save controls | PASS |
| 17 | Chat wallpapers | PASS |
| 18 | Typing indicator | PASS |
| 19 | Message search | PASS |
| 20 | Pinned messages | PASS |
| 21 | Draft messages | PASS |
| 22 | Mute | PASS |
| 23 | Archive | PASS |
| 24 | Message retry | PASS |
| 25 | Proper attachment menu | PASS |
| 26 | Verification | PASS |
| 27 | Device management | PASS |
| 28 | Block user | PASS |
| 29 | Presence/last seen | PASS |
| 30 | Profile/settings | PASS |
| 31 | ML-KEM-768 | PASS |
| 32 | ML-DSA-65 | PASS |
| 33 | AES-256-GCM | PASS |
| 34 | Argon2id | PASS |
| 35 | Device authorization | PASS |
| 36 | Device revocation | PASS |
| 37 | E2E encrypted voice | PARTIAL — same gap as item 13; note a real Android→Desktop E2E encrypted **text** message was physically confirmed on 2026-09-26/28 via the identical session-key/encryption pipeline, so the shared infrastructure is now evidence-backed — the voice-specific flow itself is not yet verified |
| 38 | E2E encrypted video | PARTIAL — same gap as item 14; same shared-pipeline evidence as item 37 applies, video-specific flow not yet verified |
| 39 | Secure deletion semantics | PASS |
| 40 | Secure edit/forward/reaction protocol events | PASS |

**Separate, cross-cutting dimension — physical Android validation**:
BLOCKED for every Android-visible feature above, uniformly. No
physical device is currently connected to this environment (checked
directly via Windows-native `adb.exe` and a Windows Device Manager USB
sweep — see the "Android build" section above for the exact commands
and results). The Phase 19.7 session already proved the full
install→launch→logcat→touch-input flow works on this same toolchain
against a physical device (Infinix X6711); nothing about that flow is
in question, only the current absence of a connected device to repeat
it against. This is the single item on this page that is not resolved
by more implementation work — it requires physical hardware access
this session does not have.

**Tally** (verified by direct count of this table's own Status column,
not by memory): 36 PASS, 4 PARTIAL (rows 13, 14, 37, 38 — all four are
the SAME underlying gap, Android voice/video recording, split across
the mandate's own item numbering; each has one named, specific missing
piece, never a vague "mostly done"), 0 NOT IMPLEMENTED, 0 rows where
physical validation was fabricated or implied without evidence.
36 + 4 = 40. Two items moved to PASS this closure pass: row 8 (Forward
— now handles image/file/voice/video on all 3 platforms) and row 15
(Media Gallery — now real UI on all 3 platforms, closing the previous
Desktop-only gap). The remaining 4 PARTIAL rows are no longer a
missing-implementation gap — real, complete Android `MediaRecorder`
code now exists, is wired into the real UI and the real encryption
pipeline, and builds successfully into the APK — the ONLY remaining
gap is physical-hardware verification, which this environment cannot
provide (no device or emulator attached, checked repeatedly). Video
additionally has a second, hardware-independent gap: no in-app Android
playback (no working video-decode backend on this Kivy build).

## Reconfirmation — 2026-10-02 (Phase 19.24 final acceptance window)

No feature source file changed between the previous closure pass and
this reconfirmation (verified directly via file-modification-time
comparison against this document's own last edit, not assumed) — this
pass is re-running the evidence behind the table above against the
current repository, not re-deriving the design. Result: every row's
status above still holds.

**Backend/security regression, rerun clean**: `crypto_unit` (22 files,
80.8s), `device_security` (26 files, 274.2s), `messaging_groups` (44
files, 527.4s), `mobile` (20 files, 170.3s) — all PASS, no failures.

**Desktop GUI, rerun clean**: `desktop_gui` (15 files, 31.0s) and
`desktop_gui_lifecycle_a` (8 files, 15.3s) PASS as batches.
`desktop_gui_lifecycle_b1` (5 files) showed one non-deterministic
teardown ERROR on its first run this pass (not a failed assertion —
the test itself passed; a fixture-teardown-timing issue), did not
reproduce on an immediate retry of the same file alone, and the full
batch then passed clean on retry (59.3s) — consistent with the
already-documented Qt/Windows teardown-timing class, not a regression.
`desktop_gui_lifecycle_b2` (5 files, including `test_phase19_24_
desktop_voice_video.py`) hit the already-documented batch-level 900s
hang again; all 5 files were then run standalone and passed clean
(29/29 tests total) — see project memory `qt_windows_gui_batch_
flakiness.md` for the full trace, including a new finding from this
pass (closing long-idle leftover `main.py` GUI processes resolved an
otherwise-alarming single-file standalone hang).

**Web/Playwright, rerun clean with documented flakiness**: the 27-test
`test_web_phase19_24_lifecycle_ui.py` suite passed 25/27 in a full run;
the remaining 39 tests across `test_web_browser_e2e.py`, `test_web_
feature_completion_e2e.py`, `test_web_persistence_reconnect.py`,
`test_web_settings_and_inbox.py`, `test_web_gateway_interop.py`, and
`test_web_client_crypto_interop.py` passed 38/39. All 3 failures
(`test_web_setting_a_wallpaper_via_real_ui_applies_and_persists`,
`test_web_unblocking_via_real_ui_restores_delivery`, `test_web_inbox_
approve_verification_request_real_ui`) failed at the IDENTICAL generic
setup line every test in these suites shares (`_wait_for(lambda:
alice.key_manager.get_public_key(bob_username) is not None)`), never
at any wallpaper/block/inbox-specific logic — ruling out a feature
regression. All 3 were rerun standalone afterward: the wallpaper test
passed 2/3 (failed once more standalone, matching its own
previously-documented history in `web_playwright_test_flakiness.md`);
the unblocking test passed 3/3; the inbox test passed 3/3. Consistent
with the already-documented environmental Playwright/Chromium timing
class — not chased further per this project's own standing discipline.

**Android**: no device or emulator attached to this session (`adb
devices -l` confirmed empty) — consistent with the gap already
documented above and in `mobile_client.md`'s "2026-09-26/28" section.
No Android work was attempted this pass beyond this direct check, per
the mandate's own instruction not to spend hours fighting an
unavailable-hardware limitation.

**Net effect on the matrix**: none of the above changes any row's
Status. Tally remains 36 PASS, 4 PARTIAL, 0 NOT IMPLEMENTED, 0
fabricated evidence.

## Reconfirmation — 2026-10-19 (final engineering window)

Every row above was re-checked against the current working tree by running
the project's own regression batches (`scripts/run_regression_batches.py`'s
batch definitions) against the real server, the real PostgreSQL database and a
real Chrome (Playwright), and by a live run of the actual launcher (`run.py`).
Nothing was mocked at a security boundary. Evidence is limited to what ran:

**Environment.** Python 3.12.10 in a clean virtualenv built from
`requirements.txt`'s pins (PySide6 6.9.1, Kivy 2.3.1, pytest 8.4.2, Playwright
1.62.0, quickjs 1.19.4), PostgreSQL 17 (Alembic head `d3f7b9c2e5a1`, no
migration run), Windows 11. The README's documented interpreter is 3.12; the
machine's default Python 3.14 with PySide6 6.12 is *not* a supported
combination (two batches exited `0xC0000409` at interpreter shutdown after every
test had passed, and Kivy/quickjs were absent) and was not used for acceptance.

| Batch | Files | Passed | Failed | Skipped | Exit |
|---|---|---|---|---|---|
| crypto_unit | 22 | 381 | 0 | 0 | 0 |
| device_security | 27 | 253 | 0 | 0 | 0 |
| messaging_groups_a | 22 | 302 | 0 | 0 | 0 |
| messaging_groups_b1 | 11 | 177 | 0 | 0 | 0 |
| messaging_groups_b2 | 11 | 194 | 0 | 0 | 0 |
| mobile | 20 | 104 | 0 | 0 | 0 |
| desktop_gui | 16 | 177 | 0 | 0 | 0 |
| desktop_gui_lifecycle_a | 8 | 107 | 0 | 0 | 0 |
| desktop_gui_lifecycle_b1 | 5 | 36 | 0 | 0 | 0 |
| desktop_gui_lifecycle_b2 | 7 | 43 | 0 | 0 | 0 |
| web | 7 | 66 | 0 | 0 | 0 |
| **Total** | **156** | **1840** | **0** | **0** | |

Four test files (`test_epoch_reservation_request_response.py`,
`test_phase19_23_ux_fixes.py`, `test_phase19_24_desktop_media_gallery.py`,
`test_phase19_24_typing_indicator.py`) were in no batch and so never ran under
the documented procedure; they are now included.

**Defects found and fixed this pass** (none in a security control):

- *Test-harness hang (root cause of the long-documented "Desktop GUI batch
  hangs").* A ChatWindow kept alive by an earlier test received a late
  message/error after its session was torn down, and `ChatWindow.show_error()`
  opened a modal `QMessageBox` that nothing headless can dismiss. Fixed with an
  autouse fixture in `tests/conftest.py` that retires finished-test windows,
  and `test_phase19_24_desktop_block.py` now asserts the "User is offline"
  report itself (and that it never reveals the block). `desktop_gui_lifecycle_b2`
  went from a 900s timeout to 35s; the media-gallery file, documented as
  unrunnable as a whole, now passes 6/6.
- *Desktop message bubbles:* the footer painted an opaque band (white-on-white
  timestamp/read tick on sent bubbles) and the last text line of a wrapped
  message collided with it, because the hidden "message actions" button changed
  the footer height after the row was measured. Fixed in `gui/message_widget.py`.
- *Web contrast:* placeholder text (2.9–3.3:1), sent-bubble timestamps
  (3.7:1) and white-on-accent text in dark mode (3.5:1) raised to >= 4.5:1 via
  design tokens only.

**Web batch stability.** The 7-file web batch passed 66/66 on three full runs
(the last two with the machine held awake). Two further
full runs failed 2/66 and 1/66 (different tests each time, all at the shared
"peer public key received" wait), and the same test failed identically on an
unmodified export of HEAD run under the same conditions, so the failures are
not attributable to this pass's changes. The failed tests passed when rerun
in isolation (two of them 3/3). The laptop (on battery, 10-minute idle sleep) was observed to
sleep and resume several times mid-run -- one earlier web run stalled for 25
minutes across such events -- so this is recorded as an environmental timing
sensitivity that was mitigated (system held awake), not proven fixed.

**Live stack.** `run.py` started the TLS server (:5000), web gateway (:8765),
static web client (:8000) and the Desktop app; the Desktop window was
responsive; a real Desktop `ClientSession` and a real Chrome session
authenticated, verified each other's identity, established an ML-KEM session
key and exchanged messages in both directions with no console or page errors.

**Android.** A debug APK was rebuilt from the current source (sanitized copy:
no `.env`, `.git` or private keys; patched python-for-android checkout as used
by the earlier builds): `org.qrscs.qrscs_mobile` 0.1.0 (versionCode 1024100),
minSdk 24, targetSdk 36, arm64-v8a, permissions INTERNET/RECORD_AUDIO/CAMERA,
29,544,821 bytes, SHA-256
`8bb5bb9c42cedbac926b689c9ab6fe206ebba9b94136c455c1764fb4047597b1`. The package
contains no `.env`/key material and only the public `certs/dev/ca.crt`. **No
Android device or emulator was attached** (`adb devices -l` empty), so nothing
about this build was installed or run; the 104 `mobile` software tests above
are the only evidence for it, and rows 13, 14, 37 and 38 keep their PARTIAL
status.

**Net effect on the matrix:** none. Tally remains 36 PASS, 4 PARTIAL
(13/14/37/38, Android voice/video physical validation), 0 NOT IMPLEMENTED.

## Reconfirmation — 2026-10-20 (security hygiene, parity and stability pass)

No row's status above changes: tally remains **36 PASS, 4 PARTIAL** (13, 14, 37,
38 — Android voice/video, still unvalidated on a physical device, which is
deferred), 0 NOT IMPLEMENTED. This section records what changed in the
security posture of the project and the evidence for it. No secret value
appears in this document, in any log it cites, or in the release archive.

### Security changes made

| Area | Before | Now | Evidence |
|---|---|---|---|
| Database login | The server connected as the `postgres` superuser | Runtime role `qrscs_app`: login only; no superuser, createdb, createrole, replication or row-security bypass; SELECT/INSERT/UPDATE/DELETE on the application tables and sequence use only; no DDL, no TRUNCATE, no access to `alembic_version`, cannot create roles, run `ALTER SYSTEM`, `COPY ... PROGRAM` or create databases | `scripts/setup_database_roles.py` (idempotent, verifies as the new roles, prints pass/fail only); **`tests/test_database_least_privilege.py` (5 tests, run on every regression)**; every DB-backed batch passes running as `qrscs_app` |
| Migrations | Same superuser | Separate role `qrscs_migrator` owns the database and schema objects; Alembic uses `MIGRATION_DATABASE_URL` when set; default privileges grant future tables to `qrscs_app` automatically | `alembic current` through the migrator = head `d3f7b9c2e5a1`; no migration was run |
| Default login | `config_server.py` fell back to a built-in superuser URL if `DATABASE_URL` was unset | No default: a missing `DATABASE_URL` stops the server with an explicit message | `config_server.py`, `database/connection.py` |
| Administrator credential | In the project `.env` (archived with the project) | Moved to `~/.qrscs/admin.env` (outside the repository, owner-only ACL), used only by the setup script | script output; `.env` holds only the two role URLs |
| Obsolete secrets | Two WSL `.env` copies held a database password and JWT secret that no longer work | Secret values replaced by placeholders in both; non-secret settings kept (two expiry settings that my first pass overwrote were restored to the documented defaults 15 / 7) | audit compared hashes without printing values: both differed from the active ones before the change; neither contains a secret now |
| Source archive | Hand-zipping the folder included `.env` and private keys | `scripts/package_release.py` archives only what Git considers part of the project, refuses secret-shaped names regardless, then validates the finished archive: forbidden names, private-key blocks / cloud keys / JWT-shaped tokens / credentialed database URLs, and **none of this machine's live secret values anywhere**; failure deletes the archive | **`tests/test_release_packaging.py` (23 tests, run on every regression)**; real archive of the final tree: 364 files, 0 env/key/cert/log entries |
| TLS socket teardown | `web/gateway/gateway.py` and `ClientSession.disconnect()` closed a TLS socket while another thread could still be inside `ssl.read` (a use-after-free) | shutdown, wait for the reader/in-flight send to leave, then close (bounded waits) | a loop that crashed the interpreter with a native access violation at its 5th run completed 14 + 30 runs clean afterwards (see limitations: a crash of the same class still occurred once in a test-server thread) |

### Regression evidence (official runner, Python 3.12 venv, real PostgreSQL and Chrome)

| Batch | Passed | Failed | Skipped |
|---|---|---|---|
| crypto_unit | 409 | 0 | 0 |
| device_security | 253 | 0 | 0 |
| messaging_groups_a | 302 | 0 | 0 |
| messaging_groups_b1 | 177 | 0 | 0 |
| messaging_groups_b2 | 194 | 0 | 0 |
| mobile | 104 | 0 | 0 |
| desktop_gui | 197 | 0 | 0 |
| desktop_gui_lifecycle_a | 107 | 0 | 0 |
| desktop_gui_lifecycle_b1 | 36 | 0 | 0 |
| desktop_gui_lifecycle_b2 | 43 | 0 | 0 |
| web_a | 39 | 0 | 0 |
| web_b | 58 | 0 | 0 |
| **Total** | **1919** | **0** | **0** |

The Web batch was split into `web_a` (6 files) and `web_b` (3 files); together
they cover all 9 Web test files exactly once (checked programmatically: no
omission, no duplicate, nothing unbatched). No test was removed, skipped or
weakened. One earlier-in-session figure is superseded: the previous single
`web` batch had 91 tests before the 6 registration tests were added.

Interruptions, recorded separately from application failures: the first full run
of this pass lost its Web batch and stalled for ~10 hours when the laptop
(on battery, 10-minute idle sleep) slept — a session token expired inside
`test_attachment_from_a_previous_session_still_decrypts`; the batch passed when
rerun with the machine held awake. In the final run `device_security` was killed
by a native `Windows fatal exception: access violation` inside `ssl.read` (the
documented crash class; no test failed, the process died, the runner reported no
counts) and passed 3/3 on immediate rerun (253 each).

### Remaining known limitations

1. **Intermittent Web timing failures in long single-process runs — UNRESOLVED.**
   Across 11 full Web-batch runs of this pass's code, 6 passed and 5 had 1–3
   failures; after the login-race fix below, 4 of 5 passed (the failing run had
   3 failures: a null WebSocket, a 'disconnected' status and a wait for a draft
   to save). Every failure was at a connection step shared by many tests, and
   the same shape occurred on the one run of an unmodified export of HEAD.
   Fixed with evidence: a login click lost when it landed before `main.js`
   attached its handlers (2 of 30 page loads before, 0 of 30 after), and the TLS
   teardown ordering above. Not reproducible in isolation: 40 of 40 held
   connections, 30 of 30 setups at 0.4 s or less, and no thread/handle growth
   across a 97-test run. Mitigation: smaller batches and a held-awake machine;
   the residual sensitivity is **not fixed**.
2. **Native `ssl.read` access violation** (documented earlier) can still kill a
   test process; the test-server harness already quarantines what it can.
3. The Desktop and Android clients keep every group-key epoch; the **Web client
   keeps only the newest**, so Web cannot show pre-rotation group history.
4. **Group pictures** do not exist on any platform (schema + protocol change,
   not started — see `feature_parity_matrix.md`).
5. **Android physical validation** (voice/video recording, video playback,
   install and launch of the rebuilt APK) remains deferred; no Android
   evidence was gathered in this pass.
6. `postgresql.conf` still has `listen_addresses = '*'` (pg_hba allows only
   loopback, so it is not reachable from other hosts); not changed because it
   needs a service restart.
7. Profile pictures and bios are not end-to-end encrypted (documented design).

## Reconfirmation — 2026-10-21 (Desktop executable, multi-user acceptance, protocol fixes)

Branch `work/desktop-web-completion-2026-10-20`, based on the preservation commit `3861769`. The changes below are
**uncommitted**; the working tree has not been approved for merge. Status of this section: **automated evidence only — no
manual acceptance has happened yet.**

### Defects found and fixed (each has a regression test that fails without the fix)

| # | Defect | How it was found | Fix | Test |
|---|---|---|---|---|
| 1 | **Login reply distinguished "no such account" from "wrong password".** The wire reply's `errors` carried `User not found.` or `Password verification failed.`, and the Desktop displayed that text, so anyone could learn whether a phone number is registered. | Acceptance scenario (the Desktop's wrong-password text differed from the server's own message) | `server/client_handler.py::handle_login_request` sends the same `{"credentials": "Invalid phone number or password."}` for both. The service still records the distinct reason for its own audit log. **Two existing tests that asserted the old, leaking detail were changed to assert the generic reply** (disclosed on purpose). | `tests/test_login_logout_integration.py::test_a_wrong_password_and_an_unknown_phone_number_look_identical` |
| 2 | **A repeated send (same `client_message_id`) was delivered twice, and a repeated *group* send broke the sender's connection.** The server tried to record the recipient row a second time, violated its unique key, logged a database error, and relayed again. | Acceptance replay scenario | Duplicates are recognised (`persist_message` marks them) and neither re-recorded nor re-relayed, for direct and group messages. | `tests/test_message_replay_idempotency.py` (3 tests; 2 fail on the previous code) |
| 3 | **A browser that logged out or closed its tab stayed "online" on the server** until some unrelated packet made the gateway try a send. | Acceptance presence scenario | `web/gateway/gateway.py` ends the connection as soon as either direction ends. | `tests/test_web_gateway_teardown.py` (2 tests; both fail without the fix) |
| 4 | **About 0.5% of requests sent the instant a WebSocket opened never got a reply** (browser registration/login timeouts; very likely the long-standing intermittent Web failures). | Acceptance registration stress (3 of 60 failed), then reproduced with no browser | Server issues no TLS 1.3 session tickets (`security/tls.py`). | `tests/test_web_gateway_first_request.py` (fails without the fix in 3 of 3 runs) |
| 5 | **The Website never recovered from a server outage.** Its reconnect re-authenticates over a short-lived socket and waited forever for a reply the gateway could never send, so the first failed attempt hung for good ("Reconnecting" indefinitely). | Acceptance outage scenario | `web/client/app.js::_sendAndReceiveOnce` ends when the socket closes or fails or after 30 s. | `tests/test_web_reconnect_after_outage.py` (fails without the fix: "it is hanging") |
| 6 | Web client kept only the newest group key, so older group history was unreadable after a rotation; a late older key could also replace the sending key. | Parity audit | Keys kept and persisted per epoch, chosen by the signed `epoch`, never downgraded. | `tests/test_web_group_key_history.py` (the main test fails on the old client with "a message from before the rotation was dropped") |

User-facing fixes that are not security properties: a user can now **see their own safety number** (Desktop and Website Settings);
Desktop **message and conversation rows and login fields are readable by assistive technology**; the Desktop **brand mark** exists
(the shipped logo file is empty); after a lost connection the Desktop shows a banner with **Sign in again** (it only said
"Disconnected"); the Desktop's unverified-contact **header no longer clips** its buttons and badge at the default window size, and its
**Settings dialog** scrolls instead of pushing Logout/Close off a small screen (the last two found by looking at real screenshots).

### Desktop executable
`scripts/build_desktop_exe.py` → `dist/desktop/QRSCS-Desktop/QRSCS-Desktop.exe` (PyInstaller 6.22.3, Python 3.12, one folder,
316 files, with an icon drawn from the application's brand mark). The script validates its own output on every build: no `.env`,
key, certificate key, log or database file, and no configured live secret value in any file (`tests/test_desktop_exe_build.py`, 11
tests). It contains only client code (server, database, mobile and test modules are excluded) and the public CA certificate.
**Not done:** code signing; a run on a clean machine without this development environment; a build from a different checkout.
The source archive (`scripts/package_release.py`) still builds and validates with every new file (435 files).

### Regression (official runner, Python 3.12 venv, real PostgreSQL and Chrome), 2026-10-21

| Batch | Passed |
|---|---|
| crypto_unit | 420 |
| device_security | 253 |
| messaging_groups_a | 305 |
| messaging_groups_b1 | 177 |
| messaging_groups_b2 | 194 |
| mobile | 104 |
| desktop_gui | 207 |
| desktop_gui_lifecycle_a | 108 |
| desktop_gui_lifecycle_b1 | 36 |
| desktop_gui_lifecycle_b2 | 43 |
| web_a | 44 |
| web_b | 66 |
| **Total** | **1,957 passed, 0 failed, 0 skipped** |

1,919 before this work; **+38 tests, none removed, skipped or weakened** (two assertions in `test_login_logout_integration.py` were
*tightened*, see defect 1). Every `tests/test_*.py` file is in exactly one batch (171 files, checked mechanically). The runner now
prints per-batch and total counts. The Web batches take about 75 s and 193 s (they took 182 s and 550 s before the gateway teardown fix).

**Web timing sensitivity.** Before the fixes, 5 of 11 full Web-batch runs had 1–3 failures. After them, two rounds of five
consecutive runs of both Web batches passed (20 of 20 batch runs; 108 tests each time) — round 1 after the TLS fix, round 2 after
the gateway fix — and the final full regression passed again. If the old failure rate (about 45% per full run) had been unchanged,
five clean runs in a row would have had a chance of about 5%. This is strong statistical evidence, **not a proof**: the mechanism
(tickets arriving while the gateway's reader thread is blocked and another thread starts the first write) is an inference from the
controlled comparison, not something observed directly, and the Website reconnect change (defect 5) was made after round 2.

### Multi-user acceptance (`tests/acceptance/`; built EXE + Chrome; isolated database `qrscs_accept`, role `qrscs_app`)

* **Accounts:** standing populations of 10 (8 Website + 2 Desktop), 20 (17 + 3) and 30 (26 + 4), **every one registered and logged in
  through the real forms** (10/10, 20/20, 30/30). Each run ends with 65 / 75 / 85 accounts in the database: the population plus the
  accounts the scenarios create themselves, of which **8 are created by protocol clients** for the authorization tests and the rest
  through the Website and Desktop registration forms. Registration through the Website form under repetition: 100/100 after the TLS
  fix (and 200/200 earlier; 3 of 60 failed before).
* **Scenarios:** 32 (+1 stress test run separately). **32/32 passed at 10, at 20 and at 30 standing accounts**; at 30 the concurrency
  scenario runs 15 simultaneous conversations (11 Website–Website, 4 Website–Desktop). Per run: ~89–169 messages, ~32–42
  conversations. Earlier failures were fixed before these runs; the ones that were the harness's own fault are listed in `PROJECT_STATE.md`.
* **Confidentiality scan (runs last):** nothing the run sent or created appears at rest on the server side. Scanned in the final
  run: 713,873 bytes of server/gateway logs, 436 database rows across every table (89 encrypted messages), 2 encrypted blobs, against
  439 patterns (89 message texts, 65 passwords, 285 key-material patterns from the browsers' identity secret keys and conversation
  keys, 2 attachments), each in plain, hex and base64 form — **0 hits**. The scanner is itself tested against planted values. Desktop
  key material is in an encrypted key store and is not extracted, so for the Desktop only plaintext and passwords are checked.

### Remaining limitations and residual risks (not hidden)

1. **Account enumeration is closed only for credential errors.** A *locked* or *inactive* account still gets a distinct message, and a
   login for an unknown number is probably faster than one that runs Argon2 (timing). Neither was changed.
2. The Desktop **Devices**, **Inbox** and group-member dialogs hold buttons inside list rows that assistive technology cannot reach
   (and UI Automation cannot drive); covered by widget-level tests and by manual acceptance, not by the UI-driven suite. Desktop
   sending of attachments (the operating system's file dialog) and Desktop message context menus are not UI-automated either.
3. The Desktop does **not** reconnect by itself (it does not keep the password); it offers "Sign in again". The Website gives up after
   about two minutes of failed attempts.
4. Web **device key sync** sends only a conversation's current key: a newly linked browser device cannot read pre-rotation history.
5. The executable is **unsigned**; Windows may warn on first run. It has only been run on this machine.
6. Group pictures remain unimplemented everywhere; Android is paused and unvalidated on hardware (unchanged).
7. All acceptance traffic is loopback on one machine; real network conditions are not exercised. No manual acceptance has been done.

## Reconfirmation — 2026-10-21, second window (Phase 19.24: Desktop/Website UI parity, chat media, group events and attachments)

Same branch, still **uncommitted**. Status: **automated evidence only — no manual acceptance has happened.** The requirement-by-requirement
map is `docs/architecture/ui_parity_requirement_map.md`; user-visible behaviour is in `feature_parity_matrix.md`.

### What changed that bears on security

| Area | Change | Why it does not weaken the model | Test |
|---|---|---|---|
| **Display names vs identity** | `users.username` remains the unique internal handle every packet is routed and authorized on; `display_name` (already a column) is non-unique and only ever shown. A taken name gets a distinct handle (`name_<6 hex>`). New `display_names_request` / `change_display_name_request` carry names only | No key, signature, route or permission is derived from a display name. A namesake cannot receive another user's message. No destructive migration; existing users untouched | `test_duplicate_display_names.py` (a message to one namesake never reaches the other), `test_desktop_display_names.py` |
| **Account-exists registration message** | Registration answers "An account with this phone number already exists. Please log in." | Registration already revealed the duplicate (it must refuse it); **login keeps the single generic reply** for unknown number and wrong password | `test_registration_integration.py`, `test_login_logout_integration.py` |
| **Profile-picture upload** | `security/image_validation.py` checks the format (PNG/JPEG/WebP/GIF), size and 1–8192 px / 40 M-pixel limits **on the server from the image header**, whatever the client claims | The browser/Desktop checks are convenience only; a hostile client is refused the same way. Pictures remain not end-to-end encrypted (documented design) | `test_profile_picture_validation.py`, `test_mobile_settings.py` (now uploads a real PNG; the old fake bytes are correctly refused) |
| **Reply references** | A reply names the original by its stable message id. The server accepts it only if that message belongs to the **same conversation** the sender can read, drops it otherwise, and stamps the stored id on the relayed packet | A reply cannot be used to probe or quote a message from another conversation; clients never resolve a reply by matching text | `test_reply_reference_integrity.py` |
| **Website refuses to send to a changed key** | `sendMessage` / `sendAttachment` refuse a peer in the KEY_CHANGED state until it is re-verified; the "Verified" line disappears the moment the key changes | Trust is not silently preserved across a key change (Desktop already behaved this way) | `test_web_messenger_layout_and_parity.py` |
| **Group membership events** | New table `group_events` (migration `e8c2a6d4f1b9`). The server writes a row in the **same transaction** as the membership change, using the authenticated actor and the member from its own records (snapshot of the handles). Delivered only to current members and only for events since they joined (a rejoin resets the start); once, in order | A client cannot inject or forge an event; text in a packet is never trusted; non-members and removed members receive nothing | `test_group_membership_events.py`, `test_desktop_group_events.py`, `test_web_group_attachments_and_events.py` |
| **Group attachments** | Website gained attach/record in the group composer. Same pipeline as before: **one `messages` row + `message_recipients`**, existing payload adapters, the group key and attachment encryption; blobs are client-side ciphertext; history and blob download are membership-gated | No plaintext group key or attachment reaches the server; a removed member or a non-member can neither fetch nor decrypt; a retry is idempotent by `client_message_id` | `test_group_attachments.py`, `test_desktop_group_attachments_gui.py`, `test_web_group_attachments_and_events.py` |
| **Desktop voice/video** | The recorder now states its format (AAC/MP4 voice, H.264+AAC/MP4 video) and the player plays **the decrypted bytes held in memory (a `QBuffer`; nothing is written to disk for playback)**; the encrypted send path is unchanged | Encryption in transit and at rest is unchanged; undecodable media shows an error and does nothing else | `test_media_playback_interop.py` (Chrome↔Qt in both directions through the server) |
| **Gateway address field** | Collapsed under "Connection settings" rather than removed | No change to what the page may connect to; TLS and origin rules are the gateway's | `test_web_chat_settings_and_recorder.py` |

### Tests changed (disclosed; none weakened or removed)

Each changed because the behaviour they described was *deliberately* changed by a requirement, and each still asserts the replacement
behaviour: typing a name in the Website search box no longer opens a chat (28 sites now press Enter); own-safety-number and profile-picture
tests now use their new locations; the mobile settings test uses a real PNG because the server now validates; the Website lifecycle suite's
"Establish key" helper tolerates the key already being established and the pin label reads "Pinned by you". The acceptance drivers read the
own safety number through the Verify Identity window. The `desktop_gui` regression batch was split in two (`desktop_gui`, `desktop_gui_b`)
because one process after ~170 Qt tests hit the documented PySide6 resource-accumulation access violation (every file passes alone);
the timeout was not changed.

### Regression (official runner, Python 3.12 venv, real PostgreSQL and Chrome), 2026-10-21 second window

| Batch | Passed |
|---|---|
| crypto_unit | 421 |
| device_security | 284 |
| messaging_groups_a | 325 |
| messaging_groups_b1 | 177 |
| messaging_groups_b2 | 194 |
| mobile | 104 |
| desktop_gui | 162 |
| desktop_gui_b | 103 |
| desktop_gui_lifecycle_a | 108 |
| desktop_gui_lifecycle_b1 | 36 |
| desktop_gui_lifecycle_b2 | 43 |
| web_a | 44 |
| web_b | 74 |
| web_c (new) | 28 |
| media_interop (new) | 15 |
| **Total** | **2,118 passed, 0 failed, 0 skipped** (1,957 before this window) |

185 test files, each in exactly one batch (checked mechanically). An earlier full run of this window had 3 Website failures (the
test helper clicked a button that is hidden once the key exists; a pin label) and one Desktop batch crash (above); both were fixed and the
complete run was repeated from the start.

### Limits and things not verified (not hidden)

1. **Real microphone/camera were never used.** Recorder tests use Chrome's fake devices and Qt synthetic tone/test-pattern inputs; audibility
   was proven by decoding (sample energy), not by a person listening. The manual checklist covers a real recording.
2. **Group events and attachments for removed members** are covered at the server and in both clients; the owner should still try
   add → remove → re-add by hand.
3. A group attachment sent by a Website member to a group containing only Android members is not validated (Android is paused; no device).
4. The Desktop "Request to add a member" button (non-admin) only creates a request; the server decides, and the admin approves in the Inbox.
5. Server-side image validation reads the header: it bounds size and dimensions but is not a malware scan; pictures are not encrypted.
6. Unchanged limits from the section above still apply (unsigned EXE, loopback only, enumeration closed for credential errors only).


## Reconfirmation — 2026-10-22 (group member addition, contact-request approval, key follow-through)

Same branch, still **uncommitted**; automated evidence only. Reported by the owner during manual acceptance: a person never
spoken to could not be added to a group and read it; the approval workflow did not finish securing the connection.

| # | Defect (root cause) | Fix | Test |
|---|---|---|---|
| 1 | **A group member added before verification never got the key.** `_distribute_group_key()` (Desktop) and `_distributeGroupKey()` (Website) skip a recipient who is not verified (correct) but forgot the skip; nothing re-sent the key once verification happened. A member's own late verification of the holder was not recovered either: the existing recovery request is for direct conversations only | The skip is remembered and retried after the explicit verification (or when an already-verified member's identity is first seen). A member who verifies the holder late sends `group_key_request` (new, additive packet) which reuses `group_key_rotation_required` | `tests/test_group_key_late_verification.py` (9; the first five failed before the fix) |
| 2 | **The Website never completed the requester's half of an approved request** (the Desktop did) and never secured the connection | `_completeRequesterSideVerification()` + `secureDirectConnection()`, with honest `establishing` / `ready` / `failed` reporting | `tests/test_web_late_verification_and_approval.py` (8) |
| 3 | **Approving, or auto-completing, a changed identity re-trusted it** — `get_peer_fingerprint_for_verification()` returns the NEW, never-compared fingerprint for a KEY_CHANGED peer, so both the approver's Approve and the requester's automatic completion would have verified it | Both refuse for KEY_CHANGED on Desktop and Website; the person must verify again by hand | `tests/test_contact_request_approval_flow.py` (8; the requester-side one failed before the fix) |
| 4 | Phone number entered when adding to a group was not resolved or shown | Looked up, shown by name and @handle with its verification state before Add; unknown numbers add nothing; a phone number is never sent as a username; **Ask to verify** sends a verification request without opening a conversation | `tests/test_web_group_member_lookup.py` (6) |
| 5 | A group member could not tell why a group was unreadable | Group info (Website and Desktop) shows each member's verification state, a **Verify** action, and a notice while this account lacks the group key | the files above |

**Authorization of the new packet.** `handle_group_key_request()` derives the requester from the authenticated socket, requires
ACTIVE membership of that group (a non-member, a removed member and a malformed id are all silent, server-log-only rejections),
sends only the existing rotation instruction for the current epoch with the requester as the sole recipient, and asks the admin
only (see `inbox_approval_workflow.md` §4b for why). The holder still wraps a key only for a VERIFIED identity and the receiver
still accepts one only from a VERIFIED sender and only with a valid ML-DSA signature; the server relays ciphertext it cannot read.
A member removed before being verified is never sent the key (the retry re-checks membership). Tests cover each of these.

**Regression run after these changes** (official runner, Python 3.12, real PostgreSQL and Chrome): messaging_groups_a 341,
messaging_groups_b1 177, messaging_groups_b2 194, device_security 284, desktop_gui 162, desktop_gui_b 117,
desktop_gui_lifecycle_a 108, _b1 36, _b2 43, web_a 44, web_c 42 — all passed. web_b: 73 passed, **1 failed**
(`test_web_bio_can_be_edited_and_is_seen_by_desktop`): a race inside the test (it waited for the server to hold the bio and then
read the page's hint without waiting for the page) that passed 2 of 3 reruns before and 6 of 6 after the test was changed to wait
for the page; nothing in the bio path was touched. Two changes were made after the batches ran (the admin-only selection above,
and that test), so the batches were **not** repeated in full afterwards: the 57 group/inbox tests and the 14 new Website tests were.
The unchanged mobile, crypto_unit and media_interop batches were not run this round.

**Limits (not hidden).** A person who is offline has no observable identity and cannot be verified, so cannot receive the key until
they are online and both sides have verified. If the admin is offline, a member's key request waits until the admin is back or the
next verification. The Desktop establishes the direct session key at the first message (existing design), not at approval. A
verification request does not carry the group it was made from. No manual acceptance of any of this has happened.


## Reconfirmation — 2026-10-22, third part (joining a group by invitation; Desktop look and navigation)

Same branch, still **uncommitted**; automated evidence only.

### Group membership now needs the person's own approval (new `group_invitation` inbox type; no migration)

* `inbox_notifications.type` is an unconstrained `String(32)`, so the new value needs no migration; `status` gains `expired`.
* **Authorization.** Only the recipient (the invitee) can decide an invitation; the inviter, an outsider and a bogus id are
  indistinguishable and rejected silently. Approval re-checks, at that moment, that the invitation is not stale (14 days) and
  that the inviter is still an active member, and re-applies the block check in both directions; otherwise it is marked expired
  and adds nobody. A second decision on the same item is a no-op.
* **Compatibility.** The behaviour is selected by an additive `consent_invitations` flag sent by the Desktop and Website; a client
  that does not send it (Android, the existing session-level API) keeps the immediate add. An invitee on Android is not
  validated (see `inbox_approval_workflow.md` §4c).
* **Trust is not manufactured.** Approving an invitation verifies the inviter only from the identity the approving client has itself
  observed, never from the notification; it refuses (and sends nothing) if that identity was not observed or its key changed.
  The inviter's side does the same when the approval arrives. This reuses, and does not widen, what a verification request already
  did. Keys are still only wrapped for, and accepted from, a VERIFIED identity.
* **Key holder.** `_dispatch_pending_rotation_if_needed()` now asks the group's admin first: members invited this way have verified
  the admin, not necessarily one another, so a non-admin distributing a new epoch could not reach them all.

| Test | Result |
|---|---|
| `tests/test_group_invitation_flow.py` (12): only approvers join; deny/ignore; duplicate and repeat decisions; outsider/inviter cannot decide; blocks; expiry; inviter left; non-admin needs admin then candidate; admin deny invites nobody; changed identity refused; legacy immediate add unchanged; messages both ways after approval | passed |
| `tests/test_web_group_invitations.py` (3), `tests/test_desktop_group_invitations.py` (3): the Inbox item, toast/notice, badge and Approve/Deny through the real windows, Website↔Desktop and Website↔Website | passed |

### Desktop look and navigation (Website parity)

A light and a dark theme from the Website's own tokens (`gui/styles.py`; chosen in Settings → Appearance, applied at the next start;
automated offscreen runs ignore a saved choice so they stay deterministic), the rail with a name under each icon and Log out, a
connection pill, All/Unread/Direct/Groups chips, the search box that looks a phone number or @handle up on Enter (typing only filters),
the list showing a handle only for namesakes, a non-blocking notice banner, and a Website-style Chat settings menu, gallery, file/voice
cards and picture editor (earlier this day). `tests/test_desktop_theme_and_navigation_parity.py` (7) and `tests/test_desktop_website_parity_fixes.py` (14).
Two old assertions changed deliberately: the rail is no longer icon-only; the Website's group tests that assumed an immediate add now approve the invitation.

**Regression for this part** (official runner, Python 3.12, real PostgreSQL and Chrome): crypto_unit 421, device_security 284, messaging_groups_a 354,
messaging_groups_b1 177, messaging_groups_b2 194, mobile 104, desktop_gui 162, desktop_gui_b 127, desktop_gui_lifecycle_a 108, _b1 36, _b2 43, web_a 44,
web_b 74, web_c 45, media_interop 15 = **2,188 passed**. The first full run had two Website page-load failures (`web_a`: a `Page.goto` timeout in a setup
fixture; `web_b`: the Login button still disabled), each passing 3 of 3 alone and both batches passing in full on a rerun. The UI-driven acceptance suite on the
rebuilt executable: **33 passed**, with the Desktop member's approval done through the real Desktop Inbox. Not run by anyone: manual acceptance, Android,
a real microphone or camera.
