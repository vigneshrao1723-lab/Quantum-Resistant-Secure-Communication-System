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
