# Media Security Architecture (Phase 19.24)

This document covers the existing, unchanged media security model
(images/files) every new payload type this phase adds must remain
compatible with, and how Voice/Video Messages — added later in this
same phase, after an earlier revision of this document had described
them as deliberately out of scope — were actually implemented within
that same, unmodified architecture.

## Existing media security model (images/files) — unchanged

- **Classification**: `domain/payload_type.py::classify_attachment()`
  picks `PayloadType.IMAGE` or `PayloadType.FILE` by MIME type, never
  by trusting a client-claimed type.
- **Encryption**: `payload/file_adapter.py::FilePayloadAdapter` — the
  same AES-256-GCM, same per-conversation epoch key, same nonce-per-
  encryption guarantee as every other payload type. No separate
  "media" key material exists anywhere.
- **Storage routing**: `domain/payload_type.py::BLOB_STORAGE_PAYLOAD_
  TYPES` — FILE/IMAGE ciphertext is written to `storage/encrypted_
  blob_store.py` (a random-filename blob directory) instead of
  inline in `messages.ciphertext`; `messages.blob_ref` is an opaque
  pointer. The server still never has plaintext — the blob is
  ciphertext at rest, exactly like an inline message.
- **Size enforcement**: server-side, unconditionally
  (`config.MAX_ATTACHMENT_CIPHERTEXT_BYTES`, checked in `persist_
  message()` **before** `store_blob()` is ever called) — never only a
  client-side check a modified client could skip.
- **Lazy delivery**: history never inlines FILE/IMAGE ciphertext; a
  client fetches it on demand via `blob_download_request`, resolved
  server-side by `message_id -> blob_ref -> membership`, never a
  client-claimed path.

## What this phase added on top, and why it needed no new media
security work

**Reactions** (`payload/reaction_adapter.py`, `PayloadType.REACTION`)
are a few bytes of UTF-8 text (typically one emoji) — deliberately
routed through the SAME `TextPayloadAdapter`-style inline-ciphertext
path (`BLOB_STORAGE_PAYLOAD_TYPES` was deliberately never extended to
include `REACTION` — `domain/payload_type.py`'s own long-standing
comment already anticipated this exact case: "a future payload type
with no reason to leave the database (e.g. a small reaction/read-
receipt marker) should not be silently routed to blob storage just
because it isn't TEXT"). No new storage backend, no new size limit
needed (a reaction's serialized size is bounded by an emoji/short
string's own natural size, orders of magnitude under any attachment
limit).

**Edit** re-encrypts a message's EXISTING payload_type in place —
scoped to TEXT only this phase (see `message_lifecycle.md`'s own
scope note) — so it reuses `TextPayloadAdapter` unchanged. It touches
no blob storage at all.

**Forward** re-uses the EXISTING send pipeline
(`send_chat_message`/`send_attachment`/`send_message`) against a new
target conversation's own key — for an attachment, this means the
already-decrypted local plaintext bytes are re-encrypted and
re-uploaded through the SAME `FilePayloadAdapter`/blob-store path a
fresh send already uses; the size limit, classification, and blob
lazy-delivery model apply identically. No new code path, so no new
attack surface.

**Delete for everyone** on a blob-stored message
(`handle_message_delete_for_everyone()`) calls the EXISTING
`storage.encrypted_blob_store.delete_blob()`, best-effort, after the
database row is already committed as deleted — a blob-deletion
failure is logged as a storage-hygiene issue, never surfaced as a
failed deletion to the sender (the row itself, which is what every
client-facing "is this deleted" check reads, is already correctly
updated regardless).

## Voice and Video Messages (added later in Phase 19.24)

`PayloadType.VOICE`/`PayloadType.VIDEO` exist, both added to
`BLOB_STORAGE_PAYLOAD_TYPES` and to `_BINARY_PASSTHROUGH_TYPES`
(`domain/payload_serializer.py`) — and registered against the exact
same `FilePayloadAdapter` FILE/IMAGE already use in both `client/
session.py`'s and `mobile/session.py`'s `_payload_adapters` dict. No
new adapter class, no new key material, no chunked-envelope design —
a recorded clip is exactly as large as this project's existing
`MAX_ATTACHMENT_SIZE_BYTES`/`MAX_ATTACHMENT_CIPHERTEXT_BYTES` bounds
already allow, so the earlier-anticipated need for a chunked, per-
chunk-nonce envelope never materialized: `gui/media_recorder_dialog.py`
caps a recording at 120s (voice) / 60s (video) precisely so it stays
well inside the existing single-ciphertext-blob bound, rather than
inventing a new streaming/chunking design this phase's own mandate
explicitly did not require if the existing bound already covers it.

**Recording, per platform:**
- **Desktop**: `PySide6.QtMultimedia` (`QMediaCaptureSession` +
  `QAudioInput`/`QCamera` + `QMediaRecorder`) — already part of this
  project's own pinned `PySide6-Addons` dependency, no new dependency
  added. Recording necessarily writes to a real local temp file
  (`QMediaRecorder` has no in-memory recording mode) — the one place a
  voice/video message's plaintext briefly touches local disk before
  encryption, exactly like any OS-level recording API; the temp file
  is deleted the moment `send_attachment()` has read its bytes into
  memory (`gui/chat_window.py::handle_recorded_media_selected()`).
- **Web**: the browser's own native `getUserMedia()`/`MediaRecorder`
  APIs (`web/client/main.js::openMediaRecorderModal()`) — never
  touches disk at all; the recorded `Blob` lives only in the page's
  own memory until `sendAttachment()` encrypts and sends it.
- **Mobile**: real `android.media.MediaRecorder` via `pyjnius`
  (`mobile/app.py::_open_media_recorder_popup()`), the same low-level
  bridging approach this project's own Android file picker
  (`_pick_file_android()`) and save picker (`_save_attachment_
  android()`) already use — added in this phase's closure pass,
  replacing an earlier `plyer`-based attempt that crashed outright on
  this project's own Windows dev machine (`OSError: access violation`
  from its Windows audio backend) and was rejected rather than shipped
  broken. Voice uses `AudioSource.MIC` (no camera/surface needed);
  video uses `AudioSource.MIC` + `VideoSource.CAMERA` with a real
  native `android.view.SurfaceView` attached directly to
  `PythonActivity`'s own view hierarchy for the camera preview (Kivy's
  own window has no per-widget Surface the camera stack can target).
  Both request the real Android runtime permission
  (`RECORD_AUDIO`/`CAMERA`, both declared in `buildozer.spec`'s
  `android.permissions`) before ever calling `MediaRecorder`, and
  report denial honestly rather than silently failing. The recorded
  file is read into memory and deleted immediately, then handed to the
  exact same `_send_attachment()` encrypt/send pipeline every other
  attachment already uses — no new encryption code was needed, only a
  real source of bytes.

  **Honest verification status**: this was written against Android's
  documented `MediaRecorder` API and this project's own established
  pyjnius conventions, and the APK builds successfully with it
  included (confirmed — see the final report's APK section). It has
  **not been physically run on an Android device**, because this
  development environment has no physical device or emulator attached
  (checked directly via `adb devices`, repeatedly, throughout this
  phase). This is stated plainly rather than implied working: the code
  is real and complete, not a placeholder, but "builds successfully"
  and "runs correctly on real hardware" are different claims, and only
  the first one has actually been verified here.

**Playback, per platform:**
- **Desktop**: `QMediaPlayer.setSourceDevice(QBuffer, hintUrl)` plays
  DIRECTLY from the already-decrypted bytes already held in memory —
  never writes decrypted plaintext to disk merely to play it back
  (`gui/message_widget.py::FileMessageBubble`'s voice/video branches).
- **Web**: native `<audio controls>`/`<video controls>` elements from
  a `Blob`/`URL.createObjectURL()` — also never touches disk.
- **Mobile**: voice plays for real via `kivy.core.audio.SoundLoader`
  (this Kivy build's `audio_sdl2` backend is confirmed working) —
  decrypted bytes are written once to this app's own private temp
  directory first, since SoundLoader has no in-memory-buffer playback
  API the way Qt's `QBuffer` does. Video does **not** play in-app: this
  Kivy build's video backend is `null` (`video_ffmpeg`/`video_
  ffpyplayer` both unavailable) — rather than ship a "player" that
  cannot actually decode anything, a received video is honestly
  Save-only, exactly like a plain file.

**Classification**: `domain/payload_type.py::classify_attachment()`
now also maps an `audio/*`/`video/*` MIME type (read from the real
extension `gui/media_recorder_dialog.py`/the browser's own recorder
gives the file — `.m4a`/`.mp4`/`.webm`) to `VOICE`/`VIDEO`; `web/
client/app.js::classifyAttachment()` is this same client's own JS-side
equivalent, preferring the browser-reported `mimeType` over filename
extension where available.

**Device revocation**: voice/video messages are ordinary attachments
sent through the exact same `chat`/payload relay path the pre-existing
L-1 device-revocation closure already covers (`server/client_
handler.py`'s single sender-side `is_device_bound_and_authorized()`
check on that shared dispatch point) — no new enforcement code was
needed. Proven explicitly, not merely assumed, on both the send AND
receive side, for both media types: `tests/test_device_identity.py::
test_revoked_device_cannot_send_a_voice_message`,
`::test_revoked_device_cannot_send_a_video_message`, and
`::test_revoked_device_cannot_receive_a_voice_or_video_message`.

## No plaintext leakage — audited this phase

Searched this phase's own new code (server handlers, repositories,
adapters) for anything that could leak reaction/edit plaintext:

- Server logs (`state.logger.info(...)` calls in the new handlers)
  log only `message_id`/`username` — never ciphertext, never a
  decrypted reaction/edit string (the server never possesses either).
- No new database column stores plaintext — `message_reactions.
  ciphertext` and the edited `messages.ciphertext` are both, as their
  names say, ciphertext.
- No new temporary file, debug dump, or analytics hook was added.

See the final report's "Security audit results" section for the
full, fresh, whole-repository secrets/plaintext sweep performed at
the end of this phase.
