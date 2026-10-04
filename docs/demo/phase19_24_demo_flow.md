# Phase 19.24 Project-Guide Demo Flow

A practical 10–15 minute walkthrough of the current feature set for a
project guide/examiner. This is a curated subset, not the full 40-item
acceptance checklist — that checklist is `docs/architecture/security/
feature_security_matrix.md`, verified by the automated test suite, not
by a live demo. Nothing below should be improvised differently from
this script; every label quoted here is the real, current UI string
(verified against `gui/chat_window.py`, `gui/message_widget.py`,
`gui/input_bar.py`).

## Before the room: start the stack

From the repository root, three processes, each in its own terminal:

```bash
venv/Scripts/python.exe -m server.server
venv/Scripts/python.exe -m web.gateway.gateway --host 127.0.0.1 --port 8765
cd web/client && venv/Scripts/python.exe -m http.server 8080 --bind 127.0.0.1
```

Then two Desktop clients for the live two-party demo:

```bash
venv/Scripts/python.exe main.py      # "Alice"
venv/Scripts/python.exe main.py      # "Bob"
```

And a browser tab at `http://127.0.0.1:8080` for the Web client leg
(Demo 14). Register two fresh throwaway accounts ahead of time (e.g.
`demoalice`/`demobob`) so registration isn't live-demoed under time
pressure — login is still live.

## 1. Login

Log in as `demoalice` on one Desktop window. **Shows**: Argon2id
password verification, a JWT issued, the main window opening with the
conversation list on the left.

## 2. Main dashboard

Point out the conversation list (left), the chat header (peer name,
online/last-seen presence subtitle, Verify Identity button, pinned-
messages/search/gallery/wallpaper header buttons), and the composer at
the bottom. **Says**: this one window is the entire client — no
separate admin/settings app.

## 3. Direct message

Open a direct chat with `demobob` (already logged in on the second
window). Type and send a message; show it arrive on Bob's window in
under a second. **Property demonstrated**: real-time relay through the
server, which never sees plaintext (point at the status bar's active
algorithm indicator).

## 4. Image/file transfer

Composer's paperclip (📎) attach button opens the attachment menu:
**"🖼️ Photo / File"**,
**"🎤 Voice Message"**, **"🎬 Video Message"**. Pick Photo/File, send an
image. **Shows**: the bubble renders the image inline on both sides;
open it full-size via the image viewer.

## 5. Reply

Right-click a message bubble → **"Reply"**. Type a response; show the
quoted-original preview rendered above the new bubble on both windows.

## 6. Edit

Right-click a message Alice sent → **"Edit"**. Change the text, resend.
**Shows**: Bob's window updates live; mention this is only offered on
sent messages (menu omits Edit for Bob's own view of Alice's message).

## 7. Delete

Right-click a message → show the menu offers **"Delete for me"** (and,
for your own messages, **"Delete for everyone"**). Pick "Delete for
everyone"; a confirmation dialog appears — confirm it. **Shows**: the
message disappears on both windows, not just the sender's.

## 8. Reaction

Right-click a message → **"React …"** → pick an emoji. **Shows**: the
reaction appears under the bubble on both windows immediately.

## 9. Group creation/message

From the conversation list, create a new group, add `demobob` as a
member, send a group message. **Shows**: group messaging reuses the
same encrypted pipeline — point out the group key distribution log
line in the status/debug output if visible.

## 10. Verification

Click **"Verify Identity"** in the chat header. **Shows**: the combined
identity fingerprint dialog; read a few characters aloud on both
windows to simulate an out-of-band comparison, then confirm on both
sides — button changes to **"Re-verify"**. **Property demonstrated**:
trust is an explicit human decision the server cannot forge or
shortcut (never automatic).

## 11. Device management

Click the **"Devices"** button above the conversation list (next to
**"Settings"**). **Shows**:
the list of authorized devices for the logged-in account; point out
that revoking a device here immediately cuts that device off from new
traffic (don't actually revoke the device you're demoing from).

## 12. Security architecture explanation

Switch to slides/whiteboard or `docs/architecture/security/
security_architecture.md`: the three-layer model — ML-KEM-768 session
establishment, ML-DSA-65 origin authentication, AES-256-GCM content
encryption — and the trust boundary (server is an untrusted relay,
never holds a private key or a session key).

## 13. ML-KEM / ML-DSA / AES-GCM / Argon2id explanation

Run the benchmark live for a concrete, measured number:

```bash
python -m benchmark.benchmark_ml_dsa
```

**Shows**: real key generation/signing/verification timings and the
primitive's key/signature sizes (1952/32/3309 bytes) — not a slide
claim, a live measurement against this project's actual implementation.

## 14. Web client demonstration

In the browser tab, connect as a third account (or re-use `demobob`
from a second identity) via the **Gateway URL** field
(`ws://127.0.0.1:8765` by default). Send/receive a message with the
Desktop Alice window. **Shows**: the same protocol, same encryption,
reaching a completely different client implementation — point out the
gateway is a transport bridge only (`web/gateway/gateway.py`'s own
docstring: it never decrypts or inspects ciphertext fields).

## 15. Cross-platform message demonstration

With the Web tab and Alice's Desktop window both open on the same
conversation, send one message from each direction and show both
arrive correctly on the other platform — the single clearest "this is
really interoperable, not two separate demos" moment to end on.

---

**What this demo does not attempt to show live** (by design, per the
mandate's own "don't demo every edge case live" instruction): message
search, pinned messages, drafts, mute/archive, typing indicators,
wallpapers, the media gallery, block/unblock, retry/idempotency, and
voice/video recording/playback. All of these are real, implemented,
and covered by the automated acceptance suite (see the feature
security matrix) — they're omitted here only to keep the live demo
inside its time budget, not because they're unready. If the guide asks
to see one of these specifically, any of them takes under a minute to
show from the header buttons or the attachment menu.

**Android**: do not promise a live on-device demo unless a physical
device is actually connected and paired at demo time (checked via
`adb devices -l` immediately beforehand) — see the feature security
matrix's Android section for the current, honest hardware-availability
status. If no device is available, show the APK build artifact and
installed-app screenshots from `physical_validation_evidence/` instead
of claiming a live run.
