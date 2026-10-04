# Mobile Client (Phase 19)

A genuine, protocol-compatible client of the existing server -- real
TLS+TCP socket, real 4-byte-length-prefixed framing, real ML-KEM-768/
ML-DSA-65/AES-256-GCM -- not a simplified or bridged reimplementation.
Uses the SAME crypto/protocol/storage Python modules `client/session.py`
(desktop) already ships, imported directly rather than ported to a
second language, unlike the web client (which had no choice: a browser
cannot import Python).

## Architecture map

```
Desktop client (gui/ + client/session.py, PySide6)
    |
    v
existing protocol (utils/protocol.py, utils/network.py)
    |
    v
server (server/, TLS+TCP)
    |
    v
existing database/storage (database/, storage_blobs/)

Web client (web/client/, vanilla JS)
    |
    v
gateway (web/gateway/gateway.py -- WebSocket <-> TCP bridge,
         needed because a browser cannot open a raw TCP socket)
    |
    v
existing protocol/server (unchanged)
    |
    v
existing database/storage (unchanged)

Mobile client (mobile/, Python + Kivy)
    |
    v
existing protocol/server -- DIRECTLY, no gateway needed
    |            (Python has raw socket access, exactly like the
    |             desktop client -- see mobile/session.py::connect())
    v
existing database/storage (unchanged)
```

No server, protocol, database, or gateway code was modified for this
phase. `mobile/` is purely additive.

## Reconnaissance findings (Step 1, before any code was written)

- No pre-existing `mobile/`, `android/`, `ios/`, `flutter/`, or
  `react-native/` directory anywhere in the repository.
- No Node.js, npm, Gradle, adb, or Android SDK/NDK installed in this
  environment (`ANDROID_HOME`/`ANDROID_SDK_ROOT` both unset) -- ruled
  out React Native, Capacitor/Ionic, and a native Kotlin/Java project
  as buildable choices HERE (all three need at least one of those
  toolchains; none is installable without internet access to a
  package/SDK manager this environment also does not have configured
  for Android specifically). Flutter's own SDK is likewise absent.
- Python 3.12 and a working `pip` (with real PyPI access) ARE
  available -- the same interpreter the desktop client and entire test
  suite already run on.
- `client/session.py`'s only non-portable dependency is `PySide6.
  QtCore.QObject`/`Signal`, used purely for its event mechanism.
  Everything else it imports -- `crypto.*`, `utils.protocol`,
  `utils.network`, `storage.secure_key_store.SecureKeyStore`,
  `payload.text_adapter`/`file_adapter`, `domain.*`, `security.tls`,
  `client.receiver.receive_messages` -- has zero Qt/GUI coupling
  (confirmed by grep across the whole tree before writing anything).
  `client/receiver.py::receive_messages(session)` in particular is
  duck-typed against a `session` object's own attributes/methods, so
  it is reused UNCHANGED by the mobile client too.

## Chosen stack

**Python 3.12 + Kivy 2.3.1**, targeting Android via `buildozer`/
python-for-android (industry-standard for shipping a Python+Kivy app
to Android; `buildozer.spec` at the repo root is the real, complete
build configuration for it).

**Why, given the environment constraints above:**

1. It is the ONLY option this environment could actually install and
   run any part of (`pip install kivy` succeeded immediately, using
   prebuilt Windows wheels -- no compiler needed; verified with a real,
   successful `import kivy` and a real, on-screen-capable `App.build()`
   call that found and initialized a genuine OpenGL window in this
   environment, not merely a headless mock).
2. It lets `mobile/session.py` **import the project's own real crypto
   modules directly** (`crypto.kyber`, `crypto.ml_dsa`, `crypto.aes`,
   `crypto.key_manager`, `crypto.identity_protocol`, `crypto.
   message_protocol`, `crypto.group_key_protocol`, `crypto.
   device_protocol`) instead of porting them to a second language --
   a STRONGER interoperability guarantee than the web client has
   (which needed a byte-exact JS port, proven in `tests/
   test_web_client_crypto_interop.py`). There is nothing to prove
   byte-exact here: it is the identical Python bytecode desktop
   already runs, executed by the same interpreter.
3. It also reuses `storage.secure_key_store.SecureKeyStore` (the
   desktop's own encrypted local persistence, Argon2id + AES-256-GCM)
   completely unmodified, `payload.text_adapter`/`file_adapter`
   completely unmodified, and `client.receiver.receive_messages`
   completely unmodified -- the smallest possible amount of genuinely
   new code for the largest possible amount of already-tested reuse.
4. It does not require going through `web/gateway/gateway.py` --
   Python has raw socket access, so the mobile client speaks the
   REAL wire protocol directly, exactly like the desktop client, which
   is arguably a MORE faithful "real client" than the web client's own
   necessarily-bridged design.
5. "Do not introduce a huge dependency stack unnecessarily" (this
   phase's own instruction): Kivy is one pip package; React Native/
   Capacitor would need an entire npm/Node ecosystem this environment
   does not have at all, and a native Kotlin project would need the
   full Android SDK/NDK/Gradle toolchain, also absent.

**Crypto library strategy:** none needed beyond what already exists --
`crypto/kyber.py` (ML-KEM-768), `crypto/ml_dsa.py` (ML-DSA-65),
`crypto/aes.py` (AES-256-GCM) are imported unchanged.

**Networking strategy:** `security.tls.build_client_context()` +
`utils.network.send_message()`/`receive_message()`, unchanged --
identical TLS context, identical 4-byte length-prefixed framing, the
real server never distinguishes a mobile connection from a desktop
one at the transport layer.

**Local storage strategy:** `storage.secure_key_store.SecureKeyStore`,
unchanged, pointed at a platform-appropriate directory via Kivy's own
`App.user_data_dir` (resolves to Android's sandboxed
`getExternalFilesDir()`-equivalent on-device, and a sensible per-user
directory in desktop-mode testing) -- see "Persistent local security"
below for exactly what is and is not stored there.

## Mobile architecture (layering)

```
UI (mobile/app.py -- Kivy widgets, LoginScreen/ChatScreen)
    |  every session-facing call is a plain Python method call;
    |  every session-originated event is delivered via _Signal.emit()
    |  on the RECEIVER thread and marshalled onto Kivy's main thread
    |  via kivy.clock.Clock.schedule_once() -- see app.py's own
    |  module docstring for the full threading-model writeup.
    v
Mobile Session / Application layer (mobile/session.py::
MobileClientSession)
    |  mirrors web/client/app.js::WebClientSession's method names,
    |  call order, and security ordering EXACTLY (this project's own
    |  designated reference implementation for mobile) -- direct
    |  messaging, groups, file/image transfer, history+dedup, read
    |  receipts, multi-device identity, all present.
    v
Protocol layer (utils/protocol.py, utils/network.py) -- UNCHANGED,
imported directly
    v
Crypto layer (crypto/kyber.py, crypto/ml_dsa.py, crypto/aes.py,
crypto/key_manager.py, crypto/*_protocol.py) -- UNCHANGED, imported
directly
    v
Secure local storage (storage/secure_key_store.py) -- UNCHANGED,
imported directly
    v
TLS/network transport (security/tls.py + Python's ssl/socket) --
UNCHANGED, imported directly
```

`MobileClientSession` does NOT subclass `client.session.ClientSession`
or `PySide6.QtCore.QObject` -- PySide6/Qt is not deployable to Android.
It is a genuinely separate, Qt-free class using a tiny `_Signal` shim
(`connect()`/`emit()`, no framework dependency) with the same
event-delivery shape client code already expects, so
`client/receiver.py::receive_messages()` works against it completely
unmodified (it only ever calls `session.handle_packet(...)`, `session.
error_occurred.emit(...)`, `session.connection_changed.emit(...)` --
never anything Qt-specific).

## Deliberate scope (matching the web client's own precedent)

Kyber/ML-KEM only (no RSA comparison-mode fallback -- this project's
own PQC default, and the web client's identical choice); no group
leave/add-members/rotation; peer-verification TRUST STATE (VERIFIED/
UNVERIFIED/KEY_CHANGED) is session-local, matching the web client's
own pre-Phase-17 baseline, rather than persisted -- **identity
keypairs and conversation/group keys themselves ARE persisted**, via
`SecureKeyStore`, unchanged from desktop, which is actually STRONGER
persistence than the web client has in that specific respect. A real
user re-observes/re-verifies a peer's fingerprint after a mobile app
restart (an already-familiar UX pattern from the web client's own
Stage-1 behavior); their already-established conversation KEYS survive
the restart regardless, via `SecureKeyStore`.

## Multi-device identity

Mobile participates in the EXISTING device model completely unchanged:
`enroll_device()`, `bind_device_session()`, `list_devices()`,
`observe_device_peer_identity()`, `confirm_device_peer_verified()`,
`authorize_device()`, `revoke_device()`, `sync_conversation_key_to_
device()` -- same wire packets, same `crypto/device_protocol.py`
canonical payloads (imported directly, not re-derived), same
server-side `server/device_handler.py` (completely unmodified). A
mobile device is never automatically trusted merely because it shares
an account -- it enrolls PENDING (unless it is the account's first
device ever, which bootstraps to AUTHORIZED, exactly like desktop/web)
and requires an already-AUTHORIZED device to vouch for it after a
real, out-of-band fingerprint comparison, proven in `tests/
test_mobile_client_session.py::
test_mobile_device_enrollment_authorization_and_key_sync` against a
REAL desktop `ClientSession`.

**The Phase 18.5 `device_id`/`announced_device_id` field-collision fix
is inherited automatically, not re-implemented**: that fix lives
entirely in `server/server_state.py`/`server/broadcaster.py`, which
mobile never touches or duplicates -- any client (desktop, web,
mobile) that ever sends an ordinary `key_exchange`/`public_key` packet
is equally protected by it, with no client-side code needed at all.

## Persistent local security

Stored, via `SecureKeyStore` (Argon2id-derived key from the login
password, AES-256-GCM at rest, unchanged from desktop):
this device's own ML-KEM-768 keypair (public + **private**), ML-DSA-65
signing keypair (public + **private**), `device_id`, and established
conversation/group keys (one entry per conversation, keyed by epoch).

**Deliberately NOT stored anywhere**: the login password itself (used
once, in memory, only to derive the store's wrapping key); the access
token/JWT (a fresh one is obtained via `authenticate_credentials()` on
every login, exactly like desktop); peer-verification TRUST STATE (see
"Deliberate scope" above); message content history (recovered on
demand via `load_history()`, exactly like every other client -- there
is no local message database on any of the three clients).

Storage location: `App.user_data_dir/keystore` (Kivy's own
platform-appropriate resolution -- a real, sandboxed, app-private
directory on Android; a conventional per-user directory when running
in desktop-mode for development/testing, as every test in this phase
does via `tmp_path`).

## Message-ID deduplication

Inherited from the Phase 18.5 web closure work unchanged: `server/
client_handler.py` already attaches `message_id` to every relayed live
`"chat"` packet (direct AND group), and `message_history_result`
already reports the same id for a stored row. `MobileClientSession.
_rendered_message_ids` (a `set`, in-memory) is populated by BOTH
`_handle_chat()` (live) and `load_history()` (recovered) -- whichever
path renders a given `message_id` first wins; the other silently
skips it. Proven in `tests/test_mobile_client_session.py::
test_mobile_offline_message_recovery_no_duplicates`.

## File/image transfer

Reuses `payload.file_adapter.FilePayloadAdapter` and `domain.
payload_type.classify_attachment()` completely unchanged -- the
crypto pipeline operates on raw `bytes` throughout (never converted to
or from UTF-8 text at any point for a FILE/IMAGE payload; only TEXT
messages are ever treated as text -- `payload.text_adapter.
TextPayloadAdapter` is a genuinely separate code path). `mobile/
session.py::send_attachment()` takes `bytes` directly (not a file
path, unlike desktop's `ClientSession.send_attachment()`) -- the
mobile-appropriate shape, matching how a real Android file/image
picker (`Kivy` plugin or platform intent) hands the app bytes, not
necessarily a filesystem path it controls.

## Testing

`tests/test_mobile_client_session.py` -- 9/9 passing, real server,
real desktop `ClientSession`, and (for one scenario) a real browser
through the real gateway running the real web client -- no mocking of
the protocol, crypto, or network layer anywhere:

| Test | Proves |
|---|---|
| `test_mobile_authenticates_connects_and_sends_public_key` | Auth, connect, login, public-key broadcast |
| `test_mobile_rejects_login_with_wrong_password` | Server remains the authority for authentication |
| `test_mobile_desktop_direct_messaging_bidirectional` | Mobile <-> Desktop, both directions, real ML-KEM/ML-DSA/AES-GCM |
| `test_mobile_rejects_tampered_message_signature` | A hand-tampered ciphertext with a stale signature is rejected, never decrypted |
| `test_mobile_offline_message_recovery_no_duplicates` | Offline recovery via `load_history()`, correct order, no duplicates across a real reconnect |
| `test_mobile_group_messaging_with_desktop` | Group creation, key distribution, bidirectional group messaging, exact key-byte match |
| `test_mobile_file_transfer_byte_exact` | Binary file (1024 bytes, every byte value) AND a 2048-byte random image, byte-for-byte, both directions |
| `test_mobile_device_enrollment_authorization_and_key_sync` | Enrollment (PENDING), authorization (fingerprint-gated), binding, mutual device-peer verification, key sync, and revocation blocking a subsequent bind |
| `test_mobile_web_direct_messaging_bidirectional` | Mobile <-> Web (through the real gateway, real browser), both directions |

No crypto interop test analogous to `test_web_client_crypto_interop.py`
was written or is needed: mobile does not port ML-KEM/ML-DSA/AES-GCM to
a second language, so there is no second implementation whose output
could diverge from Python's own -- the 9 tests above exercise the
identical code path desktop already uses, end to end, against real
peers.

The Kivy UI layer (`mobile/app.py`) was verified to **import cleanly
and construct its full widget tree** (a real `App.build()` call
against a real, successfully-initialized OpenGL/SDL2 window this
environment happened to support, plus a directly-constructed
`ChatScreen(session)` against a real `MobileClientSession` instance)
-- confirming every widget's session-attribute/method references are
correct against the real API surface. Interactive touch/render
behavior (tapping a real button, real text entry) was NOT exercised --
this environment has no Android device/emulator and no automated Kivy
UI-testing harness comparable to Playwright for the web client. This
is an honest, named gap, not claimed as tested.

**Phase 19.5 closure audit** re-ran this construction check with a
per-tab walk (`TabbedPanelItem.content.walk()`, not the whole screen's
`.walk()`, which Kivy only populates for the currently-visible tab)
and found a real bug: `TabbedPanel(do_default_tab=False)` left no tab
selected at all at startup, so the Messages tab was not actually
visible/attached until some other tab was manually switched to.
**Fixed** (`ChatScreen.__init__` now calls `tabs.switch_to(messages_tab)`
after adding all three tabs) and re-verified: all 13 required controls
(login/auth, direct messaging send/history/read/verify, group create/
send/history, and device enroll/bind/list/observe/authorize/revoke)
are present across the three tabs, and the Messages tab is confirmed
the active one at startup.

## Build/run instructions

**Desktop-mode (development/testing -- verified working in this
environment):**
```
pip install kivy
python -m mobile.app
```

**Android packaging (buildozer.spec provided, NOT executed in this
environment -- root cause now definitively identified, see below):**
a generic JRE/JDK (`java`/`javac`) is present, but there is no Android
SDK, no Android NDK, no Gradle, no `adb`, and neither `ANDROID_HOME`
nor `ANDROID_SDK_ROOT` is set.

**Phase 19.6 release-validation pass** installed `buildozer` and
`python-for-android` directly (both are pure-Python packages, so `pip
install` itself succeeds on Windows) to get first-party, concrete
evidence rather than relying on prior knowledge, and confirmed the
REAL blocker is not merely "SDK/NDK not yet downloaded" -- it is that
**neither tool's Android target can even initialize on native
Windows**, by the tools' own explicit design:

- `buildozer android debug` -> `buildozer --help` lists only `ios` as
  an available target on this platform; importing
  `buildozer.targets.android.TargetAndroid` directly raises
  `NotImplementedError: Windows platform not yet working for Android`
  -- an intentional, hard-coded platform guard in buildozer's own
  source, not a missing dependency.
- `python -m pythonforandroid.toolchain` (the lower-level tool
  buildozer itself drives) fails even earlier, at import time, with
  `ModuleNotFoundError: No module named 'sh'` -- `sh` is a POSIX-only
  process/pty wrapper library with no Windows support at all; this is
  not a package Windows can meaningfully provide.
- Neither WSL nor Docker is installed in this environment (`wsl
  --status` reports "The Windows Subsystem for Linux is not
  installed"; `docker --version` is not found). WSL is buildozer's own
  documented recommended path for Windows users, but installing it
  requires enabling Windows optional features and a **system reboot**
  to complete -- not something a non-interactive CLI session can
  perform or wait through, and not attempted here as a result (this
  closure phase's own instructions explicitly say not to wait
  indefinitely or risk the environment chasing one dependency).

**Conclusion**: no amount of installing the Android SDK/NDK/Gradle on
this native Windows environment would unblock the build -- the
toolchain itself refuses to run without WSL, Docker, or a native
Linux/macOS host. This is therefore an **architectural**, not merely a
missing-component, environment blocker. `buildozer.spec` at the repo
root is complete and correct for a machine that has one of those three
prerequisites:
```
pip install buildozer
buildozer android debug
```

## Phase 19.7 -- real WSL2 Android build and physical-device validation

A real WSL2 Ubuntu environment with Buildozer 1.6.0, Android SDK
(platform 36, build-tools 36.0.0), NDK 28.2.13676358, and a physical
Infinix X6711 (Android 14 / API 34 / arm64-v8a) superseded the
Phase 19.6 "architectural blocker" finding above (which remains
accurate for a bare native-Windows host with no WSL/Docker/Linux/macOS
available). A real, working `.apk` was built, installed, and launched
on the physical device.

**Toolchain fixes required** (applied to the WSL2-side p4a checkout
under `.buildozer/`, a build-tool cache, not tracked project source,
except where a repo file is named):
- `buildozer.spec`: `android.sdk_path`/`android.ndk_path` (reuse the
  pre-installed SDK/NDK instead of buildozer downloading its own),
  `android.skip_update = True` (the pre-installed SDK is read-only to
  this build user), `android.api = 36` (only platform actually
  installed).
- A user-owned `~/android-sdk-shim/` symlink tree, because
  buildozer's `sdkmanager_path` hard-codes the legacy pre-cmdline-tools
  SDK layout, and because `/usr/lib/android-sdk/build-tools/` contains
  a stray `debian` packaging directory that breaks buildozer's own
  `packaging.version.parse()`-based "latest build-tools" sort.
- `JAVA_HOME` pinned to a JDK 17 already present alongside the
  system default JDK 25: Gradle 8.14.3 cannot run under JDK 25
  ("Unsupported class file major version 69").
- p4a's `pythonforandroid/build.py::run_pymodules_install()` patched
  to pass the same `--platform`/`--python-version`/`--only-binary`
  flags used during dependency resolution to the actual install step
  -- PyPI now publishes Android-tagged wheels for some pure-Python
  packages (e.g. `charset_normalizer`), and p4a's own final install
  step wasn't passing the flags needed to accept them.
- p4a's `sdl2` bootstrap Java source (`HIDDeviceManager.java`)
  patched to pass `Context.RECEIVER_NOT_EXPORTED` on API 33+, guarded
  by `Build.VERSION.SDK_INT` -- Android 13+ requires an explicit
  export flag on `registerReceiver()`; this SDL2 version predates that
  requirement and crashed the app on launch
  (`SecurityException`-adjacent `hid_init` failure) until fixed.
- p4a's `cryptography` recipe (`RustCompiledComponentsRecipe`)
  patched to add `-lpython3.14` to `RUSTFLAGS`: PyO3's
  `extension-module` builds leave CPython C-API symbols (e.g.
  `PyExc_TypeError`) undefined, expecting runtime resolution against
  the already-loaded interpreter -- which works on glibc's default
  symbol search but not reliably on Android's bionic linker. Confirmed
  via a real on-device crash (`dlopen failed: cannot locate symbol
  PyExc_TypeError`) and via `llvm-nm`/`llvm-readelf` showing the
  symbol was genuinely exported by `libpython3.14.so` but not linked
  as `NEEDED` by the Rust `.so`.
- p4a's `openssl` recipe bumped 3.3.1 -> 3.5.8, and its `cryptography`
  recipe bumped 46.0.3 -> 49.0.0 (matching the desktop client's own
  `requirements.txt` pin exactly): 46.0.3 does not ship
  `cryptography.hazmat.primitives.asymmetric.mldsa` at all (ML-DSA
  support was added later); confirmed via a real on-device
  `ImportError` and by comparing against the desktop venv's own
  working `cryptography==49.0.0` install.
- `buildozer.spec` `requirements=` gained `pycryptodome`,
  `python-dotenv`, `kyber-py` -- genuinely missing from the original
  Phase 19 spec, found by tracing the real runtime import chain
  (`mobile.session` -> `crypto.aes`/`config`/`crypto.kyber`) after
  each surfaced as a real on-device `ModuleNotFoundError`, not by
  guessing.
- `buildozer.spec` `source.include_exts`/`source.include_patterns`
  tightened: `.crt` was missing from `include_exts` entirely (so
  `certs/dev/ca.crt`, needed by `security.tls.build_client_context()`,
  was never actually bundled despite being named in
  `include_patterns`), and the original `certs/*` pattern would also
  have bundled `certs/dev/server.key` and `certs/dev/ca.key` -- the
  server's and CA's own private keys -- into a distributable, more
  easily extracted mobile APK for no reason. Fixed to
  `certs/dev/ca.crt` (public cert only).
- `mobile/android_main.py` (the tracked, permanent build-time
  entrypoint swapped in for `main.py` only during an Android build,
  then restored) gained an early
  `sys.setdlopenflags(os.RTLD_NOW | os.RTLD_GLOBAL)` call as a
  defensive measure for the class of extension-loading issue above.

**Real bug found and fixed in tracked source**: `mobile/app.py`'s
`_login()` background worker's `except Exception as error:` handler
scheduled a `Clock.schedule_once(lambda dt: ... f"{error}" ...)` --
Python deletes the `as error` binding when the `except` block exits,
but `Clock.schedule_once()` runs the lambda on a later frame, so ANY
exception during login (wrong password, network error, anything)
crashed with a secondary `NameError` instead of showing the real
message. Found via a real on-device crash trace, fixed by capturing
`str(error)` into a plain variable before scheduling. This was the
only genuine application-code bug found during physical-device
testing; everything else was toolchain/build-tool/spec configuration.

**Physical-device results** (Infinix X6711, real touch input via
`adb shell input`, not simulated):
- APK built, installed (`adb install -r`), and launched with no
  crash; Kivy/SDL2 initialized against the real GPU (Mali-G57 MC2,
  OpenGL ES 3.2).
- Login screen renders correctly; all three fields (phone number,
  password, username) and the "Authenticate + Connect" button
  correctly accept real touch and keyboard input.
- Full real authentication succeeded end-to-end against the real
  server over a real network path (`adb reverse tcp:5000 tcp:5000`):
  TLS 1.3 handshake, JWT issuance and validation, Argon2 local
  key-store unlock, real ML-KEM-768 keypair generation, real
  ML-DSA-65 signing of the identity payload -- confirmed via logcat
  and via the resulting tabbed Messages/Groups/Devices UI rendering
  on-device.
- Wrong password correctly rejected (`Invalid phone number or
  password.`, surfaced in the UI, not a masked crash after the
  bugfix above).
- A genuine security check fired correctly and was observed live:
  a message sent from a second account (driven programmatically via
  the same production `MobileClientSession` code the mobile app
  itself ships, since automating the desktop Qt GUI was not attempted
  -- its window shares the same screen as the coding session driving
  this test) was rejected by the phone with
  `SECURITY: rejected (unverified_sender)`, correctly surfaced in the
  on-screen message log -- the app enforces TOFU peer verification
  before accepting a message, exactly as designed.
- **Not completed**: sending a message from the phone's own UI. The
  "message text" `TextInput` and "Verify (auto fp match)" `Button` on
  the Messages tab did not reliably accept simulated touch focus
  across many attempts (direct tap at recomputed coordinates, tab
  navigation) despite every other on-screen control in the same
  app -- both TextInputs on the login screen, the peer-username
  TextInput on this same Messages tab, the tab bar itself --
  responding correctly to the identical `adb shell input`
  mechanism. This was not resolved within this session and is
  reported as an open item, not silently assumed to be an app bug or
  silently assumed to be fine.
- **Not tested this session**: history/reconnect, read receipts,
  group messaging, file transfer, image transfer, device management
  (enrollment/authorization/revocation/key sync) via the physical
  UI.

**Final regression** (after all fixes above): `tests/
test_mobile_client_session.py` 9/9, the five targeted integration
files 43/43, `tests/test_web_feature_completion_e2e.py` 7/7 -- all
unchanged from the pre-Phase-19.7 baseline.

## Phase 19.8 -- GUI parity with desktop + full physical resolution of the touch issue

**Root cause of Phase 19.7's "message field/Verify button not
touchable" finding, PROVEN via real on-device instrumentation (not
assumed)**: a diagnostic dump of every `TextInput`/`Button`'s real
`pos`/`size` (via `Window.size` and a `widget.walk()`, logged to
logcat) showed `Window.size = (1080, 2352)` on the physical device --
NOT the full 2460px screen height (a ~108px status-bar gap), and Kivy
positions widgets in a **bottom-up** coordinate system. Phase 19.7's
tap coordinates for the Messages tab were computed without accounting
for either the offset or the Y-flip, so they landed in empty space
below the actual widgets -- not because the widgets were mispositioned,
disabled, or unreachable. Once coordinates were recomputed correctly
(`screen_y = 108 + (window_height - kivy_y - widget_height)`), the
message field, Verify button, and every other on-screen control
accepted real touch input immediately, with no code changes needed
for the widgets themselves. This is proof, not a guess -- both
outcomes described in Phase 19.7's own mandate ("prove the layout is
wrong and fix the app" vs. "prove it's a tooling limitation") were
live options; the evidence pointed at the second one, only in the
narrower, load-bearing sense that it was a *test-harness coordinate
bug*, not an unresolvable ADB limitation -- every control was, in
fact, proven physically touchable once addressed correctly.

**GUI parity work** (desktop `gui/` package audited file-by-file as
the reference; see the parity table in the final Phase 19.8 report
for the full comparison):
- `mobile/app.py`'s `LoginScreen` rebuilt to match
  `gui/login_window.py` exactly: a Login/Register mode toggle
  ("Create an account" / "Already have an account? Login"), the same
  field labels/placeholders ("+91 98765 43210", "Enter your
  password", etc.), USERNAME collected only in register mode (never
  re-typed at login -- the authenticated username now comes from the
  server's own response, matching `MainWindow.handle_login()`), and
  `full_name`/`email` synthesized from the username exactly as
  `MainWindow.handle_registration()` does (`{username}@users.invalid`),
  never asked of the user.
- A file/image "Send File" control (path `TextInput` + button) added
  to the Messages tab, mirroring `gui/input_bar.py`'s attach button
  and calling the same `session.send_attachment()` the desktop's
  `FileMessageBubble`/`ImageMessageBubble` path uses. Kivy has no
  bundled native Android file-picker widget; a path field is the
  smallest faithful adaptation given this app's already-plain,
  raw-identifier UI style (peer usernames and conversation IDs are
  already hand-typed, not picked from a list either) -- adding a real
  native picker would mean a new dependency (`plyer`) and Android
  permission for one field, which the phase's own "do not
  over-engineer" instruction weighed against.
- Device management: the desktop GUI was found, on inspection, to
  have **no device-management UI at all** -- `client/session.py` has
  the full Phase 16A-16D backend (`enroll_device()`,
  `list_devices()`, `authorize_device()`, `revoke_device()`, etc.)
  but no `gui/` file calls any of it. Mobile's existing Devices tab
  (built in Phase 19) therefore already exceeds desktop parity here;
  it was left as-is, not removed or "matched down" to the desktop's
  gap.

**Real bugs found via physical testing and fixed**:
1. `mobile/app.py::_create_group()`, `_load_group_history()`, and
   `_mark_read()` called session methods directly on the UI thread
   with no exception handling -- unlike every other handler in the
   file. A real, reproducible `ssl.SSLEOFError` (an idle persistent
   connection being dropped, observed twice on-device) crashed the
   entire app via `_create_group()` before this fix; after it, the
   same error is caught and shown as `ERROR: ...` in the group list
   label, matching the established pattern everywhere else in this
   file. Confirmed fixed by reproducing the identical error again
   post-fix and observing no crash.

**Real physical-device results** (Infinix X6711, genuine touch input
throughout, evidence in the Phase 19.8 final report): real user
registration via the UI; valid and invalid login; peer verification
via the Verify button (both directions); direct messaging Android ->
peer and peer -> Android, including a genuine TOFU
`unverified_sender` rejection observed live; message history loading;
group creation and group messaging via the UI; real file transfer via
the new Send File control; device enrollment and device listing via
the UI, showing the real ML-DSA-65 fingerprint.

## Known limitations

- Bind/authorize/revoke workflows on the Devices tab require a
  *second* physically enrolled device under the same account to
  exercise meaningfully; only one physical Android device was
  available this phase, so those three specific sub-workflows were
  not physically exercised (enrollment and listing were).
- Read receipts, image-specific transfer (as opposed to generic file
  transfer, which shares the same code path), and reconnect-after-
  disconnect were not explicitly physically re-exercised in Phase
  19.8 (reconnect/duplicate-safety were already covered by Phase 19's
  own automated integration tests, unchanged this phase).
- Peer-verification trust state is session-local (matches the web
  client's own historical scope, not a regression); identity keys and
  conversation keys themselves DO persist.
- No RSA comparison-mode fallback, no group leave/add-members/
  rotation -- matches the web client's own documented scope exactly,
  not a mobile-specific gap.
- The Phase 18.5-documented "ordinary peer identity is account-level,
  not device-level, from a third party's perspective" limitation is
  inherited, unchanged, by mobile too (same root cause: `KeyManager.
  public_keys` is a single slot per username, not per device) -- per
  this phase's own explicit instruction, this was NOT reopened or
  redesigned; no mobile-specific security blocker was discovered that
  would require doing so.
- **No automatic reconnect-on-disconnect state machine** (found during
  the Phase 19.5 closure audit's own security/behavior review; not
  present in the original Phase 19 report either, which only claimed
  "reconnect" in the sense the tests actually exercise: a fresh manual
  `connect()`/`login()`/`send_public_key()`/`start_receiver()` call
  after an intentional disconnect, which correctly resumes messaging
  using the SAME persisted identity/device/conversation keys, and
  which `start_receiver()`'s own guard prevents from ever starting a
  second, duplicate receiver thread). Unlike the web client's Phase 17
  `_scheduleReconnect()`/bounded-backoff work, mobile has no equivalent
  automatic retry-on-unexpected-drop loop. This is a real, scoped-out
  gap, not a security defect -- persistence and duplicate-connection
  safety are both already correct; only the "retry automatically
  without the user re-opening the app" convenience is missing. Left
  undone in this closure pass per its own explicit "do not add new
  features" instruction.

## Phase 19.5 security sanity audit (closure pass)

Re-verified by direct code inspection, not merely by re-running tests
(all findings: clean, no defect):

- **Plaintext**: every `send_message(self.client_socket, ...)` call
  site in `mobile/session.py` (10 total) passes either a
  `create_*_packet()` builder's output or a `packet` variable already
  built from one -- text/file/image content is always routed through
  `_send_payload()` -> `PayloadAdapter.encrypt()` first; conversation/
  group keys are always routed through `KeyManager.wrap_key_for_member()`
  (KEM-then-DEM) first. No call site sends raw content or a raw key.
- **Cryptography**: `KeyManager()` (no override) resolves to
  `config.KEY_EXCHANGE_ALGORITHM = "KYBER"` (ML-KEM-768); ML-DSA-65 via
  `self.key_manager.ml_dsa` (`crypto.ml_dsa.MLDSASigner`); AES-256-GCM
  via `crypto.aes.AESCipher` -- all imported unchanged, no primitive
  replaced or added.
- **Signature verification**: `test_mobile_rejects_tampered_message_
  signature` re-run clean this session.
- **Device security**: `self.device_id` persists via `SecureKeyStore.
  get_device_id()`/`save_device_id()`; keypairs persist via
  `load_or_create_kyber_keypair()`/`load_or_create_signing_keypair()`
  (both delegate to `SecureKeyStore`); grepped confirmed no
  `self.password`/`self._password` attribute exists anywhere in
  `mobile/session.py` or `mobile/app.py` (the login password lives
  only as a local parameter and, transiently, in the Kivy `TextInput`
  widget itself); `self.access_token` is held in memory only --
  `SecureKeyStore`'s own API has no token-related method at all, so
  there is nothing for it to persist to. `PEER_STATE_VERIFIED` is
  written in exactly one place (`confirm_peer_verified()`), gated on
  the caller supplying a fingerprint that matches the already-observed
  one -- no auto-trust path exists for a same-username or same-account
  peer/device. Revoked-device and unauthorized-device key-sync
  rejection re-confirmed via `test_mobile_device_enrollment_
  authorization_and_key_sync`.
- **History**: `load_history()` calls `verify_message_payload()` for
  every recovered entry, resolving the signing key independently (own
  key if `is_own`, else `self.peers[sender]["signing_key"]`) -- never
  trusting the entry's own claims; `_rendered_message_ids` dedup
  re-confirmed via `test_mobile_offline_message_recovery_no_duplicates`.
- **Attachments**: `send_attachment()` takes `bytes` directly; FILE/
  IMAGE always route through `FilePayloadAdapter` (`crypto.
  payload_cipher.encrypt_payload`/`decrypt_payload`, base64-then-AES-
  GCM) -- TEXT is a genuinely separate adapter (`TextPayloadAdapter`);
  no UTF-8 conversion of attachment bytes exists anywhere in the file.
  Re-confirmed via `test_mobile_file_transfer_byte_exact`'s exact
  byte-equality assertions.
- **Reconnect/persistence**: `start_receiver()` guards against a
  second receiver thread; `disconnect()` joins the existing thread and
  clears the reference before any later reconnect; identity/device/
  conversation keys survive a disconnect via `SecureKeyStore` (not
  in-memory-only) -- see "No automatic reconnect-on-disconnect state
  machine" above for the one honestly-scoped-out gap (convenience,
  not correctness or security).

## Phase 19.9 -- final mobile UI/UX rebuild, new-device validation

`mobile/app.py` was rewritten essentially from scratch to replace the
Phase 19-19.8 developer-console UI (raw peer/conversation-id
TextInputs, a literal "Verify (auto fp match)" button, a raw
device-management button row, raw exception strings on screen) with a
genuine, examiner-credible messaging app: a real conversation list
(`ChatScreen.conversations`, a UI-layer model keyed by
`identity_key` -- never a raw server ID shown to the user), a chat
screen with a header verification badge (Verified/Not verified/
Identity changed, mirroring `gui/chat_window.py`'s own three states),
sent/received/system message bubbles, a `[+] [Type a message...]
[Send]` composer, a Groups section with a "+ Create" dialog, and a
"My Devices" list (friendly device names + Authorized/Pending/This
device state) replacing the old raw Enroll/Bind/List/Observe/
Authorize/Revoke button row -- `enroll_device()`/`bind_device_session()`
now run invisibly at login, matching how a real client treats device
registration as plumbing, not a user action. All user-facing errors
route through a new `friendly_error()` mapping (`mobile/app.py`); raw
exception text is logged via `Logger.warning`, never shown.

**Real bug found and fixed, not just UI reskinning**: `Bubble`
(the message-bubble widget) originally recomputed its own wrap width
reactively from `self.parent.width` on every `width` change, while
also feeding its computed `height` back up through the same parent
chain (`anchor`/`messages_box`/`ScrollView`). On the physical device
this produced a genuine, confirmed infinite Kivy relayout loop --
`[CRITICAL] [Clock] Warning, too much iteration done before the next
frame`, firing continuously for `mobile.app.Bubble` in real `logcat`
output -- that pegged the main thread and silently dropped all further
touch input the instant a single bubble rendered (confirmed via a
real `adb shell input tap`/`input text` sequence that stopped
registering entirely after the first system bubble appeared). Fixed
by computing the wrap width once, from the stable, non-reactive
`Window.width`, at construction time, with no `width`-triggered
callback at all -- the bubble's width never changes again after
creation, which fully breaks the cycle. Verified via a from-Python
Kivy `Clock.tick()` stress test (20 bubbles, 30 ticks, no CRITICAL
warnings) before spending a rebuild cycle, then re-confirmed on the
physical device: bubbles now render correctly and touch input keeps
working through an entire multi-message conversation.

**Second real bug found (session/protocol layer, pre-existing, not
introduced this phase)**: `establish_session_key()` and
`_create_and_distribute_group_key()` both call
`_store_conversation_key()` *unconditionally*, before checking whether
the recipient's public key is cached locally. When the recipient's
key is not yet cached, key delivery is silently deferred ("no public
key available yet" / "cannot distribute group key") with **no error
raised and no retry mechanism** -- the sender's own
`_has_conversation_key()` check then reports "established" regardless,
so `send_message()`/`send_group_message()` proceed to encrypt and
"successfully" send messages the recipient can never decrypt. This
was reproduced twice under real physical-device conditions (both a
direct conversation and a freshly created group), confirmed via the
receiver's own `security_rejection` signal reporting
`decryption_failure`, and traced to this exact code path by reading
`mobile/session.py` directly -- not assumed. `mobile/session.py`
mirrors `web/client/app.js::WebClientSession` byte-for-byte in this
area (per that module's own docstring), so the same gap exists there
too; this is pre-existing, already-shipped protocol-layer behavior,
not a Phase 19.9 regression. Given the mandate's explicit instruction
not to rewrite the protocol layer without a narrowly-scoped, verified
fix, and given the blast radius of changing when/whether
`_store_conversation_key()` runs (shared by every session-key and
group-key call site, each with its own existing test coverage), no
session.py change was made; this is recorded here as a known,
reproduced gap for a future phase, not silently worked around.
**Practical mitigation confirmed working**: the observed failure
requires the recipient's public key to be uncached at the exact
moment of first key generation; once both sides have exchanged public
keys (which happens automatically and near-instantly in ordinary
continuous use), a *fresh* conversation/group created afterward
delivers correctly -- demonstrated directly (see Section 4 of the
Phase 19.9 report for the exact evidence).

**Third real finding (device management, working-as-designed once
understood, not a defect)**: `sync_conversation_key_to_device()`'s
delivery additionally requires the *receiving* device to have already
verified the *sending* device's identity locally
(`mobile/session.py::_handle_device_key_sync()` calls
`_peer_key_is_verified(source_device_id)` and silently reports
`unverified_sender` otherwise -- confirmed by a real physical-device
sync attempt that the server logged as successfully relayed, yet the
receiving device never surfaced). The original Devices-tab detail
dialog only auto-verified a device being *authorized* (the PENDING ->
AUTHORIZED direction); it had no path to verify an *already-authorized*
device from a second device's own perspective. Added a "Verify" action
to the device-detail dialog whenever the locally observed identity
state isn't `VERIFIED` (`mobile/app.py::_open_device_detail()`),
mirroring the same TOFU-verify pattern already used for peer chat
identities -- this is the intended security posture (a device must be
explicitly trusted before its synced keys are honored), not a bug to
route around by auto-trusting.

**Native Android file/image picker**: `_pick_file_android()` /
`_read_android_uri()` (`mobile/app.py`) implement a real Storage
Access Framework picker via `pyjnius` (`android.content.Intent
.ACTION_GET_CONTENT`, `ContentResolver.openInputStream()`), replacing
the old raw-filesystem-path `TextInput` this phase's mandate
specifically called out as unacceptable. `pyjnius`/`android` are
already part of every p4a "kivy" bootstrap build (confirmed present
in the build's own resolved recipe list), so no new build dependency
was needed. This structurally avoids the `[Errno 13] Permission
denied` scoped-storage error found in Phase 19.8 (the app now reads
via a content:// URI the OS itself grants access to, rather than a
raw path the app may not have permission to open) -- not merely
catching and re-displaying the same error more nicely. See the
Phase 19.9 report (Section 9) for why this specific code path could
not be physically exercised end-to-end within this phase's testing
window (it requires driving Android's own out-of-process system
picker UI, not just this app's Kivy surface).

**`buildozer.spec` cert-bundling fix**: `source.include_patterns`
listing `certs/dev/ca.crt` was found to never have actually restricted
anything -- reading `buildozer/__init__.py::_copy_application_sources()`
directly shows `include_patterns` only ever *readmits* a file/dir an
`exclude_dirs`/`exclude_patterns` rule already ruled out; it is not a
standalone allowlist. Because `source.include_exts` allows the bare
`crt` extension and `certs/` was never in `exclude_dirs`, the *sibling*
file `certs/dev/server.crt` (a public certificate, not a secret, but
not the stated intent either) was being swept into every built APK
regardless. Fixed by adding `certs` to `exclude_dirs` and an explicit
`certs/dev/server.crt` to `exclude_patterns`, then re-admitting only
the directory and the one file actually needed via
`include_patterns`. Re-verified directly against the built APK's own
`assets/private.tar`: `certs/dev/ca.crt` present, `certs/dev/server.crt`
absent, no `.key`/`.pem`/`.env` files anywhere.

## 2026-09-21 rebuild -- current feature set, build+audit only

The Phase 19.7/19.9 WSL2 toolchain (Ubuntu, Buildozer 1.6.0, Android SDK
platform 36, NDK 28.2.13676358) was still present and reachable from
this Windows host (`wsl --status` confirms Ubuntu running) and was used
to rebuild the APK against the CURRENT source tree -- reflecting every
feature shipped later in Phase 19.24 (Pin, Search, Voice/Video
playback, Wallpaper, Typing, Drafts, Mute, Archive, Block, the
redesigned attachment menu, Presence/last-seen), none of which existed
in the Phase 19.7 build.

**Environment drift found and fixed**: the buildozer install this
environment had (`~/fyp-android-venv`, a strict virtualenv with
`include-system-site-packages = false`) fails p4a's own
`pip install --user ...` step for its build-time dependencies (`jinja2`,
`sh`, `meson`, etc.) with `ERROR: Can not perform a '--user' install.
User site-packages are not visible in this virtualenv` -- a real,
version-dependent p4a/pip interaction, not a QRSCS code issue. Fixed by
installing `buildozer`/`cython` on the WSL distribution's own system
Python instead (`python3 -m pip install --user --break-system-packages
buildozer cython` -- the `--break-system-packages` flag is pip's own
documented, intended override for Debian's PEP 668 external-management
guard, appropriate here since this is a personal dev sandbox, not a
shared system), which has `site.ENABLE_USER_SITE = True` and so accepts
`--user` installs normally. The existing `.buildozer/` cache (4.7GB,
under `~/fyp-project/.../`) was reused by rsync'ing the CURRENT source
tree over that checkout (excluding `.git`/`.buildozer`/`venv`) rather
than starting a fresh checkout, so the already-compiled native recipes
(kivy, pyjnius, cryptography, pycryptodome, etc.) did not need
recompiling -- the build found its own prior `qrscs_mobile` dist as
"has compatible recipes" and reused it, so this run only repackaged the
updated Python source, completing in under a minute of actual Gradle
work (`BUILD SUCCESSFUL in 16s`).

**Build result**: `bin/qrscs_mobile-0.1.0-arm64-v8a-debug.apk`,
29,881,557 bytes.
**SHA-256**: `fe3a7804f274e9b481e22900bb972b5402828982babb046dff880d638bc190d5`

**2026-09-21, second rebuild (same day, after adding destructive-action
confirmation dialogs to `mobile/app.py`)**: source re-synced and
rebuilt via the same pipeline. `aapt dump badging` against the result
(authoritative package metadata, not inferred from `buildozer.spec`
alone):

```
package: name='org.qrscs.qrscs_mobile' versionCode='1024100' versionName='0.1.0'
compileSdkVersion='36' targetSdkVersion='36' sdkVersion(min)='24'
native-code: 'arm64-v8a'
application-label: 'QRSCS Mobile'
```

**Build result**: `bin/qrscs_mobile-0.1.0-arm64-v8a-debug.apk`,
29,882,729 bytes.
**SHA-256**: `1c522d29094c0efdae0590cce4bc71468fe409b619446288e1b9f4f6fbeaafdf`

Content audit repeated against this build with identical results to
the first rebuild above (no `.key`/`.pem`/`.env`, `certs/dev/` has only
`ca.crt`, dev-only/server-only files and directories absent, no secret
strings found). This is the current, up-to-date APK in `bin/`.

**Physical-device install attempted, device not found.** A physical
device (a vivo V2036, Android 13, arm64) was expected to be reachable
via Windows-native ADB for this rebuild. Checked directly, not
assumed: `C:\platform-tools-latest-windows\platform-tools\adb.exe
devices -l` (after `adb kill-server`/`adb start-server`) reports no
device attached; a Windows Device Manager sweep for any phone/MTP/ADB-
class USB device (`Get-PnpDevice -PresentOnly`, matched against
`USB`/`Portable`/`Phone`/`Mobile`/`MTP`/`ADB`/`Composite`) found only
generic host-controller/audio/camera entries — no Android device
enumerated. This means the device is not currently physically
connected to this machine's USB, not that the toolchain or driver
setup is broken (the same adb.exe/toolchain successfully built and
would install to a device the moment one is plugged in and USB-
debugging-authorized). Install/launch/logcat/manual touch validation
against this rebuild's new features (destructive-action confirmation
dialogs, and everything from the first rebuild's own list) remains
outstanding, exactly as the first rebuild's own note already stated,
and is the first action to take once a device is actually connected.

**Content audit** (extracted `assets/private.tar`, mirroring the exact
checks the 2026-09 cert-bundling fix above established):
- No `.key`/`.pem`/`.env` file anywhere in the payload.
- `certs/dev/` contains only `ca.crt` (public CA cert) -- no
  `server.crt`/`server.key`.
- `demo/`, `tests/`, `gui/`, `web/`, `server/`, `database/`, `alembic/`,
  `benchmark/`, `scripts/`, `docs/` are all absent from the bundled
  payload (top-level directories present: `auth`, `certs`, `client`,
  `crypto`, `domain`, `mobile`, `payload`, `security`, `storage`,
  `utils` -- exactly the mobile-relevant modules `buildozer.spec`'s own
  `source.include_patterns`/`exclude_dirs` intend).
- `phase197_peer_session.py`/`phase197_seed_test_account.py`/
  `config_server.py` (the three files with hardcoded TEST credentials
  or server-only config found during this phase's source-tree secrets
  sweep) are absent, confirming `buildozer.spec`'s
  `source.exclude_patterns` entries for them still work.
- A grep across the entire extracted payload for the real `.env`'s
  `JWT_SECRET_KEY` value, its Postgres connection string, and the demo/
  phase197 scripts' hardcoded test passwords found zero matches.

**Physical-device validation: genuinely blocked, not attempted.**
`adb devices -l` (Windows-native ADB path, and independently confirmed
again from inside WSL2's own `adb`) reports no device attached in this
environment at the time of this rebuild -- unlike the Phase 19.7
session, no physical Infinix X6711 (or any other Android device) is
connected via USB right now. Per this phase's own mandate ("Do not
claim physical validation from source inspection" / "Only report a
requirement as blocked if there is a genuine technical blocker"): this
is a real, environmental hardware-access blocker (no device physically
present to install/launch/touch-test against), not a software or
toolchain problem -- the toolchain itself is confirmed working end to
end through a real Gradle build. Install (`adb install -r`), launch,
logcat inspection, and manual touch-driven acceptance of this session's
new features (Pin, Search, Voice playback, Presence/last-seen, etc.) on
a real device remain outstanding and should be the first action taken
once a physical device is available to connect to this environment.

## 2026-09-21, third rebuild -- real Android voice/video recording,
## real cross-platform Forward for media, and Media Gallery added

Source re-synced and rebuilt via the same pipeline after this closure
pass's own additions: real `android.media.MediaRecorder`-based voice
and video recording (replacing the earlier honest "not yet available"
placeholder -- see `media_security_architecture.md`'s own "Recording,
per platform" section for the full design and its honest verification
status), a cross-platform Media Gallery (`_media_bubbles()`/
`_open_media_gallery()`/`_build_gallery_tile()`), and Forward now
handling image/file/voice/video (`Bubble` retains its attachment
bytes/mime_type/payload_type instead of discarding them, and
`_forward_bubble_to()` establishes a session key first if the target
is new). `buildozer.spec`'s `android.permissions` gained `RECORD_AUDIO`
and `CAMERA` (both confirmed present in the built APK's own manifest
via `aapt dump badging`, not merely assumed from the spec file).

```
package: name='org.qrscs.qrscs_mobile' versionCode='1024100' versionName='0.1.0'
compileSdkVersion='36' targetSdkVersion='36' sdkVersion(min)='24'
native-code: 'arm64-v8a'
uses-permission: android.permission.INTERNET
uses-permission: android.permission.RECORD_AUDIO
uses-permission: android.permission.CAMERA
```

**Build result**: `bin/qrscs_mobile-0.1.0-arm64-v8a-debug.apk`,
29,890,613 bytes.
**SHA-256**: `05e5d2957e43bdba2b6c621de1c981683ae2d086100accd161a64f60e293a20a`

Content audit repeated with identical results to the two prior rebuilds
(no `.key`/`.pem`/`.env`, `certs/dev/` has only `ca.crt`, dev-only/
server-only files absent, no secret strings found). This is the
current, up-to-date APK in `bin/`.

**Physical-device validation: still genuinely blocked.** `adb devices
-l` (Windows-native ADB, re-checked immediately before and after this
build) reports no device attached. The voice/video recording code in
this build is real and complete -- written against Android's
documented `MediaRecorder` API, using this project's own established
pyjnius conventions, and proven to build successfully into a real,
installable APK -- but has not been run on physical hardware. Nothing
in this document claims otherwise. The moment a device is available,
recording (voice and video, including permission-denial handling and
the max-duration auto-stop) should be the first thing physically
validated, followed by the rest of the checklist in `docs/
PHASE_19_24_FINAL_REPORT.md`'s Physical Android Results section.

## 2026-09-21, fourth rebuild -- recording output-file validation fix

A closer re-read of the recording code (prompted by an explicit review
request) found one real gap: `recorder.stop()` returning without
raising is not itself proof the output file exists and is non-empty --
an interrupted recording could in principle leave a missing or
zero-byte file, which would previously have let an uncaught
`FileNotFoundError` escape a Kivy button callback instead of showing
the user an honest error. Fixed in `_open_media_recorder_popup()`: the
output file's existence and size are checked explicitly before reading
it, with a friendly in-chat error message on failure, mirroring the
same error-reporting pattern already used for a failed `prepare()`/
`start()`. Rebuilt to confirm the fix compiles and packages correctly.

```
package: name='org.qrscs.qrscs_mobile' versionCode='1024100' versionName='0.1.0'
compileSdkVersion='36' targetSdkVersion='36' sdkVersion(min)='24'
native-code: 'arm64-v8a'
uses-permission: android.permission.INTERNET
uses-permission: android.permission.RECORD_AUDIO
uses-permission: android.permission.CAMERA
```

**Build result**: `bin/qrscs_mobile-0.1.0-arm64-v8a-debug.apk`,
29,890,985 bytes.
**SHA-256**: `6403121c408292d18658532df31d41bff754b0cf14fd426d0089ee4ffae5b3f1`

Content audit repeated with identical results to all three prior
rebuilds (no `.key`/`.pem`/`.env`, `certs/dev/` has only `ca.crt`,
dev-only/server-only files absent, no secret strings found, and no
tool/vendor-name or agent-description strings found either --
explicitly checked this pass, terms deliberately not spelled out here
so this note can never itself become a match against its own rule).
This is the current, up-to-date APK in `bin/`.

**Physical-device validation: still genuinely blocked.** `adb devices
-l` (Windows-native ADB, re-checked via an explicit `kill-server`/
`start-server` cycle immediately before this build) reports no device
attached. Same honest status as the third rebuild above: the code is
real, complete, and now includes this output-file-validation fix, and
builds successfully -- physical verification remains the only
outstanding step, blocked purely by hardware availability.

## 2026-09-22, fifth rebuild -- real native Android video PLAYBACK
## added, plus a genuine Web message-search bug found and fixed

Two closure-mandate items landed this pass:

**Web message-search test.** What earlier sessions had repeatedly
labeled "environmental Playwright/Chromium flakiness" (see this
project's own memory notes) turned out to be a real, deterministic
application bug once properly root-caused with a property-setter trap
on `#searchBar.hidden` that captured the actual JS call stack at the
moment of failure: `web/client/main.js`'s `#peerUsername` input
listener debounces a call to `openDirectChat(value)` 300ms after any
"input" event on that field (including a single `page.fill()`) --
and `openDirectChat()` unconditionally closes the active search bar
and wipes `#messages`, even when re-opening the peer that is already
the active chat. Under real JS-main-thread contention this timer can
fire seconds late, landing in the middle of an unrelated later
interaction (an open search) and silently destroying it -- explaining
every previously observed symptom (moving failure point, "element not
visible" click timeouts) without needing to invoke browser timing as
an unexplained black box. Fixed with a one-line guard: the debounce is
a no-op when the field's value already equals the currently-open peer.
Verified: 6/6 consecutive standalone runs of the previously-flaky test
with plain `page.click()` (no retry/workaround needed), and the full
27-test `test_web_phase19_24_lifecycle_ui.py` suite passed 27/27 twice
in a row.

**Android video playback.** This Kivy build's own video-decode backend
is still `null` (unchanged limitation, confirmed again), so instead of
a fake in-Kivy player, `mobile/app.py::_play_video_android()` bridges
to Android's real native `android.widget.VideoView` +
`android.widget.MediaController` via pyjnius -- the same
`activity.addContentView()`-alongside-Kivy's-GL-surface technique this
file already used for the camera preview during video recording.
Decrypted plaintext is written once to a private temp file (VideoView,
like MediaPlayer, has no in-memory-buffer playback API) and deleted on
completion, on error, and when the user closes the player -- never a
permanent decrypted copy, and the server never sees plaintext at any
point. A received video message's bubble now shows a real ▶ Play
button on Android (was Save-only before this pass); the desktop-
preview fallback is unchanged and still honest.

```
package: name='org.qrscs.qrscs_mobile' versionCode='1024100' versionName='0.1.0'
compileSdkVersion='36' targetSdkVersion='36' sdkVersion(min)='24'
native-code: 'arm64-v8a'
uses-permission: android.permission.INTERNET
uses-permission: android.permission.RECORD_AUDIO
uses-permission: android.permission.CAMERA
```

(all read directly from `aapt dump badging` against this exact build,
run from `/usr/lib/android-sdk/build-tools/36.0.0/aapt` in the WSL
toolchain — versionCode is unchanged from the fourth rebuild, as
expected since nothing in `buildozer.spec` that determines it changed)

**Build result**: `bin/qrscs_mobile-0.1.0-arm64-v8a-debug.apk`,
29,893,441 bytes.
**SHA-256**: `b9bd305b1706b1d8e00ac65b75d82298f70d7ec957b0c665c89e65a9e3815278`

Content audit of this build: the manifest (`AndroidManifest.xml`,
decoded from the packaged APK) confirms package name and all three
permissions above. The bundled private app data (`assets/private.tar`,
p4a's packaging of the app's own Python source, extracted and
inspected) contains only compiled `.pyc` bytecode (no `.py` source, no
`.pem`/`.key`/`.env` files anywhere), `certs/dev/` has only `ca.crt`
(a public CA certificate, not a private key), and a full string scan
of every bundled `.pyc` file found: no hardcoded database connection
strings, no cloud credential patterns, no JWT/API secret *values* (one
config-key *name*, `JWT_SECRET_KEY`, appears alongside its sibling
`JWT_AUDIENCE`/`JWT_ISSUER`/`REFRESH_TOKEN_EXPIRE_DAYS` constant names
from a shared config module -- these are environment-variable names
the server reads, not secret values, and are harmless to bundle), and
no tool/vendor-name or agent-description strings (this project's own
absolute attribution rule; terms deliberately not spelled out here) --
zero matches for any of them.

## 2026-09-22, physical-device validation attempt -- sixth rebuild
## (vmSafeMode native-crash mitigation)

**Hardware became available this same day and was genuinely
attempted -- and found a real, reproducible defect outside this
project's own application code.** A real Vivo V2036
(Android 13/API 33, Qualcomm "bengal" chipset, Adreno 610 GPU)
connected via USB, authorized, and confirmed via `adb devices -l`.
`adb install -r` succeeded; `adb shell dumpsys package` confirmed the
installed package/version matched the built APK exactly.

Launching the app (`adb shell am start`) reproduced a 100%-deterministic
native crash across 2 consecutive attempts, BEFORE any of this
project's own Python code runs: `Fatal signal 11 (SIGSEGV), code 1
(SEGV_MAPERR), fault addr 0x0 in tid ... (Jit thread pool), pid ...
(SDLActivity)`, immediately after SDL2's own EGL/BLASTBufferQueue
setup -- a crash inside Kivy/SDL2's own native bootstrap and ART's JIT
compiler, not this app's code. The same toolchain (NDK 28.2.13676358,
platform 36) previously built a working APK physically validated on a
different device (Infinix X6711, Android 14/API 34, Phase 19.7,
earlier section above) -- this is a genuine device/GPU-driver-specific
incompatibility, not a toolchain regression.

**Real mitigation applied and rebuilt**: `android:vmSafeMode="true"`
added to the manifest via `buildozer.spec`'s
`android.extra_manifest_application_arguments` (Android's own standard,
documented flag disabling JIT/AOT compilation for this app --
interpreter-only execution, a runtime execution-mode setting with zero
effect on cryptography, key material, or any security-relevant code
path). Rebuilt and reinstalled. **Confirmed real, partial improvement
by logcat evidence**: the original deterministic SIGSEGV no longer
occurs; across 5 further launch attempts the app progresses much
further into real execution (confirmed loading `libpython3.14.so` and
beginning genuine CPython module imports, e.g. `zlib.cpython-314-
aarch64-linux-android.so`, granted real SELinux execute permission) --
but the process still exits silently at a non-deterministic point
during native/CPython startup on 5/5 further attempts, before reaching
this app's own `mobile/app.py` code or any visible UI, with no crash
trace, no ANR trace, and no `am_kill`/`am_proc_died` event logged
anywhere accessible without root (this ROM's dropbox/tombstone
reporting appears to suppress or redirect this specific failure mode;
`dmesg` requires root and was not accessible). One concrete secondary
lead observed but not fixable from this project's own source: a
SELinux-enforced (enforcing, not permissive) denial of this app's
attempt to read `/proc/sys/vm/overcommit_memory`, a proc file some
native memory allocators consult -- a plausible but unconfirmed
contributor, since fixing it would mean patching CPython's or SDL2's
own native allocator, not this project's application code.

**Conclusion, stated honestly**: this is a genuine, reproducible
device/ROM-level compatibility defect in this specific physical unit
(Vivo V2036 / Funtouch OS), occurring beneath this project's own
Python application code (Kivy/SDL2/CPython's own native bootstrap),
not a defect in this project's source. It is not the same thing as "no
device available" -- a device IS connected and receives a correctly-
installed, version-matched APK -- but the app does not reach a stable,
testable running state on it, so the feature-level physical validation
checklist (login, messaging, voice/video, etc.) could not be performed
on this specific unit this pass. The vmSafeMode mitigation is kept in
`buildozer.spec` since it is a real, evidence-backed improvement with
no downside (same security architecture, same source, slightly slower
startup) even though it did not fully resolve instability on this
device. If a different physical device becomes available, or root
access to this one for a full tombstone, the investigation has a clear
next step (the SELinux/overcommit_memory lead above); it should not be
re-litigated from scratch.

```
package: name='org.qrscs.qrscs_mobile' versionCode='1024100' versionName='0.1.0'
compileSdkVersion='36' targetSdkVersion='36' sdkVersion(min)='24'
native-code: 'arm64-v8a'
uses-permission: android.permission.INTERNET
uses-permission: android.permission.RECORD_AUDIO
uses-permission: android.permission.CAMERA
```

(all read directly from `aapt dump badging` against this exact build)

**Build result**: `bin/qrscs_mobile-0.1.0-arm64-v8a-debug.apk`,
29,893,469 bytes.
**SHA-256**: `2dca620fca32a702684732235843afd858bbdb0120555dd02c51aa13cd2ddfd4`

Content audit repeated with identical results to all five prior
rebuilds (no `.key`/`.pem`/`.env`, `certs/dev/` has only `ca.crt`,
bundled app data is `.pyc`-only, no hardcoded secrets, and no tool/
vendor-name or agent-description strings found). **Superseded by the
2026-09-26 section below** -- this exact SHA-256 was the build that
reproducibly crashed on physical hardware; the current `bin/` APK is
now the one described there.

## 2026-09-24 -- controlled experiment reclassifies the Vivo failure:
## device/ROM ruled out, points to a specific native dependency

The prior section's finding (real Vivo V2036, deterministic native
SIGSEGV, vmSafeMode partially mitigates) had not yet distinguished
whether the cause was (A) this device/ROM/GPU generically, (B) this
project's specific build/dependency configuration, or (C) this
project's own Python application code. Rather than perform more
identical retries of the real app on the same device, a controlled
experiment changed exactly one variable: a MINIMAL Kivy "hello world"
app (`requirements = python3,kivy==2.3.1` only -- no cryptography, no
pynacl, no argon2-cffi, no pycryptodome, no sqlalchemy, no pydantic, no
kyber-py) was built with the identical toolchain (same WSL
`.buildozer/android/platform` checkout, same NDK 28.2.13676358, same
`android.api=36`, same `android:vmSafeMode="true"`) and installed on
the SAME physical Vivo V2036 that had failed the real app 13/13 times.

**Result: the minimal app reached a stable, rendered UI** -- a real
on-device screenshot confirms "Minimal Kivy Test OK" genuinely
displayed, alive for the full observation window (vs. the real app
never surviving past a few seconds in any attempt). This rules out (A):
the same Kivy/SDL2/ART bootstrap, same API level, same NDK, same
vmSafeMode flag all work fine on this exact hardware. The finding
points to (B) -- something in the real project's own ADDITIONAL native
dependencies (most likely `cryptography`'s Rust extension, already
flagged once before in this project's history for a different
dlopen/RTLD_GLOBAL issue -- see this file's own "Phase 19.7" section --
or one of `pynacl`/`argon2-cffi`/`pycryptodome`) interacting badly with
this specific device's old (2020-era) Adreno 610 GPU driver and/or its
JIT compiler during native library loading. It remains NOT (C): the
crash still occurs during C-extension import machinery, before
`mobile/app.py`'s own code runs.

The natural next step -- bisecting which added dependency triggers it,
by rebuilding the minimal app with one extra requirement at a time,
starting with `cryptography` -- was not completed this pass: the
device's battery reached a critical 2% during this investigation, and
further on-device testing was stopped to avoid losing the device
mid-experiment, per explicit instruction not to chase this indefinitely
once the device had already failed repeatedly. This is a real,
evidence-based narrowing of the problem (from "maybe anything" to "one
of a short, specific list of native dependencies"), not a conclusion
that the investigation is finished.

No second physical Android device was available in this environment to
cross-check (`adb devices -l` showed only the Vivo V2036 throughout);
the working reference point for this toolchain remains the Infinix
X6711 (Phase 19.7, above), on different, less GPU-constrained hardware
and without today's crypto/DB dependency set at the time it was tested.

## 2026-09-26 -- native startup crash RESOLVED; a separate,
## unrelated touch-injection limitation found and documented

**Wireless ADB became available** (Vivo V2036 over Wi-Fi, `adb pair`/
`adb connect` to a `[IPv6]:port` transport, confirmed via
`adb devices -l`), removing the USB/cable dependency for further work.

**Controlled dependency bisection, one variable at a time**, using the
minimal Kivy app from the 2026-09-24 section as the base, with the
real toolchain's cached recipe builds reused for speed:
1. Added `cryptography` alone, with a real import of
   `cryptography.hazmat.primitives.asymmetric.mldsa` (the actual
   ML-DSA-65 module this project uses) -- **survived, on-device
   screenshot confirms "cryptography import OK"**.
2. Added the REMAINING full real requirement set (`pynacl,
   sqlalchemy, pydantic, argon2-cffi, pycryptodome, python-dotenv,
   kyber-py`) with real imports of each (mirroring this project's own
   exact import paths, e.g. `from kyber_py.ml_kem import ML_KEM_768`,
   `from Crypto.Cipher import AES`) -- **survived**. A per-dependency
   diagnostic build (writing itemized OK/FAILED results to a pulled
   file, `adb pull /sdcard/Download/bisect_result.txt`) showed:
   `cryptography: OK`, `pynacl: OK`, `argon2: OK`, `pycryptodome: OK`,
   `python-dotenv: OK`, `kyber-py: OK` -- all genuinely working.
   `sqlalchemy` and `pydantic` each had a real, ordinary (non-fatal,
   Python-catchable) import error unrelated to this device or to
   native crashes (`sqlalchemy`: a `TypeError` from its
   `__firstlineno__`-manipulating compatibility shim conflicting with
   Python 3.14's newer class-layout internals; `pydantic`: a missing
   `pydantic_core` wheel for this Android/Python target) -- but a
   repo-wide check (`grep -rln "sqlalchemy\|pydantic" mobile/`)
   confirms **neither is ever actually imported by the mobile client's
   own real code** (`auth/authentication_service.py` uses `pydantic`,
   but nothing under `mobile/` imports that module) -- dead weight in
   `buildozer.spec`'s requirements list, not a runtime defect.
3. Added `RECORD_AUDIO`/`CAMERA` permissions (matching the real app's
   manifest exactly, not just `INTERNET`) -- **survived**.

None of these controlled variables reproduced the crash. The only
remaining untested variable was the real project's OWN source tree
and entrypoint (`mobile/app.py`'s full ~5,500-line module, its
complete `crypto/*`/`utils/*`/`storage/*`/`payload/*`/`domain/*`/
`security/*`/`auth/*` import chain, and `mobile/android_main.py`'s own
already-applied historical fixes -- see this file's own Phase 19.16
section on `_syscmd_file`/unsafe-fork crashes).

**Decisive final experiment: rebuilding the REAL project itself.**
Using the exact same swap mechanism `scripts/build_android_apk.sh`
automates (copy `mobile/android_main.py` to `main.py`, build, restore
the desktop `main.py` byte-for-byte afterward), the real `qrscs_mobile`
dist was rebuilt from a clean state and reinstalled.

**Result: 4/4 consecutive successful launches**, observed alive for
30s, 20s, 20s, and 15s respectively -- every one previously would have
crashed within the first ~1-2 seconds. A real on-device screenshot
(`physical_validation_evidence/real_app_alive.png`) shows the app's
genuine onboarding screen: "Enjoy the new experience of chatting with
quantum-safe friends" / "Post-quantum end-to-end encrypted messaging,
for free" / a "Get Started" button / "Powered by QRSCS post-quantum
cryptography". **The native startup crash is resolved.** The previous
13 failed attempts were against an older build artifact (SHA-256
`2dca620f...`); this new, confirmed-working build has SHA-256
`428515501b0fd89c9744ec927905afbf8cd29ca6267a5006c89282108d01aa17`
(29,893,161 bytes) and has been promoted to `bin/qrscs_mobile-0.1.0-
arm64-v8a-debug.apk` as the current APK. The precise mechanism that
changed between the crashing and working builds was not isolated
further (both use identical source and `buildozer.spec`) -- most
likely a stale/corrupt artifact in the specific old build rather than
anything reproducibly wrong in the source or config, since a byte-
identical-source clean rebuild now launches reliably.

**A second, separate, NOT-yet-resolved limitation was found while
attempting UI-driven physical validation with the app now stably
running:** `adb shell input tap`/`swipe`, and even `monkey
--pct-touch 100`, produced no visible effect on-screen. This was
proven to be a device-wide input-injection restriction, not a defect
in this project's app: the identical `input tap` command against the
OS's own home-screen launcher (tapping the visible Play Store icon)
also did nothing, while `adb shell input keyevent KEYCODE_HOME` DID
work (successfully returned to the launcher) -- isolating the failure
specifically to touch/motion event injection, not all synthetic input.
`adb shell getevent -pl` confirms the real touchscreen kernel device
(`vivo_ts_pen`, `/dev/input/event4`, correct 0-1079/0-2407 coordinate
ranges) is enumerated; a raw `sendevent` write to it was rejected with
`Permission denied` (this shell user is not root). This is almost
certainly a Vivo/Funtouch OS developer-option gate on synthetic touch
injection (commonly named "Disable permission monitoring" on similar
OEM ROMs) that is off by default and, being a physical Settings-app
toggle, cannot itself be reached without touch input already working --
a genuine chicken-and-egg limitation of this specific device/connection
combination, not a QRSCS defect. `settings list global`/`settings list
secure` did not surface an obviously-named key to flip this
programmatically without a physical finger.

**Practical consequence:** the crash blocker (rows 13/14/37/38's
primary obstacle) is resolved -- the app is confirmed to run stably on
real hardware. The remaining obstacle to completing the actual
feature-level physical checklist (login, messaging, voice/video
record+playback, etc.) is this separate, narrower, well-understood
input-injection limitation, not the application itself. The next
concrete step if physical validation is resumed: either (a) a person
physically taps the device once to enable the relevant developer
option, after which `adb shell input` should work normally for the
rest of the session, or (b) reconnect via USB ADB instead of wireless
and re-test `input tap` against the launcher first (cheap, ~10 seconds)
before assuming it is fixed.

## 2026-09-26/28 -- real physical-device session: registration, login,
## TOFU verification, and a genuine Android<->Desktop E2E encrypted
## text message, all with a human operator's touch

With the touch-injection limitation above confirmed unfixable from
this environment alone, the human operator performed the physical taps
directly on the Vivo V2036 (screen-reading and coordination handled
remotely via wireless-ADB screenshots/logcat/package inspection, per
the "physical interaction strategy" this pass's own mandate
specified), while a real Desktop peer account was driven
programmatically (no touch needed -- it runs on the Windows host, not
the touchscreen device) using the project's own real `client.session.
ClientSession` class, the exact same class `main.py`'s Desktop GUI
uses -- no mock, no test-only shortcut.

**Real, human-touch-confirmed results, in order:**
1. Registration via the real onboarding flow ("Get Started" ->
   register form -> "Account created. Please log in.") -- a real
   network round trip to a real running server (`scripts/
   run_physical_validation_server.py`, reused from the 2026-09-22
   session, still listening on port 5000 throughout), real Argon2id
   password hashing, a real row written to the real database.
2. Login with the newly-created credentials -- real JWT issuance and
   validation, landing on the real Chats/Groups/Devices/Settings tab
   UI.
3. Real contact search by phone number, opening a real new
   conversation with a Desktop peer account.
4. **A real, working security rejection observed live**: before the
   Desktop peer's identity was verified, its incoming text message was
   correctly shown as "A message from an unverified contact was
   blocked." and a separately-arrived packet as "A message could not
   be decrypted and was blocked." -- TOFU enforcement and encrypted-
   payload authentication both refusing unverified/undecryptable
   content exactly as designed, not a bug.
5. Real mutual verification: the Desktop peer independently observed
   the Android device's identity, derived its fingerprint
   (`fingerprint_combined_identity`), and called the real
   `ClientSession.confirm_peer_verification()` (the same, only,
   production method `gui/verify_identity_dialog.py` ever calls) --
   then the human operator tapped "Verify Identity" on the physical
   Android UI, which changed to "Re-verify" (i.e. now verified).
6. **A real Android -> Desktop end-to-end encrypted text message**:
   the human operator typed "hello" on the physical device's real
   keyboard and tapped Send; the Desktop peer's `load_conversation_
   history()` (the same method the real GUI's own history view calls)
   returned `{'sender': 'vivotest1', 'text': 'hello', 'is_own': False,
   ...}` -- genuinely decrypted plaintext, not inferred or assumed.
   This is real evidence that the full pipeline (ML-KEM-768 session
   establishment, ML-DSA-65-signed identity, AES-256-GCM message
   encryption, real TLS transport, real server relay, real decryption)
   works end-to-end between a physical Android device and a real
   Desktop peer.

**A real scripting bug was found and fixed during this process** (in
the throwaway Desktop-peer driver script, not in tracked project
source): the script initially omitted `session.send_public_key()` and
`session.start_receiver()` after `login()` -- both required in the
real production sequence (`main.py`'s own GUI launch path always calls
them) but easy to omit when driving `ClientSession` directly. Their
absence silently prevented the peer's identity from ever reaching the
other side and its receiver thread from ever running, which looked
like a hang. Fixed by matching the exact real launch sequence.

**What this does NOT yet establish**: voice recording, video
recording, voice/video playback, and voice/video E2E (rows 13, 14, 37,
38) specifically -- the session above validated real text messaging
and the shared verification/session-key pipeline those features also
depend on, but did not reach the attachment/recording UI before the
wireless ADB connection dropped (the device went idle across a long
gap between coordination turns, and re-pairing subsequently failed at
the network layer -- `ping` to the phone's newly-assigned address
showed 100% packet loss, i.e. the computer and phone were no longer on
a mutually routable network, not an ADB or application problem).
Rows 13/14/37/38 remain PARTIAL on that basis -- this is real,
substantial progress (the identical session-key/encryption pipeline
voice/video reuses is now proven working end-to-end on physical
hardware for text) but is honestly short of the specific voice/video
evidence those four rows require. Resuming needs: the phone reachable
on the same network as this host again, a fresh wireless pairing (or
USB), and picking up from "app already logged in and verified with a
reachable Desktop peer" -- registration/login/verification do not need
to be repeated once both sides are back on the same network, since
QRSCS persists sessions/verified-peer state locally.
