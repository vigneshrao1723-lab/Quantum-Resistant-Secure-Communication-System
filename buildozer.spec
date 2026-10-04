[app]

title = QRSCS Mobile
package.name = qrscs_mobile
package.domain = org.qrscs

# mobile/ is the app package; the rest of the repo's own Python
# modules (crypto/, utils/, storage/, payload/, domain/, security/,
# auth/, client/receiver.py, config.py, logger_config.py) are included
# unmodified via source.include_patterns below -- mobile/session.py
# imports them directly (see that module's own docstring for why: this
# is the SAME code the desktop client already ships, not a port).
source.dir = .
# Phase 19.7 -- added crt: source.include_exts and source.include_patterns
# both gate what actually gets bundled, and certs/dev/ca.crt (needed by
# security/tls.py's build_client_context() for TLS server-cert
# verification) was silently NEVER included despite being named in
# source.include_patterns below, confirmed by inspecting a built APK's
# actual contents -- .crt was simply missing from this extension list.
source.include_exts = py,png,jpg,kv,atlas,pem,crt
# Phase 19.7 -- certs/* was tightened to certs/dev/ca.crt specifically:
# the client only ever needs the CA cert to verify the server's TLS
# chain (security/tls.py's build_client_context()); the original
# wildcard was also bundling certs/dev/server.key and certs/dev/ca.key
# (the server's and CA's own PRIVATE keys) into a distributable,
# more-easily-extracted mobile APK for no reason -- caught during a
# real security review of what source.include_patterns actually pulls
# in, not by any functional test failure.
#
# Phase 19.9 -- that "tightening" never actually worked: buildozer's
# own _copy_application_sources() (buildozer/__init__.py) only ever
# uses include_patterns to READMIT a file/dir an exclude_dirs/
# exclude_patterns rule already ruled out -- it is not a standalone
# allowlist, so listing certs/dev/ca.crt here never stopped
# certs/dev/server.crt (a PUBLIC cert, not a secret, but still not the
# stated intent) from being swept in by source.include_exts' bare
# "crt" extension match. Confirmed by reading that function directly
# and by finding certs/dev/server.crt inside a real built APK's
# assets/private.tar. The .key files were never at risk (.key is not
# in include_exts at all), but the cert-bundling logic is now made to
# actually match its own stated intent: exclude the whole certs/ dir,
# then explicitly readmit only certs/dev/ (so the walk descends into
# it) and certs/dev/ca.crt at the file level; certs/dev/server.crt is
# excluded by an explicit file-level pattern so it stops passing
# through on the bare extension match.
source.include_patterns = mobile/*,crypto/*,utils/*,storage/*,payload/*,domain/*,security/*,auth/*,client/receiver.py,config.py,logger_config.py,certs/dev/,certs/dev/ca.crt
# Phase 19.21 -- phase197_peer_session.py/phase197_seed_test_account.py
# are one-off, self-documented "safe to delete" Phase 19.7 debug
# scripts sitting at the repo root (never part of source.include_
# patterns above) -- source.include_exts' bare "py" extension match
# was sweeping them into the shipped APK's private.tar regardless,
# the same class of unintended inclusion the certs/dev/server.crt
# exclusion below already exists to prevent. Found via a real APK
# content audit (not a functional test failure): their compiled
# .pyc carried the throwaway Phase 19.7 test-account password
# ("TestPass197SecureThree!") into the bundle. That password is not
# a real credential (a fake @example.invalid account on the local
# dev server only), but debug/test material has no reason to ship in
# a final artifact -- excluded here rather than deleted, since
# deleting the actual files was explicitly out of scope this phase.

# Phase 19.24 -- real APK content audit (same methodology as the
# Phase 19.21 finding above -- unzip a built APK and read assets/
# private.tar, not a functional test): config_server.py was NEVER
# meant for a client build at all -- its own module docstring says so
# explicitly ("Everything the SERVER needs and a client must never
# hold: database credentials, the JWT signing secret...") -- but it
# sits at the repo root alongside config.py (which IS legitimately
# needed client-side), so source.include_exts' bare "py" extension
# match was sweeping it in regardless of not being named in source.
# include_patterns above, the exact same unintended-inclusion class
# the phase197_*.py exclusion already exists to prevent. Its compiled
# .pyc carried this project's actual dev-environment DATABASE_URL
# (postgres:postgres@localhost) and the literal JWT_SECRET_KEY
# fallback string into the shipped APK -- both trivially recoverable
# from a decompiled .pyc. Excluded here, never imported by any mobile/
# client/receiver.py/config.py code path that was already shipping
# correctly, so this removes a real credential-exposure risk with no
# functional change to the app at all.
source.exclude_patterns = certs/dev/server.crt,phase197_peer_session.py,phase197_seed_test_account.py,config_server.py
source.exclude_dirs = tests,gui,web,server,database,alembic,demo,benchmark,scripts,docs,venv,.git,.claude,.pytest_cache,.ruff_cache,logs,storage_blobs,__pycache__,certs

version = 0.1.0

# ML-KEM-768/ML-DSA-65 (pyca/cryptography-based crypto/kyber.py,
# crypto/ml_dsa.py -- see those modules for the exact library versions
# this project pins), TLS via Python's own ssl module -- no crypto
# reimplementation for mobile; the same requirements.txt this project's
# desktop client already uses.
#
# Phase 19.7 -- pycryptodome, python-dotenv and kyber-py were added
# after a real on-device ModuleNotFoundError trace (config.py needs
# dotenv; crypto/aes.py needs Crypto/pycryptodome for AES-256-GCM;
# crypto/kyber.py needs kyber_py for its ML-KEM-768 reference
# implementation) -- confirmed reachable at runtime by tracing the
# actual mobile/session.py import chain, not guessed. pycryptodome has
# its own p4a recipe; python-dotenv and kyber-py are pure Python and
# install via p4a's pure-python-modules pip step.
requirements = python3,kivy==2.3.1,cryptography,pynacl,sqlalchemy,pydantic,argon2-cffi,pycryptodome,python-dotenv,kyber-py

orientation = portrait
fullscreen = 0

# RECORD_AUDIO/CAMERA -- real native voice/video recording
# (mobile/app.py::_record_voice_android()/_record_video_android(), via
# android.media.MediaRecorder through pyjnius). Both are Android
# "dangerous" permissions requiring the SAME runtime request flow (not
# just this manifest declaration) -- see android.permissions.
# request_permissions() at each recording entry point.
android.permissions = INTERNET,RECORD_AUDIO,CAMERA

# Phase 19.7 -- set to match the ACTUAL installed WSL2 Android
# toolchain (platforms;android-36, ndk;28.2.13676358 -- confirmed via
# `sdkmanager --list_installed` before this file was touched; only
# platform 36 is installed, not 33, so 33 would fail with "platform
# not found" regardless of NDK compatibility). minapi stays well below
# NDKAPI=21's own floor and well below the physical test device's
# Android 14 / API 34, matching this project's real target hardware
# (Infinix X6711) with headroom for older devices.
android.api = 36
android.minapi = 24
android.ndk = 28.2.13676358
android.archs = arm64-v8a

# 2026-09-22 -- physical-device validation on a real Vivo V2036
# (Android 13/API 33, Qualcomm "bengal"/Adreno 610) reproduced a
# 100%-deterministic native crash at app startup, before any of this
# app's own Python code runs: `Fatal signal 11 (SIGSEGV) ... in tid
# (Jit thread pool), pid (SDLActivity)`, immediately after SDL2's own
# EGL/BLASTBufferQueue setup. android.api=34 (this device's own real
# API level) is not installable in this WSL toolchain (only platform
# 36 is present in the read-only shared SDK, and this build user has
# no root/sudo to add another -- see this repo's own mobile_client.md
# "Toolchain fixes required" section). vmSafeMode is Android's own
# standard, documented mitigation for exactly this class of JIT-
# related native crash -- it forces the interpreter-only execution
# path (no JIT/AOT compilation) for this app specifically, a runtime
# execution-mode flag with no effect on cryptography, key material, or
# any of this project's own security architecture.
android.extra_manifest_application_arguments = android_extra_manifest_application_arguments.txt

# Phase 19.7 -- without these two explicit paths, buildozer ignores
# the pre-installed WSL2 Android SDK/NDK entirely and downloads its
# OWN separate copy into ~/.buildozer/android/platform/ (confirmed by
# directly observing a first build attempt start doing exactly that,
# discarded before it could waste real time/bandwidth on a duplicate,
# already-present toolchain -- see docs/architecture/mobile_client.md).
# Real, recognized buildozer.spec keys (confirmed by reading
# buildozer/targets/android.py's own android_sdk_dir/android_ndk_dir
# properties before adding these).
#
# android.sdk_path points at a user-owned symlink shim
# (~/android-sdk-shim), NOT /usr/lib/android-sdk directly:
# buildozer/targets/android.py::sdkmanager_path is hard-coded to
# <sdk_path>/tools/bin/sdkmanager (the legacy pre-"cmdline-tools"
# layout), which the actual, root-owned, modern SDK install at
# /usr/lib/android-sdk does not have (only cmdline-tools/17.0/bin/
# sdkmanager exists there) -- and this WSL user has no passwordless
# sudo to create it there directly. The shim is a small, user-owned
# directory of symlinks back into the real (untouched, unmodified)
# /usr/lib/android-sdk content, plus one extra symlink satisfying
# buildozer's own legacy path expectation -- confirmed working via a
# direct `sdkmanager --list_installed` run through it before wiring it
# into this file. See docs/architecture/mobile_client.md for the exact
# shim-creation commands.
android.sdk_path = /home/vignesh_t/android-sdk-shim
android.ndk_path = /usr/lib/android-sdk/ndk/28.2.13676358

# Phase 19.7 -- the shim above is read-only symlinks back into the
# root-owned real SDK; buildozer's own default behavior unconditionally
# tries to `sdkmanager --update`/reinstall platform-tools and the
# latest build-tools on every run (buildozer/targets/android.py::
# AndroidTarget.install_platform()), which needs WRITE access this WSL
# user does not have on /usr/lib/android-sdk. Every component this
# build actually needs (build-tools 36.0.0, platforms;android-36, ndk
# 28.2.13676358, platform-tools) is already installed -- this is a
# real, documented buildozer.spec option for exactly that case, not a
# workaround (confirmed by reading install_platform()'s own
# android.skip_update check before adding it).
android.skip_update = True

[buildozer]
log_level = 2
warn_on_root = 1
