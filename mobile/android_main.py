"""
Phase 19.7 -- Android build entrypoint.

Buildozer/python-for-android hard-require a file literally named
``main.py`` at the project's ``source.dir`` root (buildozer 1.6.0 has
no configurable "source.main" option -- confirmed by inspecting its
own source before writing this file). The repository's actual root
``main.py`` launches the DESKTOP PySide6 application
(`gui.main_window.MainWindow`) -- the project's own primary,
documented entry point (`python main.py`), which must keep working
unmodified and must not gain a new hard Kivy dependency just to
determine which app to launch.

This file is therefore never imported by the desktop app and is not
itself named ``main.py`` in the tracked source tree. The Android build
process (see docs/architecture/mobile_client.md's own "Android build
entrypoint swap" section) temporarily copies this file to
``main.py`` -- backing up the real one first -- runs `buildozer
android debug`, then restores the original ``main.py`` byte-for-byte.
No permanent change to the repository's desktop entry point; no
duplication of mobile/app.py's own logic (this is a two-line
redirect, not a second implementation).
"""

import os
import sys

# Phase 19.7 -- CPython's own import machinery dlopen()s extension
# modules (cryptography's Rust _rust.abi3.so, pynacl, argon2-cffi,
# pycryptodome, cffi) without RTLD_GLOBAL by default. Those modules
# leave CPython C-API symbols (e.g. PyExc_TypeError) undefined,
# expecting them to resolve against the already-loaded
# libpython3.14.so -- which works on glibc's default symbol search
# but not on Android's bionic linker unless the *loading* dlopen call
# itself uses RTLD_GLOBAL. Confirmed via a real on-device crash
# ("dlopen failed: cannot locate symbol PyExc_TypeError") and by
# inspecting _rust.abi3.so with llvm-nm/llvm-readelf: the symbol is
# genuinely exported by libpython3.14.so, just not visible to a later
# independent dlopen(). This is the standard, documented fix for this
# exact class of issue on Android/bionic; it must run before any
# extension-module import, hence its place at the top of this file.
sys.setdlopenflags(os.RTLD_NOW | os.RTLD_GLOBAL)

# Phase 19.16 -- pycryptodome's Crypto.Util._cpu_features (imported at
# module load time by Crypto.Cipher.AES, which crypto/aes.py imports)
# calls Crypto.Util._raw_api.load_pycryptodome_raw_lib() to pick which
# prebuilt native library variant to dlopen for this interpreter, and
# that helper calls the *stdlib's* platform.architecture(), which in
# turn shells out to the external "file" command via
# platform._syscmd_file()'s own subprocess.check_output() call.
# fork() (which subprocess uses) is unsafe in a multi-threaded Android
# app process -- only the calling thread is cloned, so any lock held
# by another thread at fork time can deadlock or crash the child --
# and confirmed via repeated on-device reproduction (a native, non-
# Python SIGSEGV inside _posixsubprocess, ~15-20s after cold start,
# with no user interaction needed) that it does exactly that here,
# freezing the whole app. _syscmd_file() already has a try/except
# around the subprocess call that is *meant* to handle "the file
# command isn't available" by returning '' (its documented, tested
# behavior on any system lacking /usr/bin/file), and
# platform.architecture() already falls back gracefully to
# struct.calcsize('P') when _syscmd_file() returns '' -- but Android's
# fork crashes natively instead of raising a catchable OSError, so
# that existing safety net never gets a chance to run. Short-
# circuiting _syscmd_file() to always return '' (as if "file" were
# simply not installed, which is already-anticipated stdlib behavior)
# makes platform.architecture() take that same, already-correct
# fallback path without ever forking. This changes no cryptographic
# behavior, algorithm, or key material -- it only avoids one unsafe
# platform-probing helper pycryptodome's import path happens to reach.
import platform as _platform_fix

_platform_fix._syscmd_file = lambda target, default='': default

from mobile.app import main

if __name__ == "__main__":
    main()
