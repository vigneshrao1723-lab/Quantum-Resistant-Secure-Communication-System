#!/usr/bin/env bash
set -euo pipefail

# Android APK build helper (Phase 19.19 -- L-6 closure).
#
# Run from inside WSL2, from the repository root, against an
# environment that has ALREADY been through the one-time WSL2 Android
# toolchain setup documented in docs/architecture/mobile_client.md's
# "Phase 19.7 -- real WSL2 Android build and physical-device
# validation" section (Buildozer, Android SDK/NDK, a JDK 17 install
# alongside the system default, and the p4a/build-tool patches already
# applied to .buildozer/'s build-tool cache). This script does not
# attempt to redo that one-time setup -- it automates the REPEATABLE
# per-build sequence that was, before this phase, only ever performed
# manually:
#
#   1. swap mobile/android_main.py in as the project's main.py
#      (buildozer/python-for-android hard-require that literal
#      filename at source.dir's root -- see mobile/android_main.py's
#      own docstring), backing up and restoring the real desktop
#      main.py byte-for-byte regardless of how the build ends
#   2. point JAVA_HOME at a JDK 17 (Gradle cannot run under JDK 25 --
#      "Unsupported class file major version 69", Phase 19.7 finding)
#   3. activate the Buildozer virtualenv Phase 19.7's setup created,
#      if the caller has not already activated one of their own
#   4. run `buildozer android <target>` (default: debug)
#   5. locate the resulting .apk under bin/, print its path and
#      SHA-256
#
# Usage:
#   scripts/build_android_apk.sh [debug|release]
#
# Environment overrides (all optional -- defaults match Phase 19.7's
# own WSL2 setup exactly):
#   JAVA_HOME          -- a JDK 17 install (default: /usr/lib/jvm/java-17-openjdk-amd64)
#   BUILDOZER_VENV     -- a virtualenv with buildozer installed
#                         (default: ~/fyp-android-venv), only used if
#                         `buildozer` is not already on PATH

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -f buildozer.spec ]; then
    echo "buildozer.spec not found at $REPO_ROOT -- run this from inside the repository checkout." >&2
    exit 1
fi

if [ ! -f mobile/android_main.py ]; then
    echo "mobile/android_main.py not found -- nothing to swap in as the build entrypoint." >&2
    exit 1
fi

JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

if [ ! -x "$JAVA_HOME/bin/java" ]; then
    echo "JAVA_HOME ($JAVA_HOME) has no bin/java -- set JAVA_HOME to a real JDK 17 install (Gradle fails under JDK 25)." >&2
    exit 1
fi

if ! command -v buildozer >/dev/null 2>&1; then
    BUILDOZER_VENV="${BUILDOZER_VENV:-$HOME/fyp-android-venv}"
    if [ -f "$BUILDOZER_VENV/bin/activate" ]; then
        # shellcheck disable=SC1090
        source "$BUILDOZER_VENV/bin/activate"
    fi
fi

if ! command -v buildozer >/dev/null 2>&1; then
    echo "buildozer not found on PATH and not found in \$BUILDOZER_VENV ($BUILDOZER_VENV)." >&2
    echo "Install it (pip install buildozer) or set BUILDOZER_VENV to point at a venv that has it." >&2
    exit 1
fi

BACKUP_MAIN="$(mktemp)"
cp main.py "$BACKUP_MAIN"

restore_main() {
    cp "$BACKUP_MAIN" main.py
    rm -f "$BACKUP_MAIN"
}
trap restore_main EXIT

cp mobile/android_main.py main.py

BUILD_TARGET="${1:-debug}"
echo "Building Android $BUILD_TARGET APK..."
buildozer android "$BUILD_TARGET"

APK="$(find bin -maxdepth 1 -iname '*.apk' -newer "$BACKUP_MAIN" 2>/dev/null | sort | tail -n 1)"
if [ -z "$APK" ]; then
    # Fallback: buildozer's own mtime handling can differ by
    # filesystem; the most-recently-modified .apk under bin/ is still
    # a correct answer for "what did this run just produce" as long as
    # bin/ only ever holds this project's own APKs, which it does.
    APK="$(find bin -maxdepth 1 -iname '*.apk' 2>/dev/null -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2-)"
fi

if [ -z "$APK" ]; then
    echo "Build finished but no .apk was found under bin/." >&2
    exit 1
fi

SHA256="$(sha256sum "$APK" | awk '{print $1}')"

echo "APK path: $APK"
echo "APK SHA-256: $SHA256"
