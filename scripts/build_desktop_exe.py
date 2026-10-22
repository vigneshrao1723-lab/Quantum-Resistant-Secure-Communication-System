"""Build and validate the Windows Desktop client (PyInstaller, one-folder).

Usage (from the project root, inside the project's Python 3.12 virtualenv):

    python scripts/build_desktop_exe.py [--ca-cert PATH] [--out DIR]

Output: ``dist/desktop/QRSCS-Desktop/QRSCS-Desktop.exe`` (plus its ``_internal``
folder -- distribute the whole folder). Intermediate files go to
``dist/desktop-work``; both are git-ignored.

After building, the output tree is checked: it must contain no ``.env``, no
private key, certificate key, log, database file or token file, and no file may
contain a value that is currently configured as a live secret in this
checkout's ``.env``. The build fails (non-zero exit, output removed) otherwise.
Secret values are never printed.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import package_release  # noqa: E402

APP_NAME = "QRSCS-Desktop"

CLIENT_ENV_EXAMPLE = """\
# Copy this file to ".env" next to QRSCS-Desktop.exe and edit it.
# It is read at start-up. Nothing in it is a secret: it only says where the
# server is and which certificate authority to trust.

# Address of the QRSCS server. This hostname/IP must appear in the server
# certificate's subject alternative names.
SERVER_HOST=127.0.0.1
SERVER_PORT=5000

# Optional: path to the CA certificate that signed the server certificate.
# When unset, the CA certificate bundled with this build is used.
# TLS_CA_FILE=C:\\path\\to\\ca.crt
"""


def make_icon(target: Path) -> Path:
    """Write the executable's .ico from the application's drawn brand mark."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtGui import QGuiApplication

    from gui.icons import brand_pixmap

    app = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841 -- must stay alive while painting
    target.parent.mkdir(parents=True, exist_ok=True)
    if not brand_pixmap(256).toImage().save(str(target), "ICO"):
        raise RuntimeError("could not write the executable icon")
    return target


def build(out_dir: Path, ca_cert: Path | None) -> Path:
    work = out_dir.parent / "desktop-work"
    env = dict(os.environ)
    env["QRSCS_ICON"] = str(make_icon(work / "qrscs.ico"))
    if ca_cert is not None:
        env["QRSCS_CA_CERT"] = str(ca_cert)
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--distpath", str(out_dir), "--workpath", str(work),
        str(ROOT / "scripts" / "qrscs_desktop.spec"),
    ]
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    app_dir = out_dir / APP_NAME
    (app_dir / ".env.example").write_text(CLIENT_ENV_EXAMPLE, encoding="utf-8")
    return app_dir


def validate(app_dir: Path) -> list[str]:
    """Return a list of problems (never secret values)."""
    problems: list[str] = []
    live = package_release.live_secret_values(ROOT)
    allowed = package_release.ALLOWED_NAMES
    exe = app_dir / f"{APP_NAME}.exe"
    if not exe.is_file():
        problems.append(f"{exe.name} was not produced")
    count = 0
    for path in sorted(app_dir.rglob("*")):
        if not path.is_file():
            continue
        count += 1
        rel = path.relative_to(app_dir).as_posix()
        name = path.name
        if name not in allowed and any(fnmatch.fnmatch(name.lower(), p) for p in package_release.FORBIDDEN_NAME_PATTERNS):
            # Library files such as ".pyc" inside the bundle are not expected; flag everything.
            problems.append(f"{rel}: forbidden file name")
            continue
        if path.stat().st_size <= 200_000_000:
            data = path.read_bytes()
            if any(v and v in data for v in live):
                problems.append(f"{rel}: contains a configured live secret value")
    for forbidden in ("server.key", "ca.key", "server.crt"):
        if any(p.name == forbidden for p in app_dir.rglob("*")):
            problems.append(f"{forbidden} must not be bundled")
    print(f"validated {count} files in {app_dir}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ca-cert", type=Path, default=None,
                        help="public CA certificate to bundle (default: certs/dev/ca.crt)")
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "desktop")
    args = parser.parse_args(argv)

    app_dir = build(args.out.resolve(), args.ca_cert)
    problems = validate(app_dir)
    if problems:
        for problem in problems:
            print("FAIL:", problem, file=sys.stderr)
        shutil.rmtree(app_dir, ignore_errors=True)
        return 1
    print(f"OK: {app_dir / (APP_NAME + '.exe')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
