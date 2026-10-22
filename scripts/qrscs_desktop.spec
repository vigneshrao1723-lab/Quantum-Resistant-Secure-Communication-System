# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the QRSCS Desktop client (one-folder build).

Build it with ``python scripts/build_desktop_exe.py`` -- that script sets the
output folders and validates the result. Running ``pyinstaller`` on this file
directly also works.

What is bundled (read-only):
  * the application code and its pinned dependencies
  * ``gui/resources`` (images)
  * the PUBLIC CA certificate the client verifies the server against
    (``QRSCS_CA_CERT``, default ``certs/dev/ca.crt``)

What is deliberately NOT bundled: ``.env``, any private key (``*.key``), the
server certificate/key, the database/JWT configuration, logs, key stores, and
every server-only module. The Desktop client talks to the server only over the
network (see tests/test_client_import_boundary.py).
"""

import os
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 -- provided by PyInstaller

ca_cert = Path(os.environ.get("QRSCS_CA_CERT", ROOT / "certs" / "dev" / "ca.crt"))

icon = os.environ.get("QRSCS_ICON")

datas = [(str(ROOT / "gui" / "resources"), "gui/resources")]
if ca_cert.is_file():
    datas.append((str(ca_cert), "certs/dev"))
else:
    print(f"WARNING: CA certificate {ca_cert} not found; the build will not trust any server by default.")

# Server-only, mobile-only and test-only packages must never end up in a client.
excludes = [
    "sqlalchemy", "alembic", "psycopg2", "websockets", "kivy", "kivymd",
    "playwright", "pytest", "quickjs", "tkinter", "unittest",
    "mobile", "server", "database", "tests", "web", "scripts", "benchmark", "demo",
]

a = Analysis(  # noqa: F821
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="QRSCS-Desktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=icon if icon and Path(icon).is_file() else None,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="QRSCS-Desktop",
)
