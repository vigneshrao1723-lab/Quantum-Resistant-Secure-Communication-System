"""
The Desktop executable build refuses to ship anything secret.

These tests exercise ``scripts/build_desktop_exe.validate`` on hostile
fixtures built at run time; they do not run PyInstaller. (The real build is
exercised end to end by tests/acceptance.)
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import build_desktop_exe, package_release  # noqa: E402


@pytest.fixture()
def app_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(package_release, "live_secret_values", lambda root=None: [b"live-secret-value-123"])
    folder = tmp_path / build_desktop_exe.APP_NAME
    (folder / "_internal" / "certs" / "dev").mkdir(parents=True)
    (folder / f"{build_desktop_exe.APP_NAME}.exe").write_bytes(b"MZ binary")
    (folder / "_internal" / "certs" / "dev" / "ca.crt").write_text("public certificate")
    (folder / ".env.example").write_text(build_desktop_exe.CLIENT_ENV_EXAMPLE)
    return folder


def test_a_clean_bundle_passes(app_dir):
    assert build_desktop_exe.validate(app_dir) == []


def test_a_missing_executable_fails(app_dir):
    (app_dir / f"{build_desktop_exe.APP_NAME}.exe").unlink()

    assert any("was not produced" in p for p in build_desktop_exe.validate(app_dir))


@pytest.mark.parametrize("name", [".env", "server.key", "ca.key", "server.crt", "id_rsa", "notes.log", "x.sqlite3"])
def test_secret_looking_files_are_refused(app_dir, name):
    (app_dir / "_internal" / name).write_text("irrelevant")

    assert build_desktop_exe.validate(app_dir), name


def test_a_configured_live_secret_value_in_any_file_is_refused(app_dir):
    (app_dir / "_internal" / "library.bin").write_bytes(b"prefix live-secret-value-123 suffix")

    problems = build_desktop_exe.validate(app_dir)

    assert any("live secret" in p for p in problems)
    assert not any("live-secret-value-123" in p for p in problems)  # the value itself is never reported


def test_the_client_env_template_sets_only_non_secret_options():
    settings = [
        line.split("=", 1)[0].strip().lstrip("#").strip()
        for line in build_desktop_exe.CLIENT_ENV_EXAMPLE.splitlines()
        if "=" in line
    ]

    assert settings == ["SERVER_HOST", "SERVER_PORT", "TLS_CA_FILE"]
