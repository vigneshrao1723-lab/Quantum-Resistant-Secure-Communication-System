"""Fixtures for the acceptance suite (run separately: ``pytest tests/acceptance``).

These tests need a built Desktop executable (``python scripts/build_desktop_exe.py``)
and the isolated acceptance database (created here, fresh for every session).
Synthetic accounts only; credentials exist in memory for the run and are never
written to disk or logs.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from tests.acceptance import desktop_driver, evidence, stack as stack_module, web_driver

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXE = ROOT / "dist" / "desktop" / "QRSCS-Desktop" / "QRSCS-Desktop.exe"
ARTIFACTS = ROOT / "dist" / "acceptance"


def new_password() -> str:
    # Satisfies the password policy (length, upper, lower, digit, symbol); random per account.
    return "Aa1!" + secrets.token_urlsafe(14)


def new_identity(prefix: str):
    suffix = uuid.uuid4().hex[:8]
    password = new_password()
    evidence.record_password(password)
    return {
        "username": f"{prefix}_{suffix}",
        "phone": "+91" + str(uuid.uuid4().int % 10**10).zfill(10),
        "password": password,
    }


@pytest.fixture(scope="session")
def run_dir():
    path = ARTIFACTS / time.strftime("run-%Y%m%d-%H%M%S")
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def stack(run_dir):
    import acceptance_db  # scripts/ is put on sys.path by stack.py

    acceptance_db.create()
    s = stack_module.AcceptanceStack(run_dir).start()
    yield s
    s.stop()


@pytest.fixture(scope="session")
def exe_path():
    path = Path(os.environ.get("QRSCS_DESKTOP_EXE", DEFAULT_EXE))
    assert path.is_file(), f"Desktop executable not built: {path} (run scripts/build_desktop_exe.py)"
    # Start it once and close it again so the operating system's first-run scan of a new build is
    # paid here, not inside the first scenario's timing.
    import subprocess

    warm_env = {k: v for k, v in os.environ.items() if k != "QT_QPA_PLATFORM"}
    warm = subprocess.Popen([str(path)], env=warm_env)
    time.sleep(8)
    warm.terminate()
    try:
        warm.wait(timeout=15)
    except subprocess.TimeoutExpired:
        warm.kill()
    return path


@pytest.fixture(scope="session")
def uia():
    agent = desktop_driver.UiaAgent()
    yield agent
    agent.close()


@pytest.fixture(scope="session")
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        yield b
        b.close()


@pytest.fixture()
def web_user(browser, stack):
    users = []

    def make(prefix="web"):
        ident = new_identity(prefix)
        user = web_driver.WebUser(browser, stack, ident["username"], ident["phone"], ident["password"])
        users.append(user)
        return user

    yield make
    for user in users:
        user.close()


@pytest.fixture()
def desktop_user(stack, exe_path, uia):
    apps = []

    def make(prefix="desk"):
        ident = new_identity(prefix)
        key_store = Path(tempfile.mkdtemp(prefix="qrscs_ks_"))
        app = desktop_driver.DesktopApp([str(exe_path)], stack.client_env(key_store), uia)
        app.identity = ident
        app.username, app.phone, app.password = ident["username"], ident["phone"], ident["password"]
        app.key_store = key_store
        apps.append(app)
        return app

    yield make
    for app in apps:
        app.stop()
        shutil.rmtree(app.key_store, ignore_errors=True)


def digits(text: str) -> str:
    """Normalise a displayed fingerprint for comparison (hex groups, no spaces/newlines)."""
    return re.sub(r"[^0-9A-Fa-f]", "", text).upper()


@pytest.fixture()
def party(web_user, desktop_user):
    """Factory: a registered and logged-in participant of the given kind ("web" or "desktop")."""
    from tests.acceptance.parties import DesktopParty, WebParty

    made = []

    def make(kind, prefix=None, login=True):
        prefix = prefix or kind[:3]
        p = WebParty(web_user(prefix)) if kind == "web" else DesktopParty(desktop_user(prefix))
        p.register()
        if login:
            p.login()
        made.append(p)
        return p

    yield make


# ---------------------------------------------------------------------------
# Evidence: per-test results and the account ledger (no credentials, ever)
# ---------------------------------------------------------------------------

_RESULTS: list[dict] = []
LEDGER: list[dict] = []


def pytest_runtest_logreport(report):
    if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
        _RESULTS.append({"test": report.nodeid, "outcome": report.outcome, "seconds": round(report.duration, 2)})


def pytest_sessionfinish(session, exitstatus):
    import json

    run_dirs = sorted(ARTIFACTS.glob("run-*")) if ARTIFACTS.exists() else []
    if not run_dirs:
        return
    target = run_dirs[-1]
    (target / "test_results.json").write_text(json.dumps(_RESULTS, indent=2), encoding="utf-8")
    (target / "accounts.json").write_text(json.dumps(LEDGER, indent=2), encoding="utf-8")


POPULATION_WEB = int(os.environ.get("QRSCS_ACCEPT_WEB", "8"))
POPULATION_DESKTOP = int(os.environ.get("QRSCS_ACCEPT_DESKTOP", "2"))


@pytest.fixture(scope="session")
def population(stack, browser, exe_path, uia):
    """Registered AND logged-in accounts, created through the real registration forms.

    Every attempt is recorded in the ledger (username, client, registration/login outcome) so the
    report can state exact counts. Passwords are random per account and live only in memory.
    """
    from tests.acceptance.parties import DesktopParty, WebParty

    parties = []
    keystores = []

    def attempt(kind, index):
        ident = new_identity(f"{kind[:3]}{index:02d}")
        entry = {"username": ident["username"], "client": kind, "registered": False, "logged_in": False, "error": None}
        LEDGER.append(entry)
        try:
            if kind == "web":
                party = WebParty(web_driver.WebUser(browser, stack, ident["username"], ident["phone"], ident["password"]))
            else:
                ks = Path(tempfile.mkdtemp(prefix="qrscs_ks_"))
                keystores.append(ks)
                app = desktop_driver.DesktopApp([str(exe_path)], stack.client_env(ks), uia)
                app.username, app.phone, app.password = ident["username"], ident["phone"], ident["password"]
                party = DesktopParty(app)
            party.register()
            entry["registered"] = True
            party.login()
            entry["logged_in"] = True
            parties.append(party)
        except Exception as error:  # recorded, then re-raised by the test that needs the account
            entry["error"] = f"{type(error).__name__}: {str(error)[:200]}"
        return entry

    for i in range(POPULATION_WEB):
        attempt("web", i)
    for i in range(POPULATION_DESKTOP):
        attempt("desktop", i)

    yield parties

    for party in parties:
        party.close()
    for ks in keystores:
        shutil.rmtree(ks, ignore_errors=True)
