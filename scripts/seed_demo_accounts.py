"""Create the two demo accounts through the real applications (no database inserts).

    venv\\Scripts\\python.exe scripts\\seed_demo_accounts.py            # needs the demo stack running

  demo_alice  registers and logs in through the real Desktop application window (the built
              QRSCS-Desktop.exe by default, or ``--source`` for main.py through the venv pythonw),
              using the Desktop's normal key store, so the identity stays usable afterwards.
  demo_bob    registers and logs in through the real Website in Chrome, in a dedicated, persistent
              Chrome profile (~/.qrscs/demo-chrome-bob) so its identity keys stay in that browser.
              Open it again with scripts\\open_demo_website.cmd.

Both go to the demo stack of scripts/start_demo.py (database ``qrscs_demo``). The phone numbers and the
random passwords are written to ~/.qrscs/demo_accounts.txt (outside the repository, current-user-only
permissions). The passwords are never printed. The script refuses to run twice (it will not overwrite
that file) and checks the accounts do not already exist.

The Desktop windows are driven through UI Automation: leave the keyboard and mouse alone while it runs.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

DEMO_DB = "qrscs_demo"
STATE_FILE = ROOT / "logs" / "demo" / "stack.json"
ACCOUNTS_FILE = Path.home() / ".qrscs" / "demo_accounts.txt"
BOB_PROFILE = Path.home() / ".qrscs" / "demo-chrome-bob"
WEB_URL = "http://127.0.0.1:8010/index.html"
GATEWAY_URL = "ws://127.0.0.1:8765"
DEFAULT_EXE = ROOT / "dist" / "desktop" / "QRSCS-Desktop" / "QRSCS-Desktop.exe"


def identity(username):
    return {
        "username": username,
        "phone": "+91" + str(uuid.uuid4().int % 10**10).zfill(10),
        "password": "Aa1!" + secrets.token_urlsafe(14),  # satisfies the password policy
    }


def db_usernames():
    import acceptance_db
    import psycopg2
    import setup_database_roles as roles

    app_url, _ = acceptance_db.urls(DEMO_DB)
    p = roles._parts(app_url)
    conn = psycopg2.connect(host="127.0.0.1", port=p["port"], user=p["user"], password=p["password"],
                            dbname=DEMO_DB, connect_timeout=5)
    try:
        cur = conn.cursor()
        cur.execute("select current_database()")
        assert cur.fetchone()[0] == DEMO_DB
        cur.execute("select username from users")
        return {row[0] for row in cur.fetchall()}
    finally:
        conn.close()


def wait_until(predicate, timeout, what):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as error:  # element not there yet / page navigating
            last = type(error).__name__
        time.sleep(0.2)
    raise SystemExit(f"ERROR: timed out waiting for {what}" + (f" (last: {last})" if last else ""))


def register_bob_on_website(bob):
    from playwright.sync_api import sync_playwright

    BOB_PROFILE.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            str(BOB_PROFILE), channel="chrome", headless=True, viewport={"width": 1280, "height": 800})
        try:
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(WEB_URL)
            page.wait_for_selector("html[data-app-ready]", state="attached", timeout=15000)
            page.evaluate("(u) => { document.getElementById('gatewayUrl').value = u; }", GATEWAY_URL)
            page.click("#toggleModeBtn")
            page.fill("#regUsername", bob["username"])
            page.fill("#phoneNumber", bob["phone"])
            page.fill("#password", bob["password"])
            page.fill("#regConfirmPassword", bob["password"])
            page.click("#connectBtn")
            wait_until(lambda: "Account created" in page.inner_text("#authStatus"), 30, "Website registration")
            # Log in so the browser creates and stores this account's identity keys.
            page.fill("#phoneNumber", bob["phone"])
            page.fill("#password", bob["password"])
            page.click("#connectBtn")
            wait_until(lambda: "Connected and authenticated as" in page.inner_text("#log"), 40, "Website login")
            wait_until(lambda: "Ready." in page.inner_text("#log"), 40, "Website session ready")
            time.sleep(3)  # let the page persist its identity state
        finally:
            context.close()


def register_alice_on_desktop(alice, command):
    from tests.acceptance import desktop_driver as dd

    agent = dd.UiaAgent()
    app = None
    try:
        app = dd.DesktopApp(command, {"SERVER_HOST": "127.0.0.1", "SERVER_PORT": "5000"}, agent, cwd=str(ROOT))
        dd.register(app, alice["username"], alice["phone"], alice["password"])
        dd.login(app, alice["phone"], alice["password"])
        time.sleep(4)  # identity keys are generated and the key store written at first login
        dd.logout(app)
    finally:
        if app is not None:
            app.stop()
        agent.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", action="store_true", help="drive main.py via the venv pythonw instead of the exe")
    ap.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    args = ap.parse_args(argv)

    if not STATE_FILE.is_file():
        raise SystemExit("ERROR: the demo stack is not running. Start it first: scripts\\start_demo.cmd")
    if ACCOUNTS_FILE.exists():
        raise SystemExit(f"ERROR: {ACCOUNTS_FILE} already exists; refusing to create accounts twice or overwrite it.")
    existing = db_usernames()
    clash = {"demo_alice", "demo_bob"} & existing
    if clash:
        raise SystemExit(f"ERROR: account(s) already exist in {DEMO_DB}: {sorted(clash)}")

    alice, bob = identity("demo_alice"), identity("demo_bob")

    # Record the credentials FIRST (so a half-finished run never loses a password), restricted to this user.
    import setup_database_roles as roles

    ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACCOUNTS_FILE.write_text(
        "QRSCS demo accounts (database qrscs_demo). Log in with PHONE + PASSWORD.\n"
        + "".join(f"\n{who['username']}  [{where}]\n  phone   : {who['phone']}\n  password: {who['password']}\n"
                 for who, where in ((alice, "use on the Desktop app"), (bob, "use on the Website, Chrome profile "
                                                                           "~/.qrscs/demo-chrome-bob")))
        + "\nThis file is outside the repository on purpose. Do not commit or share it.\n",
        encoding="utf-8")
    roles._restrict_to_current_user(ACCOUNTS_FILE)

    command = [str(ROOT / "venv" / "Scripts" / "pythonw.exe"), "main.py"] if args.source else [str(args.exe)]
    print("Registering demo_bob through the real Website (Chrome)...", flush=True)
    register_bob_on_website(bob)
    print("Registering demo_alice through the real Desktop application...", flush=True)
    register_alice_on_desktop(alice, command)

    created = db_usernames()
    missing = {"demo_alice", "demo_bob"} - created
    if missing:
        raise SystemExit(f"ERROR: not created: {sorted(missing)}")
    print("")
    print("Created through the real apps: demo_alice (Desktop) and demo_bob (Website).")
    print(f"  Phones and passwords: {ACCOUNTS_FILE}  (not printed here)")
    print(f"  demo_alice phone: {alice['phone']}")
    print(f"  demo_bob   phone: {bob['phone']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
