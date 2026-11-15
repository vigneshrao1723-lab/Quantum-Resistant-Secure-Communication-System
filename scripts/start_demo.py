"""Start the local demo stack: chat server, web gateway and the Website, on this laptop.

    venv\\Scripts\\python.exe scripts\\start_demo.py            # or double-click scripts\\start_demo.cmd
    venv\\Scripts\\python.exe scripts\\start_demo.py --strict-5432   # abort if port 5432 is shared

What it does, in order (and stops with a clear message at the first problem):

  1. PostgreSQL Windows service is running.
  2. Ports 5000 (server), 8765 (web gateway) and 8010 (Website) are free.
  3. Port 5432: reports it when more than one process is listening there (for example a Docker
     container publishing the same port) and proves which server the stack will really talk to.
  4. The demo database ``qrscs_demo`` exists. This script never creates, drops or migrates anything;
     create it once with:  venv\\Scripts\\python.exe scripts\\acceptance_db.py create --db qrscs_demo
  5. Starts ``run.py --no-desktop --web-port 8010`` with the repository's virtual environment, detached,
     with DATABASE_URL / MIGRATION_DATABASE_URL pointed at ``qrscs_demo`` through the process
     environment. The development database ``qrscs`` is never used by this stack, and nothing in
     ``.env`` is changed.

The stack's process id is recorded in ``logs/demo/stack.json`` (ignored by Git) so that
``scripts/stop_demo.py`` stops exactly what was started here and nothing else.

Credentials are read in-process and handed to the child through its environment; they are never
printed, and connection errors are reported by type only (a driver's message can echo the URL).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

DEMO_DB = "qrscs_demo"
PG_SERVICE_DEFAULT = "postgresql-x64-17"
SERVER_PORT, GATEWAY_PORT, WEB_PORT = 5000, 8765, 8010
STATE_FILE = ROOT / "logs" / "demo" / "stack.json"
LOG_FILE = ROOT / "logs" / "demo" / "stack.log"
VENV_PYTHON = ROOT / "venv" / "Scripts" / "python.exe"


def say(text=""):
    print(text, flush=True)


def fail(code, *lines):
    for line in lines:
        print(line, file=sys.stderr, flush=True)
    return code


def run(command):
    return subprocess.run(command, capture_output=True, text=True, errors="replace").stdout


def service_state(name):
    out = run(["sc", "query", name])
    if "does not exist" in out or "FAILED 1060" in out:
        return None
    match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", out)
    return match.group(1) if match else "UNKNOWN"


def listeners(port):
    """{(local address, pid)} for every TCP listener on ``port`` (IPv4 and IPv6)."""
    found = set()
    for line in run(["netstat", "-ano"]).splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "TCP" and parts[3] == "LISTENING" and parts[1].rsplit(":", 1)[-1] == str(port):
            found.add((parts[1], int(parts[4])))
    return found


def process_name(pid):
    out = run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]).strip()
    match = re.match(r'"([^"]+)"', out)
    return match.group(1) if match else "unknown"


def describe(entries):
    return ", ".join(f"{addr} -> {process_name(pid)} (pid {pid})" for addr, pid in sorted(entries))


def probe(host, parts):
    """(postmaster start time, current database) as seen through ``host``, or None if unreachable."""
    import psycopg2

    try:
        conn = psycopg2.connect(host=host, port=parts["port"], user=parts["user"], password=parts["password"],
                                dbname=parts["dbname"], connect_timeout=5)
        try:
            cur = conn.cursor()
            cur.execute("select pg_postmaster_start_time()::text, current_database()")
            return cur.fetchone()
        finally:
            conn.close()
    except Exception:  # never show the message: a driver can echo the connection URL
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pg-service", default=PG_SERVICE_DEFAULT, help="PostgreSQL Windows service name")
    ap.add_argument("--strict-5432", action="store_true", help="refuse to start when port 5432 is shared")
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for the stack to listen")
    args = ap.parse_args(argv)

    if not VENV_PYTHON.is_file():
        return fail(2, f"ERROR: the repository virtual environment is missing: {VENV_PYTHON}")

    if STATE_FILE.is_file():
        try:
            old = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if run(["tasklist", "/FI", f"PID eq {old['pid']}", "/NH"]).count(str(old["pid"])):
                return fail(2, f"ERROR: a demo stack started by this script is already running (pid {old['pid']}).",
                            "       Stop it first:  venv\\Scripts\\python.exe scripts\\stop_demo.py")
        except (ValueError, KeyError, OSError):
            pass

    # 1. PostgreSQL service
    state = service_state(args.pg_service)
    if state != "RUNNING":
        return fail(2, f"ERROR: PostgreSQL service '{args.pg_service}' is {state or 'not installed'}, not RUNNING.",
                    "       Start it (Services app, or an elevated: net start " + args.pg_service + ") and run this again.")
    say(f"[ok] PostgreSQL service {args.pg_service} is RUNNING")

    # 2. Application ports
    busy = False
    for label, port in (("chat server", SERVER_PORT), ("web gateway", GATEWAY_PORT), ("Website", WEB_PORT)):
        taken = listeners(port)
        if taken:
            busy = True
            print(f"ERROR: port {port} ({label}) is already in use by: {describe(taken)}", file=sys.stderr, flush=True)
        else:
            say(f"[ok] port {port} ({label}) is free")
    if busy:
        return fail(3, "       Nothing was started. Stop whatever holds those ports (for the stack started by this",
                    "       script: venv\\Scripts\\python.exe scripts\\stop_demo.py) and run this again.")

    # 3 + 4. Demo database and port 5432
    import acceptance_db
    import setup_database_roles as roles

    try:
        app_url, migration_url = acceptance_db.urls(DEMO_DB)
    except Exception as error:
        return fail(2, f"ERROR: cannot work out the demo database URLs ({type(error).__name__}); is .env complete?")
    app_parts = roles._parts(app_url)
    if app_parts["dbname"] != DEMO_DB or DEMO_DB in ("qrscs", "postgres"):
        return fail(2, "ERROR: refusing to continue: the target database is not the demo database.")

    pg5432 = listeners(5432)
    contended = len({pid for _addr, pid in pg5432}) > 1
    if contended:
        print("ERROR: port 5432 is CONTENDED: more than one process is listening on it:", file=sys.stderr, flush=True)
        print(f"       {describe(pg5432)}", file=sys.stderr, flush=True)
        print("       Which server a client reaches depends on the address it resolves 'localhost' to.",
              file=sys.stderr, flush=True)
        if args.strict_5432:
            return fail(4, "       --strict-5432 given: nothing was started.")

    v4 = probe("127.0.0.1", app_parts)
    if v4 is None:
        return fail(2, f"ERROR: cannot reach database '{DEMO_DB}' on 127.0.0.1:{app_parts['port']} as the application role.",
                    "       Create it once (never touches 'qrscs'):",
                    f"         venv\\Scripts\\python.exe scripts\\acceptance_db.py create --db {DEMO_DB}")
    if v4[1] != DEMO_DB:
        return fail(2, f"ERROR: connected to database '{v4[1]}', expected '{DEMO_DB}'. Nothing was started.")
    say(f"[ok] database {DEMO_DB} reachable on 127.0.0.1 (server started {v4[0]})")
    if contended:
        v6 = probe("::1", app_parts)
        if v6 is None:
            say("[note] ::1:5432 does not serve this database; the stack is pinned to 127.0.0.1 anyway")
        elif v6[0] != v4[0]:
            say("[warn] ::1:5432 answers from a DIFFERENT PostgreSQL server than 127.0.0.1:5432.")
            say("       The stack is pinned to 127.0.0.1, so it uses the server verified above.")
        else:
            say("[ok] 127.0.0.1 and ::1 reach the same PostgreSQL server despite the shared port")

    # 5. Start. The URLs go into the child's environment only, pinned to 127.0.0.1 so a second
    #    server on the IPv6 side of port 5432 can never answer.
    pinned_app = roles._url(app_parts["user"], app_parts["password"], "127.0.0.1", app_parts["port"], DEMO_DB)
    mig_parts = roles._parts(migration_url)
    pinned_mig = roles._url(mig_parts["user"], mig_parts["password"], "127.0.0.1", mig_parts["port"], DEMO_DB)
    # Encrypted attachment blobs of the demo go to their own folder (ignored by Git), not into the
    # development storage_blobs/ directory.
    blob_dir = ROOT / "logs" / "demo" / "blobs"
    blob_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, DATABASE_URL=pinned_app, MIGRATION_DATABASE_URL=pinned_mig,
               FILE_STORAGE_ROOT=str(blob_dir), PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log = open(LOG_FILE, "w", encoding="utf-8", errors="replace")
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    proc = subprocess.Popen(
        [str(VENV_PYTHON), "-u", "run.py", "--no-desktop", "--web-port", str(WEB_PORT)],
        cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, creationflags=flags,
    )
    deadline = time.monotonic() + args.wait
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
            return fail(5, f"ERROR: the stack exited during start-up (code {proc.returncode}). Last log lines:",
                        *("       " + re.sub(r"(://[^:/\s]+:)[^@\s]+@", r"\1***@", line) for line in tail))
        if all(listeners(p) for p in (SERVER_PORT, GATEWAY_PORT, WEB_PORT)):
            break
        time.sleep(0.5)
    else:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        return fail(5, f"ERROR: the stack did not listen on all three ports within {args.wait}s; it was stopped.",
                    f"       See {LOG_FILE}")

    STATE_FILE.write_text(json.dumps({
        "pid": proc.pid, "started": time.strftime("%Y-%m-%d %H:%M:%S"), "database": DEMO_DB,
        "python": str(VENV_PYTHON), "ports": {"server": SERVER_PORT, "gateway": GATEWAY_PORT, "website": WEB_PORT},
    }, indent=2), encoding="utf-8")
    say("")
    say(f"Demo stack is running (pid {proc.pid}), database '{DEMO_DB}'.")
    say(f"  Website  : http://127.0.0.1:{WEB_PORT}/   (web gateway ws://127.0.0.1:{GATEWAY_PORT})")
    say(f"  Server   : 127.0.0.1:{SERVER_PORT} (TLS) - the Desktop app connects here")
    say(f"  Log      : {LOG_FILE}")
    say("  Stop     : venv\\Scripts\\python.exe scripts\\stop_demo.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
