"""Stop the demo stack that ``scripts/start_demo.py`` started - and nothing else.

    venv\\Scripts\\python.exe scripts\\stop_demo.py          # or double-click scripts\\stop_demo.cmd

It reads the process id recorded in ``logs/demo/stack.json``, checks that this process really is this
repository's ``run.py`` (so a recycled process id can never take down something unrelated), and ends
that process together with the server, gateway and Website processes it started. It never kills by
name, never touches PostgreSQL, Docker or any other project's processes, and never changes a database.
If the record is missing it only reports what is listening on 5000 / 8765 / 8010.
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "logs" / "demo" / "stack.json"
PORTS = {"server": 5000, "gateway": 8765, "website": 8010}


def run(command):
    return subprocess.run(command, capture_output=True, text=True, errors="replace").stdout


def listeners(port):
    found = set()
    for line in run(["netstat", "-ano"]).splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "TCP" and parts[3] == "LISTENING" and parts[1].rsplit(":", 1)[-1] == str(port):
            found.add(int(parts[4]))
    return found


def pid_alive(pid):
    """True while a process with this id exists (``tasklist`` CSV: image, pid, ...)."""
    out = run(["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH"])
    return any(len(row) > 1 and row[1] == str(int(pid)) for row in csv.reader(out.splitlines()))


def command_line(pid):
    out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
               f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}' | Select-Object -ExpandProperty CommandLine)"])
    return out.strip()


def main():
    if not STATE_FILE.is_file():
        print("No demo stack record found (logs/demo/stack.json): nothing to stop.")
        for name, port in PORTS.items():
            pids = listeners(port)
            if pids:
                print(f"  note: port {port} ({name}) is in use by pid(s) {sorted(pids)}; "
                      "not started by this script, so it is left alone.")
        return 0

    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        pid = int(state["pid"])
    except (ValueError, KeyError, OSError):
        print("ERROR: logs/demo/stack.json is unreadable; nothing was stopped.", file=sys.stderr)
        return 2

    cmd = command_line(pid)
    if not cmd:
        print(f"The recorded stack (pid {pid}) is no longer running.")
    elif (str(ROOT / "venv" / "Scripts" / "python.exe").lower() in cmd.lower()
          and "run.py" in cmd and "--no-desktop" in cmd):
        print(f"Stopping the demo stack (pid {pid}) and the processes it started...")
        out = subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True, text=True)
        # taskkill /T works through the whole tree and exits non-zero with "no running instance" for
        # children that already ended when their parent was killed. That is not a failure. What decides
        # success is that the recorded root process is gone (and, below, that the ports are free).
        gone_by = time.monotonic() + 10
        while pid_alive(pid) and time.monotonic() < gone_by:
            time.sleep(0.2)
        if pid_alive(pid):
            print(f"ERROR: could not stop pid {pid}:", re.sub(r"\s+", " ", out.stdout + out.stderr).strip(),
                  file=sys.stderr)
            return 3
    else:
        print(f"ERROR: pid {pid} is not this repository's run.py (it is something else now); refusing to kill it.",
              file=sys.stderr)
        print("       The stale record was left in place; check logs/demo/stack.json.", file=sys.stderr)
        return 4

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and any(listeners(p) for p in PORTS.values()):
        time.sleep(0.5)
    still = {name: sorted(listeners(port)) for name, port in PORTS.items() if listeners(port)}
    if still:
        print(f"WARNING: ports still in use after stopping: {still}. They are not tracked by this script; "
              "find out what owns them before starting again.", file=sys.stderr)
        STATE_FILE.unlink(missing_ok=True)
        return 5
    STATE_FILE.unlink(missing_ok=True)
    print("Stopped. Ports 5000, 8765 and 8010 are free.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
