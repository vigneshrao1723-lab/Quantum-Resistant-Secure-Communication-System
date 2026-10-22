"""A real, isolated QRSCS deployment for acceptance testing.

Starts three separate processes -- the chat server, the web gateway and a static
web server -- exactly as ``run.py`` does, but:

* against the isolated ``qrscs_accept`` database (never the development DB),
  connecting as the least-privilege ``qrscs_app`` role;
* with a throwaway encrypted-blob directory;
* on non-default ports, so a developer's own instance is left alone;
* with every process's output written to ``dist/acceptance/<run>/logs`` where the
  leak scanner later inspects it.

Credentials for the database are passed only through child-process environments
and are never printed or written to disk.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import acceptance_db  # noqa: E402

SERVER_PORT = 15000
GATEWAY_PORT = 18765
STATIC_PORT = 18000


def _assert_port_free(port: int):
    """Refuse to start on a port something else already holds.

    Without this a stale process from an earlier run could answer the readiness check, and the
    new processes (which fail to bind) would go unnoticed while the test talked to the old one.
    """
    with socket.socket() as probe:
        probe.settimeout(0.5)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise RuntimeError(
                f"port {port} is already in use (a stale server from an earlier run?); "
                "stop that process before running the acceptance suite"
            )


def _wait_port(port: int, procs, timeout: float = 40.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for name, p in procs:
            if p.poll() is not None:
                raise RuntimeError(f"{name} exited during start-up (code {p.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                pass
        except OSError:
            time.sleep(0.2)
            continue
        # Connected: make sure the process we just started is still alive and therefore the owner.
        time.sleep(0.5)
        for name, p in procs:
            if p.poll() is not None:
                raise RuntimeError(f"{name} exited during start-up (code {p.returncode})")
        return
    raise TimeoutError(f"nothing is listening on 127.0.0.1:{port}")


@dataclass
class AcceptanceStack:
    run_dir: Path
    server_port: int = SERVER_PORT
    gateway_port: int = GATEWAY_PORT
    static_port: int = STATIC_PORT
    dbname: str = acceptance_db.DEFAULT_DB
    extra_env: dict = field(default_factory=dict)
    _procs: list = field(default_factory=list, init=False)
    _handles: list = field(default_factory=list, init=False)
    blob_dir: Path | None = field(default=None, init=False)
    _log_offsets: dict = field(default_factory=dict, init=False)
    _env: dict = field(default_factory=dict, init=False)

    @property
    def log_dir(self) -> Path:
        return self.run_dir / "logs"

    @property
    def gateway_url(self) -> str:
        return f"ws://127.0.0.1:{self.gateway_port}"

    @property
    def web_url(self) -> str:
        return f"http://127.0.0.1:{self.static_port}/index.html"

    def client_env(self, key_store: Path) -> dict:
        """Environment for a Desktop client process (no server-side secrets)."""
        return {
            "SERVER_HOST": "127.0.0.1",
            "SERVER_PORT": str(self.server_port),
            "KEY_STORE_DIR": str(key_store),
        }

    def _start(self, name, command, env, cwd=ROOT, append=False):
        self.log_dir.mkdir(parents=True, exist_ok=True)
        handle = open(self.log_dir / f"{name}.log", "ab" if append else "wb")
        self._handles.append(handle)
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT)
        self._procs.append((name, proc))
        return proc

    def start(self) -> "AcceptanceStack":
        for port in (self.server_port, self.gateway_port, self.static_port):
            _assert_port_free(port)
        # The server/gateway also write to the project's logs/ folder; remember where it ended so the
        # confidentiality scan reads only what THIS run added.
        project_logs = ROOT / "logs"
        self._log_offsets = {p: p.stat().st_size for p in project_logs.glob("*.log")} if project_logs.exists() else {}
        app_url, _ = acceptance_db.urls(self.dbname)
        self.blob_dir = Path(tempfile.mkdtemp(prefix="qrscs_blobs_"))
        env = dict(os.environ)
        env.update(
            DATABASE_URL=app_url,
            FILE_STORAGE_ROOT=str(self.blob_dir),
            SERVER_PORT=str(self.server_port),
            SERVER_HOST="127.0.0.1",
            PYTHONUNBUFFERED="1",
        )
        env.update(self.extra_env)
        self._env = env
        self._start("server", [sys.executable, "-m", "server.server"], env)
        _wait_port(self.server_port, self._procs)
        self._start(
            "gateway",
            [sys.executable, "-m", "web.gateway.gateway", "--port", str(self.gateway_port)],
            env,
        )
        _wait_port(self.gateway_port, self._procs)
        # The static server needs no secrets at all.
        clean = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "MIGRATION_DATABASE_URL")}
        self._start(
            "static",
            [sys.executable, "-m", "http.server", str(self.static_port), "--bind", "127.0.0.1",
             "--directory", str(ROOT / "web" / "client")],
            clean,
        )
        _wait_port(self.static_port, self._procs)
        return self

    def stop_server(self):
        """Stop only the chat server (clients and the gateway stay up), as if it had crashed."""
        for index, (name, proc) in enumerate(self._procs):
            if name == "server":
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                del self._procs[index]
                return
        raise RuntimeError("the server is not running")

    def start_server(self):
        """Start the chat server again on the same port, database and blob store."""
        _assert_port_free(self.server_port)
        self._start("server", [sys.executable, "-m", "server.server"], self._env, append=True)
        _wait_port(self.server_port, self._procs)

    def logs_written_by_this_run(self):
        """(label, bytes) for every log this run produced: captured process output + new project-log lines."""
        out = []
        for path in sorted(self.log_dir.glob("*.log")):
            out.append((f"captured {path.name}", path.read_bytes()))
        project_logs = ROOT / "logs"
        if project_logs.exists():
            for path in sorted(project_logs.glob("*.log")):
                start = self._log_offsets.get(path, 0)
                with open(path, "rb") as handle:
                    handle.seek(start)
                    out.append((f"logs/{path.name}", handle.read()))
        return out

    def stop(self):
        for _, proc in reversed(self._procs):
            if proc.poll() is None:
                proc.terminate()
        for _, proc in reversed(self._procs):
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        for handle in self._handles:
            handle.close()
        self._procs.clear()
        self._handles.clear()
        if self.blob_dir:
            shutil.rmtree(self.blob_dir, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
