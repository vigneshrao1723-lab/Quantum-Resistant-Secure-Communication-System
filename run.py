"""Start the existing server, web client, gateway, and desktop UI.

    python run.py                     # server, gateway, Website and one Desktop window
    python run.py --no-desktop        # same, without opening a Desktop window
    python run.py --web-port 8100 --gateway-port 8865   # when the defaults are in use

The chat server's port is SERVER_PORT from .env (default 5000). Run it with the
project's virtual environment's Python so the pinned dependencies are used.
"""

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WEB_CLIENT = ROOT / "web" / "client"
STARTUP_TIMEOUT_SECONDS = 30
STARTUP_RETRY_SECONDS = 0.2
SHUTDOWN_TIMEOUT_SECONDS = 5
DEFAULT_GATEWAY_PORT = 8765
DEFAULT_WEB_PORT = 8000


def port_in_use(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def check_prerequisites(server_port, ports):
    """Return a list of problems that would stop the stack from starting."""
    problems = []

    if not (ROOT / ".env").exists():
        problems.append(
            "No .env file. Copy .env.example to .env and fill it in (see README, 'Environment configuration')."
        )

    try:
        # Importing these validates .env (DATABASE_URL, JWT_SECRET_KEY, ...) and the TLS settings.
        import config
        import config_server  # noqa: F401
    except ValueError as error:
        problems.append(f"Configuration error: {error}")
    else:
        for name, path in (
            ("TLS certificate", config.TLS_CERT_FILE),
            ("TLS private key", config.TLS_KEY_FILE),
            ("TLS CA certificate", config.TLS_CA_FILE),
        ):
            if not Path(path).exists():
                problems.append(
                    f"{name} not found: {path}. Run `python scripts/generate_dev_certs.py`."
                )

    for name, port in ports:
        if port_in_use(port):
            problems.append(
                f"Port {port} ({name}) is already in use. Stop whatever is using it, "
                f"or choose another port ({'set SERVER_PORT in .env' if port == server_port else 'see --help'})."
            )

    return problems


def wait_for_port(processes, name, port):
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        for process_name, process in processes:
            exit_code = process.poll()
            if exit_code is not None:
                raise RuntimeError(
                    f"{process_name} exited during startup with code {exit_code}."
                )
        if port_in_use(port):
            return
        time.sleep(STARTUP_RETRY_SECONDS)
    raise TimeoutError(
        f"{name} did not start listening on 127.0.0.1:{port} "
        f"within {STARTUP_TIMEOUT_SECONDS} seconds."
    )


def stop_processes(processes):
    for name, process in reversed(processes):
        if process.poll() is None:
            print(f"Stopping {name}...", flush=True)
            process.terminate()

    for _, process in reversed(processes):
        if process.poll() is None:
            try:
                process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def start_process(processes, name, command, ready_port=None):
    print(f"Starting {name}...", flush=True)
    process = subprocess.Popen(command, cwd=ROOT)
    processes.append((name, process))
    if ready_port is None:
        time.sleep(STARTUP_RETRY_SECONDS)
        exit_code = process.poll()
        if exit_code is not None:
            raise RuntimeError(f"{name} exited during startup with code {exit_code}.")
    else:
        wait_for_port(processes, name, ready_port)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway-port", type=int, default=DEFAULT_GATEWAY_PORT,
                        help=f"WebSocket gateway port (default {DEFAULT_GATEWAY_PORT})")
    parser.add_argument("--web-port", type=int, default=DEFAULT_WEB_PORT,
                        help=f"Website port (default {DEFAULT_WEB_PORT})")
    parser.add_argument("--no-desktop", action="store_true", help="do not open a Desktop window")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(ROOT))
    try:
        from config import SERVER_PORT as server_port
    except ValueError as error:
        print(f"Unable to start the applications: configuration error: {error}", file=sys.stderr)
        return 1

    problems = check_prerequisites(
        server_port,
        (
            ("secure chat server", server_port),
            ("web gateway", args.gateway_port),
            ("web client", args.web_port),
        ),
    )
    if problems:
        print("Unable to start the applications:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    processes = []
    try:
        start_process(
            processes,
            "secure chat server",
            [sys.executable, "-m", "server.server"],
            ready_port=server_port,
        )
        start_process(
            processes,
            "web gateway",
            [sys.executable, "-m", "web.gateway.gateway", "--port", str(args.gateway_port)],
            ready_port=args.gateway_port,
        )
        start_process(
            processes,
            "web client",
            [
                sys.executable,
                "-m",
                "http.server",
                str(args.web_port),
                "--directory",
                str(WEB_CLIENT),
            ],
            ready_port=args.web_port,
        )
        if not args.no_desktop:
            start_process(
                processes,
                "desktop application",
                [sys.executable, str(ROOT / "main.py")],
            )

        website = f"http://127.0.0.1:{args.web_port}"
        if args.gateway_port != DEFAULT_GATEWAY_PORT:
            website += f"/?gateway=ws://127.0.0.1:{args.gateway_port}"
        print("\nAll applications are running.", flush=True)
        print(f"Web client: {website}", flush=True)
        print(f"Web gateway: ws://127.0.0.1:{args.gateway_port}", flush=True)
        print("Press Ctrl+C to stop everything.", flush=True)

        while True:
            for name, process in processes:
                exit_code = process.poll()
                if exit_code is not None:
                    raise RuntimeError(
                        f"{name} stopped unexpectedly with code {exit_code}."
                    )
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nShutdown requested.", flush=True)
    except (OSError, RuntimeError) as error:
        print(f"\nUnable to start the applications: {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        stop_processes(processes)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
