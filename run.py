"""Start the existing server, web client, gateway, and desktop UI."""

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


def wait_for_port(processes, name, port):
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        for process_name, process in processes:
            exit_code = process.poll()
            if exit_code is not None:
                raise RuntimeError(
                    f"{process_name} exited during startup with code {exit_code}."
                )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
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


def main():
    processes = []
    try:
        start_process(
            processes,
            "secure chat server",
            [sys.executable, "-m", "server.server"],
            ready_port=5000,
        )
        start_process(
            processes,
            "web gateway",
            [sys.executable, "-m", "web.gateway.gateway"],
            ready_port=8765,
        )
        start_process(
            processes,
            "web client",
            [
                sys.executable,
                "-m",
                "http.server",
                "8000",
                "--directory",
                str(WEB_CLIENT),
            ],
            ready_port=8000,
        )
        start_process(
            processes,
            "desktop application",
            [sys.executable, str(ROOT / "main.py")],
        )

        print("\nAll applications are running.", flush=True)
        print("Web client: http://127.0.0.1:8000", flush=True)
        print("Web gateway: ws://127.0.0.1:8765", flush=True)
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
