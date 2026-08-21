"""
D8 / L-4 + P1 -- bounded connection concurrency and graceful shutdown.

Before L-4, server/server.py ran ``while True: accept()`` and spawned
an unbounded non-daemon thread per connection: a connection flood
became thread and memory exhaustion, and there was no way to stop the
loop at all -- Ctrl+C left non-daemon connection threads holding the
process open.

These tests drive the REAL start_server() accept loop against an
ephemeral port, not a reimplementation of it.
"""

import socket
import threading
import time

import pytest

from server import server as server_module


def _free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture()
def running_server(monkeypatch):
    """The real accept loop, on an ephemeral port, with a small slot
    count and a short handshake deadline so the test is fast."""

    port = _free_port()

    monkeypatch.setattr(server_module, "SERVER_PORT", port)
    monkeypatch.setattr(server_module, "SERVER_BIND_HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "MAX_CONCURRENT_CONNECTIONS", 2)
    monkeypatch.setattr(server_module, "HANDSHAKE_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(
        server_module, "_connection_slots", threading.BoundedSemaphore(2)
    )
    monkeypatch.setattr(server_module, "_shutdown", threading.Event())
    monkeypatch.setattr(server_module, "_active_threads", set())

    thread = threading.Thread(target=server_module.start_server, daemon=True)
    thread.start()

    # Wait until it is actually listening before any test touches it.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            probe.close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        server_module.shutdown_server()
        pytest.fail("server never started listening")

    # The readiness probe above IS a connection: it takes a slot and
    # holds it until its (doomed) TLS handshake finishes. Waiting for
    # the slots to come back makes every test below deterministic --
    # without this, a test that asserts on slot availability races the
    # probe's own teardown and fails under full-suite load while
    # passing in isolation.
    if not _wait_for_free_slots(server_module._connection_slots, 2):
        server_module.shutdown_server()
        pytest.fail("probe connection never released its slot")

    yield port, thread

    server_module.shutdown_server()
    thread.join(timeout=15)


def _wait_for_free_slots(semaphore, count, timeout=15.0):
    """Wait until ``count`` slots are simultaneously free."""

    deadline = time.time() + timeout

    while time.time() < deadline:
        if _slots_available(semaphore, count):
            return True
        time.sleep(0.05)

    return False


def _slots_available(semaphore, count):
    """Acquire ``count`` slots without blocking, then give them back."""

    taken = 0
    try:
        for _ in range(count):
            if not semaphore.acquire(blocking=False):
                return False
            taken += 1
        return True
    finally:
        for _ in range(taken):
            semaphore.release()


# ----------------------------------------------------------------------
# L-4 -- the limit
# ----------------------------------------------------------------------


def test_connections_beyond_the_limit_are_refused_promptly(running_server):
    """With every slot held, a new connection must be closed straight
    away -- and WITHOUT a TLS handshake, since the whole point is to
    spend nothing on a connection already refused."""

    port, _thread = running_server

    # Hold both slots so the outcome is deterministic rather than a
    # race against the handshake deadline.
    assert _wait_for_free_slots(server_module._connection_slots, 2)
    assert server_module._connection_slots.acquire(blocking=False)
    assert server_module._connection_slots.acquire(blocking=False)

    try:
        refused = socket.create_connection(("127.0.0.1", port), timeout=5)
        refused.settimeout(5)

        # The server closes it, so the read returns EOF quickly rather
        # than hanging or completing a handshake.
        started = time.time()
        data = refused.recv(64)
        elapsed = time.time() - started

        assert data == b"", "refused connection should be closed, not served"
        assert elapsed < 5, f"refusal took {elapsed:.2f}s"

        refused.close()
    finally:
        server_module._connection_slots.release()
        server_module._connection_slots.release()


def test_the_accept_loop_survives_a_flood(running_server):
    """Exceeding the limit must degrade throughput, not kill the
    server. After the flood the loop is still accepting."""

    port, thread = running_server

    floods = []
    for _ in range(25):
        try:
            floods.append(socket.create_connection(("127.0.0.1", port), timeout=2))
        except OSError:
            pass

    for sock in floods:
        try:
            sock.close()
        except OSError:
            pass

    assert thread.is_alive(), "the accept loop died under a connection flood"

    # Still serving: a fresh connection is still accepted.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            survivor = socket.create_connection(("127.0.0.1", port), timeout=1)
            survivor.close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        pytest.fail("server stopped accepting connections after the flood")


def test_every_slot_is_returned_after_failed_handshakes(running_server):
    """Slots are released in a finally, so even the failed-handshake
    path (which is every connection in this test, since none of them
    speak TLS) gives its slot back. A leak here would wedge the server
    permanently after enough bad connections."""

    port, _thread = running_server

    for _ in range(6):
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.close()
        except OSError:
            pass

    # Handshake deadline is 0.5s; allow generous slack for CI.
    deadline = time.time() + 15
    while time.time() < deadline:
        if _slots_available(server_module._connection_slots, 2):
            break
        time.sleep(0.1)
    else:
        pytest.fail("connection slots were leaked -- the server would wedge")


def test_the_limit_is_a_bounded_semaphore_not_an_unbounded_pool():
    """Structural: the production module must not go back to spawning
    a thread per connection with nothing in the way."""

    assert isinstance(
        server_module._connection_slots, threading.BoundedSemaphore
    ) or hasattr(server_module._connection_slots, "acquire")

    source = (server_module.__file__ or "")
    assert source, "server module has no file"

    with open(source, encoding="utf-8") as handle:
        text = handle.read()

    assert "_connection_slots.acquire(blocking=False)" in text, (
        "the accept loop no longer takes a connection slot before "
        "spawning a thread"
    )
    assert "daemon=True" in text, (
        "connection threads must be daemons so a hard exit is never "
        "blocked by a parked read"
    )


# ----------------------------------------------------------------------
# P1 -- graceful shutdown
# ----------------------------------------------------------------------


def test_shutdown_stops_the_accept_loop_and_returns(monkeypatch):
    """start_server() must return. Previously it could not: the loop
    was ``while True`` with no exit."""

    port = _free_port()

    monkeypatch.setattr(server_module, "SERVER_PORT", port)
    monkeypatch.setattr(server_module, "SERVER_BIND_HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "HANDSHAKE_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(
        server_module, "_connection_slots", threading.BoundedSemaphore(4)
    )
    monkeypatch.setattr(server_module, "_shutdown", threading.Event())
    monkeypatch.setattr(server_module, "_active_threads", set())

    thread = threading.Thread(target=server_module.start_server, daemon=True)
    thread.start()

    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            probe.close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        server_module.shutdown_server()
        pytest.fail("server never started listening")

    server_module.shutdown_server()
    thread.join(timeout=15)

    assert not thread.is_alive(), "start_server() did not return after shutdown"


def test_the_port_is_released_after_shutdown(monkeypatch):
    """The listening socket must actually be closed, not just
    abandoned -- otherwise a restart fails to bind."""

    port = _free_port()

    for attempt in range(2):
        monkeypatch.setattr(server_module, "SERVER_PORT", port)
        monkeypatch.setattr(server_module, "SERVER_BIND_HOST", "127.0.0.1")
        monkeypatch.setattr(
            server_module, "_connection_slots", threading.BoundedSemaphore(4)
        )
        monkeypatch.setattr(server_module, "_shutdown", threading.Event())
        monkeypatch.setattr(server_module, "_active_threads", set())

        thread = threading.Thread(target=server_module.start_server, daemon=True)
        thread.start()

        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                probe = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                probe.close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            server_module.shutdown_server()
            pytest.fail(f"server never started listening (attempt {attempt + 1})")

        server_module.shutdown_server()
        thread.join(timeout=15)

        assert not thread.is_alive(), f"attempt {attempt + 1} did not shut down"


def test_shutdown_is_safe_to_call_before_the_server_starts():
    """It is reachable from a signal handler, so it must never raise."""

    server_module.shutdown_server()


def test_serve_client_does_not_touch_the_connection_slots():
    """Regression: the slot was first released inside _serve_client(),
    which assumed its caller had acquired one. Anything calling
    _serve_client() directly -- tests/test_tls_production_integration.py
    does -- then released a slot it never took, raising
    "Semaphore released too many times" and, worse, silently RAISING
    the effective connection limit each time it happened.

    Acquire and release now live together in _serve_with_slot().
    """

    import inspect

    source = inspect.getsource(server_module._serve_client)

    assert "_connection_slots" not in source, (
        "_serve_client() must not manage connection slots; that belongs "
        "to _serve_with_slot()"
    )

    wrapper = inspect.getsource(server_module._serve_with_slot)

    assert "_connection_slots.release()" in wrapper
    assert "finally" in wrapper, "the slot must be released on every exit path"


def test_a_direct_serve_client_call_leaves_the_limit_intact():
    """Behavioural form of the same regression."""

    slots = threading.BoundedSemaphore(1)
    original = server_module._connection_slots
    server_module._connection_slots = slots

    try:
        class _DeadContext:
            def wrap_socket(self, *args, **kwargs):
                raise OSError("no handshake here")

        class _DeadSocket:
            def settimeout(self, _value):
                pass

            def close(self):
                pass

        class _State:
            class logger:
                @staticmethod
                def warning(_message):
                    pass

        server_module._serve_client(
            _State(), _DeadContext(), _DeadSocket(), ("127.0.0.1", 1)
        )

        # The one slot must still be available, and releasing it must
        # not be possible (it was never taken).
        assert slots.acquire(blocking=False)
        slots.release()
    finally:
        server_module._connection_slots = original
