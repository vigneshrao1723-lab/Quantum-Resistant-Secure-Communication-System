"""
Quantum-Resistant Secure Communication System

Server Entry Point
"""

import socket
import ssl
import threading

from config import (
    HANDSHAKE_TIMEOUT_SECONDS,
    MAX_CONCURRENT_CONNECTIONS,
    SERVER_BIND_HOST,
    SERVER_PORT,
)
from security.tls import build_server_context
from server.client_handler import handle_client
from server.server_state import ServerState

# D8 / L-4 -- bounds how many connections are being served at once.
#
# A semaphore rather than a thread pool on purpose: the existing model
# is one thread per connection, and a connection here is long-lived and
# mostly blocked on a socket read, not a short unit of work. A pool
# sized for CPU would deadlock the moment every worker was parked on an
# idle chat connection. This keeps the model unchanged and simply
# refuses to start the (N+1)th one.
_connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)

# D8 / P1 -- set to stop the accept loop and signal live connections to
# wind down. Threads are tracked so shutdown can join them instead of
# exiting with work still in flight.
_shutdown = threading.Event()
_active_threads = set()
_active_threads_lock = threading.Lock()


def _serve_client(state, tls_context, client_socket, client_address):
    """
    TLS-wrap one accepted connection and dispatch to handle_client()
    on success (TLS Transport Security).

    Runs inside its own per-connection thread rather than the shared
    accept() loop below, so a slow or failing handshake only ever
    affects this one connection -- consistent with the existing
    one-thread-per-connection model (a slow plaintext read inside
    handle_client() already only ever blocked its own thread, not
    accept()).

    A failed handshake (wrong protocol, a client that doesn't trust or
    doesn't present what this context requires, or a client that
    isn't speaking TLS at all) is logged and the raw socket is closed
    -- handle_client() is never called with an un-wrapped socket, and
    the failure never reaches or affects any other connection.

    D8 / L-3: a deadline covers the whole pre-authentication phase --
    the TLS handshake AND the auth/login/register packet that follows.
    Without it, a peer that completed a handshake and then said
    nothing held this thread forever, which is the cheapest possible
    denial of service. handle_client() clears the deadline the moment
    the connection authenticates, because an authenticated client is
    entitled to sit idle waiting for messages.

    Deliberately owns NO connection slot. Slot accounting lives
    entirely in _serve_with_slot() below, so acquire and release sit
    next to each other in one function rather than being split across
    a caller and a callee -- and so this function stays directly
    callable, which tests/test_tls_production_integration.py relies on.
    """

    try:
        client_socket.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
        tls_socket = tls_context.wrap_socket(client_socket, server_side=True)
    except (ssl.SSLError, OSError) as error:
        # socket.timeout is an OSError subclass, so a handshake that
        # stalls lands here alongside a malformed one.
        state.logger.warning(
            f"TLS handshake failed for {client_address}: {error}"
        )
        client_socket.close()
        return

    handle_client(state, tls_socket, client_address)


def _serve_with_slot(state, tls_context, client_socket, client_address):
    """
    Thread body for one accepted connection: run _serve_client() and
    then give back the connection slot the accept loop took for it
    (D8 / L-4).

    The release is in a finally, so a slot comes back on every exit
    path -- including a failed TLS handshake, which is the common case
    under a flood. A leak here would wedge the server permanently
    after enough bad connections.
    """

    try:
        _serve_client(state, tls_context, client_socket, client_address)
    finally:
        _connection_slots.release()

        with _active_threads_lock:
            _active_threads.discard(threading.current_thread())


def _reject_connection(state, client_socket, client_address):
    """
    Turn away a connection that arrived while every slot was busy
    (D8 / L-4).

    Closed immediately and without a TLS handshake: the point is to
    spend as little as possible on a connection this server has
    already decided not to serve. The accept() loop keeps running, so
    reaching the limit degrades throughput rather than taking the
    server down -- which is the entire difference between a bounded
    and an unbounded server under flood.
    """

    state.logger.warning(
        f"Refused connection from {client_address}: "
        f"at the {MAX_CONCURRENT_CONNECTIONS}-connection limit"
    )

    try:
        client_socket.close()
    except OSError:
        pass


def shutdown_server():
    """
    Ask the accept loop to stop and live connections to wind down
    (D8 / P1).

    Safe to call from a signal handler or another thread. start_server()
    does the actual closing and joining, so there is exactly one place
    that owns the listening socket.
    """

    _shutdown.set()


def start_server():
    """
    Start the secure communication server.

    Returns when the listening socket has been closed and every
    connection thread has finished or been given its join deadline
    (D8 / P1) -- previously this ran an unconditional ``while True``
    with no way out, so Ctrl+C left non-daemon connection threads
    holding the process open.
    """

    _shutdown.clear()

    # Create shared server state
    state = ServerState()

    # Build the TLS server context once at startup -- reused for
    # every accepted connection, never rebuilt per client (TLS
    # Transport Security). security.tls.build_server_context() is the
    # single authoritative TLS implementation; no second SSLContext or
    # certificate configuration exists anywhere else.
    tls_context = build_server_context()

    # Create server socket
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # Binds SERVER_BIND_HOST -- the interface to listen on -- which is
    # deliberately a separate setting from the client's SERVER_HOST
    # (D0 -- Configuration & Network Separation). Defaults to loopback,
    # so reachability from other devices is always an explicit choice
    # (SERVER_BIND_HOST=0.0.0.0), never an accident.
    server_socket.bind((SERVER_BIND_HOST, SERVER_PORT))

    server_socket.listen()

    # So the accept loop wakes up regularly enough to notice a
    # shutdown request instead of blocking in accept() forever.
    server_socket.settimeout(0.5)

    reachability = (
        "all interfaces -- reachable from other devices"
        if SERVER_BIND_HOST in ("0.0.0.0", "::")
        else "loopback only -- not reachable from other devices"
    )

    print("=" * 60)
    print(" Quantum-Resistant Secure Communication Server")
    print(f" Listening on {SERVER_BIND_HOST}:{SERVER_PORT} (TLS)")
    print(f" Bind scope: {reachability}")
    print(f" Connection limit: {MAX_CONCURRENT_CONNECTIONS}")
    print(" Waiting for clients...")
    print("=" * 60)

    state.logger.info(
        f"Server started on {SERVER_BIND_HOST}:{SERVER_PORT} (TLS) -- {reachability}"
    )

    try:

        while not _shutdown.is_set():

            try:
                client_socket, client_address = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                # The listening socket was closed underneath us during
                # shutdown; nothing left to accept.
                break

            # D8 / L-4 -- take a slot BEFORE spawning anything.
            # Non-blocking so a flood is refused promptly instead of
            # queueing inside the accept loop and stalling legitimate
            # connections behind it.
            if not _connection_slots.acquire(blocking=False):
                _reject_connection(state, client_socket, client_address)
                continue

            thread = threading.Thread(
                target=_serve_with_slot,
                args=(
                    state,
                    tls_context,
                    client_socket,
                    client_address
                ),
                # Daemon so a hard exit is never blocked by a
                # connection parked on a read. The orderly path still
                # joins them below; this is the backstop, not the plan.
                daemon=True,
            )

            with _active_threads_lock:
                _active_threads.add(thread)

            thread.start()

            print(
                f"Active Connections: "
                f"{len(state.clients)}"
            )

    except KeyboardInterrupt:
        print("\nShutting down...")
        state.logger.info("Shutdown requested (KeyboardInterrupt)")

    finally:
        _shutdown.set()

        # Stop accepting first, so nothing new arrives while the
        # existing connections are being closed.
        try:
            server_socket.close()
        except OSError:
            pass

        _close_active_connections(state)

        print("Server stopped.")
        state.logger.info("Server stopped")


def _close_active_connections(state, join_timeout=5.0):
    """
    Close every live client socket, then wait for its thread (D8 / P1).

    Sockets are closed FIRST and threads joined afterwards, because a
    connection thread is almost always blocked in recv(). Joining
    without closing would simply wait out the stall timeout on every
    connection in turn; closing makes that recv() return immediately
    so handle_client()'s existing teardown runs normally -- the same
    teardown a client-initiated disconnect already uses, so no
    protocol or authentication behaviour changes here.

    The join is bounded: a thread that refuses to finish must not
    prevent the process from exiting, which is why the threads are
    daemons as well.
    """

    for client_socket in list(getattr(state, "clients", {})):
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client_socket.close()
        except OSError:
            pass

    with _active_threads_lock:
        threads = list(_active_threads)

    for thread in threads:
        thread.join(timeout=join_timeout)

    still_running = [thread for thread in threads if thread.is_alive()]

    if still_running:
        state.logger.warning(
            f"{len(still_running)} connection thread(s) did not finish within "
            f"{join_timeout}s; exiting anyway (they are daemon threads)."
        )


if __name__ == "__main__":
    start_server()
