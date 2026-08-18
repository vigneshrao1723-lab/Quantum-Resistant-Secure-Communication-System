"""
Shared TLS test support.

The one place tests construct TLS-wrapped sockets. Reuses
security.tls.build_server_context()/build_client_context() exactly as
the real server/client do -- no second TLS implementation, no
duplicated SSLContext construction, no duplicated certificate
verification configuration. Every socket-based integration test (the
dedicated tests in test_tls_transport.py, and the migrated direct/
group/persistence/routing suites) wraps its sockets through the two
helpers below instead of each building its own SSLContext.

security.tls's context builders read TLS_CERT_FILE/TLS_KEY_FILE/
TLS_CA_FILE from config.py -- the same development certificate/CA
scripts/generate_dev_certs.py writes to certs/dev/ is what both the
real application and every test in this suite trust and present.
"""

import socket
import ssl
import threading

from security.tls import build_client_context, build_server_context


def wrap_server_socket(client_socket, context):
    """
    TLS-wrap one accepted connection, server side -- the exact same
    wrap_socket() call server/server.py uses. ``context`` must be a
    caller-supplied SSLContext (from build_server_context()), built
    once per test server and reused for every connection it accepts --
    never rebuilt here per connection. This mirrors
    build_server_context()'s own documented contract ("built once...
    and reused for every accepted connection -- never rebuilt per
    client"), which server/server.py already follows (one context at
    startup, reused for the process's lifetime). Test-harness
    hardening: rebuilding a fresh SSLContext (and re-reading the
    certificate/key from disk) on every one of a full suite's hundreds
    of connections, concurrently across many per-connection threads,
    is a load pattern production never exercises and is consistent
    with the intermittent Windows SSL alert failures observed under
    heavy concurrent full-suite runs.
    """

    return context.wrap_socket(client_socket, server_side=True)


def wrap_client_socket(sock, server_hostname="127.0.0.1"):
    """
    TLS-wrap a connected client socket, verifying the server
    certificate against the trusted CA -- the exact same context
    builder and wrap_socket() call ClientSession.connect() uses.
    """

    context = build_client_context()
    return context.wrap_socket(sock, server_hostname=server_hostname)


def serve_tls_client(
    handle_client, state, client_socket, client_address, logger=None, *, context
):
    """
    Server-side accept-loop helper: TLS-wrap one accepted connection
    and dispatch to ``handle_client`` on success. A failed handshake is
    logged (if a logger is given) and the raw socket is closed --
    ``handle_client`` is never called with an un-wrapped socket, and
    the failure is isolated to this one connection. Mirrors
    server/server.py's own per-connection handling exactly, so
    test_tls_transport.py's "plain TCP against a TLS-only server" test
    exercises the identical failure path the real server has.

    ``context`` (keyword-only, required -- see wrap_server_socket())
    must be built once by the caller's fixture, before its accept loop
    starts, and passed to every call for connections that fixture
    accepts -- not rebuilt per connection.
    """

    try:
        tls_socket = wrap_server_socket(client_socket, context)
    except (ssl.SSLError, OSError) as error:
        # OSError (not just ssl.SSLError): a client that aborts mid-
        # handshake -- e.g. because it just rejected our certificate,
        # or isn't speaking TLS at all -- can surface as a plain
        # connection-reset/aborted error at the socket layer rather
        # than an SSLError, depending on platform/timing. Either way
        # it's a failed handshake, not a server bug.
        if logger is not None:
            logger.warning(f"TLS handshake failed for {client_address}: {error}")
        client_socket.close()
        return

    handle_client(state, tls_socket, client_address)


class ServerHarness:
    """
    Owns one test server's listening socket, accept thread, accepted
    sockets and per-connection handler threads, so that shutdown is
    deterministic instead of best-effort.

    Why this exists
    ---------------
    Every socket integration suite used to carry its own copy of the
    same accept loop, ending in::

        stop.set()
        server_socket.close()
        accept_thread.join(timeout=2)
        for handler_thread in handler_threads:
            handler_thread.join(timeout=2)

    Two things are wrong with that, and both were observed:

    1. ``join(timeout=2)`` silently gives up. A handler that has not
       finished is simply abandoned -- still running, still holding a
       TLS socket derived from this fixture's SSLContext. When the
       fixture returns, that context becomes garbage while the thread
       is still using the OpenSSL structures behind it. Under a full
       suite this intermittently killed the interpreter outright
       (SIGSEGV, exit 139) rather than failing a test.

    2. The fixture that owns the *client* sockets tears down BEFORE
       the fixture that owns the server (pytest unwinds in reverse
       dependency order), so client sockets were closed while the
       accept loop was still running and handlers were still live --
       both ends of the same TLS connections being torn down
       concurrently from different threads.

    Shutdown is therefore split into two idempotent phases so the
    owner of the client sockets can sequence itself against the
    server:

        stop_accepting()   stop event, close the listening socket,
                           join the accept thread -- no new
                           connections, no accept() in flight
        <close clients>    handler threads' peers disappear, so their
                           receive loops end on their own
        join_handlers()    every handler finishes its own TLS teardown
                           before anything else proceeds

    ``shutdown()`` runs both, so a fixture that has no client sockets
    of its own can simply call it.

    Joins assert rather than swallow. A thread that cannot be joined
    is exactly the leak that causes the crash, so it must surface as a
    visible test failure here, not as a segfault somewhere later. If a
    handler is still blocked in recv() when we come to join it -- for
    instance because a test never closed its client socket -- its
    socket is shut down to unblock it first; that is done only for
    threads that are actually stuck, never on the healthy path.

    Supports tuple unpacking (``state, port = harness``) so the
    fixtures that yield it keep the ``state, port`` contract every
    existing test already unpacks.
    """

    #: Grace period for a handler expected to exit on its own.
    _HANDLER_GRACE_SECONDS = 2.0

    #: Further wait after forcibly unblocking a stuck handler.
    _HANDLER_FORCE_SECONDS = 5.0

    _ACCEPT_JOIN_SECONDS = 5.0

    def __init__(
        self,
        state,
        port,
        stop,
        server_socket,
        accept_thread,
        handler_threads,
        accepted_sockets,
    ):
        self.state = state
        self.port = port
        self._stop = stop
        self._server_socket = server_socket
        self._accept_thread = accept_thread
        self._handler_threads = handler_threads
        self._accepted_sockets = accepted_sockets
        self._accepting_stopped = False
        self._handlers_joined = False

    def __iter__(self):
        """Preserve the ``state, port = running_server`` contract."""

        return iter((self.state, self.port))

    def stop_accepting(self):
        """Phase 1 -- no new connections, no accept() in flight."""

        if self._accepting_stopped:
            return

        self._accepting_stopped = True

        self._stop.set()

        try:
            self._server_socket.close()
        except OSError:
            pass

        self._accept_thread.join(timeout=self._ACCEPT_JOIN_SECONDS)

        assert not self._accept_thread.is_alive(), (
            f"accept thread did not terminate within "
            f"{self._ACCEPT_JOIN_SECONDS}s"
        )

    def join_handlers(self):
        """Phase 2 -- every per-connection handler thread has finished.

        Run this AFTER the client sockets are closed: a handler sits in
        receive_message() until its peer disconnects, so joining first
        would always hit the grace period.
        """

        if self._handlers_joined:
            return

        self._handlers_joined = True

        for handler_thread in list(self._handler_threads):
            handler_thread.join(timeout=self._HANDLER_GRACE_SECONDS)

        if any(t.is_alive() for t in self._handler_threads):

            # Something is still blocked on a socket read. Unblock it
            # rather than abandoning it -- an abandoned thread outlives
            # this fixture's SSLContext and is what crashes the
            # interpreter later. shutdown() (not close()) is used so
            # the owning thread still performs its own close.
            for accepted in list(self._accepted_sockets):
                try:
                    accepted.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            for handler_thread in list(self._handler_threads):
                handler_thread.join(timeout=self._HANDLER_FORCE_SECONDS)

        still_alive = [t for t in self._handler_threads if t.is_alive()]

        assert not still_alive, (
            f"{len(still_alive)} handler thread(s) did not terminate; a "
            f"leaked thread holding a TLS socket from this fixture's "
            f"SSLContext is what causes the intermittent interpreter crash "
            f"this harness exists to prevent"
        )

    def shutdown(self):
        """Both phases, in order. Idempotent."""

        self.stop_accepting()
        self.join_handlers()


def start_test_server(serve_connection=None, state=None):
    """
    Start a TLS test server on an ephemeral port and return a
    :class:`ServerHarness` owning its lifecycle.

    One SSLContext is built here and reused for every connection this
    server accepts -- see wrap_server_socket() for why that matters --
    and it is kept referenced by the harness for as long as any handler
    thread can still be using it.

    ``serve_connection`` is called in a per-connection thread as
    ``serve_connection(state, context, client_socket, address)``. It
    defaults to the standard path every integration suite uses:
    serve_tls_client() dispatching into server.client_handler's real
    handle_client(). test_tls_production_integration.py overrides it to
    exercise server.server's own _serve_client() instead.

    The caller is responsible for shutting the harness down -- normally
    ``yield harness`` followed by ``harness.shutdown()``.
    """

    # Imported here rather than at module import time so this module
    # stays importable by tests that do not start a server.
    from server.client_handler import handle_client
    from server.server_state import ServerState

    if state is None:
        state = ServerState()

    context = build_server_context()

    if serve_connection is None:

        def serve_connection(state, context, client_socket, address):
            serve_tls_client(
                handle_client,
                state,
                client_socket,
                address,
                state.logger,
                context=context,
            )

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    port = server_socket.getsockname()[1]

    stop = threading.Event()
    handler_threads = []
    accepted_sockets = []

    def accept_loop():
        server_socket.settimeout(0.2)
        while not stop.is_set():
            try:
                client_socket, address = server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            accepted_sockets.append(client_socket)

            handler_thread = threading.Thread(
                target=serve_connection,
                args=(state, context, client_socket, address),
                daemon=True,
            )
            handler_thread.start()
            handler_threads.append(handler_thread)

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()

    harness = ServerHarness(
        state,
        port,
        stop,
        server_socket,
        accept_thread,
        handler_threads,
        accepted_sockets,
    )

    # Keep the context alive for exactly as long as the harness is --
    # no handler thread may outlive the object its TLS sockets came
    # from.
    harness._tls_context = context

    return harness


def serve_once_with_context(context):
    """
    Accept exactly one connection and perform the server-side TLS
    handshake with an arbitrary caller-supplied context, in a
    background thread. Used only by negative-path tests (an untrusted
    CA, a wrong-hostname certificate) that need a server presenting
    something other than the real trusted development certificate --
    those tests care solely about how the *client* reacts, so any
    server-side handshake exception is swallowed here rather than
    propagated.

    Returns (listener_socket, port, thread) -- the caller is
    responsible for closing the listener and joining the thread.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def accept_and_handshake():
        listener.settimeout(3)
        try:
            conn, _addr = listener.accept()
        except TimeoutError:
            return
        try:
            context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=accept_and_handshake, daemon=True)
    thread.start()

    return listener, port, thread
