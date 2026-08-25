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

# ----------------------------------------------------------------------
# Quarantine for handler threads that could not be joined.
#
# A thread that is still running when its fixture goes away is the
# whole problem: it holds TLS sockets derived from that fixture's
# SSLContext, and once the fixture's last reference drops, OpenSSL's
# structures are freed underneath a thread that is still inside
# SSL_read(). That is a use-after-free, and it is what turned an
# intermittent test failure into an interpreter crash
# (0xc0000374 / SIGSEGV) somewhere later in the run.
#
# Nothing here makes a stuck thread exit -- join_handlers() still
# asserts, loudly, exactly as before. What this does is bound the
# CONSEQUENCE: the context and its sockets are moved somewhere that
# lives for the rest of the process, so the objects a running thread
# may touch can never be collected. A leak is a bounded, diagnosable
# problem; a heap corruption is not.
_QUARANTINE = []
_QUARANTINE_LOCK = threading.Lock()

#: OpenSSL SSL objects deliberately never freed -- see _retain_sslobj().
_RETAINED_SSLOBJS = []


def _retain_sslobj(sslobj):
    """Keep an OpenSSL SSL object alive for the process lifetime.

    Used before force-closing a socket a handler thread is still
    reading -- see ServerHarness._unblock_handlers().
    """

    with _QUARANTINE_LOCK:
        _RETAINED_SSLOBJS.append(sslobj)


def _quarantine(context, sockets, threads):
    """Retain everything a still-running handler thread might use, for
    the lifetime of the process."""

    with _QUARANTINE_LOCK:
        _QUARANTINE.append(
            {
                "context": context,
                "sockets": list(sockets),
                "threads": list(threads),
            }
        )


def quarantined_thread_count():
    """Number of handler threads that had to be quarantined. Tests use
    this to assert the harness is not accumulating live threads."""

    with _QUARANTINE_LOCK:
        return sum(
            1
            for entry in _QUARANTINE
            for thread in entry["threads"]
            if thread.is_alive()
        )


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
    handle_client,
    state,
    client_socket,
    client_address,
    logger=None,
    *,
    context,
    on_wrapped=None,
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

    ``on_wrapped`` (optional) is called with the TLS socket as soon as
    the handshake succeeds, so the harness can hold a reference to the
    socket the handler thread will actually block on.

    That reference is necessary rather than convenient. ssl's
    wrap_socket() DETACHES the socket it is given -- the original
    object's fileno() becomes -1 -- so the raw pre-handshake socket the
    accept loop recorded is a dead handle within microseconds of being
    stored. Every attempt to unblock a stuck handler through it raised
    OSError and was swallowed, which is why the previous escalation
    path in join_handlers() never actually did anything.
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

    if on_wrapped is not None:
        on_wrapped(tls_socket)

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

        # Sockets the handler threads are actually blocked on, as
        # opposed to the pre-handshake sockets in _accepted_sockets
        # (which ssl detaches -- see serve_tls_client()). Registered
        # from the connection thread, read from the fixture thread, so
        # every access is guarded.
        self._live_sockets = []
        self._lock = threading.Lock()

    def __iter__(self):
        """Preserve the ``state, port = running_server`` contract."""

        return iter((self.state, self.port))

    def register_connection(self, tls_socket):
        """Record a live TLS socket a handler thread is serving.

        Called from the connection thread the moment the handshake
        completes, so that join_handlers() has something real to close
        if that thread later has to be unblocked.
        """

        with self._lock:
            self._live_sockets.append(tls_socket)

    def _unblock_handlers(self):
        """Force every still-running handler out of its blocking read.

        Uses close(), NOT shutdown(). That distinction is the whole
        repair, and it is measured rather than assumed -- against a
        real SSLSocket blocked in recv() on this platform:

            peer close()                 wakes immediately
            peer shutdown(SHUT_RDWR)     wakes immediately
            own shutdown(SHUT_RDWR)      DOES NOT WAKE
            own close()                  wakes immediately  (60/60)

        The old code called shutdown(SHUT_RDWR) on the handler's own
        socket -- the one mechanism in that list that does not work --
        and called it on an already-detached object, so it raised
        OSError and was swallowed. Handlers were therefore never
        unblocked and were abandoned by the join below.

        close() from another thread is safe here: CPython's _ssl module
        serialises I/O on an SSLSocket, so the read returns b"" rather
        than tearing the SSL object out from under the reader. Verified
        over 60 iterations with a forced gc.collect() after each, with
        no interpreter crash.
        """

        with self._lock:
            live = list(self._live_sockets)
            raw_accepted = list(self._accepted_sockets)

        # Live TLS sockets first -- these are what handlers block on.
        #
        # The retained _sslobj reference is not incidental. close()
        # sets SSLSocket._sslobj = None, which drops the last reference
        # to the underlying _ssl._SSLSocket and calls SSL_free() -- and
        # the whole reason we are here is that another thread is
        # currently inside SSL_read() on exactly that object. Freeing it
        # under the reader would be the same use-after-free this method
        # exists to avoid, just triggered by the cure instead of the
        # disease. Holding a reference keeps the OpenSSL structure alive
        # while still closing the file descriptor, which is what
        # actually wakes the reader.
        for sock in live:
            try:
                sslobj = getattr(sock, "_sslobj", None)
                if sslobj is not None:
                    _retain_sslobj(sslobj)
            except Exception:  # noqa: BLE001 - retention is best effort
                pass
            try:
                sock.close()
            except OSError:
                pass

        # The raw accepted sockets are already detached on the TLS
        # path (a no-op here), but are still the real socket for a
        # harness whose serve_connection never wraps -- e.g.
        # test_server_auth_integration.py's plain-socket override.
        for sock in raw_accepted:
            try:
                sock.close()
            except OSError:
                pass

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

            # Something is still blocked on a socket read -- typically a
            # test that finished without closing its client socket.
            # Unblock it rather than abandoning it; see
            # _unblock_handlers() for why this is close() and not
            # shutdown().
            self._unblock_handlers()

            for handler_thread in list(self._handler_threads):
                handler_thread.join(timeout=self._HANDLER_FORCE_SECONDS)

        still_alive = [t for t in self._handler_threads if t.is_alive()]

        if still_alive:
            # Unjoinable. The assertion below still fails the test --
            # nothing is being suppressed -- but before it does, hand
            # everything those threads can still touch to the
            # process-lifetime quarantine. Otherwise this fixture's
            # SSLContext is collected while they are inside OpenSSL,
            # and the run dies with a heap corruption far away from
            # here instead of failing right here with a usable message.
            with self._lock:
                sockets = list(self._live_sockets) + list(self._accepted_sockets)

            _quarantine(getattr(self, "_tls_context", None), sockets, still_alive)

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

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    port = server_socket.getsockname()[1]

    stop = threading.Event()
    handler_threads = []
    accepted_sockets = []

    # Built before the accept loop starts, and before the default
    # serve_connection below closes over it, so every connection this
    # server accepts can register the socket its handler will block on
    # (see ServerHarness.register_connection()).
    harness = ServerHarness(
        state,
        port,
        stop,
        server_socket,
        None,
        handler_threads,
        accepted_sockets,
    )

    # Keep the context alive for exactly as long as the harness is --
    # no handler thread may outlive the object its TLS sockets came
    # from.
    harness._tls_context = context

    if serve_connection is None:

        def serve_connection(state, context, client_socket, address):
            serve_tls_client(
                handle_client,
                state,
                client_socket,
                address,
                state.logger,
                context=context,
                on_wrapped=harness.register_connection,
            )

    def accept_loop():
        server_socket.settimeout(0.2)
        while not stop.is_set():
            try:
                client_socket, address = server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            handler_thread = threading.Thread(
                target=serve_connection,
                args=(state, context, client_socket, address),
                daemon=True,
            )

            # Recorded under the harness lock, and BEFORE the thread
            # starts: a connection that is accepted but not yet
            # tracked is one join_handlers() would not know to wait
            # for.
            with harness._lock:
                accepted_sockets.append(client_socket)
                handler_threads.append(handler_thread)

            handler_thread.start()

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    harness._accept_thread = accept_thread
    accept_thread.start()

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
