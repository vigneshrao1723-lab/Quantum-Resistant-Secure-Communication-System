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

from security.tls import build_client_context


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
