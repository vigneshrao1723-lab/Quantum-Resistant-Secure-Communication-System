"""
Quantum-Resistant Secure Communication System

Server Entry Point
"""

import socket
import ssl
import threading

from config import SERVER_BIND_HOST, SERVER_PORT
from security.tls import build_server_context
from server.client_handler import handle_client
from server.server_state import ServerState


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
    """

    try:
        tls_socket = tls_context.wrap_socket(client_socket, server_side=True)
    except (ssl.SSLError, OSError) as error:
        state.logger.warning(
            f"TLS handshake failed for {client_address}: {error}"
        )
        client_socket.close()
        return

    handle_client(state, tls_socket, client_address)


def start_server():
    """
    Start the secure communication server.
    """

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

    reachability = (
        "all interfaces -- reachable from other devices"
        if SERVER_BIND_HOST in ("0.0.0.0", "::")
        else "loopback only -- not reachable from other devices"
    )

    print("=" * 60)
    print(" Quantum-Resistant Secure Communication Server")
    print(f" Listening on {SERVER_BIND_HOST}:{SERVER_PORT} (TLS)")
    print(f" Bind scope: {reachability}")
    print(" Waiting for clients...")
    print("=" * 60)

    state.logger.info(
        f"Server started on {SERVER_BIND_HOST}:{SERVER_PORT} (TLS) -- {reachability}"
    )

    while True:

        client_socket, client_address = server_socket.accept()

        thread = threading.Thread(
            target=_serve_client,
            args=(
                state,
                tls_context,
                client_socket,
                client_address
            )
        )

        thread.start()

        print(
            f"Active Connections: "
            f"{len(state.clients)}"
        )


if __name__ == "__main__":
    start_server()
