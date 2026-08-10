"""
TLS transport security.

The single authoritative implementation of TLS context construction,
for both the server and the client (TLS Transport Security phase).
Transport-layer only: confidentiality, integrity, and server
authentication for the TCP connection itself -- independent of, and
not a replacement for, the application-level Kyber/AES-256-GCM
end-to-end encryption of message content (crypto/key_manager.py,
crypto/aes.py). See docs/architecture/tls_transport.md for the full
relationship between the two layers.

Used at exactly two connection-establishment points:
  - server/server.py builds one server context at startup and wraps
    each accepted socket with it.
  - client/session.py builds a client context inside
    ClientSession.connect() and wraps the socket before returning.

Every other module continues to treat the connection as a generic
socket-like stream -- utils/network.py's sendall()/recv() calls work
identically on the resulting ssl.SSLSocket, so this module has no
callers anywhere else in the application.

tests/tls_test_support.py reuses these exact two functions rather than
building a second, parallel TLS implementation for tests.
"""

import ssl

from config import TLS_CA_FILE, TLS_CERT_FILE, TLS_KEY_FILE


def build_server_context() -> ssl.SSLContext:
    """
    Build the server-side TLS context: presents the server certificate
    and private key, and requires TLS 1.2 or newer. Intended to be
    built once (server/server.py, at startup) and reused for every
    accepted connection -- never rebuilt per client.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    context.load_cert_chain(certfile=TLS_CERT_FILE, keyfile=TLS_KEY_FILE)

    return context


def build_client_context() -> ssl.SSLContext:
    """
    Build the client-side TLS context: trusts only the configured CA
    (TLS_CA_FILE -- the development CA for local use, a real CA's
    bundle in production via the same environment-overridable
    setting), requires a valid certificate chain, and verifies the
    server hostname against the certificate's SAN. verify_mode and
    check_hostname are ssl's own secure defaults for
    PROTOCOL_TLS_CLIENT -- set explicitly here rather than left
    implicit, so the security posture is visible in code, not just
    inherited silently.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    context.load_verify_locations(cafile=TLS_CA_FILE)

    return context
