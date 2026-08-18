"""
Production-wiring tests for TLS Transport Security.

Unlike tests/test_tls_transport.py (which proves the TLS layer itself
via tests/tls_test_support.py's helpers, and the five migrated
existing integration suites, which prove application behavior over
TLS via that same shared helper), these tests exercise the actual
production code paths directly:

  - server/server.py's _serve_client() -- the exact function
    start_server()'s accept loop uses as its per-connection thread
    target -- imported and called directly, not reimplemented.
  - client/session.py's ClientSession.connect() -- the real,
    unmodified method the GUI and terminal client call -- driven with
    a real ClientSession instance, not a raw socket wrapped by hand.

This closes the one remaining gap the other TLS test files don't
cover: that server.py and session.py's own code, not just a parallel
test harness that mirrors it, actually performs the TLS handshake
correctly. Full messaging round trips (direct, group, persistence,
routing-security hardening) are deliberately not re-proven here --
that's already exhaustively covered, over TLS, by the five migrated
suites (test_private_messaging_integration.py,
test_group_messaging_integration.py,
test_message_persistence_integration.py,
test_chat_encryption_integration.py,
test_message_routing_security.py); duplicating that here would test
the same application behavior twice for no additional confidence.

Run with:
    pytest tests/test_tls_production_integration.py -v
"""

import socket
import ssl
import threading
import uuid

import pytest
from cryptography.hazmat.primitives import serialization

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from scripts.generate_dev_certs import generate_dev_ca, generate_server_cert
from server.server import _serve_client
from tests.tls_test_support import start_test_server


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "TLS Production Integration Test",
            "username": f"tlsprod_{suffix_hint}{suffix}",
            "email": f"tlsprod_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete_user(username):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(username)
        if user is not None:
            for session in SessionRepository(db).get_active_sessions_for_user(user.id):
                db.delete(session)
            db.delete(user)
            db.commit()
    finally:
        db.close()


def _login_and_get_token(payload):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        result = auth_service.authenticate_user(
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


@pytest.fixture()
def real_tls_server():
    """
    An accept loop built from server/server.py's own production
    pieces: ServerState, security.tls.build_server_context() (the
    same call start_server() makes), and _serve_client() itself,
    imported directly from server.server rather than reimplemented --
    bound to an ephemeral port instead of config.PORT so it can run
    inside the test suite. This is the real server.py wrapping logic.
    """
    # Overrides the default connection handler: this suite
    # exercises server.server's own _serve_client().
    def _serve(state, context, client_socket, address):
        _serve_client(state, context, client_socket, address)

    harness = start_test_server(_serve)

    yield harness

    harness.shutdown()


@pytest.fixture()
def real_session(real_tls_server, monkeypatch):
    """
    A real, unmodified ClientSession, pointed at the ephemeral real
    TLS server above via monkeypatched client.session.SERVER_PORT --
    client.session.SERVER_HOST is already "127.0.0.1", matching the
    development certificate's SAN, so only the port needs to move for
    a test run. Nothing about ClientSession itself is altered.
    """
    _state, port = real_tls_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    session = ClientSession()
    yield session
    session.disconnect()


# ----------------------------------------------------------------------
# A/B. Real server + real client: trusted TLS connection succeeds
# ----------------------------------------------------------------------

def test_real_client_session_connects_over_tls_via_real_server(real_session):
    """ClientSession.connect() (unmodified) against server.server's own
    _serve_client() (unmodified) -- the actual production code on both
    ends, not a parallel test mirror of it."""
    real_session.connect()

    assert real_session.connected is True
    assert isinstance(real_session.client_socket, ssl.SSLSocket)
    assert real_session.client_socket.version() in ("TLSv1.2", "TLSv1.3")


# ----------------------------------------------------------------------
# C. Real client rejects an untrusted certificate
# ----------------------------------------------------------------------

def test_real_client_session_rejects_untrusted_server(tmp_path, monkeypatch):
    """The real ClientSession.connect() -- not a hand-built test
    context -- must refuse a server presenting a certificate signed by
    a CA it doesn't trust."""
    other_ca_key, other_ca_cert = generate_dev_ca(common_name="Untrusted Prod Test CA")
    server_key, server_cert = generate_server_cert(other_ca_key, other_ca_cert)

    cert_path = tmp_path / "untrusted_server.crt"
    key_path = tmp_path / "untrusted_server.key"
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    untrusted_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    untrusted_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def accept_once():
        listener.settimeout(3)
        try:
            conn, _addr = listener.accept()
        except TimeoutError:
            return
        try:
            untrusted_context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()

    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    session = ClientSession()
    try:
        with pytest.raises(ssl.SSLError):
            session.connect()
    finally:
        session.disconnect()
        listener.close()
        thread.join(timeout=2)


# ----------------------------------------------------------------------
# F. JWT authentication over the real TLS connection
# ----------------------------------------------------------------------

def test_real_client_session_full_handshake_over_tls(real_session):
    """login() (a real JWT, via AuthenticationService) and
    send_public_key() (a real Kyber public key, via KeyManager) both
    succeed when driven through the real, unmodified ClientSession
    methods after a real connect() -- proving the full pre-messaging
    handshake works end-to-end over the actual production TLS wrapping
    on both ends, not just that a bare socket wrap succeeds. Live
    message exchange itself is out of scope here -- see this file's
    module docstring for why."""
    payload = _register_user("flow_")
    try:
        real_session.connect()

        real_session.access_token = _login_and_get_token(payload)
        real_session.login(payload["username"])

        assert real_session.username == payload["username"]

        real_session.send_public_key()  # must not raise
    finally:
        _delete_user(payload["username"])
