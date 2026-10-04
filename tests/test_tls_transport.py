"""
Dedicated tests for TLS Transport Security.

Proves the TLS layer independently, against the real
server.client_handler.handle_client accept loop wrapped in TLS via
tests/tls_test_support.py -- which itself reuses security.tls's exact
context builders, never a second/fake TLS implementation.

Covers:
  - Trusted-CA connections succeed; untrusted-CA and wrong-hostname/
    SAN connections are rejected by the client (never a server-side
    or hostname-check bypass).
  - The server's TLS 1.2 floor is both met by a normal client and
    actually enforced against an older one.
  - The critical property: a plaintext TCP client cannot successfully
    authenticate against the TLS-only server -- TLS is mandatory, not
    silently optional.
  - JWT authentication, Kyber public-key exchange, direct messaging,
    and group messaging all still work, unmodified, over TLS.
  - utils/network.py's real send_message()/receive_message() framing
    functions work unchanged over an ssl.SSLSocket.
  - Application-level (Kyber/AES) confidentiality and tamper-detection
    are unaffected by -- and independent of -- the TLS layer beneath
    them.

Run with:
    pytest tests/test_tls_transport.py -v
"""

import json
import socket
import ssl
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from config import TLS_CA_FILE
from crypto.aes import AESCipher
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from scripts.generate_dev_certs import generate_dev_ca, generate_server_cert
from tests.tls_test_support import (
    serve_once_with_context,
    start_test_server,
    wrap_client_socket,
)
from utils.network import receive_message, send_message
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_group_create_packet,
    create_payload_packet,
    create_public_key_packet,
)


def _send(sock, message):
    data = json.dumps(message).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recvall(sock, n):
    data = b""
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except (ConnectionResetError, ConnectionAbortedError):
            # A connection the server closed after a failed TLS
            # handshake (this file's plain-TCP-rejection test) can
            # surface as a hard reset rather than a graceful close,
            # depending on platform/timing -- treated identically to
            # the graceful "no more data" case below.
            return None
        if not chunk:
            return None
        data += chunk
    return data


def _recv(sock, timeout=3):
    sock.settimeout(timeout)
    header = _recvall(sock, 4)
    if not header:
        return None
    length = struct.unpack("!I", header)[0]
    data = _recvall(sock, length)
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        return data.decode("utf-8")


def _recv_until(sock, predicate, attempts=40, per_attempt_timeout=0.3):
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except (TimeoutError, OSError):
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


@pytest.fixture()
def running_server():
    """
    A real handle_client accept loop, TLS-only: every accepted socket
    is wrapped via tests/tls_test_support.serve_tls_client() -- the
    exact same context builder and wrap_socket() call
    server/server.py's real accept loop uses -- before handle_client()
    ever sees it. A connection whose handshake fails never reaches
    handle_client() and never affects any other connection (isolated
    per-thread, mirroring the real server).
    """
    harness = start_test_server()

    yield harness

    harness.shutdown()


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "TLS Transport Test",
            "username": f"tlstest_{suffix_hint}{suffix}",
            "email": f"tlstest_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
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
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _connect_tls(port):
    """Raw TCP connect + the real client-side TLS wrap (trusted CA,
    hostname verification enabled) -- mirrors ClientSession.connect()."""
    raw_sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    return wrap_client_socket(raw_sock)


def _connect_and_authenticate(port, user_payload, algorithm="KYBER"):
    sock = _connect_tls(port)
    token = _login_and_get_token(user_payload)

    _send(sock, create_auth_packet(token))
    auth_result = _recv(sock)
    assert auth_result["success"] is True, auth_result
    username = auth_result["username"]

    _send(
        sock,
        create_public_key_packet(
            username=username, algorithm=algorithm, public_key="dummy-public-key"
        ),
    )

    return sock, username


@pytest.fixture()
def alice_and_bob(running_server):
    _state, port = running_server

    alice_payload = _register_user("alice_")
    bob_payload = _register_user("bob_")

    alice_sock, alice_name = _connect_and_authenticate(port, alice_payload)
    bob_sock, bob_name = _connect_and_authenticate(port, bob_payload)

    yield {"port": port, "alice": (alice_sock, alice_name), "bob": (bob_sock, bob_name)}

    alice_sock.close()
    bob_sock.close()
    _delete_user(alice_payload["username"])
    _delete_user(bob_payload["username"])


def _write_pem(path, key=None, cert=None):
    if key is not None:
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    else:
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ----------------------------------------------------------------------
# 1. Trusted certificate -> connection succeeds
# ----------------------------------------------------------------------

def test_trusted_certificate_connection_succeeds(running_server):
    _state, port = running_server

    sock = _connect_tls(port)
    try:
        assert isinstance(sock, ssl.SSLSocket)
        # A real round trip over the TLS-wrapped socket, not just a
        # completed handshake.
        _send(sock, create_auth_packet("not-a-real-token"))
        response = _recv(sock)
        assert response is not None
        assert response["type"] == "auth_result"
    finally:
        sock.close()


# ----------------------------------------------------------------------
# 2. Untrusted CA -> client rejects connection
# ----------------------------------------------------------------------

def test_untrusted_ca_is_rejected(tmp_path):
    other_ca_key, other_ca_cert = generate_dev_ca(common_name="Untrusted Test CA")
    server_key, server_cert = generate_server_cert(other_ca_key, other_ca_cert)

    cert_path = tmp_path / "untrusted_server.crt"
    key_path = tmp_path / "untrusted_server.key"
    _write_pem(cert_path, cert=server_cert)
    _write_pem(key_path, key=server_key)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    listener, port, thread = serve_once_with_context(server_context)
    try:
        raw_sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        with pytest.raises(ssl.SSLError):
            wrap_client_socket(raw_sock)
    finally:
        listener.close()
        thread.join(timeout=2)


# ----------------------------------------------------------------------
# 3. Wrong hostname/SAN -> client rejects connection
# ----------------------------------------------------------------------

def test_wrong_hostname_san_is_rejected(tmp_path):
    """A certificate signed by the real, trusted dev CA -- so chain-of-
    trust is a non-issue -- but whose SAN names a different host than
    "127.0.0.1" must still be rejected, on hostname-verification
    grounds alone. Reuses wrap_client_socket() (and therefore
    security.tls.build_client_context()) exactly as every other test
    in this file does -- no separate client context is built here."""
    ca_key_path = Path(TLS_CA_FILE).with_name("ca.key")
    ca_key = serialization.load_pem_private_key(
        ca_key_path.read_bytes(), password=None
    )
    ca_cert = x509.load_pem_x509_certificate(Path(TLS_CA_FILE).read_bytes())

    server_key, server_cert = generate_server_cert(
        ca_key, ca_cert, common_name="wrong-host.example", sans=["wrong-host.example"]
    )

    cert_path = tmp_path / "wrong_host_server.crt"
    key_path = tmp_path / "wrong_host_server.key"
    _write_pem(cert_path, cert=server_cert)
    _write_pem(key_path, key=server_key)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    listener, port, thread = serve_once_with_context(server_context)
    try:
        raw_sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        with pytest.raises(ssl.SSLError):
            wrap_client_socket(raw_sock, server_hostname="127.0.0.1")
    finally:
        listener.close()
        thread.join(timeout=2)


# ----------------------------------------------------------------------
# 4/5. TLS minimum version
# ----------------------------------------------------------------------

def test_tls_minimum_version_is_negotiated(running_server):
    _state, port = running_server

    sock = _connect_tls(port)
    try:
        assert sock.version() in ("TLSv1.2", "TLSv1.3")
    finally:
        sock.close()


def test_tls_minimum_version_rejects_older_client(running_server):
    _state, port = running_server

    old_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    old_context.check_hostname = True
    old_context.verify_mode = ssl.CERT_REQUIRED
    old_context.load_verify_locations(cafile=TLS_CA_FILE)

    try:
        old_context.maximum_version = ssl.TLSVersion.TLSv1_1
    except ValueError:
        pytest.skip("Local OpenSSL build cannot express a sub-TLS1.2 ceiling")

    raw_sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    with pytest.raises(ssl.SSLError):
        old_context.wrap_socket(raw_sock, server_hostname="127.0.0.1")


# ----------------------------------------------------------------------
# 6. CRITICAL TEST: plain TCP cannot authenticate against the
#    TLS-only server.
# ----------------------------------------------------------------------

def test_plain_tcp_client_cannot_authenticate_against_tls_only_server(running_server):
    """TLS must not be silently optional. A client that skips the TLS
    handshake entirely and sends a plaintext "auth" packet must never
    receive a valid application response -- the server's per-connection
    TLS wrap must fail and close the connection before handle_client()
    (and therefore authenticate_connection()) ever runs."""
    _state, port = running_server

    plain_sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        _send(plain_sock, create_auth_packet("irrelevant-token"))
        response = _recv(plain_sock, timeout=2)
        assert response is None
    finally:
        plain_sock.close()


# ----------------------------------------------------------------------
# 7. JWT authentication over TLS
# ----------------------------------------------------------------------

def test_jwt_authentication_succeeds_over_tls(running_server):
    _state, port = running_server

    payload = _register_user("auth_")
    try:
        sock = _connect_tls(port)
        try:
            token = _login_and_get_token(payload)
            _send(sock, create_auth_packet(token))
            result = _recv(sock)
            assert result["success"] is True
            assert result["username"] == payload["username"]
        finally:
            sock.close()
    finally:
        _delete_user(payload["username"])


# ----------------------------------------------------------------------
# 8. Kyber/public-key exchange over TLS
# ----------------------------------------------------------------------

def test_public_key_exchange_succeeds_over_tls(alice_and_bob):
    alice_sock, alice_name = alice_and_bob["alice"]
    bob_sock, bob_name = alice_and_bob["bob"]

    alice_receives_bob_key = _recv_until(
        alice_sock,
        lambda p: p.get("type") == "key_exchange" and p.get("username") == bob_name,
    )
    bob_receives_alice_key = _recv_until(
        bob_sock,
        lambda p: p.get("type") == "key_exchange" and p.get("username") == alice_name,
    )

    assert alice_receives_bob_key is not None
    assert bob_receives_alice_key is not None


# ----------------------------------------------------------------------
# 9. Direct messaging over TLS
# ----------------------------------------------------------------------

def test_direct_messaging_works_over_tls(alice_and_bob):
    alice_sock, alice_name = alice_and_bob["alice"]
    bob_sock, bob_name = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_chat_packet(
            sender=alice_name,
            receiver=bob_name,
            message="hello-over-tls",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert delivered["sender"] == alice_name
    assert delivered["message"] == "hello-over-tls"


# ----------------------------------------------------------------------
# 10. Group messaging over TLS
# ----------------------------------------------------------------------

def test_group_messaging_works_over_tls(running_server):
    _state, port = running_server

    payloads = [_register_user(f"grp{i}_") for i in range(3)]
    connections = [_connect_and_authenticate(port, p) for p in payloads]

    try:
        creator_sock, creator_name = connections[0]
        member_b_sock, member_b_name = connections[1]
        member_c_sock, member_c_name = connections[2]

        _send(
            creator_sock,
            create_group_create_packet(
                sender=creator_name,
                name="TLS Group",
                member_usernames=[member_b_name, member_c_name],
            ),
        )

        for sock in (creator_sock, member_b_sock, member_c_sock):
            result = _recv_until(sock, lambda p: p.get("type") == "group_create_result")
            assert result is not None

        conversation_id = result["conversation_id"]

        envelope = PayloadEnvelope(
            payload_type=PayloadType.TEXT,
            ciphertext="group-message-over-tls",
            content_metadata={},
        )
        packet = create_payload_packet(
            sender=creator_name,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id=conversation_id,
        )

        _send(creator_sock, packet)

        delivered_b = _recv_until(member_b_sock, lambda p: p.get("type") == "chat")
        delivered_c = _recv_until(member_c_sock, lambda p: p.get("type") == "chat")

        assert delivered_b is not None
        assert delivered_b["message"] == "group-message-over-tls"
        assert delivered_c is not None
        assert delivered_c["message"] == "group-message-over-tls"
    finally:
        for sock, _name in connections:
            sock.close()
        for payload in payloads:
            _delete_user(payload["username"])


# ----------------------------------------------------------------------
# 11. Existing network framing works unchanged over SSLSocket
# ----------------------------------------------------------------------

def test_existing_network_framing_works_over_sslsocket(running_server):
    """Uses the real utils.network.send_message()/receive_message()
    functions directly (not this file's local _send/_recv mimics) to
    prove production framing code needs no TLS-awareness."""
    _state, port = running_server

    sock = _connect_tls(port)
    try:
        send_message(sock, create_auth_packet("irrelevant-token"))
        response = receive_message(sock)
        assert isinstance(response, dict)
        assert response["type"] == "auth_result"
    finally:
        sock.close()


# ----------------------------------------------------------------------
# 12. Ciphertext confidentiality intact over TLS (application-level
#     E2EE independent of the transport layer)
# ----------------------------------------------------------------------

def test_ciphertext_confidentiality_intact_over_tls(alice_and_bob):
    alice_sock, alice_name = alice_and_bob["alice"]
    bob_sock, bob_name = alice_and_bob["bob"]

    session_key = b"K" * 32
    plaintext = "still end-to-end encrypted over TLS"
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    _send(
        alice_sock,
        create_chat_packet(
            sender=alice_name,
            receiver=bob_name,
            message=ciphertext,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    # What travels on the wire (even TLS-decrypted, at the application
    # layer) is still AES-GCM ciphertext, never the plaintext.
    assert delivered["message"] != plaintext
    assert AESCipher(session_key).decrypt(delivered["message"]) == plaintext


# ----------------------------------------------------------------------
# 13. Tampered ciphertext still fails to decrypt over TLS
# ----------------------------------------------------------------------

def test_tampered_ciphertext_over_tls_still_fails_to_decrypt(alice_and_bob):
    alice_sock, alice_name = alice_and_bob["alice"]
    bob_sock, bob_name = alice_and_bob["bob"]

    session_key = b"K" * 32
    ciphertext = AESCipher(session_key).encrypt("original message")
    tampered = ciphertext[:-4] + ("A" * 4)

    _send(
        alice_sock,
        create_chat_packet(
            sender=alice_name,
            receiver=bob_name,
            message=tampered,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None

    with pytest.raises(ValueError):
        AESCipher(session_key).decrypt(delivered["message"])
