"""
Integration tests proving AES-256-GCM end-to-end encryption actually
holds through the real client-server chat flow: the server relays
only ciphertext (never plaintext, never decrypts), and only the
intended receiving client can decrypt it.

These tests drive the same production primitives ClientSession uses
internally (crypto.key_manager.KeyManager, crypto.aes.AESCipher,
utils.protocol packet builders) directly over raw sockets against the
real server.client_handler.handle_client accept loop -- the same
pattern as test_server_auth_integration.py. ClientSession itself
isn't used here because it hardcodes config.HOST/PORT inside
connect(), and this suite needs a fresh ephemeral port per run;
everything it does (auth, public-key exchange, session-key exchange,
AES encrypt/decrypt) is reproduced with the identical real classes.

Run with:
    pytest tests/test_chat_encryption_integration.py -v
"""

import base64
import json
import os
import socket
import struct
import threading
import time
import uuid

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from security.tls import build_server_context
from server.client_handler import handle_client
from server.server_state import ServerState
from tests.tls_test_support import serve_tls_client, wrap_client_socket
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_public_key_packet,
    create_session_key_packet,
)


def _send(sock, message):
    data = json.dumps(message).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recvall(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
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
    """Repeatedly receive, skipping packets that don't satisfy
    predicate (join/user_list/unrelated key_exchange broadcast noise),
    until a match or timeout."""
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except TimeoutError:
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


@pytest.fixture()
def running_server():
    """Runs the real handle_client accept loop against an ephemeral port."""
    state = ServerState()

    # Test-harness hardening: one SSLContext per fixture instance,
    # built once and reused for every connection this fixture's
    # accept loop handles -- mirrors build_server_context()'s own
    # documented contract ("built once... and reused for every
    # accepted connection -- never rebuilt per client"), which
    # server/server.py already follows. Previously each connection's
    # serve_tls_client() call rebuilt a fresh SSLContext (and re-read
    # the cert/key from disk) internally; under a full-suite run that
    # meant hundreds of concurrent, independent SSLContext
    # constructions across many threads -- a load pattern production
    # never exercises -- consistent with the intermittent Windows SSL
    # alert failures observed under heavy concurrent runs.
    tls_context = build_server_context()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    port = server_socket.getsockname()[1]

    stop = threading.Event()
    # Test-harness hardening: previously only accept_thread was
    # joined at teardown -- an in-flight per-connection handler
    # thread (blocked in recv()/the TLS handshake) could keep running
    # into the next test's setup, racing that test's own socket
    # teardown and surfacing as a raw OS-level error (observed:
    # WinError 10038, "operation attempted on something that is not
    # a socket") rather than a clean, isolated failure. Tracked here
    # so every one can be joined below.
    handler_threads = []

    def accept_loop():
        server_socket.settimeout(0.2)
        while not stop.is_set():
            try:
                client_socket, addr = server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            handler_thread = threading.Thread(
                target=serve_tls_client,
                args=(handle_client, state, client_socket, addr, state.logger),
                kwargs={"context": tls_context},
                daemon=True,
            )
            handler_thread.start()
            handler_threads.append(handler_thread)

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()

    yield state, port

    stop.set()
    server_socket.close()
    accept_thread.join(timeout=2)

    for handler_thread in handler_threads:
        handler_thread.join(timeout=2)


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Encryption Test",
            "username": f"enctest_{suffix_hint}{suffix}",
            "email": f"enctest_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
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


class _ConnectedClient:
    """Performs the exact handshake steps ClientSession.login() +
    send_public_key() perform (JWT auth, then public-key announce),
    using the real KeyManager, over a raw socket pointed at the
    test's ephemeral server port."""

    def __init__(self, port, user_payload):
        self.key_manager = KeyManager()
        self.sock = wrap_client_socket(
            socket.create_connection(("127.0.0.1", port), timeout=3)
        )

        token = _login_and_get_token(user_payload)
        _send(self.sock, create_auth_packet(token))
        auth_result = _recv(self.sock)
        assert auth_result["success"] is True, auth_result
        self.username = auth_result["username"]

        _send(
            self.sock,
            create_public_key_packet(
                username=self.username,
                algorithm=self.key_manager.algorithm,
                public_key=self.key_manager.public_key.decode("utf-8"),
            ),
        )

    def close(self):
        self.sock.close()


def _wait_for_public_key(state, client, attempts=40):
    # state.clients is keyed by the server-accepted socket object, not
    # the client's own socket.create_connection() object, so match by
    # username rather than indexing the dict directly.
    for _ in range(attempts):
        for record in state.clients.values():
            if (
                record.get("username") == client.username
                and record.get("public_key") is not None
            ):
                return
        time.sleep(0.05)
    raise AssertionError(f"Server never registered a public key for {client.username}")


def _exchange_public_keys(client_a, client_b):
    """Each side learns the other's public key, mirroring what the
    server's distribute_public_keys() sends out after both connect."""
    packet_for_a = _recv_until(
        client_a.sock,
        lambda p: p.get("type") == "key_exchange"
        and p.get("username") == client_b.username,
    )
    assert packet_for_a is not None
    client_a.key_manager.add_public_key(client_b.username, packet_for_a["public_key"])

    packet_for_b = _recv_until(
        client_b.sock,
        lambda p: p.get("type") == "key_exchange"
        and p.get("username") == client_a.username,
    )
    assert packet_for_b is not None
    client_b.key_manager.add_public_key(client_a.username, packet_for_b["public_key"])


def _establish_session_key(sender, receiver):
    """Mirror ClientSession.establish_session_key(): sender generates
    (or Kyber-encapsulates) an AES key for receiver and sends it
    wrapped over the wire; receiver unwraps it on the other end."""
    algorithm = sender.key_manager.algorithm

    if algorithm == "KYBER":
        encrypted_key, session_key = sender.key_manager.encapsulate_session_key(
            receiver.username
        )
    else:
        session_key = os.urandom(32)
        raw_encrypted_key = sender.key_manager.encrypt_session_key(
            receiver.username, session_key
        )
        encrypted_key = base64.b64encode(raw_encrypted_key).decode("utf-8")

    sender.key_manager.store_key(receiver.username, session_key)

    _send(
        sender.sock,
        create_session_key_packet(
            sender=sender.username,
            receiver=receiver.username,
            algorithm=algorithm,
            encrypted_key=encrypted_key,
        ),
    )

    packet = _recv_until(
        receiver.sock,
        lambda p: p.get("type") == "key_exchange"
        and p.get("operation") == "session_key",
    )
    assert packet is not None

    if algorithm == "KYBER":
        received_key = receiver.key_manager.decapsulate_session_key(
            packet["encrypted_key"]
        )
    else:
        received_key = receiver.key_manager.decrypt_session_key(
            base64.b64decode(packet["encrypted_key"])
        )

    receiver.key_manager.store_key(sender.username, received_key)

    return session_key


@pytest.fixture()
def two_clients(running_server):
    state, port = running_server

    user_a = _register_user("a_")
    user_b = _register_user("b_")

    client_a = _ConnectedClient(port, user_a)
    _wait_for_public_key(state, client_a)
    client_b = _ConnectedClient(port, user_b)
    _wait_for_public_key(state, client_b)

    _exchange_public_keys(client_a, client_b)

    yield client_a, client_b

    client_a.close()
    client_b.close()
    _delete_user(user_a["username"])
    _delete_user(user_b["username"])


def test_server_relays_ciphertext_not_plaintext(two_clients):
    client_a, client_b = two_clients
    session_key = _establish_session_key(client_a, client_b)

    plaintext = "This is a secret message that must never cross the wire in the clear."
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    _send(
        client_a.sock,
        create_chat_packet(
            sender=client_a.username, receiver=client_b.username, message=ciphertext
        ),
    )

    received = _recv_until(client_b.sock, lambda p: p.get("type") == "chat")
    assert received is not None

    # This is exactly what the server itself relayed -- prove it's
    # ciphertext, not the plaintext, and doesn't leak the plaintext.
    assert received["message"] == ciphertext
    assert received["message"] != plaintext
    assert plaintext not in received["message"]
    assert plaintext.encode("utf-8") not in base64.b64decode(received["message"])


def test_receiver_decrypts_to_original_plaintext(two_clients):
    client_a, client_b = two_clients
    _establish_session_key(client_a, client_b)

    plaintext = "Decrypt me correctly, please."
    session_key_a_side = client_a.key_manager.get_key(client_b.username)
    ciphertext = AESCipher(session_key_a_side).encrypt(plaintext)

    _send(
        client_a.sock,
        create_chat_packet(
            sender=client_a.username, receiver=client_b.username, message=ciphertext
        ),
    )

    received = _recv_until(client_b.sock, lambda p: p.get("type") == "chat")
    assert received is not None

    session_key_b_side = client_b.key_manager.get_key(client_a.username)
    decrypted = AESCipher(session_key_b_side).decrypt(received["message"])

    assert decrypted == plaintext


def test_wrong_session_key_fails_to_decrypt(two_clients):
    client_a, client_b = two_clients
    _establish_session_key(client_a, client_b)

    plaintext = "Only the right key should open this."
    real_key = client_a.key_manager.get_key(client_b.username)
    ciphertext = AESCipher(real_key).encrypt(plaintext)

    wrong_key = b"0" * 32
    with pytest.raises(ValueError):
        AESCipher(wrong_key).decrypt(ciphertext)


def test_tampered_ciphertext_on_the_wire_fails_to_decrypt(two_clients):
    client_a, client_b = two_clients
    session_key = _establish_session_key(client_a, client_b)

    plaintext = "Tamper with me and I should refuse to decrypt."
    ciphertext = AESCipher(session_key).encrypt(plaintext)

    _send(
        client_a.sock,
        create_chat_packet(
            sender=client_a.username, receiver=client_b.username, message=ciphertext
        ),
    )

    received = _recv_until(client_b.sock, lambda p: p.get("type") == "chat")
    assert received is not None

    raw = bytearray(base64.b64decode(received["message"]))
    raw[-1] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode("utf-8")

    with pytest.raises(ValueError):
        AESCipher(session_key).decrypt(tampered)


def test_multiple_encrypted_messages_between_two_users(two_clients):
    client_a, client_b = two_clients
    session_key = _establish_session_key(client_a, client_b)
    cipher = AESCipher(session_key)

    messages = [
        "first message",
        "second message",
        "third message with emoji \U0001f512",
    ]

    for message in messages:
        _send(
            client_a.sock,
            create_chat_packet(
                sender=client_a.username,
                receiver=client_b.username,
                message=cipher.encrypt(message),
            ),
        )

    received_plaintexts = []
    for _ in messages:
        received = _recv_until(client_b.sock, lambda p: p.get("type") == "chat")
        assert received is not None
        received_plaintexts.append(cipher.decrypt(received["message"]))

    assert received_plaintexts == messages


def test_multiple_encrypted_user_pairs_simultaneously(running_server):
    """Two independent conversations at once, each with its own AES
    session key -- neither pair's server-relayed ciphertext should be
    decryptable with the other pair's key."""
    state, port = running_server

    users = [_register_user(f"pair{i}_") for i in range(4)]
    clients = []

    try:
        for user in users:
            client = _ConnectedClient(port, user)
            _wait_for_public_key(state, client)
            clients.append(client)

        _exchange_public_keys(clients[0], clients[1])
        _exchange_public_keys(clients[2], clients[3])

        key_01 = _establish_session_key(clients[0], clients[1])
        key_23 = _establish_session_key(clients[2], clients[3])

        assert key_01 != key_23

        _send(
            clients[0].sock,
            create_chat_packet(
                sender=clients[0].username,
                receiver=clients[1].username,
                message=AESCipher(key_01).encrypt("pair-one message"),
            ),
        )
        _send(
            clients[2].sock,
            create_chat_packet(
                sender=clients[2].username,
                receiver=clients[3].username,
                message=AESCipher(key_23).encrypt("pair-two message"),
            ),
        )

        received_1 = _recv_until(clients[1].sock, lambda p: p.get("type") == "chat")
        received_3 = _recv_until(clients[3].sock, lambda p: p.get("type") == "chat")

        assert received_1 is not None
        assert received_3 is not None
        assert AESCipher(key_01).decrypt(received_1["message"]) == "pair-one message"
        assert AESCipher(key_23).decrypt(received_3["message"]) == "pair-two message"

        # Cross-pair key confusion must fail.
        with pytest.raises(ValueError):
            AESCipher(key_23).decrypt(received_1["message"])
    finally:
        for client in clients:
            client.close()
        for user in users:
            _delete_user(user["username"])
