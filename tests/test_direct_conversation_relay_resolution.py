"""
Tests for D3.1 (Conversation Operations Migration, first slice):
direct-conversation-id resolution moves server-side, ahead of chat
relay/persistence and session_key relay, instead of the receiving
client resolving/creating it itself via a direct database call (see
client/conversation_store.py::ensure_direct_conversation_id(), not
migrated by this slice, but no longer reached by handle_chat()/
handle_session_key() once a later slice updates them to read the
fields this one adds).

Traces exactly the flow the D3 audit called out:

  1. A relayed direct "chat" packet now carries a NEW field,
     "direct_conversation_id" -- deliberately never "conversation_id",
     since the client's handle_chat() derives is_group from that
     field's mere presence (group packets set it, direct ones never
     did); reusing it would misclassify every direct message as a
     group one the moment a client reads it.
  2. A relayed "session_key" packet now carries "conversation_id" --
     safe to reuse there, since session_key packets are always direct
     (group keys use a separate packet type, group_key_distribution).
  3. Both packet types' "sender" field is now always the authenticated
     socket identity -- server/client_handler.py::client_handler.py
     already did this for "chat"; this slice extends the identical
     hardening to "session_key".
  4. ConversationRepository.get_or_create_direct_conversation() now
     takes a transaction-scoped Postgres advisory lock keyed on the
     (sorted) pair of user ids, so two concurrent resolutions for the
     same pair converge on one conversation instead of racing to
     create two.

Uses raw sockets against the real server.client_handler.handle_client
accept loop -- the same harness pattern as
test_message_routing_security.py and test_chat_encryption_integration.py
-- plus one real-crypto round trip (manually reproducing
ClientSession's handshake/session-key/AES steps, exactly as
test_chat_encryption_integration.py already does, since ClientSession
itself hardcodes config.SERVER_PORT and can't target a fresh ephemeral
per-test port) to prove ordinary encrypted direct chat is completely
unaffected by this slice.

Run with:
    pytest tests/test_direct_conversation_relay_resolution.py -v
"""

import base64
import json
import os
import socket
import struct
import threading
import time
import uuid
from datetime import datetime, timezone

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
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
    harness = start_test_server()

    yield harness

    harness.shutdown()


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "D3.1 Relay Resolution Test",
            "username": f"d31_{suffix_hint}{suffix}",
            "email": f"d31_{suffix_hint}{suffix}@example.com",
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


def _connect_and_authenticate(port, user_payload, algorithm="KYBER"):
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))
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

    yield {
        "port": port,
        "alice": (alice_sock, alice_name, alice_payload["user_id"]),
        "bob": (bob_sock, bob_name, bob_payload["user_id"]),
    }

    alice_sock.close()
    bob_sock.close()
    _delete_user(alice_payload["username"])
    _delete_user(bob_payload["username"])


def _find_direct_conversation_id(user_a_id, user_b_id):
    db = SessionLocal()
    try:
        conversation = ConversationRepository(db)._find_direct_conversation(
            uuid.UUID(user_a_id), uuid.UUID(user_b_id)
        )
        return str(conversation.id) if conversation else None
    finally:
        db.close()


# ----------------------------------------------------------------------
# A. Direct chat relay carries the resolved direct_conversation_id
# ----------------------------------------------------------------------


def test_direct_chat_relay_attaches_resolved_direct_conversation_id(alice_and_bob):
    alice_sock, alice_name, alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_chat_packet(
            sender=alice_name,
            receiver=bob_name,
            message="first-ever-message",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert delivered.get("direct_conversation_id")
    uuid.UUID(delivered["direct_conversation_id"])  # must be a real UUID string

    expected = _find_direct_conversation_id(alice_id, bob_id)
    assert expected is not None
    assert delivered["direct_conversation_id"] == expected


def test_direct_chat_packet_never_misclassifies_as_group(alice_and_bob):
    """The exact regression the audit flagged: a client's
    handle_chat() derives is_group from bool(packet.get("conversation_id")).
    direct_conversation_id must never be aliased onto that field."""
    alice_sock, alice_name, _alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, _bob_id = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_chat_packet(
            sender=alice_name,
            receiver=bob_name,
            message="still-a-direct-message",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )

    delivered = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert delivered.get("direct_conversation_id")

    # The field a client's is_group check actually reads.
    assert not delivered.get("conversation_id")
    assert bool(delivered.get("conversation_id")) is False


def test_direct_conversation_id_is_stable_across_messages(alice_and_bob):
    alice_sock, alice_name, alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_chat_packet(
            sender=alice_name, receiver=bob_name, message="one",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    first = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
    assert first is not None

    _send(
        bob_sock,
        create_chat_packet(
            sender=bob_name, receiver=alice_name, message="two",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
    second = _recv_until(alice_sock, lambda p: p.get("type") == "chat")
    assert second is not None

    assert first["direct_conversation_id"] == second["direct_conversation_id"]

    db = SessionLocal()
    try:
        message_repo = MessageRepository(db)
        conversation = None
        for _ in range(100):
            conversation = message_repo.get_conversation(
                uuid.UUID(alice_id), uuid.UUID(bob_id)
            )
            if len(conversation) >= 2:
                break
            time.sleep(0.05)

        assert len(conversation) == 2
        assert str(conversation[0].conversation_id) == first["direct_conversation_id"]
        assert str(conversation[1].conversation_id) == first["direct_conversation_id"]
    finally:
        db.close()


def test_offline_direct_message_also_gets_resolved_conversation_id(running_server):
    """The offline/queued persistence branch (no connected recipient)
    must resolve and persist conversation_id exactly like the online
    relay branch does -- there is no packet to attach it to (nobody
    receives it live), only the database row."""
    _state, port = running_server

    alice_payload = _register_user("offline_a_")
    bob_payload = _register_user("offline_b_")

    try:
        alice_sock, alice_name = _connect_and_authenticate(port, alice_payload)
        try:
            # bob is never connected in this test -- offline the whole
            # time.
            _send(
                alice_sock,
                create_chat_packet(
                    sender=alice_name,
                    receiver=bob_payload["username"],
                    message="offline message to bob",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ),
            )

            db = SessionLocal()
            try:
                message_repo = MessageRepository(db)
                conversation = None
                for _ in range(100):
                    conversation = message_repo.get_conversation(
                        uuid.UUID(alice_payload["user_id"]),
                        uuid.UUID(bob_payload["user_id"]),
                    )
                    if conversation:
                        break
                    time.sleep(0.05)

                assert conversation
                persisted_conversation_id = str(conversation[-1].conversation_id)
                assert persisted_conversation_id
            finally:
                db.close()

            expected = _find_direct_conversation_id(
                alice_payload["user_id"], bob_payload["user_id"]
            )
            assert expected is not None
            assert persisted_conversation_id == expected
        finally:
            alice_sock.close()
    finally:
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


# ----------------------------------------------------------------------
# B. Concurrency: two simultaneous first contacts converge on one id
# ----------------------------------------------------------------------


def test_concurrent_repository_calls_for_the_same_pair_resolve_to_one_conversation():
    """Direct, deterministic proof of the advisory-lock fix: two
    threads, two independent DB sessions, synchronized to call
    get_or_create_direct_conversation() for the same never-before-seen
    pair at the same instant."""
    user_a = _register_user("race_a_")
    user_b = _register_user("race_b_")

    try:
        barrier = threading.Barrier(2)
        results = [None, None]
        errors = []

        def worker(index):
            db = SessionLocal()
            try:
                barrier.wait(timeout=5)
                conversation = ConversationRepository(db).get_or_create_direct_conversation(
                    uuid.UUID(user_a["user_id"]), uuid.UUID(user_b["user_id"])
                )
                db.commit()
                results[index] = str(conversation.id)
            except Exception as error:  # noqa: BLE001 -- captured for
                # this test's own assertion below, not silently
                # discarded.
                errors.append(error)
            finally:
                db.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert not errors, errors
        assert results[0] is not None
        assert results[0] == results[1]

        db = SessionLocal()
        try:
            member_rows = (
                db.query(ConversationMember)
                .filter(ConversationMember.user_id == uuid.UUID(user_a["user_id"]))
                .all()
            )
            direct_ids = {
                str(row.conversation_id)
                for row in member_rows
                if db.get(Conversation, row.conversation_id).type == Conversation.TYPE_DIRECT
            }
            assert direct_ids == {results[0]}, (
                "exactly one direct conversation row must exist for this pair, "
                f"found {direct_ids}"
            )
        finally:
            db.close()
    finally:
        _delete_user(user_a["username"])
        _delete_user(user_b["username"])


def test_two_clients_racing_their_first_message_converge_on_one_conversation(running_server):
    """Same property, exercised end-to-end: two real connections
    sending their first-ever message to each other at (as close to)
    the same instant as socket scheduling allows."""
    _state, port = running_server

    alice_payload = _register_user("racesock_a_")
    bob_payload = _register_user("racesock_b_")

    alice_sock, alice_name = _connect_and_authenticate(port, alice_payload)
    bob_sock, bob_name = _connect_and_authenticate(port, bob_payload)

    try:
        barrier = threading.Barrier(2)

        def send_from(sock, sender, receiver, text):
            barrier.wait(timeout=5)
            _send(
                sock,
                create_chat_packet(
                    sender=sender,
                    receiver=receiver,
                    message=text,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ),
            )

        thread_a = threading.Thread(
            target=send_from, args=(alice_sock, alice_name, bob_name, "hi from alice")
        )
        thread_b = threading.Thread(
            target=send_from, args=(bob_sock, bob_name, alice_name, "hi from bob")
        )
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=5)
        thread_b.join(timeout=5)

        delivered_to_bob = _recv_until(bob_sock, lambda p: p.get("type") == "chat")
        delivered_to_alice = _recv_until(alice_sock, lambda p: p.get("type") == "chat")

        assert delivered_to_bob is not None
        assert delivered_to_alice is not None
        assert delivered_to_bob["direct_conversation_id"]
        assert (
            delivered_to_bob["direct_conversation_id"]
            == delivered_to_alice["direct_conversation_id"]
        )

        # Live delivery (_recv_until() above) only proves the packet was
        # relayed -- persist_message() runs after the relay, in each
        # side's own handler thread, so both writes can still be
        # in-flight here. Waiting for both to actually land before
        # cleanup's cascading DELETE FROM users runs avoids racing that
        # DELETE against two concurrent INSERTs into messages, which
        # can genuinely deadlock in Postgres (observed: a real
        # DeadlockDetected error under stress, unrelated to the
        # advisory lock -- pure row-lock contention between concurrent
        # writers). Mirrors the identical wait-for-persistence pattern
        # already used elsewhere in this file (e.g.
        # test_direct_conversation_id_is_stable_across_messages) and in
        # test_message_routing_security.py.
        db = SessionLocal()
        try:
            message_repo = MessageRepository(db)
            conversation = []
            for _ in range(100):
                conversation = message_repo.get_conversation(
                    uuid.UUID(alice_payload["user_id"]),
                    uuid.UUID(bob_payload["user_id"]),
                )
                if len(conversation) >= 2:
                    break
                time.sleep(0.05)

            assert len(conversation) == 2
        finally:
            db.close()
    finally:
        alice_sock.close()
        bob_sock.close()
        _delete_user(alice_payload["username"])
        _delete_user(bob_payload["username"])


# ----------------------------------------------------------------------
# C. Sender identity cannot be forged on session_key packets
# ----------------------------------------------------------------------


def test_session_key_sender_cannot_be_forged(alice_and_bob):
    alice_sock, alice_name, _alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, _bob_id = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_session_key_packet(
            sender="mallory",
            receiver=bob_name,
            algorithm="KYBER",
            encrypted_key="forged-payload-irrelevant-to-this-test",
        ),
    )

    delivered = _recv_until(
        bob_sock,
        lambda p: p.get("type") == "key_exchange" and p.get("operation") == "session_key",
    )
    assert delivered is not None
    assert delivered["sender"] == alice_name
    assert delivered["sender"] != "mallory"


# ----------------------------------------------------------------------
# D. Session-key relay still works and carries a resolved conversation_id
# ----------------------------------------------------------------------


def test_session_key_relay_still_works_and_carries_conversation_id(alice_and_bob):
    alice_sock, alice_name, alice_id = alice_and_bob["alice"]
    bob_sock, bob_name, bob_id = alice_and_bob["bob"]

    _send(
        alice_sock,
        create_session_key_packet(
            sender=alice_name,
            receiver=bob_name,
            algorithm="KYBER",
            encrypted_key="opaque-encapsulation-bytes",
            epoch=3,
        ),
    )

    delivered = _recv_until(
        bob_sock,
        lambda p: p.get("type") == "key_exchange" and p.get("operation") == "session_key",
    )
    assert delivered is not None
    assert delivered["encrypted_key"] == "opaque-encapsulation-bytes"
    assert delivered["algorithm"] == "KYBER"
    assert delivered["epoch"] == 3
    assert delivered["sender"] == alice_name

    assert delivered.get("conversation_id")
    uuid.UUID(delivered["conversation_id"])

    expected = _find_direct_conversation_id(alice_id, bob_id)
    assert expected is not None
    assert delivered["conversation_id"] == expected


# ----------------------------------------------------------------------
# E. Real encrypted chat is unaffected end to end
# ----------------------------------------------------------------------


class _ConnectedClient:
    """Performs the exact handshake steps ClientSession.login() +
    send_public_key() perform (JWT auth, then public-key announce),
    using the real KeyManager, over a raw socket pointed at the test's
    ephemeral server port -- mirrors
    test_chat_encryption_integration.py's identical helper, since
    ClientSession itself hardcodes config.SERVER_PORT."""

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


def test_direct_chat_still_works_end_to_end_with_real_crypto(running_server):
    """The end-to-end regression check: ordinary encrypted direct
    chat -- handshake, Kyber/RSA session-key exchange, AES-256-GCM
    encrypt/decrypt -- is completely unaffected by this slice. Neither
    the crypto nor KeyManager logic was touched; this proves it."""
    state, port = running_server

    user_a = _register_user("crypto_a_")
    user_b = _register_user("crypto_b_")

    client_a = _ConnectedClient(port, user_a)
    _wait_for_public_key(state, client_a)
    client_b = _ConnectedClient(port, user_b)
    _wait_for_public_key(state, client_b)

    try:
        _exchange_public_keys(client_a, client_b)

        session_key = _establish_session_key(client_a, client_b)

        plaintext = "ordinary direct message, unaffected by D3.1"
        cipher = AESCipher(session_key)
        ciphertext = cipher.encrypt(plaintext)

        _send(
            client_a.sock,
            create_chat_packet(
                sender=client_a.username,
                receiver=client_b.username,
                message=ciphertext,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
        )

        delivered = _recv_until(client_b.sock, lambda p: p.get("type") == "chat")
        assert delivered is not None
        assert delivered["sender"] == client_a.username

        decrypted = AESCipher(session_key).decrypt(delivered["message"])
        assert decrypted == plaintext

        # The new field is present alongside completely unaffected
        # crypto -- this slice is additive, not a behavior change for
        # a client that doesn't yet read it.
        assert delivered.get("direct_conversation_id")
    finally:
        client_a.close()
        client_b.close()
        _delete_user(user_a["username"])
        _delete_user(user_b["username"])
