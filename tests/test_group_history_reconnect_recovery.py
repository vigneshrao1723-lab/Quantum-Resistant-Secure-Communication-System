"""
Regression tests for Issue 4 (real-application testing bug report):
conversation history appearing to show "session expired" instead of
previous messages.

Diagnosis (given before implementation): no literal "session expired"
text exists anywhere in gui/. At the time this diagnosis was written,
load_conversation_history() was a pure local-DB read that never
touched the socket or the JWT; D4.3 (Message/History Operations
Migration) later moved it behind a server request/response, but the
conclusion below is unaffected -- a valid, already-authenticated
connection's history request cannot itself produce anything
resembling "session expired" either, real auth-token expiry is
handled entirely at connection time (authenticate_connection()), long
before load_conversation_history() is ever reachable. What the user
almost certainly saw is the existing, correctly-working placeholder
(ClientSession._UNDECRYPTABLE_PLACEHOLDER, "Message unavailable
(encrypted in a previous session)"). Two distinct situations sit
behind it:

  - Direct conversations, after a restart: NOT a bug -- session keys
    are ephemeral by design (fresh Kyber/RSA negotiation every
    process run, never persisted), so this is expected, already
    tested elsewhere (test_message_persistence_integration.py), and
    explicitly allowed by the acceptance criteria for this issue. The
    test below locks in that this remains true end-to-end through real
    sockets, not just at the DB-read level.

  - Group conversations, after a reconnect: a genuine, fixed bug.
    Phase 7's reconnect recovery only covered an *outstanding
    rotation*; it did nothing for a member simply reconnecting with a
    brand-new, empty KeyManager (i.e. every login), even though the
    key material objectively still exists among other members. The
    fix (server/client_handler.py::_ensure_group_keys_current_for_reconnecting_user())
    asks another connected active member to redeliver the *current*
    epoch's key -- not a new epoch -- so a reconnecting member regains
    full access to their group's history, unlike a newly *added*
    member (Issue 2), who deliberately does not.

Run with:
    pytest tests/test_group_history_reconnect_recovery.py -v
"""

import json
import os
import socket
import struct
import time
import uuid
from datetime import datetime, timezone

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import (
    create_auth_packet,
    create_chat_packet,
    create_group_create_packet,
    create_group_key_distribution_packet,
    create_group_key_rotation_complete_packet,
    create_payload_packet,
    create_public_key_packet,
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
            "full_name": "History Reconnect Test",
            "username": f"hrtest_{suffix_hint}{suffix}",
            "email": f"hrtest_{suffix_hint}{suffix}@example.com",
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


class _GroupClient:
    """See test_group_membership_integration.py's identical class for
    the full rationale -- duplicated per this codebase's convention.
    reconnect() is the piece this suite specifically exercises."""

    def __init__(self, port, user_payload):
        self.key_manager = KeyManager()
        self.username = None
        self.user_id = user_payload["user_id"]
        self._payload = user_payload
        self.sock = None
        self._connect(port)

    def _connect(self, port):
        self.sock = wrap_client_socket(
            socket.create_connection(("127.0.0.1", port), timeout=3)
        )
        token = _login_and_get_token(self._payload)
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

    def reconnect(self, port):
        """Close and re-establish the connection with a BRAND NEW
        KeyManager -- exactly what a real app restart looks like: the
        same authenticated user, zero cached key material."""
        self.sock.close()
        self.key_manager = KeyManager()
        self._connect(port)

    def close(self):
        self.sock.close()


def _get_epoch_state(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_epoch_state(uuid.UUID(conversation_id))
    finally:
        db.close()


@pytest.fixture()
def pair(running_server):
    _state, port = running_server

    payloads = [_register_user(f"p{i}_") for i in range(2)]
    creator = _GroupClient(port, payloads[0])
    reconnector = _GroupClient(port, payloads[1])

    # Exchange public keys.
    packet = _recv_until(
        creator.sock,
        lambda p: p.get("type") == "key_exchange" and p.get("username") == reconnector.username,
    )
    assert packet is not None
    creator.key_manager.add_public_key(reconnector.username, packet["public_key"])

    packet = _recv_until(
        reconnector.sock,
        lambda p: p.get("type") == "key_exchange" and p.get("username") == creator.username,
    )
    assert packet is not None
    reconnector.key_manager.add_public_key(creator.username, packet["public_key"])

    _send(
        creator.sock,
        create_group_create_packet(
            sender=creator.username, name="Reconnect Pair", member_usernames=[reconnector.username]
        ),
    )

    conversation_id = None
    for client in (creator, reconnector):
        result = _recv_until(client.sock, lambda p: p.get("type") == "group_create_result")
        assert result is not None
        conversation_id = result["conversation_id"]

    group_key = os.urandom(32)
    creator.key_manager.store_key(conversation_id, group_key, epoch=1)
    encapsulation, wrapped_key = creator.key_manager.wrap_key_for_member(
        reconnector.username, group_key
    )
    _send(
        creator.sock,
        create_group_key_distribution_packet(
            sender=creator.username,
            conversation_id=conversation_id,
            recipient=reconnector.username,
            encapsulation=encapsulation,
            wrapped_key=wrapped_key,
            epoch=1,
        ),
    )
    key_packet = _recv_until(
        reconnector.sock,
        lambda p: p.get("type") == "group_key_distribution" and p.get("epoch") == 1,
    )
    assert key_packet is not None
    received_key = reconnector.key_manager.unwrap_received_key(
        key_packet["encapsulation"], key_packet["wrapped_key"]
    )
    reconnector.key_manager.store_key(conversation_id, received_key, epoch=1)

    yield {
        "port": port,
        "conversation_id": conversation_id,
        "creator": creator,
        "reconnector": reconnector,
        "group_key": group_key,
        "payloads": payloads,
    }

    for client in (creator, reconnector):
        try:
            client.close()
        except OSError:
            pass
    for payload in payloads:
        _delete_user(payload["username"])


def test_baseline_group_messaging_works_before_reconnect(pair):
    """Sanity check the fixture itself -- if this fails, the bug is
    somewhere else entirely, not in reconnect recovery."""
    creator = pair["creator"]
    reconnector = pair["reconnector"]
    conversation_id = pair["conversation_id"]

    ciphertext = AESCipher(pair["group_key"]).encrypt("message before reconnect")
    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT, ciphertext=ciphertext, content_metadata={}
    )
    _send(
        creator.sock,
        create_payload_packet(
            sender=creator.username,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id=conversation_id,
            epoch=1,
        ),
    )

    delivered = _recv_until(reconnector.sock, lambda p: p.get("type") == "chat")
    assert delivered is not None
    assert AESCipher(pair["group_key"]).decrypt(delivered["message"]) == (
        "message before reconnect"
    )


def test_reconnecting_member_key_is_redelivered_without_a_rotation(pair):
    """The core Issue 4 fix: the reconnecting member's KeyManager is
    empty; the server must ask the still-connected creator to
    redeliver epoch 1 -- and this must NOT bump current_key_epoch
    (unlike Issue 2's add-member flow), since nobody joined or left."""
    creator = pair["creator"]
    reconnector = pair["reconnector"]
    conversation_id = pair["conversation_id"]
    port = pair["port"]

    assert reconnector.key_manager.get_key(conversation_id, epoch=1) == pair["group_key"]

    reconnector.reconnect(port)

    # A brand-new KeyManager -- exactly the state a real app restart
    # leaves a client in, and exactly what caused the reported bug.
    assert reconnector.key_manager.get_key(conversation_id, epoch=1) is None

    # A fresh KeyManager also means a fresh Kyber keypair -- the
    # creator must learn the reconnector's NEW public key
    # (distribute_public_keys() sends it) before it can correctly
    # wrap anything for them again.
    new_public_key_packet = _recv_until(
        creator.sock,
        lambda p: p.get("type") == "key_exchange" and p.get("username") == reconnector.username,
    )
    assert new_public_key_packet is not None
    creator.key_manager.add_public_key(
        reconnector.username, new_public_key_packet["public_key"]
    )

    # The server should ask the still-connected creator to redeliver.
    rotation_packet = _recv_until(
        creator.sock,
        lambda p: (
            p.get("type") == "group_key_rotation_required"
            and p.get("conversation_id") == conversation_id
            and p.get("epoch") == 1
            and reconnector.username in p.get("members", [])
        ),
    )
    assert rotation_packet is not None, (
        "server never asked an existing member to redeliver the key "
        "to the reconnecting member"
    )

    # The creator already has epoch 1 -- must reuse it exactly, not
    # generate a new (and therefore incompatible) one.
    assert creator.key_manager.get_key(conversation_id, epoch=1) == pair["group_key"]

    encapsulation, wrapped_key = creator.key_manager.wrap_key_for_member(
        reconnector.username, pair["group_key"]
    )
    _send(
        creator.sock,
        create_group_key_distribution_packet(
            sender=creator.username,
            conversation_id=conversation_id,
            recipient=reconnector.username,
            encapsulation=encapsulation,
            wrapped_key=wrapped_key,
            epoch=1,
        ),
    )
    _send(
        creator.sock,
        create_group_key_rotation_complete_packet(conversation_id=conversation_id, epoch=1),
    )

    redelivered_packet = _recv_until(
        reconnector.sock,
        lambda p: p.get("type") == "group_key_distribution" and p.get("epoch") == 1,
    )
    assert redelivered_packet is not None

    redelivered_key = reconnector.key_manager.unwrap_received_key(
        redelivered_packet["encapsulation"], redelivered_packet["wrapped_key"]
    )
    reconnector.key_manager.store_key(conversation_id, redelivered_key, epoch=1)

    # Exactly the original key -- not a new, incompatible one.
    assert redelivered_key == pair["group_key"]

    # Not a rotation: the epoch counters must be untouched.
    current, confirmed = _get_epoch_state(conversation_id)
    assert current == 1
    assert confirmed == 1


def test_reconnected_member_can_decrypt_pre_reconnect_history(pair):
    """The user-visible fix: unlike a newly ADDED member (Issue 2),
    a RECONNECTED member regains the same epoch key and can therefore
    still read messages sent before they reconnected."""
    creator = pair["creator"]
    reconnector = pair["reconnector"]
    conversation_id = pair["conversation_id"]
    port = pair["port"]

    pre_reconnect_ciphertext = AESCipher(pair["group_key"]).encrypt(
        "sent while reconnector was about to drop"
    )

    reconnector.reconnect(port)

    new_public_key_packet = _recv_until(
        creator.sock,
        lambda p: p.get("type") == "key_exchange" and p.get("username") == reconnector.username,
    )
    assert new_public_key_packet is not None
    creator.key_manager.add_public_key(
        reconnector.username, new_public_key_packet["public_key"]
    )

    rotation_packet = _recv_until(
        creator.sock,
        lambda p: (
            p.get("type") == "group_key_rotation_required" and p.get("epoch") == 1
        ),
    )
    assert rotation_packet is not None

    encapsulation, wrapped_key = creator.key_manager.wrap_key_for_member(
        reconnector.username, pair["group_key"]
    )
    _send(
        creator.sock,
        create_group_key_distribution_packet(
            sender=creator.username,
            conversation_id=conversation_id,
            recipient=reconnector.username,
            encapsulation=encapsulation,
            wrapped_key=wrapped_key,
            epoch=1,
        ),
    )
    _send(
        creator.sock,
        create_group_key_rotation_complete_packet(conversation_id=conversation_id, epoch=1),
    )

    redelivered_packet = _recv_until(
        reconnector.sock,
        lambda p: p.get("type") == "group_key_distribution" and p.get("epoch") == 1,
    )
    assert redelivered_packet is not None
    redelivered_key = reconnector.key_manager.unwrap_received_key(
        redelivered_packet["encapsulation"], redelivered_packet["wrapped_key"]
    )
    reconnector.key_manager.store_key(conversation_id, redelivered_key, epoch=1)

    # Reconnector can decrypt a message that was encrypted (in this
    # test, before the reconnect) using the redelivered key -- proving
    # the "previous messages" case from the bug report.
    decrypted = AESCipher(redelivered_key).decrypt(pre_reconnect_ciphertext)
    assert decrypted == "sent while reconnector was about to drop"


def test_no_literal_session_expired_text_anywhere_in_the_flow(pair):
    """Guards the exact bug report: nothing in this flow ever produces
    auth-expiry wording -- the placeholder (if shown at all, before
    redelivery completes) is the documented, non-alarming one."""
    from client.session import _UNDECRYPTABLE_PLACEHOLDER

    assert "expired" not in _UNDECRYPTABLE_PLACEHOLDER.lower()
    assert "session expired" not in _UNDECRYPTABLE_PLACEHOLDER.lower()


# ----------------------------------------------------------------------
# Direct conversations: locking in the correct (not-a-bug) behavior.
# ----------------------------------------------------------------------


def _make_connected_session(payload):
    """Real ClientSession: connect() -> login() -> send_public_key()
    -> start_receiver() -- required because load_conversation_history()
    now uses send_request() (D4.3), which can only be resolved by a
    running receiver thread reading real socket data."""
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _open_direct_chat(session, partner_username):
    summary = ConversationSummary(
        conversation_id=None, username=partner_username, is_online=True, latest_message=None,
    )
    session.set_current_chat(summary)


def test_direct_history_placeholder_after_restart_is_not_an_auth_error(
    running_server, monkeypatch
):
    """The other half of Issue 4's diagnosis: a direct conversation's
    session key is ephemeral by design, so a fresh ClientSession
    genuinely has no key for it. The correct, tested behavior is the
    existing placeholder -- never an exception, never anything
    resembling an authentication failure. D4.3: this now also proves
    the same for the migrated request/response history path -- a
    genuine server round trip on a real, freshly-reconnected session,
    not just a local decrypt call."""
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sender_payload = _register_user("d_sender_")
    recipient_payload = _register_user("d_recipient_")

    try:
        sender_sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))
        recipient_sock = wrap_client_socket(
            socket.create_connection(("127.0.0.1", port), timeout=3)
        )

        for sock, payload in ((sender_sock, sender_payload), (recipient_sock, recipient_payload)):
            token = _login_and_get_token(payload)
            _send(sock, create_auth_packet(token))
            auth_result = _recv(sock)
            assert auth_result["success"] is True
            _send(
                sock,
                create_public_key_packet(
                    username=auth_result["username"], algorithm="KYBER", public_key="dummy"
                ),
            )

        session_key = b"D" * 32
        ciphertext = AESCipher(session_key).encrypt("a message before the restart")

        _send(
            sender_sock,
            create_chat_packet(
                sender=sender_payload["username"],
                receiver=recipient_payload["username"],
                message=ciphertext,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
        )
        _recv_until(recipient_sock, lambda p: p.get("type") == "chat")

        # Poll for persistence, matching every other integration test's pattern.
        message_repo_db = SessionLocal()
        try:
            message_repo = MessageRepository(message_repo_db)
            for _ in range(100):
                conversation = message_repo.get_conversation(
                    uuid.UUID(sender_payload["user_id"]), uuid.UUID(recipient_payload["user_id"])
                )
                if conversation:
                    break
                time.sleep(0.05)
            assert conversation, "message never persisted"
        finally:
            message_repo_db.close()

        # A brand-new, really-reconnected ClientSession standing in
        # for a full app restart -- no exception must escape, and the
        # result must be the documented placeholder, not an empty
        # list or a crash.
        fresh_session = _make_connected_session(recipient_payload)
        try:
            _open_direct_chat(fresh_session, sender_payload["username"])
            history = fresh_session.load_conversation_history(sender_payload["username"])
        finally:
            fresh_session.disconnect()

        assert len(history) == 1
        assert history[0]["text"] == (
            "Message unavailable (encrypted in a previous session)"
        )
        assert "expired" not in history[0]["text"].lower()
    finally:
        sender_sock.close()
        recipient_sock.close()
        _delete_user(sender_payload["username"])
        _delete_user(recipient_payload["username"])
