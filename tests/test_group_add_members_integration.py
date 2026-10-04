"""
Integration tests for Issue 2 (real-application testing bug report):
Add Members After Group Creation.

Runs against the real server.client_handler.handle_client accept loop
over TLS -- same harness pattern as test_group_membership_integration.py,
including its raw-socket _GroupClient class (duplicated here rather
than imported, matching this codebase's established per-file
convention) so these tests can drive the group_add_members protocol
and the reused key-rotation machinery step by step.

Design under test (see the diagnosis given before implementation):
adding a member reuses Phase 7's epoch-rotation mechanism exactly --
reserve_next_epoch(), _dispatch_pending_rotation_if_needed(),
handle_group_key_rotation_required() are all unchanged. Consequence:
the new member gets only the new epoch's key (cannot read history from
before they joined); existing members keep their old epoch key (their
own history stays readable) and also get the new one.

Run with:
    pytest tests/test_group_add_members_integration.py -v
"""

import json
import os
import socket
import struct
import time
import uuid
from datetime import datetime, timezone

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import (
    create_auth_packet,
    create_group_add_members_packet,
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
            "full_name": "Add Members Test",
            "username": f"addmem_{suffix_hint}{suffix}",
            "email": f"addmem_{suffix_hint}{suffix}@example.com",
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


class _GroupClient:
    """See test_group_membership_integration.py's identical class for
    the full rationale -- duplicated per this codebase's convention."""

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

    def close(self):
        self.sock.close()


def _exchange_all_public_keys(clients):
    for client in clients:
        for other in clients:
            if other is client:
                continue
            packet = _recv_until(
                client.sock,
                lambda p, other=other: (
                    p.get("type") == "key_exchange"
                    and p.get("username") == other.username
                ),
            )
            assert packet is not None, (
                f"{client.username} never received {other.username}'s public key"
            )
            client.key_manager.add_public_key(other.username, packet["public_key"])


def _create_group(creator, other_members, name="Add Members Trio"):
    _send(
        creator.sock,
        create_group_create_packet(
            sender=creator.username,
            name=name,
            member_usernames=[m.username for m in other_members],
        ),
    )

    conversation_id = None

    for client in (creator, *other_members):
        result = _recv_until(client.sock, lambda p: p.get("type") == "group_create_result")
        assert result is not None
        conversation_id = result["conversation_id"]

    return conversation_id


def _distribute_initial_key(creator, members, conversation_id, epoch=1):
    group_key = os.urandom(32)
    creator.key_manager.store_key(conversation_id, group_key, epoch=epoch)

    for member in members:
        encapsulation, wrapped_key = creator.key_manager.wrap_key_for_member(
            member.username, group_key
        )
        _send(
            creator.sock,
            create_group_key_distribution_packet(
                sender=creator.username,
                conversation_id=conversation_id,
                recipient=member.username,
                encapsulation=encapsulation,
                wrapped_key=wrapped_key,
                epoch=epoch,
            ),
        )

    return group_key


def _receive_group_key(member, conversation_id, epoch=1):
    packet = _recv_until(
        member.sock,
        lambda p: (
            p.get("type") == "group_key_distribution"
            and p.get("recipient") == member.username
            and p.get("epoch") == epoch
        ),
    )
    assert packet is not None, (
        f"{member.username} never received epoch {epoch} for {conversation_id}"
    )
    group_key = member.key_manager.unwrap_received_key(
        packet["encapsulation"], packet["wrapped_key"]
    )
    member.key_manager.store_key(conversation_id, group_key, epoch=epoch)
    return group_key


def _send_group_message(sender, conversation_id, plaintext, epoch=None):
    epoch = epoch if epoch is not None else sender.key_manager.current_epoch(conversation_id)
    key = sender.key_manager.get_key(conversation_id, epoch=epoch)
    ciphertext = AESCipher(key).encrypt(plaintext)

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT, ciphertext=ciphertext, content_metadata={}
    )

    _send(
        sender.sock,
        create_payload_packet(
            sender=sender.username,
            envelope=envelope,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id=conversation_id,
            epoch=epoch,
        ),
    )


def _receive_and_decrypt_group_message(recipient, conversation_id):
    packet = _recv_until(recipient.sock, lambda p: p.get("type") == "chat")
    assert packet is not None
    epoch = packet.get("epoch") or 1
    key = recipient.key_manager.get_key(conversation_id, epoch=epoch)
    assert key is not None, f"{recipient.username} has no key for epoch {epoch}"
    return AESCipher(key).decrypt(packet["message"]), epoch


def _receive_rotation_required(candidates, conversation_id, epoch, attempts=15):
    for candidate in candidates:
        packet = _recv_until(
            candidate.sock,
            lambda p: (
                p.get("type") == "group_key_rotation_required"
                and p.get("conversation_id") == conversation_id
                and p.get("epoch") == epoch
            ),
            attempts=attempts,
            per_attempt_timeout=0.2,
        )
        if packet is not None:
            return candidate, packet
    return None, None


def _handle_rotation_required(initiator, packet):
    """Mirrors ClientSession.handle_group_key_rotation_required()."""
    conversation_id = packet["conversation_id"]
    epoch = packet["epoch"]
    recipients = [m for m in packet.get("members", []) if m != initiator.username]

    if initiator.key_manager.has_key(conversation_id, epoch=epoch):
        group_key = initiator.key_manager.get_key(conversation_id, epoch=epoch)
    else:
        group_key = os.urandom(32)
        initiator.key_manager.store_key(conversation_id, group_key, epoch=epoch)

    for member in recipients:
        encapsulation, wrapped_key = initiator.key_manager.wrap_key_for_member(
            member, group_key
        )
        _send(
            initiator.sock,
            create_group_key_distribution_packet(
                sender=initiator.username,
                conversation_id=conversation_id,
                recipient=member,
                encapsulation=encapsulation,
                wrapped_key=wrapped_key,
                epoch=epoch,
            ),
        )

    _send(
        initiator.sock,
        create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=epoch
        ),
    )

    return group_key


def _get_active_member_ids(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_member_user_ids(uuid.UUID(conversation_id))
    finally:
        db.close()


def _get_epoch_state(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_epoch_state(uuid.UUID(conversation_id))
    finally:
        db.close()


def _wait_for_confirmed_epoch(conversation_id, expected_epoch, attempts=60):
    """group_key_rotation_complete is sent fire-and-forget by the test
    helper -- the server processes and commits it asynchronously, on
    its own connection thread. Poll rather than assume it has already
    landed by the time this returns, mirroring every other
    persistence-polling helper in this codebase's integration suites."""
    for _ in range(attempts):
        current, confirmed = _get_epoch_state(conversation_id)
        if confirmed == expected_epoch:
            return current, confirmed
        time.sleep(0.05)
    return _get_epoch_state(conversation_id)


@pytest.fixture()
def trio_and_candidate(running_server):
    """A 3-member group (creator, member_b, member_c) plus a 4th
    registered+connected user (candidate) who is NOT yet a member --
    the target of the add-members flow under test."""
    _state, port = running_server

    payloads = [_register_user(f"m{i}_") for i in range(4)]
    clients = [_GroupClient(port, p) for p in payloads]

    _exchange_all_public_keys(clients)

    creator, member_b, member_c, candidate = clients
    conversation_id = _create_group(creator, [member_b, member_c])

    _distribute_initial_key(creator, [member_b, member_c], conversation_id, epoch=1)
    _receive_group_key(member_b, conversation_id, epoch=1)
    _receive_group_key(member_c, conversation_id, epoch=1)

    yield {
        "port": port,
        "conversation_id": conversation_id,
        "creator": creator,
        "member_b": member_b,
        "member_c": member_c,
        "candidate": candidate,
        "payloads": payloads,
    }

    for client in clients:
        try:
            client.close()
        except OSError:
            pass
    for payload in payloads:
        _delete_user(payload["username"])


def _do_add_member(fixture):
    """Runs the full add-members flow: creator requests the add,
    everyone gets group_members_added, the server dispatches a
    rotation, some connected existing member (or the candidate --
    _select_connected_active_member has no preference) fulfils it, and
    the new member receives the new epoch's key. Returns the new
    epoch number."""
    creator = fixture["creator"]
    member_b = fixture["member_b"]
    member_c = fixture["member_c"]
    candidate = fixture["candidate"]
    conversation_id = fixture["conversation_id"]

    _send(
        creator.sock,
        create_group_add_members_packet(
            sender=creator.username,
            conversation_id=conversation_id,
            member_usernames=[candidate.username],
        ),
    )

    all_four = (creator, member_b, member_c, candidate)
    for client in all_four:
        added_packet = _recv_until(
            client.sock, lambda p: p.get("type") == "group_members_added"
        )
        assert added_packet is not None, f"{client.username} never got group_members_added"
        assert set(added_packet["members"]) == {c.username for c in all_four}

    new_epoch = 2

    initiator, rotation_packet = _receive_rotation_required(
        [creator, member_b, member_c, candidate], conversation_id, new_epoch
    )
    assert initiator is not None, "nobody was dispatched the new epoch"

    _handle_rotation_required(initiator, rotation_packet)

    for client in all_four:
        if client is initiator:
            continue
        if client.username not in rotation_packet.get("members", []):
            continue
        _receive_group_key(client, conversation_id, epoch=new_epoch)

    return new_epoch


def test_add_member_delivers_group_members_added_to_everyone(trio_and_candidate):
    _do_add_member(trio_and_candidate)


def test_new_member_persists_in_membership(trio_and_candidate):
    fixture = trio_and_candidate
    _do_add_member(fixture)

    member_ids = _get_active_member_ids(fixture["conversation_id"])
    assert uuid.UUID(fixture["candidate"].user_id) in member_ids
    assert len(member_ids) == 4


def test_epoch_is_bumped_exactly_once_by_an_add(trio_and_candidate):
    fixture = trio_and_candidate
    _do_add_member(fixture)

    current, confirmed = _wait_for_confirmed_epoch(fixture["conversation_id"], 2)
    assert current == 2
    assert confirmed == 2


def test_new_member_can_send_and_be_understood_by_old_members(trio_and_candidate):
    fixture = trio_and_candidate
    epoch = _do_add_member(fixture)

    candidate = fixture["candidate"]
    member_b = fixture["member_b"]
    conversation_id = fixture["conversation_id"]

    _send_group_message(candidate, conversation_id, "hello from the new member", epoch=epoch)

    text, received_epoch = _receive_and_decrypt_group_message(member_b, conversation_id)
    assert text == "hello from the new member"
    assert received_epoch == epoch


def test_old_members_can_still_communicate_after_add(trio_and_candidate):
    fixture = trio_and_candidate
    epoch = _do_add_member(fixture)

    creator = fixture["creator"]
    member_b = fixture["member_b"]
    member_c = fixture["member_c"]
    candidate = fixture["candidate"]
    conversation_id = fixture["conversation_id"]

    _send_group_message(creator, conversation_id, "still talking fine", epoch=epoch)

    for recipient in (member_b, member_c, candidate):
        text, _epoch = _receive_and_decrypt_group_message(recipient, conversation_id)
        assert text == "still talking fine"


def test_old_members_retain_pre_add_history_key(trio_and_candidate):
    """Security property: existing members must not lose access to
    their own pre-add history just because a rotation happened."""
    fixture = trio_and_candidate
    creator = fixture["creator"]
    member_b = fixture["member_b"]
    conversation_id = fixture["conversation_id"]

    pre_add_key = creator.key_manager.get_key(conversation_id, epoch=1)

    _do_add_member(fixture)

    # member_b must still hold the epoch-1 key after the rotation.
    assert member_b.key_manager.get_key(conversation_id, epoch=1) == pre_add_key


def test_new_member_cannot_decrypt_pre_add_history(trio_and_candidate):
    """The core security property of reusing epoch rotation for adds:
    a newly added member never received epoch 1's key, so a message
    encrypted before they joined must remain out of reach for them --
    mirrors Phase 7's departed-member guarantee, inverted for joining."""
    fixture = trio_and_candidate
    candidate = fixture["candidate"]
    conversation_id = fixture["conversation_id"]

    _do_add_member(fixture)

    assert candidate.key_manager.get_key(conversation_id, epoch=1) is None


def test_non_member_cannot_add_members(trio_and_candidate):
    """Security: only an active member may request an add."""
    fixture = trio_and_candidate
    candidate = fixture["candidate"]
    conversation_id = fixture["conversation_id"]

    # candidate is not yet a member -- their own add request must be
    # silently rejected, not grant them membership as a side effect.
    _send(
        candidate.sock,
        create_group_add_members_packet(
            sender=candidate.username,
            conversation_id=conversation_id,
            member_usernames=[candidate.username],
        ),
    )

    added_packet = _recv_until(
        candidate.sock, lambda p: p.get("type") == "group_members_added", attempts=10
    )
    assert added_packet is None

    member_ids = _get_active_member_ids(conversation_id)
    assert uuid.UUID(candidate.user_id) not in member_ids
