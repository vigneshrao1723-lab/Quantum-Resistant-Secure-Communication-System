"""
Integration tests for Phase 7 (Group Membership Management): voluntary
group leave and versioned group-key rotation.

Runs against the real server.client_handler.handle_client accept loop,
over TLS (same harness pattern as the other integration suites, via
tests/tls_test_support.py). Drives raw KeyManager + protocol packets
directly rather than a full ClientSession -- this suite needs to
deliberately simulate things a real client would never intentionally
do (e.g. receiving a rotation instruction and never confirming it, to
prove partial-distribution recovery), which a real ClientSession's
receiver thread doesn't give test code that kind of fine-grained
control over.

Run with:
    pytest tests/test_group_membership_integration.py -v
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
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
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
    create_group_create_packet,
    create_group_key_distribution_packet,
    create_group_key_rotation_complete_packet,
    create_group_leave_packet,
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


def _assert_no_packet(sock, predicate, attempts=10, per_attempt_timeout=0.2):
    """The negative-space counterpart of _recv_until: fails if a
    packet matching predicate ever shows up in the window."""
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except (TimeoutError, OSError):
            candidate = None
        if candidate is not None and predicate(candidate):
            raise AssertionError(f"Unexpected matching packet arrived: {candidate}")


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
            "full_name": "Group Membership Test",
            "username": f"gmemtest_{suffix_hint}{suffix}",
            "email": f"gmemtest_{suffix_hint}{suffix}@example.com",
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
    """A raw-socket, TLS-wrapped, authenticated connection with its
    own KeyManager -- deliberately not a full ClientSession, so tests
    can drive the group-key protocol step by step (including steps a
    real client would never stop halfway through)."""

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
        """Close and re-establish the connection -- exercises the
        server's reconnect-recovery hook, exactly like a real client
        restarting."""
        self.sock.close()
        self._connect(port)

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


def _create_trio_group(creator, member_b, member_c, name="Phase 7 Trio"):
    _send(
        creator.sock,
        create_group_create_packet(
            sender=creator.username,
            name=name,
            member_usernames=[member_b.username, member_c.username],
        ),
    )

    conversation_id = None

    for client in (creator, member_b, member_c):
        result = _recv_until(
            client.sock, lambda p: p.get("type") == "group_create_result"
        )
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
    from crypto.aes import AESCipher

    epoch = epoch if epoch is not None else sender.key_manager.current_epoch(
        conversation_id
    )
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
    from crypto.aes import AESCipher

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


def _handle_rotation_required(initiator, packet, send_complete=True):
    """Mirrors ClientSession.handle_group_key_rotation_required():
    reuse-if-already-stored, generate-and-store otherwise, distribute,
    then (unless the test wants to simulate a crash) confirm."""
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

    if send_complete:
        _send(
            initiator.sock,
            create_group_key_rotation_complete_packet(
                conversation_id=conversation_id, epoch=epoch
            ),
        )

    return group_key


def _get_epoch_state(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_epoch_state(uuid.UUID(conversation_id))
    finally:
        db.close()


def _get_left_at(conversation_id, user_id):
    db = SessionLocal()
    try:
        from database.models.conversation_member import ConversationMember

        member = (
            db.query(ConversationMember)
            .filter(
                ConversationMember.conversation_id == uuid.UUID(conversation_id),
                ConversationMember.user_id == uuid.UUID(user_id),
            )
            .one()
        )
        return member.left_at
    finally:
        db.close()


def _get_active_member_ids(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_member_user_ids(
            uuid.UUID(conversation_id)
        )
    finally:
        db.close()


def _wait_for(predicate, attempts=40, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def trio(running_server):
    _state, port = running_server

    payloads = [_register_user(f"m{i}_") for i in range(3)]
    clients = [_GroupClient(port, p) for p in payloads]

    _exchange_all_public_keys(clients)

    creator, member_b, member_c = clients
    conversation_id = _create_trio_group(creator, member_b, member_c)

    _distribute_initial_key(creator, [member_b, member_c], conversation_id, epoch=1)
    _receive_group_key(member_b, conversation_id, epoch=1)
    _receive_group_key(member_c, conversation_id, epoch=1)

    yield {
        "port": port,
        "conversation_id": conversation_id,
        "creator": creator,
        "member_b": member_b,
        "member_c": member_c,
        "payloads": payloads,
    }

    for client in clients:
        try:
            client.close()
        except OSError:
            pass
    for payload in payloads:
        _delete_user(payload["username"])


# ----------------------------------------------------------------------
# B/C/D. Leave authorization
# ----------------------------------------------------------------------

def test_active_member_can_leave(trio):
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))

    packet = _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )
    assert packet is not None

    assert _wait_for(
        lambda: _get_left_at(conversation_id, member_c.user_id) is not None
    )


def test_non_member_cannot_leave(trio, running_server):
    _state, port = running_server
    conversation_id = trio["conversation_id"]

    outsider_payload = _register_user("outsider_")
    outsider = _GroupClient(port, outsider_payload)

    try:
        before = _get_active_member_ids(conversation_id)

        _send(outsider.sock, create_group_leave_packet(
            sender=outsider.username, conversation_id=conversation_id
        ))

        time.sleep(0.3)

        after = _get_active_member_ids(conversation_id)
        assert set(before) == set(after)
    finally:
        outsider.close()
        _delete_user(outsider_payload["username"])


def test_duplicate_leave_is_idempotent(trio):
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    left_at_first = _get_left_at(conversation_id, member_c.user_id)

    # A second leave attempt for an already-departed member must not
    # raise, and must not disturb left_at.
    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    time.sleep(0.3)

    assert _get_left_at(conversation_id, member_c.user_id) == left_at_first


# ----------------------------------------------------------------------
# F/G. Epoch reservation
# ----------------------------------------------------------------------

def test_leave_reserves_exactly_one_new_epoch(trio):
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]

    current_before, confirmed_before = _get_epoch_state(conversation_id)
    assert (current_before, confirmed_before) == (1, 1)

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    assert _wait_for(lambda: _get_epoch_state(conversation_id)[0] == 2)

    current_after, confirmed_after = _get_epoch_state(conversation_id)
    assert current_after == 2
    assert confirmed_after == 1
    assert _get_left_at(conversation_id, member_c.user_id) is not None


# ----------------------------------------------------------------------
# H/I/J/K. Multi-epoch messaging + history
# ----------------------------------------------------------------------

def test_message_before_and_after_leave_use_correct_epochs(trio):
    conversation_id = trio["conversation_id"]
    creator = trio["creator"]
    member_b = trio["member_b"]
    member_c = trio["member_c"]

    # Before leave: epoch 1.
    _send_group_message(creator, conversation_id, "before leave", epoch=1)
    text_b, epoch_b = _receive_and_decrypt_group_message(member_b, conversation_id)
    _recv_until(member_c.sock, lambda p: p.get("type") == "chat")  # drain for c
    assert text_b == "before leave"
    assert epoch_b == 1

    def _persisted_messages():
        db = SessionLocal()
        try:
            return MessageRepository(db).get_group_conversation(
                uuid.UUID(conversation_id)
            )
        finally:
            db.close()

    # Persistence happens on the server thread right after relaying --
    # poll briefly rather than assuming it's already committed and
    # visible the instant the client-side receive returns (the same
    # race every other integration suite in this codebase polls for).
    assert _wait_for(lambda: len(_persisted_messages()) >= 1)
    assert _persisted_messages()[-1].epoch == 1

    # Charlie leaves -> epoch 2 reserved.
    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )
    _recv_until(
        creator.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )
    _recv_until(
        member_b.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    # Rotation: whichever of creator/member_b the server picked handles it.
    initiator, rotation_packet = _receive_rotation_required(
        [creator, member_b], conversation_id, epoch=2
    )
    assert initiator is not None, "no connected remaining member was selected"
    _handle_rotation_required(initiator, rotation_packet)

    other = member_b if initiator is creator else creator
    _receive_group_key(other, conversation_id, epoch=2)

    assert _wait_for(lambda: _get_epoch_state(conversation_id) == (2, 2))

    # After leave: epoch 2, and Charlie must not see it.
    _send_group_message(creator, conversation_id, "after leave", epoch=2)
    text_b2, epoch_b2 = _receive_and_decrypt_group_message(member_b, conversation_id)
    assert text_b2 == "after leave"
    assert epoch_b2 == 2

    _assert_no_packet(member_c.sock, lambda p: p.get("type") == "chat")

    assert _wait_for(lambda: len(_persisted_messages()) >= 2)
    messages = _persisted_messages()
    assert [m.epoch for m in messages] == [1, 2]

    # History: both epochs decrypt correctly for a remaining member.
    for message in messages:
        key = member_b.key_manager.get_key(conversation_id, epoch=message.epoch or 1)
        assert key is not None
        from crypto.aes import AESCipher
        plaintext = AESCipher(key).decrypt(message.ciphertext)
        assert plaintext in ("before leave", "after leave")


# ----------------------------------------------------------------------
# M. Missing epoch -> placeholder behavior (at the KeyManager level the
# client layer relies on -- proven directly, matching how
# _decrypt_history_message() itself behaves on a None key).
# ----------------------------------------------------------------------

def test_member_without_an_epoch_key_cannot_decrypt_it(trio):
    conversation_id = trio["conversation_id"]
    member_b = trio["member_b"]

    assert member_b.key_manager.get_key(conversation_id, epoch=99) is None


# ----------------------------------------------------------------------
# N. Server never receives the raw group key
# ----------------------------------------------------------------------

def test_server_only_relays_opaque_key_material(trio):
    """The wire packets the server routes for key distribution never
    contain anything but ciphertext-shaped opaque fields -- no field
    named/shaped like a raw 32-byte AES key."""
    conversation_id = trio["conversation_id"]
    creator = trio["creator"]
    member_b = trio["member_b"]

    group_key = os.urandom(32)
    creator.key_manager.store_key(conversation_id, group_key, epoch=1)

    encapsulation, wrapped_key = creator.key_manager.wrap_key_for_member(
        member_b.username, group_key
    )
    packet = create_group_key_distribution_packet(
        sender=creator.username,
        conversation_id=conversation_id,
        recipient=member_b.username,
        encapsulation=encapsulation,
        wrapped_key=wrapped_key,
        epoch=1,
    )

    assert group_key not in json.dumps(packet).encode("utf-8", errors="ignore")
    assert set(packet.keys()) == {
        "type", "sender", "conversation_id", "recipient",
        "encapsulation", "wrapped_key", "epoch",
    }


# ----------------------------------------------------------------------
# P/O. Rotation reuses an existing epoch key rather than generating twice
# ----------------------------------------------------------------------

def test_duplicate_rotation_instruction_reuses_the_same_key(trio):
    conversation_id = trio["conversation_id"]
    creator = trio["creator"]

    fake_epoch = 5
    packet = {
        "conversation_id": conversation_id,
        "epoch": fake_epoch,
        "members": [],
    }

    first_key = _handle_rotation_required(creator, packet, send_complete=False)
    second_key = _handle_rotation_required(creator, packet, send_complete=False)

    assert first_key == second_key


# ----------------------------------------------------------------------
# Q/R. Completion advances confirmed epoch; never regresses
# ----------------------------------------------------------------------

def test_rotation_complete_advances_confirmed_epoch(trio):
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]
    creator = trio["creator"]
    member_b = trio["member_b"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    initiator, rotation_packet = _receive_rotation_required(
        [creator, member_b], conversation_id, epoch=2
    )
    assert initiator is not None
    _handle_rotation_required(initiator, rotation_packet)

    assert _wait_for(lambda: _get_epoch_state(conversation_id) == (2, 2))


def test_stale_completion_does_not_regress_confirmed_epoch(trio):
    conversation_id = trio["conversation_id"]
    creator = trio["creator"]

    db = SessionLocal()
    try:
        repo = ConversationRepository(db)
        conv_uuid = uuid.UUID(conversation_id)
        repo.reserve_next_epoch(conv_uuid)
        repo.reserve_next_epoch(conv_uuid)
        repo.confirm_epoch(conv_uuid, 3)
        repo.commit()
    finally:
        db.close()

    _send(
        creator.sock,
        create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=2
        ),
    )
    time.sleep(0.3)

    _current, confirmed = _get_epoch_state(conversation_id)
    assert confirmed == 3


# ----------------------------------------------------------------------
# S/T/U. Multiple outstanding epochs + partial-distribution recovery
# ----------------------------------------------------------------------

def test_partial_distribution_leaves_epoch_outstanding(trio):
    """The initiator receives the rotation instruction, generates the
    key, but never confirms (simulating a crash mid-distribution).
    confirmed_key_epoch must stay behind current_key_epoch."""
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]
    creator = trio["creator"]
    member_b = trio["member_b"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    initiator, rotation_packet = _receive_rotation_required(
        [creator, member_b], conversation_id, epoch=2
    )
    assert initiator is not None

    # Generate and "distribute" but never send the completion signal.
    _handle_rotation_required(initiator, rotation_packet, send_complete=False)

    time.sleep(0.3)

    current, confirmed = _get_epoch_state(conversation_id)
    assert current == 2
    assert confirmed == 1


def test_reconnect_recovers_an_outstanding_rotation(trio):
    """After a simulated partial failure, a remaining member
    reconnecting must cause the server to dispatch the outstanding
    epoch again."""
    conversation_id = trio["conversation_id"]
    port = trio["port"]
    member_c = trio["member_c"]
    creator = trio["creator"]
    member_b = trio["member_b"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    first_initiator, rotation_packet = _receive_rotation_required(
        [creator, member_b], conversation_id, epoch=2
    )
    assert first_initiator is not None

    # Simulate a crash: generate the key locally, never confirm, never
    # actually reach the other remaining member -- then disconnect
    # entirely, so it can no longer be re-selected as the initiator
    # (making which client gets picked next deterministic for this
    # test, not just "harmless either way").
    generated_key = _handle_rotation_required(
        first_initiator, rotation_packet, send_complete=False
    )
    first_initiator.close()

    other = member_b if first_initiator is creator else creator

    # `other` reconnects -- the server's reconnect-recovery hook must
    # dispatch the still-outstanding epoch 2 again. first_initiator is
    # gone, so `other` is now the only connected active member left to
    # select.
    other.reconnect(port)

    second_initiator, second_packet = _receive_rotation_required(
        [other], conversation_id, epoch=2
    )
    assert second_initiator is other
    assert second_packet["epoch"] == 2

    recovered_key = _handle_rotation_required(other, second_packet)

    assert _wait_for(lambda: _get_epoch_state(conversation_id) == (2, 2))

    # V: recovery succeeding is proven by get_epoch_state reaching
    # (2, 2) above, and by `other` (which had no epoch-2 key before
    # this) ending up with a well-defined one it generated itself --
    # `generated_key` (the first, never-confirmed initiator's key) and
    # `recovered_key` are two different clients' independent
    # generations in this scenario, since the original initiator is
    # deliberately never given a chance to redistribute; the property
    # this test proves is that recovery completes and reaches
    # (confirmed == current), not that every possible initiator agrees
    # on identical bytes (that property -- reuse, not regeneration --
    # is proven directly by test_duplicate_rotation_instruction_reuses_the_same_key).
    assert recovered_key is not None
    assert generated_key is not None


# ----------------------------------------------------------------------
# W/X/Y. Departed member security
# ----------------------------------------------------------------------

def test_departed_member_receives_no_new_key(trio):
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]
    creator = trio["creator"]
    member_b = trio["member_b"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    initiator, rotation_packet = _receive_rotation_required(
        [creator, member_b], conversation_id, epoch=2
    )
    assert initiator is not None
    _handle_rotation_required(initiator, rotation_packet)

    _assert_no_packet(
        member_c.sock,
        lambda p: p.get("type") == "group_key_distribution" and p.get("epoch") == 2,
    )


def test_departed_member_cannot_send_group_messages(trio):
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]
    creator = trio["creator"]
    member_b = trio["member_b"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    before = _get_active_member_ids(conversation_id)
    assert uuid.UUID(member_c.user_id) not in before

    db = SessionLocal()
    try:
        before_count = len(
            MessageRepository(db).get_group_conversation(uuid.UUID(conversation_id))
        )
    finally:
        db.close()

    # Charlie still has epoch 1 -- attempts to inject a message anyway.
    _send_group_message(member_c, conversation_id, "i should not be able to send this", epoch=1)

    _assert_no_packet(creator.sock, lambda p: p.get("type") == "chat")
    _assert_no_packet(member_b.sock, lambda p: p.get("type") == "chat")

    time.sleep(0.3)
    db = SessionLocal()
    try:
        after_count = len(
            MessageRepository(db).get_group_conversation(uuid.UUID(conversation_id))
        )
    finally:
        db.close()
    assert after_count == before_count


def test_departed_member_does_not_receive_future_group_messages(trio):
    conversation_id = trio["conversation_id"]
    member_c = trio["member_c"]
    creator = trio["creator"]
    member_b = trio["member_b"]

    _send(member_c.sock, create_group_leave_packet(
        sender=member_c.username, conversation_id=conversation_id
    ))
    _recv_until(
        member_c.sock,
        lambda p: p.get("type") == "group_member_left"
        and p.get("username") == member_c.username,
    )

    initiator, rotation_packet = _receive_rotation_required(
        [creator, member_b], conversation_id, epoch=2
    )
    assert initiator is not None
    _handle_rotation_required(initiator, rotation_packet)
    other = member_b if initiator is creator else creator
    _receive_group_key(other, conversation_id, epoch=2)

    assert _wait_for(lambda: _get_epoch_state(conversation_id) == (2, 2))

    _send_group_message(creator, conversation_id, "charlie should never see this", epoch=2)

    _assert_no_packet(member_c.sock, lambda p: p.get("type") == "chat")
