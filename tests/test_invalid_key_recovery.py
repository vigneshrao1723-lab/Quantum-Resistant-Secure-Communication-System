"""
D6.7 -- Invalid-key recovery verification.

Integration-level proof, using real sockets, a real ClientSession
distribution path, and real ML-KEM key material, that a member whose
public key is unusable degrades gracefully and can recover -- through
the mechanisms that already exist, with no new recovery path added.

Three ways a member's key can be unusable, and how each arises:

  missing    The member was never online while this client was, so
             distribute_public_keys() never delivered their key.
             get_public_key() returns None.

  malformed  The member's key material fails validation. Since D6.5
             this is rejected at import by handle_public_key(), so it
             collapses into the "missing" case -- nothing is cached.
             The behaviour under test is that the rejection leaves no
             partial state and does not disturb other members.

  stale      The member reconnected with a fresh KeyManager, so the
             key this client still holds belongs to a keypair the
             member no longer has. Wrapping to it produces material
             they cannot unwrap.

For each, this module verifies the four properties required of the
recovery path:

  1. distribution to valid members continues
  2. the affected member does not receive incorrectly wrapped key
     material
  3. the member recovers via the existing reconnect /
     key-registration / rotation mechanism
  4. the group is consistent afterwards -- every member holding the
     same epoch key, able to decrypt the same traffic

Run with:
    pytest tests/test_invalid_key_recovery.py -v
"""

import base64
import json
import os
import socket
import struct
import uuid

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.aes import AESCipher
from crypto.key_manager import KeyManager
from crypto.kyber import ML_KEM_768_PUBLIC_KEY_BYTES
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import (
    create_auth_packet,
    create_group_create_packet,
    create_group_leave_packet,
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
        except TimeoutError:
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
            "full_name": "Invalid Key Recovery Test",
            "username": f"ikrec_{suffix_hint}{suffix}",
            "email": f"ikrec_{suffix_hint}{suffix}@example.com",
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
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


class _GroupClient:
    """A real socket plus a real KeyManager. Mirrors
    test_group_history_reconnect_recovery.py's identical class --
    duplicated per this codebase's per-file harness convention."""

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
        _send(self.sock, create_auth_packet(_login_and_get_token(self._payload)))
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
        """Close and reconnect with a BRAND NEW KeyManager -- exactly
        what an application restart looks like."""
        self.sock.close()
        self.key_manager = KeyManager()
        self._connect(port)

    def learn_key_of(self, other_username):
        """Consume the peer's public key from the wire and cache it."""
        packet = _recv_until(
            self.sock,
            lambda p: (
                p.get("type") == "key_exchange"
                and p.get("operation") == "public_key"
                and p.get("username") == other_username
            ),
        )
        assert packet is not None, f"never received {other_username}'s public key"
        self.key_manager.add_public_key(other_username, packet["public_key"])
        return packet["public_key"]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _distributor_session(client):
    """A real ClientSession wired to this client's socket and
    KeyManager, so _distribute_group_key() runs for real."""

    session = ClientSession()
    session.username = client.username
    session.client_socket = client.sock
    session.key_manager = client.key_manager

    return session


@pytest.fixture()
def trio(running_server):
    """Three real group members with fully exchanged public keys."""

    _state, port = running_server

    payloads = [_register_user(f"m{index}_") for index in range(3)]
    clients = [_GroupClient(port, payload) for payload in payloads]

    distributor, healthy, affected = clients

    # Full mesh key exchange.
    distributor.learn_key_of(healthy.username)
    distributor.learn_key_of(affected.username)
    healthy.learn_key_of(distributor.username)
    affected.learn_key_of(distributor.username)

    _send(
        distributor.sock,
        create_group_create_packet(
            sender=distributor.username,
            name="Invalid Key Recovery Group",
            member_usernames=[healthy.username, affected.username],
        ),
    )

    conversation_id = None
    for client in clients:
        result = _recv_until(
            client.sock, lambda p: p.get("type") == "group_create_result"
        )
        assert result is not None
        conversation_id = result["conversation_id"]

    yield {
        "port": port,
        "conversation_id": conversation_id,
        "distributor": distributor,
        "healthy": healthy,
        "affected": affected,
        "payloads": payloads,
    }

    for client in clients:
        client.close()
    for payload in payloads:
        _delete_user(payload["username"])


def _distribute(trio, group_key, epoch=1):
    """Run the real distribution path for both non-distributor members."""

    distributor = trio["distributor"]
    session = _distributor_session(distributor)

    distributor.key_manager.store_key(trio["conversation_id"], group_key, epoch=epoch)

    session._distribute_group_key(
        trio["conversation_id"],
        group_key,
        epoch,
        [trio["healthy"].username, trio["affected"].username],
    )


def _receive_group_key(client, conversation_id, epoch):
    """Wait for a group key delivery and unwrap it. Returns the key, or
    None if nothing arrived."""

    packet = _recv_until(
        client.sock,
        lambda p: (
            p.get("type") == "group_key_distribution" and p.get("epoch") == epoch
        ),
        attempts=12,
    )

    if packet is None:
        return None

    key = client.key_manager.unwrap_received_key(
        packet["encapsulation"], packet["wrapped_key"]
    )
    client.key_manager.store_key(conversation_id, key, epoch=epoch)

    return key


# ----------------------------------------------------------------------
# 1. Missing public key
# ----------------------------------------------------------------------

def test_missing_key_member_is_skipped_and_others_still_served(trio):
    """Properties 1 and 2 for the missing-key case."""

    distributor = trio["distributor"]
    affected = trio["affected"]

    # Simulate "never learned this member's key".
    distributor.key_manager.public_keys.pop(affected.username, None)
    assert distributor.key_manager.get_public_key(affected.username) is None

    group_key = os.urandom(32)
    _distribute(trio, group_key, epoch=1)

    assert _receive_group_key(trio["healthy"], trio["conversation_id"], 1) == group_key
    assert _receive_group_key(affected, trio["conversation_id"], 1) is None


# ----------------------------------------------------------------------
# 2. Malformed public key
# ----------------------------------------------------------------------

def test_malformed_key_is_rejected_and_leaves_no_partial_state(trio):
    """
    D6.5 rejects malformed key material at import, so it never becomes
    cached state. The malformed key must also not destroy the good key
    already held for that member.
    """

    distributor = trio["distributor"]
    affected = trio["affected"]

    good_key = distributor.key_manager.get_public_key(affected.username)
    assert good_key is not None

    with pytest.raises(ValueError):
        distributor.key_manager.add_public_key(affected.username, "!!!!")

    assert distributor.key_manager.get_public_key(affected.username) == good_key, (
        "a rejected key must not disturb the working one"
    )


def test_right_length_invalid_key_does_not_block_other_members(trio):
    """
    The case that survives D6.5: a key of exactly the right length
    whose contents are not a valid encapsulation key passes import and
    fails inside ML-KEM during wrapping. Distribution to the healthy
    member must still complete (property 1), and the affected member
    must receive nothing (property 2).
    """

    distributor = trio["distributor"]
    affected = trio["affected"]

    plausible_but_invalid = base64.b64encode(
        os.urandom(ML_KEM_768_PUBLIC_KEY_BYTES)
    ).decode("ascii")

    distributor.key_manager.add_public_key(affected.username, plausible_but_invalid)

    group_key = os.urandom(32)
    _distribute(trio, group_key, epoch=1)

    assert _receive_group_key(trio["healthy"], trio["conversation_id"], 1) == group_key
    assert _receive_group_key(affected, trio["conversation_id"], 1) is None


# ----------------------------------------------------------------------
# 3. Stale public key
# ----------------------------------------------------------------------

def test_stale_key_produces_material_the_owner_cannot_unwrap(trio):
    """
    Establishes precisely why a stale key is a problem, so the recovery
    test below is meaningful: wrapping to a superseded key yields
    material the member cannot unwrap with their current keypair.

    Note which layer actually catches it. ML-KEM decapsulation with the
    wrong decapsulation key does NOT raise -- implicit rejection is a
    deliberate KEM property, and it returns a different shared secret
    instead. The mismatch is caught one layer up, by AES-256-GCM's
    authentication tag in the KEM-then-DEM composition, as a
    ValueError. Asserting the specific error keeps this test honest:
    it proves the failure is detected by authenticated encryption,
    not merely that "something went wrong".
    """

    distributor = trio["distributor"]
    affected = trio["affected"]
    conversation_id = trio["conversation_id"]

    stale_key_bytes = distributor.key_manager.get_public_key(affected.username)

    # The member rotates their keypair, as any restart would do.
    affected.key_manager = KeyManager()

    group_key = os.urandom(32)
    distributor.key_manager.store_key(conversation_id, group_key, epoch=1)

    encapsulation, wrapped_key = distributor.key_manager.wrap_key_for_member(
        affected.username, group_key
    )

    assert distributor.key_manager.get_public_key(affected.username) == stale_key_bytes

    # The member's NEW private key cannot recover a key wrapped to the
    # old public key -- and the attempt is rejected, never silently
    # yielding wrong key material.
    with pytest.raises(ValueError, match="authentication failed"):
        affected.key_manager.unwrap_received_key(encapsulation, wrapped_key)


def test_reconnect_replaces_stale_key_and_restores_consistency(trio):
    """
    Properties 3 and 4: the affected member recovers through the
    EXISTING mechanism -- reconnect re-registers a fresh public key,
    distribute_public_keys() pushes it to the still-connected
    distributor, and a redistribution then succeeds -- after which the
    whole group holds the same epoch key and can decrypt the same
    traffic.
    """

    distributor = trio["distributor"]
    healthy = trio["healthy"]
    affected = trio["affected"]
    conversation_id = trio["conversation_id"]

    stale = distributor.key_manager.get_public_key(affected.username)

    # The member restarts: brand-new KeyManager, brand-new keypair.
    affected.reconnect(trio["port"])

    # Existing mechanism: the reconnecting client's key is pushed to
    # every already-connected peer.
    refreshed = distributor.learn_key_of(affected.username)

    assert distributor.key_manager.get_public_key(affected.username) != stale, (
        "reconnect must replace the stale key, not append to it"
    )
    assert refreshed

    # Redistribute the current epoch to everyone.
    group_key = os.urandom(32)
    _distribute(trio, group_key, epoch=1)

    healthy_key = _receive_group_key(healthy, conversation_id, 1)
    affected_key = _receive_group_key(affected, conversation_id, 1)

    assert healthy_key == group_key
    assert affected_key == group_key, (
        "after recovery the member must unwrap the SAME group key"
    )

    # Property 4: group consistency -- one epoch, one key, everyone can
    # read the same ciphertext.
    ciphertext = AESCipher(
        distributor.key_manager.get_key(conversation_id, epoch=1)
    ).encrypt("post-recovery group message")

    for client in (healthy, affected):
        assert AESCipher(
            client.key_manager.get_key(conversation_id, epoch=1)
        ).decrypt(ciphertext) == "post-recovery group message"


def test_recovered_member_receives_a_later_epoch_normally(trio):
    """
    Recovery must not leave the member in a special state: once their
    key is refreshed they take part in subsequent epochs like anyone
    else.

    Epoch 2 is reserved the way production reserves it -- a member
    leaves, which bumps the conversation's current_key_epoch -- rather
    than simply stamping a higher number on a distribution. The server
    now bounds the epoch by what it has actually reserved (see
    tests/test_group_key_distribution_authorization.py::
    test_member_cannot_distribute_an_epoch_beyond_the_reserved_one), so
    an unreserved epoch 2 would be correctly refused.
    """

    distributor = trio["distributor"]
    healthy = trio["healthy"]
    affected = trio["affected"]
    conversation_id = trio["conversation_id"]

    affected.reconnect(trio["port"])
    distributor.learn_key_of(affected.username)

    epoch_one_key = os.urandom(32)
    _distribute(trio, epoch_one_key, epoch=1)

    assert _receive_group_key(affected, conversation_id, 1) == epoch_one_key

    # Reserve epoch 2 legitimately: a leave bumps current_key_epoch.
    _send(
        healthy.sock,
        create_group_leave_packet(
            sender=healthy.username, conversation_id=conversation_id
        ),
    )
    assert _recv_until(
        healthy.sock,
        lambda p: (
            p.get("type") == "group_member_left"
            and p.get("username") == healthy.username
        ),
    ) is not None, "the leave must be server-confirmed before epoch 2 is used"

    epoch_two_key = os.urandom(32)
    _distribute(trio, epoch_two_key, epoch=2)

    assert _receive_group_key(affected, conversation_id, 2) == epoch_two_key

    # Both epochs coexist, so pre-rotation history stays readable.
    assert affected.key_manager.get_key(conversation_id, epoch=1) == epoch_one_key
    assert affected.key_manager.get_key(conversation_id, epoch=2) == epoch_two_key
    assert affected.key_manager.current_epoch(conversation_id) == 2
