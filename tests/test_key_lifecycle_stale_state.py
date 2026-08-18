"""
D6.6 -- Key lifecycle / stale-key handling.

Proves that stale or superseded key material cannot incorrectly
RECEIVE or AUTHORIZE a new group key epoch, using the existing
architecture only -- no new lifecycle is introduced here.

The lifecycle, as it actually exists:

  registration  handle_client() reads the key once during connection
                setup and stores it against the socket; the packet's
                own username field is never read (see
                tests/test_public_key_identity_binding.py).

  reconnect     Every login builds a fresh KeyManager, so every
                reconnect brings a NEW keypair. distribute_public_keys()
                pushes it to all connected peers, and add_public_key()
                overwrites whatever they had cached.

  replacement   Overwrite-on-receipt is the only replacement mechanism;
                there is no mid-session re-registration path (a second
                key_exchange packet in the receive loop is inert).

  rotation      Server-dispatched only. reserve_next_epoch() bumps
                current_key_epoch; confirm_epoch() advances
                confirmed_key_epoch, and only an active member may
                call it.

  leave         leave_conversation() sets left_at, which removes the
                member from get_member_user_ids() immediately.

What this module adds, deliberately narrowed to what is NOT already
covered elsewhere:

  * A departed member cannot AUTHORIZE a new epoch. Existing coverage
    stops at test_group_membership_integration.py::
    test_rotation_complete_advances_confirmed_epoch, which proves only
    the happy path; nothing proved that a member who has left, or a
    user who never joined, cannot advance confirmed_key_epoch. Faking
    that confirmation is not cosmetic: it would convince the server a
    rotation finished, so _dispatch_pending_rotation_if_needed() would
    stop re-dispatching it, and members who never received the new key
    would be stranded on the old epoch permanently.

  * A superseded public key is genuinely replaced on reconnect, so a
    peer cannot keep wrapping to key material the owner no longer
    holds.

Deliberately NOT duplicated here, because it is already covered:
KeyManager's own epoch invariants -- store_key() never overwriting an
epoch, and current_epoch never moving backwards -- are proven in
tests/test_key_manager.py. Receiving a key as a departed member is
proven in tests/test_group_key_distribution_authorization.py (D6.3).

Run with:
    pytest tests/test_key_lifecycle_stale_state.py -v
"""

import json
import socket
import struct
import uuid

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import (
    create_auth_packet,
    create_group_create_packet,
    create_group_key_rotation_complete_packet,
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
            "full_name": "Key Lifecycle Test",
            "username": f"klife_{suffix_hint}{suffix}",
            "email": f"klife_{suffix_hint}{suffix}@example.com",
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

    _send(sock, create_auth_packet(_login_and_get_token(user_payload)))

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


def _epoch_state(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_epoch_state(uuid.UUID(conversation_id))
    finally:
        db.close()


def _barrier(sock):
    """Round-trip on ``sock`` so every packet already sent on it has
    been processed -- each connection is a single sequential receive
    loop, so a later response cannot overtake an earlier packet."""

    request_id = str(uuid.uuid4())

    _send(sock, {"type": "conversation_list_request", "request_id": request_id})

    response = _recv_until(
        sock,
        lambda p: (
            p.get("type") == "conversation_list_result"
            and p.get("request_id") == request_id
        ),
    )

    assert response is not None, "connection must still be alive"

    return response


@pytest.fixture()
def party(running_server):
    """Three group members plus one authenticated non-member."""

    _state, port = running_server

    payloads = [_register_user(f"p{index}_") for index in range(4)]
    connections = [_connect_and_authenticate(port, payload) for payload in payloads]

    people = [
        {"sock": sock, "username": username, "user_id": payload["user_id"]}
        for (sock, username), payload in zip(connections, payloads)
    ]

    yield {"port": port, "members": people[:3], "outsider": people[3]}

    for sock, _username in connections:
        sock.close()

    for payload in payloads:
        _delete_user(payload["username"])


def _create_group(party, name="Key Lifecycle Group"):
    creator, member_b, member_c = party["members"]

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name=name,
            member_usernames=[member_b["username"], member_c["username"]],
        ),
    )

    results = [
        _recv_until(person["sock"], lambda p: p.get("type") == "group_create_result")
        for person in party["members"]
    ]

    for result in results:
        assert result is not None

    return results[0]["conversation_id"]


def _leave_group(person, conversation_id):
    _send(
        person["sock"],
        create_group_leave_packet(
            sender=person["username"], conversation_id=conversation_id
        ),
    )

    confirmed = _recv_until(
        person["sock"],
        lambda p: (
            p.get("type") == "group_member_left"
            and p.get("username") == person["username"]
        ),
    )

    assert confirmed is not None, "the leave must be server-confirmed"


# ----------------------------------------------------------------------
# Stale membership must not be able to AUTHORIZE a new epoch
# ----------------------------------------------------------------------

def test_departed_member_cannot_advance_confirmed_epoch(party):
    """
    A member who has left still holds the old epoch's key material.
    They must not be able to claim a rotation completed: doing so would
    stop the server re-dispatching it, stranding members who never
    received the new key.
    """

    conversation_id = _create_group(party)
    _creator, _member_b, member_c = party["members"]

    _leave_group(member_c, conversation_id)

    current_epoch, confirmed_before = _epoch_state(conversation_id)

    assert current_epoch > confirmed_before, (
        "leaving must reserve a new, not-yet-confirmed epoch"
    )

    # The departed member forges the confirmation.
    _send(
        member_c["sock"],
        create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=current_epoch
        ),
    )

    _barrier(member_c["sock"])

    _current_after, confirmed_after = _epoch_state(conversation_id)

    assert confirmed_after == confirmed_before, (
        "a departed member must not advance confirmed_key_epoch"
    )


def test_non_member_cannot_advance_confirmed_epoch(party):
    """The same property for a user who never joined at all."""

    conversation_id = _create_group(party)
    _creator, _member_b, member_c = party["members"]
    outsider = party["outsider"]

    _leave_group(member_c, conversation_id)

    current_epoch, confirmed_before = _epoch_state(conversation_id)

    _send(
        outsider["sock"],
        create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=current_epoch
        ),
    )

    _barrier(outsider["sock"])

    _current_after, confirmed_after = _epoch_state(conversation_id)

    assert confirmed_after == confirmed_before, (
        "a non-member must not advance confirmed_key_epoch"
    )


def test_active_member_can_still_advance_confirmed_epoch(party):
    """
    The positive control for the two rejections above: the mechanism
    itself must still work, otherwise the tests above would pass for
    the wrong reason.
    """

    conversation_id = _create_group(party)
    creator, _member_b, member_c = party["members"]

    _leave_group(member_c, conversation_id)

    current_epoch, confirmed_before = _epoch_state(conversation_id)

    assert current_epoch > confirmed_before

    _send(
        creator["sock"],
        create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=current_epoch
        ),
    )

    _barrier(creator["sock"])

    _current_after, confirmed_after = _epoch_state(conversation_id)

    assert confirmed_after == current_epoch, (
        "an active member must still be able to confirm a rotation"
    )


def test_stale_epoch_confirmation_cannot_regress_state(party):
    """
    confirm_epoch() guards with max(), so even a legitimate but stale
    confirmation (a delayed retry naming an older epoch) cannot move
    confirmed_key_epoch backwards.
    """

    conversation_id = _create_group(party)
    creator, member_b, member_c = party["members"]

    _leave_group(member_c, conversation_id)

    current_epoch, _confirmed = _epoch_state(conversation_id)

    _send(
        creator["sock"],
        create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=current_epoch
        ),
    )
    _barrier(creator["sock"])

    _current, confirmed_high = _epoch_state(conversation_id)
    assert confirmed_high == current_epoch

    # A stale confirmation for epoch 1 arriving late.
    _send(
        member_b["sock"],
        create_group_key_rotation_complete_packet(
            conversation_id=conversation_id, epoch=1
        ),
    )
    _barrier(member_b["sock"])

    _current_after, confirmed_after = _epoch_state(conversation_id)

    assert confirmed_after == confirmed_high, (
        "a stale confirmation must not regress confirmed_key_epoch"
    )


# ----------------------------------------------------------------------
# Superseded public key must actually be replaced
# ----------------------------------------------------------------------

def test_reconnect_replaces_the_servers_cached_public_key(running_server):
    """
    Every login builds a fresh KeyManager, so a reconnect always brings
    a new keypair. The server's per-connection record must carry the
    NEW key -- a peer that kept wrapping to the old one would produce
    key material the owner can no longer unwrap.
    """

    state, port = running_server

    payload = _register_user("rekey_")

    first_sock = wrap_client_socket(
        socket.create_connection(("127.0.0.1", port), timeout=3)
    )
    _send(first_sock, create_auth_packet(_login_and_get_token(payload)))
    auth_result = _recv(first_sock)
    assert auth_result["success"] is True
    username = auth_result["username"]

    _send(
        first_sock,
        create_public_key_packet(
            username=username, algorithm="KYBER", public_key="ORIGINAL-KEY"
        ),
    )
    _barrier(first_sock)

    assert _cached_key_for(state, username) == "ORIGINAL-KEY"

    first_sock.close()

    # Reconnect with different key material, as a fresh KeyManager
    # would produce. The replacement must be the FIRST key_exchange
    # packet on the new connection -- that is the only registration
    # point; a later one would be inert (see
    # tests/test_public_key_identity_binding.py).
    second_sock = wrap_client_socket(
        socket.create_connection(("127.0.0.1", port), timeout=3)
    )
    _send(second_sock, create_auth_packet(_login_and_get_token(payload)))
    second_auth = _recv(second_sock)
    assert second_auth["success"] is True

    _send(
        second_sock,
        create_public_key_packet(
            username=username, algorithm="KYBER", public_key="REPLACEMENT-KEY"
        ),
    )
    _barrier(second_sock)

    cached = _cached_key_for(state, username)

    assert cached == "REPLACEMENT-KEY", (
        "the reconnected session must carry the new key, not the stale one"
    )

    second_sock.close()
    _delete_user(payload["username"])


def _cached_key_for(state, username):
    """The public key the server currently holds for a username, across
    whichever connections are live."""

    for client in list(state.clients.values()):
        if client["username"] == username and client["public_key"] is not None:
            return client["public_key"]

    return None
