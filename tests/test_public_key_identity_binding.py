"""
Characterization tests for public-key identity binding (D6).

These lock down a security property the current implementation ALREADY
has. They are not a new trust architecture, and they add no PKI,
certificates, or fingerprints -- the D6.4 audit established that the
existing binding is sound and that key substitution is not reachable by
an authenticated client. What was missing was any test proving it, so a
future refactor could have quietly reintroduced the flaw.

The property:

    A client's public key is bound to the identity the SERVER
    authenticated for that connection, never to any identity the
    client asserts in the packet.

Concretely, server/client_handler.py reads only ``algorithm`` and
``public_key`` from the key_exchange packet -- the ``username`` field
create_public_key_packet() includes is never read. ServerState.
set_public_key() stores the key against the socket, and
server/broadcaster.py::distribute_public_keys() re-labels it on the way
out with client["username"], which came from the JWT validated at
authenticate_connection() time.

The two tests below correspond to the two properties confirmed by the
audit:

  1. A user authenticated as A cannot register a key that peers file
     under user B -- peers always see it under A.

  2. A public-key packet sent AFTER authentication (i.e. in the main
     receive loop rather than during connection setup) can legitimately
     update the SENDER's own key (Phase 16D -- Multi-Device Security
     Hardening added a live re-broadcast handler, used by
     ClientSession.enroll_device() to attach device_id to a device-
     aware client's identity once it becomes known, which happens after
     the original bootstrap broadcast already fired -- see server/
     client_handler.py's own "Public Key Re-broadcast" comment). What
     is NOT possible, before or after that addition, is using it to
     rebind a DIFFERENT identity: ServerState.set_public_key() is keyed
     by socket and distribute_public_keys() re-labels the outgoing
     packet with client["username"] from the JWT-authenticated
     connection state -- the packet's own claimed ``username`` field is
     still never read by either. A post-authentication packet claiming
     to belong to someone else therefore still updates (and is still
     only ever relayed under) the AUTHENTICATED sender's own identity,
     never the claimed one.

Run with:
    pytest tests/test_public_key_identity_binding.py -v
"""

import json
import socket
import struct
import uuid

import pytest

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.tls_test_support import (
    start_test_server,
    wrap_client_socket,
)
from utils.protocol import create_auth_packet, create_public_key_packet


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
            "full_name": "Key Binding Test",
            "username": f"pkbind_{suffix_hint}{suffix}",
            "email": f"pkbind_{suffix_hint}{suffix}@example.com",
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


def _authenticate(port, payload):
    """Connect + authenticate only -- the public key is sent by the test
    itself, since what it contains is exactly what is under test."""

    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))

    _send(sock, create_auth_packet(_login_and_get_token(payload)))

    auth_result = _recv(sock)
    assert auth_result["success"] is True, auth_result

    return sock, auth_result["username"]


@pytest.fixture()
def two_users(running_server):
    state, port = running_server

    payloads = [_register_user("a_"), _register_user("b_")]

    yield {"port": port, "payloads": payloads, "server_state": state}

    for payload in payloads:
        _delete_user(payload["username"])


def _server_keys_by_username(state):
    """The server's own view: which public key is filed under which
    authenticated username."""

    return {
        client["username"]: client["public_key"]
        for client in list(state.clients.values())
    }


def _await_public_key_for(sock, username):
    return _recv_until(
        sock,
        lambda p: (
            p.get("type") == "key_exchange"
            and p.get("operation") == "public_key"
            and p.get("username") == username
        ),
    )


# ----------------------------------------------------------------------
# 1. A cannot register a public key claiming to belong to B
# ----------------------------------------------------------------------

def test_public_key_is_labelled_with_the_authenticated_username(two_users):
    """
    The attacker authenticates as themselves but claims a different
    username inside the key_exchange packet. The victim must receive
    the key labelled with the ATTACKER's real, authenticated username,
    never the claimed one -- otherwise the victim would encrypt session
    and group keys to the attacker while believing they were talking to
    someone else.
    """

    port = two_users["port"]
    victim_payload, attacker_payload = two_users["payloads"]

    victim_sock, victim_name = _authenticate(port, victim_payload)
    _send(
        victim_sock,
        create_public_key_packet(
            username=victim_name, algorithm="KYBER", public_key="victim-public-key"
        ),
    )

    attacker_sock, attacker_name = _authenticate(port, attacker_payload)

    # The forgery: a truthful key, an untruthful owner.
    _send(
        attacker_sock,
        create_public_key_packet(
            username=victim_name,  # claimed -- must be ignored
            algorithm="KYBER",
            public_key="attacker-public-key",
        ),
    )

    delivered = _await_public_key_for(victim_sock, attacker_name)

    assert delivered is not None, (
        "the attacker's key must still be distributed -- under their own name"
    )
    assert delivered["username"] == attacker_name
    assert delivered["username"] != victim_name
    assert delivered["public_key"] == "attacker-public-key"

    victim_sock.close()
    attacker_sock.close()


def test_forged_key_does_not_replace_the_victims_own_key_on_the_server(two_users):
    """
    The same forgery viewed from server state: the attacker's packet
    must land on the attacker's own connection record only. The
    victim's stored key must be untouched, since substituting it is
    what would enable a man-in-the-middle.
    """

    port = two_users["port"]
    victim_payload, attacker_payload = two_users["payloads"]

    victim_sock, victim_name = _authenticate(port, victim_payload)
    _send(
        victim_sock,
        create_public_key_packet(
            username=victim_name, algorithm="KYBER", public_key="victim-public-key"
        ),
    )

    attacker_sock, attacker_name = _authenticate(port, attacker_payload)
    _send(
        attacker_sock,
        create_public_key_packet(
            username=victim_name,
            algorithm="KYBER",
            public_key="attacker-public-key",
        ),
    )

    # Wait until the attacker's key has definitely been processed and
    # distributed, so the assertion below is not racing registration.
    assert _await_public_key_for(victim_sock, attacker_name) is not None

    keys_by_username = _server_keys_by_username(two_users["server_state"])

    assert keys_by_username[victim_name] == "victim-public-key"
    assert keys_by_username[attacker_name] == "attacker-public-key"

    victim_sock.close()
    attacker_sock.close()


# ----------------------------------------------------------------------
# 2. A post-authentication public-key packet cannot rebind the identity
# ----------------------------------------------------------------------

def test_post_authentication_public_key_packet_cannot_rebind_a_different_identity(two_users):
    """
    The first key_exchange packet is consumed during connection setup.
    A second one, arriving in the main receive loop, is (Phase 16D)
    processed as a legitimate re-broadcast of the SENDER's own
    identity -- but an attempted identity swap (claiming a DIFFERENT
    username than the one this socket authenticated as) must still be
    completely ineffective: the victim's own server-side key entry
    must stay untouched, and whatever IS relayed to the victim as a
    result must still be correctly labelled with the attacker's own
    authenticated username, never the claimed one.
    """

    port = two_users["port"]
    victim_payload, attacker_payload = two_users["payloads"]

    victim_sock, victim_name = _authenticate(port, victim_payload)
    _send(
        victim_sock,
        create_public_key_packet(
            username=victim_name, algorithm="KYBER", public_key="victim-public-key"
        ),
    )

    attacker_sock, attacker_name = _authenticate(port, attacker_payload)
    _send(
        attacker_sock,
        create_public_key_packet(
            username=attacker_name, algorithm="KYBER", public_key="attacker-key-v1"
        ),
    )

    assert _await_public_key_for(victim_sock, attacker_name) is not None

    # Second key_exchange packet, now in the main loop, attempting both
    # a legitimate-looking key update AND an identity swap (claiming to
    # be victim_name, not this socket's own authenticated identity).
    _send(
        attacker_sock,
        create_public_key_packet(
            username=victim_name,
            algorithm="KYBER",
            public_key="attacker-key-v2",
        ),
    )

    # The identity swap fails: whatever reaches the victim as a result
    # of this packet is labelled with the ATTACKER's own authenticated
    # username, never victim_name -- ServerState.set_public_key() is
    # keyed by socket and distribute_public_keys() re-labels from the
    # JWT-authenticated state, never from the packet's own claimed
    # "username" field (which is not even read).
    relayed = _await_public_key_for(victim_sock, attacker_name)
    assert relayed is not None, (
        "Phase 16D: a post-authentication public-key packet from the "
        "sender's OWN authenticated connection is now a legitimate "
        "re-broadcast and must still reach the victim -- correctly "
        "labelled."
    )
    assert relayed["username"] == attacker_name
    assert relayed["username"] != victim_name
    assert relayed["public_key"] == "attacker-key-v2"

    keys_by_username = _server_keys_by_username(two_users["server_state"])

    # The victim's OWN stored key is never touched by anything the
    # attacker's connection sends -- this is the actual security
    # property this test exists to protect.
    assert keys_by_username[victim_name] == "victim-public-key"

    # The attacker's own key entry legitimately updates to their own
    # latest broadcast -- exactly what Phase 16D's re-broadcast
    # capability is for (e.g. ClientSession.enroll_device() attaching
    # device_id once it becomes known, after the original bootstrap
    # broadcast already fired).
    assert keys_by_username[attacker_name] == "attacker-key-v2"

    victim_sock.close()
    attacker_sock.close()
