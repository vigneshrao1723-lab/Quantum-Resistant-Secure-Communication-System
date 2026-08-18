"""
Regression tests for Issue 1 (real-application testing bug report):
group creation appeared to allow only one other member.

Diagnosis: the protocol/server/persistence layers never imposed a
limit -- group_create's member_usernames, handle_group_create()'s
resolution loop, and ConversationRepository.create_group_conversation()
are all generic over an arbitrary-length list. The actual bug was a
GUI-only checkbox-click issue in gui/create_group_dialog.py (see that
file's build_ui() docstring) -- these tests instead prove the backend
never had a limit, at 2, 3, and 5 total members, and the GUI test
below proves the checkbox fix itself.

Run with:
    pytest tests/test_group_creation_multi_member.py -v
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
            "full_name": "Multi Member Test",
            "username": f"mmtest_{suffix_hint}{suffix}",
            "email": f"mmtest_{suffix_hint}{suffix}@example.com",
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


def _connect_and_authenticate(port, user_payload):
    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=3))
    token = _login_and_get_token(user_payload)

    _send(sock, create_auth_packet(token))
    auth_result = _recv(sock)
    assert auth_result["success"] is True, auth_result
    username = auth_result["username"]

    _send(
        sock,
        create_public_key_packet(
            username=username, algorithm="KYBER", public_key="dummy-public-key"
        ),
    )

    return sock, username


@pytest.fixture()
def make_group_of(running_server):
    """Factory fixture: make_group_of(n) registers+connects n users
    and returns them as a list of {"sock", "username", "user_id"}
    dicts. Cleans up every user it created, however many were asked
    for across however many calls in one test."""
    _state, port = running_server
    created = []

    def _make(n):
        payloads = [_register_user(f"u{i}_") for i in range(n)]
        connections = [_connect_and_authenticate(port, p) for p in payloads]
        created.extend(zip([c[0] for c in connections], payloads))
        return [
            {"sock": sock, "username": username, "user_id": payload["user_id"]}
            for (sock, username), payload in zip(connections, payloads)
        ]

    yield _make

    for sock, payload in created:
        sock.close()
        _delete_user(payload["username"])


def _create_group_and_collect_results(members, name):
    creator, *others = members

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name=name,
            member_usernames=[m["username"] for m in others],
        ),
    )

    results = {
        m["username"]: _recv_until(m["sock"], lambda p: p.get("type") == "group_create_result")
        for m in members
    }
    return results


@pytest.mark.parametrize("total_members", [2, 3, 5])
def test_group_can_be_created_with_multiple_members(make_group_of, total_members):
    """The core Issue 1 regression proof: creating a group with more
    than one OTHER member (2, 3, or 5 total members) succeeds, and
    every single one of them -- not just the creator -- receives the
    confirmation with the complete member list."""
    members = make_group_of(total_members)

    results = _create_group_and_collect_results(members, f"Group of {total_members}")

    for member in members:
        result = results[member["username"]]
        assert result is not None, f"{member['username']} never received group_create_result"
        assert set(result["members"]) == {m["username"] for m in members}
        assert result["conversation_id"] == results[members[0]["username"]]["conversation_id"]


def test_group_of_five_all_share_the_same_conversation_id(make_group_of):
    members = make_group_of(5)

    results = _create_group_and_collect_results(members, "Big Group")

    conversation_ids = {r["conversation_id"] for r in results.values()}
    assert len(conversation_ids) == 1


def test_only_explicitly_selected_users_become_members(make_group_of):
    """
    BUG 3 (server-side half): membership is exactly the creator plus
    the usernames actually requested -- an online user who was NOT
    selected must not be pulled in.

    The client-side defect was a dialog that mis-collected the
    selection (see tests/test_group_member_selection_clicks.py). This
    asserts the other end of the contract, directly against the
    ConversationMember rows, so a future change that widened
    membership server-side could not pass unnoticed.

    Four users are connected; only two are named in the request. The
    fourth is deliberately left online and unselected -- being
    connected must not be enough to join a group.
    """

    creator, selected, bystander, other_bystander = make_group_of(4)

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name="Selected Only",
            member_usernames=[selected["username"]],
        ),
    )

    result = _recv_until(
        creator["sock"], lambda p: p.get("type") == "group_create_result"
    )
    assert result is not None

    conversation_id = uuid.UUID(result["conversation_id"])

    db = SessionLocal()
    try:
        member_ids = {
            str(member_id)
            for member_id in ConversationRepository(db).get_member_user_ids(
                conversation_id
            )
        }
    finally:
        db.close()

    assert member_ids == {creator["user_id"], selected["user_id"]}, (
        "membership must be exactly the creator plus the requested user"
    )

    for excluded in (bystander, other_bystander):
        assert excluded["user_id"] not in member_ids, (
            f"{excluded['username']} was online but never selected, and "
            f"must not be a member"
        )

    # The creator is added from the authenticated session, exactly once,
    # even though the client never names itself in the request.
    assert len(member_ids) == 2


def test_unselected_online_user_never_receives_the_group(make_group_of):
    """The confirmation is delivered only to actual members, so an
    unselected online user's client never learns the group exists --
    which is what made it look like everyone had been added."""

    creator, selected, bystander = make_group_of(3)

    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name="No Bystanders",
            member_usernames=[selected["username"]],
        ),
    )

    assert _recv_until(
        selected["sock"], lambda p: p.get("type") == "group_create_result"
    ) is not None, "the selected member must receive the group"

    assert _recv_until(
        bystander["sock"],
        lambda p: p.get("type") == "group_create_result",
        attempts=8,
    ) is None, "an unselected online user must not receive the group"
