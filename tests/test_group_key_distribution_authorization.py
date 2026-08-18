"""
Security regression tests for group_key_distribution authorization (D6).

Verifies, against the real server.client_handler.handle_client accept
loop (same harness pattern as test_message_routing_security.py), the
three parts of D6:

  D6.1 Extraction: the inline "group_key_distribution" relay branch is
       now handle_group_key_distribution(); every previously-valid
       member -> member distribution still relays unchanged.

  D6.2 Sender authorization: only an active member of the conversation
       may distribute a group key for it. A non-member (and a member
       who has since left) is rejected silently -- server-side log
       only, nothing relayed, no error packet returned. The
       client-supplied "sender" field is overwritten with the
       authenticated username before relay, exactly as handle_client()
       already does for "chat" and direct "session_key" packets.

  D6.3 Recipient authorization: the key may only be delivered to
       another active member of that same conversation -- a member
       cannot use the relay to hand a group key to an outsider.

Why this mattered: server/broadcaster.py's distribute_public_keys()
sends every connected client's public key to every other connected
client regardless of shared membership, so before D6 any authenticated
user could produce a validly-wrapped key for any online victim and
inject it into any conversation. KeyManager.store_key()'s
"highest epoch wins" rule would then make the injected key that
victim's CURRENT key -- poisoning the group's key state.

Nothing here tests cryptography: the wrapped_key/encapsulation fields
are opaque markers, exactly as opaque to the server as real ones. Key
generation, wrapping, and unwrapping remain entirely client-side and
are unchanged by D6.

Run with:
    pytest tests/test_group_key_distribution_authorization.py -v
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
from utils.protocol import (
    create_auth_packet,
    create_group_add_members_packet,
    create_group_create_packet,
    create_group_key_distribution_packet,
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
            "full_name": "Key Distribution Test",
            "username": f"gkdtest_{suffix_hint}{suffix}",
            "email": f"gkdtest_{suffix_hint}{suffix}@example.com",
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
def party(running_server):
    """
    Four connected, authenticated users. The first three become members
    of a group conversation; ``outsider`` never joins any conversation
    but IS authenticated and connected -- exactly the attacker position
    D6.2 closes (and, as a recipient, the one D6.3 closes).
    """

    _state, port = running_server

    payloads = [_register_user(f"p{index}_") for index in range(4)]
    connections = [_connect_and_authenticate(port, payload) for payload in payloads]

    people = [
        {"sock": sock, "username": username, "user_id": payload["user_id"]}
        for (sock, username), payload in zip(connections, payloads)
    ]

    yield {
        "port": port,
        "members": people[:3],
        "outsider": people[3],
    }

    for sock, _username in connections:
        sock.close()

    for payload in payloads:
        _delete_user(payload["username"])


def _create_group(party, name="Key Distribution Test Group"):
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
        assert result is not None, "every member must receive group_create_result"

    return results[0]["conversation_id"]


def _distribute(sock, sender, conversation_id, recipient, wrapped_key, epoch=1):
    """Send one group_key_distribution packet. ``wrapped_key`` doubles
    as a marker so a test can tell exactly which packet arrived."""

    _send(
        sock,
        create_group_key_distribution_packet(
            sender=sender,
            conversation_id=conversation_id,
            recipient=recipient,
            encapsulation="opaque-encapsulation",
            wrapped_key=wrapped_key,
            epoch=epoch,
        ),
    )


def _await_distribution(sock, attempts=40):
    return _recv_until(
        sock,
        lambda p: p.get("type") == "group_key_distribution",
        attempts=attempts,
    )


def _barrier(sock):
    """
    Force a full round trip on ``sock``, proving every packet already
    sent on it has been processed by its handler thread (each
    connection is served by a single sequential receive loop, so a
    response to a later request cannot overtake an earlier packet).

    This makes the rejection assertions deterministic rather than
    timing-based: once the barrier returns, a packet that was going to
    be relayed already has been. Also doubles as a liveness check --
    a handler that crashed on a malformed packet cannot answer.
    """

    request_id = str(uuid.uuid4())

    _send(sock, {"type": "conversation_list_request", "request_id": request_id})

    response = _recv_until(
        sock,
        lambda p: (
            p.get("type") == "conversation_list_result"
            and p.get("request_id") == request_id
        ),
    )

    assert response is not None, "connection must still be alive and responsive"

    return response


# ----------------------------------------------------------------------
# D6.2 -- sender authorization
# ----------------------------------------------------------------------

def test_non_member_sender_cannot_distribute_group_key(party):
    """1. A connected, authenticated non-member injecting key material
    into a conversation they do not belong to is rejected."""

    conversation_id = _create_group(party)
    _creator, member_b, _member_c = party["members"]
    outsider = party["outsider"]

    _distribute(
        outsider["sock"],
        sender=outsider["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="INJECTED-BY-NON-MEMBER",
    )

    # Once the outsider's own connection has completed a round trip,
    # any relay that was going to happen already has.
    _barrier(outsider["sock"])

    assert _await_distribution(member_b["sock"], attempts=6) is None, (
        "a non-member's group key must never be relayed"
    )


def test_departed_member_cannot_distribute_group_key(party):
    """3. A member who has left the conversation loses distribution
    rights immediately -- get_member_user_ids() filters left_at."""

    conversation_id = _create_group(party)
    creator, member_b, member_c = party["members"]

    _send(
        member_c["sock"],
        create_group_leave_packet(
            sender=member_c["username"], conversation_id=conversation_id
        ),
    )

    left = _recv_until(
        member_c["sock"],
        lambda p: (
            p.get("type") == "group_member_left"
            and p.get("username") == member_c["username"]
        ),
    )
    assert left is not None, "the leave must be confirmed before asserting on it"

    _distribute(
        member_c["sock"],
        sender=member_c["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="INJECTED-BY-DEPARTED-MEMBER",
    )

    _barrier(member_c["sock"])

    assert _await_distribution(member_b["sock"], attempts=6) is None, (
        "a departed member's group key must never be relayed"
    )

    # A still-active member is unaffected by the departure.
    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="LEGITIMATE-AFTER-LEAVE",
        epoch=2,
    )

    delivered = _await_distribution(member_b["sock"])

    assert delivered is not None
    assert delivered["wrapped_key"] == "LEGITIMATE-AFTER-LEAVE"


def test_forged_sender_field_is_overwritten_with_authenticated_username(party):
    """4. The client-supplied sender field is never trusted."""

    conversation_id = _create_group(party)
    creator, member_b, _member_c = party["members"]
    outsider = party["outsider"]

    _distribute(
        creator["sock"],
        sender=outsider["username"],  # forged
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="FORGED-SENDER-PROBE",
    )

    delivered = _await_distribution(member_b["sock"])

    assert delivered is not None
    assert delivered["wrapped_key"] == "FORGED-SENDER-PROBE"
    assert delivered["sender"] == creator["username"]
    assert delivered["sender"] != outsider["username"]


# ----------------------------------------------------------------------
# D6.3 -- recipient authorization
# ----------------------------------------------------------------------

def test_member_cannot_distribute_group_key_to_non_member(party):
    """5. A legitimate member may not route a group key to an outsider."""

    conversation_id = _create_group(party)
    creator, _member_b, _member_c = party["members"]
    outsider = party["outsider"]

    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=outsider["username"],
        wrapped_key="LEAKED-TO-OUTSIDER",
    )

    _barrier(creator["sock"])

    assert _await_distribution(outsider["sock"], attempts=6) is None, (
        "a group key must never be relayed to a non-member"
    )


def test_departed_member_cannot_receive_group_key(party):
    """5 (continued). Departure removes receive rights too, so a
    post-leave rotation key cannot reach the member who left."""

    conversation_id = _create_group(party)
    creator, _member_b, member_c = party["members"]

    _send(
        member_c["sock"],
        create_group_leave_packet(
            sender=member_c["username"], conversation_id=conversation_id
        ),
    )

    left = _recv_until(
        member_c["sock"],
        lambda p: (
            p.get("type") == "group_member_left"
            and p.get("username") == member_c["username"]
        ),
    )
    assert left is not None

    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_c["username"],
        wrapped_key="SENT-TO-DEPARTED-MEMBER",
        epoch=2,
    )

    _barrier(creator["sock"])

    assert _await_distribution(member_c["sock"], attempts=6) is None, (
        "a departed member must not receive new group key material"
    )


# ----------------------------------------------------------------------
# Malformed input
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "conversation_id",
    [None, "", "not-a-uuid", "1234", 12345],
    ids=["none", "empty", "malformed", "numeric-string", "non-string"],
)
def test_invalid_conversation_id_is_rejected_safely(party, conversation_id):
    """6. Missing/invalid conversation_id is rejected without relaying
    and without killing the connection."""

    _create_group(party)
    creator, member_b, _member_c = party["members"]

    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="INVALID-CONVERSATION-ID",
    )

    # Barrier asserts the handler survived the malformed packet.
    _barrier(creator["sock"])

    assert _await_distribution(member_b["sock"], attempts=6) is None


@pytest.mark.parametrize(
    "recipient",
    [None, "", "no-such-user-exists"],
    ids=["none", "empty", "unknown-username"],
)
def test_invalid_recipient_is_rejected_safely(party, recipient):
    """7. Missing/invalid recipient is rejected without relaying and
    without killing the connection."""

    conversation_id = _create_group(party)
    creator, member_b, _member_c = party["members"]

    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=recipient,
        wrapped_key="INVALID-RECIPIENT",
    )

    _barrier(creator["sock"])

    # Nothing may reach any real member as a side effect.
    assert _await_distribution(member_b["sock"], attempts=6) is None


# ----------------------------------------------------------------------
# D6.1 -- extraction preserved existing valid behavior
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# Epoch authorization -- what may be distributed, not just by/to whom
# ----------------------------------------------------------------------

def test_member_cannot_distribute_an_epoch_beyond_the_reserved_one(party):
    """
    Membership alone must not let a member choose the epoch.

    KeyManager.store_key() tracks the current epoch with max(), so a
    key stamped with an absurdly high epoch becomes the recipient's
    CURRENT key immediately -- every outgoing group message would be
    encrypted under a key of the sender's choosing. Worse, it is
    permanent: every subsequent legitimate rotation carries a lower
    number, so max() never displaces it, and the victim stays poisoned
    even after the attacker leaves the group.

    The server therefore bounds the epoch by what it has actually
    reserved for the conversation.
    """

    conversation_id = _create_group(party)
    creator, member_b, _member_c = party["members"]

    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="POISONED-FUTURE-EPOCH",
        epoch=999999,
    )

    _barrier(creator["sock"])

    assert _await_distribution(member_b["sock"], attempts=6) is None, (
        "an epoch beyond the server's reserved epoch must not be relayed"
    )


@pytest.mark.parametrize(
    "bad_epoch",
    [0, -1, -999, "1", "abc", 1.5, True, [], {}],
    ids=["zero", "negative", "very-negative", "numeric-string",
         "non-numeric-string", "float", "bool", "list", "dict"],
)
def test_invalid_epoch_values_are_rejected(party, bad_epoch):
    """
    A non-integer epoch is rejected server-side rather than relayed.

    This matters beyond tidiness: the receiving client does
    ``store_key(..., epoch=packet["epoch"])``, and KeyManager compares
    epochs with max(). A string epoch would raise TypeError inside the
    receiver thread; a bool would silently alias epoch 1.
    """

    conversation_id = _create_group(party)
    creator, member_b, _member_c = party["members"]

    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="INVALID-EPOCH",
        epoch=bad_epoch,
    )

    _barrier(creator["sock"])

    assert _await_distribution(member_b["sock"], attempts=6) is None


def test_epoch_equal_to_the_reserved_epoch_is_allowed(party):
    """The positive control: the bound is an upper bound, not an
    exclusion. Epoch 1 is exactly what group creation distributes, and
    it must still be relayed."""

    conversation_id = _create_group(party)
    creator, member_b, _member_c = party["members"]

    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="AT-RESERVED-EPOCH",
        epoch=1,
    )

    delivered = _await_distribution(member_b["sock"])

    assert delivered is not None
    assert delivered["wrapped_key"] == "AT-RESERVED-EPOCH"
    assert delivered["epoch"] == 1


def test_rotation_epoch_is_allowed_after_the_server_reserves_it(party):
    """
    A real rotation must still work end to end: a member leaves, the
    server reserves the next epoch, and the higher epoch that was
    previously rejected is now legitimately distributable.
    """

    conversation_id = _create_group(party)
    creator, member_b, member_c = party["members"]

    # Epoch 2 is not yet reserved -- rejected.
    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="TOO-EARLY",
        epoch=2,
    )
    _barrier(creator["sock"])
    assert _await_distribution(member_b["sock"], attempts=6) is None

    # A leave reserves epoch 2.
    _send(
        member_c["sock"],
        create_group_leave_packet(
            sender=member_c["username"], conversation_id=conversation_id
        ),
    )
    assert _recv_until(
        member_c["sock"],
        lambda p: (
            p.get("type") == "group_member_left"
            and p.get("username") == member_c["username"]
        ),
    ) is not None

    # Now the same epoch 2 is legitimate.
    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=member_b["username"],
        wrapped_key="AFTER-ROTATION-RESERVED",
        epoch=2,
    )

    delivered = _await_distribution(member_b["sock"])

    assert delivered is not None
    assert delivered["wrapped_key"] == "AFTER-ROTATION-RESERVED"
    assert delivered["epoch"] == 2


def test_member_to_member_distribution_still_succeeds(party):
    """2 + 8. The ordinary group creation -> key distribution path is
    unchanged: an active member reaches another active member, with
    every opaque field relayed byte-for-byte."""

    conversation_id = _create_group(party)
    creator, member_b, member_c = party["members"]

    for recipient in (member_b, member_c):

        _distribute(
            creator["sock"],
            sender=creator["username"],
            conversation_id=conversation_id,
            recipient=recipient["username"],
            wrapped_key=f"WRAPPED-FOR-{recipient['username']}",
        )

        delivered = _await_distribution(recipient["sock"])

        assert delivered is not None, f"{recipient['username']} must receive the key"
        assert delivered["type"] == "group_key_distribution"
        assert delivered["conversation_id"] == conversation_id
        assert delivered["recipient"] == recipient["username"]
        assert delivered["wrapped_key"] == f"WRAPPED-FOR-{recipient['username']}"
        assert delivered["encapsulation"] == "opaque-encapsulation"
        assert delivered["epoch"] == 1
        assert delivered["sender"] == creator["username"]


def test_added_member_can_receive_group_key(party):
    """9. The add-member flow still works, and a newly added member is
    immediately authorized to receive key material."""

    creator, member_b, _member_c = party["members"]
    outsider = party["outsider"]

    # Group of two, so the outsider can be added to it below.
    _send(
        creator["sock"],
        create_group_create_packet(
            sender=creator["username"],
            name="Add Member Test Group",
            member_usernames=[member_b["username"]],
        ),
    )

    created = _recv_until(
        creator["sock"], lambda p: p.get("type") == "group_create_result"
    )
    assert created is not None
    conversation_id = created["conversation_id"]

    # Before being added, the outsider cannot receive a key (D6.3).
    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=outsider["username"],
        wrapped_key="BEFORE-ADD",
    )

    _barrier(creator["sock"])

    assert _await_distribution(outsider["sock"], attempts=6) is None

    _send(
        creator["sock"],
        create_group_add_members_packet(
            sender=creator["username"],
            conversation_id=conversation_id,
            member_usernames=[outsider["username"]],
        ),
    )

    added = _recv_until(
        outsider["sock"],
        lambda p: (
            p.get("type") == "group_members_added"
            and p.get("conversation_id") == conversation_id
        ),
    )
    assert added is not None, "the added member must be told about the group"

    # After being added, the same distribution is authorized.
    _distribute(
        creator["sock"],
        sender=creator["username"],
        conversation_id=conversation_id,
        recipient=outsider["username"],
        wrapped_key="AFTER-ADD",
        epoch=2,
    )

    delivered = _await_distribution(outsider["sock"])

    assert delivered is not None
    assert delivered["wrapped_key"] == "AFTER-ADD"
    assert delivered["sender"] == creator["username"]


def test_leave_still_triggers_rotation_dispatch(party):
    """10. The leave -> rotation flow is untouched by D6: the server
    still instructs a remaining connected member to establish the next
    epoch. (D6 gates the relay of key material, never the server's own
    rotation dispatch.)"""

    conversation_id = _create_group(party)
    creator, member_b, member_c = party["members"]

    _send(
        member_c["sock"],
        create_group_leave_packet(
            sender=member_c["username"], conversation_id=conversation_id
        ),
    )

    rotation = None

    for candidate in (creator, member_b):
        rotation = _recv_until(
            candidate["sock"],
            lambda p: (
                p.get("type") == "group_key_rotation_required"
                and p.get("conversation_id") == conversation_id
            ),
            attempts=12,
        )
        if rotation is not None:
            break

    assert rotation is not None, (
        "a remaining connected member must still be asked to rotate"
    )
    assert rotation["epoch"] >= 2
    assert member_c["username"] not in rotation["members"]
