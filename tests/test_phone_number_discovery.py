"""
BUG 7 -- phone-based user discovery.

Discovery used to accept only the internal UUID primary key, and the
application never displayed that UUID anywhere, so no user could
obtain the one value the feature accepted. Typing a username returned
"not found" -- correct behaviour, and still unusable. The phone number
is now the user-facing identifier; users.id stays the internal primary
key and UUID lookup keeps working for internal callers.

Two things the audit proved, which these tests pin down:

  * Discovery is a DATABASE lookup, not a presence lookup. An offline
    user is found exactly like an online one. Presence (BUG 8) and
    discovery are unrelated, and a test here asserts that directly.

  * A malformed identifier used to be fatal. uuid.UUID() escaped
    handle_user_lookup() into handle_client()'s outer `except`, whose
    `finally` broadcast a leave, removed the client from state.clients
    and closed the socket -- one bad lookup DISCONNECTED the searcher.
    The GUI was shielded only because find_user_by_id() validated
    client-side; nothing at the protocol level was. Two tests below
    drive malformed identifiers over a raw socket and assert the
    connection survives.

Normalisation is what makes the UNIQUE constraint meaningful:
"+91 98765 43210", "+91-98765-43210" and "+919876543210" are one
number and must collide rather than create three accounts.

Ownership is NOT verified -- there is no OTP, deliberately out of
scope -- so a phone number identifies an account, never a verified
person.

Run with:
    pytest tests/test_phone_number_discovery.py -v
"""

import json
import socket
import struct
import time
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from security.phone_number import (
    InvalidPhoneNumberError,
    is_valid_phone_number,
    normalize_phone_number,
)
from tests.tls_test_support import start_test_server, wrap_client_socket
from utils.protocol import create_auth_packet, create_public_key_packet

# Distinct per run so concurrent/repeated runs cannot collide on the
# UNIQUE constraint.
_PHONE_PREFIX = "+9199"


def _unique_phone():
    return f"{_PHONE_PREFIX}{uuid.uuid4().int % 10**8:08d}"


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


@pytest.fixture()
def auth_service():
    db = SessionLocal()

    yield AuthenticationService(db)

    db.close()


def _register(phone_number=None, suffix_hint=""):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Phone Discovery Test",
            "username": f"phd_{suffix_hint}{suffix}",
            "email": f"phd_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": phone_number or _unique_phone(),
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete(username):
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


def _token(payload):
    db = SessionLocal()
    try:
        result = AuthenticationService(db).authenticate_user(
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _connect(payload):
    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _wait_for(predicate, attempts=100, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def accounts():
    """Registered accounts, cleaned up however the test used them."""

    created = []

    def _make(phone_number=None, hint=""):
        payload = _register(phone_number, hint)
        created.append(payload)
        return payload

    yield _make

    for payload in created:
        _delete(payload["username"])


@pytest.fixture()
def connected(running_server, monkeypatch, accounts):
    """Factory for real, connected ClientSessions against the harness."""

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sessions = []

    def _connect_account(payload):
        session = _connect(payload)
        sessions.append(session)
        return session

    yield _connect_account

    for session in sessions:
        try:
            session.disconnect()
        except OSError:
            pass


# ----------------------------------------------------------------------
# 1-5. Registration, validation, uniqueness, normalisation
# ----------------------------------------------------------------------

def test_registration_requires_a_phone_number(auth_service):
    """1: a missing phone number is rejected, not silently accepted."""

    suffix = uuid.uuid4().hex[:10]
    result = auth_service.register_user(
        RegisterRequest(
            full_name="No Phone",
            username=f"phd_nophone_{suffix}",
            email=f"phd_nophone_{suffix}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
            phone_number="",
        )
    )

    assert result.success is False
    assert "phone_number" in (result.errors or {})


def test_registration_with_a_valid_phone_number_succeeds(accounts):
    """2: the happy path, and the stored value is canonical."""

    payload = accounts("+91 98765 12345")

    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(payload["username"])
        assert user is not None
        assert user.phone_number == "+919876512345"
    finally:
        db.close()


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "abc", "+", "12345", "+91-98765-4321x", "++919876543210",
     "9" * 16, "phone"],
    ids=["empty", "blank", "letters", "plus-only", "too-short",
         "trailing-letter", "double-plus", "too-many-digits", "word"],
)
def test_invalid_phone_numbers_are_rejected(auth_service, bad):
    """3: malformed numbers never reach the database."""

    suffix = uuid.uuid4().hex[:10]
    result = auth_service.register_user(
        RegisterRequest(
            full_name="Bad Phone",
            username=f"phd_bad_{suffix}",
            email=f"phd_bad_{suffix}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
            phone_number=bad,
        )
    )

    assert result.success is False
    assert "phone_number" in (result.errors or {})


def test_duplicate_phone_number_is_rejected(accounts, auth_service):
    """4: the same number cannot register twice."""

    first = accounts("+91 98765 22222")

    suffix = uuid.uuid4().hex[:10]
    result = auth_service.register_user(
        RegisterRequest(
            full_name="Second",
            username=f"phd_dup_{suffix}",
            email=f"phd_dup_{suffix}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
            phone_number="+919876522222",
        )
    )

    assert result.success is False
    assert "phone_number" in (result.errors or {})
    assert first["username"]


def test_differently_formatted_duplicates_are_also_rejected(accounts, auth_service):
    """4 + 5 together: uniqueness is enforced on the CANONICAL value, so
    a different spelling of the same number still collides. Without
    normalisation before the check, both rows would insert and the
    UNIQUE constraint would not catch it either."""

    accounts("+919876533333")

    suffix = uuid.uuid4().hex[:10]
    result = auth_service.register_user(
        RegisterRequest(
            full_name="Reformatted",
            username=f"phd_fmt_{suffix}",
            email=f"phd_fmt_{suffix}@example.com",
            password="Str0ng!Passw0rd",
            confirm_password="Str0ng!Passw0rd",
            phone_number="+91 98765-33333",
        )
    )

    assert result.success is False
    assert "phone_number" in (result.errors or {})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("+91 98765 43210", "+919876543210"),
        ("+91-98765-43210", "+919876543210"),
        ("+919876543210", "+919876543210"),
        ("+91 (98765) 43210", "+919876543210"),
        ("  +91 98765 43210  ", "+919876543210"),
        ("09876543210", "09876543210"),
    ],
    ids=["spaces", "dashes", "canonical", "parens", "padded", "national"],
)
def test_phone_normalization(raw, expected):
    """5: equivalent spellings resolve to one canonical form."""

    assert normalize_phone_number(raw) == expected
    assert is_valid_phone_number(raw) is True


def test_normalization_preserves_the_leading_plus():
    """'+91...' and '91...' are different numbers and must not merge."""

    assert normalize_phone_number("+919876543210") != normalize_phone_number(
        "919876543210"
    )


def test_normalize_raises_for_invalid_input():
    with pytest.raises(InvalidPhoneNumberError):
        normalize_phone_number("not-a-number")

    assert is_valid_phone_number("not-a-number") is False


# ----------------------------------------------------------------------
# 6-9. Lookup
# ----------------------------------------------------------------------

def test_search_online_user_by_phone(accounts, connected):
    """6: an online user is found by phone number."""

    alice = accounts(hint="alice_")
    bob = accounts("+91 98765 44444", hint="bob_")

    alice_session = connected(alice)
    connected(bob)

    found = alice_session.find_user_by_phone_number("+919876544444")

    assert found is not None
    assert found["username"] == bob["username"]
    assert found["user_id"] == bob["user_id"]


def test_search_offline_user_by_phone(accounts, connected):
    """
    7: THE property that matters -- discovery is a database lookup, so
    a user who has never connected is found exactly like an online one.
    Presence and discovery are independent.
    """

    alice = accounts(hint="alice_")
    offline = accounts("+91 98765 55555", hint="offline_")

    alice_session = connected(alice)

    # `offline` is registered but never connects.
    found = alice_session.find_user_by_phone_number("+91 98765 55555")

    assert found is not None, "an offline user must still be discoverable"
    assert found["username"] == offline["username"]


def test_search_is_format_insensitive(accounts, connected):
    """The searcher may type the number any reasonable way -- the server
    normalises before matching."""

    alice = accounts(hint="alice_")
    bob = accounts("+919876566666", hint="bob_")

    alice_session = connected(alice)

    for spelling in ("+919876566666", "+91 98765 66666", "+91-98765-66666"):
        found = alice_session.find_user_by_phone_number(spelling)
        assert found is not None, spelling
        assert found["username"] == bob["username"]


def test_nonexistent_phone_returns_clean_not_found(accounts, connected):
    """8: a well-formed number nobody registered returns None, cleanly."""

    alice_session = connected(accounts(hint="alice_"))

    assert alice_session.find_user_by_phone_number("+919999000111") is None
    assert alice_session.is_connected() is True


def test_uuid_lookup_still_works(accounts, connected):
    """9: the internal UUID path is unchanged -- this is additive."""

    alice = accounts(hint="alice_")
    bob = accounts(hint="bob_")

    alice_session = connected(alice)
    connected(bob)

    found = alice_session.find_user_by_id(bob["user_id"])

    assert found is not None
    assert found["username"] == bob["username"]


def test_lookup_response_exposes_only_minimal_fields(accounts, connected):
    """Privacy: the result carries identity only -- never email,
    password state, or internal flags."""

    alice_session = connected(accounts(hint="alice_"))
    bob = accounts("+91 98765 77777", hint="bob_")

    found = alice_session.find_user_by_phone_number("+919876577777")

    assert set(found) == {"user_id", "username", "display_name"}
    assert bob["email"] not in str(found)


# ----------------------------------------------------------------------
# 10-11. Malformed input must never disconnect the client
# ----------------------------------------------------------------------

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
    return json.loads(data.decode("utf-8"))


def _recv_until(sock, predicate, attempts=30, per_attempt_timeout=0.3):
    for _ in range(attempts):
        try:
            candidate = _recv(sock, timeout=per_attempt_timeout)
        except TimeoutError:
            candidate = None
        if candidate and predicate(candidate):
            return candidate
    return None


@pytest.fixture()
def raw_client(running_server, accounts):
    """A raw authenticated socket -- bypasses ClientSession's
    client-side validation, which is the only reason the GUI never hit
    the defect these tests cover."""

    _state, port = running_server
    payload = accounts(hint="raw_")

    sock = wrap_client_socket(socket.create_connection(("127.0.0.1", port), timeout=5))
    _send(sock, create_auth_packet(_token(payload)))
    assert _recv(sock)["success"] is True

    _send(
        sock,
        create_public_key_packet(
            username=payload["username"], algorithm="KYBER", public_key="dummy"
        ),
    )

    yield sock, payload

    try:
        sock.close()
    except OSError:
        pass


@pytest.mark.parametrize(
    "malformed",
    ["BOB_DEMO", "not-a-uuid", "", "12345", "'; DROP TABLE users; --"],
    ids=["username", "garbage", "empty", "digits", "sql-ish"],
)
def test_malformed_uuid_lookup_does_not_disconnect(raw_client, malformed):
    """
    10: the regression that mattered most. Before the fix this raised
    ValueError out of handle_user_lookup(), and handle_client()'s
    `finally` then removed the client and closed the socket -- one bad
    lookup disconnected the searcher.
    """

    sock, _payload = raw_client
    request_id = str(uuid.uuid4())

    _send(
        sock,
        {
            "type": "user_lookup_request",
            "request_id": request_id,
            "user_id": malformed,
        },
    )

    # An empty identifier is ignored by design (no response), so the
    # liveness probe below is what proves survival in every case.
    probe_id = str(uuid.uuid4())
    _send(sock, {"type": "conversation_list_request", "request_id": probe_id})

    assert _recv_until(
        sock,
        lambda p: (
            p.get("type") == "conversation_list_result"
            and p.get("request_id") == probe_id
        ),
    ) is not None, "the connection was dropped by a malformed lookup"


@pytest.mark.parametrize(
    "malformed",
    ["not-a-phone", "+", "abc123", "", "9" * 40],
    ids=["letters", "plus-only", "mixed", "empty", "too-long"],
)
def test_malformed_phone_lookup_does_not_disconnect(raw_client, malformed):
    """11: the same guarantee for the new identifier type."""

    sock, _payload = raw_client

    _send(
        sock,
        {
            "type": "user_lookup_request",
            "request_id": str(uuid.uuid4()),
            "identifier_type": "phone",
            "identifier": malformed,
        },
    )

    probe_id = str(uuid.uuid4())
    _send(sock, {"type": "conversation_list_request", "request_id": probe_id})

    assert _recv_until(
        sock,
        lambda p: (
            p.get("type") == "conversation_list_result"
            and p.get("request_id") == probe_id
        ),
    ) is not None, "the connection was dropped by a malformed phone lookup"


def test_malformed_phone_lookup_returns_not_found(raw_client):
    """A malformed identifier is reported exactly like one that matches
    nobody, so a caller cannot distinguish the two."""

    sock, _payload = raw_client
    request_id = str(uuid.uuid4())

    _send(
        sock,
        {
            "type": "user_lookup_request",
            "request_id": request_id,
            "identifier_type": "phone",
            "identifier": "not-a-phone",
        },
    )

    response = _recv_until(
        sock,
        lambda p: (
            p.get("type") == "user_lookup_result"
            and p.get("request_id") == request_id
        ),
    )

    assert response is not None
    assert response.get("user_id") is None


# ----------------------------------------------------------------------
# 12-15. Multi-client discovery and the conversation flow
# ----------------------------------------------------------------------

def test_newly_connected_user_can_discover_an_existing_user(accounts, connected):
    """12: connection order must not affect discovery."""

    alice = accounts("+91 98765 88881", hint="alice_")
    bob = accounts("+91 98765 88882", hint="bob_")

    connected(alice)          # already online
    bob_session = connected(bob)   # joins later

    found = bob_session.find_user_by_phone_number("+919876588881")

    assert found is not None
    assert found["username"] == alice["username"]


def test_existing_user_can_discover_a_newly_connected_user(accounts, connected):
    """13: the other direction."""

    alice = accounts("+91 98765 88883", hint="alice_")
    bob = accounts("+91 98765 88884", hint="bob_")

    alice_session = connected(alice)
    connected(bob)

    found = alice_session.find_user_by_phone_number("+919876588884")

    assert found is not None
    assert found["username"] == bob["username"]


def test_three_clients_can_each_discover_the_others(accounts, connected):
    """14: independent, symmetric discovery across three clients."""

    people = {
        "alice": accounts("+91 98765 99991", hint="alice_"),
        "bob": accounts("+91 98765 99992", hint="bob_"),
        "carol": accounts("+91 98765 99993", hint="carol_"),
    }
    phones = {
        "alice": "+919876599991",
        "bob": "+919876599992",
        "carol": "+919876599993",
    }

    sessions = {name: connected(payload) for name, payload in people.items()}

    for searcher in people:
        for target in people:
            if searcher == target:
                continue
            found = sessions[searcher].find_user_by_phone_number(phones[target])
            assert found is not None, f"{searcher} could not find {target}"
            assert found["username"] == people[target]["username"]


def test_lookup_leads_into_the_existing_direct_conversation_flow(accounts, connected):
    """
    15: a successful lookup feeds the unchanged conversation flow --
    the found username opens a direct conversation, resolved
    server-side, and a message is delivered.
    """

    alice = accounts("+91 98765 12321", hint="alice_")
    bob = accounts("+91 98765 32123", hint="bob_")

    alice_session = connected(alice)
    bob_session = connected(bob)

    assert _wait_for(
        lambda: alice_session.key_manager.get_public_key(bob["username"]) is not None
    )

    found = alice_session.find_user_by_phone_number("+919876532123")
    assert found is not None

    alice_session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=found["username"],
            is_online=True,
            latest_message=None,
        )
    )

    assert alice_session.current_conversation_id is not None

    alice_session.send_chat_message("found you by phone number")

    def bob_got_it():
        summary = bob_session.conversation_store.get(alice["username"])
        return (
            summary is not None
            and summary.latest_message is not None
            and summary.latest_message.text == "found you by phone number"
        )

    assert _wait_for(bob_got_it), "the discovered user never received the message"


def test_own_phone_number_is_returned_by_the_real_login_flow(
    running_server, monkeypatch, accounts
):
    """
    7.5: the signed-in user can read their own identifier back, which
    is what makes it shareable.

    Drives the REAL login path -- authenticate_credentials(), which is
    what gui/main_window.py::handle_login() calls -- rather than
    minting a token directly, because the phone number travels on the
    login_result packet that path produces.
    """

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    alice = accounts("+91 98765 45454", hint="alice_")

    session = ClientSession()
    result = session.authenticate_credentials(
        alice["username"], alice["password"]
    )

    assert result.success, result.errors
    assert result.phone_number == "+919876545454", (
        "login must return the user's own phone number so the UI can show it"
    )

    # And it is never another account's number.
    assert result.username == alice["username"]
