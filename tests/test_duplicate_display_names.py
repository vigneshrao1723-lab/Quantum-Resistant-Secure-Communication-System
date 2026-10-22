"""
Two people may choose the same name; messages still reach the right person.

``users.username`` is the account's unique internal handle (what every packet routes on);
``users.display_name`` is the name a person chose and sees, and it need not be unique. When a
chosen name is already somebody's handle, the new account gets its own handle. These tests use
the real server over TLS with real authenticated connections.
"""

import uuid
from datetime import datetime, timezone

from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from database.connection import SessionLocal
from database.repositories.user_repository import UserRepository
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from tests.test_group_messaging_integration import (  # noqa: F401 -- helpers and fixture reused
    _connect_and_authenticate,
    _delete_user,
    _recv_until,
    _send,
    running_server,
)
from utils.protocol import (
    MAX_DISPLAY_NAME_LENGTH,
    create_change_display_name_request_packet,
    create_display_names_request_packet,
    create_payload_packet,
)

PASSWORD = "Str0ng!Passw0rd"


def _register(name):
    """Register through the real service with the given chosen name; returns the stored account."""
    db = SessionLocal()
    try:
        phone = "+91" + str(uuid.uuid4().int % 10**10).zfill(10)
        result = AuthenticationService(db).register_user(RegisterRequest(
            full_name=name, username=name, email=f"{name}@users.invalid",
            password=PASSWORD, confirm_password=PASSWORD, phone_number=phone,
        ))
        assert result.success, result.errors
        account = UserRepository(db).get_by_id(result.user_id)
        return {"username": account.username, "display_name": account.display_name,
                "phone_number": phone, "password": PASSWORD, "user_id": str(account.id)}
    finally:
        db.close()


def _request(sock, packet, reply_type):
    packet = dict(packet, request_id=str(uuid.uuid4()))
    _send(sock, packet)
    return _recv_until(sock, lambda p: p.get("type") == reply_type and p.get("request_id") == packet["request_id"])


def test_two_people_with_the_same_name_get_distinct_handles_and_the_same_display_name():
    name = f"Same Name {uuid.uuid4().hex[:6]}"
    first, second = _register(name), _register(name)
    try:
        assert first["username"] == name
        assert second["username"] != first["username"]
        assert first["display_name"] == second["display_name"] == name
        # The synthetic e-mail addresses did not collide either.
        db = SessionLocal()
        try:
            repo = UserRepository(db)
            assert repo.get_by_id(first["user_id"]).email != repo.get_by_id(second["user_id"]).email
        finally:
            db.close()
    finally:
        _delete_user(first["username"])
        _delete_user(second["username"])


def test_a_message_to_one_namesake_never_reaches_the_other(running_server):
    _state, port = running_server
    name = f"Twin {uuid.uuid4().hex[:6]}"
    alice = _register(f"alice_{uuid.uuid4().hex[:6]}")
    twin_a, twin_b = _register(name), _register(name)
    socks = []
    try:
        a_sock, _ = _connect_and_authenticate(port, alice)
        ta_sock, _ = _connect_and_authenticate(port, twin_a)
        tb_sock, _ = _connect_and_authenticate(port, twin_b)
        socks += [a_sock, ta_sock, tb_sock]

        packet = create_payload_packet(
            sender=alice["username"],
            envelope=PayloadEnvelope(payload_type=PayloadType.TEXT, ciphertext="for-twin-b-only", content_metadata={}),
            timestamp=datetime.now(timezone.utc).isoformat(),
            receiver=twin_b["username"],
            client_message_id=str(uuid.uuid4()),
        )
        _send(a_sock, packet)

        got_b = _recv_until(tb_sock, lambda p: p.get("type") == "chat" and p.get("message") == "for-twin-b-only")
        got_a = _recv_until(ta_sock, lambda p: p.get("type") == "chat", attempts=8)

        assert got_b is not None, "the addressed account did not receive the message"
        assert got_a is None, "a namesake received a message addressed to someone else"
    finally:
        for sock in socks:
            sock.close()
        for account in (alice, twin_a, twin_b):
            _delete_user(account["username"])


def test_display_names_are_looked_up_by_handle_and_unknown_handles_are_absent(running_server):
    _state, port = running_server
    name = f"Lookup {uuid.uuid4().hex[:6]}"
    asker, one, two = _register(f"asker_{uuid.uuid4().hex[:6]}"), _register(name), _register(name)
    try:
        sock, _ = _connect_and_authenticate(port, asker)
        try:
            reply = _request(sock, create_display_names_request_packet(
                [one["username"], two["username"], "no_such_handle_" + uuid.uuid4().hex]
            ), "display_names_result")
        finally:
            sock.close()

        assert reply["names"] == {one["username"]: name, two["username"]: name}
    finally:
        for account in (asker, one, two):
            _delete_user(account["username"])


def test_changing_the_display_name_affects_only_your_own_account_and_is_validated(running_server):
    _state, port = running_server
    me, other = _register(f"me_{uuid.uuid4().hex[:6]}"), _register(f"other_{uuid.uuid4().hex[:6]}")
    try:
        sock, _ = _connect_and_authenticate(port, me)
        try:
            ok = _request(sock, create_change_display_name_request_packet("  Vignesh  "), "change_display_name_result")
            too_long = _request(sock, create_change_display_name_request_packet("x" * (MAX_DISPLAY_NAME_LENGTH + 1)),
                                "change_display_name_result")
            empty = _request(sock, create_change_display_name_request_packet("   "), "change_display_name_result")
            control = _request(sock, create_change_display_name_request_packet("bad\x07name"), "change_display_name_result")
            # Another person may pick the very same display name: it is not unique.
            other_sock, _ = _connect_and_authenticate(port, other)
            try:
                same = _request(other_sock, create_change_display_name_request_packet("Vignesh"), "change_display_name_result")
            finally:
                other_sock.close()
        finally:
            sock.close()

        assert ok["success"] is True and ok["display_name"] == "Vignesh"
        assert same["success"] is True
        for refused in (too_long, empty, control):
            assert refused["success"] is False and refused["error"]

        db = SessionLocal()
        try:
            repo = UserRepository(db)
            assert repo.get_by_id(me["user_id"]).display_name == "Vignesh"
            assert repo.get_by_id(me["user_id"]).username == me["username"]  # the handle never changes
            assert repo.get_by_id(other["user_id"]).display_name == "Vignesh"
        finally:
            db.close()
    finally:
        _delete_user(me["username"])
        _delete_user(other["username"])
