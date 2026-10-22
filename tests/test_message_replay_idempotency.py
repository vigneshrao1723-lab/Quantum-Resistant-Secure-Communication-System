"""
Sending the same message twice (same ``client_message_id``) delivers it once.

A retry after a lost acknowledgement re-sends a message the server already has. It must be stored
once (it always was) AND relayed once: the server used to try to record the recipient row a second
time, which violated its unique key, logged a database error, and relayed the message again --
every recipient was shown it twice. Found by the acceptance suite's replay scenario.
"""

import uuid
from datetime import datetime, timezone

from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from tests.test_group_messaging_integration import (  # noqa: F401 -- fixtures and helpers reused
    SessionLocal,
    _create_group,
    _recv_until,
    _send,
    running_server,
    trio,
)
from utils.protocol import create_payload_packet


def _packet(sender, ciphertext, client_message_id, receiver=None, conversation_id=None):
    return create_payload_packet(
        sender=sender,
        envelope=PayloadEnvelope(payload_type=PayloadType.TEXT, ciphertext=ciphertext, content_metadata={}),
        timestamp=datetime.now(timezone.utc).isoformat(),
        receiver=receiver,
        conversation_id=conversation_id,
        client_message_id=client_message_id,
    )


def _stored(client_message_id):
    from sqlalchemy import text

    db = SessionLocal()
    try:
        return db.execute(
            text("SELECT count(*) FROM messages WHERE client_message_id = :c"), {"c": client_message_id}
        ).scalar()
    finally:
        db.close()


def _chat_packets_in_the_next_moments(sock, attempts=8):
    seen = []
    for _ in range(attempts):
        packet = _recv_until(sock, lambda p: p.get("type") == "chat", attempts=2)
        if packet is not None:
            seen.append(packet)
    return seen


def test_a_repeated_direct_message_is_stored_and_delivered_once(trio):
    sender, receiver, _third = trio["members"]
    client_message_id = str(uuid.uuid4())
    packet = _packet(sender["username"], "direct-repeat-blob", client_message_id, receiver=receiver["username"])

    _send(sender["sock"], dict(packet))
    first = _recv_until(receiver["sock"], lambda p: p.get("type") == "chat")
    assert first is not None and first["message"] == "direct-repeat-blob"

    _send(sender["sock"], dict(packet))  # the retry
    again = _chat_packets_in_the_next_moments(receiver["sock"])

    assert again == [], "the recipient was sent the repeated message again"
    assert _stored(client_message_id) == 1


def test_a_repeated_group_message_is_stored_and_delivered_once_to_every_member(trio):
    sender, member_b, member_c = trio["members"]
    conversation_id = _create_group(trio, "repeat-group")
    client_message_id = str(uuid.uuid4())
    packet = _packet(sender["username"], "group-repeat-blob", client_message_id, conversation_id=conversation_id)

    _send(sender["sock"], dict(packet))
    for member in (member_b, member_c):
        got = _recv_until(member["sock"], lambda p: p.get("type") == "chat")
        assert got is not None and got["message"] == "group-repeat-blob"

    _send(sender["sock"], dict(packet))  # the retry
    for member in (member_b, member_c):
        assert _chat_packets_in_the_next_moments(member["sock"]) == [], "a member was sent the repeat again"

    assert _stored(client_message_id) == 1

    # The sender's connection is still healthy: the next, different message reaches every member.
    _send(sender["sock"], _packet(sender["username"], "group-next-blob", str(uuid.uuid4()),
                                  conversation_id=conversation_id))
    for member in (member_b, member_c):
        nxt = _recv_until(member["sock"], lambda p: p.get("type") == "chat" and p.get("message") == "group-next-blob")
        assert nxt is not None, "a repeated group send broke the sender's connection"


def test_a_repeated_send_does_not_break_the_connection_for_the_next_message(trio):
    sender, receiver, _third = trio["members"]
    client_message_id = str(uuid.uuid4())
    packet = _packet(sender["username"], "first-blob", client_message_id, receiver=receiver["username"])
    _send(sender["sock"], dict(packet))
    _recv_until(receiver["sock"], lambda p: p.get("type") == "chat")
    _send(sender["sock"], dict(packet))

    _send(sender["sock"], _packet(sender["username"], "next-blob", str(uuid.uuid4()), receiver=receiver["username"]))

    nxt = _recv_until(receiver["sock"], lambda p: p.get("type") == "chat" and p.get("message") == "next-blob")
    assert nxt is not None
