"""
A reply points at its original by the original's stable, server-assigned id -- and only ever at a
message in the same conversation.

Real server over TLS with real authenticated connections. The recipient is shown the reference the
server actually stored, never the one the sender typed into the packet, so a sender cannot make a
recipient's client quote (or fetch, or navigate to) a message from a conversation the recipient is
not part of.
"""

import uuid
from datetime import datetime, timezone

from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType
from tests.test_duplicate_display_names import _register
from tests.test_group_messaging_integration import (  # noqa: F401 -- helpers and fixture reused
    _connect_and_authenticate,
    _delete_user,
    _recv_until,
    _send,
    running_server,
)
from utils.protocol import create_payload_packet


def _text_packet(sender, receiver, body, reply_to=None):
    return create_payload_packet(
        sender=sender,
        envelope=PayloadEnvelope(payload_type=PayloadType.TEXT, ciphertext=body, content_metadata={}),
        timestamp=datetime.now(timezone.utc).isoformat(),
        receiver=receiver,
        client_message_id=str(uuid.uuid4()),
        reply_to_message_id=reply_to,
    )


def _deliver(sender_sock, recipient_sock, packet):
    """Send ``packet`` and return the 'chat' packet the recipient was shown."""

    _send(sender_sock, packet)
    return _recv_until(recipient_sock, lambda p: p.get("type") == "chat" and p.get("message") == packet["message"])


def test_replies_resolve_only_within_their_own_conversation(running_server):
    _state, port = running_server
    alice, bob, carol = _register("ref_alice"), _register("ref_bob"), _register("ref_carol")
    socks = []
    try:
        a_sock, _ = _connect_and_authenticate(port, alice)
        b_sock, _ = _connect_and_authenticate(port, bob)
        c_sock, _ = _connect_and_authenticate(port, carol)
        socks += [a_sock, b_sock, c_sock]

        # alice -> bob: the original bob will reply to.
        original = _deliver(a_sock, b_sock, _text_packet(alice["username"], bob["username"], "the-original"))
        assert original and original.get("message_id")
        assert original.get("reply_to_message_id") is None

        # bob replies to it: alice is shown the stored reference, equal to the original's id.
        reply = _deliver(
            b_sock, a_sock,
            _text_packet(bob["username"], alice["username"], "a-reply", reply_to=original["message_id"]),
        )
        assert reply is not None
        assert reply["reply_to_message_id"] == original["message_id"]

        # A message in a DIFFERENT conversation (alice -> carol)...
        elsewhere = _deliver(a_sock, c_sock, _text_packet(alice["username"], carol["username"], "private-to-carol"))
        assert elsewhere and elsewhere.get("message_id")

        # ...cannot be named as the target of a reply to bob. The message is still delivered, but
        # the reference is dropped -- bob's client is never pointed at carol's conversation.
        crossed = _deliver(
            a_sock, b_sock,
            _text_packet(alice["username"], bob["username"], "crossed", reply_to=elsewhere["message_id"]),
        )
        assert crossed is not None, "a message with a bad reply reference must still be delivered"
        assert crossed["reply_to_message_id"] is None

        # An id that does not exist, and one that is not even an id: delivered, reference dropped.
        for bogus in (str(uuid.uuid4()), "not-a-uuid"):
            shown = _deliver(
                a_sock, b_sock,
                _text_packet(alice["username"], bob["username"], f"bogus-{bogus[:6]}", reply_to=bogus),
            )
            assert shown is not None
            assert shown["reply_to_message_id"] is None
    finally:
        for sock in socks:
            sock.close()
        for account in (alice, bob, carol):
            _delete_user(account["username"])
