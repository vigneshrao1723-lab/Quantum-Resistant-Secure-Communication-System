"""
Protocol Module

Defines all packet formats used by the application.
"""

from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import PayloadType


def create_auth_packet(access_token):
    """
    Create an authentication request packet carrying the
    client's JWT access token.
    """

    return {
        "type": "auth",
        "access_token": access_token
    }


def create_auth_result_packet(
    success,
    message,
    username=None
):
    """
    Create a packet reporting the outcome of server-side
    JWT authentication.
    """

    return {
        "type": "auth_result",
        "success": success,
        "message": message,
        "username": username
    }


def create_payload_packet(
    sender,
    envelope,
    timestamp=None,
    receiver=None,
    conversation_id=None,
    epoch=None
):
    """
    Wrap an already-encrypted PayloadEnvelope for the wire.

    Transport-only: this function knows nothing about serialization
    or encryption -- envelope.ciphertext is opaque to it. This is the
    generic packet-layer entry point every payload type (text, and in
    future files, images, voice, video) uses; create_chat_packet()
    below exists only so every pre-existing text caller keeps working
    unmodified.

    Exactly one of `receiver` (a username -- direct conversation) or
    `conversation_id` (a group conversation) should be given. This is
    the addressing extension Phase 4 (Secure Group Messaging
    Foundation) adds -- a group message reuses this exact packet
    shape and "chat" type rather than a duplicate one; the server
    routes on whichever field is present.

    `epoch` (Phase 7 -- Group Membership Management): which group-key
    epoch (crypto/key_manager.py) encrypted this message -- always 1
    for a direct conversation, and for a group before its first
    rotation. Optional and additive: every existing caller that omits
    it gets `epoch: None` on the wire, which persist_message() and
    handle_chat() both already treat as 1, identical to today's
    behavior.
    """

    return {
        "type": "chat",
        "sender": sender,
        "receiver": receiver,
        "conversation_id": conversation_id,
        "message": envelope.ciphertext,
        "payload_type": envelope.payload_type,
        "content_metadata": envelope.content_metadata or None,
        "timestamp": timestamp,
        "epoch": epoch
    }


def create_chat_packet(
    sender,
    receiver,
    message,
    timestamp=None
):
    """
    Create a private chat message packet.

    A backward-compatible wrapper around create_payload_packet():
    every existing caller keeps working with its original signature
    and output shape (plus the additive fields the generic builder
    adds). `message` is wrapped into a "text" PayloadEnvelope and
    handed to the generic builder. New payload types, and group
    messaging, call create_payload_packet() directly instead of
    extending this function.
    """

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext=message,
        content_metadata={},
    )

    return create_payload_packet(sender, envelope, timestamp, receiver=receiver)


def create_group_create_packet(
    sender,
    name,
    member_usernames
):
    """
    Ask the server to create a new group conversation. No existing
    packet performs this operation, so this is genuinely new rather
    than a duplicate of anything in the payload pipeline.
    """

    return {
        "type": "group_create",
        "sender": sender,
        "name": name,
        "members": member_usernames
    }


def create_group_create_result_packet(
    conversation_id,
    name,
    creator,
    members
):
    """
    Confirm a group's creation to every currently connected member
    (including the creator), so each client's sidebar and (for the
    creator) group-key distribution can proceed.
    """

    return {
        "type": "group_create_result",
        "conversation_id": conversation_id,
        "name": name,
        "creator": creator,
        "members": members
    }


def create_group_key_distribution_packet(
    sender,
    conversation_id,
    recipient,
    encapsulation,
    wrapped_key,
    epoch=1
):
    """
    Deliver one member's wrapped copy of a group key
    (crypto/key_manager.py's wrap_key_for_member()). The server only
    ever relays this packet's opaque fields -- it never sees the
    group key itself.

    `epoch` (Phase 7 -- Group Membership Management): which epoch this
    wrapped key belongs to. Defaults to 1 -- the one existing call
    site (initial group creation) passes it explicitly, since epoch 1
    is exactly what that flow has always produced; a rotation
    (post-leave) passes the new epoch number instead.
    """

    return {
        "type": "group_key_distribution",
        "sender": sender,
        "conversation_id": conversation_id,
        "recipient": recipient,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": epoch
    }


def create_group_leave_packet(sender, conversation_id):
    """
    Ask the server to remove the sender from a group conversation
    (Phase 7 -- Group Membership Management). The server derives who
    is actually leaving from the authenticated socket, never from
    this packet's `sender` field -- it's included only for logging/
    symmetry with the other group packets, the same way `sender` is
    present-but-not-trusted on a "chat" packet.
    """

    return {
        "type": "group_leave",
        "sender": sender,
        "conversation_id": conversation_id
    }


def create_group_member_left_packet(conversation_id, username, members):
    """
    Notify every former member of a group -- both the ones remaining
    and the one who just left -- that `username` left (Phase 7 --
    Group Membership Management). One packet, two interpretations: a
    remaining recipient updates its participant list; the departed
    recipient (whose own username matches `username`) removes the
    conversation from its own view -- this doubles as that member's
    only confirmation their leave succeeded, no separate ack packet
    needed. `members` is the remaining active members' usernames.
    """

    return {
        "type": "group_member_left",
        "conversation_id": conversation_id,
        "username": username,
        "members": members
    }


def create_group_key_rotation_required_packet(conversation_id, epoch, members):
    """
    Server -> one selected, currently-connected active member: you are
    responsible for generating (or, on a retry, reusing) `epoch`'s
    group key and distributing it to `members` (Phase 7 -- Group
    Membership Management). Carries no key material -- only
    coordination metadata (conversation_id, an epoch number, and a
    list of usernames), all of which the server already legitimately
    knows. Reused unchanged for both the immediate post-leave dispatch
    and a later reconnect-triggered catch-up dispatch.
    """

    return {
        "type": "group_key_rotation_required",
        "conversation_id": conversation_id,
        "epoch": epoch,
        "members": members
    }


def create_group_key_rotation_complete_packet(conversation_id, epoch):
    """
    Client -> server: distribution of `epoch`'s group key has been
    attempted for every remaining member (Phase 7 -- Group Membership
    Management). Carries no key material. The server uses this only to
    advance conversations.confirmed_key_epoch and, if a backlog
    remains, dispatch the next epoch -- it never inspects or requires
    anything about the key itself.
    """

    return {
        "type": "group_key_rotation_complete",
        "conversation_id": conversation_id,
        "epoch": epoch
    }


def create_delivery_failure_packet(
    receiver,
    reason="User is offline."
):
    """
    Create a packet informing the sender that a private message
    could not be delivered (e.g. the recipient is not connected).
    """

    return {
        "type": "delivery_failure",
        "receiver": receiver,
        "reason": reason
    }


def create_join_packet(username):
    """
    Create a user joined packet.
    """

    return {
        "type": "join",
        "username": username
    }


def create_leave_packet(username):
    """
    Create a user left packet.
    """

    return {
        "type": "leave",
        "username": username
    }


def create_user_list_packet(users):
    """
    Create a packet containing the current
    online users.
    """

    return {
        "type": "user_list",
        "users": users
    }


def create_public_key_packet(
    username,
    algorithm,
    public_key
):
    """
    Create a public key exchange packet.
    """

    return {
        "type": "key_exchange",
        "operation": "public_key",
        "algorithm": algorithm,
        "username": username,
        "public_key": public_key
    }


def create_session_key_packet(
    sender,
    receiver,
    algorithm,
    encrypted_key
):
    """
    Create an encrypted AES session key packet.
    """

    return {
        "type": "key_exchange",
        "operation": "session_key",
        "algorithm": algorithm,
        "sender": sender,
        "receiver": receiver,
        "encrypted_key": encrypted_key
    }


def parse_packet(packet):
    """
    Return the packet as-is.

    All packets are already Python dictionaries after
    receive_message(), so no parsing is required.
    """

    return packet