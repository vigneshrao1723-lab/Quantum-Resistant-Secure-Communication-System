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
    conversation_id=None
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
    """

    return {
        "type": "chat",
        "sender": sender,
        "receiver": receiver,
        "conversation_id": conversation_id,
        "message": envelope.ciphertext,
        "payload_type": envelope.payload_type,
        "content_metadata": envelope.content_metadata or None,
        "timestamp": timestamp
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
    wrapped_key
):
    """
    Deliver one member's wrapped copy of a group key
    (crypto/key_manager.py's wrap_key_for_member()). The server only
    ever relays this packet's two opaque fields -- it never sees the
    group key itself.
    """

    return {
        "type": "group_key_distribution",
        "sender": sender,
        "conversation_id": conversation_id,
        "recipient": recipient,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key
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