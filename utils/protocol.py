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


def create_group_add_members_packet(sender, conversation_id, member_usernames):
    """
    Ask the server to add one or more users to an existing group
    conversation (real-application bug fix, Issue 2 -- Add Members
    After Group Creation). The server derives who is *requesting* the
    add from the authenticated socket, never from this packet's
    `sender` field -- included only for logging/symmetry with the
    other group packets, exactly like `group_leave`'s `sender` field.
    """

    return {
        "type": "group_add_members",
        "sender": sender,
        "conversation_id": conversation_id,
        "members": member_usernames
    }


def create_group_members_added_packet(conversation_id, name, members):
    """
    Notify every active member of a group -- both the ones who were
    already there and the ones just added -- of its current,
    authoritative participant list (Issue 2 -- Add Members After Group
    Creation). Sent to everyone rather than split into an "old
    members" and "new members" variant: ConversationStore.
    add_or_update_group() is already safe to call whether or not the
    recipient had this conversation before (it preserves
    latest_message if it did, creates a fresh entry if it didn't), so
    one packet shape serves both audiences with no client-side branch.
    `members` is the complete, updated active-member username list.
    """

    return {
        "type": "group_members_added",
        "conversation_id": conversation_id,
        "name": name,
        "members": members
    }


def create_read_receipt_packet(conversation_id):
    """
    Ask the server to mark every currently-unread message in
    ``conversation_id`` as read, on behalf of the authenticated
    connection (C2 -- Read Receipts). Deliberately carries no reader/
    recipient/user field at all -- the server derives who is reading
    exclusively from the authenticated socket (see
    server/client_handler.py::handle_read_receipt()), never from
    anything client-supplied, so there is nothing here a malicious
    client could forge to mark a different user's messages read.
    """

    return {
        "type": "read_receipt",
        "conversation_id": conversation_id
    }


def create_read_receipt_notification_packet(conversation_id, reader):
    """
    Server -> the other active member(s) of a conversation: `reader`
    has read up to now in `conversation_id` (C2 -- Read Receipts).
    Carries no message content, no message-id list, and no per-
    recipient status -- conversation-level "read up to now" is the
    whole signal; each recipient re-derives whatever it needs for its
    own sent-message display from what it already holds locally.
    """

    return {
        "type": "read_receipt_notification",
        "conversation_id": conversation_id,
        "reader": reader
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
    encrypted_key,
    epoch=None
):
    """
    Create an encrypted AES session key packet.

    `epoch` (direct-message key desynchronization fix): which
    server-reserved key epoch (Conversation.current_key_epoch --
    the exact same counter and ConversationRepository.reserve_next_epoch()
    Phase 7 already uses for group-key rotation, reused unchanged here)
    this session key belongs to. Optional and additive: an omitted
    epoch defaults to `None` on the wire, which handle_session_key()
    already treats as 1, identical to pre-fix behavior.
    """

    return {
        "type": "key_exchange",
        "operation": "session_key",
        "algorithm": algorithm,
        "sender": sender,
        "receiver": receiver,
        "encrypted_key": encrypted_key,
        "epoch": epoch
    }


def parse_packet(packet):
    """
    Return the packet as-is.

    All packets are already Python dictionaries after
    receive_message(), so no parsing is required.
    """

    return packet