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
    epoch=None,
    message_signature=None,
    sender_device_id=None,
    reply_to_message_id=None,
    client_message_id=None,
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

    `message_signature` (Message-Level ML-DSA Origin Authentication):
    base64-encoded ML-DSA signature over crypto/message_protocol.py::
    canonical_message_payload(sender, receiver, conversation_id,
    envelope.payload_type, envelope.ciphertext,
    envelope.content_metadata, epoch) -- see that module for the
    canonical construction, and client/session.py::
    _send_encrypted_payload()/handle_chat() for where it is produced
    and verified. Optional and additive, exactly like Phase 11's
    signing_public_key/identity_signature fields on the identity
    packet: omitted (None) by any caller built before this phase
    existed. handle_chat() rejects a "chat" packet with no
    message_signature at all -- there is no legacy unsigned message
    path, unlike the identity packet's (see this phase's own audit of
    why an unsigned identity-establishment path was allowed to remain
    for defense-in-depth reasons that do not apply here: a message
    packet never establishes trust, so there is nothing for an unsigned
    one to legitimately do).
    """

    packet = {
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

    if message_signature is not None:
        packet["message_signature"] = message_signature

    # Phase 16D -- Device-Aware Peer Identity: optional, additive,
    # transport-level ONLY -- deliberately not part of
    # crypto/message_protocol.py::canonical_message_payload()'s signed
    # fields, so no cryptographic primitive changes at all. Tells a
    # device-aware receiver WHICH of the sender's devices signed this
    # message, so it can resolve the matching (username, device_id)
    # trust-state slot (see client/session.py::_peer_identity_key())
    # instead of the single account-level slot. Since this field is
    # never itself trusted -- the ML-DSA signature is still verified
    # against whatever key gets resolved -- an attacker tampering with
    # it in transit can only ever cause a fail-closed rejection
    # (resolving the wrong/no key), never a false acceptance. Omitted
    # by every pre-existing caller.
    if sender_device_id is not None:
        packet["sender_device_id"] = sender_device_id

    # Phase 19.24 -- Message Lifecycle Events: REPLY. The logical
    # message this one replies to -- addressed by message_id alone
    # (never a client-claimed conversation_id/receiver pairing), the
    # same "resolve message_id -> conversation_id -> membership
    # server-side" pattern create_blob_download_request_packet()
    # already established. Optional and additive; every pre-existing
    # caller omits it.
    if reply_to_message_id is not None:
        packet["reply_to_message_id"] = reply_to_message_id

    # Phase 19.24 -- Message Lifecycle Events: RETRY idempotency. An
    # optional client-generated UUID a sender attaches so persist_
    # message() can recognize a retried send as the SAME message
    # rather than creating a duplicate (see database/models/message.py
    # ::client_message_id's own docstring). Optional and additive.
    if client_message_id is not None:
        packet["client_message_id"] = client_message_id

    return packet


def create_chat_packet(
    sender,
    receiver,
    message,
    timestamp=None,
    message_signature=None,
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

    `message_signature` (Message-Level ML-DSA Origin Authentication):
    passed straight through to create_payload_packet() -- see its own
    docstring. Optional and additive, exactly like every other
    parameter this wrapper already forwards.
    """

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT,
        ciphertext=message,
        content_metadata={},
    )

    return create_payload_packet(
        sender, envelope, timestamp, receiver=receiver,
        message_signature=message_signature,
    )


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
    epoch=1,
    group_key_signature=None,
):
    """
    Deliver one member's wrapped copy of a group key
    (crypto/key_manager.py's wrap_key_for_member()). The server only
    ever relays this packet's opaque fields -- it never sees the
    group key itself.

    Authorization (D6 -- Key Distribution Authorization): the relay is
    no longer unconditional. The server requires the authenticated
    sender to be an active member of `conversation_id`, and requires
    `recipient` to be an active member of that same conversation,
    before forwarding anything -- see server/client_handler.py::
    handle_group_key_distribution(). `sender` is present for logging/
    symmetry only and is NOT trusted: the server overwrites it with
    the authenticated username before relay, exactly as it already
    does for a "chat" and a direct "session_key" packet. Rejections
    are silent (server-side log only). The packet's field shape is
    unchanged.

    `epoch` (Phase 7 -- Group Membership Management): which epoch this
    wrapped key belongs to. Defaults to 1 -- the one existing call
    site (initial group creation) passes it explicitly, since epoch 1
    is exactly what that flow has always produced; a rotation
    (post-leave) passes the new epoch number instead.

    `group_key_signature` (Group-Key-Distribution ML-DSA Origin
    Authentication): base64-encoded ML-DSA signature over crypto/
    group_key_protocol.py::canonical_group_key_payload(sender,
    conversation_id, recipient, encapsulation, wrapped_key, epoch) --
    see that module for the canonical construction, and client/
    session.py::_distribute_group_key()/handle_group_key_distribution()
    for where it is produced and verified. Optional and additive,
    exactly like Phase 11's identity-packet fields and Phase 12B's
    message_signature field. handle_group_key_distribution() rejects a
    packet with no group_key_signature at all -- there is no legacy
    unsigned path for group-key material, for the same reason Phase
    12B gave ordinary messages none: this packet only ever installs
    trust, it never itself needs a defense-in-depth mismatch-detection
    fallback the way the identity-announcement packet's legacy branch
    does.
    """

    packet = {
        "type": "group_key_distribution",
        "sender": sender,
        "conversation_id": conversation_id,
        "recipient": recipient,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": epoch
    }

    if group_key_signature is not None:
        packet["group_key_signature"] = group_key_signature

    return packet


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


def create_direct_key_recovery_available_packet(conversations):
    """
    Server -> a reconnecting client: these are the DIRECT
    conversations you can read, and the key epochs their stored
    messages are encrypted under (BUG 4 -- Fix B).

    ``conversations`` is a list of {"conversation_id": str, "epochs":
    [int, ...]}. Coordination metadata only -- conversation ids and
    epoch numbers, both of which the server already tracks; no key
    material, and nothing the recipient is not already authorized to
    read (the same conversation-membership rule that governs message
    history).

    This exists so the CLIENT can decide what it actually needs.
    Whether a given epoch's key is already cached is knowledge only
    the client has -- the server holds no keys and therefore cannot
    tell a client that has just restarted from one that never left.
    Announcing what is available and letting the client ask for the
    subset it lacks is what keeps a reconnect from re-wrapping and
    re-sending every historical key every time.
    """

    return {
        "type": "direct_key_recovery_available",
        "conversations": conversations
    }


def create_direct_key_recovery_request_packet(conversation_id, epochs):
    """
    Client -> server: I am missing these epochs for this direct
    conversation; please ask a partner who has them to send them
    (BUG 4 -- Fix B).

    Carries no key material and no identity: the server derives the
    requester exclusively from the authenticated connection (see
    server/client_handler.py::handle_direct_key_recovery_request()),
    so there is nothing here for a malicious client to forge in order
    to obtain someone else's keys. The conversation and the epochs it
    names are both verified server-side before anything is dispatched.
    """

    return {
        "type": "direct_key_recovery_request",
        "conversation_id": conversation_id,
        "epochs": epochs
    }


def create_direct_key_redelivery_required_packet(conversation_id, epoch, recipient):
    """
    Server -> the currently-connected partner of a DIRECT conversation:
    ``recipient`` has just reconnected and is holding queued messages
    encrypted under ``epoch``; if you still have that exact epoch's
    key, hand them a wrapped copy (BUG 4 -- Fix B, direct key
    recovery). Carries no key material -- only coordination metadata
    (conversation_id, an epoch number, one username), all of which the
    server already legitimately knows.

    Deliberately NOT create_group_key_rotation_required_packet() reused
    under a new name, even though the two are shaped alike. That packet
    instructs its receiver to GENERATE a key when it doesn't have the
    epoch (see ClientSession.handle_group_key_rotation_required()'s
    os.urandom(32) branch), which is exactly the wrong thing to do
    here: a freshly generated key cannot decrypt ciphertext that
    already exists, so inventing one would leave the recipient holding
    a key that authenticates nothing while the real messages stay
    unreadable -- and, because KeyManager tracks the current epoch with
    max(), would additionally poison both sides' notion of the current
    key. The handler for this packet redelivers an existing key or
    does nothing at all.

    ``epoch`` is the epoch the queued MESSAGES were encrypted under
    (messages.epoch), never the conversation's current epoch -- a
    direct conversation accumulates a new epoch every time either side
    establishes a key with an empty KeyManager, so "current" is
    routinely NOT the epoch an older queued message needs.
    """

    return {
        "type": "direct_key_redelivery_required",
        "conversation_id": conversation_id,
        "epoch": epoch,
        "recipient": recipient
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


def create_typing_indicator_packet(conversation_id, is_typing):
    """
    Tell the server this account is (or has just stopped) typing in
    ``conversation_id`` (Phase 19.24 -- Typing Indicator). Deliberately
    carries no sender field -- mirrors create_read_receipt_packet()'s
    identical pattern: the server derives who exclusively from the
    authenticated socket (see server/client_handler.py::
    handle_typing_indicator()), never from anything client-supplied.

    Purely a live, ephemeral hint -- never persisted anywhere, on
    either side, and never replayed via message_history_request. A
    client that never sees the matching is_typing=False (e.g. the
    sender's connection drops mid-type) is expected to age the
    indicator out locally after a short timeout, exactly like a real
    messaging app; the server itself does not track or expire this
    state either.
    """

    return {
        "type": "typing_indicator",
        "conversation_id": conversation_id,
        "is_typing": bool(is_typing),
    }


def create_typing_indicator_notification_packet(conversation_id, username, is_typing):
    """
    Server -> the other active member(s) of a conversation: `username`
    has started (or stopped) typing in `conversation_id` (Phase 19.24
    -- Typing Indicator). Mirrors create_read_receipt_notification_
    packet()'s shape; never sent back to the actor's own socket (see
    handle_typing_indicator()'s own docstring for why).
    """

    return {
        "type": "typing_indicator_notification",
        "conversation_id": conversation_id,
        "username": username,
        "is_typing": bool(is_typing),
    }


def create_user_lookup_request_packet(user_id):
    """
    Ask the server to look up a user by their unique ID (D2 -- Server-
    Side API / Authentication Migration; migrates the read
    ClientSession.find_user_by_id() previously performed directly
    against PostgreSQL onto this request/response pair instead).
    Carries only the id being searched for -- who is asking is derived
    from the authenticated socket server-side, matching every other
    request handler in server/client_handler.py. Correlated via D1's
    request_id mechanism, attached by ClientSession.send_request()
    itself -- never set here.
    """

    return {
        "type": "user_lookup_request",
        "user_id": user_id
    }


def create_user_lookup_by_phone_request_packet(phone_number):
    """
    Ask the server to find a user by their phone number (BUG 7 --
    phone-based user discovery).

    Additive: create_user_lookup_request_packet() above is unchanged
    and still resolves by UUID, which internal callers and every
    existing test continue to use. This variant carries an explicit
    identifier_type so the server never has to guess what a string is
    -- the previous design assumed every identifier was a UUID and
    fed it straight to uuid.UUID().

    The phone number is sent as the user typed it; the server
    normalises it through security/phone_number.py before looking it
    up, so the client cannot bypass canonicalisation and the two sides
    can only ever agree on what a number means.

    Answered by the same user_lookup_result packet, so the response
    shape and its deliberately minimal field set are unchanged.
    """

    return {
        "type": "user_lookup_request",
        "identifier_type": "phone",
        "identifier": phone_number
    }


def create_user_lookup_result_packet(
    request_id,
    user_id=None,
    username=None,
    display_name=None
):
    """
    Server -> client: the result of a user_lookup_request (D2). A
    match returns exactly the same minimal projection
    ClientSession.find_user_by_id() has always returned -- user_id,
    username, display_name -- deliberately never email, password
    hash, or any other User field. No match (a well-formed id that
    doesn't exist) leaves every field None, matching
    find_user_by_id()'s existing contract of not letting a caller
    distinguish a malformed guess from a well-formed-but-nonexistent
    one. request_id is echoed from the request so
    ClientSession.send_request()'s pending correlation resolves.
    """

    return {
        "type": "user_lookup_result",
        "request_id": request_id,
        "user_id": user_id,
        "username": username,
        "display_name": display_name
    }


def create_register_request_packet(
    full_name,
    username,
    email,
    phone_number,
    password,
    confirm_password
):
    """
    Ask the server to register a new user account (D2 -- Server-Side
    API / Authentication Migration; migrates registration off its
    previous direct-PostgreSQL client-side implementation in
    gui/main_window.py). Sent on a connection that has not
    authenticated and never will for this operation -- there is no
    user yet to authenticate as. Carries the same fields
    auth.schemas.RegisterRequest already defines; the server performs
    exactly the same validation (AuthenticationService.register_user(),
    unchanged) it always would have, just now over the wire instead of
    via direct client-side DB access. request_id is attached by
    ClientSession.send_request() itself, never set here.
    """

    return {
        "type": "register_request",
        "full_name": full_name,
        "username": username,
        "email": email,
        # BUG 7 -- mandatory discovery identifier; the server
        # normalises and enforces uniqueness.
        "phone_number": phone_number,
        "password": password,
        "confirm_password": confirm_password
    }


def create_register_result_packet(
    request_id,
    success,
    message,
    user_id=None,
    errors=None
):
    """
    Server -> client: the result of a register_request (D2). Mirrors
    auth.schemas.RegistrationResult's own shape exactly (success,
    message, user_id, errors) so the client can reconstruct one
    without any new client-side validation logic. request_id is
    echoed from the request so ClientSession.send_request()'s pending
    correlation resolves.
    """

    return {
        "type": "register_result",
        "request_id": request_id,
        "success": success,
        "message": message,
        "user_id": user_id,
        "errors": errors
    }


def create_login_request_packet(identifier, password):
    """
    Ask the server to authenticate a username/email + password (D2 --
    Server-Side API / Authentication Migration; final slice, migrating
    login off its previous direct-PostgreSQL client-side implementation
    in gui/main_window.py and client/client.py). Sent on a connection
    that has not authenticated yet -- there is no JWT to present until
    this succeeds. Carries only what auth.schemas.LoginRequest's two
    callers here have ever actually populated (identifier, password);
    device/platform metadata is left to a future caller that needs it,
    exactly as before this migration. request_id is attached by the
    caller itself (mirrors create_register_request_packet() -- this
    also runs before any receiver thread exists, so
    ClientSession.send_request() is not used here either).
    """

    return {
        "type": "login_request",
        "identifier": identifier,
        "password": password
    }


def create_login_result_packet(
    request_id,
    success,
    message,
    phone_number=None,
    user_id=None,
    username=None,
    role=None,
    session_id=None,
    access_token=None,
    refresh_token=None,
    expires_in=None,
    token_type=None,
    errors=None
):
    """
    Server -> client: the result of a login_request (D2). Mirrors
    auth.schemas.AuthenticationResult's shape exactly, with TokenPair's
    fields flattened in rather than nested -- every packet in this
    protocol is a flat dict, and the client reconstructs both
    dataclasses from these fields (see ClientSession.
    authenticate_credentials()). Deliberately carries nothing beyond
    what AuthenticationResult itself already exposes -- never a
    password hash or any other internal User field. request_id is
    echoed from the request for symmetry with every other *_result
    packet, though this one is read synchronously rather than via D1's
    correlation (see create_login_request_packet()).
    """

    return {
        "type": "login_result",
        "request_id": request_id,
        "success": success,
        "message": message,
        "user_id": user_id,
        "username": username,
        # BUG 7 (7.5) -- the identifier other users search by. Returned
        # so the client can display it back to its own owner; it is the
        # authenticated user's own number, never another account's.
        "phone_number": phone_number,
        "role": role,
        "session_id": session_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "token_type": token_type,
        "errors": errors
    }


def create_logout_request_packet():
    """
    Ask the server to revoke this connection's session (D2 -- Server-
    Side API / Authentication Migration; final slice, migrating logout
    off its previous direct-PostgreSQL client-side implementation).
    Sent on the already-authenticated connection -- unlike
    register_request/login_request, this carries no identity fields at
    all: which session to revoke is derived server-side from the
    authenticated connection/state (see server/client_handler.py::
    handle_logout_request()), never from anything client-supplied, so
    there is nothing here a malicious client could forge to log out a
    different session.
    """

    return {
        "type": "logout_request"
    }


def create_logout_result_packet(request_id, success, message):
    """
    Server -> client: the result of a logout_request (D2). Echoes
    request_id so ClientSession.send_request()'s pending correlation
    resolves -- unlike login/register, logout runs on the already-
    authenticated connection with the receiver thread already running,
    so it uses D1's normal request/response path.
    """

    return {
        "type": "logout_result",
        "request_id": request_id,
        "success": success,
        "message": message
    }


def create_direct_conversation_request_packet(username):
    """
    Ask the server to get-or-create the direct conversation with
    ``username`` (D3.3 -- Conversation Operations Migration). This is
    the request/response counterpart to what D3.1 already resolves
    automatically ahead of a direct chat/session_key relay -- used for
    the one remaining case that isn't triggered by an incoming packet:
    ClientSession.set_current_chat() opening a chat with someone never
    messaged before. Carries only the partner's username -- who the
    caller itself is comes from the authenticated connection
    server-side, never from this packet. request_id is attached by
    ClientSession.send_request() itself, never set here.
    """

    return {
        "type": "direct_conversation_request",
        "username": username
    }


def create_direct_conversation_result_packet(
    request_id,
    conversation_id=None,
    error=None
):
    """
    Server -> client: the result of a direct_conversation_request
    (D3.3). ``conversation_id`` is set on success; ``error`` is set
    (and conversation_id left None) if the given username doesn't
    resolve to a real user -- mirrors ConversationStore.
    ensure_direct_conversation_id()'s existing "unknown user" contract
    (a raised ValueError), now surfaced as a field over the wire
    instead of a local exception. request_id is echoed from the
    request so ClientSession.send_request()'s pending correlation
    resolves.
    """

    return {
        "type": "direct_conversation_result",
        "request_id": request_id,
        "conversation_id": conversation_id,
        "error": error
    }


def create_epoch_reservation_request_packet(conversation_id):
    """
    Ask the server to reserve the next key epoch for a direct
    conversation, before establishing a fresh AES session key (D4.1 --
    Message/History Operations Migration, first slice). Replaces
    ClientSession.establish_session_key()'s previous direct, client-
    side ConversationRepository.reserve_next_epoch() call -- the last
    remaining client-side database write anywhere in direct-
    conversation key establishment. Carries only the conversation_id
    being keyed -- who the caller is comes from the authenticated
    connection server-side, never from this packet. request_id is
    attached by ClientSession.send_request() itself, never set here.
    """

    return {
        "type": "epoch_reservation_request",
        "conversation_id": conversation_id
    }


def create_epoch_reservation_result_packet(
    request_id,
    epoch=None,
    error=None
):
    """
    Server -> client: the result of an epoch_reservation_request
    (D4.1). ``epoch`` is set on success; ``error`` is set (and epoch
    left None) if conversation_id is missing/malformed or the
    authenticated caller is not currently a member of that
    conversation -- mirrors create_direct_conversation_result_packet()'s
    identical success/error shape. request_id is echoed from the
    request so ClientSession.send_request()'s pending correlation
    resolves.
    """

    return {
        "type": "epoch_reservation_result",
        "request_id": request_id,
        "epoch": epoch,
        "error": error
    }


def create_conversation_list_request_packet():
    """
    Ask the server for every conversation the authenticated caller
    currently belongs to (D4.2 -- Message/History Operations
    Migration, second slice). Replaces ClientSession.
    load_conversations()'s previous direct, client-side
    ConversationRepository.get_conversation_previews_for_user() call --
    the last remaining client-side database read for the sidebar's
    initial population. Carries no fields at all -- which user's
    conversations to return comes entirely from the authenticated
    connection server-side, mirroring create_logout_request_packet()'s
    identical "nothing here a malicious client could forge" shape.
    request_id is attached by ClientSession.send_request() itself,
    never set here.
    """

    return {
        "type": "conversation_list_request"
    }


def create_conversation_list_result_packet(request_id, conversations):
    """
    Server -> client: the result of a conversation_list_request
    (D4.2). ``conversations`` is a list of plain dicts, one per
    conversation the caller belongs to, each shaped to carry exactly
    what ClientSession.load_conversations()/_build_latest_message_preview()
    need to reconstruct a ConversationSummary/MessagePreview --
    everything ConversationRepository.get_conversation_previews_for_user()
    already returned as ORM rows, now serialized:
    {conversation_id, is_group, group_name, participants,
    latest_message: {payload_type, ciphertext, epoch, timestamp,
    content_metadata} | None}. ``ciphertext``/``content_metadata`` stay
    exactly as opaque here as they were as a direct database read --
    decryption remains entirely client-side; nothing here is
    decrypted, inspected, or altered by the server. request_id is
    echoed from the request so ClientSession.send_request()'s pending
    correlation resolves.
    """

    return {
        "type": "conversation_list_result",
        "request_id": request_id,
        "conversations": conversations
    }


def create_message_history_request_packet(conversation_id, is_group):
    """
    Ask the server for a conversation's full stored message history
    (D4.3 -- Message/History Operations Migration, third slice).
    Replaces ClientSession.load_conversation_history()'s previous
    direct, client-side MessageRepository/ConversationRepository/
    UserRepository reads. Addressed explicitly by conversation_id
    (never a username, unlike D3.3's direct_conversation_request) --
    the caller is expected to already have resolved it, via
    set_current_chat(), before opening a conversation's history.
    ``is_group`` only shapes which repository query the server runs
    and how read-status is filtered -- it carries no authorization
    weight of its own; membership is checked independently of it. Who
    the caller is comes from the authenticated connection server-side,
    never from this packet. request_id is attached by ClientSession.
    send_request() itself, never set here. No pagination -- the full
    history is returned in one response, exactly matching this
    codebase's existing behavior (no LIMIT/OFFSET exists anywhere in
    the repository layer today).
    """

    return {
        "type": "message_history_request",
        "conversation_id": conversation_id,
        "is_group": is_group
    }


def create_message_history_result_packet(request_id, messages=None, error=None):
    """
    Server -> client: the result of a message_history_request (D4.3).
    ``messages`` is a list of plain dicts, one per stored message,
    ordered exactly as MessageRepository.get_conversation()/
    get_group_conversation() already order them: {message_id, sender,
    timestamp, is_own, payload_type, epoch, ciphertext, blob_ref,
    content_metadata, read_status}. ``ciphertext`` is only ever this
    already-encrypted, opaque value -- decryption stays entirely
    client-side; the server never decrypts historical ciphertext.
    ``blob_ref`` is metadata only (Option A -- lazy blob delivery): a
    FILE/IMAGE message's actual encrypted content is never embedded
    here, only its reference -- the client fetches it separately via
    blob_download_request, on demand, exactly mirroring where
    ensure_direct_conversation_id()/_load_blob_history_content() used
    to read it directly from local blob storage. request_id is echoed
    from the request so ClientSession.send_request()'s pending
    correlation resolves.
    """

    return {
        "type": "message_history_result",
        "request_id": request_id,
        "messages": messages,
        "error": error
    }


def create_blob_download_request_packet(message_id):
    """
    Ask the server for one historical FILE/IMAGE message's encrypted
    blob content (D4.3 -- Message/History Operations Migration, third
    slice; Option A -- lazy blob delivery), following up a
    message_history_request/result that reported only the message's
    blob_ref, never its content. Addressed by message_id, not blob_ref
    -- blob_ref is an opaque storage-backend filename with no
    queryable link to a conversation, so it cannot be authorized
    directly; the server resolves message_id -> conversation_id ->
    membership itself (see handle_blob_download_request()), never
    trusting anything the client claims about which conversation a
    message belongs to. request_id is attached by ClientSession.
    send_request() itself, never set here.
    """

    return {
        "type": "blob_download_request",
        "message_id": message_id
    }


def create_blob_download_result_packet(request_id, ciphertext=None, error=None):
    """
    Server -> client: the result of a blob_download_request (D4.3).
    ``ciphertext`` is the same base64 string
    storage.encrypted_blob_store.load_blob() already produces --
    opaque, already-encrypted, never decrypted or inspected server-
    side; decryption remains entirely client-side, exactly as it was
    when the client read this same blob directly off local storage.
    ``error`` is set (and ciphertext left None) if message_id is
    missing/malformed, the message doesn't exist, the caller isn't a
    member of its conversation, or the message has no attachment --
    the first three are deliberately indistinguishable from each
    other on the wire (mirroring this codebase's existing "don't let
    an error message reveal which guess was closer" convention); the
    fourth is safe to report distinctly since it is only ever reached
    after authorization has already succeeded. request_id is echoed
    from the request so ClientSession.send_request()'s pending
    correlation resolves.
    """

    return {
        "type": "blob_download_result",
        "request_id": request_id,
        "ciphertext": ciphertext,
        "error": error
    }


def create_delivery_failure_packet(
    receiver,
    reason="User is offline.",
    message_id=None,
):
    """
    Create a packet informing the sender that a private message
    could not be delivered (e.g. the recipient is not connected).

    ``message_id`` (Phase 19.14 -- Message Status Ticks): optional,
    added additively -- only set at the one call site where the
    message was actually persisted before the failure was detected
    (server/client_handler.py's live-relay branch); the earlier
    "could not even be persisted" failure path has no message row to
    reference and correctly leaves this None. A client showing a
    per-message error tick falls back to marking its most recently
    sent, still-pending message to ``receiver`` when this is None,
    exactly as it already had to before this field existed.
    """

    return {
        "type": "delivery_failure",
        "receiver": receiver,
        "reason": reason,
        "message_id": message_id,
    }


def create_message_delivered_packet(receiver, message_id, conversation_id=None):
    """
    Server -> sender (Phase 19.14 -- Message Status Ticks): a direct
    message was just relayed live to at least one of ``receiver``'s
    currently-connected devices (server/client_handler.py's
    "delivered_to_any_device" branch, which already promotes the
    MessageRecipient row to DELIVERED -- this packet is the one thing
    that branch was previously missing: telling the SENDER it
    happened at all). Before this phase, a live-delivered message and
    one still in flight looked identical to the sender -- there was no
    positive delivered signal, only the negative ones (delivery_
    failure/message_queued) for the two cases where delivery did NOT
    happen live. Reusing MessageDeliveryStatus.DELIVERED as this
    packet's implicit meaning, not inventing a new status.
    """

    return {
        "type": "message_delivered",
        "receiver": receiver,
        "message_id": message_id,
        "conversation_id": conversation_id,
    }


def create_message_queued_packet(receiver, message_id=None, conversation_id=None):
    """
    Server -> sender: the recipient is a real, registered user who is
    not connected right now, and their message has been safely
    persisted as ciphertext for later delivery (BUG 4 -- Fix A).

    This is a SUCCESS response, and the distinction from
    create_delivery_failure_packet() is the whole point of it. The
    server has stored offline direct messages since C1, but still
    answered with delivery_failure -- so the sender's GUI raised an
    error for a message that was, in fact, safely saved. "Not relayed
    live at this instant" and "not delivered, do something about it"
    are different facts and now have different packets.

    delivery_failure keeps its original meaning exactly, for the cases
    that really are failures: a recipient who does not exist at all,
    and a persistence attempt that genuinely failed.

    Deliberately NOT a claim of delivery. The recipient's
    MessageRecipient row stays QUEUED (never DELIVERED) until the
    message is actually relayed to them -- see
    server/client_handler.py::_record_direct_recipient().
    """

    return {
        "type": "message_queued",
        "receiver": receiver,
        "message_id": message_id,
        "conversation_id": conversation_id
    }


# ======================================================================
# Phase 19.24 -- Message Lifecycle Events (edit/delete/reactions).
#
# Every event below is addressed by message_id alone (never a client-
# claimed conversation_id/receiver pairing) -- the server always
# resolves message_id -> conversation_id -> membership/authorization
# itself (see server/client_handler.py::handle_message_edit() et al.),
# the same pattern create_blob_download_request_packet() already
# established. None of these packets ever carry a client-supplied
# "actor"/"editor"/"deleted_by" field on the REQUEST side -- the
# server derives the actor exclusively from the authenticated socket,
# exactly like create_read_receipt_packet() already does. The actor
# only ever appears on the NOTIFICATION (server -> other clients) side,
# where it is the server's own, already-authenticated answer.
# ======================================================================


def create_message_edit_packet(message_id, envelope, epoch, message_signature, expected_edit_version):
    """
    Client -> server: re-encrypt this message's content in place.

    ``envelope``/``epoch``/``message_signature`` are produced exactly
    like a live "chat" send (see create_payload_packet()) -- an edit is
    authenticated/signed content, not a bare string. ``expected_edit_
    version`` is this client's last-known edit_version for the message
    (0 for a never-edited message) -- server/client_handler.py::
    handle_message_edit() rejects the edit if the row's actual
    edit_version has since moved past it (a concurrent edit from
    another of the sender's own devices, or a stale/replayed/duplicate
    packet), rather than silently overwriting a newer edit with an
    older one.
    """

    return {
        "type": "message_edit",
        "message_id": message_id,
        "ciphertext": envelope.ciphertext,
        "content_metadata": envelope.content_metadata or None,
        "epoch": epoch,
        "message_signature": message_signature,
        "expected_edit_version": expected_edit_version,
    }


def create_message_edited_notification_packet(
    message_id, conversation_id, ciphertext, content_metadata, epoch,
    message_signature, editor, edited_at, edit_version,
):
    """
    Server -> every conversation member (including the editor's OTHER
    authorized devices -- multi-device sync): the accepted result of a
    message_edit. ``editor`` is the server's own authenticated answer
    (always equal to the message's original sender -- see handle_
    message_edit()'s docstring for why no broader edit-authorization
    policy exists), never echoed from the request.
    """

    return {
        "type": "message_edited",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "ciphertext": ciphertext,
        "content_metadata": content_metadata,
        "epoch": epoch,
        "message_signature": message_signature,
        "editor": editor,
        "edited_at": edited_at,
        "edit_version": edit_version,
    }


def create_message_delete_for_me_packet(message_id):
    """
    Client -> server: hide this message from the requesting user only
    (database/models/message_hidden_for_user.py). Carries no other
    field -- the actor is always the authenticated socket.
    """

    return {"type": "message_delete_for_me", "message_id": message_id}


def create_message_delete_for_everyone_packet(message_id):
    """
    Client -> server: request REAL, authorized global deletion of this
    message's content (server/client_handler.py::handle_message_
    delete_for_everyone()). Carries no actor field -- the server
    re-derives the original sender from the stored row and rejects
    unless the authenticated socket IS that sender.
    """

    return {"type": "message_delete_for_everyone", "message_id": message_id}


def create_message_deleted_notification_packet(message_id, conversation_id, deleted_by, deleted_at):
    """
    Server -> every conversation member (including the deleter's other
    devices): a message_delete_for_everyone was accepted. Never carries
    ciphertext/content -- there is none left server-side by the time
    this is sent (handle_message_delete_for_everyone() nulls it in the
    same transaction). ``deleted_by`` is the server's own authenticated
    answer, for UI attribution ("You deleted this message" vs. "<name>
    deleted this message").
    """

    return {
        "type": "message_deleted",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "deleted_by": deleted_by,
        "deleted_at": deleted_at,
    }


def create_reaction_add_packet(message_id, envelope, epoch, message_signature=None):
    """
    Client -> server: set/replace the requesting user's reaction on
    this message. ``envelope`` is the AES-256-GCM-encrypted reaction
    string (payload/reaction_adapter.py) under the conversation's
    current epoch key -- the server persists ciphertext only and never
    learns which reaction was chosen (see database/models/
    message_reaction.py's own docstring).

    ``message_signature`` (continued Phase 19.24 -- receiver-side
    verification): base64-encoded ML-DSA-65 signature over crypto/
    message_protocol.py::canonical_message_payload(..., purpose=
    REACTION_PAYLOAD_PURPOSE) -- lets the RECEIVING client verify this
    reaction's origin independently of trusting the server's own
    authorization check, exactly like an ordinary chat message.
    Optional only for backward compatibility with a caller that
    predates this addition; every real caller now supplies it.
    """

    packet = {
        "type": "reaction_add",
        "message_id": message_id,
        "ciphertext": envelope.ciphertext,
        "epoch": epoch,
    }
    if message_signature is not None:
        packet["message_signature"] = message_signature
    return packet


def create_reaction_remove_packet(message_id):
    """Client -> server: remove the requesting user's reaction (if
    any) from this message. No ciphertext -- there is nothing left to
    encrypt once removed."""

    return {"type": "reaction_remove", "message_id": message_id}


def create_reaction_updated_notification_packet(
    message_id, conversation_id, actor, action, ciphertext=None, epoch=None,
    message_signature=None,
):
    """
    Server -> every conversation member: a reaction_add or
    reaction_remove was accepted. ``action`` is "add" or "remove".
    ``actor`` is the server's own authenticated answer -- who reacted,
    never a client-supplied field. ``ciphertext``/``epoch``/
    ``message_signature`` are present only for "add" (all None for
    "remove", since there is nothing to decrypt or verify).
    ``message_signature`` is relayed through unchanged from the
    original reaction_add packet -- the server never generates or
    checks it itself, exactly like an ordinary chat message's
    signature; verification is the RECEIVING client's job (see
    ClientSession.handle_reaction_updated()).
    """

    return {
        "type": "reaction_updated",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "actor": actor,
        "action": action,
        "ciphertext": ciphertext,
        "epoch": epoch,
        "message_signature": message_signature,
    }


def create_message_pin_packet(message_id):
    """
    Client -> server: pin ``message_id`` for every member of its
    conversation (Phase 19.24 -- Pinned Messages). No ciphertext/epoch/
    signature -- unlike reaction_add, there is no content of its own
    here to protect or verify; see database/models/message.py::
    pinned_at/pinned_by's own docstring for the full trust-model
    rationale (attribution is server-derived from the authenticated
    connection, exactly like deleted_by already is).
    """

    return {"type": "message_pin", "message_id": message_id}


def create_message_unpin_packet(message_id):
    """Client -> server: unpin ``message_id``, if currently pinned."""

    return {"type": "message_unpin", "message_id": message_id}


def create_message_pinned_notification_packet(
    message_id, conversation_id, pinned_by, pinned_at,
):
    """
    Server -> every conversation member: ``message_id`` was pinned.
    ``pinned_by`` is the server's own authenticated answer (a
    username), never a client-supplied field.
    """

    return {
        "type": "message_pinned",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "pinned_by": pinned_by,
        "pinned_at": pinned_at,
    }


def create_message_unpinned_notification_packet(message_id, conversation_id, unpinned_by):
    """Server -> every conversation member: ``message_id`` was
    unpinned. ``unpinned_by`` is who performed the unpin (server-
    derived), kept for logging/attribution parity with the pin
    notification even though most UIs will simply drop the row."""

    return {
        "type": "message_unpinned",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "unpinned_by": unpinned_by,
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
    public_key,
    signing_public_key=None,
    identity_signature=None,
    device_id=None,
):
    """
    Create a public key exchange packet.

    ``signing_public_key``/``identity_signature`` (Protocol-Level
    ML-DSA Origin Authentication): optional and additive. When present,
    they carry this sender's base64-encoded ML-DSA-65 public key and
    its ML-DSA signature over crypto/identity_protocol.py::
    canonical_identity_payload(username, public_key, signing_public_key)
    -- see that module for the canonical construction, and
    client/session.py::send_public_key()/handle_public_key() for where
    they are produced and verified. Omitted (None) by every pre-
    existing caller that built this packet before this phase existed,
    which keeps constructing exactly the legacy, unsigned packet shape
    -- ClientSession.handle_public_key() treats the absence of
    ``signing_public_key`` as "legacy packet, use the existing KEM-only
    path", not as an error.

    ``device_id`` (Phase 16D -- Device-Aware Peer Identity): optional
    and additive, and deliberately NOT part of the ML-DSA-signed
    identity payload above -- it is transport metadata only, telling a
    device-aware receiver WHICH of this account's devices this
    identity belongs to (see client/session.py::_peer_identity_key()),
    never a claim the receiver is asked to cryptographically trust on
    its own. Omitted by every pre-existing caller (a session that has
    never called enroll_device(), which is every one of this
    codebase's pre-16D regression tests), which keeps constructing the
    exact same packet shape as before.
    """

    packet = {
        "type": "key_exchange",
        "operation": "public_key",
        "algorithm": algorithm,
        "username": username,
        "public_key": public_key
    }

    if signing_public_key is not None:
        packet["signing_public_key"] = signing_public_key

    if identity_signature is not None:
        packet["identity_signature"] = identity_signature

    if device_id is not None:
        packet["device_id"] = device_id

    return packet


def create_session_key_packet(
    sender,
    receiver,
    algorithm,
    encrypted_key,
    epoch=None,
    conversation_id=None,
    session_key_signature=None,
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

    `conversation_id` (RSA Direct-Session-Key ML-DSA Origin
    Authentication, Phase 13.6): the sender's own, locally-resolved
    direct-conversation id -- the same value bound into
    `session_key_signature` below. Optional and additive: server/
    client_handler.py's own, pre-existing D3.1 hardening still
    overwrites this field with its own server-side resolution
    (`_resolve_direct_conversation_id(sender_id, recipient_id)`)
    before relay, exactly as before Phase 13.6 -- never trusting a
    client-supplied value for THAT purpose. Sending it here too is
    what lets the receiver's signature check independently confirm the
    server's resolution agrees with what the sender actually signed;
    it does not replace or weaken the server-side check.

    `session_key_signature` (RSA Direct-Session-Key ML-DSA Origin
    Authentication, Phase 13.6): base64-encoded ML-DSA signature over
    crypto/session_key_protocol.py::canonical_rsa_session_key_payload(
    sender, receiver, conversation_id, algorithm, encrypted_key, epoch)
    -- see that module for the canonical construction, and client/
    session.py::establish_session_key()/handle_session_key() for where
    it is produced and verified. Optional and additive, exactly like
    Phase 13's group_key_signature field. Only meaningful for the RSA
    branch: a KYBER-mode session key is never sent as this packet type
    (it uses group_key_distribution/group_key_signature instead -- see
    handle_session_key()'s own docstring on why its "algorithm ==
    KYBER" branch is legacy/unreachable in current production code).
    handle_session_key() rejects an RSA-mode packet with no
    session_key_signature at all -- there is no legacy unsigned path
    for session-key material, for the same reason Phase 13 gave
    group-key material none.
    """

    packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "algorithm": algorithm,
        "sender": sender,
        "receiver": receiver,
        "encrypted_key": encrypted_key,
        "epoch": epoch
    }

    if conversation_id is not None:
        packet["conversation_id"] = conversation_id

    if session_key_signature is not None:
        packet["session_key_signature"] = session_key_signature

    return packet


def parse_packet(packet):
    """
    Return the packet as-is.

    All packets are already Python dictionaries after
    receive_message(), so no parsing is required.
    """

    return packet


# ============================================================
# Multi-Device Identity (Phase 16)
# ============================================================
#
# Flat-dict / request_id convention identical to every other
# request/response packet pair above (e.g. direct_conversation_
# request/result, epoch_reservation_request/result) -- request_id is
# attached by ClientSession.send_request() itself, never set here,
# exactly like those. The account identity used server-side is always
# resolved from the authenticated connection (user.id), never trusted
# from any field on these packets -- see server/device_handler.py.


def create_device_enroll_request_packet(
    device_id, device_name, platform, kem_public_key, ml_dsa_public_key, enrollment_signature
):
    """
    A device's own, self-signed request to become known to the
    account (crypto/device_protocol.py::canonical_device_enrollment_
    payload()). ``enrollment_signature`` is base64-encoded, over that
    canonical payload, signed with THIS device's own private ML-DSA
    key -- proves possession of the advertised keys, not authorization
    (see that module's own docstring).
    """

    return {
        "type": "device_enroll_request",
        "device_id": device_id,
        "device_name": device_name,
        "platform": platform,
        "kem_public_key": kem_public_key,
        "ml_dsa_public_key": ml_dsa_public_key,
        "enrollment_signature": enrollment_signature,
    }


def create_device_enroll_result_packet(request_id, success, state=None, device_id=None, error=None):
    return {
        "type": "device_enroll_result",
        "request_id": request_id,
        "success": success,
        "state": state,
        "device_id": device_id,
        "error": error,
    }


def create_device_list_request_packet():
    return {"type": "device_list_request"}


def create_device_list_result_packet(request_id, devices):
    """
    ``devices`` is a list of dicts, each already stripped down to
    non-sensitive fields (device_id, device_name, platform,
    fingerprint, state, created_at) by the caller -- never including
    the raw public key bytes/base64 unless a caller genuinely needs
    them (kept out by default to match this project's established
    "don't relay more than the receiver needs" convention).
    """

    return {"type": "device_list_result", "request_id": request_id, "devices": devices}


def create_device_authorize_packet(target_device_id, target_fingerprint, authorizer_device_id, authorization_signature):
    """
    An already-AUTHORIZED device vouching for a PENDING one
    (crypto/device_protocol.py::canonical_device_authorization_
    payload()). ``authorization_signature`` is base64-encoded, signed
    with the AUTHORIZING device's own private ML-DSA key.
    """

    return {
        "type": "device_authorize",
        "target_device_id": target_device_id,
        "target_fingerprint": target_fingerprint,
        "authorizer_device_id": authorizer_device_id,
        "authorization_signature": authorization_signature,
    }


def create_device_authorize_result_packet(request_id, success, error=None):
    return {"type": "device_authorize_result", "request_id": request_id, "success": success, "error": error}


def create_device_revoke_packet(target_device_id, revoker_device_id, revocation_signature):
    """
    An already-AUTHORIZED device revoking a device (possibly itself)
    (crypto/device_protocol.py::canonical_device_revocation_payload()).
    ``revocation_signature`` is base64-encoded, signed with the
    REVOKING device's own private ML-DSA key.
    """

    return {
        "type": "device_revoke",
        "target_device_id": target_device_id,
        "revoker_device_id": revoker_device_id,
        "revocation_signature": revocation_signature,
    }


def create_device_revoke_result_packet(request_id, success, error=None):
    return {"type": "device_revoke_result", "request_id": request_id, "success": success, "error": error}


def create_device_session_bind_packet(device_id, session_nonce, binding_signature):
    """
    Phase 16B -- Device Authentication Binding: proves THIS connection
    is operated by the party holding the private ML-DSA key for
    ``device_id`` (crypto/device_protocol.py::canonical_device_
    session_binding_payload()). ``binding_signature`` is base64-
    encoded, signed with the connecting device's own private ML-DSA
    key.
    """

    return {
        "type": "device_session_bind",
        "device_id": device_id,
        "session_nonce": session_nonce,
        "binding_signature": binding_signature,
    }


def create_device_session_bind_result_packet(request_id, success, error=None):
    return {
        "type": "device_session_bind_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


# ------------------------------------------------------------------
# Cross-Device Key Synchronization (Phase 16C)
# ------------------------------------------------------------------


def create_device_key_sync_packet(
    target_device_id, target_fingerprint, conversation_id, epoch,
    package_type, encapsulation, wrapped_key, sync_signature,
):
    """
    One device delivering wrapped conversation/group key material to
    another of the same account's own devices
    (crypto/device_protocol.py::canonical_device_key_sync_payload()).
    ``encapsulation``/``wrapped_key`` are exactly what KeyManager.
    wrap_key_for_member() already produces for ordinary group-key
    distribution -- reused unchanged, never a new wire format.
    ``sync_signature`` is base64-encoded, signed with the SOURCE
    device's own private ML-DSA key.
    """

    return {
        "type": "device_key_sync",
        "target_device_id": target_device_id,
        "target_fingerprint": target_fingerprint,
        "conversation_id": conversation_id,
        "epoch": epoch,
        "package_type": package_type,
        "encapsulation": encapsulation or None,
        "wrapped_key": wrapped_key,
        "sync_signature": sync_signature,
    }


def create_device_key_sync_result_packet(request_id, success, error=None):
    return {
        "type": "device_key_sync_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


# ------------------------------------------------------------------
# Inbox: verification requests + group member-add approval
# (Phase 19.13 -- User Manual Feedback Implementation)
#
# Both workflows share one small server-side store (database/models/
# inbox_notification.py) and one request/response/list shape here --
# neither packet carries any cryptography of its own. Approving a
# verification_request still requires the RECIPIENT's own client to
# call the existing, unweakened ClientSession.confirm_combined_peer_
# verification() locally, using the fingerprint it has already
# observed for the requester -- this inbox layer only records who
# asked whom and what they decided; it is never itself the trust
# decision. Approving a group_add_request runs through the exact
# same server-side add-member + group-key-distribution path an
# admin's own direct group_add_members already does (server/
# client_handler.py's _perform_group_add_members()) -- reused, not
# duplicated.
# ------------------------------------------------------------------


def create_verification_request_packet(target_username):
    """
    Ask the server to notify ``target_username`` that the sender wants
    to verify their identity. The sender's own identity comes from the
    authenticated socket server-side, never from this packet.
    """

    return {
        "type": "verification_request",
        "target_username": target_username,
    }


def create_group_remove_member_packet(conversation_id, target_username):
    """
    Ask the server to remove ``target_username`` from a group
    conversation. Server-enforced admin-only (server/client_handler.py
    ::handle_group_remove_member()) -- the caller's role is always
    re-derived server-side from ConversationRepository.
    get_admin_user_id(), never trusted from this packet or from
    whether the client happened to show the Remove Member button.
    """

    return {
        "type": "group_remove_member",
        "conversation_id": conversation_id,
        "target_username": target_username,
    }


def create_group_remove_member_result_packet(request_id, success, error=None):
    return {
        "type": "group_remove_member_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


def create_inbox_list_request_packet():
    """
    Ask for every inbox notification (pending or already resolved)
    addressed to the authenticated caller. Carries no fields, exactly
    like create_conversation_list_request_packet() -- whose inbox to
    return is entirely the authenticated connection's own identity.
    """

    return {
        "type": "inbox_list_request",
    }


def create_inbox_list_result_packet(request_id, notifications):
    """
    Server -> client: the result of an inbox_list_request.
    ``notifications`` is a list of plain dicts: {notification_id,
    type ("verification_request"|"group_add_request"), status
    ("pending"|"approved"|"denied"), requester_username,
    created_at, and -- group_add_request only --
    conversation_id/group_name/candidate_username}.
    """

    return {
        "type": "inbox_list_result",
        "request_id": request_id,
        "notifications": notifications,
    }


def create_inbox_response_packet(notification_id, approve):
    """
    The recipient's decision on one pending inbox notification.
    ``approve`` True/False -- server-side handling differs by the
    notification's own ``type`` (verification_request vs
    group_add_request), see handle_inbox_response()'s own docstring.
    Sending this for a verification_request does NOT itself perform
    cryptographic verification -- the recipient's client must already
    have called confirm_combined_peer_verification() locally before
    sending approve=True (see gui/mobile UI wiring); this packet only
    ever records/propagates that outcome.
    """

    return {
        "type": "inbox_response",
        "notification_id": notification_id,
        "approve": approve,
    }


def create_inbox_notification_packet(notification):
    """
    Server -> client: a brand-new inbox notification has just arrived
    for this connection (pushed live, if online, the moment it is
    created -- see handle_verification_request()/
    handle_group_add_members()). Same per-notification shape as one
    entry in create_inbox_list_result_packet()'s ``notifications``
    list, so the client can reuse one parsing path for both.
    """

    return {
        "type": "inbox_notification",
        "notification": notification,
    }


def create_inbox_response_result_packet(notification):
    """
    Server -> the ORIGINAL REQUESTER: their earlier verification_
    request or group_add_request has just been approved or denied
    (pushed live if they are online). Same per-notification shape
    again, so "was this approved or denied" and "here is a brand new
    request for you" render through the same client-side code path.
    """

    return {
        "type": "inbox_response_result",
        "notification": notification,
    }


# ------------------------------------------------------------------
# Settings (Phase 19.14): change username/password, profile picture
# upload/fetch. Server-side, all four are authenticated-account-only
# self-service operations -- see auth/authentication_service.py::
# change_username()/change_password() and server/client_handler.py's
# profile-picture handlers for the actual validation/storage.
# ------------------------------------------------------------------


def create_change_username_request_packet(new_username):
    return {"type": "change_username_request", "new_username": new_username}


def create_change_username_result_packet(request_id, success, error=None):
    return {
        "type": "change_username_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


def create_change_password_request_packet(current_password, new_password, confirm_password):
    """
    ``current_password``/``new_password`` travel over this connection's
    existing TLS 1.3 channel only (the same transport every credential
    -- the original login password, the register password -- already
    crosses); never logged, never persisted in plaintext anywhere (see
    AuthenticationService.change_password()'s own docstring).
    """

    return {
        "type": "change_password_request",
        "current_password": current_password,
        "new_password": new_password,
        "confirm_password": confirm_password,
    }


def create_change_password_result_packet(request_id, success, error=None):
    return {
        "type": "change_password_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


def create_profile_picture_upload_request_packet(image_base64, content_type):
    """
    ``image_base64`` is the raw (not end-to-end encrypted) image
    bytes, base64-encoded -- a profile picture is, by design, visible
    to any other user who looks this account up, unlike message
    attachments (crypto/... payload adapters), which stay end-to-end
    encrypted. Still travels only over this connection's TLS channel.
    """

    return {
        "type": "profile_picture_upload_request",
        "image_base64": image_base64,
        "content_type": content_type,
    }


def create_profile_picture_upload_result_packet(request_id, success, error=None):
    return {
        "type": "profile_picture_upload_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


def create_profile_picture_request_packet(username):
    return {"type": "profile_picture_request", "username": username}


def create_profile_picture_result_packet(request_id, found, image_base64=None, content_type=None):
    return {
        "type": "profile_picture_result",
        "request_id": request_id,
        "found": found,
        "image_base64": image_base64,
        "content_type": content_type,
    }


# ------------------------------------------------------------------
# Bio (Phase 19.22 -- Settings): the User.bio column has existed since
# the initial migration but had no wire format at all until now. Same
# request/response shape as change_username_request/result and
# profile_picture_request/result above -- update-own + fetch-by-
# username, no new pattern introduced.
# ------------------------------------------------------------------


def create_change_bio_request_packet(bio):
    return {"type": "change_bio_request", "bio": bio}


def create_change_bio_result_packet(request_id, success, error=None):
    return {
        "type": "change_bio_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


def create_bio_request_packet(username):
    return {"type": "bio_request", "username": username}


def create_last_seen_request_packet(username):
    """Phase 19.24 -- Presence/Last Seen. Client -> server: ask for
    ``username``'s last-seen timestamp -- only ever sent for a peer
    the requester's own online_users list already reports as OFFLINE
    (an online peer has nothing to ask for)."""

    return {"type": "last_seen_request", "username": username}


def create_last_seen_result_packet(request_id, found, last_seen_at=None):
    """``found=False`` covers both "no such account" and "blocked in
    either direction" -- same account-enumeration/privacy guard as
    create_bio_result_packet()'s identical "found" contract. ``last_
    seen_at`` is None whenever the account has never disconnected
    (still online right now, or has never logged in), which is a true
    statement, not a missing one -- the client must render "no last-
    seen information" rather than inventing a time.
    """

    return {
        "type": "last_seen_result",
        "request_id": request_id,
        "found": found,
        "last_seen_at": last_seen_at,
    }


def create_bio_result_packet(request_id, found, bio=None):
    return {
        "type": "bio_result",
        "request_id": request_id,
        "found": found,
        "bio": bio,
    }


# ------------------------------------------------------------------
# Phase 19.24 -- Block User. Same request/response shape as change_
# username_request/result above -- a block/unblock is server-side and
# persisted (database/models/blocked_user.py), unlike Mute/Archive's
# local-only preferences, since it must be enforced for every
# authorized device of both accounts, not just this one connection.
# ------------------------------------------------------------------


def create_block_user_request_packet(target_username):
    return {"type": "block_user_request", "target_username": target_username}


def create_block_user_result_packet(request_id, success, error=None):
    return {
        "type": "block_user_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


def create_unblock_user_request_packet(target_username):
    return {"type": "unblock_user_request", "target_username": target_username}


def create_unblock_user_result_packet(request_id, success, error=None):
    return {
        "type": "unblock_user_result",
        "request_id": request_id,
        "success": success,
        "error": error,
    }


def create_blocked_users_list_request_packet():
    return {"type": "blocked_users_list_request"}


def create_blocked_users_list_result_packet(request_id, usernames):
    return {
        "type": "blocked_users_list_result",
        "request_id": request_id,
        "usernames": usernames,
    }