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