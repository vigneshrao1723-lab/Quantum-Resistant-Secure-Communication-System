"""
Client Handler Module

Handles communication with individual clients.
"""

import uuid
from datetime import datetime, timezone

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from config import KEY_EXCHANGE_ALGORITHM
from database.connection import SessionLocal
from database.models.conversation import Conversation
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.user_repository import UserRepository
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import BLOB_STORAGE_PAYLOAD_TYPES, PayloadType
from security.jwt_handler import TokenExpiredError, TokenValidationError
from server.broadcaster import (
    broadcast,
    broadcast_user_list,
    distribute_public_keys,
    send_to_client,
)
from storage import encrypted_blob_store
from utils.network import receive_message
from utils.protocol import (
    create_auth_result_packet,
    create_conversation_list_result_packet,
    create_delivery_failure_packet,
    create_direct_conversation_result_packet,
    create_epoch_reservation_result_packet,
    create_group_create_result_packet,
    create_group_key_rotation_required_packet,
    create_group_member_left_packet,
    create_group_members_added_packet,
    create_join_packet,
    create_leave_packet,
    create_login_result_packet,
    create_logout_result_packet,
    create_read_receipt_notification_packet,
    create_register_result_packet,
    create_user_lookup_result_packet,
    parse_packet,
)


def _parse_message_timestamp(raw_timestamp):
    """
    Parse the client-supplied ISO 8601 timestamp from a chat packet.

    Falls back to the current server time if the timestamp is
    missing or malformed, rather than failing the persistence.
    """

    if raw_timestamp:
        try:
            parsed = datetime.fromisoformat(raw_timestamp)

            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

            return parsed
        except ValueError:
            pass

    return datetime.now(timezone.utc).replace(tzinfo=None)


def persist_message(sender_id, receiver_id, algorithm, packet, conversation_id=None):
    """
    Persist a successfully delivered private message.

    Only ever called after a "chat" packet has been routed to a
    connected recipient -- failed deliveries are never stored. Stores
    ciphertext only; the server never decrypts messages.

    Resolves (or creates) the direct conversation between sender and
    receiver and records it on the message, alongside the existing
    receiver_id -- the Phase 1 conversation-addressing foundation
    (Architecture Blueprint v2). Live routing above is unaffected;
    only persistence gains this extra, additive step.

    `conversation_id`: for a direct message (the only case before
    Phase 4), omitted -- resolved via get_or_create_direct_conversation()
    exactly as before. persist_group_message() below passes it
    explicitly, since a group's conversation already exists by the
    time any message is sent to it; every direct call site and every
    existing test is unaffected by this optional addition.

    Builds a PayloadEnvelope from the packet's (Phase 3) payload_type/
    content_metadata fields -- present and PayloadType.TEXT/None for
    every packet built by create_chat_packet()'s backward-compatible
    wrapper, and defaulted here to PayloadType.TEXT/None for the rare
    case of a packet missing them entirely. The envelope is opaque to
    the server either way: it only ever stores its fields, never
    inspects or decrypts ciphertext. content_metadata binds straight
    into the JSONB column as a plain dict -- no manual JSON
    (de)serialization.

    Storage routing (Phase 6 -- Secure File & Image Transfer
    Infrastructure): a payload_type in BLOB_STORAGE_PAYLOAD_TYPES
    (domain/payload_type.py) has its ciphertext written to
    storage/encrypted_blob_store.py instead of the ciphertext column,
    with blob_ref recording where it went; every other payload_type is
    unaffected and keeps storing ciphertext inline exactly as before.
    This is the only place that decision is made -- neither the
    storage backend nor MessageRepository know payload_type exists.
    """

    db = SessionLocal()

    try:
        message_repo = MessageRepository(db)

        if conversation_id is None:
            conversation_repo = ConversationRepository(db)
            conversation = conversation_repo.get_or_create_direct_conversation(
                sender_id, receiver_id
            )
            conversation_id = conversation.id

        envelope = PayloadEnvelope(
            payload_type=packet.get("payload_type") or PayloadType.TEXT,
            ciphertext=packet.get("message"),
            content_metadata=packet.get("content_metadata") or {},
        )

        if envelope.payload_type in BLOB_STORAGE_PAYLOAD_TYPES:
            blob_ref = encrypted_blob_store.store_blob(envelope.ciphertext.encode("utf-8"))
            ciphertext = None
        else:
            blob_ref = None
            ciphertext = envelope.ciphertext

        message = message_repo.save_message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            conversation_id=conversation_id,
            ciphertext=ciphertext,
            blob_ref=blob_ref,
            payload_type=envelope.payload_type,
            content_metadata=envelope.content_metadata or None,
            algorithm=algorithm or KEY_EXCHANGE_ALGORITHM,
            timestamp=_parse_message_timestamp(packet.get("timestamp")),
            epoch=packet.get("epoch") or 1,
        )

        db.commit()

        return message
    finally:
        db.close()


def _resolve_direct_conversation_id(sender_id, receiver_id):
    """
    Get-or-create the direct conversation between two users and return
    its id as a string (D3.1 -- Conversation Operations Migration,
    first slice).

    Called from the "chat" and "session_key" relay branches below,
    before either packet is ever sent to its recipient, so the
    resolved id can be attached to the outgoing packet -- the
    receiving client no longer has to resolve or create it itself via
    a direct database call (see client/conversation_store.py::
    ensure_direct_conversation_id(), not yet migrated by this slice,
    but no longer reached from handle_chat()/handle_session_key() once
    they consume the field this populates).

    Reuses ConversationRepository.get_or_create_direct_conversation()
    completely unchanged, including its pg_advisory_xact_lock()-based
    concurrency guard (D3.1) -- what makes it safe to call this from
    two different connections' handler threads for the same pair at
    the same time, which is now a real possibility with resolution
    centralized here rather than spread across independent client
    processes.
    """

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)

        conversation = conversation_repo.get_or_create_direct_conversation(
            sender_id, receiver_id
        )

        conversation_repo.commit()

        return str(conversation.id)
    finally:
        db.close()


def persist_group_message(
    sender_id, conversation_id, member_ids, connected_member_ids, algorithm, packet
):
    """
    Persist a group message (Phase 4 -- Secure Group Messaging
    Foundation): content is stored once via the same persist_message()
    every direct message uses -- receiver_id is populated with
    sender_id, a documented legacy placeholder, since messages.receiver_id
    keeps its existing NOT NULL, single-recipient meaning unchanged and
    a group message has no single recipient; conversation_id +
    message_recipients are authoritative instead.

    Delivery state per member (excluding the sender) is recorded
    separately via MessageRepository.record_recipients() -- QUEUED for
    members who were not connected at send time, DELIVERED for those
    who were (already known from the live fan-out above, for free).

    A known, accepted limitation for this foundation phase: the
    content row and the recipient rows are committed in two separate
    transactions (reusing persist_message()'s own self-contained
    session rather than threading a shared one through it). If the
    second transaction were to fail, the message itself would still
    be correctly persisted and readable -- only its delivery-status
    bookkeeping would be missing, not corrupted. Full atomicity is a
    reasonable future hardening, not required for this foundation.
    """

    message = persist_message(
        sender_id=sender_id,
        receiver_id=sender_id,
        algorithm=algorithm,
        packet=packet,
        conversation_id=conversation_id,
    )

    db = SessionLocal()

    try:
        message_repo = MessageRepository(db)

        recipient_ids = [member_id for member_id in member_ids if member_id != sender_id]
        delivered_ids = [
            member_id for member_id in connected_member_ids if member_id != sender_id
        ]

        message_repo.record_recipients(message.id, recipient_ids, delivered_ids)

        db.commit()
    finally:
        db.close()


def _record_direct_recipient(message, receiver_id, delivered):
    """
    Create a direct message's MessageRecipient row (C2 -- Read
    Receipts): DELIVERED if the recipient was connected and live-
    relayed to just now, QUEUED otherwise (the C1 offline-persistence
    path) -- exactly mirroring persist_group_message()'s own
    DELIVERED/QUEUED split, reusing record_recipients() unchanged
    rather than a new method. A direct message always has exactly one
    recipient, so this is always a one-element list -- the same
    generic method group messages already use, not a parallel
    mechanism for direct messages.

    Before C2, a direct message never got a MessageRecipient row at
    all (see database/models/message_recipient.py's own prior
    docstring); this is the one behavioral change to that existing
    invariant, needed so read receipts have a row to transition to
    READ later.
    """

    db = SessionLocal()

    try:
        message_repo = MessageRepository(db)

        message_repo.record_recipients(
            message.id,
            [receiver_id],
            [receiver_id] if delivered else [],
        )

        db.commit()
    finally:
        db.close()


def handle_group_chat_delivery(state, client_socket, user, conversation_id, packet):
    """
    Route a group-addressed "chat" packet (conversation_id set,
    receiver unset -- see create_payload_packet()) to every other
    connected member, then persist it once via persist_group_message().

    Mirrors the direct "chat" branch's shape (look up recipients,
    send_to_client, then persist) but fans out to N members instead
    of matching one -- the server-side half of Design B (one
    encryption, one relay operation, O(N) sends).

    Security hardening: the authenticated sender (``user``, never the
    client-supplied packet field) must itself be an active member of
    ``conversation_id`` before anything below runs. member_ids already
    comes from ConversationRepository.get_member_user_ids(), which
    already filters out members who have left (left_at IS NOT NULL) --
    so this one check also correctly rejects a removed member, with no
    extra query. A rejection is silent (log only, early return, no
    relay, no persistence, no MessageRecipient rows, no packet sent
    back) -- responding at all would confirm to a non-member whether
    conversation_id is valid.
    """

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(uuid.UUID(conversation_id))
    finally:
        db.close()

    if user.id not in member_ids:

        state.logger.warning(
            f"Rejected group chat: {user.username} is not a member of "
            f"conversation {conversation_id}"
        )

        return

    member_id_strings = {str(member_id) for member_id in member_ids}
    connected_member_ids = []

    for sock, client in list(state.clients.items()):

        if sock == client_socket:
            continue

        # Only actually-successful sends count as "connected" here --
        # connected_member_ids feeds persist_group_message()'s
        # DELIVERED/QUEUED split below, so a failed relay must not be
        # recorded as delivered.
        if (
            client.get("user_id") in member_id_strings
            and send_to_client(sock, packet)
        ):
            connected_member_ids.append(uuid.UUID(client["user_id"]))

    state.logger.info(
        f"{user.username} -> group {conversation_id}: "
        f"[Encrypted Message] ({len(connected_member_ids)} connected recipients)"
    )

    sender_client = state.get_client(client_socket)

    persist_group_message(
        sender_id=user.id,
        conversation_id=uuid.UUID(conversation_id),
        member_ids=member_ids,
        connected_member_ids=connected_member_ids,
        algorithm=(sender_client or {}).get("algorithm"),
        packet=packet,
    )


def handle_group_create(state, client_socket, user, packet):
    """
    Create a new group conversation and confirm it to every currently
    connected member (including the creator) -- create_group_conversation()
    is the exact extension point ConversationRepository has documented
    since Phase 1. No group key is generated or seen here: that
    happens client-side once the creator receives the confirmation
    (see ClientSession.handle_group_create_result()) -- the server
    only ever relays wrapped key material, never plaintext keys.
    """

    name = packet.get("name")
    member_usernames = packet.get("members") or []

    db = SessionLocal()

    try:
        user_repo = UserRepository(db)
        conversation_repo = ConversationRepository(db)

        member_ids = [user.id]
        resolved_usernames = [user.username]

        for username in member_usernames:

            if username == user.username:
                continue

            member = user_repo.get_by_username(username)

            if member is None:
                continue

            member_ids.append(member.id)
            resolved_usernames.append(member.username)

        conversation = conversation_repo.create_group_conversation(
            member_ids=member_ids, name=name
        )

        conversation_repo.commit()

        conversation_id = str(conversation.id)
    finally:
        db.close()

    result_packet = create_group_create_result_packet(
        conversation_id=conversation_id,
        name=name,
        creator=user.username,
        members=resolved_usernames,
    )

    for sock, client in list(state.clients.items()):

        if client["username"] in resolved_usernames:
            send_to_client(sock, result_packet)

    state.logger.info(
        f"{user.username} created group '{name}' ({conversation_id}) "
        f"with members {resolved_usernames}"
    )


def _usernames_for(db, member_ids):
    """Resolve a list of user ids to their usernames, skipping any
    that no longer exist. Small groups, one lookup per member --
    mirrors handle_group_create()'s own username-resolution loop."""

    user_repo = UserRepository(db)

    usernames = []

    for member_id in member_ids:

        member = user_repo.get_by_id(member_id)

        if member is not None:
            usernames.append(member.username)

    return usernames


def _select_connected_active_member(state, member_ids, exclude_user_id=None):
    """
    Return the (socket, username) of one currently-connected member
    among ``member_ids``, or None if none are connected (Phase 7 --
    Group Membership Management). Any valid connected member is
    acceptable -- there is no election, no username/id ordering
    requirement; the server is the sole issuer of rotation
    instructions, so which specific connected member is picked has no
    correctness implications, only that at most one is picked per
    dispatch.
    """

    member_id_strings = {str(member_id) for member_id in member_ids}

    for sock, client in list(state.clients.items()):

        if exclude_user_id is not None and client.get("user_id") == str(exclude_user_id):
            continue

        if client.get("user_id") in member_id_strings:
            return sock, client["username"]

    return None


def _dispatch_pending_rotation_if_needed(state, conversation_id_str):
    """
    If a conversation's confirmed_key_epoch is behind its
    current_key_epoch, select one currently-connected active member
    and send them a group_key_rotation_required instruction for the
    next unconfirmed epoch (Phase 7 -- Group Membership Management).

    A no-op if already caught up, or if no active member is currently
    connected -- the gap is picked up again the next time an active
    member connects (see handle_client()'s reconnect-recovery hook) or
    the next time a rotation completes for this conversation (see
    handle_group_key_rotation_complete(), which calls this again after
    advancing confirmed_key_epoch, so a multi-epoch backlog is caught
    up one epoch at a time, in order, never skipped).
    """

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        conversation_id = uuid.UUID(conversation_id_str)

        current_epoch, confirmed_epoch = conversation_repo.get_epoch_state(
            conversation_id
        )

        if current_epoch is None or confirmed_epoch >= current_epoch:
            return

        next_epoch = confirmed_epoch + 1

        member_ids = conversation_repo.get_member_user_ids(conversation_id)
        member_usernames = _usernames_for(db, member_ids)
    finally:
        db.close()

    selected = _select_connected_active_member(state, member_ids)

    if selected is None:
        state.logger.info(
            f"No connected active member available to rotate "
            f"{conversation_id_str} to epoch {next_epoch}; deferred until "
            f"an active member connects."
        )
        return

    sock, selected_username = selected

    recipients = [u for u in member_usernames if u != selected_username]

    dispatched = send_to_client(
        sock,
        create_group_key_rotation_required_packet(
            conversation_id=conversation_id_str,
            epoch=next_epoch,
            members=recipients,
        ),
    )

    if not dispatched:
        # No retry here -- this is a best-effort dispatch to whichever
        # active member happened to be selected; the docstring's own
        # self-healing already covers this (the next connection or
        # rotation-complete event calls this function again and picks
        # a member fresh). Reporting the actual outcome only, not
        # attempting a second delivery.
        state.logger.warning(
            f"Failed to dispatch group key rotation for "
            f"{conversation_id_str} epoch {next_epoch} to "
            f"{selected_username}"
        )
        return

    state.logger.info(
        f"Dispatched group key rotation for {conversation_id_str} epoch "
        f"{next_epoch} to {selected_username}"
    )


def handle_group_leave(state, client_socket, user, packet):
    """
    Remove the authenticated user from a group conversation (Phase 7
    -- Group Membership Management).

    Security: who leaves is derived entirely from the authenticated
    socket (``user``), never from packet["sender"]/packet["user_id"]/
    packet["username"] -- mirrors the sender-authentication and
    group-membership-authorization hardening already in
    handle_group_chat_delivery(). Membership is verified the same way
    (get_member_user_ids()) before anything is changed.

    Transactional: left_at is set and the next epoch is reserved in
    the SAME session, committed once -- see
    ConversationRepository.reserve_next_epoch()'s docstring for why a
    split here (unlike persist_group_message()'s accepted two-
    transaction gap) is not acceptable: losing the epoch reservation
    while the departure commits would leave the group silently stuck
    on a key the departed member still holds, with nothing to ever
    trigger a rotation.
    """

    conversation_id = packet.get("conversation_id")

    if not conversation_id:
        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        conversation_uuid = uuid.UUID(conversation_id)

        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

        if user.id not in member_ids:

            state.logger.warning(
                f"Rejected group_leave: {user.username} is not a member of "
                f"{conversation_id}"
            )

            return

        conversation_repo.leave_conversation(conversation_uuid, user.id)
        conversation_repo.reserve_next_epoch(conversation_uuid)

        conversation_repo.commit()

        remaining_ids = [m for m in member_ids if m != user.id]
        remaining_usernames = _usernames_for(db, remaining_ids)
    finally:
        db.close()

    member_left_packet = create_group_member_left_packet(
        conversation_id=conversation_id,
        username=user.username,
        members=remaining_usernames,
    )

    all_former_id_strings = {str(m) for m in member_ids}

    for sock, client in list(state.clients.items()):

        if client.get("user_id") in all_former_id_strings:
            send_to_client(sock, member_left_packet)

    state.logger.info(
        f"{user.username} left group {conversation_id} "
        f"(remaining: {remaining_usernames})"
    )

    if not remaining_ids:
        return

    _dispatch_pending_rotation_if_needed(state, conversation_id)


def handle_group_key_rotation_complete(state, client_socket, user, packet):
    """
    A rotation initiator has finished attempting distribution of an
    epoch's group key (Phase 7 -- Group Membership Management).
    Carries no key material -- only conversation_id and an epoch
    number.

    Authorization: only an active member of the conversation may
    advance its confirmed_key_epoch -- otherwise a non-member could
    falsely claim a rotation completed, tricking the server into never
    re-dispatching it to the members who never actually received the
    key. Advancing is itself guarded with max() (see
    ConversationRepository.confirm_epoch()), so even a legitimate but
    stale/duplicate confirmation cannot regress state.

    Chains immediately into the next epoch if this conversation still
    has a backlog (multiple leaves before an earlier rotation
    finished) -- see _dispatch_pending_rotation_if_needed().
    """

    conversation_id = packet.get("conversation_id")
    epoch = packet.get("epoch")

    if not conversation_id or epoch is None:
        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        conversation_uuid = uuid.UUID(conversation_id)

        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

        if user.id not in member_ids:

            state.logger.warning(
                f"Rejected group_key_rotation_complete: {user.username} is "
                f"not a member of {conversation_id}"
            )

            return

        conversation_repo.confirm_epoch(conversation_uuid, epoch)
        conversation_repo.commit()
    finally:
        db.close()

    state.logger.info(
        f"{user.username} confirmed group key rotation for {conversation_id} "
        f"epoch {epoch}"
    )

    _dispatch_pending_rotation_if_needed(state, conversation_id)


def handle_group_add_members(state, client_socket, user, packet):
    """
    Add one or more users to an existing group conversation
    (real-application bug fix, Issue 2 -- Add Members After Group
    Creation).

    Security: who is requesting the add is derived entirely from the
    authenticated socket (``user``), never trusted from the packet --
    mirrors handle_group_leave()'s pattern exactly. Any active member
    may add members: this app has no owner/role concept (Phase 7's own
    "any active member" rotation-initiator selection already
    established that trust model; this reuses it, not a new one). A
    non-member requester is rejected silently, same as every other
    group-authorization check in this file.

    Deliberately reuses the exact epoch-rotation machinery a leave
    already uses, rather than a new key-distribution path:
    reserve_next_epoch() bumps current_key_epoch exactly as it does
    for a leave, and the unchanged _dispatch_pending_rotation_if_needed()
    picks a currently-connected active member to generate/redistribute
    that new epoch's key to every current member, old and new alike.
    Consequence (intentional, not a side effect): a newly added member
    receives only the new epoch's key -- they cannot decrypt group
    history from before they joined -- while existing members keep
    their old epoch key (their own history stays readable) and also
    receive the new one, so everyone can keep talking.
    """

    conversation_id = packet.get("conversation_id")
    member_usernames = packet.get("members") or []

    if not conversation_id or not member_usernames:
        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        user_repo = UserRepository(db)
        conversation_uuid = uuid.UUID(conversation_id)

        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

        if user.id not in member_ids:

            state.logger.warning(
                f"Rejected group_add_members: {user.username} is not a "
                f"member of {conversation_id}"
            )

            return

        new_user_ids = []

        for username in member_usernames:

            candidate = user_repo.get_by_username(username)

            if candidate is None or candidate.id in member_ids:
                continue

            new_user_ids.append(candidate.id)

        if not new_user_ids:
            return

        affected = conversation_repo.add_members(conversation_uuid, new_user_ids)

        if not affected:
            return

        conversation_repo.reserve_next_epoch(conversation_uuid)

        conversation_repo.commit()

        all_member_ids = conversation_repo.get_member_user_ids(conversation_uuid)
        all_usernames = _usernames_for(db, all_member_ids)

        conversation = db.get(Conversation, conversation_uuid)
        name = conversation.name if conversation is not None else None
    finally:
        db.close()

    members_added_packet = create_group_members_added_packet(
        conversation_id=conversation_id,
        name=name,
        members=all_usernames,
    )

    all_member_id_strings = {str(member_id) for member_id in all_member_ids}

    for sock, client in list(state.clients.items()):

        if client.get("user_id") in all_member_id_strings:
            send_to_client(sock, members_added_packet)

    state.logger.info(
        f"{user.username} added members to group {conversation_id} "
        f"(now: {all_usernames})"
    )

    _dispatch_pending_rotation_if_needed(state, conversation_id)


def handle_read_receipt(state, client_socket, user, packet):
    """
    Mark every currently-unread message in a conversation as read, on
    behalf of the authenticated connection (C2 -- Read Receipts).

    Security: the reader is derived exclusively from the authenticated
    socket (``user.id``) -- create_read_receipt_packet() carries no
    reader/recipient/user field at all, so there is nothing a
    malicious client could supply to mark a different user's messages
    read; MessageRepository.mark_conversation_read() is itself scoped
    to exactly this recipient_id, so even a forged packet field
    (there isn't one) couldn't reach another user's row. For a group
    conversation, the authenticated user must currently be an active
    member (get_member_user_ids() -- the identical check
    handle_group_leave()/handle_group_chat_delivery() already use); a
    non-member's request is silently rejected, matching the
    established pattern for every other group-authorization check in
    this file. This same check also correctly covers direct
    conversations -- ConversationMember rows exist for both direct and
    group conversations (get_or_create_direct_conversation() creates
    one per participant), so no is_group branch is needed here at all.
    """

    conversation_id = packet.get("conversation_id")

    if not conversation_id:
        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        conversation_uuid = uuid.UUID(conversation_id)

        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

        if user.id not in member_ids:

            state.logger.warning(
                f"Rejected read_receipt: {user.username} is not a member of "
                f"conversation {conversation_id}"
            )

            return

        message_repo = MessageRepository(db)

        newly_read_message_ids = message_repo.mark_conversation_read(
            conversation_uuid, user.id
        )

        if not newly_read_message_ids:
            return

        db.commit()

        recipient_id_strings = {
            str(member_id) for member_id in member_ids if member_id != user.id
        }
    finally:
        db.close()

    notification = create_read_receipt_notification_packet(
        conversation_id=conversation_id,
        reader=user.username,
    )

    for sock, client in list(state.clients.items()):

        if client.get("user_id") in recipient_id_strings:
            send_to_client(sock, notification)

    state.logger.info(
        f"{user.username} read {len(newly_read_message_ids)} message(s) "
        f"in conversation {conversation_id}"
    )


def handle_user_lookup(state, client_socket, user, packet):
    """
    Look up a user by their unique ID on behalf of the authenticated
    connection (D2 -- Server-Side API / Authentication Migration;
    first slice of the client -> server API migration, moving
    ClientSession.find_user_by_id() off its previous direct
    PostgreSQL access).

    Security: matches find_user_by_id()'s pre-migration model exactly
    -- any authenticated user may look up any other by id (a lookup
    grants no privilege of its own; sending to or opening a
    conversation with the result still goes through this file's
    existing sender-authentication and group-membership checks,
    completely unchanged). ``user`` is derived from the authenticated
    socket by dispatch before this function is ever reached -- the
    same structural guarantee every other packet handler in this file
    already relies on -- so there is no additional per-request
    authorization check to perform here; the packet's own fields are
    never a source of identity. Returns only {user_id, username,
    display_name} for both a match and a "not found" result -- never
    email, password hash, or any other User field -- so a caller can't
    distinguish a malformed guess from a well-formed-but-nonexistent
    one, exactly like the pre-migration behavior.

    A missing request_id/user_id is silently ignored (mirrors
    handle_read_receipt()'s identical guard for a missing
    conversation_id). A user_id that fails to parse as a UUID is
    intentionally NOT specially guarded -- it propagates to this
    file's outer exception handler exactly like every other packet
    field parsed with uuid.UUID() elsewhere in this file (conversation_id
    in handle_read_receipt()/handle_group_leave(), etc.); this is an
    existing, already-accepted class of gap, not something introduced
    here. A well-behaved client never triggers it: ClientSession.
    find_user_by_id() already validates the id format itself before
    ever sending a request.
    """

    request_id = packet.get("request_id")
    user_id = packet.get("user_id")

    if not request_id or not user_id:
        return

    db = SessionLocal()

    try:
        found = UserRepository(db).get_by_id(uuid.UUID(user_id))
    finally:
        db.close()

    if found is None:
        response = create_user_lookup_result_packet(request_id=request_id)
    else:
        response = create_user_lookup_result_packet(
            request_id=request_id,
            user_id=str(found.id),
            username=found.username,
            display_name=found.display_name,
        )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send user_lookup_result to {user.username} "
            f"(request_id={request_id})"
        )


def _recover_pending_rotations_for_user(state, user):
    """
    Reconnect recovery (Phase 7 -- Group Membership Management): for
    every active group conversation this user belongs to where a
    rotation was reserved but never confirmed complete, dispatch the
    next outstanding epoch -- picking up a rotation an earlier
    initiator never finished (e.g. it disconnected mid-distribution).

    Purely event-driven off the existing connection-setup path in
    handle_client() -- no scheduler, polling loop, or background
    worker. Called once, after distribute_public_keys() has already
    queued this user's peers' public keys to them on this same
    connection -- TCP/TLS's in-order, per-connection delivery
    guarantees those are processed by this client's receiver thread
    before any rotation instruction sent afterward on the same socket,
    so a freshly (re)connected initiator already has what it needs to
    wrap a key for every other remaining member.
    """

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        pending_conversation_ids = (
            conversation_repo.get_group_conversations_with_pending_rotation(user.id)
        )
    finally:
        db.close()

    for conversation_id in pending_conversation_ids:
        _dispatch_pending_rotation_if_needed(state, str(conversation_id))


def _ensure_group_keys_current_for_reconnecting_user(state, user):
    """
    Reconnect recovery, part 2 (real-application bug fix, Issue 4 --
    group conversation history incorrectly appearing undecryptable
    after a restart/reconnect).

    _recover_pending_rotations_for_user() above only re-dispatches a
    key when a rotation was left outstanding (confirmed_key_epoch <
    current_key_epoch). It does nothing for the far more common case:
    a member simply reconnecting with a brand-new, empty KeyManager --
    i.e. every login -- where nothing was ever "pending" in the
    epoch-counter sense, since no rotation happened at all. Without
    this, such a client has no way to ever receive a group's current
    key again unless some unrelated later rotation event happens to
    include them.

    For each of this user's active group conversations, if another
    active member is currently connected, ask them (reusing
    group_key_rotation_required / handle_group_key_rotation_required
    completely unchanged -- no new client-side code) to redeliver the
    *current* epoch's key to just this user. Safe to run
    unconditionally on every reconnect, whether or not this user
    actually still needs it: if they already have that epoch cached,
    the redelivery is a harmless no-op on their end, since
    KeyManager.store_key() never overwrites an existing epoch.
    """

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        conversation_ids = conversation_repo.get_active_group_conversation_ids(user.id)
    finally:
        db.close()

    for conversation_id in conversation_ids:

        db = SessionLocal()

        try:
            conversation_repo = ConversationRepository(db)
            current_epoch, _confirmed_epoch = conversation_repo.get_epoch_state(
                conversation_id
            )
            member_ids = conversation_repo.get_member_user_ids(conversation_id)
        finally:
            db.close()

        if current_epoch is None:
            continue

        selected = _select_connected_active_member(
            state, member_ids, exclude_user_id=user.id
        )

        if selected is None:
            continue

        sock, _selected_username = selected

        redelivery_requested = send_to_client(
            sock,
            create_group_key_rotation_required_packet(
                conversation_id=str(conversation_id),
                epoch=current_epoch,
                members=[user.username],
            ),
        )

        if not redelivery_requested:
            # No retry here -- matches _dispatch_pending_rotation_if_needed()'s
            # identical reasoning: this runs again on this user's next
            # reconnect, and is a harmless no-op if they already have
            # the key by then.
            state.logger.warning(
                f"Failed to request current-epoch key redelivery for "
                f"{conversation_id} to reconnecting member {user.username}"
            )
            continue

        state.logger.info(
            f"Requested current-epoch key redelivery for {conversation_id} "
            f"to reconnecting member {user.username}"
        )


def handle_register_request(state, client_socket, packet):
    """
    Register a new user account on behalf of an as-yet-unauthenticated
    connection (D2 -- Server-Side API / Authentication Migration;
    second slice, migrating gui/main_window.py's registration path off
    its previous direct, local AuthenticationService/PostgreSQL call).

    Unlike every other handler in this file, this one runs before
    authenticate_connection() ever succeeds -- there is no JWT and no
    authenticated `user` to derive an identity from, because
    registration's entire purpose is creating one. This is not a new
    trust boundary: gui/main_window.py::handle_registration() already
    called AuthenticationService.register_user() with no authentication
    of its own, before this migration -- the server enforces exactly
    the same validation (AuthenticationService.register_user() itself,
    completely unchanged) it always would have, just now over the wire
    instead of via direct DB access from the client machine.

    A missing request_id is silently ignored -- there is no correlated
    caller to answer (mirrors handle_user_lookup()'s identical guard).
    Every other missing/malformed field is left entirely to
    RegisterRequest/register_user()'s own existing validation, exactly
    as before this migration.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    db = SessionLocal()

    try:
        result = AuthenticationService(db).register_user(
            RegisterRequest(
                full_name=packet.get("full_name"),
                username=packet.get("username"),
                email=packet.get("email"),
                password=packet.get("password"),
                confirm_password=packet.get("confirm_password"),
            )
        )
    finally:
        db.close()

    response = create_register_result_packet(
        request_id=request_id,
        success=result.success,
        message=result.message,
        user_id=result.user_id,
        errors=result.errors,
    )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send register_result (request_id={request_id})"
        )


def handle_login_request(state, client_socket, packet):
    """
    Authenticate a not-yet-authenticated connection via username/email
    + password (D2 -- Server-Side API / Authentication Migration; final
    slice, migrating gui/main_window.py's and client/client.py's
    previous direct, local AuthenticationService.authenticate_user()
    call off the client). Runs from authenticate_connection(), before
    any JWT exists -- obtaining that JWT is exactly what this does.
    Mirrors handle_register_request() closely: same pre-auth placement,
    same fresh-SessionLocal()-per-call pattern, same "always return
    None afterward" contract from its caller.

    Password verification and token issuance are entirely
    AuthenticationService.authenticate_user()'s existing, unchanged
    responsibility -- nothing here duplicates or second-guesses it
    (including its failed-login-attempt lockout bookkeeping). The
    response is built solely from the returned AuthenticationResult, so
    it can never carry a password hash or any other internal User
    field -- only what AuthenticationResult itself already exposes.

    A missing request_id is silently ignored -- there is no correlated
    caller to answer (mirrors handle_register_request()'s identical
    guard). identifier/password are the only fields ever read from the
    packet; there is no client-supplied identity here to distrust in
    the first place -- user_id/username/session_id/tokens are all
    computed fresh, server-side, by authenticate_user().
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    db = SessionLocal()

    try:
        result = AuthenticationService(db).authenticate_user(
            LoginRequest(
                identifier=packet.get("identifier"),
                password=packet.get("password"),
            )
        )
    finally:
        db.close()

    token_pair = result.token_pair

    response = create_login_result_packet(
        request_id=request_id,
        success=result.success,
        message=result.message,
        user_id=result.user_id,
        username=result.username,
        role=result.role,
        session_id=result.session_id,
        access_token=token_pair.access_token if token_pair else None,
        refresh_token=token_pair.refresh_token if token_pair else None,
        expires_in=token_pair.expires_in if token_pair else None,
        token_type=token_pair.token_type if token_pair else None,
        errors=result.errors,
    )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send login_result (request_id={request_id})"
        )


def handle_logout_request(state, client_socket, user, packet):
    """
    Revoke the authenticated connection's own session (D2 -- Server-
    Side API / Authentication Migration; final slice, migrating
    gui/main_window.py's previous direct, local
    AuthenticationService.logout(session_id) call off the client).

    Security: the session revoked is always this connection's own --
    session_id is read from state.get_client(client_socket) (the
    server's own record, established once from the validated JWT at
    authenticate_connection() time), never from the packet. The packet
    itself (see create_logout_request_packet()) carries no identity
    fields at all, so there is nothing for a client to forge here to
    log out a session other than its own. ``user`` is likewise the
    authenticated identity dispatch already resolved -- used only for
    the failure-to-send log line, matching handle_user_lookup()'s
    identical pattern.

    A missing request_id is silently ignored, mirroring every other D2
    handler's identical guard.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    client = state.get_client(client_socket)
    session_id = client.get("session_id") if client else None

    if not session_id:
        response = create_logout_result_packet(
            request_id, False, "No active session to log out."
        )
    else:
        db = SessionLocal()

        try:
            revoked = AuthenticationService(db).logout(session_id)
        finally:
            db.close()

        response = create_logout_result_packet(
            request_id,
            revoked,
            "Logged out." if revoked else "Session was already logged out.",
        )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send logout_result to {user.username} "
            f"(request_id={request_id})"
        )


def handle_direct_conversation_request(state, client_socket, user, packet):
    """
    Get-or-create the direct conversation between the authenticated
    connection and a named partner (D3.3 -- Conversation Operations
    Migration), on demand. This is the request/response counterpart to
    what D3.1 already resolves automatically ahead of a direct chat/
    session_key relay -- needed here for the one client-side caller
    that isn't triggered by an incoming packet at all: ClientSession.
    set_current_chat() opening a chat with someone never messaged
    before (a genuine "create", unlike every other former caller of
    ConversationStore.ensure_direct_conversation_id(), which either
    already has the id from a relayed packet since D3.2, or is left
    for a later slice).

    Security: the caller's own half of the pair is always user.id --
    the authenticated identity from the JWT validated at
    authenticate_connection() time -- never anything read from the
    packet. The partner is chosen by username, exactly like the
    receiver of a chat packet or the identifier on a login_request;
    that field addresses who the caller wants to interact with, it is
    never a source of identity for the caller itself.

    Reuses _resolve_direct_conversation_id() completely unchanged --
    the exact same pg_advisory_xact_lock()-protected path D3.1 already
    uses for live relay -- so a request from here and a simultaneous
    first message between the same pair still safely converge on one
    conversation.

    A missing request_id is silently ignored, mirroring every other
    D2/D3 handler's identical guard. A username that doesn't resolve
    to a real user reports an error field rather than crashing or
    silently creating something -- mirrors ensure_direct_conversation_id()'s
    existing "Unknown user" contract, now surfaced over the wire
    instead of a local exception. A username that resolves to the
    caller's own account also reports an error field instead of
    reaching _resolve_direct_conversation_id() -- a self-pair would
    violate ConversationMember's (conversation_id, user_id) uniqueness
    constraint there. Usernames are not treated as secret
    here (unlike user_lookup_request's id-based lookup) -- they are
    already freely addressable and observable elsewhere in this
    protocol (the online user list, a chat packet's receiver field),
    so reporting "unknown" plainly introduces no new enumeration risk.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    username = packet.get("username")

    db = SessionLocal()

    try:
        partner = UserRepository(db).get_by_username(username)
    finally:
        db.close()

    if partner is None:
        response = create_direct_conversation_result_packet(
            request_id=request_id,
            error=f"Unknown user: {username}",
        )
    elif partner.id == user.id:
        response = create_direct_conversation_result_packet(
            request_id=request_id,
            error="Cannot open a conversation with yourself.",
        )
    else:
        conversation_id = _resolve_direct_conversation_id(user.id, partner.id)

        response = create_direct_conversation_result_packet(
            request_id=request_id,
            conversation_id=conversation_id,
        )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send direct_conversation_result to {user.username} "
            f"(request_id={request_id})"
        )


def handle_epoch_reservation_request(state, client_socket, user, packet):
    """
    Reserve the next key epoch for a direct conversation on behalf of
    the authenticated connection (D4.1 -- Message/History Operations
    Migration, first slice), replacing ClientSession.
    establish_session_key()'s previous direct, client-side
    ConversationRepository.reserve_next_epoch() call -- the last
    remaining client-side database write anywhere in direct-
    conversation key establishment.

    Security: the caller's identity is always user.id -- the
    authenticated identity from the JWT validated at
    authenticate_connection() time -- never anything read from the
    packet. Before reserving, the authenticated caller must be an
    active member of conversation_id (get_member_user_ids() -- the
    identical check handle_group_leave()/handle_group_chat_delivery()/
    handle_read_receipt() already use). This is a genuinely new
    authorization boundary: the previous direct, client-side database
    call had nothing stopping it from reserving an epoch for any
    conversation_id at all, member or not.

    A missing/malformed conversation_id and a well-formed but
    nonexistent or non-member one all resolve to the same rejection --
    get_member_user_ids() simply returns no rows either way -- so none
    of those cases are distinguishable from each other on the wire,
    mirroring this codebase's existing "don't let an error message
    reveal which guess was closer" convention (e.g. find_user_by_id()).

    Reuses ConversationRepository.reserve_next_epoch() completely
    unchanged -- the exact same counter Phase 7's group-key rotation
    and this method's own prior client-side implementation both
    already used.

    A missing request_id is silently ignored, mirroring every other
    D2/D3/D4 handler's identical guard.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    conversation_id = packet.get("conversation_id")

    try:
        conversation_uuid = uuid.UUID(conversation_id)
    except (TypeError, ValueError, AttributeError):
        conversation_uuid = None

    epoch = None
    error = None

    if conversation_uuid is None:
        error = "Invalid or missing conversation_id."
    else:
        db = SessionLocal()

        try:
            conversation_repo = ConversationRepository(db)

            member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

            if user.id not in member_ids:

                state.logger.warning(
                    f"Rejected epoch_reservation_request: {user.username} is "
                    f"not a member of conversation {conversation_id}"
                )

                error = "Not a member of this conversation."

            else:

                epoch = conversation_repo.reserve_next_epoch(conversation_uuid)

                conversation_repo.commit()
        finally:
            db.close()

    response = create_epoch_reservation_result_packet(
        request_id=request_id,
        epoch=epoch,
        error=error,
    )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send epoch_reservation_result to {user.username} "
            f"(request_id={request_id})"
        )


def handle_conversation_list_request(state, client_socket, user, packet):
    """
    Return every conversation the authenticated connection currently
    belongs to (D4.2 -- Message/History Operations Migration, second
    slice), replacing ClientSession.load_conversations()'s previous
    direct, client-side ConversationRepository.
    get_conversation_previews_for_user() call -- the last remaining
    client-side database read for the sidebar's initial population.

    Security: the caller's identity is always user.id -- the
    authenticated identity from the JWT validated at
    authenticate_connection() time -- never anything read from the
    packet (this request carries no fields at all). Unlike D4.1's
    epoch reservation, no additional membership check is needed here:
    get_conversation_previews_for_user() is already fully scoped to
    exactly one user_id -- there is no "list someone else's
    conversations" surface for a client-supplied id to have ever
    reached, since the id was never client-supplied in the first
    place.

    Reuses ConversationRepository.get_conversation_previews_for_user()
    completely unchanged. Each row is serialized into a plain dict --
    conversation_id, is_group, group_name, participants (usernames),
    and an optional latest_message (payload_type, ciphertext, epoch,
    timestamp, content_metadata) -- mirroring exactly what
    ClientSession.load_conversations()/_build_latest_message_preview()
    used to read directly off the ORM rows. ``ciphertext`` is only
    ever this already-encrypted, opaque value -- decryption stays
    entirely client-side; the server does not decrypt, inspect, or
    alter it. A FILE/IMAGE latest_message's ciphertext is None here
    exactly as it is in the database (see persist_message()) --
    previews never need blob content, only payload_type/
    content_metadata (e.g. filename) to render.

    A missing request_id is silently ignored, mirroring every other
    D2/D3/D4 handler's identical guard.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)

        previews = conversation_repo.get_conversation_previews_for_user(user.id)

        conversations = []

        for preview in previews:

            is_group = preview.conversation.type == Conversation.TYPE_GROUP

            latest_message = None

            if preview.latest_message is not None:

                latest_message = {
                    "payload_type": preview.latest_message.payload_type,
                    "ciphertext": preview.latest_message.ciphertext,
                    "epoch": preview.latest_message.epoch,
                    "timestamp": preview.latest_message.timestamp.isoformat(),
                    "content_metadata": preview.latest_message.content_metadata or {},
                }

            conversations.append({
                "conversation_id": str(preview.conversation.id),
                "is_group": is_group,
                "group_name": preview.conversation.name,
                "participants": [
                    participant.username for participant in preview.participants
                ],
                "latest_message": latest_message,
            })
    finally:
        db.close()

    response = create_conversation_list_result_packet(
        request_id=request_id,
        conversations=conversations,
    )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send conversation_list_result to {user.username} "
            f"(request_id={request_id})"
        )


def authenticate_connection(state, client_socket, client_address):
    """
    Receive and validate the client's JWT access token.

    Returns the authenticated (user, session) pair on success, or
    None on failure. In both cases an "auth_result" packet is sent
    back to the client before returning.

    A first packet of type "register_request" or "login_request" is
    handled here too (D2), before the "auth" check below: a
    registering or logging-in client has no token to send yet, so
    neither can wait for the normal post-authentication dispatch loop
    the way user_lookup_request/logout_request do. Both always return
    None afterward -- like every other rejection path in this function
    -- so the connection is closed by handle_client()'s existing
    teardown without ever being registered as a live client; obtaining
    a login_result's tokens is always a separate, throwaway connection
    from the one that later sends them via the "auth" packet below
    (see ClientSession.authenticate_credentials()). The pre-existing
    "auth" branch below is otherwise untouched.
    """

    auth_packet = receive_message(client_socket)

    if not auth_packet:
        return None

    auth_packet = parse_packet(auth_packet)

    if isinstance(auth_packet, dict) and auth_packet.get("type") == "register_request":
        handle_register_request(state, client_socket, auth_packet)
        return None

    if isinstance(auth_packet, dict) and auth_packet.get("type") == "login_request":
        handle_login_request(state, client_socket, auth_packet)
        return None

    if not isinstance(auth_packet, dict) or auth_packet.get("type") != "auth":
        send_to_client(
            client_socket,
            create_auth_result_packet(False, "Authentication required.")
        )
        return None

    access_token = auth_packet.get("access_token")

    db = SessionLocal()

    try:
        auth_service = AuthenticationService(db)

        try:
            user = auth_service.get_current_user(access_token)
            user_session = auth_service.get_current_session(access_token)
        except TokenExpiredError:
            state.logger.info(
                f"Rejected connection from {client_address}: token expired"
            )
            send_to_client(
                client_socket,
                create_auth_result_packet(
                    False,
                    "Session token has expired. Please log in again."
                )
            )
            return None
        except TokenValidationError:
            state.logger.info(
                f"Rejected connection from {client_address}: invalid token"
            )
            send_to_client(
                client_socket,
                create_auth_result_packet(
                    False,
                    "Invalid or unauthorized session."
                )
            )
            return None
    finally:
        db.close()

    send_to_client(
        client_socket,
        create_auth_result_packet(True, "Authenticated.", username=user.username)
    )

    return user, user_session


def handle_client(state, client_socket, client_address):
    """
    Handle communication with a connected client.
    """

    username = None

    try:

        # -----------------------------
        # Authenticate via JWT
        # -----------------------------
        authenticated = authenticate_connection(state, client_socket, client_address)

        if authenticated is None:
            return

        user, user_session = authenticated
        username = user.username

        # Register client, associated with the authenticated user/session
        state.add_client(
            client_socket,
            username,
            user_id=str(user.id),
            session_id=user_session.session_id
        )

        print(f"[CONNECTED] {username} ({client_address})")
        state.logger.info(f"{username} connected")

        # -----------------------------
        # Receive RSA public key
        # -----------------------------
        key_packet = receive_message(client_socket)

        if not key_packet:
            return

        key_packet = parse_packet(key_packet)

        if (
            key_packet.get("type") == "key_exchange"
            and key_packet.get("operation") == "public_key"
        ):

            state.set_public_key(
                client_socket,
                key_packet["algorithm"],
                key_packet["public_key"]
            )

            state.logger.info(
                f"Received {key_packet['algorithm']} public key "
                f"from {username}"
            )

            # Synchronize public keys between all connected clients
            distribute_public_keys(
                state,
                client_socket
            )

            # -----------------------------
            # Group key rotation recovery (Phase 7)
            #
            # Must come after distribute_public_keys() above -- see
            # _recover_pending_rotations_for_user()'s docstring for
            # why that ordering, on this same connection, is load-
            # bearing rather than incidental.
            # -----------------------------
            _recover_pending_rotations_for_user(state, user)

            # -----------------------------
            # Group key redelivery on plain reconnect (Issue 4 fix)
            #
            # Covers the case the above does not: no rotation is
            # outstanding, but this reconnecting client's own
            # KeyManager is empty (a fresh process/login). Same
            # ordering requirement as above, for the same reason.
            # -----------------------------
            _ensure_group_keys_current_for_reconnecting_user(state, user)

        # -----------------------------
        # Notify other clients
        # -----------------------------
        join_packet = create_join_packet(username)

        broadcast(
            state,
            join_packet,
            client_socket
        )

        # -----------------------------
        # Broadcast updated online users
        # -----------------------------
        broadcast_user_list(state)

        # -----------------------------
        # Receive packets
        # -----------------------------
        while True:

            packet = receive_message(client_socket)

            if not packet:
                break

            packet = parse_packet(packet)

            # -----------------------------
            # Sender authentication (security hardening)
            #
            # The client-supplied "sender" field is never trustworthy --
            # it is caller-controlled data. The authenticated identity
            # for this socket (established once, above, via JWT) is the
            # only authoritative source of who sent a chat packet.
            # Overwriting it here, before either the direct or group
            # routing path runs, means both branches relay the correct
            # value without either needing its own check. Persistence
            # was already correct (persist_message()/persist_group_message()
            # take sender_id=user.id directly, never reading this field)
            # and is unaffected by this change.
            # -----------------------------
            if packet.get("type") == "chat":
                packet["sender"] = username

            # D3.1 -- Conversation Operations Migration: the identical
            # hardening for a direct session_key packet's sender field,
            # not previously overwritten here. Needed now because the
            # direct-conversation resolution below uses the
            # authenticated sender's id, never whatever the packet
            # claims -- so the displayed/attributed identity and the
            # one actually used to resolve the conversation can never
            # diverge. Persistence is not affected: session_key packets
            # are relay-only and were never stored.
            if (
                packet.get("type") == "key_exchange"
                and packet.get("operation") == "session_key"
            ):
                packet["sender"] = username

            # -----------------------------
            # Private Chat Packet
            # -----------------------------
            if packet.get("type") == "chat" and packet.get("conversation_id"):

                # Group-addressed chat packet (Phase 4) -- same "chat"
                # type and packet shape as a direct message, routed
                # differently because conversation_id is set instead
                # of receiver. The direct-message branch below is
                # untouched by this addition.
                handle_group_chat_delivery(
                    state,
                    client_socket,
                    user,
                    packet.get("conversation_id"),
                    packet,
                )

            elif packet.get("type") == "chat":

                receiver = packet.get("receiver")

                for sock, client in list(state.clients.items()):

                    if client["username"] == receiver:

                        print(
                            f"{username} -> {receiver}: "
                            f"[Encrypted Message]"
                        )

                        state.logger.info(
                            f"{username} -> {receiver}: "
                            f"[Encrypted Message]"
                        )

                        # D3.1 -- Conversation Operations Migration:
                        # resolved here, before relay, so the receiving
                        # client can read it straight off the packet
                        # instead of resolving/creating it itself via a
                        # direct database call. Deliberately a NEW
                        # field, never "conversation_id" -- the
                        # receiving client's handle_chat() derives
                        # is_group from that field's mere presence
                        # (group packets set it, direct ones never
                        # did), so reusing it here would misclassify
                        # every direct message as a group one the
                        # moment a client is updated to read it.
                        direct_conversation_id = _resolve_direct_conversation_id(
                            user.id, client["user_id"]
                        )
                        packet["direct_conversation_id"] = direct_conversation_id

                        delivered = send_to_client(
                            sock,
                            packet
                        )

                        sender_client = state.get_client(client_socket)

                        message = persist_message(
                            sender_id=user.id,
                            receiver_id=client["user_id"],
                            algorithm=(sender_client or {}).get("algorithm"),
                            packet=packet,
                            conversation_id=direct_conversation_id,
                        )

                        # C2 -- Read Receipts: DELIVERED only if the
                        # live relay above actually succeeded -- a
                        # send_to_client() failure (dead socket,
                        # aborted connection) must not be recorded as
                        # delivered; QUEUED is exactly the correct,
                        # already-existing status for "persisted but
                        # not yet confirmed delivered" (the same status
                        # the offline branch below uses).
                        try:
                            _record_direct_recipient(
                                message,
                                uuid.UUID(client["user_id"]),
                                delivered=delivered,
                            )
                        except Exception as error:  # noqa: BLE001

                            # Intentionally broad and scoped to this
                            # bookkeeping call alone -- the message was
                            # already relayed and persisted above, so a
                            # failure here (e.g. a transient DB error
                            # writing the MessageRecipient row) must
                            # never undo or interrupt a delivery that
                            # already succeeded; only read-receipt
                            # status tracking is at risk, not the
                            # message itself. Reuses the same logging
                            # as the OFFLINE branch's equivalent guard
                            # below -- the failure is always visible,
                            # never silently swallowed.
                            print(f"[ERROR] {error}")

                            state.logger.error(str(error))

                        break

                else:

                    # Loop completed without finding a matching
                    # connected recipient. The message is still
                    # persisted (real-application bug fix, C1 --
                    # Offline Direct-Message Persistence) exactly like
                    # a group message already is regardless of which
                    # members are connected (see persist_group_message()) --
                    # only delivery_failure's live-relay-didn't-happen
                    # meaning stays unchanged; it never claimed the
                    # message was lost, only that it wasn't delivered
                    # right now.
                    #
                    # A receiver that doesn't resolve to any real user
                    # at all (typo, never registered) is unaffected --
                    # persist_message() requires a real receiver_id
                    # foreign key, so there is nothing to persist
                    # under, exactly as before this fix.
                    db = SessionLocal()

                    try:
                        offline_user = UserRepository(db).get_by_username(receiver)
                    finally:
                        db.close()

                    if offline_user is not None:

                        try:
                            sender_client = state.get_client(client_socket)

                            # D3.1 -- Conversation Operations Migration:
                            # resolved the same way as the online branch
                            # above, even though nothing is relayed live
                            # here -- persist_message() still needs it,
                            # and a later reconnect's history/list
                            # request (a future slice) must see the same
                            # conversation an online delivery would have
                            # used.
                            direct_conversation_id = _resolve_direct_conversation_id(
                                user.id, offline_user.id
                            )

                            message = persist_message(
                                sender_id=user.id,
                                receiver_id=offline_user.id,
                                algorithm=(sender_client or {}).get("algorithm"),
                                packet=packet,
                                conversation_id=direct_conversation_id,
                            )

                            # C2 -- Read Receipts: nobody was
                            # connected to relay to, above -- QUEUED,
                            # not DELIVERED.
                            _record_direct_recipient(
                                message,
                                offline_user.id,
                                delivered=False,
                            )

                        except Exception as error:  # noqa: BLE001

                            # Intentionally broad, not an oversight:
                            # persist_message() can fail for reasons
                            # spanning unrelated exception hierarchies
                            # -- SQLAlchemyError from db.commit()/the
                            # conversation lookup, OSError from
                            # encrypted_blob_store's filesystem write
                            # (FILE/IMAGE payloads), or AttributeError/
                            # TypeError from a malformed packet -- and
                            # no single specific except would isolate
                            # all of them. This failure must be
                            # isolated here so delivery_failure (below)
                            # is still returned to the sender no matter
                            # what went wrong; letting it propagate
                            # would skip that response entirely. Reuses
                            # the exact logging this file's own outer
                            # exception handler already uses -- the
                            # failure is always visible, never silently
                            # swallowed, and nothing here ever reports
                            # the message as successfully persisted.
                            print(f"[ERROR] {error}")

                            state.logger.error(str(error))

                    # Loop completed without finding a matching
                    # connected recipient -- report delivery failure
                    # to the sender instead of silently dropping it.
                    state.logger.info(
                        f"Delivery failed: {username} -> {receiver} "
                        f"(recipient not connected)"
                    )

                    send_to_client(
                        client_socket,
                        create_delivery_failure_packet(receiver)
                    )

            # -----------------------------
            # Session Key Exchange Packet
            # -----------------------------
            elif (
                packet.get("type") == "key_exchange"
                and packet.get("operation") == "session_key"
            ):

                receiver = packet.get("receiver")

                for sock, client in state.clients.items():

                    if client["username"] == receiver:

                        # D3.1 -- Conversation Operations Migration:
                        # resolved from the authenticated sender
                        # (user.id) and the matched recipient's own
                        # user_id -- never from anything the packet
                        # claims. A session_key packet is always
                        # direct (group keys use group_key_distribution
                        # instead), so there is no is_group ambiguity
                        # here the way there is for "chat" -- reusing
                        # the field name "conversation_id" is safe.
                        packet["conversation_id"] = _resolve_direct_conversation_id(
                            user.id, client["user_id"]
                        )

                        if send_to_client(sock, packet):

                            state.logger.info(
                                f"Forwarded session key "
                                f"from {username} to {receiver}"
                            )

                        else:

                            state.logger.warning(
                                f"Failed to forward session key "
                                f"from {username} to {receiver}"
                            )

                        break

            # -----------------------------
            # Group Create Packet
            # -----------------------------
            elif packet.get("type") == "group_create":

                handle_group_create(state, client_socket, user, packet)

            # -----------------------------
            # Group Key Distribution Packet
            # -----------------------------
            elif packet.get("type") == "group_key_distribution":

                recipient = packet.get("recipient")

                for sock, client in list(state.clients.items()):

                    if client["username"] == recipient:

                        if send_to_client(sock, packet):

                            state.logger.info(
                                f"Forwarded group key for "
                                f"{packet.get('conversation_id')} "
                                f"from {username} to {recipient}"
                            )

                        else:

                            state.logger.warning(
                                f"Failed to forward group key for "
                                f"{packet.get('conversation_id')} "
                                f"from {username} to {recipient}"
                            )

                        break

            # -----------------------------
            # Group Leave Packet (Phase 7)
            # -----------------------------
            elif packet.get("type") == "group_leave":

                handle_group_leave(state, client_socket, user, packet)

            # -----------------------------
            # Group Key Rotation Complete Packet (Phase 7)
            # -----------------------------
            elif packet.get("type") == "group_key_rotation_complete":

                handle_group_key_rotation_complete(state, client_socket, user, packet)

            # -----------------------------
            # Group Add Members Packet (Issue 2 fix)
            # -----------------------------
            elif packet.get("type") == "group_add_members":

                handle_group_add_members(state, client_socket, user, packet)

            # -----------------------------
            # Read Receipt Packet (C2)
            # -----------------------------
            elif packet.get("type") == "read_receipt":

                handle_read_receipt(state, client_socket, user, packet)

            # -----------------------------
            # User Lookup Request (D2)
            # -----------------------------
            elif packet.get("type") == "user_lookup_request":

                handle_user_lookup(state, client_socket, user, packet)

            # -----------------------------
            # Logout Request (D2)
            # -----------------------------
            elif packet.get("type") == "logout_request":

                handle_logout_request(state, client_socket, user, packet)

            # -----------------------------
            # Direct Conversation Request (D3.3)
            # -----------------------------
            elif packet.get("type") == "direct_conversation_request":

                handle_direct_conversation_request(state, client_socket, user, packet)

            # -----------------------------
            # Epoch Reservation Request (D4.1)
            # -----------------------------
            elif packet.get("type") == "epoch_reservation_request":

                handle_epoch_reservation_request(state, client_socket, user, packet)

            # -----------------------------
            # Conversation List Request (D4.2)
            # -----------------------------
            elif packet.get("type") == "conversation_list_request":

                handle_conversation_list_request(state, client_socket, user, packet)

    except Exception as e:

        print(f"[ERROR] {e}")
        state.logger.error(str(e))

    finally:

        client = state.get_client(client_socket)

        if client:

            username = client["username"]

            leave_packet = create_leave_packet(username)

            broadcast(
                state,
                leave_packet,
                client_socket
            )

            # Remove client before broadcasting
            state.remove_client(client_socket)

            # Broadcast updated online users
            broadcast_user_list(state)

        try:
            client_socket.close()
        except OSError:
            pass

        print(f"[DISCONNECTED] {client_address}")

        if username:
            state.logger.info(f"{username} disconnected")