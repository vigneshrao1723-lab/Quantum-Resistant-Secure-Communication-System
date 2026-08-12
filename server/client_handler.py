"""
Client Handler Module

Handles communication with individual clients.
"""

import uuid
from datetime import datetime, timezone

from auth.authentication_service import AuthenticationService
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
    create_delivery_failure_packet,
    create_group_create_result_packet,
    create_group_key_rotation_required_packet,
    create_group_member_left_packet,
    create_group_members_added_packet,
    create_join_packet,
    create_leave_packet,
    create_read_receipt_notification_packet,
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


def authenticate_connection(state, client_socket, client_address):
    """
    Receive and validate the client's JWT access token.

    Returns the authenticated (user, session) pair on success, or
    None on failure. In both cases an "auth_result" packet is sent
    back to the client before returning.
    """

    auth_packet = receive_message(client_socket)

    if not auth_packet:
        return None

    auth_packet = parse_packet(auth_packet)

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

                        delivered = send_to_client(
                            sock,
                            packet
                        )

                        sender_client = state.get_client(client_socket)

                        message = persist_message(
                            sender_id=user.id,
                            receiver_id=client["user_id"],
                            algorithm=(sender_client or {}).get("algorithm"),
                            packet=packet
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

                            message = persist_message(
                                sender_id=user.id,
                                receiver_id=offline_user.id,
                                algorithm=(sender_client or {}).get("algorithm"),
                                packet=packet
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