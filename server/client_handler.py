"""
Client Handler Module

Handles communication with individual clients.
"""

import base64
import uuid
from datetime import datetime, timezone

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from config import (
    KEY_EXCHANGE_ALGORITHM,
    MAX_ATTACHMENT_CIPHERTEXT_BYTES,
)
from database.connection import SessionLocal
from database.models.conversation import Conversation
from database.models.inbox_notification import TYPE_GROUP_ADD_REQUEST, TYPE_VERIFICATION_REQUEST
from database.models.user import User
from database.repositories.blocked_user_repository import BlockedUserRepository
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.inbox_repository import InboxRepository
from database.repositories.message_repository import MessageRepository
from database.repositories.user_repository import UserRepository
from domain.message_delivery_status import MessageDeliveryStatus
from domain.payload_envelope import PayloadEnvelope
from domain.payload_type import BLOB_STORAGE_PAYLOAD_TYPES, PayloadType
from security.jwt_handler import TokenExpiredError, TokenValidationError
from security.phone_number import (
    InvalidPhoneNumberError,
    normalize_phone_number,
)
from server.broadcaster import (
    broadcast,
    broadcast_user_list,
    distribute_public_keys,
    send_to_client,
)
from server.device_handler import (
    handle_device_authorize,
    handle_device_enroll_request,
    handle_device_key_sync,
    handle_device_list_request,
    handle_device_revoke,
    handle_device_session_bind,
    is_device_bound_and_authorized,
)
from storage import encrypted_blob_store
from utils.network import receive_message
from utils.protocol import (
    create_auth_result_packet,
    create_blob_download_result_packet,
    create_conversation_list_result_packet,
    create_block_user_result_packet,
    create_blocked_users_list_result_packet,
    create_delivery_failure_packet,
    create_direct_conversation_result_packet,
    create_direct_key_recovery_available_packet,
    create_direct_key_redelivery_required_packet,
    create_epoch_reservation_result_packet,
    create_group_create_result_packet,
    create_group_key_rotation_required_packet,
    create_change_password_result_packet,
    create_change_username_result_packet,
    create_group_member_left_packet,
    create_group_members_added_packet,
    create_group_remove_member_result_packet,
    create_inbox_list_result_packet,
    create_inbox_notification_packet,
    create_inbox_response_result_packet,
    create_unblock_user_result_packet,
    create_join_packet,
    create_bio_result_packet,
    create_change_bio_result_packet,
    create_leave_packet,
    create_login_result_packet,
    create_logout_result_packet,
    create_message_delivered_packet,
    create_message_deleted_notification_packet,
    create_last_seen_result_packet,
    create_message_edited_notification_packet,
    create_message_history_result_packet,
    create_message_pinned_notification_packet,
    create_message_queued_packet,
    create_message_unpinned_notification_packet,
    create_reaction_updated_notification_packet,
    create_profile_picture_result_packet,
    create_profile_picture_upload_result_packet,
    create_read_receipt_notification_packet,
    create_register_result_packet,
    create_typing_indicator_notification_packet,
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

            # D8 / P1 -- the attachment limit enforced SERVER-side.
            #
            # config.MAX_ATTACHMENT_SIZE_BYTES was checked only in
            # client/session.py, i.e. only by clients that choose to
            # check it. A modified client could write arbitrarily
            # large blobs into FILE_STORAGE_ROOT, which has no quota,
            # no retention policy and no cleanup -- disk exhaustion
            # with nothing in the way.
            #
            # The bound is the EXACT ciphertext size a maximum-size
            # attachment produces (see config._wire_ciphertext_bytes),
            # so a legitimate 25 MiB file is accepted and one byte
            # more is not. Checked before store_blob(), so an
            # oversized payload never reaches the filesystem.
            #
            # This is deliberately a second, independent limit rather
            # than a restatement of MAX_FRAME_BYTES: the frame cap
            # protects memory during the read, this protects disk at
            # rest, and the frame cap has to carry JSON envelope
            # slack that must not become attachment headroom.
            ciphertext_size = len(envelope.ciphertext or "")

            if ciphertext_size > MAX_ATTACHMENT_CIPHERTEXT_BYTES:
                raise ValueError(
                    f"Attachment ciphertext is {ciphertext_size:,} bytes; "
                    f"the maximum is {MAX_ATTACHMENT_CIPHERTEXT_BYTES:,}."
                )

            blob_ref = encrypted_blob_store.store_blob(envelope.ciphertext.encode("utf-8"))
            ciphertext = None
        else:
            blob_ref = None
            ciphertext = envelope.ciphertext

        # Phase 19.24 -- Message Lifecycle Events. reply_to_message_id
        # is a client-supplied field, but a FOREIGN KEY to messages.id
        # -- an attacker naming a message_id from a conversation they
        # are not even a member of gains nothing (the reply is still
        # only ever relayed to THIS conversation's own members, exactly
        # like every other field on this packet; rendering the quoted
        # preview is a client-side, best-effort convenience, never an
        # access grant). A malformed/unparseable value is dropped
        # rather than raising -- a reply reference is enrichment, not
        # something that should ever fail an otherwise-valid send.
        reply_to_message_id = packet.get("reply_to_message_id")
        try:
            reply_to_message_id = (
                uuid.UUID(reply_to_message_id) if reply_to_message_id else None
            )
        except (ValueError, AttributeError, TypeError):
            reply_to_message_id = None

        message, was_duplicate = message_repo.save_message_idempotent(
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
            # Message-Level ML-DSA Origin Authentication: carried into
            # offline storage unchanged, opaque to the server -- see
            # client/session.py::_decrypt_history_message() for where
            # it is verified on read. None for any packet with no
            # signature at all (there is no legacy unsigned path for
            # messages -- see handle_chat()'s own docstring).
            message_signature=packet.get("message_signature"),
            reply_to_message_id=reply_to_message_id,
            client_message_id=packet.get("client_message_id") or None,
        )

        if was_duplicate:
            # A retried send whose ORIGINAL attempt already succeeded
            # (same client_message_id) -- nothing new was inserted.
            # Still committed, not rolled back: SessionLocal expires
            # every tracked object on rollback regardless of
            # expire_on_commit=False, which would turn this function's
            # own return value into a DetachedInstanceError the moment
            # a caller reads message.id after db.close() below. Nothing
            # uncommitted here is unsafe to commit -- get_or_create_
            # direct_conversation() above is itself idempotent, and no
            # new Message row was created. Any blob this retry just
            # wrote via store_blob() is an orphan; deliberately left
            # for existing blob-cleanup/retention tooling rather than
            # deleted here (it already exists on disk independently of
            # this DB transaction).
            db.commit()
            return message

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
    a direct database call (client/conversation_store.py::
    ensure_direct_conversation_id() -- unmigrated by this slice, since
    it was no longer reached from handle_chat()/handle_session_key()
    once they consume the field this populates -- was itself deleted
    in D4.3, once its one remaining caller was migrated too).

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
    sender_id, conversation_id, member_ids, algorithm, packet
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
    separately via MessageRepository.record_recipients(), and every row
    is created QUEUED -- "persisted, not yet live-delivered".

    BUG 2 -- ordering. This now runs BEFORE the fan-out, not after, so
    a recipient can never hold a message whose MessageRecipient row
    does not exist yet. Previously the relay came first, which left a
    window in which a recipient could legitimately read the message
    while there was no row for a read receipt to update -- and
    handle_read_receipt() discarded such receipts silently. Because
    nothing has been relayed at this point, QUEUED is simply accurate;
    handle_group_chat_delivery() promotes the members the relay
    actually reached via _mark_recipients_delivered() afterwards.

    Returns the persisted message so the caller can address that
    promotion without a second lookup.

    A known, accepted limitation retained from this foundation phase:
    the content row and the recipient rows are committed in two
    separate transactions (reusing persist_message()'s own
    self-contained session rather than threading a shared one
    through). If the second transaction were to fail, the message
    itself would still be correctly persisted and readable -- only its
    delivery-status bookkeeping would be missing, not corrupted. Full
    atomicity remains a reasonable future hardening; the ordering fix
    above does not depend on it, since both transactions now complete
    before anything is relayed.
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

        message_repo.record_recipients(message.id, recipient_ids, [])

        db.commit()
    finally:
        db.close()

    return message


def _record_direct_recipient(message, receiver_id):
    """
    Create a direct message's MessageRecipient row as QUEUED (C2 --
    Read Receipts; ordering per BUG 2).

    Always QUEUED, never DELIVERED. The row is now written BEFORE the
    message is relayed, so at the moment it is created nothing has
    been delivered yet -- QUEUED ("persisted, not yet live-delivered")
    is simply the truth. A successful relay promotes it afterwards via
    _mark_recipients_delivered().

    That ordering is the fix for a real race: the server used to relay
    first and record afterwards, which left a window where the
    recipient held the message and could legitimately read it while
    the row a read receipt must update did not exist yet. In that
    window mark_conversation_read() matched nothing and
    handle_read_receipt() discarded the receipt silently.

    Reuses record_recipients() unchanged, with an empty delivered set.
    A direct message always has exactly one recipient, so this is
    always a one-element list -- the same generic method group
    messages already use, not a parallel mechanism.
    """

    db = SessionLocal()

    try:
        message_repo = MessageRepository(db)

        message_repo.record_recipients(message.id, [receiver_id], [])

        db.commit()
    finally:
        db.close()


def _mark_recipients_delivered(message_id, recipient_ids):
    """
    Promote QUEUED -> DELIVERED for the recipients a relay actually
    reached (BUG 2). Shared by the direct and group paths so there is
    exactly one place this transition happens.

    Never downgrades READ: MessageRepository.mark_delivered() selects
    only QUEUED rows, so a recipient who read the message in the gap
    between row creation and this call keeps READ. See that method for
    why that gap is reachable rather than theoretical.
    """

    recipient_ids = list(recipient_ids)

    if not recipient_ids:
        return []

    db = SessionLocal()

    try:
        message_repo = MessageRepository(db)

        promoted = message_repo.mark_delivered(message_id, recipient_ids)

        db.commit()

        return promoted
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

    sender_client = state.get_client(client_socket)

    # BUG 2 -- persist BEFORE relaying, so every member's
    # MessageRecipient row exists (QUEUED) before any of them can hold
    # the message and send a read receipt for it. Relaying first left a
    # window in which a receipt had no row to update and was silently
    # discarded.
    #
    # Deliberately not wrapped: a group message that cannot be
    # persisted is not deliverable state this handler should paper
    # over, and letting it propagate matches how this path already
    # behaved when persistence failed.
    message = persist_group_message(
        sender_id=user.id,
        conversation_id=uuid.UUID(conversation_id),
        member_ids=member_ids,
        algorithm=(sender_client or {}).get("algorithm"),
        packet=packet,
    )

    # Phase 18.5 -- Step 6 (History Deduplication): same rationale as
    # the direct-chat relay's identical addition -- the stable id
    # message_history_result already reports for this row once
    # persisted, added here additively so a client that already
    # rendered this live group message can recognize it again later via
    # history and skip re-rendering it. Not part of any ML-DSA-signed
    # payload, so this changes nothing about what was already signed.
    packet["message_id"] = str(message.id)

    member_id_strings = {str(member_id) for member_id in member_ids}
    connected_member_ids = []

    for sock, client in list(state.clients.items()):

        if sock == client_socket:
            continue

        # Phase 19.18 -- L-1 closure, group side: same per-socket
        # revoked-device skip as the direct-chat relay above -- a
        # revoked member's device is excluded from this fan-out (and
        # therefore from connected_member_ids/DELIVERED promotion)
        # without affecting any of their OTHER, non-revoked devices,
        # or any other member.
        if (
            client.get("user_id") in member_id_strings
            and is_device_bound_and_authorized(state, sock) is False
        ):

            state.logger.warning(
                f"Dropped group chat relay in {conversation_id}: "
                f"a recipient's bound device is not AUTHORIZED"
            )

            continue

        # Only actually-successful sends count as "connected" here --
        # connected_member_ids drives the QUEUED -> DELIVERED promotion
        # below, so a failed relay must not be recorded as delivered.
        if (
            client.get("user_id") in member_id_strings
            and send_to_client(sock, packet)
        ):
            connected_member_ids.append(uuid.UUID(client["user_id"]))

    state.logger.info(
        f"{user.username} -> group {conversation_id}: "
        f"[Encrypted Message] ({len(connected_member_ids)} connected recipients)"
    )

    # Promote only the members actually reached, and only from QUEUED --
    # a member who has already read the message keeps READ (see
    # MessageRepository.mark_delivered()). The sender is never in
    # connected_member_ids, so they are never promoted either.
    _mark_recipients_delivered(
        message.id,
        [
            member_id
            for member_id in connected_member_ids
            if member_id != user.id
        ],
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
        blocked_repo = BlockedUserRepository(db)

        for username in member_usernames:

            if username == user.username:
                continue

            member = user_repo.get_by_username(username)

            if member is None:
                continue

            # Phase 19.24 -- Block User: a block in EITHER direction
            # between the creator and a candidate member silently
            # excludes them from this BRAND NEW group -- same silent-
            # skip pattern as "member is None" above (never a
            # distinguishable error). Does not touch any EXISTING
            # group's membership -- see database/models/blocked_
            # user.py's own docstring for why a 1:1 block never
            # retroactively affects a shared group thread.
            if blocked_repo.is_blocked(member.id, user.id) or blocked_repo.is_blocked(user.id, member.id):
                continue

            member_ids.append(member.id)
            resolved_usernames.append(member.username)

        conversation = conversation_repo.create_group_conversation(
            member_ids=member_ids, name=name, creator_id=user.id,
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


def handle_group_remove_member(state, client_socket, user, packet):
    """
    Remove ANOTHER member from a group conversation (Phase 19.13 --
    Group Admin). Unlike handle_group_leave() (self-service, any
    member), this is admin-only: the caller's role is always
    re-derived server-side from ConversationRepository.
    get_admin_user_id(), never trusted from the packet or from
    whether the requesting client's own UI happened to show a Remove
    Member button. A non-admin caller (including an admin trying to
    remove themselves through this path, or a group with no recorded
    admin) is rejected with a friendly error, no membership change,
    no crash -- mirrors every other group-authorization rejection in
    this file.

    Reuses leave_conversation() + reserve_next_epoch() +
    _dispatch_pending_rotation_if_needed() exactly as handle_group_
    leave() does -- the removed member must lose access to future
    messages the same way a self-departed member does, which requires
    the same key rotation, not a different one.
    """

    conversation_id = packet.get("conversation_id")
    target_username = packet.get("target_username")
    request_id = packet.get("request_id")

    if not conversation_id or not target_username:
        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        user_repo = UserRepository(db)
        conversation_uuid = uuid.UUID(conversation_id)

        admin_id = conversation_repo.get_admin_user_id(conversation_uuid)

        if admin_id is None or admin_id != user.id:

            state.logger.warning(
                f"Rejected group_remove_member: {user.username} is not the "
                f"admin of {conversation_id}"
            )

            send_to_client(client_socket, create_group_remove_member_result_packet(
                request_id=request_id, success=False,
                error="Only the group admin can remove members.",
            ))

            return

        target = user_repo.get_by_username(target_username)
        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

        if target is None or target.id not in member_ids:
            send_to_client(client_socket, create_group_remove_member_result_packet(
                request_id=request_id, success=False,
                error=f"{target_username} is not a member of this group.",
            ))
            return

        if target.id == admin_id:
            send_to_client(client_socket, create_group_remove_member_result_packet(
                request_id=request_id, success=False,
                error="The group admin cannot be removed.",
            ))
            return

        conversation_repo.leave_conversation(conversation_uuid, target.id)
        conversation_repo.reserve_next_epoch(conversation_uuid)

        conversation_repo.commit()

        remaining_ids = [m for m in member_ids if m != target.id]
        remaining_usernames = _usernames_for(db, remaining_ids)
    finally:
        db.close()

    member_left_packet = create_group_member_left_packet(
        conversation_id=conversation_id,
        username=target_username,
        members=remaining_usernames,
    )

    all_former_id_strings = {str(m) for m in member_ids}

    for sock, client in list(state.clients.items()):

        if client.get("user_id") in all_former_id_strings:
            send_to_client(sock, member_left_packet)

    send_to_client(client_socket, create_group_remove_member_result_packet(
        request_id=request_id, success=True,
    ))

    state.logger.info(
        f"{user.username} (admin) removed {target_username} from group "
        f"{conversation_id} (remaining: {remaining_usernames})"
    )

    if remaining_ids:
        _dispatch_pending_rotation_if_needed(state, conversation_id)


# ------------------------------------------------------------------
# Inbox: verification requests + group member-add approval
# (Phase 19.13 -- User Manual Feedback Implementation)
# ------------------------------------------------------------------


def _push_inbox_notification(state, recipient_user_id, notification_dict, *, is_response=False):
    """
    Best-effort live delivery of one inbox notification to
    ``recipient_user_id`` if they are currently connected -- a no-op
    if not; they will see it next time their client sends
    inbox_list_request (login, or opening the Inbox screen). Mirrors
    every other "push if online, otherwise it waits" pattern already
    in this file (e.g. group_key_rotation_required).

    ``is_response`` selects the packet shape: True for "here is the
    outcome of YOUR earlier request" (create_inbox_response_result_
    packet, sent to the original requester), False for "here is a
    brand-new request for YOU to act on" (create_inbox_notification_
    packet, sent to the recipient).
    """

    recipient_id_string = str(recipient_user_id)

    for sock, client in list(state.clients.items()):

        if client.get("user_id") == recipient_id_string:

            packet = (
                create_inbox_response_result_packet(notification_dict)
                if is_response
                else create_inbox_notification_packet(notification_dict)
            )

            send_to_client(sock, packet)

            return


def _serialize_verification_notification(notification, requester_username, recipient_username=None):
    return {
        "notification_id": str(notification.id),
        "type": TYPE_VERIFICATION_REQUEST,
        "status": notification.status,
        "requester_username": requester_username,
        "recipient_username": recipient_username,
        "created_at": notification.created_at.isoformat(),
    }


def _serialize_group_add_notification(notification, requester_username, candidate_username, group_name=None):
    return {
        "notification_id": str(notification.id),
        "type": TYPE_GROUP_ADD_REQUEST,
        "status": notification.status,
        "requester_username": requester_username,
        "candidate_username": candidate_username,
        "conversation_id": str(notification.conversation_id),
        "group_name": group_name,
        "created_at": notification.created_at.isoformat(),
    }


def handle_verification_request(state, client_socket, user, packet):
    """
    USER A (the authenticated caller) asks the server to notify
    USER B (``target_username``) that A wants B to verify A's
    identity (Phase 19.13 -- Inbox + Verification Request Workflow).

    This handler NEVER performs or influences cryptographic
    verification itself -- it only records who asked whom
    (InboxRepository.create_verification_request(), with duplicate
    protection built in) and, if B is online, pushes a live
    notification. The actual trust decision happens entirely on B's
    own client when B approves (see handle_inbox_response()'s own
    docstring) -- exactly ClientSession.confirm_combined_peer_
    verification(), called locally with B's own already-observed
    fingerprint, unchanged and unweakened.
    """

    target_username = packet.get("target_username")

    if not target_username or target_username == user.username:
        return

    db = SessionLocal()

    try:
        user_repo = UserRepository(db)
        inbox_repo = InboxRepository(db)

        target = user_repo.get_by_username(target_username)

        if target is None:
            return

        # Phase 19.24 -- Block User: a block in EITHER direction
        # refuses the request silently, the same as an unknown
        # username above -- never a distinguishable error, so a
        # blocked requester cannot use this to confirm they've been
        # blocked.
        blocked_repo = BlockedUserRepository(db)
        if blocked_repo.is_blocked(target.id, user.id) or blocked_repo.is_blocked(user.id, target.id):
            return

        notification = inbox_repo.create_verification_request(
            requester_id=user.id, recipient_id=target.id,
        )
        inbox_repo.commit()

        notification_dict = _serialize_verification_notification(notification, user.username)
        recipient_id = target.id
    finally:
        db.close()

    _push_inbox_notification(state, recipient_id, notification_dict)

    state.logger.info(
        f"{user.username} requested verification from {target_username}"
    )


def handle_inbox_list_request(state, client_socket, user, packet):
    """
    Return every inbox notification (pending or resolved) where the
    authenticated caller is either the recipient or the original
    requester (InboxRepository.get_for_user()) -- mirrors
    handle_conversation_list_request()'s identical "identity comes
    from the authenticated socket, request carries no fields" shape.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    db = SessionLocal()

    try:
        inbox_repo = InboxRepository(db)
        user_repo = UserRepository(db)

        notifications = []

        for notification in inbox_repo.get_for_user(user.id):

            requester = user_repo.get_by_id(notification.requester_user_id)
            requester_username = requester.username if requester is not None else None

            if notification.type == TYPE_VERIFICATION_REQUEST:
                notifications.append(
                    _serialize_verification_notification(notification, requester_username)
                )
            else:
                candidate = user_repo.get_by_id(notification.candidate_user_id)
                candidate_username = candidate.username if candidate is not None else None
                conversation = db.get(Conversation, notification.conversation_id)
                group_name = conversation.name if conversation is not None else None
                notifications.append(
                    _serialize_group_add_notification(
                        notification, requester_username, candidate_username, group_name,
                    )
                )
    finally:
        db.close()

    send_to_client(client_socket, create_inbox_list_result_packet(
        request_id=request_id, notifications=notifications,
    ))


def handle_inbox_response(state, client_socket, user, packet):
    """
    The authenticated caller (the notification's RECIPIENT) approves
    or denies one pending inbox notification (InboxRepository.
    resolve() -- pending-only, so a second response to an
    already-resolved notification is a safe no-op: duplicate-
    processing protection). Security: which notification and whose
    decision is always re-derived from the authenticated socket +
    the notification's own stored recipient_user_id, never trusted
    from anything else in the packet -- a caller who is not the
    recipient gets exactly the same "not found" outcome as a bogus
    notification_id, never a hint that a different notification_id
    would have worked.

    verification_request: approving here does NOT itself verify
    anything cryptographically -- see handle_verification_request()'s
    docstring. This handler only records the outcome and notifies the
    original requester; the recipient's own client is responsible for
    having already called confirm_combined_peer_verification() BEFORE
    sending an approve=True inbox_response (see mobile/app.py's
    Inbox screen wiring) -- exactly as it would from the existing
    Verify Identity dialog.

    group_add_request: approving here runs the real membership change
    through _perform_group_add_members() -- the exact same path an
    admin's own direct add uses -- rather than re-implementing it.
    """

    notification_id = packet.get("notification_id")
    approve = bool(packet.get("approve"))

    if not notification_id:
        return

    db = SessionLocal()

    try:
        inbox_repo = InboxRepository(db)
        user_repo = UserRepository(db)

        notification = inbox_repo.get_by_id(uuid.UUID(notification_id))

        if notification is None or notification.recipient_user_id != user.id:

            state.logger.warning(
                f"Rejected inbox_response: {user.username} is not the "
                f"recipient of notification {notification_id}"
            )

            return

        notification_type = notification.type
        requester_id = notification.requester_user_id
        conversation_id = notification.conversation_id
        candidate_id = notification.candidate_user_id

        resolved = inbox_repo.resolve(uuid.UUID(notification_id), approve)

        if resolved is None:
            # Already resolved (duplicate Approve/Deny) -- no-op.
            return

        inbox_repo.commit()

        requester = user_repo.get_by_id(requester_id)
        requester_username = requester.username if requester is not None else None

        if notification_type == TYPE_VERIFICATION_REQUEST:
            notification_dict = _serialize_verification_notification(
                resolved, requester_username, recipient_username=user.username,
            )
        else:
            candidate = user_repo.get_by_id(candidate_id)
            candidate_username = candidate.username if candidate is not None else None
            conversation = db.get(Conversation, conversation_id)
            group_name = conversation.name if conversation is not None else None
            notification_dict = _serialize_group_add_notification(
                resolved, requester_username, candidate_username, group_name,
            )

        should_add_member = (
            notification_type == TYPE_GROUP_ADD_REQUEST and approve
            and candidate_id not in set(
                ConversationRepository(db).get_member_user_ids(conversation_id)
            )
        )
        conversation_id_str = str(conversation_id) if conversation_id else None
        candidate_id_value = candidate_id
    finally:
        db.close()

    _push_inbox_notification(state, requester_id, notification_dict, is_response=True)

    state.logger.info(
        f"{user.username} {'approved' if approve else 'denied'} "
        f"{notification_type} {notification_id} from {requester_username}"
    )

    if should_add_member:
        _perform_group_add_members(
            state, conversation_id_str, [candidate_id_value], user.username,
        )


# ------------------------------------------------------------------
# Settings (Phase 19.14): change username/password, profile picture
# upload/fetch.
# ------------------------------------------------------------------

# Deliberately smaller than MAX_ATTACHMENT_CIPHERTEXT_BYTES (chat
# attachments already stream in over the existing, size-tested blob
# pipeline) -- a profile picture arrives as one single packet, not
# chunked, so this cap keeps that packet a reasonable size on the
# wire rather than reusing the much larger attachment limit.
_MAX_PROFILE_PICTURE_BYTES = 2 * 1024 * 1024


def handle_change_username_request(state, client_socket, user, packet):
    """
    Rename the authenticated connection's own account (Phase 19.14 --
    Settings). Identity to change is always ``user`` -- the
    authenticated socket -- never anything else in the packet.

    Updates this connection's own in-memory state.clients[...]
    ["username"] immediately on success, so every routing check that
    reads it (message delivery, group broadcasts, user-list) reflects
    the new name for the REST OF THIS CONNECTION without requiring a
    reconnect. Known, disclosed limitation (see Phase 19.14's own
    final report): other already-open conversations on OTHER clients
    still reference the OLD username in their own local state until
    they independently reload it (e.g. a fresh conversation_list_
    request) -- there is no broadcast-a-rename-to-every-peer packet in
    this phase's scope.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    new_username = packet.get("new_username")

    db = SessionLocal()

    try:
        result = AuthenticationService(db).change_username(user.id, new_username)
    finally:
        db.close()

    send_to_client(client_socket, create_change_username_result_packet(
        request_id=request_id, success=result["success"], error=result["error"],
    ))

    if result["success"]:
        old_username = user.username
        client = state.get_client(client_socket)
        if client is not None:
            client["username"] = new_username
        user.username = new_username
        state.logger.info(f"{old_username} changed their username to {new_username}")


def handle_change_password_request(state, client_socket, user, packet):
    """
    Change the authenticated connection's own account password (Phase
    19.14 -- Settings). Requires the current password (see
    AuthenticationService.change_password()'s own docstring for why).
    Neither the current nor the new password is ever logged -- only
    the outcome (see AuthenticationService's own _log_auth_event calls).
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    current_password = packet.get("current_password") or ""
    new_password = packet.get("new_password") or ""
    confirm_password = packet.get("confirm_password") or ""

    db = SessionLocal()

    try:
        result = AuthenticationService(db).change_password(
            user.id, current_password, new_password, confirm_password,
        )
    finally:
        db.close()

    send_to_client(client_socket, create_change_password_result_packet(
        request_id=request_id, success=result["success"], error=result["error"],
    ))

    if result["success"]:
        state.logger.info(f"{user.username} changed their password")


def handle_block_user_request(state, client_socket, user, packet):
    """
    Block ``target_username`` on behalf of the authenticated connection
    (Phase 19.24 -- Block User). Server-side and persisted (database/
    models/blocked_user.py), unlike Mute/Archive's local-only
    preferences -- this must be enforced for every authorized device
    of both accounts, not just this one connection, and must survive
    logout/reinstall.

    Directional: only ``user`` (the caller) blocks ``target_username``
    -- the reverse relationship, if any, is untouched. Blocking
    yourself, or a username that does not resolve, fails cleanly with
    an error rather than silently succeeding at nothing.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_username = packet.get("target_username")

    db = SessionLocal()

    try:
        if not target_username:
            success, error = False, "A username is required."
        elif target_username == user.username:
            success, error = False, "You cannot block yourself."
        else:
            target = UserRepository(db).get_by_username(target_username)
            if target is None:
                success, error = False, "No such user."
            else:
                BlockedUserRepository(db).block(user.id, target.id)
                db.commit()
                success, error = True, None
    finally:
        db.close()

    send_to_client(client_socket, create_block_user_result_packet(
        request_id=request_id, success=success, error=error,
    ))

    if success:
        state.logger.info(f"{user.username} blocked {target_username}")
        # Presence hides each blocked party from the other immediately,
        # not just from the next unrelated connect/disconnect trigger.
        broadcast_user_list(state)


def handle_unblock_user_request(state, client_socket, user, packet):
    """Reverse of handle_block_user_request() -- see its own
    docstring. Unblocking a username that was never blocked, or that
    does not resolve, is treated as a harmless success (the end state
    the caller wants -- "not blocked" -- is already true)."""

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_username = packet.get("target_username")

    db = SessionLocal()

    try:
        if not target_username:
            success, error = False, "A username is required."
        else:
            target = UserRepository(db).get_by_username(target_username)
            if target is not None:
                BlockedUserRepository(db).unblock(user.id, target.id)
                db.commit()
            success, error = True, None
    finally:
        db.close()

    send_to_client(client_socket, create_unblock_user_result_packet(
        request_id=request_id, success=success, error=error,
    ))

    if success:
        state.logger.info(f"{user.username} unblocked {target_username}")
        broadcast_user_list(state)


def handle_blocked_users_list_request(state, client_socket, user, packet):
    """Return every username the authenticated connection's own
    account currently has blocked (Phase 19.24 -- Block User) -- never
    the reverse direction (who has blocked THIS account), which is
    never revealed to anyone, mirroring every mainstream messaging
    app's own privacy model."""

    request_id = packet.get("request_id")

    if not request_id:
        return

    db = SessionLocal()

    try:
        blocked_ids = BlockedUserRepository(db).get_blocked_user_ids(user.id)
        usernames = sorted(_usernames_for(db, blocked_ids))
    finally:
        db.close()

    send_to_client(client_socket, create_blocked_users_list_result_packet(
        request_id=request_id, usernames=usernames,
    ))


def handle_profile_picture_upload_request(state, client_socket, user, packet):
    """
    Store a new profile picture for the authenticated connection's own
    account (Phase 19.14 -- Settings). Reuses storage.encrypted_
    blob_store.store_blob()/delete_blob() unchanged -- the same
    generic, payload-agnostic on-disk blob backend chat attachments
    already use -- rather than a second storage mechanism. Unlike a
    chat attachment, this is intentionally NOT end-to-end encrypted:
    a profile picture is meant to be visible to any other user who
    looks this account up (see create_profile_picture_upload_request_
    packet()'s own docstring); store_blob() itself has no opinion on
    that either way, it only ever persists whatever bytes it is given.

    The previous picture's blob (if any) is deleted after the new one
    is safely stored and committed -- never before, so a failure
    partway through never leaves the account with no picture at all.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    image_base64 = packet.get("image_base64")

    if not image_base64:
        send_to_client(client_socket, create_profile_picture_upload_result_packet(
            request_id=request_id, success=False, error="No image data received.",
        ))
        return

    try:
        image_bytes = base64.b64decode(image_base64, validate=True)
    except (TypeError, ValueError):
        send_to_client(client_socket, create_profile_picture_upload_result_packet(
            request_id=request_id, success=False, error="Malformed image data.",
        ))
        return

    if not image_bytes or len(image_bytes) > _MAX_PROFILE_PICTURE_BYTES:
        send_to_client(client_socket, create_profile_picture_upload_result_packet(
            request_id=request_id, success=False,
            error=f"Image must be under {_MAX_PROFILE_PICTURE_BYTES // (1024 * 1024)} MB.",
        ))
        return

    old_reference = user.profile_picture

    db = SessionLocal()

    try:
        new_reference = encrypted_blob_store.store_blob(image_bytes)

        user_repo = UserRepository(db)
        db_user = user_repo.get_by_id(user.id)
        user_repo.update_profile_picture(db_user, new_reference, datetime.now(timezone.utc).replace(tzinfo=None))
        user_repo.commit()
    finally:
        db.close()

    user.profile_picture = new_reference

    if old_reference:
        encrypted_blob_store.delete_blob(old_reference)

    send_to_client(client_socket, create_profile_picture_upload_result_packet(
        request_id=request_id, success=True,
    ))

    state.logger.info(f"{user.username} updated their profile picture")


def handle_profile_picture_request(state, client_socket, user, packet):
    """
    Return another (or this same) account's current profile picture,
    by username, to the authenticated caller (Phase 19.14 -- Settings/
    Profile Viewer). ``found=False`` (no image data) for an account
    with none set, or one that does not exist -- deliberately the
    SAME response either way, so this cannot be used to enumerate
    usernames by whether a picture comes back.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_username = packet.get("username")

    db = SessionLocal()

    try:
        target = UserRepository(db).get_by_username(target_username) if target_username else None
        reference = target.profile_picture if target is not None else None
    finally:
        db.close()

    if not reference:
        send_to_client(client_socket, create_profile_picture_result_packet(
            request_id=request_id, found=False,
        ))
        return

    try:
        image_bytes = encrypted_blob_store.load_blob(reference)
    except (encrypted_blob_store.InvalidBlobReference, FileNotFoundError, OSError):
        send_to_client(client_socket, create_profile_picture_result_packet(
            request_id=request_id, found=False,
        ))
        return

    send_to_client(client_socket, create_profile_picture_result_packet(
        request_id=request_id, found=True,
        image_base64=base64.b64encode(image_bytes).decode("ascii"),
    ))


_MAX_BIO_CHARS = 256


def handle_change_bio_request(state, client_socket, user, packet):
    """
    Set/replace the authenticated connection's own bio (Phase 19.22 --
    Settings). The User.bio column has existed since the initial
    migration but had no handler at all until now -- follows
    handle_change_username_request()'s exact shape: identity to change
    is always ``user``, this connection's own in-memory copy is
    updated immediately so it reflects everywhere for the rest of this
    connection without requiring a reconnect.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    bio = (packet.get("bio") or "").strip()

    if len(bio) > _MAX_BIO_CHARS:
        send_to_client(client_socket, create_change_bio_result_packet(
            request_id=request_id, success=False,
            error=f"Bio must be under {_MAX_BIO_CHARS} characters.",
        ))
        return

    db = SessionLocal()

    try:
        user_repo = UserRepository(db)
        db_user = user_repo.get_by_id(user.id)
        user_repo.update_bio(db_user, bio, datetime.now(timezone.utc).replace(tzinfo=None))
        user_repo.commit()
    finally:
        db.close()

    user.bio = bio

    send_to_client(client_socket, create_change_bio_result_packet(
        request_id=request_id, success=True,
    ))

    state.logger.info(f"{user.username} updated their bio")


def handle_bio_request(state, client_socket, user, packet):
    """
    Return another (or this same) account's current bio, by username
    (Phase 19.22 -- Settings). ``found=False`` for an account with no
    bio set or one that does not exist -- same account-enumeration
    guard as handle_profile_picture_request()'s identical choice.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_username = packet.get("username")

    db = SessionLocal()

    try:
        target = UserRepository(db).get_by_username(target_username) if target_username else None
        bio = target.bio if target is not None else None
    finally:
        db.close()

    if not bio:
        send_to_client(client_socket, create_bio_result_packet(
            request_id=request_id, found=False,
        ))
        return

    send_to_client(client_socket, create_bio_result_packet(
        request_id=request_id, found=True, bio=bio,
    ))


def handle_last_seen_request(state, client_socket, user, packet):
    """
    Phase 19.24 -- Presence/Last Seen. Return another account's last-
    seen timestamp, by username. Security: ``found=False`` (hiding
    last_seen_at entirely) whenever the requester has blocked the
    target OR the target has blocked the requester -- the SAME "hide
    presence in either direction" rule broadcast_user_list() already
    enforces for the online/offline signal itself (server/
    broadcaster.py); last_seen_at is just presence's persisted
    complement, so it gets the identical privacy treatment, not a
    weaker one. Also found=False for an unknown username, same
    account-enumeration guard as handle_bio_request()'s identical
    choice -- a blocked-vs-nonexistent target must be indistinguishable
    to the requester.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_username = packet.get("username")

    db = SessionLocal()

    try:
        target = UserRepository(db).get_by_username(target_username) if target_username else None

        if target is None:
            found = False
            last_seen_at = None
        else:
            blocked_repo = BlockedUserRepository(db)
            hidden = (
                blocked_repo.is_blocked(user.id, target.id)
                or blocked_repo.is_blocked(target.id, user.id)
            )
            found = not hidden
            last_seen_at = (
                target.last_seen_at.isoformat()
                if (found and target.last_seen_at) else None
            )
    finally:
        db.close()

    send_to_client(client_socket, create_last_seen_result_packet(
        request_id=request_id, found=found, last_seen_at=last_seen_at,
    ))


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


def handle_group_key_distribution(state, client_socket, user, packet):
    """
    Relay one member's wrapped copy of a group key to another member
    (D6 -- Key Distribution Authorization; extracted unchanged from the
    inline "group_key_distribution" branch handle_client() used to
    carry, then hardened).

    The server still never sees the group key itself: encapsulation/
    wrapped_key stay opaque and are forwarded byte-for-byte, exactly as
    before. Key generation, wrapping, and unwrapping remain entirely
    client-side (crypto/key_manager.py::wrap_key_for_member()/
    unwrap_received_key()) -- this handler only decides whether a relay
    is allowed, never what is relayed.

    Authorization (D6.2 -- sender): the authenticated identity for this
    socket (``user``, established via JWT at authenticate_connection()
    time) must be an active member of conversation_id, using the same
    ConversationRepository.get_member_user_ids() check
    handle_group_leave()/handle_group_chat_delivery()/
    handle_group_key_rotation_complete()/handle_epoch_reservation_request()
    already use. This closes a genuinely new authorization boundary:
    the previous inline relay performed no membership check at all, so
    any authenticated user could inject key material into any
    conversation. That mattered because distribute_public_keys()
    broadcasts every connected client's public key to every other
    connected client regardless of shared membership, so a non-member
    could produce a validly-wrapped key for any online victim, and
    KeyManager.store_key()'s "highest epoch wins" rule would then make
    the injected key that victim's CURRENT key for the conversation --
    poisoning the group's key state and breaking decryption for the
    real members.

    packet["sender"] is overwritten with the authenticated username
    before forwarding -- the identical hardening handle_client()
    already applies to "chat" and direct "session_key" packets, and for
    the same reason: a client-supplied sender field is never
    trustworthy. Today's receiving client does not read that field (see
    ClientSession.handle_group_key_distribution(), which keys off
    ``recipient`` alone), so this is consistency/defence-in-depth
    rather than a fix for a live exploit -- but it means no future
    reader of this packet can inherit a spoofable identity.

    Authorization (D6.3 -- recipient): the matched recipient must
    itself be an active member of the same conversation. Verified
    against the connected socket's own server-assigned user_id (the
    identity bound at authentication, never a client-supplied field) --
    the same membership set and the same comparison shape
    _select_connected_active_member() already uses, so there is no
    second, duplicate notion of "is a member" anywhere in this file.
    A member cannot use this relay to hand a group key to an outsider.
    (A malicious member could of course leak a key they already hold
    out-of-band; this check is not claimed to prevent that -- it
    enforces the server's own authorization model consistently and
    stops accidental or forged misrouting.)

    Rejections are silent, server-log-only -- no error packet is
    returned to the sender, matching every other group-authorization
    check in this file. A missing/malformed conversation_id, a missing
    recipient, a non-member sender, and a non-member recipient are
    therefore indistinguishable on the wire, mirroring the existing
    "don't let an error reveal which guess was closer" convention (see
    handle_epoch_reservation_request()).

    A recipient who is not currently connected is a silent no-op, with
    nothing forwarded -- unchanged from the original inline behavior.
    """

    # Phase 16B -- Device State Enforcement (Step 4): a sender whose
    # OWN connection is bound to a device that has since been REVOKED
    # must not be able to distribute new key material at all -- checked
    # first, before anything else, so a revoked device gets no partial
    # processing. None (never bound a device on this connection --
    # every pre-Phase-16 client, and every existing test) is
    # deliberately NOT a rejection -- see is_device_bound_and_authorized()'s
    # own docstring for why.
    sender_device_state = is_device_bound_and_authorized(state, client_socket)

    if sender_device_state is False:

        state.logger.warning(
            f"Rejected group_key_distribution from {user.username}: "
            f"sender's bound device is not AUTHORIZED"
        )

        return

    conversation_id = packet.get("conversation_id")
    recipient = packet.get("recipient")

    if not conversation_id or not recipient:

        state.logger.warning(
            f"Rejected group_key_distribution from {user.username}: "
            f"missing conversation_id or recipient"
        )

        return

    try:
        conversation_uuid = uuid.UUID(conversation_id)
    except (TypeError, ValueError, AttributeError):

        state.logger.warning(
            f"Rejected group_key_distribution from {user.username}: "
            f"invalid conversation_id"
        )

        return

    # Epoch must be a plain positive integer. bool is excluded
    # explicitly because bool subclasses int, so True would otherwise
    # sail through as epoch 1.
    epoch = packet.get("epoch")

    if epoch is None:
        epoch = 1

    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:

        state.logger.warning(
            f"Rejected group_key_distribution from {user.username}: "
            f"invalid epoch"
        )

        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)
        current_epoch, _confirmed_epoch = conversation_repo.get_epoch_state(
            conversation_uuid
        )
    finally:
        db.close()

    if user.id not in member_ids:

        state.logger.warning(
            f"Rejected group_key_distribution: {user.username} is not a "
            f"member of {conversation_id}"
        )

        return

    # The epoch may not exceed what the server itself has reserved for
    # this conversation.
    #
    # Without this, membership alone was enough to poison a peer
    # permanently. KeyManager.store_key() tracks the current epoch with
    # max(), so a member could distribute a key of their own choosing
    # stamped with an absurdly high epoch (999999): the victim would
    # immediately encrypt every outgoing group message under it, and --
    # because every subsequent legitimate rotation carries a LOWER
    # number -- would never recover, even after the attacker left the
    # group. Only a client restart cleared it.
    #
    # Every legitimate distribution is bounded by current_key_epoch:
    # group creation uses epoch 1 (the column default), a rotation uses
    # the epoch reserve_next_epoch() already bumped current_key_epoch
    # to, and reconnect redelivery re-sends current_key_epoch itself.
    if current_epoch is None or epoch > current_epoch:

        state.logger.warning(
            f"Rejected group_key_distribution from {user.username}: "
            f"epoch {epoch} exceeds the reserved epoch for "
            f"{conversation_id}"
        )

        return

    # Never trust a client-supplied sender field -- see docstring.
    packet["sender"] = user.username

    member_id_strings = {str(member_id) for member_id in member_ids}

    for sock, client in list(state.clients.items()):

        if client["username"] != recipient:
            continue

        if client.get("user_id") not in member_id_strings:

            state.logger.warning(
                f"Rejected group_key_distribution: recipient {recipient} "
                f"is not a member of {conversation_id}"
            )

            return

        # Phase 16B -- Device State Enforcement (Step 4): a recipient
        # whose bound device has been REVOKED must not receive newly
        # distributed key material either, even though the packet
        # already reached the server -- this is the server-side half
        # of "REVOKED cannot receive new cryptographic material"; the
        # receiving ClientSession's own independent peer-verification
        # state was in any case never told to trust a revoked device
        # (defense in depth, see docs/architecture/
        # multi_device_identity.md).
        if is_device_bound_and_authorized(state, sock) is False:

            state.logger.warning(
                f"Dropped group_key_distribution to {recipient}: "
                f"recipient's bound device is not AUTHORIZED"
            )

            return

        if send_to_client(sock, packet):

            state.logger.info(
                f"Forwarded group key for "
                f"{conversation_id} "
                f"from {user.username} to {recipient}"
            )

        else:

            state.logger.warning(
                f"Failed to forward group key for "
                f"{conversation_id} "
                f"from {user.username} to {recipient}"
            )

        return


def _perform_group_add_members(state, conversation_id, new_user_ids, acting_username):
    """
    The actual membership-change side of adding members to a group --
    factored out of handle_group_add_members() (Phase 19.13 -- Group
    Admin) so both the admin's own direct add and an approved
    group_add_request (handle_inbox_response()) run through exactly
    one implementation, never two copies that could drift apart.
    ``new_user_ids`` must already be filtered to real, not-yet-member
    user ids -- this function performs no further authorization check
    of its own (both callers have already established the acting user
    is allowed to do this, by different means: direct admin identity,
    or a resolved admin-approved inbox notification).

    Deliberately reuses the exact epoch-rotation machinery a leave
    already uses, rather than a new key-distribution path:
    reserve_next_epoch() bumps current_key_epoch exactly as it does
    for a leave, and the unchanged _dispatch_pending_rotation_if_needed()
    picks a currently-connected active member to generate/redistribute
    that new epoch's key to every current member, old and new alike.
    """

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        conversation_uuid = uuid.UUID(conversation_id) if isinstance(conversation_id, str) else conversation_id

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
        conversation_id=str(conversation_uuid),
        name=name,
        members=all_usernames,
    )

    all_member_id_strings = {str(member_id) for member_id in all_member_ids}

    for sock, client in list(state.clients.items()):

        if client.get("user_id") in all_member_id_strings:
            send_to_client(sock, members_added_packet)

    state.logger.info(
        f"{acting_username} added members to group {conversation_id} "
        f"(now: {all_usernames})"
    )

    _dispatch_pending_rotation_if_needed(state, str(conversation_uuid))


def handle_group_add_members(state, client_socket, user, packet):
    """
    Add one or more users to an existing group conversation
    (real-application bug fix, Issue 2 -- Add Members After Group
    Creation).

    Security: who is requesting the add is derived entirely from the
    authenticated socket (``user``), never trusted from the packet --
    mirrors handle_group_leave()'s pattern exactly. A non-member
    requester is rejected silently, same as every other group-
    authorization check in this file.

    Phase 19.13 -- Group Admin: this app used to have no owner/role
    concept at all, and any active member could add members directly.
    Now the group's admin (ConversationRepository.get_admin_user_id(),
    recorded at creation -- see create_group_conversation()) can still
    add directly, through _perform_group_add_members() below -- but a
    NON-admin member's request creates a pending group_add_request
    inbox notification addressed to the admin instead of performing
    the add immediately; nothing about group membership changes until
    the admin approves it (handle_inbox_response()). A group with no
    recorded admin at all (created before this phase existed) keeps
    the old "any member" behavior unchanged -- there is no admin to
    route a request to.
    """

    conversation_id = packet.get("conversation_id")
    member_usernames = packet.get("members") or []

    if not conversation_id or not member_usernames:
        return

    db = SessionLocal()

    try:
        conversation_repo = ConversationRepository(db)
        user_repo = UserRepository(db)
        inbox_repo = InboxRepository(db)
        conversation_uuid = uuid.UUID(conversation_id)

        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

        if user.id not in member_ids:

            state.logger.warning(
                f"Rejected group_add_members: {user.username} is not a "
                f"member of {conversation_id}"
            )

            return

        candidates = []
        blocked_repo = BlockedUserRepository(db)

        for username in member_usernames:

            candidate = user_repo.get_by_username(username)

            if candidate is None or candidate.id in member_ids:
                continue

            # Phase 19.24 -- Block User: mirrors handle_group_create()'s
            # own identical exclusion -- a block in either direction
            # between the requester and a candidate silently excludes
            # them from being added, never a distinguishable error.
            if blocked_repo.is_blocked(candidate.id, user.id) or blocked_repo.is_blocked(user.id, candidate.id):
                continue

            candidates.append(candidate)

        if not candidates:
            return

        admin_id = conversation_repo.get_admin_user_id(conversation_uuid)

        if admin_id is not None and admin_id != user.id:

            # Non-admin request -- create a pending approval instead
            # of adding anyone yet.
            notifications = []

            for candidate in candidates:
                notification = inbox_repo.create_group_add_request(
                    requester_id=user.id, admin_id=admin_id,
                    conversation_id=conversation_uuid, candidate_id=candidate.id,
                )
                notifications.append((notification, candidate))

            inbox_repo.commit()

            admin_user = db.get(User, admin_id)
            admin_username = admin_user.username if admin_user is not None else None
        else:
            new_user_ids = [candidate.id for candidate in candidates]
            notifications = None
    finally:
        db.close()

    if notifications is None:
        _perform_group_add_members(state, conversation_id, new_user_ids, user.username)
        return

    for notification, candidate in notifications:

        _push_inbox_notification(
            state, admin_id,
            _serialize_group_add_notification(notification, user.username, candidate.username),
        )

    state.logger.info(
        f"{user.username} requested adding {[c.username for _, c in notifications]} "
        f"to group {conversation_id} -- awaiting approval from {admin_username}"
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


def handle_typing_indicator(state, client_socket, user, packet):
    """
    Relay a live "is typing" / "stopped typing" hint to the other
    currently-active member(s) of a conversation (Phase 19.24 --
    Typing Indicator).

    Security: the actor is always ``user.id`` -- create_typing_
    indicator_packet() carries no sender field at all, mirroring
    handle_read_receipt()'s identical pattern; membership is
    re-derived from the database (get_member_user_ids(), the same
    check every other conversation-scoped handler in this file uses),
    so a non-member's packet is silently ignored, never trusted to
    announce typing in a conversation the sender cannot even see.

    Deliberately NOT persisted anywhere, and never replayed through
    message_history_request -- purely a live, ephemeral hint, exactly
    like create_typing_indicator_packet()'s own docstring states.

    Unlike read receipts (and edit/delete/reaction, which broadcast
    back to the actor too so their OWN other devices/UI can react),
    the sender's own socket is explicitly excluded from the relay
    here: there is no reason for a client to be told about its own
    typing state, and echoing it back would only cost bandwidth for
    something the sender already knows.
    """

    conversation_id = packet.get("conversation_id")

    if not conversation_id:
        return

    is_typing = bool(packet.get("is_typing"))

    db = SessionLocal()

    try:
        try:
            conversation_uuid = uuid.UUID(conversation_id)
        except (ValueError, AttributeError, TypeError):
            return

        conversation_repo = ConversationRepository(db)

        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

        if user.id not in member_ids:

            state.logger.warning(
                f"Rejected typing_indicator: {user.username} is not a "
                f"member of conversation {conversation_id}"
            )

            return

        recipient_id_strings = {
            str(member_id) for member_id in member_ids if member_id != user.id
        }

        # Phase 19.24 -- Block User: a DIRECT conversation is always
        # exactly two members -- if either has blocked the other, ANY
        # live hint about the sender's typing must not reach them
        # (mirrors the "chat" packet's own block enforcement). Groups
        # are deliberately excluded (member_ids has more than two
        # members) -- see database/models/blocked_user.py's own
        # docstring for why a 1:1 block never reaches into a shared
        # group thread.
        if len(member_ids) == 2:
            blocked_repo = BlockedUserRepository(db)
            other_id = next((m for m in member_ids if m != user.id), None)
            if other_id is not None and (
                blocked_repo.is_blocked(other_id, user.id)
                or blocked_repo.is_blocked(user.id, other_id)
            ):
                recipient_id_strings = set()
    finally:
        db.close()

    notification = create_typing_indicator_notification_packet(
        conversation_id=conversation_id,
        username=user.username,
        is_typing=is_typing,
    )

    for sock, client in list(state.clients.items()):

        if sock is client_socket:
            continue

        if client.get("user_id") in recipient_id_strings:
            send_to_client(sock, notification)


# ======================================================================
# Phase 19.24 -- Message Lifecycle Events (edit/delete/reactions).
#
# Every handler below shares the SAME authorization shape: the actor
# is ALWAYS user.id (the authenticated socket, from dispatch's own
# lookup -- see the module-level note at the "chat" branch: "the
# client-supplied sender field is never trustworthy"), NEVER a
# client-supplied field, and a target message's authorization fact
# (its sender_id, or its conversation membership) is ALWAYS re-derived
# from the database, never trusted from the packet. A request that
# fails either check is silently rejected (logged, not error-reported
# to the sender) -- mirrors handle_read_receipt()'s own fail-closed,
# no-op-on-rejection behavior.
# ======================================================================


def _broadcast_to_conversation_members(state, packet, member_id_strings, exclude_socket=None):
    """
    Send ``packet`` to every currently-connected socket belonging to
    any of ``member_id_strings`` (a set of str(user.id)) -- the shared
    fan-out shape handle_read_receipt() already established, factored
    out because Phase 19.24 adds five more handlers that need the
    identical broadcast, now including the ACTOR's own other
    authorized devices (multi-device sync -- unlike read receipts,
    which have no reason to tell a user about their own read action,
    an edit/delete/reaction must reach every one of the actor's own
    other logged-in devices too, so ``member_id_strings`` is expected
    to include the actor here, not exclude them).

    L-1 -- Device Revocation: a socket whose bound device has since
    been revoked is skipped, exactly like handle_chat()'s own
    direct-relay loop already does -- an already-connected revoked
    device must not continue receiving ordinary protected chat
    traffic, and an edit/delete/reaction notification carries exactly
    that (re-encrypted content, or the fact that protected content was
    removed).

    ``exclude_socket``, when given, is skipped regardless of whose
    device it is -- used to avoid echoing a notification back to the
    exact socket that just sent the request it resulted from (that
    client already knows; it applied the change locally the moment its
    own request was accepted).
    """

    for sock, client in list(state.clients.items()):

        if sock is exclude_socket:
            continue

        if client.get("user_id") not in member_id_strings:
            continue

        if is_device_bound_and_authorized(state, sock) is False:
            continue

        send_to_client(sock, packet)


def handle_message_edit(state, client_socket, user, packet):
    """
    Re-encrypt an existing message's content in place (Phase 19.24).

    Security: authorization is "the authenticated socket IS this
    message's ORIGINAL sender" -- re-derived from the stored row
    (message.sender_id), never from anything in the packet. No other
    actor (not a group admin, not any other member) may ever edit
    someone else's message; this is deliberately narrower than the
    admin-authorized delete-for-everyone policy could have been,
    because an edit changes the APPARENT AUTHOR'S OWN WORDS, which no
    one but that author should ever be able to produce.

    Out-of-order/replay protection: expected_edit_version must match
    the row's CURRENT edit_version exactly (0 for a never-edited
    message) -- a stale or duplicate/replayed message_edit packet
    (naming a version this row has already moved past) is rejected,
    never silently applied and never silently ignored without telling
    the sender their edit did not take effect.
    """

    message_id_raw = packet.get("message_id")

    if not message_id_raw:
        return

    db = SessionLocal()

    try:
        try:
            message_uuid = uuid.UUID(message_id_raw)
        except (ValueError, AttributeError, TypeError):
            return

        message_repo = MessageRepository(db)
        message = message_repo.get_message(message_uuid)

        if message is None:
            state.logger.warning(
                f"Rejected message_edit: {user.username} referenced "
                f"unknown message {message_id_raw}"
            )
            return

        if message.sender_id != user.id:
            state.logger.warning(
                f"Rejected message_edit: {user.username} is not the "
                f"sender of message {message_id_raw}"
            )
            return

        if message.deleted_at is not None:
            state.logger.warning(
                f"Rejected message_edit: message {message_id_raw} was "
                f"already deleted"
            )
            return

        expected_edit_version = packet.get("expected_edit_version")

        if expected_edit_version is None or int(expected_edit_version) != message.edit_version:
            state.logger.warning(
                f"Rejected message_edit: stale edit_version for "
                f"message {message_id_raw} (expected "
                f"{message.edit_version}, client sent {expected_edit_version!r})"
            )
            return

        ciphertext = packet.get("ciphertext")

        if not ciphertext:
            return

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(message.conversation_id)

        message_repo.apply_edit(
            message,
            ciphertext=ciphertext,
            content_metadata=packet.get("content_metadata"),
            epoch=packet.get("epoch") or 1,
            message_signature=packet.get("message_signature"),
        )

        db.commit()

        conversation_id = str(message.conversation_id) if message.conversation_id else None
        edited_at = message.edited_at.isoformat() if message.edited_at else None
        edit_version = message.edit_version
        response_ciphertext = message.ciphertext
        response_content_metadata = message.content_metadata
        response_epoch = message.epoch
        response_signature = message.message_signature
        member_id_strings = {str(member_id) for member_id in member_ids}
    finally:
        db.close()

    notification = create_message_edited_notification_packet(
        message_id=message_id_raw,
        conversation_id=conversation_id,
        ciphertext=response_ciphertext,
        content_metadata=response_content_metadata,
        epoch=response_epoch,
        message_signature=response_signature,
        editor=user.username,
        edited_at=edited_at,
        edit_version=edit_version,
    )

    _broadcast_to_conversation_members(state, notification, member_id_strings)

    state.logger.info(f"{user.username} edited message {message_id_raw}")


def handle_message_delete_for_me(state, client_socket, user, packet):
    """
    Hide a message for the requesting user only (Phase 19.24). No
    broadcast at all -- this is a per-viewer preference, invisible to
    every other participant, by design (see database/models/
    message_hidden_for_user.py's own docstring). The ONLY reason this
    is a server-side row at all (rather than pure client-local state)
    is so it synchronizes to the requesting user's OWN other
    authorized devices -- handled by simply being read back on their
    next history request, not by a live notification.
    """

    message_id_raw = packet.get("message_id")

    if not message_id_raw:
        return

    db = SessionLocal()

    try:
        try:
            message_uuid = uuid.UUID(message_id_raw)
        except (ValueError, AttributeError, TypeError):
            return

        message_repo = MessageRepository(db)
        message = message_repo.get_message(message_uuid)

        if message is None:
            return

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(message.conversation_id)

        if user.id not in member_ids:
            state.logger.warning(
                f"Rejected message_delete_for_me: {user.username} is not "
                f"a member of the conversation containing {message_id_raw}"
            )
            return

        message_repo.hide_for_user(message_uuid, user.id)

        db.commit()
    finally:
        db.close()

    state.logger.info(f"{user.username} hid message {message_id_raw} for themself")


def handle_message_delete_for_everyone(state, client_socket, user, packet):
    """
    Real, authorized global deletion (Phase 19.24). Security:
    authorization is "the authenticated socket IS this message's
    ORIGINAL sender", re-derived from the stored row, exactly like
    handle_message_edit() -- no client-supplied actor field, no
    broader "any admin can delete" policy (see database/models/
    message.py::deleted_by's own docstring for why).

    Deletion is REAL: MessageRepository.apply_delete_for_everyone()
    nulls ciphertext/content_metadata/message_signature/blob_ref on
    this row in the same transaction this handler commits, and (for a
    blob-stored FILE/IMAGE payload) the referenced encrypted_blob_
    store file is removed too, best-effort, AFTER the commit succeeds
    (so a blob-deletion failure can never leave the database row
    half-updated). What is left server-side afterward is exactly:
    message_id, sender_id, conversation_id, timestamp, deleted_at,
    deleted_by -- enough to render "Message deleted" in the right
    place in history, nothing that could reconstruct the original
    content.
    """

    message_id_raw = packet.get("message_id")

    if not message_id_raw:
        return

    db = SessionLocal()

    try:
        try:
            message_uuid = uuid.UUID(message_id_raw)
        except (ValueError, AttributeError, TypeError):
            return

        message_repo = MessageRepository(db)
        message = message_repo.get_message(message_uuid)

        if message is None:
            return

        if message.sender_id != user.id:
            state.logger.warning(
                f"Rejected message_delete_for_everyone: {user.username} "
                f"is not the sender of message {message_id_raw}"
            )
            return

        if message.deleted_at is not None:
            # Already deleted -- idempotent no-op, not an error (a
            # retried/duplicate delete request must not fail or
            # re-broadcast).
            return

        blob_ref_to_remove = message.blob_ref

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(message.conversation_id)

        message_repo.apply_delete_for_everyone(message, deleted_by_user_id=user.id)

        db.commit()

        conversation_id = str(message.conversation_id) if message.conversation_id else None
        deleted_at = message.deleted_at.isoformat() if message.deleted_at else None
        member_id_strings = {str(member_id) for member_id in member_ids}
    finally:
        db.close()

    if blob_ref_to_remove:
        try:
            encrypted_blob_store.delete_blob(blob_ref_to_remove)
        except Exception as error:  # noqa: BLE001
            # The database row is ALREADY committed as deleted at this
            # point -- a blob-cleanup failure here is a storage-hygiene
            # issue to log, never a reason to tell the sender their
            # deletion failed (it did not).
            state.logger.warning(
                f"Could not remove blob {blob_ref_to_remove} for deleted "
                f"message {message_id_raw}: {error}"
            )

    notification = create_message_deleted_notification_packet(
        message_id=message_id_raw,
        conversation_id=conversation_id,
        deleted_by=user.username,
        deleted_at=deleted_at,
    )

    _broadcast_to_conversation_members(state, notification, member_id_strings)

    state.logger.info(f"{user.username} deleted message {message_id_raw} for everyone")


def handle_message_pin(state, client_socket, user, packet):
    """
    Pin a message for every member of its conversation (Phase 19.24 --
    Pinned Messages).

    Trust model: pin/unpin carries no content of its own -- unlike
    reaction_add/message_edit, there is no ciphertext to encrypt,
    relay, or independently verify via ML-DSA. What this handler
    protects is authorization (who may pin), and that rests on the
    SAME trust boundary every other conversation-scoped action in this
    file already relies on: the authenticated TLS connection itself.
    ``pinned_by`` in the resulting notification is always user.username
    (server-derived), never a client-supplied field -- a malicious
    client cannot forge who performed the pin, exactly like deleted_by
    on delete-for-everyone.

    Authorization is "currently an ACTIVE member of the message's
    conversation" -- deliberately broader than edit/delete's sender-
    only rule (see database/models/message.py::pinned_at's own
    docstring): any participant may pin/unpin any message, matching
    ordinary messenger conventions (WhatsApp/Telegram/Signal all allow
    any participant to pin in a direct chat; this project does not
    special-case group admin-only pinning, since the mandate's own
    phrasing -- "group admin behavior if applicable" -- does not
    require it, and adding a bespoke admin-only restriction here would
    be an unrequested extra rule, not a security fix).

    Idempotent-ish: re-pinning an already-pinned message simply
    updates pinned_at/pinned_by to reflect the latest pin action, and
    still broadcasts (a re-pin is a real, useful event -- e.g. "bumping"
    a pin back to the top of a pinned-messages view).
    """

    message_id_raw = packet.get("message_id")

    if not message_id_raw:
        return

    db = SessionLocal()

    try:
        try:
            message_uuid = uuid.UUID(message_id_raw)
        except (ValueError, AttributeError, TypeError):
            return

        message_repo = MessageRepository(db)
        message = message_repo.get_message(message_uuid)

        if message is None:
            return

        if message.deleted_at is not None:
            state.logger.warning(
                f"Rejected message_pin: message {message_id_raw} was "
                f"already deleted"
            )
            return

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(message.conversation_id)

        if user.id not in member_ids:
            state.logger.warning(
                f"Rejected message_pin: {user.username} is not a "
                f"member of the conversation containing {message_id_raw}"
            )
            return

        message_repo.pin_message(message_uuid, user.id)

        db.commit()

        conversation_id = str(message.conversation_id) if message.conversation_id else None
        pinned_at = message.pinned_at.isoformat() if message.pinned_at else None
        member_id_strings = {str(member_id) for member_id in member_ids}
    finally:
        db.close()

    notification = create_message_pinned_notification_packet(
        message_id=message_id_raw,
        conversation_id=conversation_id,
        pinned_by=user.username,
        pinned_at=pinned_at,
    )

    _broadcast_to_conversation_members(state, notification, member_id_strings)

    state.logger.info(f"{user.username} pinned message {message_id_raw}")


def handle_message_unpin(state, client_socket, user, packet):
    """
    Unpin a message (Phase 19.24 -- Pinned Messages). Same membership-
    based authorization as handle_message_pin() -- any active member
    may unpin, not only whoever originally pinned it. Idempotent: an
    already-unpinned message is a silent no-op, no broadcast (there is
    nothing new for other members to learn).
    """

    message_id_raw = packet.get("message_id")

    if not message_id_raw:
        return

    db = SessionLocal()

    try:
        try:
            message_uuid = uuid.UUID(message_id_raw)
        except (ValueError, AttributeError, TypeError):
            return

        message_repo = MessageRepository(db)
        message = message_repo.get_message(message_uuid)

        if message is None:
            return

        if message.pinned_at is None:
            return

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(message.conversation_id)

        if user.id not in member_ids:
            state.logger.warning(
                f"Rejected message_unpin: {user.username} is not a "
                f"member of the conversation containing {message_id_raw}"
            )
            return

        message_repo.unpin_message(message_uuid)

        db.commit()

        conversation_id = str(message.conversation_id) if message.conversation_id else None
        member_id_strings = {str(member_id) for member_id in member_ids}
    finally:
        db.close()

    notification = create_message_unpinned_notification_packet(
        message_id=message_id_raw,
        conversation_id=conversation_id,
        unpinned_by=user.username,
    )

    _broadcast_to_conversation_members(state, notification, member_id_strings)

    state.logger.info(f"{user.username} unpinned message {message_id_raw}")


def handle_reaction_add(state, client_socket, user, packet):
    """
    Set/replace the authenticated user's reaction on a message (Phase
    19.24). Security: the actor is always user.id; authorization is
    "currently an active member of the message's conversation" -- any
    member may react (unlike edit/delete, which are sender-only),
    matching the general chat-participation model every other
    conversation-scoped action in this file already uses (e.g.
    handle_read_receipt()'s identical membership check).

    ``ciphertext`` is opaque to the server -- the AES-256-GCM-encrypted
    reaction string (payload/reaction_adapter.py), under the
    conversation's current epoch key. The server persists it and
    relays it; it never decrypts or inspects it.
    """

    message_id_raw = packet.get("message_id")
    ciphertext = packet.get("ciphertext")

    if not message_id_raw or not ciphertext:
        return

    db = SessionLocal()

    try:
        try:
            message_uuid = uuid.UUID(message_id_raw)
        except (ValueError, AttributeError, TypeError):
            return

        message_repo = MessageRepository(db)
        message = message_repo.get_message(message_uuid)

        if message is None or message.deleted_at is not None:
            return

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(message.conversation_id)

        if user.id not in member_ids:
            state.logger.warning(
                f"Rejected reaction_add: {user.username} is not a member "
                f"of the conversation containing {message_id_raw}"
            )
            return

        epoch = packet.get("epoch") or 1
        message_signature = packet.get("message_signature")

        message_repo.upsert_reaction(
            message_uuid, user.id, ciphertext=ciphertext, epoch=epoch,
            message_signature=message_signature,
        )

        db.commit()

        conversation_id = str(message.conversation_id) if message.conversation_id else None
        member_id_strings = {str(member_id) for member_id in member_ids}
    finally:
        db.close()

    notification = create_reaction_updated_notification_packet(
        message_id=message_id_raw,
        conversation_id=conversation_id,
        actor=user.username,
        action="add",
        ciphertext=ciphertext,
        message_signature=message_signature,
        epoch=epoch,
    )

    _broadcast_to_conversation_members(state, notification, member_id_strings)

    state.logger.info(f"{user.username} reacted to message {message_id_raw}")


def handle_reaction_remove(state, client_socket, user, packet):
    """
    Remove the authenticated user's reaction from a message, if any
    (Phase 19.24). Same membership authorization as handle_reaction_
    add(); idempotent -- removing a reaction that does not exist is a
    silent no-op, not an error, and triggers no broadcast (there is
    nothing for other members to newly learn).
    """

    message_id_raw = packet.get("message_id")

    if not message_id_raw:
        return

    db = SessionLocal()

    try:
        try:
            message_uuid = uuid.UUID(message_id_raw)
        except (ValueError, AttributeError, TypeError):
            return

        message_repo = MessageRepository(db)
        message = message_repo.get_message(message_uuid)

        if message is None:
            return

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(message.conversation_id)

        if user.id not in member_ids:
            state.logger.warning(
                f"Rejected reaction_remove: {user.username} is not a "
                f"member of the conversation containing {message_id_raw}"
            )
            return

        removed = message_repo.remove_reaction(message_uuid, user.id)

        if not removed:
            db.rollback()
            return

        db.commit()

        conversation_id = str(message.conversation_id) if message.conversation_id else None
        member_id_strings = {str(member_id) for member_id in member_ids}
    finally:
        db.close()

    notification = create_reaction_updated_notification_packet(
        message_id=message_id_raw,
        conversation_id=conversation_id,
        actor=user.username,
        action="remove",
    )

    _broadcast_to_conversation_members(state, notification, member_id_strings)

    state.logger.info(f"{user.username} removed their reaction on message {message_id_raw}")


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
    # BUG 7 -- two identifier types, resolved explicitly rather than by
    # assuming every string is a UUID.
    #
    #   identifier_type == "phone"  ->  identifier, normalised, then
    #                                   matched against the canonical
    #                                   users.phone_number column
    #   otherwise                   ->  user_id, the original UUID
    #                                   path, unchanged for internal
    #                                   and backward-compatible callers
    identifier_type = packet.get("identifier_type")

    if identifier_type == "phone":
        identifier = packet.get("identifier")
    else:
        identifier = packet.get("user_id")

    if not request_id or not identifier:
        return

    db = SessionLocal()

    try:
        user_repo = UserRepository(db)

        if identifier_type == "phone":

            # Normalised server-side, never trusting the client to have
            # done it: the column stores the canonical form, so an
            # un-normalised term would silently miss a user who is
            # really there.
            try:
                found = user_repo.get_by_phone_number(
                    normalize_phone_number(identifier)
                )
            except InvalidPhoneNumberError:
                found = None

        else:

            # uuid.UUID() raises for a malformed string. Before this
            # guard the exception escaped this handler entirely, was
            # caught by handle_client()'s outer `except Exception`, and
            # its `finally` then broadcast a leave, removed the client
            # from state.clients and closed the socket -- so one
            # malformed lookup DISCONNECTED the searching user. The
            # GUI happened to be shielded because find_user_by_id()
            # validates client-side first, but nothing at the protocol
            # level was. Caught here, matching the
            # (TypeError, ValueError, AttributeError) convention every
            # other uuid.UUID() call site in this file already uses.
            try:
                found = user_repo.get_by_id(uuid.UUID(identifier))
            except (TypeError, ValueError, AttributeError):
                found = None

        # Phase 19.24 -- Block User: a block in EITHER direction makes
        # this lookup report "not found", the exact same response a
        # well-formed-but-nonexistent search already produces -- never
        # a distinguishable "found but blocked" result, matching this
        # handler's own stated privacy contract for a malformed guess.
        if found is not None:
            blocked_repo = BlockedUserRepository(db)
            if blocked_repo.is_blocked(found.id, user.id) or blocked_repo.is_blocked(user.id, found.id):
                found = None
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


def _recover_direct_keys_for_reconnecting_user(state, client_socket, user):
    """
    Reconnect recovery for DIRECT conversations, step 1 of 2 (BUG 4
    -- Fix B): announce what is recoverable.

    The direct-message counterpart of
    _ensure_group_keys_current_for_reconnecting_user() above, and
    deliberately built the same way -- the server asks a connected
    peer to hand this user a wrapped copy of a key, and never holds,
    sees, or generates key material itself. The transport reuses the
    existing, already-authorized group_key_distribution relay
    unchanged (see handle_group_key_distribution(), whose membership
    and epoch-bound checks are expressed purely in terms of
    conversation membership and so apply to a direct conversation
    exactly as they do to a group one).

    Why this is needed at all: a direct session key is established
    live over the socket (ClientSession.establish_session_key()) and
    kept only in the peers' RAM. If the recipient is offline when it
    is sent, the relay finds nobody to forward it to and the key is
    simply gone -- while the SENDER goes on encrypting under it and
    the server goes on persisting that ciphertext. The recipient then
    reconnects with an empty KeyManager and their stored messages
    decrypt to nothing but the "encrypted in a previous session"
    placeholder, permanently.

    Why this ANNOUNCES rather than pushes. Only the client knows which
    epochs it already holds -- the server holds no keys and cannot
    tell a client that just restarted from one that never left. So
    this sends the list of conversations and the epochs their messages
    are encrypted under, and the client asks back for the subset it
    actually lacks (handle_direct_key_recovery_request() below). A
    client that lost nothing asks for nothing, which is what keeps a
    routine reconnect from re-wrapping and re-sending every historical
    key every time.

    Scope, and the defect this shape fixes. The requirements come from
    MessageRepository.get_direct_conversation_epochs_for_user(), which
    selects on CONVERSATION MEMBERSHIP, not on delivery status. An
    earlier version drove recovery from QUEUED MessageRecipient rows,
    which failed twice over: a queued message that had been read was
    no longer QUEUED, so the next restart left already-read history
    permanently unreadable; and a user's own SENT messages have no
    MessageRecipient row of their own, so a sender could never recover
    the epochs needed to read their own side of a conversation.
    Membership covers both, and grants nothing beyond what
    handle_message_history_request() already lets this user read.

    Epoch correctness remains the load-bearing detail: the epochs
    named are exactly those messages.epoch records, never the
    conversation's current epoch. A direct conversation gains a fresh
    epoch on every key establishment by either side, so "current" is
    routinely not what a stored message needs.

    A conversation with no messages is never announced -- the query
    reaches a conversation only through its messages.

    If no partner is connected when the client asks, nothing happens:
    no key is invented, nothing is marked delivered, and the client is
    announced to again on its next reconnect. Symmetrically, when the
    PARTNER reconnects this same function runs for them, at which
    point this user (now the connected peer) can satisfy their
    request.
    """

    db = SessionLocal()

    try:
        required = MessageRepository(db).get_direct_conversation_epochs_for_user(
            user.id
        )
    finally:
        db.close()

    if not required:
        # No direct history at all, or none with messages. Nothing to
        # announce, and specifically no packet sent for an empty
        # conversation.
        return

    conversations = [
        {"conversation_id": str(conversation_id), "epochs": epochs}
        for conversation_id, epochs in required.items()
    ]

    announced = send_to_client(
        client_socket,
        create_direct_key_recovery_available_packet(conversations),
    )

    if not announced:
        state.logger.warning(
            f"Failed to announce direct key recovery to {user.username}"
        )

        return

    state.logger.info(
        f"Announced direct key recovery to {user.username}: "
        f"{[(c['conversation_id'], c['epochs']) for c in conversations]}"
    )


def handle_direct_key_recovery_request(state, client_socket, user, packet):
    """
    A client is missing some historical epochs for a direct
    conversation and is asking for them (BUG 4 -- Fix B).

    The server holds no keys, so all it can do -- and all it does
    here -- is ask a connected partner who does hold them to send a
    wrapped copy, exactly as the group reconnect recovery already
    does. Key material never passes through this handler.

    Authorization, in the order it is applied:

      * The requester is the authenticated identity for this socket
        (``user``), never anything the packet claims -- so a client
        cannot request another user's keys by naming them.
      * The requester must be an active member of the conversation:
        enforced by asking the repository for THIS USER's accessible
        direct conversations and refusing anything not in that set.
        This is the same conversation-membership rule
        handle_message_history_request() uses to decide who may read
        these messages at all, so recovery can never reach a
        conversation whose history the caller could not already fetch.
      * Each requested epoch must actually be referenced by that
        conversation's stored messages. A client cannot fish for
        arbitrary epoch numbers, and cannot induce a partner to
        distribute an epoch no message was ever encrypted under.
      * The partner selected must itself be an active member
        (_select_connected_active_member), and the relay that
        ultimately carries the key re-checks both sender and recipient
        membership independently (handle_group_key_distribution).

    Rejections are silent and server-log-only, matching every other
    authorization check in this file.
    """

    conversation_id = packet.get("conversation_id")
    requested_epochs = packet.get("epochs")

    if not conversation_id or not isinstance(requested_epochs, list):

        state.logger.warning(
            f"Rejected direct_key_recovery_request from {user.username}: "
            f"missing conversation_id or epochs"
        )

        return

    try:
        conversation_uuid = uuid.UUID(conversation_id)
    except (TypeError, ValueError, AttributeError):

        state.logger.warning(
            f"Rejected direct_key_recovery_request from {user.username}: "
            f"invalid conversation_id"
        )

        return

    # bool is excluded explicitly because it subclasses int, so True
    # would otherwise sail through as epoch 1.
    epochs = {
        candidate
        for candidate in requested_epochs
        if not isinstance(candidate, bool)
        and isinstance(candidate, int)
        and candidate >= 1
    }

    if not epochs:

        state.logger.warning(
            f"Rejected direct_key_recovery_request from {user.username}: "
            f"no valid epochs"
        )

        return

    db = SessionLocal()

    try:
        message_repo = MessageRepository(db)

        # Membership AND "this epoch really exists in this
        # conversation" in one query, scoped to this authenticated
        # user: a conversation the user is not an active member of
        # simply is not in the result.
        available = message_repo.get_direct_conversation_epochs_for_user(
            user.id, conversation_id=conversation_uuid
        )

        conversation_repo = ConversationRepository(db)
        member_ids = conversation_repo.get_member_user_ids(conversation_uuid)
    finally:
        db.close()

    known_epochs = set(available.get(conversation_uuid, []))

    if not known_epochs:

        state.logger.warning(
            f"Rejected direct_key_recovery_request from {user.username}: "
            f"{conversation_id} is not an accessible direct conversation"
        )

        return

    recoverable = sorted(epochs & known_epochs)

    if not recoverable:

        state.logger.warning(
            f"Rejected direct_key_recovery_request from {user.username}: "
            f"no requested epoch is referenced by {conversation_id}"
        )

        return

    selected = _select_connected_active_member(
        state, member_ids, exclude_user_id=user.id
    )

    if selected is None:

        # The partner is offline too. Deliberately no retry, no
        # queue, and above all no invented key: the client will be
        # announced to again on its next reconnect, and the partner
        # returning is what makes recovery possible.
        state.logger.info(
            f"No connected partner to redeliver {conversation_id} "
            f"epochs {recoverable} to {user.username}"
        )

        return

    sock, partner_username = selected

    for epoch in recoverable:

        redelivery_requested = send_to_client(
            sock,
            create_direct_key_redelivery_required_packet(
                conversation_id=str(conversation_uuid),
                epoch=epoch,
                recipient=user.username,
            ),
        )

        if not redelivery_requested:
            # Same reasoning as the group path's identical guard: this
            # runs again on the next reconnect, and is a harmless
            # no-op if the key has arrived by then.
            state.logger.warning(
                f"Failed to request direct key redelivery for "
                f"{conversation_id} epoch {epoch} to {user.username}"
            )
            continue

        state.logger.info(
            f"Requested direct key redelivery for {conversation_id} "
            f"epoch {epoch} from {partner_username} to {user.username}"
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
                phone_number=packet.get("phone_number") or "",
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
    Authenticate a not-yet-authenticated connection via phone number
    + password (UI Finalization -- Login Identifier: username/email are
    no longer accepted here -- see AuthenticationService.
    authenticate_user()) (D2 -- Server-Side API / Authentication Migration; final
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
        phone_number=result.phone_number,
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
    -- now additionally returning unread_count (BUG -- Offline Unread/
    Notification) alongside its previously unchanged fields. Each row
    is serialized into a plain dict -- conversation_id, is_group,
    group_name, participants (usernames), an optional latest_message
    (payload_type, ciphertext, epoch, timestamp, content_metadata),
    and unread_count -- mirroring exactly what ClientSession.
    load_conversations()/_build_latest_message_preview() used to read
    directly off the ORM rows. ``ciphertext`` is only ever this
    already-encrypted, opaque value -- decryption stays entirely
    client-side; the server does not decrypt, inspect, or alter it. A
    FILE/IMAGE latest_message's ciphertext is None here exactly as it
    is in the database (see persist_message()) -- previews never need
    blob content, only payload_type/content_metadata (e.g. filename)
    to render. unread_count is a plain integer derived from this
    user's own MessageRecipient.status rows (see _get_unread_counts())
    -- message-state metadata only, never message content or key
    material.

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

            admin_username = None

            if is_group:
                # Phase 19.13 -- Group Admin: so a client can show/
                # hide admin-only controls (Remove Member) the moment
                # a group appears in the sidebar, not only right after
                # creating it. Server-enforced regardless (see
                # handle_group_remove_member()) -- this is purely a UI
                # convenience, never trusted as the actual check.
                admin_id = conversation_repo.get_admin_user_id(preview.conversation.id)
                if admin_id is not None:
                    admin_user = db.get(User, admin_id)
                    admin_username = admin_user.username if admin_user is not None else None

            conversations.append({
                "conversation_id": str(preview.conversation.id),
                "is_group": is_group,
                "group_name": preview.conversation.name,
                "admin_username": admin_username,
                "participants": [
                    participant.username for participant in preview.participants
                ],
                "latest_message": latest_message,
                # BUG -- Offline Unread/Notification: additive field,
                # the server-authoritative count of this user's own
                # not-yet-READ MessageRecipient rows in this
                # conversation (ConversationRepository.
                # _get_unread_counts()) -- message-state metadata
                # only, never message content or key material.
                "unread_count": preview.unread_count,
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


def _read_status_for_own_message(message_repo, message, is_group, member_ids):
    """
    Server-side port of ClientSession._read_status_for_own_message()
    (D4.3 -- Message/History Operations Migration, third slice) --
    identical logic, ported line-for-line, now computed here since the
    client no longer has direct database access to compute it itself.
    Only ever called for is_own rows (see handle_message_history_request()
    below) -- never for a message this user received, which this
    codebase's own security model already keeps this user from seeing
    anyone else's read state for anyway.
    """

    recipient_rows = message_repo.get_recipients_for_message(message.id)

    if not recipient_rows:
        return None

    if is_group:
        relevant_rows = [
            row for row in recipient_rows if row.recipient_id in member_ids
        ]
    else:
        relevant_rows = recipient_rows

    if not relevant_rows:
        return False

    return all(row.status == MessageDeliveryStatus.READ for row in relevant_rows)


def _delivery_status_for_own_message(message_repo, message, is_group, member_ids):
    """
    Phase 19.23 -- Issue 3/5 (tri-state ticks survive history reload):
    additive companion to _read_status_for_own_message() above, which
    deliberately only ever returns True/False/None and therefore
    cannot distinguish QUEUED from DELIVERED (both are simply "not
    every relevant row is READ"). That flattening is exactly right for
    ``read_status``'s own existing bool/None contract (left byte-for-
    byte unchanged here, including for every test asserting `is True`/
    `is False`/`is None` against it) but is exactly wrong for a client
    that wants to render a genuine three-state SENT/DELIVERED/READ
    tick that survives reconnect/history-reload -- Phase 19.14's live
    "message_delivered" packet only ever reaches a client that is
    connected at the moment delivery happens, so a client who was
    offline then and reconnects later has no other way to recover it.

    Returns the MessageDeliveryStatus string value ("queued" /
    "delivered" / "read") for the worst-case (least-delivered) row
    among the relevant recipients, or None when there is nothing to
    report -- no recipient rows at all (a legacy message, mirroring
    _read_status_for_own_message()'s own None case exactly), or (group
    case) no currently-relevant row. "Worst case" mirrors the existing
    all()-based READ computation above: a group message only counts as
    READ once EVERY active recipient has read it, so it only counts as
    DELIVERED once every active recipient has at least received it,
    and remains QUEUED while even one still has not.
    """

    recipient_rows = message_repo.get_recipients_for_message(message.id)

    if not recipient_rows:
        return None

    if is_group:
        relevant_rows = [
            row for row in recipient_rows if row.recipient_id in member_ids
        ]
    else:
        relevant_rows = recipient_rows

    if not relevant_rows:
        return None

    if all(row.status == MessageDeliveryStatus.READ for row in relevant_rows):
        return MessageDeliveryStatus.READ.value

    if all(
        row.status in (MessageDeliveryStatus.DELIVERED, MessageDeliveryStatus.READ)
        for row in relevant_rows
    ):
        return MessageDeliveryStatus.DELIVERED.value

    return MessageDeliveryStatus.QUEUED.value


def handle_message_history_request(state, client_socket, user, packet):
    """
    Return a conversation's full stored message history on behalf of
    the authenticated connection (D4.3 -- Message/History Operations
    Migration, third slice), replacing ClientSession.
    load_conversation_history()'s previous direct, client-side
    MessageRepository/ConversationRepository/UserRepository reads --
    the last remaining client-side database access for message
    content itself.

    Security: the caller's identity is always user.id -- the
    authenticated identity from the JWT validated at
    authenticate_connection() time -- never anything read from the
    packet. Before returning anything, the authenticated caller must
    be an active member of conversation_id (get_member_user_ids() --
    the identical check D4.1's handle_epoch_reservation_request() and
    every group-authorization check in this file already use). A
    direct conversation's ConversationMember rows exist for both
    parties exactly like a group's, so this same check covers both
    conversation types with no is_group branch needed for the
    authorization decision itself -- is_group only shapes which
    repository query runs and how read_status is filtered, mirroring
    ClientSession.load_conversation_history()'s own pre-migration
    branching exactly; a wrong or lied-about is_group value cannot
    expose another user's data, since the membership check above is
    independent of it.

    Option A -- lazy blob delivery: a FILE/IMAGE message's ciphertext
    is never included here, only its blob_ref -- the client fetches
    the actual content separately, on demand, via
    blob_download_request. TEXT ciphertext IS included, exactly as it
    always was when the client read it directly from the database --
    it is never decrypted, inspected, or altered here; decryption
    remains entirely client-side.

    Reuses MessageRepository.get_conversation()/get_group_conversation(),
    ConversationRepository.get_member_user_ids(), UserRepository.
    get_by_id(), and MessageRepository.get_recipients_for_message()
    completely unchanged.

    A missing request_id is silently ignored, mirroring every other
    D2/D3/D4 handler's identical guard. No pagination -- the complete
    history is returned in one response, matching this codebase's
    existing behavior exactly (see
    create_message_history_request_packet()'s docstring).
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    conversation_id_raw = packet.get("conversation_id")
    is_group = bool(packet.get("is_group"))

    try:
        conversation_uuid = uuid.UUID(conversation_id_raw)
    except (TypeError, ValueError, AttributeError):
        conversation_uuid = None

    messages_payload = None
    error = None

    if conversation_uuid is None:
        error = "Invalid or missing conversation_id."
    else:
        db = SessionLocal()

        try:
            conversation_repo = ConversationRepository(db)
            message_repo = MessageRepository(db)
            user_repo = UserRepository(db)

            member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

            if user.id not in member_ids:

                state.logger.warning(
                    f"Rejected message_history_request: {user.username} is "
                    f"not a member of conversation {conversation_id_raw}"
                )

                error = "Not a member of this conversation."

            else:

                if is_group:
                    messages = message_repo.get_group_conversation(conversation_uuid)
                else:
                    other_ids = [
                        member_id for member_id in member_ids if member_id != user.id
                    ]
                    partner_id = other_ids[0] if other_ids else None
                    messages = (
                        message_repo.get_conversation(user.id, partner_id)
                        if partner_id is not None
                        else []
                    )

                usernames_by_id = {}

                for member_id in member_ids:
                    member = user_repo.get_by_id(member_id)
                    if member is not None:
                        usernames_by_id[member_id] = member.username

                # Phase 19.24 -- Issue: Delete For Me. Filtered out
                # BEFORE building the payload, not merely marked --
                # this user asked for these to disappear from their
                # own history entirely, on every one of their own
                # devices (that is the whole point of this being a
                # server-side row rather than client-local state; see
                # database/models/message_hidden_for_user.py).
                hidden_message_ids = message_repo.get_hidden_message_ids_for_user(
                    user.id, [message.id for message in messages]
                )
                messages = [
                    message for message in messages
                    if message.id not in hidden_message_ids
                ]

                # Phase 19.24 -- reactions, batched in one query rather
                # than one per message (Message Lifecycle Events'
                # "history recovery" requirement for reactions).
                reactions_by_message = message_repo.get_reactions_for_messages(
                    [message.id for message in messages]
                )

                messages_payload = []

                for message in messages:

                    is_own = message.sender_id == user.id

                    read_status = (
                        _read_status_for_own_message(
                            message_repo, message, is_group, member_ids
                        )
                        if is_own
                        else None
                    )

                    delivery_status = (
                        _delivery_status_for_own_message(
                            message_repo, message, is_group, member_ids
                        )
                        if is_own
                        else None
                    )

                    messages_payload.append({
                        "message_id": str(message.id),
                        "sender": usernames_by_id.get(message.sender_id, "Unknown"),
                        # Message-Level ML-DSA Origin Authentication:
                        # exactly the addressing fields the ORIGINAL
                        # sender signed over on the live "chat" packet
                        # (create_payload_packet()) -- one of the two
                        # is always None, mirroring that packet shape,
                        # so the receiver's canonical reconstruction
                        # (client/session.py::load_conversation_history())
                        # agrees byte-for-byte with what was signed.
                        "receiver": (
                            None if is_group
                            else usernames_by_id.get(message.receiver_id)
                        ),
                        "conversation_id": (
                            str(conversation_uuid) if is_group else None
                        ),
                        "message_signature": message.message_signature,
                        "timestamp": message.timestamp.isoformat(),
                        "is_own": is_own,
                        "payload_type": message.payload_type,
                        "epoch": message.epoch,
                        "ciphertext": message.ciphertext,
                        "blob_ref": message.blob_ref,
                        "content_metadata": message.content_metadata or {},
                        "read_status": read_status,
                        # Phase 19.23 -- additive only (see
                        # _delivery_status_for_own_message()'s
                        # docstring): a client that does not know this
                        # key simply never reads it, exactly like any
                        # other dict key it has never heard of; nothing
                        # about read_status's own existing bool/None
                        # contract changes.
                        "delivery_status": delivery_status,
                        # Phase 19.24 -- Message Lifecycle Events, all
                        # additive. reply_to_message_id: None for an
                        # ordinary message. edited_at/edit_version:
                        # None/0 for a never-edited message. deleted_at/
                        # deleted_by set together, at which point
                        # ciphertext/content_metadata/message_signature/
                        # blob_ref above are ALREADY None (real deletion
                        # -- see handle_message_delete_for_everyone()) --
                        # this flag is what tells the client to render
                        # "Message deleted" instead of attempting to
                        # decrypt null ciphertext. reactions: a list of
                        # {user, ciphertext, epoch} -- the server never
                        # decrypts them; the client resolves `user` to a
                        # username the same way `sender` above already
                        # is.
                        "reply_to_message_id": (
                            str(message.reply_to_message_id)
                            if message.reply_to_message_id else None
                        ),
                        "edited_at": (
                            message.edited_at.isoformat() if message.edited_at else None
                        ),
                        "edit_version": message.edit_version,
                        "deleted_at": (
                            message.deleted_at.isoformat() if message.deleted_at else None
                        ),
                        "deleted_by": (
                            usernames_by_id.get(message.deleted_by, "Unknown")
                            if message.deleted_by else None
                        ),
                        "client_message_id": message.client_message_id,
                        # Phase 19.24 -- Pinned Messages: recovered on
                        # every history load exactly like edit/delete/
                        # reaction state above -- a client that missed a
                        # live message_pinned/message_unpinned
                        # notification (offline, or a newly-authorized
                        # device with no prior live traffic at all)
                        # still ends up with the CURRENT pin state, not
                        # a stale or missing one.
                        "pinned_at": (
                            message.pinned_at.isoformat() if message.pinned_at else None
                        ),
                        "pinned_by": (
                            usernames_by_id.get(message.pinned_by, "Unknown")
                            if message.pinned_by else None
                        ),
                        "reactions": [
                            {
                                "user": usernames_by_id.get(reactor_id, "Unknown"),
                                "ciphertext": ciphertext,
                                "epoch": epoch,
                                "message_signature": reaction_signature,
                            }
                            for reactor_id, ciphertext, epoch, reaction_signature in
                            reactions_by_message.get(message.id, [])
                        ],
                    })
        finally:
            db.close()

    response = create_message_history_result_packet(
        request_id=request_id,
        messages=messages_payload,
        error=error,
    )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send message_history_result to {user.username} "
            f"(request_id={request_id})"
        )


def handle_blob_download_request(state, client_socket, user, packet):
    """
    Return one historical FILE/IMAGE message's encrypted blob content
    on behalf of the authenticated connection (D4.3 -- Message/History
    Operations Migration, third slice; Option A -- lazy blob
    delivery), following up a message_history_request/result that
    reported only the message's blob_ref.

    Security: message_id is resolved to its owning conversation_id via
    MessageRepository.get_message() -- never trusted from the packet
    beyond that lookup -- and the authenticated caller must be an
    active member of that conversation (get_member_user_ids(), the
    same check every other handler in this file uses). An unknown
    message_id and a real-but-forbidden one report the identical
    error, so neither is distinguishable from the other on the wire;
    a message with no blob_ref (a genuine TEXT message, or a data
    inconsistency) is reported distinctly, since that branch is only
    reachable after authorization has already succeeded.

    Reuses storage.encrypted_blob_store.load_blob() completely
    unchanged -- the exact same call ClientSession.
    _load_blob_history_content() used to make directly against local
    storage; the server is the only component with a legitimate
    reason to access FILE_STORAGE_ROOT, since only the server actually
    runs where it lives. The returned ciphertext is never decrypted,
    inspected, or altered here -- decryption remains entirely client-
    side, exactly as before.

    A missing request_id is silently ignored, mirroring every other
    D2/D3/D4 handler's identical guard.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    message_id_raw = packet.get("message_id")

    try:
        message_uuid = uuid.UUID(message_id_raw)
    except (TypeError, ValueError, AttributeError):
        message_uuid = None

    ciphertext = None
    error = None

    if message_uuid is None:
        error = "Unknown message."
    else:
        db = SessionLocal()

        try:
            message = MessageRepository(db).get_message(message_uuid)

            if message is None:
                error = "Unknown message."
            else:
                member_ids = ConversationRepository(db).get_member_user_ids(
                    message.conversation_id
                )

                if user.id not in member_ids:

                    state.logger.warning(
                        f"Rejected blob_download_request: {user.username} is "
                        f"not a member of conversation {message.conversation_id}"
                    )

                    error = "Unknown message."

                elif not message.blob_ref:
                    error = "No attachment content for this message."
                else:
                    ciphertext = encrypted_blob_store.load_blob(
                        message.blob_ref
                    ).decode("utf-8")
        finally:
            db.close()

    response = create_blob_download_result_packet(
        request_id=request_id,
        ciphertext=ciphertext,
        error=error,
    )

    if not send_to_client(client_socket, response):
        state.logger.warning(
            f"Failed to send blob_download_result to {user.username} "
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

    # D8 / L-3 -- allow_idle=False: this is the pre-authentication
    # read, where a peer that connects and then says nothing is
    # precisely the denial of service being defended against. The
    # handshake deadline set in server/server.py::_serve_client()
    # therefore has to be allowed to fire.
    auth_packet = receive_message(client_socket, allow_idle=False)

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
        # Still connection SETUP, so still no idle tolerance.
        key_packet = receive_message(client_socket, allow_idle=False)

        if not key_packet:
            return

        key_packet = parse_packet(key_packet)

        # Connection setup is complete; CLEAR the pre-authentication
        # deadline so an established connection reads in blocking mode.
        #
        # Deliberately AFTER the public-key read above, not straight
        # after authentication: setup is not finished until the key
        # packet has arrived, and a client that authenticates and then
        # goes silent mid-setup is still holding a thread for nothing.
        # The deadline set in server/server.py::_serve_client() covers
        # that whole window and is what bounds an unauthenticated peer.
        #
        # This previously installed a long stall timeout instead of
        # clearing it, so an established connection kept reading in
        # timeout mode for its whole life. That was measured to cause
        # an intermittent regression: with it, this file's own group
        # membership suite failed 4/30 (plus one 0xc0000374 heap
        # corruption); with the socket returned to blocking, 30/30 and
        # 60/60 across arms. The mechanism was never demonstrated -- a
        # dependency-free TLS stress showed no spurious EOF on either
        # Python 3.12.0/OpenSSL 3.0.11 or 3.13.14/OpenSSL 3.0.21 -- so
        # the timeout is removed rather than tuned. Stall detection for
        # an already-authenticated peer is given up knowingly; the
        # pre-auth deadline, the frame-size cap and the connection
        # limit all remain, and those are what bound an anonymous
        # attacker.
        try:
            client_socket.settimeout(None)
        except OSError:
            pass

        if (
            key_packet.get("type") == "key_exchange"
            and key_packet.get("operation") == "public_key"
        ):

            state.set_public_key(
                client_socket,
                key_packet["algorithm"],
                key_packet["public_key"],
                signing_public_key=key_packet.get("signing_public_key"),
                identity_signature=key_packet.get("identity_signature"),
                device_id=key_packet.get("device_id"),
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
            # Direct key redelivery on reconnect (BUG 4 -- Fix B)
            #
            # The direct-conversation counterpart of the two group
            # recoveries above, and subject to the same ordering
            # requirement for the same reason: it asks a connected
            # partner to wrap a key FOR this user, which that partner
            # can only do once distribute_public_keys() has given them
            # this user's current public key. A fresh login means a
            # fresh keypair, so a partner holding the previous
            # session's public key would otherwise wrap for an
            # identity this client can no longer decapsulate.
            # -----------------------------
            _recover_direct_keys_for_reconnecting_user(state, client_socket, user)

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

            # D8 / L-3 -- allow_idle=True: this is the long-lived
            # dispatch loop. A connection sitting quietly between
            # messages is normal and must never be disconnected,
            # so a deadline firing with nothing received is
            # absorbed and the read resumes. A frame that starts
            # arriving and then stalls still raises.
            packet = receive_message(client_socket, allow_idle=True)

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

                # Phase 19.18 -- L-1 closure: revocation was previously
                # enforced only on the group-key-distribution and
                # device-key-sync relay paths (is_device_bound_and_
                # authorized()'s own two pre-existing call sites), not
                # on ordinary chat -- a device revoked mid-connection
                # could keep sending/receiving with key material it
                # already held. Checked here, once, before the
                # direct/group branch below, so both paths are covered
                # by one check -- mirrors handle_group_key_distribution()
                # 's own sender check exactly, including the same
                # False-only (never None) rejection semantics: None
                # means this connection never bound a device at all
                # (every pre-Phase-16 client, and every client that
                # simply never opted into per-device identity) and is
                # deliberately NOT a rejection -- only a live, current
                # REVOKED state blocks anything. Silent drop, no error
                # sent back, same as every other security rejection in
                # this file.
                if is_device_bound_and_authorized(state, client_socket) is False:

                    state.logger.warning(
                        f"Rejected chat from {username}: sender's bound "
                        f"device is not AUTHORIZED"
                    )

                    continue

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

                # Phase 18.5 -- Same-Account Multi-Device Routing audit:
                # the receiver is resolved ONCE, up front, regardless of
                # whether they are currently connected -- both the
                # live-relay and offline-persistence paths below need
                # the identical User row. Unifies what used to be two
                # separate lookups (an online path keyed off
                # state.clients, an offline path keyed off
                # UserRepository) into one, removing the duplicated
                # persist-or-queue logic that used to live only in the
                # offline branch.
                db = SessionLocal()
                try:
                    receiver_user = UserRepository(db).get_by_username(receiver)
                    # Phase 19.24 -- Block User: checked in the SAME
                    # session as the lookup above, before persistence
                    # or relay -- a block in EITHER direction refuses
                    # the send entirely (mirrors every mainstream
                    # messaging app: blocking stops messages both ways,
                    # not just the direction the blocker initiated).
                    # Reuses create_delivery_failure_packet() rather
                    # than inventing a new rejection type -- every
                    # client already handles this packet correctly.
                    blocked = receiver_user is not None and (
                        BlockedUserRepository(db).is_blocked(receiver_user.id, user.id)
                        or BlockedUserRepository(db).is_blocked(user.id, receiver_user.id)
                    )
                finally:
                    db.close()

                if receiver_user is None:

                    # Genuine failure: no such account at all. Nothing
                    # to persist, nothing to relay.
                    state.logger.info(
                        f"Delivery failed: {username} -> {receiver} "
                        f"(unknown recipient)"
                    )

                    send_to_client(
                        client_socket,
                        create_delivery_failure_packet(receiver)
                    )

                elif blocked:

                    state.logger.info(
                        f"Delivery failed: {username} -> {receiver} "
                        f"(blocked)"
                    )

                    send_to_client(
                        client_socket,
                        create_delivery_failure_packet(receiver)
                    )

                else:

                    # D3.1 -- Conversation Operations Migration:
                    # resolved here, before relay, so the receiving
                    # client can read it straight off the packet
                    # instead of resolving/creating it itself via a
                    # direct database call. Deliberately a NEW field,
                    # never "conversation_id" -- the receiving client's
                    # handle_chat() derives is_group from that field's
                    # mere presence (group packets set it, direct ones
                    # never did), so reusing it here would misclassify
                    # every direct message as a group one the moment a
                    # client is updated to read it.
                    direct_conversation_id = _resolve_direct_conversation_id(
                        user.id, receiver_user.id
                    )
                    packet["direct_conversation_id"] = direct_conversation_id

                    sender_client = state.get_client(client_socket)

                    # BUG 2 -- persist the message AND its QUEUED
                    # recipient row BEFORE relaying, so the row a read
                    # receipt must update always exists by the time the
                    # recipient could send one. Persisted EXACTLY ONCE
                    # here, regardless of how many of the recipient's
                    # own currently-connected devices end up matching
                    # below (Phase 18.5 -- Same-Account Multi-Device
                    # Routing: this relay used to stop at the FIRST
                    # matching socket for `receiver` it happened to
                    # find in state.clients -- an unconditional `break`
                    # -- silently skipping every OTHER simultaneously-
                    # connected device of that same account. This now
                    # mirrors handle_group_chat_delivery()'s own,
                    # already-correct, already-precedented per-socket
                    # fan-out below -- not a new routing mechanism, the
                    # SAME one group messaging already shipped with).
                    message = None

                    try:
                        message = persist_message(
                            sender_id=user.id,
                            receiver_id=receiver_user.id,
                            algorithm=(sender_client or {}).get("algorithm"),
                            packet=packet,
                            conversation_id=direct_conversation_id,
                        )

                        _record_direct_recipient(message, receiver_user.id)

                    except Exception as error:  # noqa: BLE001

                        # Intentionally broad, not an oversight:
                        # persist_message() can fail for reasons
                        # spanning unrelated exception hierarchies --
                        # SQLAlchemyError from db.commit()/the
                        # conversation lookup, OSError from
                        # encrypted_blob_store's filesystem write
                        # (FILE/IMAGE payloads), or AttributeError/
                        # TypeError from a malformed packet -- and no
                        # single specific except would isolate all of
                        # them. The failure is always logged, never
                        # silently swallowed.
                        print(f"[ERROR] {error}")

                        state.logger.error(str(error))

                    if message is None:

                        # Genuine failure: the recipient exists, but
                        # persistence raised above. Nothing was stored,
                        # so nothing must be claimed.
                        state.logger.info(
                            f"Delivery failed: {username} -> {receiver} "
                            f"(message could not be persisted)"
                        )

                        send_to_client(
                            client_socket,
                            create_delivery_failure_packet(receiver)
                        )

                    else:

                        # Phase 18.5 -- Step 6 (History Deduplication):
                        # the SAME stable id message_history_result
                        # already reports for this row once persisted
                        # (server/client_handler.py::
                        # handle_message_history_request()) -- added
                        # here, additively, so a client that already
                        # rendered this live message can recognize it
                        # again later via history and skip re-rendering
                        # it, without needing a second identifier
                        # scheme. Not part of any ML-DSA-signed payload
                        # (canonical_message_payload() never included
                        # it, on either side), so adding it here changes
                        # nothing about what was already signed or how
                        # it verifies.
                        packet["message_id"] = str(message.id)

                        delivered_to_any_device = False

                        for sock, client in list(state.clients.items()):

                            if sock == client_socket:
                                continue

                            if client["username"] != receiver:
                                continue

                            # Phase 19.18 -- L-1 closure, recipient side:
                            # skip only THIS specific revoked device's
                            # socket -- the message is already persisted
                            # above regardless (still reaches the
                            # account via history / any other,
                            # non-revoked, currently-connected device of
                            # theirs in this same loop), mirroring
                            # handle_group_key_distribution()'s own
                            # per-recipient-socket check exactly.
                            if is_device_bound_and_authorized(state, sock) is False:

                                state.logger.warning(
                                    f"Dropped chat relay to {receiver}: "
                                    f"recipient's bound device is not AUTHORIZED"
                                )

                                continue

                            print(
                                f"{username} -> {receiver}: "
                                f"[Encrypted Message]"
                            )

                            state.logger.info(
                                f"{username} -> {receiver}: "
                                f"[Encrypted Message]"
                            )

                            if send_to_client(sock, packet):
                                delivered_to_any_device = True

                        # C2 -- Read Receipts: DELIVERED only if the
                        # live relay above actually reached at least
                        # one of the recipient's currently-connected
                        # devices -- a send_to_client() failure on
                        # every match must not be recorded as
                        # delivered; QUEUED is exactly the correct,
                        # already-existing status for "persisted but
                        # not yet confirmed delivered". Reaching TWO (or
                        # more) of the recipient's own devices still
                        # only ever promotes the ONE MessageRecipient
                        # row (receiver_user.id) -- there is one
                        # recipient row per ACCOUNT, not per device,
                        # exactly like read receipts are already
                        # account-level, never device-level (see
                        # handle_read_receipt()/mark_conversation_read(),
                        # unchanged by this phase).
                        #
                        # BUG 2: this promotion only ever moves
                        # QUEUED -> DELIVERED. If the recipient read the
                        # message in the gap between the row being
                        # written above and this line, the row is
                        # already READ and mark_delivered() leaves it
                        # alone -- READ is terminal with respect to
                        # delivery status.
                        if delivered_to_any_device:

                            try:
                                _mark_recipients_delivered(
                                    message.id,
                                    [receiver_user.id],
                                )
                            except Exception as error:  # noqa: BLE001

                                # Intentionally broad and scoped to this
                                # bookkeeping call alone -- the message
                                # was already relayed and persisted
                                # above, so a failure here (e.g. a
                                # transient DB error writing the
                                # MessageRecipient row) must never undo
                                # or interrupt a delivery that already
                                # succeeded; only read-receipt status
                                # tracking is at risk, not the message
                                # itself.
                                print(f"[ERROR] {error}")

                                state.logger.error(str(error))

                            # Phase 19.14 -- Message Status Ticks: tell
                            # the SENDER this happened at all -- see
                            # create_message_delivered_packet()'s own
                            # docstring for why this was previously
                            # entirely missing. Sent even if the
                            # MessageRecipient bookkeeping above just
                            # failed: the live relay itself (send_to_
                            # client() returning True) is the actual
                            # fact being reported, not that row.
                            send_to_client(
                                client_socket,
                                create_message_delivered_packet(
                                    receiver=receiver,
                                    message_id=str(message.id),
                                    conversation_id=(
                                        str(message.conversation_id)
                                        if message.conversation_id
                                        else None
                                    ),
                                )
                            )

                        else:

                            # BUG 4 -- Fix A: a real registered user who
                            # is simply not connected on ANY device
                            # right now is NOT a delivery failure. The
                            # ciphertext is stored and its recipient row
                            # is QUEUED, so the honest answer to the
                            # sender is "accepted, not yet delivered" --
                            # answering delivery_failure here would make
                            # the sender's GUI show an error for a
                            # message that had just been saved
                            # correctly.
                            #
                            # QUEUED is not upgraded to DELIVERED here:
                            # nothing was relayed to anybody. Only the
                            # live-relay path above records DELIVERED.
                            state.logger.info(
                                f"Queued: {username} -> {receiver} "
                                f"(recipient not connected, message persisted)"
                            )

                            send_to_client(
                                client_socket,
                                create_message_queued_packet(
                                    receiver=receiver,
                                    message_id=str(message.id),
                                    conversation_id=(
                                        str(message.conversation_id)
                                        if message.conversation_id
                                        else None
                                    ),
                                )
                            )

            # -----------------------------
            # Public Key Re-broadcast (Phase 16D -- Device-Aware Peer
            # Identity)
            #
            # The bootstrap read earlier in this file (see this
            # function's own "Received {algorithm} public key" log
            # line) only ever fires ONCE, as part of connection setup
            # -- before this phase, no legitimate client ever sent a
            # SECOND "key_exchange"/"public_key" packet later in the
            # same connection, so nothing needed to handle one here.
            # ClientSession.enroll_device() (client/session.py) now
            # does exactly that: it re-sends this client's identity,
            # this time carrying device_id, the moment self.device_id
            # first becomes known (enroll_device() is an explicit,
            # later, app-level action -- normally well after the
            # bootstrap broadcast already fired with device_id still
            # unset). Without this branch that second packet would
            # silently fall through every elif below and never reach
            # any peer, exactly as observed before this branch existed.
            #
            # Reuses state.set_public_key()/distribute_public_keys()
            # completely unchanged -- the same storage and the same
            # relay-to-everyone-else fan-out the bootstrap path already
            # uses, just invoked a second time. The server still never
            # inspects, validates, or trusts device_id for anything of
            # its own; it is stored and relayed exactly like signing_
            # public_key/identity_signature already are, and every
            # receiving client's own _handle_signed_public_key() still
            # requires a valid ML-DSA signature before trusting any of
            # it.
            # -----------------------------
            elif (
                packet.get("type") == "key_exchange"
                and packet.get("operation") == "public_key"
            ):

                state.set_public_key(
                    client_socket,
                    packet["algorithm"],
                    packet["public_key"],
                    signing_public_key=packet.get("signing_public_key"),
                    identity_signature=packet.get("identity_signature"),
                    device_id=packet.get("device_id"),
                )

                distribute_public_keys(state, client_socket)

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

                handle_group_key_distribution(state, client_socket, user, packet)

            # -----------------------------
            # Direct Key Recovery Request (BUG 4 -- Fix B)
            # -----------------------------
            elif packet.get("type") == "direct_key_recovery_request":

                handle_direct_key_recovery_request(state, client_socket, user, packet)

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
            # Group Remove Member + Inbox (Phase 19.13)
            # -----------------------------
            elif packet.get("type") == "group_remove_member":

                handle_group_remove_member(state, client_socket, user, packet)

            elif packet.get("type") == "verification_request":

                handle_verification_request(state, client_socket, user, packet)

            elif packet.get("type") == "inbox_list_request":

                handle_inbox_list_request(state, client_socket, user, packet)

            elif packet.get("type") == "inbox_response":

                handle_inbox_response(state, client_socket, user, packet)

            # -----------------------------
            # Settings (Phase 19.14)
            # -----------------------------
            elif packet.get("type") == "change_username_request":

                handle_change_username_request(state, client_socket, user, packet)

            elif packet.get("type") == "change_password_request":

                handle_change_password_request(state, client_socket, user, packet)

            # -----------------------------
            # Block User (Phase 19.24)
            # -----------------------------
            elif packet.get("type") == "block_user_request":

                handle_block_user_request(state, client_socket, user, packet)

            elif packet.get("type") == "unblock_user_request":

                handle_unblock_user_request(state, client_socket, user, packet)

            elif packet.get("type") == "blocked_users_list_request":

                handle_blocked_users_list_request(state, client_socket, user, packet)

            elif packet.get("type") == "profile_picture_upload_request":

                handle_profile_picture_upload_request(state, client_socket, user, packet)

            elif packet.get("type") == "profile_picture_request":

                handle_profile_picture_request(state, client_socket, user, packet)

            elif packet.get("type") == "change_bio_request":

                handle_change_bio_request(state, client_socket, user, packet)

            elif packet.get("type") == "bio_request":

                handle_bio_request(state, client_socket, user, packet)

            elif packet.get("type") == "last_seen_request":

                handle_last_seen_request(state, client_socket, user, packet)

            # -----------------------------
            # Read Receipt Packet (C2)
            # -----------------------------
            elif packet.get("type") == "read_receipt":

                handle_read_receipt(state, client_socket, user, packet)

            # Phase 19.24 -- Message Lifecycle Events.
            elif packet.get("type") == "message_edit":

                handle_message_edit(state, client_socket, user, packet)

            elif packet.get("type") == "message_delete_for_me":

                handle_message_delete_for_me(state, client_socket, user, packet)

            elif packet.get("type") == "message_delete_for_everyone":

                handle_message_delete_for_everyone(state, client_socket, user, packet)

            elif packet.get("type") == "reaction_add":

                handle_reaction_add(state, client_socket, user, packet)

            elif packet.get("type") == "reaction_remove":

                handle_reaction_remove(state, client_socket, user, packet)

            elif packet.get("type") == "message_pin":

                handle_message_pin(state, client_socket, user, packet)

            elif packet.get("type") == "message_unpin":

                handle_message_unpin(state, client_socket, user, packet)

            # -----------------------------
            # Typing Indicator (Phase 19.24)
            # -----------------------------
            elif packet.get("type") == "typing_indicator":

                handle_typing_indicator(state, client_socket, user, packet)

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
            # Multi-Device Identity (Phase 16)
            # -----------------------------
            elif packet.get("type") == "device_enroll_request":

                handle_device_enroll_request(state, client_socket, user, packet)

            elif packet.get("type") == "device_list_request":

                handle_device_list_request(state, client_socket, user, packet)

            elif packet.get("type") == "device_authorize":

                handle_device_authorize(state, client_socket, user, packet)

            elif packet.get("type") == "device_revoke":

                handle_device_revoke(state, client_socket, user, packet)

            elif packet.get("type") == "device_session_bind":

                handle_device_session_bind(state, client_socket, user, packet)

            elif packet.get("type") == "device_key_sync":

                handle_device_key_sync(state, client_socket, user, packet)

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

            # -----------------------------
            # Message History Request (D4.3)
            # -----------------------------
            elif packet.get("type") == "message_history_request":

                handle_message_history_request(state, client_socket, user, packet)

            # -----------------------------
            # Blob Download Request (D4.3)
            # -----------------------------
            elif packet.get("type") == "blob_download_request":

                handle_blob_download_request(state, client_socket, user, packet)

    except Exception as e:

        print(f"[ERROR] {e}")
        state.logger.error(str(e))

    finally:

        client = state.get_client(client_socket)

        if client:

            username = client["username"]

            # Phase 19.24 -- Presence/Last Seen: recorded here, not on
            # every message, so it reflects "when this connection
            # actually ended" -- a single overwritten timestamp (see
            # database/models/user.py::last_seen_at's own docstring),
            # best-effort (a DB error here must never prevent the rest
            # of this cleanup -- the client is disconnecting either
            # way).
            user_id = client.get("user_id")
            if user_id:
                db = SessionLocal()
                try:
                    user_row = UserRepository(db).get_by_id(user_id)
                    if user_row is not None:
                        UserRepository(db).update_last_seen(user_row, datetime.now(timezone.utc).replace(tzinfo=None))
                        db.commit()
                except Exception as error:  # noqa: BLE001
                    state.logger.warning(f"Could not record last_seen_at for {username}: {error}")
                finally:
                    db.close()

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