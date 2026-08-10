"""
Client Handler Module

Handles communication with individual clients.
"""

import uuid
from datetime import datetime, timezone

from auth.authentication_service import AuthenticationService
from config import KEY_EXCHANGE_ALGORITHM
from database.connection import SessionLocal
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
    create_join_packet,
    create_leave_packet,
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

        if client.get("user_id") in member_id_strings:

            send_to_client(sock, packet)

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

                        send_to_client(
                            sock,
                            packet
                        )

                        sender_client = state.get_client(client_socket)

                        persist_message(
                            sender_id=user.id,
                            receiver_id=client["user_id"],
                            algorithm=(sender_client or {}).get("algorithm"),
                            packet=packet
                        )

                        break

                else:

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

                        send_to_client(
                            sock,
                            packet
                        )

                        state.logger.info(
                            f"Forwarded session key "
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

                        send_to_client(
                            sock,
                            packet
                        )

                        state.logger.info(
                            f"Forwarded group key for "
                            f"{packet.get('conversation_id')} "
                            f"from {username} to {recipient}"
                        )

                        break

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