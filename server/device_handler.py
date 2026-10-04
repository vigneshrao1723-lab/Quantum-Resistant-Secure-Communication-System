"""
Device management request handlers (Phase 16 -- Multi-Device
Identity).

Mirrors server/client_handler.py's own established handler
conventions exactly (see e.g. handle_epoch_reservation_request()):
each handler takes (state, client_socket, user, packet), opens its own
fresh SessionLocal() per call, resolves the account identity ONLY from
``user`` (the already-authenticated User ORM object the caller's
dispatch loop resolved from the validated JWT -- never from anything
inside ``packet``), and replies with exactly one result packet.

Security-critical invariant, repeated at every verification point
below: a signature is verified against a public key resolved from
THIS SERVER'S OWN already-stored state (the target device's own
advertised key for a self-signed enrollment; the authorizing device's
already-AUTHORIZED key on file for authorize/revoke) -- never against
a key carried in the packet being verified. This is the same
verify-before-install ordering client/session.py::handle_group_key_
distribution() already established for peer-to-peer key material,
applied here to account-device management instead.
"""

import base64
import uuid

from crypto.device_protocol import (
    canonical_device_authorization_payload,
    canonical_device_enrollment_payload,
    canonical_device_key_sync_payload,
    canonical_device_revocation_payload,
    canonical_device_session_binding_payload,
    verify_device_payload,
)
from database.connection import SessionLocal
from database.models.device import DEVICE_STATE_AUTHORIZED
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.device_repository import DeviceRepository
from utils.protocol import (
    create_device_authorize_result_packet,
    create_device_enroll_result_packet,
    create_device_key_sync_result_packet,
    create_device_list_result_packet,
    create_device_revoke_result_packet,
    create_device_session_bind_result_packet,
)


def is_device_bound_and_authorized(state, client_socket):
    """
    Phase 16B -- Device State Enforcement: True only if THIS connection
    has completed a real, signature-verified device_session_bind
    (handle_device_session_bind() below) AND that device is currently
    AUTHORIZED. False for every connection that never opted into the
    device system at all (the pre-Phase-16 default -- see this
    function's own callers for why that is deliberately NOT itself a
    rejection) and for one whose device has since been REVOKED.

    Re-checks the CURRENT database state on every call rather than
    trusting a cached flag from bind time -- a device revoked mid-
    connection must stop passing this check on its very next relayed
    packet, without requiring it to reconnect first.
    """

    client_info = state.get_client(client_socket)
    device_id = client_info.get("device_id") if client_info else None

    if device_id is None:
        return None  # not opted into the device system on this connection

    db = SessionLocal()
    try:
        device = DeviceRepository(db).get_by_id(uuid.UUID(device_id))
        return bool(device is not None and device.state == DEVICE_STATE_AUTHORIZED)
    finally:
        db.close()


def _send(state, client_socket, user, response, label):
    from server.broadcaster import send_to_client

    if not send_to_client(client_socket, response):
        state.logger.warning(f"Failed to send {label} to {user.username}")


def handle_device_enroll_request(state, client_socket, user, packet):
    """
    A device's own, self-signed request to become known to this
    account. Verified against the device's OWN advertised ML-DSA
    public key (self-consistency -- proves possession of the claimed
    private key, exactly like crypto/identity_protocol.py's identical
    caveat, NOT authorization by itself). The account is always
    ``user`` -- the authenticated connection's own identity -- never
    anything the packet claims.

    Bootstrap exception (docs/architecture/multi_device_identity.md's
    "Bootstrap case"): if this account currently has zero AUTHORIZED
    devices, this one is auto-authorized -- identical, in trust shape,
    to today's implicit single-device model. Every subsequent device
    is inserted as PENDING and requires a real device_authorize from
    an existing AUTHORIZED device.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    device_id = packet.get("device_id")
    kem_public_key = packet.get("kem_public_key")
    ml_dsa_public_key_b64 = packet.get("ml_dsa_public_key")
    signature_b64 = packet.get("enrollment_signature")
    device_name = packet.get("device_name")
    platform = packet.get("platform")

    error = None
    state_value = None

    try:
        device_uuid = uuid.UUID(device_id)
    except (TypeError, ValueError, AttributeError):
        device_uuid = None

    if device_uuid is None or not kem_public_key or not ml_dsa_public_key_b64:
        error = "Malformed device enrollment request."
    elif not signature_b64:
        error = "Missing enrollment_signature."
    else:
        try:
            ml_dsa_public_key = base64.b64decode(ml_dsa_public_key_b64, validate=True)
            signature = base64.b64decode(signature_b64, validate=True)
        except Exception:  # noqa: BLE001 -- malformed base64, untrusted input
            ml_dsa_public_key = None
            signature = None

        if ml_dsa_public_key is None:
            error = "Malformed base64 in enrollment request."
        else:
            payload = canonical_device_enrollment_payload(
                user.username, device_id, kem_public_key, ml_dsa_public_key,
                device_name, platform,
            )

            try:
                verified = verify_device_payload(payload, signature, ml_dsa_public_key)
            except (TypeError, ValueError):
                verified = False

            if not verified:
                state.logger.warning(
                    f"Rejected device_enroll_request from {user.username}: "
                    f"self-signature did not verify."
                )
                error = "Enrollment signature did not verify."
            else:
                from crypto.key_manager import fingerprint_combined_identity

                fingerprint = fingerprint_combined_identity(kem_public_key, ml_dsa_public_key)

                db = SessionLocal()
                try:
                    device_repo = DeviceRepository(db)

                    if device_repo.get_by_id(device_uuid) is not None:
                        error = "device_id already enrolled."
                    else:
                        auto_authorize = device_repo.get_authorized_device_count(user.id) == 0

                        device_repo.enroll(
                            device_id=device_uuid,
                            user_id=user.id,
                            kem_public_key=kem_public_key,
                            ml_dsa_public_key=ml_dsa_public_key_b64,
                            fingerprint=fingerprint,
                            device_name=device_name,
                            platform=platform,
                            auto_authorize=auto_authorize,
                        )
                        device_repo.commit()

                        state_value = DEVICE_STATE_AUTHORIZED if auto_authorize else "PENDING"

                        state.logger.info(
                            f"Device {device_id} enrolled for {user.username} "
                            f"(state={state_value})"
                        )
                finally:
                    db.close()

    response = create_device_enroll_result_packet(
        request_id=request_id, success=error is None, state=state_value,
        device_id=device_id if error is None else None, error=error,
    )
    _send(state, client_socket, user, response, "device_enroll_result")


def handle_device_list_request(state, client_socket, user, packet):
    request_id = packet.get("request_id")

    if not request_id:
        return

    db = SessionLocal()
    try:
        device_repo = DeviceRepository(db)
        devices = device_repo.get_devices_for_user(user.id)

        devices_payload = [
            {
                "device_id": str(d.device_id),
                "device_name": d.device_name,
                "platform": d.platform,
                "fingerprint": d.fingerprint,
                "state": d.state,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                # Phase 16C -- Cross-Device Key Synchronization: PUBLIC
                # keys only (the exact same wire representation the
                # "key_exchange"/"public_key" packet already broadcasts
                # to every OTHER connected user), needed so one of the
                # account's own devices can observe+verify another as a
                # device-peer (see ClientSession.
                # observe_device_peer_identity()) before wrapping key
                # material for it. Never a private key -- none exists
                # in this row to leak (see database/models/device.py).
                "kem_public_key": d.kem_public_key,
                "ml_dsa_public_key": d.ml_dsa_public_key,
            }
            for d in devices
        ]
    finally:
        db.close()

    response = create_device_list_result_packet(request_id, devices_payload)
    _send(state, client_socket, user, response, "device_list_result")


def handle_device_authorize(state, client_socket, user, packet):
    """
    An already-AUTHORIZED device vouching for a PENDING one. The
    signature is verified against the AUTHORIZING device's OWN
    already-AUTHORIZED public key on file for this account -- never
    against anything in the packet -- and the authorizer must itself
    currently be AUTHORIZED for THIS account (an authorized device for
    a different account can never authorize anything here).
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_device_id = packet.get("target_device_id")
    target_fingerprint = packet.get("target_fingerprint")
    authorizer_device_id = packet.get("authorizer_device_id")
    signature_b64 = packet.get("authorization_signature")

    error = None

    try:
        target_uuid = uuid.UUID(target_device_id)
        authorizer_uuid = uuid.UUID(authorizer_device_id)
    except (TypeError, ValueError, AttributeError):
        target_uuid = authorizer_uuid = None

    if target_uuid is None or authorizer_uuid is None or not signature_b64:
        error = "Malformed device_authorize request."
    else:
        db = SessionLocal()
        try:
            device_repo = DeviceRepository(db)

            authorizer = device_repo.get_by_id(authorizer_uuid)
            target = device_repo.get_by_id(target_uuid)

            if authorizer is None or authorizer.user_id != user.id or authorizer.state != DEVICE_STATE_AUTHORIZED:
                state.logger.warning(
                    f"Rejected device_authorize from {user.username}: "
                    f"authorizer {authorizer_device_id} is not an AUTHORIZED "
                    f"device on this account."
                )
                error = "Authorizing device is not an authorized device on this account."
            elif target is None or target.user_id != user.id:
                error = "Unknown target device for this account."
            elif target.fingerprint != target_fingerprint:
                state.logger.warning(
                    f"Rejected device_authorize: claimed fingerprint for "
                    f"{target_device_id} does not match the stored one."
                )
                error = "Target fingerprint does not match the enrolled device."
            else:
                try:
                    signature = base64.b64decode(signature_b64, validate=True)
                    authorizer_public_key = base64.b64decode(
                        authorizer.ml_dsa_public_key, validate=True
                    )
                except Exception:  # noqa: BLE001
                    signature = authorizer_public_key = None

                payload = canonical_device_authorization_payload(
                    user.username, target_device_id, target_fingerprint, authorizer_device_id,
                ) if signature is not None else None

                verified = False
                if payload is not None:
                    try:
                        verified = verify_device_payload(payload, signature, authorizer_public_key)
                    except (TypeError, ValueError):
                        verified = False

                if not verified:
                    state.logger.warning(
                        f"Rejected device_authorize from {user.username}: "
                        f"authorization signature did not verify."
                    )
                    error = "Authorization signature did not verify."
                else:
                    device_repo.authorize(target, authorizer_uuid)
                    device_repo.commit()
                    state.logger.info(
                        f"Device {target_device_id} authorized for {user.username} "
                        f"by device {authorizer_device_id}"
                    )
        finally:
            db.close()

    response = create_device_authorize_result_packet(request_id, error is None, error)
    _send(state, client_socket, user, response, "device_authorize_result")


def handle_device_revoke(state, client_socket, user, packet):
    """
    An already-AUTHORIZED device revoking a device (possibly itself).
    Same signature-origin discipline as handle_device_authorize().
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_device_id = packet.get("target_device_id")
    revoker_device_id = packet.get("revoker_device_id")
    signature_b64 = packet.get("revocation_signature")

    error = None

    try:
        target_uuid = uuid.UUID(target_device_id)
        revoker_uuid = uuid.UUID(revoker_device_id)
    except (TypeError, ValueError, AttributeError):
        target_uuid = revoker_uuid = None

    if target_uuid is None or revoker_uuid is None or not signature_b64:
        error = "Malformed device_revoke request."
    else:
        db = SessionLocal()
        try:
            device_repo = DeviceRepository(db)

            revoker = device_repo.get_by_id(revoker_uuid)
            target = device_repo.get_by_id(target_uuid)

            if revoker is None or revoker.user_id != user.id or revoker.state != DEVICE_STATE_AUTHORIZED:
                state.logger.warning(
                    f"Rejected device_revoke from {user.username}: revoker "
                    f"{revoker_device_id} is not an AUTHORIZED device on this account."
                )
                error = "Revoking device is not an authorized device on this account."
            elif target is None or target.user_id != user.id:
                error = "Unknown target device for this account."
            else:
                try:
                    signature = base64.b64decode(signature_b64, validate=True)
                    revoker_public_key = base64.b64decode(revoker.ml_dsa_public_key, validate=True)
                except Exception:  # noqa: BLE001
                    signature = revoker_public_key = None

                payload = canonical_device_revocation_payload(
                    user.username, target_device_id, revoker_device_id,
                ) if signature is not None else None

                verified = False
                if payload is not None:
                    try:
                        verified = verify_device_payload(payload, signature, revoker_public_key)
                    except (TypeError, ValueError):
                        verified = False

                if not verified:
                    state.logger.warning(
                        f"Rejected device_revoke from {user.username}: "
                        f"revocation signature did not verify."
                    )
                    error = "Revocation signature did not verify."
                else:
                    device_repo.revoke(target)
                    device_repo.commit()
                    state.logger.info(
                        f"Device {target_device_id} revoked for {user.username} "
                        f"by device {revoker_device_id}"
                    )
        finally:
            db.close()

    response = create_device_revoke_result_packet(request_id, error is None, error)
    _send(state, client_socket, user, response, "device_revoke_result")


def handle_device_session_bind(state, client_socket, user, packet):
    """
    Phase 16B -- Device Authentication Binding (Step 3). Verifies this
    connection is genuinely operated by the party holding the private
    ML-DSA key for the claimed ``device_id``, that the device belongs
    to THIS authenticated account, and that it is currently AUTHORIZED
    -- then tags this connection's own ServerState entry with
    ``device_id`` so later, security-relevant relay decisions
    (server/device_handler.py::is_device_bound_and_authorized(), used
    by server/client_handler.py's group_key_distribution/chat relay --
    see this phase's own report for the exact enforcement points) can
    re-check its live state on every subsequent packet.

    The public key verified against is ALWAYS the one already stored
    for this device_id (resolved server-side, from the devices table)
    -- never anything in the packet -- exactly like every other
    verification in this module.
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    device_id = packet.get("device_id")
    session_nonce = packet.get("session_nonce")
    signature_b64 = packet.get("binding_signature")

    error = None

    try:
        device_uuid = uuid.UUID(device_id)
    except (TypeError, ValueError, AttributeError):
        device_uuid = None

    if device_uuid is None or not session_nonce or not signature_b64:
        error = "Malformed device_session_bind request."
    else:
        db = SessionLocal()
        try:
            device = DeviceRepository(db).get_by_id(device_uuid)

            if device is None or device.user_id != user.id:
                error = "Unknown device for this account."
            elif device.state != DEVICE_STATE_AUTHORIZED:
                state.logger.warning(
                    f"Rejected device_session_bind from {user.username}: "
                    f"device {device_id} is not AUTHORIZED (state={device.state})."
                )
                error = "Device is not authorized."
            else:
                try:
                    signature = base64.b64decode(signature_b64, validate=True)
                    device_public_key = base64.b64decode(device.ml_dsa_public_key, validate=True)
                except Exception:  # noqa: BLE001
                    signature = device_public_key = None

                verified = False
                if signature is not None:
                    payload = canonical_device_session_binding_payload(
                        user.username, device_id, session_nonce,
                    )
                    try:
                        verified = verify_device_payload(payload, signature, device_public_key)
                    except (TypeError, ValueError):
                        verified = False

                if not verified:
                    state.logger.warning(
                        f"Rejected device_session_bind from {user.username}: "
                        f"binding signature did not verify."
                    )
                    error = "Binding signature did not verify."
                else:
                    client_info = state.get_client(client_socket)
                    if client_info is not None:
                        client_info["device_id"] = device_id
                    state.logger.info(
                        f"Device {device_id} bound to this connection for {user.username}"
                    )
        finally:
            db.close()

    response = create_device_session_bind_result_packet(request_id, error is None, error)
    _send(state, client_socket, user, response, "device_session_bind_result")


def _find_socket_for_bound_device(state, user_id_str, device_id_str):
    """Device-based routing (Phase 16C) -- distinct from every other
    relay in this codebase, which routes by username. Only a
    connection that has completed a real device_session_bind() for
    EXACTLY this device_id (and belongs to the same account) is
    matched; a device that is enrolled/authorized but not currently
    bound on any live connection is correctly treated as "not
    currently reachable", the same silent-no-op convention
    handle_group_key_distribution() already uses for an offline
    recipient."""

    for sock, client in list(state.clients.items()):
        if client.get("user_id") == user_id_str and client.get("device_id") == device_id_str:
            return sock
    return None


def handle_device_key_sync(state, client_socket, user, packet):
    """
    Relay one device's wrapped conversation/group key material to
    another of the SAME account's own devices (Phase 16C). The server
    never sees the key itself -- encapsulation/wrapped_key are exactly
    what KeyManager.wrap_key_for_member() already produces for
    ordinary group-key distribution, forwarded byte-for-byte opaque,
    unchanged from that existing convention.

    Authorization (Step 6/7 -- never trust client-supplied device
    state as proof; the server's own DeviceRepository row is the only
    authority):
      1. The SENDER's own connection must already be a real,
         signature-verified, AUTHORIZED device binding
         (is_device_bound_and_authorized() -- re-reads live DB state,
         rejects a PENDING/REVOKED source outright).
      2. The TARGET device must belong to THIS SAME account
         (user.id), must be AUTHORIZED (never PENDING/REVOKED --
         Step 6 items 6/7), and its claimed fingerprint must match the
         server's own stored value (Step 8 -- binds the package to a
         specific, unambiguous device identity, not just an opaque id
         the server could otherwise silently redirect).
      3. sync_signature is verified against the SOURCE device's own
         already-on-file public key (resolved server-side, never from
         the packet) -- proves this exact package, including its
         wrapped key material, actually came from that device.

    A target device that is not CURRENTLY connected+bound is a silent
    no-op -- mirrors handle_group_key_distribution()'s identical
    "recipient not connected" behavior; there is no store-and-forward
    for this packet type in this phase (see this phase's own report,
    "Remaining limitations").
    """

    request_id = packet.get("request_id")

    if not request_id:
        return

    target_device_id = packet.get("target_device_id")
    target_fingerprint = packet.get("target_fingerprint")
    conversation_id = packet.get("conversation_id")
    epoch = packet.get("epoch")
    if epoch is None:
        epoch = 1
    package_type = packet.get("package_type")
    encapsulation = packet.get("encapsulation")
    wrapped_key = packet.get("wrapped_key")
    signature_b64 = packet.get("sync_signature")

    error = None

    source_device_state = is_device_bound_and_authorized(state, client_socket)

    # Step 6 (Phase 16E) -- epoch must be a plain positive integer,
    # mirroring server/client_handler.py::handle_group_key_
    # distribution()'s identical, pre-existing check exactly (bool is
    # excluded explicitly since it subclasses int). Checked before the
    # DB round trip below, alongside every other malformed-field check.
    epoch_is_valid_type = not isinstance(epoch, bool) and isinstance(epoch, int) and epoch >= 1

    if source_device_state is not True:
        state.logger.warning(
            f"Rejected device_key_sync from {user.username}: sender's "
            f"device is not a bound, AUTHORIZED device."
        )
        error = "Source device is not an authorized, bound device."
    elif not target_device_id or not conversation_id or not wrapped_key or not package_type or not signature_b64:
        error = "Malformed device_key_sync request."
    elif not epoch_is_valid_type:
        state.logger.warning(
            f"Rejected device_key_sync from {user.username}: invalid epoch."
        )
        error = "Invalid epoch."
    else:
        try:
            target_uuid = uuid.UUID(target_device_id)
        except (TypeError, ValueError, AttributeError):
            target_uuid = None

        try:
            conversation_uuid = uuid.UUID(conversation_id)
        except (TypeError, ValueError, AttributeError):
            conversation_uuid = None

        if target_uuid is None:
            error = "Malformed target_device_id."
        elif conversation_uuid is None:
            error = "Malformed conversation_id."
        else:
            source_device_id = state.get_client(client_socket).get("device_id")

            db = SessionLocal()
            try:
                # Step 3 (Phase 16E) -- conversation-authorization
                # audit: authorized-source + authorized-same-account-
                # target is NOT sufficient on its own to prove the
                # AUTHENTICATED account is actually a party to
                # ``conversation_id`` at all. Without this, any two
                # AUTHORIZED devices of one account could sync
                # material under a conversation_id belonging to a
                # conversation neither device's account ever joined
                # (an arbitrary/guessed/redirected id). Checked here,
                # authoritatively, from the server's own membership
                # table -- never from anything the client claims.
                #
                # Direct and group conversations share the exact same
                # underlying membership representation
                # (ConversationMember rows -- see server/client_
                # handler.py's own identical use of get_member_user_
                # ids() for group "chat"/group_key_distribution relay
                # authorization), so one check covers both: since the
                # target device is already required (below) to belong
                # to this SAME account, confirming the authenticated
                # account itself is a member is sufficient for either
                # conversation shape -- there is no separate "is the
                # target device's account a member" check to add, it
                # is the same account.
                conversation_repo = ConversationRepository(db)
                member_ids = conversation_repo.get_member_user_ids(conversation_uuid)

                if user.id not in member_ids:
                    state.logger.warning(
                        f"Rejected device_key_sync from {user.username}: "
                        f"account is not a member of conversation "
                        f"{conversation_id}."
                    )
                    error = "Account is not a member of this conversation."
                    device_repo = source_device = target_device = None
                else:
                    # Step 6 (Phase 16E) -- epoch authority. The
                    # receiver's own monotonic KeyManager.store_key()
                    # protection (max()-based, never rolls back) is a
                    # necessary CLIENT-side defense against a malicious
                    # relay, but is not a substitute for the server
                    # validating what it can authoritatively validate
                    # BEFORE ever relaying anything: Conversation.
                    # current_key_epoch (bumped by reserve_next_epoch(),
                    # the same counter establish_session_key()/group
                    # rotation already use) is the one server-side
                    # authority for "how far this conversation has
                    # legitimately progressed." Mirrors server/client_
                    # handler.py::handle_group_key_distribution()'s own,
                    # pre-existing, identical bound exactly -- reused,
                    # not reinvented -- which already documents why:
                    # without it, membership alone would let a member
                    # stamp a self-chosen, arbitrarily high epoch that
                    # a receiver's own max()-based tracking could never
                    # recover from without a restart.
                    current_epoch, _confirmed_epoch = conversation_repo.get_epoch_state(
                        conversation_uuid
                    )

                    if current_epoch is None or epoch > current_epoch:
                        state.logger.warning(
                            f"Rejected device_key_sync from {user.username}: "
                            f"epoch {epoch} exceeds the reserved epoch for "
                            f"{conversation_id}."
                        )
                        error = "Epoch exceeds the reserved epoch for this conversation."
                        device_repo = source_device = target_device = None
                    else:
                        device_repo = DeviceRepository(db)
                        source_device = device_repo.get_by_id(uuid.UUID(source_device_id))
                        target_device = device_repo.get_by_id(target_uuid)

                if error is not None:
                    pass
                elif target_device is None or target_device.user_id != user.id:
                    error = "Unknown target device for this account."
                elif target_device.state != DEVICE_STATE_AUTHORIZED:
                    state.logger.warning(
                        f"Rejected device_key_sync from {user.username}: "
                        f"target device {target_device_id} is not AUTHORIZED."
                    )
                    error = "Target device is not authorized."
                elif target_device.fingerprint != target_fingerprint:
                    state.logger.warning(
                        f"Rejected device_key_sync: claimed target fingerprint "
                        f"does not match the stored one for {target_device_id}."
                    )
                    error = "Target fingerprint does not match the enrolled device."
                else:
                    try:
                        signature = base64.b64decode(signature_b64, validate=True)
                        source_public_key = base64.b64decode(
                            source_device.ml_dsa_public_key, validate=True
                        )
                    except Exception:  # noqa: BLE001
                        signature = source_public_key = None

                    verified = False
                    if signature is not None:
                        payload = canonical_device_key_sync_payload(
                            user.username, source_device_id, target_device_id,
                            target_fingerprint, conversation_id, epoch, package_type,
                            encapsulation, wrapped_key,
                        )
                        try:
                            verified = verify_device_payload(payload, signature, source_public_key)
                        except (TypeError, ValueError):
                            verified = False

                    if not verified:
                        state.logger.warning(
                            f"Rejected device_key_sync from {user.username}: "
                            f"sync signature did not verify."
                        )
                        error = "Sync signature did not verify."
                    else:
                        from server.broadcaster import send_to_client

                        target_socket = _find_socket_for_bound_device(
                            state, str(user.id), target_device_id
                        )

                        if target_socket is not None:
                            relay_packet = dict(packet)
                            relay_packet.pop("request_id", None)
                            relay_packet["source_device_id"] = source_device_id
                            relay_packet["sender"] = user.username

                            if send_to_client(target_socket, relay_packet):
                                state.logger.info(
                                    f"Relayed device_key_sync for conversation "
                                    f"{conversation_id} from device "
                                    f"{source_device_id} to device {target_device_id}"
                                )
                        else:
                            state.logger.info(
                                f"device_key_sync target device {target_device_id} "
                                f"not currently connected -- dropped (no store-and-forward)."
                            )
            finally:
                db.close()

    response = create_device_key_sync_result_packet(request_id, error is None, error)
    _send(state, client_socket, user, response, "device_key_sync_result")
