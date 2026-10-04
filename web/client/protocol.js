// Phase 15 -- Web Interoperability, Stage 1.
//
// Packet builders mirroring utils/protocol.py field-for-field. No new
// fields are invented; every shape here was read directly from the
// existing Python source (see docs/architecture/web_interoperability.md
// for the exact function this each one mirrors).

export function createLoginRequestPacket(identifier, password) {
  return { type: "login_request", identifier, password };
}

export function createAuthPacket(accessToken) {
  return { type: "auth", access_token: accessToken };
}

// Mirrors utils/protocol.py::create_register_request_packet() exactly --
// same field names, same "register_request" type, same server-side
// validation (AuthenticationService.register_user(), unchanged).
// Mirrors utils/protocol.py's own profile-picture packet builders
// exactly (Phase 19.17C -- Mobile already had a full, working, tested
// client for this; Desktop/Web had none, despite the backend/protocol
// already fully supporting it). Deliberately NOT end-to-end encrypted
// -- a profile picture is meant to be visible to anyone who looks
// this account up, unlike message attachments -- still travels only
// over this connection's TLS/WSS channel.
export function createProfilePictureUploadRequestPacket(imageBase64, contentType) {
  return { type: "profile_picture_upload_request", image_base64: imageBase64, content_type: contentType };
}

export function createProfilePictureRequestPacket(username) {
  return { type: "profile_picture_request", username };
}

// Phase 19.18 -- L-5 closure: mirrors utils/protocol.py's own Inbox
// packet builders exactly (Phase 19.13) -- same already-existing,
// already-tested server-side handlers Desktop/Mobile already use.
export function createVerificationRequestPacket(targetUsername) {
  return { type: "verification_request", target_username: targetUsername };
}

export function createInboxListRequestPacket() {
  return { type: "inbox_list_request" };
}

// Phase 19.23 -- Issue 1: mirrors utils/protocol.py::
// create_conversation_list_request_packet() exactly -- the same
// request Desktop and Android already use to restore the sidebar at
// login. Web never called this at all before this phase (see
// WebClientSession.loadConversations()'s own docstring).
export function createConversationListRequestPacket() {
  return { type: "conversation_list_request" };
}

export function createInboxResponsePacket(notificationId, approve) {
  return { type: "inbox_response", notification_id: notificationId, approve };
}

// Mirrors utils/protocol.py::create_group_remove_member_packet() --
// admin-only, server-enforced (server/client_handler.py::
// handle_group_remove_member() re-derives the admin from the database
// every call, never trusts this packet or whether the UI happened to
// show a Remove button).
export function createGroupRemoveMemberPacket(conversationId, targetUsername) {
  return { type: "group_remove_member", conversation_id: conversationId, target_username: targetUsername };
}

// Mirrors utils/protocol.py's own change_username/change_password
// packet builders exactly -- same already-existing, already-tested
// server-side handlers every other client already uses.
export function createChangeUsernameRequestPacket(newUsername) {
  return { type: "change_username_request", new_username: newUsername };
}

export function createChangePasswordRequestPacket(currentPassword, newPassword, confirmPassword) {
  return {
    type: "change_password_request",
    current_password: currentPassword,
    new_password: newPassword,
    confirm_password: confirmPassword,
  };
}

export function createRegisterRequestPacket(fullName, username, email, phoneNumber, password, confirmPassword) {
  return {
    type: "register_request",
    full_name: fullName,
    username,
    email,
    phone_number: phoneNumber,
    password,
    confirm_password: confirmPassword,
  };
}

export function createPublicKeyPacket(username, algorithm, publicKey, signingPublicKey, identitySignatureB64) {
  return {
    type: "key_exchange",
    operation: "public_key",
    algorithm,
    username,
    public_key: publicKey,
    signing_public_key: signingPublicKey,
    identity_signature: identitySignatureB64,
  };
}

export function createDirectConversationRequestPacket(username) {
  return { type: "direct_conversation_request", username };
}

export function createEpochReservationRequestPacket(conversationId) {
  return { type: "epoch_reservation_request", conversation_id: conversationId };
}

export function createGroupKeyDistributionPacket(
  sender, conversationId, recipient, encapsulationB64, wrappedKeyB64, epoch, groupKeySignatureB64
) {
  return {
    type: "group_key_distribution",
    sender,
    conversation_id: conversationId,
    recipient,
    encapsulation: encapsulationB64 || null,
    wrapped_key: wrappedKeyB64,
    epoch,
    group_key_signature: groupKeySignatureB64,
  };
}

// Phase 18 -- payloadType/contentMetadata generalized (Stage 1 always
// passed the literal "text"/null): the SAME packet shape already
// carries FILE/IMAGE payloads on the desktop (utils/protocol.py::
// create_payload_packet()) -- no new packet type, no new field.
export function createPayloadPacket(
  sender, receiver, conversationId, ciphertext, epoch, messageSignatureB64,
  payloadType, contentMetadata, replyToMessageId, clientMessageId
) {
  const packet = {
    type: "chat",
    sender,
    receiver: receiver || null,
    conversation_id: conversationId || null,
    message: ciphertext,
    payload_type: payloadType || "text",
    content_metadata: contentMetadata || null,
    timestamp: new Date().toISOString(),
    epoch,
    message_signature: messageSignatureB64,
  };
  // Phase 19.24 -- Message Lifecycle Events: optional and additive,
  // mirrors utils/protocol.py::create_payload_packet() exactly.
  if (replyToMessageId) packet.reply_to_message_id = replyToMessageId;
  if (clientMessageId) packet.client_message_id = clientMessageId;
  return packet;
}

// ---------------------------------------------------------------
// Phase 19.24 -- Message Lifecycle Events (edit/delete/reactions).
// Mirrors utils/protocol.py's identical packet constructors exactly
// -- same field names, same "no client-supplied actor field" shape.
// ---------------------------------------------------------------

export function createMessageEditPacket(messageId, ciphertext, contentMetadata, epoch, messageSignatureB64, expectedEditVersion) {
  return {
    type: "message_edit",
    message_id: messageId,
    ciphertext,
    content_metadata: contentMetadata || null,
    epoch,
    message_signature: messageSignatureB64,
    expected_edit_version: expectedEditVersion,
  };
}

export function createMessageDeleteForMePacket(messageId) {
  return { type: "message_delete_for_me", message_id: messageId };
}

export function createMessageDeleteForEveryonePacket(messageId) {
  return { type: "message_delete_for_everyone", message_id: messageId };
}

export function createReactionAddPacket(messageId, ciphertext, epoch, messageSignatureB64) {
  const packet = { type: "reaction_add", message_id: messageId, ciphertext, epoch };
  if (messageSignatureB64) packet.message_signature = messageSignatureB64;
  return packet;
}

export function createReactionRemovePacket(messageId) {
  return { type: "reaction_remove", message_id: messageId };
}

export function createMessagePinPacket(messageId) {
  return { type: "message_pin", message_id: messageId };
}

export function createMessageUnpinPacket(messageId) {
  return { type: "message_unpin", message_id: messageId };
}

// -------------------------------------------------------------
// Phase 18 -- Web UX + Feature Completion.
// -------------------------------------------------------------

export function createGroupCreatePacket(sender, name, memberUsernames) {
  return { type: "group_create", sender, name, members: memberUsernames };
}

export function createMessageHistoryRequestPacket(conversationId, isGroup) {
  return { type: "message_history_request", conversation_id: conversationId, is_group: !!isGroup };
}

// Phase 18.5 -- Step 7 (File/Image History): mirrors utils/protocol.py::
// create_blob_download_request_packet() -- follows up a
// message_history_result entry that reported only a FILE/IMAGE
// message's blob_ref, never its content (Option A -- lazy blob
// delivery). Addressed by message_id, never blob_ref -- the server
// resolves message_id -> conversation_id -> membership itself.
export function createBlobDownloadRequestPacket(messageId) {
  return { type: "blob_download_request", message_id: messageId };
}

export function createReadReceiptPacket(conversationId) {
  return { type: "read_receipt", conversation_id: conversationId };
}

// Phase 19.24 -- Typing Indicator. Mirrors utils/protocol.py::
// create_typing_indicator_packet() exactly -- no sender field; the
// server derives who from the authenticated connection.
export function createTypingIndicatorPacket(conversationId, isTyping) {
  return { type: "typing_indicator", conversation_id: conversationId, is_typing: Boolean(isTyping) };
}

// Phase 19.24 -- Block User. Mirrors utils/protocol.py's identical
// packet constructors exactly -- server-side and persisted, unlike
// Mute/Archive's local-only preferences.
export function createLastSeenRequestPacket(username) {
  return { type: "last_seen_request", username };
}

export function createBlockUserRequestPacket(targetUsername) {
  return { type: "block_user_request", target_username: targetUsername };
}

export function createUnblockUserRequestPacket(targetUsername) {
  return { type: "unblock_user_request", target_username: targetUsername };
}

export function createBlockedUsersListRequestPacket() {
  return { type: "blocked_users_list_request" };
}

// -------------------------------------------------------------
// Phase 18 Step 8 -- Web Multi-Device Identity.
// Mirrors utils/protocol.py's create_device_*_packet() field-for-
// field; no new packet type or field invented.
// -------------------------------------------------------------

export function createDeviceEnrollRequestPacket(
  deviceId, deviceName, platform, kemPublicKey, mlDsaPublicKey, enrollmentSignatureB64
) {
  return {
    type: "device_enroll_request",
    device_id: deviceId,
    device_name: deviceName,
    platform,
    kem_public_key: kemPublicKey,
    ml_dsa_public_key: mlDsaPublicKey,
    enrollment_signature: enrollmentSignatureB64,
  };
}

export function createDeviceListRequestPacket() {
  return { type: "device_list_request" };
}

export function createDeviceAuthorizePacket(
  targetDeviceId, targetFingerprint, authorizerDeviceId, authorizationSignatureB64
) {
  return {
    type: "device_authorize",
    target_device_id: targetDeviceId,
    target_fingerprint: targetFingerprint,
    authorizer_device_id: authorizerDeviceId,
    authorization_signature: authorizationSignatureB64,
  };
}

export function createDeviceRevokePacket(targetDeviceId, revokerDeviceId, revocationSignatureB64) {
  return {
    type: "device_revoke",
    target_device_id: targetDeviceId,
    revoker_device_id: revokerDeviceId,
    revocation_signature: revocationSignatureB64,
  };
}

export function createDeviceSessionBindPacket(deviceId, sessionNonce, bindingSignatureB64) {
  return {
    type: "device_session_bind",
    device_id: deviceId,
    session_nonce: sessionNonce,
    binding_signature: bindingSignatureB64,
  };
}

export function createDeviceKeySyncPacket(
  targetDeviceId, targetFingerprint, conversationId, epoch,
  packageType, encapsulationB64, wrappedKeyB64, syncSignatureB64
) {
  return {
    type: "device_key_sync",
    target_device_id: targetDeviceId,
    target_fingerprint: targetFingerprint,
    conversation_id: conversationId,
    epoch,
    package_type: packageType,
    encapsulation: encapsulationB64 || null,
    wrapped_key: wrappedKeyB64,
    sync_signature: syncSignatureB64,
  };
}
