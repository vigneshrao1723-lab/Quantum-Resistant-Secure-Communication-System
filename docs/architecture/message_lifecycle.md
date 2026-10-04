# Message Lifecycle (Phase 19.24)

Formal state model for a message, and the honest scope boundary of
what Phase 19.24 actually shipped.

## States

```
CREATED (client-local, pre-send)
   |
   v
SENT ----------------------------------> FAILED (send_chat_message() raised;
   |                                              client-local only, never persisted)
   v
DELIVERED  (relayed live to >=1 of the recipient's connected devices;
   |         server-derived, see server/client_handler.py's
   |         _mark_recipients_delivered() -- unchanged from Phase 19.14/19.23)
   v
READ  (server/client_handler.py::mark_conversation_read(), unchanged)
```

Orthogonal to the above (a message can be edited and/or reacted-to at
any point after SENT; it can be deleted from any state):

```
                    +--> EDITED (edit_version increments, edited_at set;
                    |            content_metadata/ciphertext replaced in
                    |            place -- SAME message_id, never a second
                    |            row)
message row ------->+
                    |
                    +--> DELETED FOR ME (per-viewer only; message_hidden_
                    |     for_user row; every OTHER field on the message
                    |     row is untouched)
                    |
                    +--> DELETED FOR EVERYONE (terminal; ciphertext/
                          content_metadata/message_signature/blob_ref
                          all NULLed; deleted_at/deleted_by set; a
                          DELETED message can no longer be EDITED --
                          see handle_message_edit()'s deleted_at guard)
```

## What "delete" actually means here — an honest statement

**Delete for me** removes the message from this user's own view/
history on every one of their authorized devices (`message_hidden_
for_user`, filtered server-side before history is even returned to
that user — see `handle_message_history_request()`). It never affects
any other participant's copy.

**Delete for everyone** is REAL server-side data minimization, not a
UI flag: `MessageRepository.apply_delete_for_everyone()` NULLs
`ciphertext`/`content_metadata`/`message_signature` on the row (and,
for a blob-stored FILE/IMAGE payload, the referenced
`encrypted_blob_store` file is deleted from disk too, best-effort,
after the DB commit succeeds). What is left in the `messages` table
afterward is exactly: `id`, `sender_id`, `conversation_id`,
`timestamp`, `deleted_at`, `deleted_by` — nothing that can reconstruct
the original plaintext.

**What this does NOT and cannot do** — stated honestly, per this
phase's own mandate ("do not falsely claim... erase... external
backups, screenshots, or plaintext copied outside its control"):

- It cannot un-send a message a recipient already read, screenshotted,
  forwarded, or copied before the deletion happened.
- It cannot reach a recipient's own local decrypted cache/history (a
  client-local concern — each client is expected to purge its own
  rendered/cached copy on receiving the `message_deleted` notification,
  but this project does not audit or enforce that a compromised or
  modified client actually does so).
- It cannot reach a device that is offline at deletion time until that
  device reconnects and reloads history (at which point it correctly
  sees the already-deleted state, per `handle_message_history_request
  ()`'s own filtering — there is no window where a reconnecting client
  can still fetch the pre-deletion plaintext).
- It does not touch database backups, WAL archives, or any other
  infrastructure-level copy of the ciphertext that existed before the
  deletion ran — those are outside this application's control.

## Retry and idempotency

Every live send now carries a client-generated `client_message_id`
(UUID4). A retry of the exact same content, using the exact same id
(the GUI captures it *before* the risky send, specifically so it
survives an exception — see `messaging_event_architecture.md`), is
guaranteed by `MessageRepository.save_message_idempotent()`'s UNIQUE
constraint to create at most one message row, never a duplicate.

## Scope boundary — current status

**Revision note**: an earlier revision of this section, written midway
through Phase 19.24, listed Voice/Video, Wallpapers/Typing/Search/Pin/
Drafts/Mute/Archive/Block/Attachment-menu, real GUI wiring for Reply/
Edit/Delete/Forward/Copy/Reactions, and receive-side ML-DSA
verification of edit/reaction notifications as not implemented. All of
these were implemented, with real UI and passing tests, later in the
same phase. See the 40-item acceptance matrix (`docs/architecture/
security/feature_security_matrix.md`) for the authoritative,
evidence-cited per-feature status. What remains genuinely deferred:

- **Native Android voice/video recording** (part of items 13, 14, 37,
  38) — playback works on Android (voice for real via `SoundLoader`;
  video is an honest Save-only fallback, since this Kivy build has no
  working video backend), but recording does not: `plyer` was tried
  and found to crash on this dev machine's Windows audio backend, and
  a native `pyjnius`-based `MediaRecorder`/Camera2 implementation needs
  real Android hardware to develop and validate, which this
  environment does not have. Desktop (`PySide6.QtMultimedia`) and Web
  (`getUserMedia`/`MediaRecorder`) both record for real. See
  `media_security_architecture.md`'s Voice/Video section.
- **Media gallery is Desktop-only** (item 15) — Mobile/Web gallery
  views were not built this phase.
- **Message-level ML-DSA signature verification on RECEIPT of an
  edit/reaction/delete notification is now implemented on all three
  clients** — `_verify_lifecycle_event_signature()` (`client/
  session.py`, `mobile/session.py`) / `_verifyLifecycleEventSignature()`
  (`web/client/app.js`) call `verify_message_payload()`/
  `verifyMessagePayload()` before trusting a live `message_edited`/
  `reaction_updated` notification's actor/content, closing what an
  earlier revision of this document listed as a known gap.
