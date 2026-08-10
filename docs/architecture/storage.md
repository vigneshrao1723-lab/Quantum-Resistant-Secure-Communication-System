# Message Storage Architecture

Introduced in Phase 6 (Secure File & Image Transfer Infrastructure). This
document explains where a message's ciphertext actually lives, why there
are two places it can live, and what a future payload type must do to fit
into this without changing the storage layer itself.

## Two storage paths for one column pair

Every persisted message (`database/models/message.py`) carries encrypted
content in exactly one of two places:

1. **Inline** — `messages.ciphertext` holds the ciphertext directly.
2. **Blob storage** — the ciphertext is written to disk via
   `storage/encrypted_blob_store.py`, and `messages.blob_ref` holds the
   opaque reference needed to retrieve it.

Which path a message takes is decided once, in one place:
`domain/payload_type.py`'s `BLOB_STORAGE_PAYLOAD_TYPES`, consumed by a
single conditional in `persist_message()`
(`server/client_handler.py`). Nothing else in the system — not
`MessageRepository`, not `encrypted_blob_store.py`, not any client code —
knows this decision exists.

## Why text stays inline

Chat text is small (realistically well under a few KB per message) and is
read constantly — every conversation history load walks the `ciphertext`
column directly through the database. Keeping it inline means:

- No filesystem I/O on the read path that renders a conversation.
- No orphaned-file bookkeeping for the overwhelmingly common case.
- Zero change to a code path that predates this architecture: `TEXT`
  ciphertext is produced by `payload/text_adapter.py` specifically to stay
  byte-for-byte identical to what `AESCipher.encrypt()` has always
  produced, and it is stored exactly as it always has been.

`PayloadType.TEXT` is therefore the one payload type not present in
`BLOB_STORAGE_PAYLOAD_TYPES`.

## Why files/images use blob storage

Binary payloads (`PayloadType.FILE`, `PayloadType.IMAGE`) are not
bounded the way a chat message is — a document or photo can be
megabytes. Storing that inline would:

- Bloat every row and every query that touches `messages`, including ones
  that have nothing to do with the file (history scans, conversation
  previews).
- Push large binary data through PostgreSQL's TOAST mechanism for no
  benefit, when a plain file on disk does the same job with less
  overhead.

So `persist_message()` writes their ciphertext bytes to
`storage/encrypted_blob_store.py` instead, and records only a reference.
The blob store itself never sees `payload_type`, filename, MIME type, or
anything else describing *what* the content is — it stores and returns
opaque bytes and references. That differentiation lives entirely in
`PayloadType`, `content_metadata`, and the relevant `PayloadAdapter` (see
"Integrating a future payload type" below). The server still never
decrypts anything either way — it stores and relays ciphertext, inline or
blobbed, with the same zero-knowledge guarantee.

## Lifecycle of `blob_ref`

1. **Write.** A client encrypts binary content through a
   `PayloadAdapter` (currently `payload/file_adapter.py`'s
   `FilePayloadAdapter`, shared by `FILE` and `IMAGE`), producing a
   `PayloadEnvelope` whose `ciphertext` is a base64-wrapped AES
   ciphertext string — exactly like any other payload, just via
   `crypto/payload_cipher.py`'s generic strategy rather than the
   text-compatibility one.
2. **Route.** The envelope reaches `persist_message()` inside a `"chat"`
   packet, same as a text message. `persist_message()` checks
   `envelope.payload_type in BLOB_STORAGE_PAYLOAD_TYPES`. For `FILE`/
   `IMAGE`, it calls `encrypted_blob_store.store_blob()` with the
   ciphertext bytes and gets back a reference (today: a UUID4 hex string
   that is also the on-disk filename under `FILE_STORAGE_ROOT`).
3. **Persist.** The `Message` row is saved with `ciphertext=None` and
   `blob_ref=<reference>`.
4. **Read.** A future retrieval path (not yet implemented — this phase is
   infrastructure only) reads `message.blob_ref`, calls
   `encrypted_blob_store.load_blob(blob_ref)`, and relays the bytes back
   to a client for decryption. No payload-type branching is needed here
   either: the presence of `blob_ref` alone says "fetch from blob
   storage."
5. **Delete.** `encrypted_blob_store.delete_blob()` exists for this
   lifecycle stage (e.g. message deletion) but has no caller yet in this
   phase — deferred until a message-deletion feature needs it.

`blob_ref` is deliberately a plain nullable string column, not a foreign
key to another table: a blob reference is a single optional pointer with
no independent relational data of its own (no separate lifecycle, no
separate queries), so a dedicated table would add structure without a
reason to.

**`blob_ref` is an implementation detail of the current backend, not a
generic abstraction.** It assumes one storage backend: the local
filesystem under `FILE_STORAGE_ROOT`. If a future phase introduces
additional backends (cloud object storage, distributed storage, a
different inline strategy for a new small type, ...), `blob_ref` is the
field that evolves — for example, gaining a backend discriminator, or
becoming a structured reference instead of a bare string. That evolution
stays entirely within the storage layer. `PayloadType`, `content_metadata`,
and `PayloadAdapter` do not need to know how or where a `blob_ref`'s
target is actually stored, and nothing above the storage layer needs to
change when it does.

## Integrating a future payload type

A future binary payload type (voice, video, ...) that wants blob storage
touches exactly these places:

1. **`domain/payload_type.py`** — add the enum member, and add it to
   `BLOB_STORAGE_PAYLOAD_TYPES` in the same edit if it should be
   blob-stored. This is the one, colocated decision point; nothing
   downstream needs to change to support a new blob-stored type.
2. **`domain/payload_serializer.py`** — only if the new type needs
   something other than a raw bytes passthrough (`FILE`/`IMAGE` already
   share the existing binary-passthrough branch; a genuinely novel
   encoding would add its own branch here).
3. **A `PayloadAdapter`** (`payload/`) — reuse `FilePayloadAdapter` if the
   type is "arbitrary binary content, no special wire format" (as
   `FILE`/`IMAGE` are); write a new adapter only if the type needs a
   distinct encryption strategy.
4. **`client/session.py`** — register the adapter instance in
   `self._payload_adapters` under the new `PayloadType`. No other method
   in `ClientSession` changes.

A type that should stay inline (e.g. a short structured marker, a
reaction) simply does **not** get added to `BLOB_STORAGE_PAYLOAD_TYPES` —
no other step changes. `server/client_handler.py` and
`storage/encrypted_blob_store.py` are never edited for a new payload
type, blob-stored or not.

## Invariants

Every `Message` row satisfies exactly one of the following, always:

| | `ciphertext` | `blob_ref` |
|---|---|---|
| **Inline payload** (e.g. `TEXT`) | `!= NULL` | `== NULL` |
| **Blob payload** (e.g. `FILE`, `IMAGE`) | `== NULL` | `!= NULL` |

There is no valid row where both are `NULL` (content stored nowhere) or
both are set (ambiguous source of truth). `persist_message()` is the only
write path for `Message.ciphertext`/`Message.blob_ref` and enforces this
by construction — the two are always assigned from the same
`if payload_type in BLOB_STORAGE_PAYLOAD_TYPES` branch, never
independently. Any code reading a `Message` row can rely on this without
re-deriving it from `payload_type`: check `blob_ref is not None` to know
whether to fetch from blob storage, not the payload type.
