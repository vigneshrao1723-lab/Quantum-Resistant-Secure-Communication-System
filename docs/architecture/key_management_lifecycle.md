# Key Management Lifecycle

Written Phase 19.19, closing the documentation gap Limitation L-8
named ("G. Key management lifecycle — Thin"). Traces every key this
system generates, wraps, persists, rotates, or destroys, end to end,
citing the actual code at each step.

## 1. The two key categories

| Category | Examples | Lives in |
|---|---|---|
| **Identity keys** — one per device, long-lived | ML-KEM-768 keypair, ML-DSA-65 keypair | `crypto/key_manager.py::KeyManager`, persisted via `storage/secure_key_store.py::SecureKeyStore` |
| **Conversation keys** — one per (conversation, epoch), rotated | AES-256-GCM symmetric key | `KeyManager._conversation_keys`, also persisted via `SecureKeyStore` |

The server never holds either category — see `docs/architecture/
server_architecture.md` §1. Everything below is entirely client-side
(Desktop `client/session.py`, Android `mobile/session.py` — the same
`KeyManager`/`SecureKeyStore` classes, imported unmodified by both;
Web ports the equivalent logic to JavaScript, `web/client/crypto.js`/
`storage.js`).

## 2. Identity key generation

`KeyManager.load_or_create_kyber_keypair(key_store)` / `load_or_create_
signing_keypair(key_store)`: on first-ever run for an installation,
generates a fresh ML-KEM-768 keypair and ML-DSA-65 keypair locally
(`crypto/kyber.py`, `crypto/ml_dsa.py` — real post-quantum primitives,
not simulated), then persists both through `key_store.save_own_
kyber_keypair()`/`save_own_signing_keypair()`. On every later run, the
SAME method reads the persisted keypair back instead of generating a
new one — proven by `tests/test_own_kyber_keypair_persistence.py`/
`test_own_signing_keypair_persistence.py` constructing a genuinely
fresh `ClientSession` against the same on-disk store. This is what
gives a device a stable identity across restarts — a device's
fingerprint (`crypto/key_manager.py::fingerprint_combined_identity()`)
never changes unless the local store is deleted or a NEW device
enrolls (Phase 16, `docs/architecture/multi_device_identity.md`).

**The private half never leaves the device.** `ClientSession.send_
public_key()` transmits only `KeyManager.public_key` (the KEM
encapsulation key) and the ML-DSA public verification key — never the
private/secret halves, over the wire, ever.

## 3. Peer key observation (not yet trust)

`KeyManager.add_public_key(username, public_key)` caches a peer's
CURRENT public key, purely for encrypting a session/group key TO
them later. Observing a key is never the same as verifying it — see
`storage/secure_key_store.py`'s own `PEER_STATE_UNVERIFIED`/
`PEER_STATE_VERIFIED`/`KEY_CHANGED` state machine and `docs/
architecture/security/security_architecture.md`'s peer-verification
model. `KeyManager` itself carries no verification-state concept at
all — that lives entirely in `SecureKeyStore`/`ClientSession`'s own
trust layer, deliberately kept separate from "what key would I
encrypt to right now."

## 4. Conversation key establishment

**Direct conversations**: `KeyManager.encapsulate_session_key(username)`
performs a real ML-KEM-768 encapsulation against the peer's currently
observed public key, producing a shared AES-256-GCM key; the receiving
side's `decapsulate_session_key()` recovers the identical key from the
encapsulation ciphertext. `store_key(conversation_id, key, epoch=1)`
records it.

**Group conversations**: the group's admin/creator generates one
AES-256-GCM key locally (never from any member's individual KEM
material) and calls `wrap_key_for_member(username, key_bytes)` once
per member — ML-KEM encapsulation-then-AES-wrap ("KEM-then-DEM"),
the SAME composition device-to-device sync (§6 below) reuses
unmodified. Each member's `unwrap_received_key()` recovers the same
group key.

## 5. Epoch model and rotation

`KeyManager.store_key(conversation_id, key, epoch=1)`'s epoch counter
is **strictly monotonic per conversation**:
`self._current_epoch[conversation_id] = max(current, epoch)` — no code
path, including device-to-device sync, can ever move it backward
(proven directly by `tests/test_device_key_sync_hardening.py::
test_stale_epoch_sync_cannot_roll_back_already_advanced_local_epoch`
and `tests/test_key_lifecycle_stale_state.py`). A group's epoch
advances on membership change (a member added or removed — Phase 7),
each new epoch getting its own freshly generated key, delivered the
same wrap-and-send way as epoch 1. The SERVER is authoritative only
for *which epoch number is next* (`ConversationRepository.reserve_
next_epoch()`, `server_architecture.md` §4) — it never sees or
influences the key material itself, only prevents two clients racing
to claim the same epoch number.

`store_key()` is idempotent per exact `(conversation_id, epoch)`: a
second call with the identical epoch and key is a safe no-op, which is
what makes exact-replay-of-a-sync-package safe by construction (Phase
16D, `multi_device_identity.md`'s "Exact replay semantics" section) —
no separate replay-detection code was needed.

## 6. Cross-device synchronization

An account's second (or later) device does not independently
re-establish keys for a conversation it did not create the epoch for —
`ClientSession._resolve_direct_conversation_id()` explicitly refuses a
conversation with yourself, so a naive "just call establish_session_
key() again" would collide with the epoch an already-conversing
sibling device holds. Instead, `sync_conversation_key_to_device()`
(Phase 16C) has an ALREADY-authorized sibling device wrap the EXISTING
key (same KEM-then-DEM primitive as §4) and deliver it directly,
device-to-device, addressed by `device_id` rather than username. See
`multi_device_identity.md`'s "Cross-device key distribution" and
"Phase 16C" sections for the full protocol and its security model.

## 7. Persistence: `SecureKeyStore`

One encrypted file per local installation (`storage/secure_key_store.py`),
holding: the device's own KEM/ML-DSA keypairs, its `device_id`, every
conversation key at every epoch it has ever held, and peer-verification
records (fingerprint + state + signing key, Phase 19.19's Android
persistence work — see `multi_device_identity.md`'s own Phase 19.19
section).

- **Key derivation**: Argon2id (`argon2.low_level.hash_secret_raw`,
  `Type.ID`) turns the user's password into a 32-byte storage key —
  never a bare digest, never the password itself. A random 16-byte
  salt per store means two users, or the same password on two
  machines, never derive the same key. KDF cost parameters are
  recorded in the file header so they can be raised later without
  breaking existing stores.
- **Encryption**: the whole payload is AES-256-GCM (`crypto/aes.py`,
  the same cipher every message uses), fresh random 12-byte nonce per
  write, nonce+tag prepended. GCM's own tag is what makes a wrong
  password, a corrupted file, and a tampered file all fail the same
  way: `KeyStoreLocked`, never a partial or attacker-influenced read.
- **Failure is non-destructive**: a failed unlock (wrong password,
  corruption) never deletes or overwrites the existing file — a
  password typo cannot destroy a user's history.
- **Locking discipline**: `SecureKeyStore`'s own lock is a leaf lock
  (guards only the file write, never calls back into `KeyManager`);
  `KeyManager.store_key()`'s `on_change` callback holds `KeyManager`'s
  own lock when it calls `save()`, so the dependency graph is
  one-directional (`KeyManager -> SecureKeyStore`, never the reverse)
  by construction, not by convention — see the module's own
  "Locking" docstring for the specific cyclic-lock bug this shape was
  deliberately built to make unreachable.

## 8. Destruction / revocation semantics

**Revocation is prospective, never retroactive erasure.** A device or
peer that is revoked/un-verified going forward cannot receive NEW key
material, but nothing in this system (or any system where recipients
hold their own decryption keys) can reach into an already-revoked
device's local `SecureKeyStore` and remove a key it legitimately
received before revocation — stated explicitly, and tested
(`multi_device_identity.md`'s "Revocation semantics" sections, Phase
16B and 16C). `remove_key(conversation_id)` exists for a client's own,
local, voluntary cleanup (e.g. leaving a group) — it has no
server-side or cross-device counterpart.

## 9. Cross-client consistency

Desktop and Android import the literal same `crypto.key_manager`/
`storage.secure_key_store` modules — there is structurally no way for
their key lifecycle to drift, since it is not reimplemented, only
imported. Web (`web/client/crypto.js`, `storage.js`) is a from-scratch
JavaScript port of the same ML-KEM/ML-DSA/AES-GCM/Argon2id-equivalent
operations and the same encrypted-local-storage shape (IndexedDB
instead of a filesystem file) — proven byte-compatible with the Python
implementation by `tests/test_web_client_crypto_interop.py`, not
assumed.
