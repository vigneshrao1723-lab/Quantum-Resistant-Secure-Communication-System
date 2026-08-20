"""
Locally persisted, password-encrypted conversation key store (BUG 1).

Why this exists
---------------
Message history is server-authoritative and survives restarts intact --
the rows, the ciphertext, the blobs and the metadata all come back.
What did not come back was the ability to READ any of it: conversation
AES keys lived only in KeyManager's in-memory dict, and every launch
built a fresh KeyManager. The server is deliberately blind to those
keys, and peer recovery can only relay what some other client still
holds in RAM -- so once every participant had closed the application,
the keys were gone from the whole system and history became
permanently undecryptable.

This module persists exactly those keys, encrypted at rest under a key
derived from the user's own password. It changes nothing about the
server, the protocol, the database, or the message flow.

What is stored, and what is not
-------------------------------
Only ``{conversation_id: {epoch: key_bytes}}`` -- the minimum required
to read history.

The client's long-term Kyber/RSA keypair is deliberately NOT persisted.
It is used for key EXCHANGE, never to decrypt a stored message, so
keeping it is not needed to read history; and persisting it would make
this client's public key stable across restarts, which is a change to
the identity/trust model (see D6.4) rather than a history fix. Fewer
secrets on disk is also simply better.

Security properties
-------------------
* Argon2id (argon2-cffi's raw KDF -- the same library the server
  already uses to hash passwords) derives the storage key from the
  password. Never SHA-256(password), never the password itself.
* A 16-byte salt is generated randomly per store and written in the
  file header, so two users -- or the same password on two machines --
  never derive the same key.
* The payload is encrypted with the project's existing AES-256-GCM
  (crypto/aes.py), which generates a fresh random 12-byte nonce per
  encryption and prepends nonce + tag. No nonce is ever reused or
  derived deterministically.
* Authentication is enforced by GCM's tag. A wrong password, a
  corrupted file, or a tampered file all fail closed with
  KeyStoreLocked -- they never return partial or attacker-chosen keys.
* A failed unlock never deletes or overwrites the existing file, so a
  password typo cannot destroy a user's history.

The KDF parameters are recorded in the header, so they can be raised
later without making existing stores unreadable.

Locking
-------
This store's lock is a LEAF lock: it guards the file write and nothing
else, and no code path inside it acquires any other lock or calls back
into KeyManager. Callers may hold KeyManager's lock when they call
save(); this store never acquires KeyManager's.

That direction is the whole point. An earlier version offered a
save_from(provider) that took this lock and then invoked a provider
which took KeyManager's -- giving the lock graph a STORE -> KM edge to
sit alongside the KM -> STORE edge created by store_key()'s on_change
callback. No deadlock was reachable, but only because every caller
happened to already hold KeyManager's lock; a single future caller
(a flush on logout, a periodic save, a GUI action) would have closed
the cycle silently. The edge is now gone by construction rather than
by convention.

Atomicity of "snapshot then write" is preserved by the CALLER: the
session persists from inside KeyManager.store_key()'s lock, so no
other thread can add an epoch between the export and the write.

Threat model, stated honestly
-----------------------------
This deliberately trades one property for another. Before, keys
evaporated when the process exited, which gave a kind of at-rest
protection by accident. Now they persist, so an attacker who obtains
BOTH the file AND the user's password can read that user's history.
That is why the file is never written in plaintext and why the KDF is
a real password-hashing function rather than a bare digest. Nothing
about the server's blindness changes: it still holds no keys and still
cannot decrypt anything.
"""

import base64
import json
import os
import secrets
import threading
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw

from config import (
    KEY_STORE_ARGON2_MEMORY_COST,
    KEY_STORE_ARGON2_PARALLELISM,
    KEY_STORE_ARGON2_TIME_COST,
    KEY_STORE_DIR,
)
from crypto.aes import AESCipher

# Bumped only if the on-disk layout changes incompatibly. Readers
# refuse a version they do not understand rather than guessing.
KEY_STORE_VERSION = 1

SALT_SIZE = 16
DERIVED_KEY_SIZE = 32


class KeyStoreError(Exception):
    """Base class for key-store failures."""


class KeyStoreLocked(KeyStoreError):
    """
    The store exists but could not be authenticated and decrypted --
    a wrong password, a corrupted file, or a tampered one.

    Deliberately does not distinguish between those cases: the
    authentication tag cannot tell them apart, and guessing would
    either mislead the user or leak whether a password was close.
    """


def _derive_key(password, salt, time_cost, memory_cost, parallelism):
    """Argon2id, password -> 32-byte storage key."""

    if not isinstance(password, str) or not password:
        raise KeyStoreError("A password is required to unlock the key store.")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=DERIVED_KEY_SIZE,
        type=Type.ID,
    )


class SecureKeyStore:
    """
    One user's encrypted conversation-key file.

    Lifecycle: unlock() after the server has authenticated the user
    (so the password is known to be correct and a user_id exists),
    save() whenever a key is added, lock() on logout.
    """

    def __init__(self, user_id, storage_dir=None):
        if not user_id:
            raise KeyStoreError("A user id is required to open a key store.")

        self._user_id = str(user_id)
        self._dir = Path(storage_dir) if storage_dir else Path(KEY_STORE_DIR)
        self._derived_key = None
        self._salt = None
        self._params = None

        # BUG 1 -- serialises the whole snapshot-and-write sequence.
        # Keys arrive on several threads (receiver, key recovery, GUI),
        # and a save built from a stale snapshot would silently drop
        # epochs from the file -- reintroducing exactly the
        # history-loss this store exists to prevent.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------

    @property
    def path(self):
        """Per-user file. Keys belong to one account, and two accounts
        sharing a machine must never share a store."""

        return self._dir / f"{self._user_id}.keystore"

    @property
    def is_unlocked(self):
        return self._derived_key is not None

    def exists(self):
        return self.path.exists()

    # ------------------------------------------------------------------

    def unlock(self, password):
        """
        Derive the storage key and return the stored conversation keys
        as ``{conversation_id: {epoch: key_bytes}}``.

        A missing file is a fresh local installation, not an error: a
        new salt is generated, an empty mapping is returned, and normal
        login proceeds. Existing peer recovery remains the fallback for
        anything this client has never held.

        Raises KeyStoreLocked if a file exists but cannot be
        authenticated. The file is left exactly as it was.
        """

        if not self.exists():
            self._salt = secrets.token_bytes(SALT_SIZE)
            self._params = {
                "time_cost": KEY_STORE_ARGON2_TIME_COST,
                "memory_cost": KEY_STORE_ARGON2_MEMORY_COST,
                "parallelism": KEY_STORE_ARGON2_PARALLELISM,
            }
            self._derived_key = _derive_key(password, self._salt, **self._params)
            return {}

        try:
            header = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise KeyStoreLocked(
                f"The local key store could not be read: {error}"
            ) from error

        if header.get("version") != KEY_STORE_VERSION:
            raise KeyStoreLocked(
                f"Unsupported key store version {header.get('version')!r}."
            )

        try:
            salt = base64.b64decode(header["salt"], validate=True)
            params = {
                "time_cost": int(header["time_cost"]),
                "memory_cost": int(header["memory_cost"]),
                "parallelism": int(header["parallelism"]),
            }
            payload = header["payload"]
        except (KeyError, TypeError, ValueError) as error:
            raise KeyStoreLocked(
                "The local key store header is malformed."
            ) from error

        derived = _derive_key(password, salt, **params)

        try:
            plaintext = AESCipher(derived).decrypt(payload)
        except ValueError as error:
            # GCM tag mismatch: wrong password, corruption, or
            # tampering. Fail closed and leave the file untouched.
            raise KeyStoreLocked(
                "The local key store could not be unlocked. The password may "
                "be wrong, or the file may be corrupted."
            ) from error

        try:
            document = json.loads(plaintext)
            bound = document["header"]
            raw = document["keys"]
        except (KeyError, TypeError, ValueError) as error:
            raise KeyStoreLocked(
                "The local key store contents are malformed."
            ) from error

        # The plaintext header is only trustworthy if it matches the
        # copy sealed inside the authenticated payload. A mismatch
        # means the file was edited after it was written.
        expected = {"version": KEY_STORE_VERSION, "kdf": "argon2id", **params}

        if bound != expected:
            raise KeyStoreLocked(
                "The local key store header does not match its authenticated "
                "contents; the file has been modified."
            )

        self._salt = salt
        self._params = params
        self._derived_key = derived

        return self._decode(raw)

    def save(self, conversation_keys):
        """
        Encrypt and write the given ``{conversation_id: {epoch: key}}``.

        Written to a temporary file and then moved into place, so an
        interrupted write cannot leave a half-written store that would
        lock the user out of their own history.
        """

        # Only the write is guarded. This lock is deliberately a LEAF:
        # nothing reachable from inside it ever acquires another lock,
        # and in particular it never calls back into KeyManager. That
        # is what keeps the lock-order graph acyclic -- see the
        # "Locking" note in this module's docstring.
        with self._lock:
            self._write(conversation_keys)

    def _write(self, conversation_keys):
        """Encrypt and atomically replace the file. Callers hold the
        lock."""

        if not self.is_unlocked:
            raise KeyStoreError("The key store must be unlocked before saving.")

        # The header is necessarily plaintext -- the salt and KDF cost
        # are needed to derive the key before anything can be
        # decrypted. It is therefore also bound INTO the authenticated
        # payload, and unlock() requires the two copies to agree. An
        # attacker who edits the header (weakening the KDF cost,
        # claiming a different version) changes only the outer copy, so
        # the mismatch is detected and the unlock fails closed.
        #
        # Done this way rather than as GCM associated data because
        # crypto/aes.py's AESCipher -- shared with every message in the
        # system -- exposes no AAD parameter. Widening that shared
        # primitive for this one caller would be a much larger and
        # riskier change than the protection warrants, and this
        # achieves the same property.
        bound = {
            "version": KEY_STORE_VERSION,
            "kdf": "argon2id",
            **self._params,
        }

        payload = AESCipher(self._derived_key).encrypt(
            json.dumps({"header": bound, "keys": self._encode(conversation_keys)})
        )

        document = {
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "payload": payload,
            **bound,
        }

        self._dir.mkdir(parents=True, exist_ok=True)

        temporary = self.path.with_suffix(".keystore.tmp")
        temporary.write_text(json.dumps(document), encoding="utf-8")
        os.replace(temporary, self.path)

    def lock(self):
        """Drop the derived key. The file is deliberately left in
        place -- logging out must not cost the user their history."""

        self._derived_key = None
        self._salt = None
        self._params = None

    # ------------------------------------------------------------------

    @staticmethod
    def _encode(conversation_keys):
        return {
            str(conversation_id): {
                str(epoch): base64.b64encode(key).decode("ascii")
                for epoch, key in epochs.items()
            }
            for conversation_id, epochs in (conversation_keys or {}).items()
        }

    @staticmethod
    def _decode(raw):
        decoded = {}

        for conversation_id, epochs in (raw or {}).items():
            decoded[str(conversation_id)] = {
                int(epoch): base64.b64decode(value)
                for epoch, value in (epochs or {}).items()
            }

        return decoded
