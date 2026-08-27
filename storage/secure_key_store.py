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
``{conversation_id: {epoch: key_bytes}}`` -- the minimum required to
read history -- plus, since Server-Untrusted Identity Verification
Stage 1, one small additional section: a per-peer public-key
fingerprint and verification state (PEER_STATE_UNVERIFIED or
PEER_STATE_VERIFIED). This is presentation/comparison metadata, not
key material used for encryption -- it lets a peer's identity claim be
checked against what THIS user has previously observed or explicitly
verified, independent of anything the server currently asserts. It is
stored in the same encrypted file, under the same password-derived
key, for the same reason the conversation keys are: it must survive a
restart, and it must never touch the server or the database.

Server-Untrusted Identity Verification, Stage 2.5 adds one more small
section: this local user's OWN Kyber (ML-KEM-768) keypair -- both
halves, public and private. Originally (D6.4) this was deliberately
NOT persisted, on the reasoning that it is used for key EXCHANGE, not
to decrypt stored messages, so keeping it was not needed to read
history, and persisting it would make this client's public key stable
across restarts -- a change to the identity/trust model rather than a
history fix.

That reasoning held only as long as key stability across restarts was
out of scope. Stage 1/2 (peer-key fingerprinting and substitution
detection) made it in scope: KeyManager.__init__() regenerates a fresh
ML-KEM keypair on every login, so without this section a user's
"legitimate key rotation" and "a malicious server substituting a
different key" become the same event on every single relogin --
indistinguishable, and happening constantly, which would make Stage
2's already-proven protection either unusable or ignored. Persisting
this local user's own keypair here -- reusing exactly the same
encrypted-at-rest, password-derived-key infrastructure already
protecting conversation keys and peer fingerprints, not a new
mechanism -- is what makes a VERIFIED peer fingerprint (of THIS user,
from someone else's perspective) mean anything across more than one
login. It remains algorithm-specific to Kyber: RSA (kept only for
classical-vs-post-quantum comparison) still generates a fresh keypair
every session, unchanged -- see KeyManager.load_or_create_kyber_keypair().

The private half never leaves this file: it is written only into this
same encrypted payload, is never sent to the server (see
ClientSession.send_public_key(), which only ever transmits
KeyManager.public_key -- the encapsulation/public half), and this
module still changes nothing about the server, the protocol, the
database, or the message flow. Fewer secrets on disk was, and remains,
simply better where it doesn't cost anything -- this is the one place
persisting a secret buys a real security property Stage 1/2 cannot
provide without it.

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
from crypto.kyber import ML_KEM_768_PRIVATE_KEY_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES

# Bumped only if the on-disk layout changes incompatibly. Readers
# refuse a version they do not understand rather than guessing.
KEY_STORE_VERSION = 1

SALT_SIZE = 16
DERIVED_KEY_SIZE = 32

# Peer public-key verification state (Server-Untrusted Identity
# Verification, Stage 1). A peer is UNVERIFIED the moment any key is
# first observed for them -- never automatically VERIFIED, since
# nothing about merely receiving a key (from the untrusted server)
# establishes that it genuinely belongs to that peer. Only an
# explicit future verification action (a later stage, not yet
# implemented) may ever produce VERIFIED.
PEER_STATE_UNVERIFIED = "UNVERIFIED"
PEER_STATE_VERIFIED = "VERIFIED"


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

        # Peer verification state, {username: {"fingerprint": str,
        # "state": PEER_STATE_UNVERIFIED | PEER_STATE_VERIFIED}} --
        # populated by unlock(), mutated only through
        # record_observed_peer_fingerprint()/verify_peer_fingerprint().
        self._peers = {}

        # This local user's own Kyber (ML-KEM-768) keypair (Server-
        # Untrusted Identity Verification, Stage 2.5):
        # (encapsulation_key, decapsulation_key), both raw bytes, or
        # None if never persisted -- populated by unlock(), mutated
        # only through save_own_kyber_keypair().
        self._own_kyber_keypair = None

        # The most recently known {conversation_id: {epoch: key_bytes}}
        # snapshot -- set by unlock() and by save(). Needed so the
        # peer-verification methods below, which have no conversation-
        # key snapshot of their own to write, can still persist through
        # the same single-file _write() without ever having to guess
        # at or discard the conversation keys already on disk.
        self._last_keys_snapshot = {}

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
            self._peers = {}
            self._own_kyber_keypair = None
            self._last_keys_snapshot = {}
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
            # Absent, not required: every store written before Stage 1
            # existed has no "peers" section at all, and must unlock
            # exactly as it always did -- an empty peer-verification
            # state is the true, honest description of "never recorded
            # any peer fingerprints", not a malformed file.
            peers_raw = document.get("peers", {})
            # Absent, not required, same reasoning: every store written
            # before Stage 2.5 existed has no "own_kyber_keypair"
            # section -- that honestly means "no keypair persisted
            # yet", not a malformed file (Server-Untrusted Identity
            # Verification, Stage 2.5). KeyManager.
            # load_or_create_kyber_keypair() treats None exactly the
            # same whether it comes from a pre-Stage-2.5 store or a
            # brand-new one: generate once, persist from here on.
            own_kyber_keypair_raw = document.get("own_kyber_keypair")
        except (KeyError, TypeError, ValueError) as error:
            raise KeyStoreLocked(
                "The local key store contents are malformed."
            ) from error

        try:
            decoded_peers = self._decode_peers(peers_raw)
        except (KeyError, TypeError, ValueError) as error:
            raise KeyStoreLocked(
                "The local key store's peer verification data is malformed."
            ) from error

        try:
            decoded_own_kyber_keypair = self._decode_own_kyber_keypair(
                own_kyber_keypair_raw
            )
        except (KeyError, TypeError, ValueError) as error:
            # Fail closed (Server-Untrusted Identity Verification,
            # Stage 2.5): this section is only ever absent (handled
            # above) or exactly what this module itself previously
            # wrote, since it lives inside the same GCM-authenticated
            # payload as everything else here -- reaching this branch
            # means the authenticated contents are structurally wrong,
            # not that an attacker forged them (a forged payload would
            # already have failed the GCM tag check above). Refusing
            # the whole store rather than silently generating a
            # replacement keypair is deliberate: a replacement would
            # be a NEW identity that any peer who already VERIFIED this
            # user's old fingerprint would see as an unexplained
            # KEY_CHANGED, with no way to tell it apart from an actual
            # attack. The same fail-closed handling already applies to
            # a malformed "peers" section above, for the same reason.
            raise KeyStoreLocked(
                "The local key store's own Kyber keypair data is malformed."
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
        self._peers = decoded_peers
        self._own_kyber_keypair = decoded_own_kyber_keypair

        decoded_keys = self._decode(raw)
        self._last_keys_snapshot = decoded_keys

        return decoded_keys

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
            self._last_keys_snapshot = conversation_keys
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
            json.dumps({
                "header": bound,
                "keys": self._encode(conversation_keys),
                "peers": self._encode_peers(self._peers),
                "own_kyber_keypair": self._encode_own_kyber_keypair(
                    self._own_kyber_keypair
                ),
            })
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
        self._peers = {}
        self._own_kyber_keypair = None
        self._last_keys_snapshot = {}

    # ------------------------------------------------------------------
    # Peer public-key verification (Server-Untrusted Identity
    # Verification, Stage 1)
    # ------------------------------------------------------------------

    def get_peer_verification(self, username):
        """
        Return {"fingerprint": str, "state": PEER_STATE_*} for
        ``username``, or None if no fingerprint has ever been
        observed for them.
        """

        entry = self._peers.get(username)

        if entry is None:
            return None

        return dict(entry)

    def has_verified_fingerprint(self, username):
        """True only if this peer has an explicitly VERIFIED entry --
        never true merely because a key was observed."""

        entry = self._peers.get(username)

        return entry is not None and entry["state"] == PEER_STATE_VERIFIED

    def fingerprint_matches_verified(self, username, fingerprint):
        """
        True if ``fingerprint`` matches the VERIFIED fingerprint on
        file for ``username``. False both when it does not match AND
        when there is no verified entry at all to match against --
        callers that need to distinguish "no verified entry" from "a
        mismatch" should call has_verified_fingerprint() first.
        """

        entry = self._peers.get(username)

        if entry is None or entry["state"] != PEER_STATE_VERIFIED:
            return False

        return entry["fingerprint"] == fingerprint

    def record_observed_peer_fingerprint(self, username, fingerprint):
        """
        Record ``fingerprint`` as this peer's current UNVERIFIED key.

        Never touches an existing VERIFIED entry -- silently does
        nothing in that case, by design: the server is not trusted to
        assert identity, so a freshly-observed key can never demote or
        replace one this user has already explicitly verified. Only
        verify_peer_fingerprint() (a later stage's explicit user
        action) may ever change a VERIFIED entry. Safe and expected to
        be called every time a peer's key is (re)observed, including
        repeatedly for the same still-unverified key.

        The "is it already VERIFIED" check and the write below MUST
        happen as one atomic step under self._lock, not as a check
        followed by a separately-locked write: a client's receiver
        thread (a live key arriving) and an explicit verification
        action can genuinely run concurrently against the same peer
        (Server-Untrusted Identity Verification, Stage 2 is exactly
        this -- ClientSession.handle_public_key() calls this method
        from the receiver thread). An unlocked check-then-locked-write
        leaves a window where verify_peer_fingerprint() could complete
        in between -- this call would then still see its own
        (correct, at the time) "not verified yet" result and overwrite
        the VERIFIED entry that had just been set, defeating the exact
        protection this method exists to provide.
        """

        if not username:
            raise KeyStoreError("A peer username is required.")

        with self._lock:

            existing = self._peers.get(username)

            if existing is not None and existing["state"] == PEER_STATE_VERIFIED:
                return

            self._peers[username] = {
                "fingerprint": fingerprint,
                "state": PEER_STATE_UNVERIFIED,
            }
            self._write(self._last_keys_snapshot)

    def verify_peer_fingerprint(self, username, fingerprint):
        """
        Explicitly mark ``fingerprint`` as ``username``'s VERIFIED
        key -- the action a later stage's explicit user-driven
        verification step performs. This is the ONLY method that ever
        sets PEER_STATE_VERIFIED, and the only one allowed to
        overwrite an existing VERIFIED entry: calling it IS the
        explicit authorization record_observed_peer_fingerprint()'s
        protection exists to require.
        """

        if not username:
            raise KeyStoreError("A peer username is required.")

        with self._lock:
            self._peers[username] = {
                "fingerprint": fingerprint,
                "state": PEER_STATE_VERIFIED,
            }
            self._write(self._last_keys_snapshot)

    @staticmethod
    def _encode_peers(peers):
        return {
            str(username): {
                "fingerprint": str(entry["fingerprint"]),
                "state": str(entry["state"]),
            }
            for username, entry in (peers or {}).items()
        }

    @staticmethod
    def _decode_peers(raw):
        decoded = {}

        for username, entry in (raw or {}).items():
            state = entry["state"]

            if state not in (PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED):
                raise ValueError(f"Unknown peer verification state {state!r}.")

            decoded[str(username)] = {
                "fingerprint": str(entry["fingerprint"]),
                "state": state,
            }

        return decoded

    # ------------------------------------------------------------------
    # This local user's own Kyber (ML-KEM-768) keypair (Server-Untrusted
    # Identity Verification, Stage 2.5)
    # ------------------------------------------------------------------

    def get_own_kyber_keypair(self):
        """
        Return this local user's persisted Kyber keypair as
        ``(encapsulation_key, decapsulation_key)`` -- both raw bytes,
        byte-for-byte identical to what was originally passed to
        save_own_kyber_keypair() -- or None if none has ever been
        persisted (a fresh installation, or a store created before
        Stage 2.5 existed).
        """

        return self._own_kyber_keypair

    def save_own_kyber_keypair(self, encapsulation_key, decapsulation_key):
        """
        Persist this local user's Kyber keypair. Called exactly once
        ever, per installation -- the first time KeyManager.
        load_or_create_kyber_keypair() finds nothing already on file.

        Deliberately refuses to overwrite an existing persisted
        keypair, unlike a conversation-key epoch or an observed peer
        fingerprint: there is no legitimate "this changed, update it"
        case for this user's own identity key from this method's
        caller -- Stage 2.5 exists specifically so this key does NOT
        change across logins. A caller reaching this branch with a
        keypair already on file is a bug, not a routine event: minting
        a second, silently-swapped identity underneath whatever peers
        have already VERIFIED this user's current fingerprint is
        exactly the failure this store must never produce on its own,
        so this fails closed (raises) rather than silently proceeding.
        """

        if not isinstance(encapsulation_key, (bytes, bytearray)) or not encapsulation_key:
            raise KeyStoreError("An encapsulation (public) key is required.")

        if not isinstance(decapsulation_key, (bytes, bytearray)) or not decapsulation_key:
            raise KeyStoreError("A decapsulation (private) key is required.")

        with self._lock:

            if self._own_kyber_keypair is not None:
                raise KeyStoreError(
                    "An own Kyber keypair is already persisted for this "
                    "user; it must never be silently replaced."
                )

            self._own_kyber_keypair = (
                bytes(encapsulation_key),
                bytes(decapsulation_key),
            )
            self._write(self._last_keys_snapshot)

    @staticmethod
    def _encode_own_kyber_keypair(own_kyber_keypair):
        if own_kyber_keypair is None:
            return None

        encapsulation_key, decapsulation_key = own_kyber_keypair

        return {
            "encapsulation_key": base64.b64encode(encapsulation_key).decode("ascii"),
            "decapsulation_key": base64.b64encode(decapsulation_key).decode("ascii"),
        }

    @staticmethod
    def _decode_own_kyber_keypair(raw):
        if raw is None:
            return None

        encapsulation_key = base64.b64decode(raw["encapsulation_key"], validate=True)
        decapsulation_key = base64.b64decode(raw["decapsulation_key"], validate=True)

        if len(encapsulation_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"Persisted Kyber encapsulation key must decode to exactly "
                f"{ML_KEM_768_PUBLIC_KEY_BYTES} bytes; got "
                f"{len(encapsulation_key)}."
            )

        if len(decapsulation_key) != ML_KEM_768_PRIVATE_KEY_BYTES:
            raise ValueError(
                f"Persisted Kyber decapsulation key must decode to exactly "
                f"{ML_KEM_768_PRIVATE_KEY_BYTES} bytes; got "
                f"{len(decapsulation_key)}."
            )

        return (encapsulation_key, decapsulation_key)

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
