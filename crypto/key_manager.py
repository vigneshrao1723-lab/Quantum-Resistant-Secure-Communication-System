import base64
import hashlib
import threading

from config import KEY_EXCHANGE_ALGORITHM
from crypto.aes import AESCipher
from crypto.kyber import KyberKEM
from crypto.ml_dsa import MLDSASigner
from crypto.rsa import RSAEncryption


def fingerprint_public_key(public_key_bytes):
    """
    Deterministic SHA-256 fingerprint of a peer's raw public-key bytes
    (Server-Untrusted Identity Verification, Stage 1).

    A pure function, deliberately: no KeyManager instance, no network
    I/O, no GUI dependency, no mutation of the input -- it only ever
    reads ``public_key_bytes``. Exists so a received public key's
    identity can eventually be compared by a human through a channel
    the server does not control (a later stage's job -- this function
    only computes the value to compare, it does not display, transmit,
    or store it). Does not alter, wrap, or otherwise touch ML-KEM/RSA
    key material or behavior in any way.

    Works identically regardless of which algorithm produced the
    bytes -- KyberKEM.export_public_key() (base64 text, encoded here
    as UTF-8) and RSAEncryption.export_public_key() (PEM bytes) both
    already return something hashable; this makes no assumption about
    key format beyond "some bytes".

    Representation: the SHA-256 digest, encoded as uppercase hex and
    grouped into 4-character blocks separated by spaces (e.g.
    "A1B2 C3D4 ..."), the same convention GPG/Signal-style manual
    fingerprint comparison already uses -- easier to read aloud or
    compare in short chunks than one unbroken 64-character string.
    """

    if isinstance(public_key_bytes, str):
        public_key_bytes = public_key_bytes.encode("utf-8")

    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise TypeError(
            f"Public key must be bytes-like or str, not "
            f"{type(public_key_bytes).__name__}."
        )

    return _format_fingerprint(bytes(public_key_bytes))


def _format_fingerprint(raw_bytes):
    """
    SHA-256 of ``raw_bytes``, formatted as uppercase hex grouped into
    4-character blocks -- the shared hash-and-format tail of
    fingerprint_public_key() and fingerprint_combined_identity(), so
    both produce output in the exact same convention from one place,
    never two independently-maintained copies of the same formatting
    logic. ``raw_bytes`` must already be exactly the bytes to hash --
    this function performs no canonicalization, type coercion, or
    concatenation of its own.
    """

    digest = hashlib.sha256(raw_bytes).hexdigest().upper()

    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def fingerprint_combined_identity(kem_public_key_bytes, signing_public_key_bytes):
    """
    Deterministic combined-identity fingerprint of a peer's ML-KEM
    public key AND ML-DSA public key together (Server-Untrusted
    Identity Verification -- ML-DSA identity foundation), as ONE
    fingerprint representing ONE identity -- never two independent
    fingerprints for the same peer. Reuses fingerprint_public_key()'s
    exact hash-and-format convention (via _format_fingerprint()), so
    the output is visually and structurally identical to the existing,
    already-approved single-key fingerprint format -- same length, same
    grouping, same uppercase-hex representation -- just computed over
    both keys' bytes instead of one.

    Canonical representation: each key's raw bytes, prefixed with its
    own length as a 4-byte unsigned big-endian integer, concatenated in
    a FIXED order (KEM first, then signing) --

        pack(">I", len(kem_public_key_bytes)) + kem_public_key_bytes
      + pack(">I", len(signing_public_key_bytes)) + signing_public_key_bytes

    The length prefixes make this concatenation unambiguous by
    construction: two different (kem, signing) pairs can never collide
    into the same byte sequence merely because one key is a prefix of
    the other, or because the split point between the two keys is
    otherwise inferrable from context. Deliberately NOT canonical JSON,
    str(), or repr() -- none of those give the same length-prefixed,
    binary-safe, encoding-independent guarantee (see this feature's own
    design report, Phase 9, for the full comparison).

    Only ever computed from PUBLIC key bytes -- there is no code path
    in this function, or in any caller, that could feed it private key
    material; it has no parameter through which a private key could
    even be passed.

    Accepts str or bytes-like for either argument, exactly like
    fingerprint_public_key() -- both KyberKEM's and MLDSASigner's raw
    public-key exports are already bytes, but this stays permissive at
    the boundary the same way the existing function already is.
    """

    if isinstance(kem_public_key_bytes, str):
        kem_public_key_bytes = kem_public_key_bytes.encode("utf-8")

    if isinstance(signing_public_key_bytes, str):
        signing_public_key_bytes = signing_public_key_bytes.encode("utf-8")

    if not isinstance(kem_public_key_bytes, (bytes, bytearray)):
        raise TypeError(
            f"KEM public key must be bytes-like or str, not "
            f"{type(kem_public_key_bytes).__name__}."
        )

    if not isinstance(signing_public_key_bytes, (bytes, bytearray)):
        raise TypeError(
            f"Signing public key must be bytes-like or str, not "
            f"{type(signing_public_key_bytes).__name__}."
        )

    kem_public_key_bytes = bytes(kem_public_key_bytes)
    signing_public_key_bytes = bytes(signing_public_key_bytes)

    canonical = (
        len(kem_public_key_bytes).to_bytes(4, "big") + kem_public_key_bytes
        + len(signing_public_key_bytes).to_bytes(4, "big") + signing_public_key_bytes
    )

    return _format_fingerprint(canonical)


class KeyManager:
    """
    Handles Kyber/RSA keys and AES session keys.

    The active key-exchange algorithm is controlled by
    config.KEY_EXCHANGE_ALGORITHM ("KYBER" or "RSA"), which
    lets the rest of the app stay algorithm-agnostic while
    still allowing a classical-vs-post-quantum comparison.
    """

    def __init__(self):

        self.algorithm = KEY_EXCHANGE_ALGORITHM.upper()

        # ---------------------------------
        # Kyber (post-quantum KEM)
        # ---------------------------------

        self.kyber = KyberKEM()
        self.kyber.generate_keys()

        # ---------------------------------
        # RSA (classical, kept for comparison)
        # ---------------------------------

        self.rsa = RSAEncryption()
        self.rsa.generate_keys()

        # ---------------------------------
        # ML-DSA (post-quantum signing identity)
        # ---------------------------------
        #
        # Unlike self.kyber/self.rsa above, this is NOT gated on
        # self.algorithm: a signing identity authenticates the origin
        # of key-distribution packets regardless of which KEM
        # algorithm produced the key material being distributed, so
        # both KYBER and RSA comparison modes need one. Ephemeral
        # here, exactly like self.kyber/self.rsa are before
        # load_or_create_signing_keypair() runs -- see that method for
        # how this becomes the persisted, stable identity across
        # restarts.
        self.ml_dsa = MLDSASigner()
        self.ml_dsa.generate_keys()

        # Export own public key for whichever algorithm is active
        self.public_key = self._export_own_public_key()

        # Store other clients' public keys
        # (Kyber -> raw bytes, RSA -> cryptography key object)
        self.public_keys = {}

        # Store AES keys by conversation_id (Phase 5 -- Secure Group
        # Key Distribution). This is the ONLY identity the encryption
        # layer ever receives -- a direct conversation's key and a
        # group conversation's key are stored and looked up exactly
        # the same way; KeyManager has no notion of "direct" or
        # "group" at all. conversation_id resolution (including for
        # a not-yet-created direct conversation) is entirely
        # ConversationStore's responsibility -- see
        # client/conversation_store.py::ensure_direct_conversation_id().
        #
        # Phase 7 -- Group Membership Management: each conversation_id
        # maps to a dict of {epoch: key_bytes}, not a single key.
        # Rotating a group's key (after a member leaves) never deletes
        # or overwrites an older epoch -- historical messages encrypted
        # under epoch 1 must stay decryptable after epoch 2 exists.
        # Direct conversations, and a group before its first rotation,
        # simply never have more than epoch 1. Example:
        # {
        #     "3fa8...": {1: b"...32 bytes..."},               # direct
        #     "9c21...": {1: b"...", 2: b"...", 3: b"..."},     # group, rotated twice
        # }
        self.keys = {}

        # BUG 1 -- guards the conversation key map. store_key() can be
        # called concurrently by the receiver thread (an arriving
        # session_key / group_key_distribution) and by the GUI thread
        # (establish_session_key), and the persistence callback exports
        # the map from inside store_key(), so export and mutation must
        # not interleave. Reentrant because that callback path
        # re-enters this lock on the same thread.
        self._lock = threading.RLock()

        # BUG 1 -- optional callback invoked whenever a NEW conversation
        # epoch key is stored, so a persistent key store can be kept up
        # to date without every store_key() call site having to
        # remember to save. Left None here: KeyManager itself knows
        # nothing about persistence, and nothing about this class's
        # behaviour changes until someone sets it.
        self.on_change = None

        # conversation_id -> highest epoch ever stored for it. Tracked
        # separately (not derived by taking max(self.keys[id]) on every
        # lookup) so get_key(id) -- "give me the current key" -- stays
        # O(1), and so it can only ever move forward (see store_key()).
        self._current_epoch = {}

    # =====================================================
    # Algorithm Helpers
    # =====================================================

    def _export_own_public_key(self):
        """
        Export this client's public key for the
        currently active algorithm.
        """

        if self.algorithm == "KYBER":
            return self.kyber.export_public_key().encode("utf-8")

        return self.rsa.export_public_key()

    def load_or_create_kyber_keypair(self, key_store):
        """
        Make this local user's Kyber (ML-KEM-768) keypair the one
        persisted in ``key_store``, instead of the ephemeral one
        __init__() always generates (Server-Untrusted Identity
        Verification, Stage 2.5).

        __init__() runs before any SecureKeyStore is available --
        ClientSession constructs KeyManager before login, and
        SecureKeyStore cannot be unlocked until the account password
        is known -- so it always generates a keypair first, unaware of
        whatever may already be on file. This method is called exactly
        once, from ClientSession._unlock_key_store() right after that
        store successfully unlocks, and resolves the two keypairs into
        one of the following:

        * ``key_store`` already holds a persisted keypair (every login
          after the very first): it REPLACES __init__()'s keypair.
          That one is discarded -- never exported, sent, or used for
          any cryptographic operation, since self.public_key is
          recomputed below before this method returns and nothing
          reads self.kyber's fields before this method runs (see
          ClientSession.send_public_key(), always called later).

        * ``key_store`` holds none yet (first login ever, or a store
          created before Stage 2.5 existed): __init__()'s keypair
          becomes the permanent one, persisted here so every
          subsequent login loads the same keypair instead of
          generating a new one.

        Never calls KyberKEM.generate_keys() itself -- by the time this
        runs, a keypair already exists (from __init__()) or is loaded
        from key_store; this method only ever assigns already-existing
        bytes, in either direction.

        A no-op if the active algorithm is not KYBER: RSA is
        deliberately out of Stage 2.5's scope (see
        storage/secure_key_store.py's module docstring) and keeps
        generating a fresh keypair every session, unchanged.
        """

        if self.algorithm != "KYBER":
            return

        persisted = key_store.get_own_kyber_keypair()

        if persisted is not None:
            self.kyber.encapsulation_key, self.kyber.decapsulation_key = persisted
        else:
            key_store.save_own_kyber_keypair(
                self.kyber.encapsulation_key,
                self.kyber.decapsulation_key,
            )

        self.public_key = self._export_own_public_key()

    def load_or_create_signing_keypair(self, key_store):
        """
        Make this local user's ML-DSA-65 signing keypair the one
        persisted in ``key_store``, instead of the ephemeral one
        __init__() always generates (ML-DSA identity/key-persistence
        foundation phase).

        Mirrors load_or_create_kyber_keypair()'s resolution shape
        exactly -- called once, from ClientSession._unlock_key_store()
        right after the store unlocks, resolving __init__()'s ephemeral
        keypair against whatever key_store already holds:

        * ``key_store`` already holds a persisted signing keypair
          (every login after the first): it REPLACES __init__()'s
          keypair via import_private_key(), which also re-derives the
          public key from the loaded seed.

        * ``key_store`` holds none yet (first login ever): __init__()'s
          keypair becomes the permanent one, persisted here.

        Unlike load_or_create_kyber_keypair(), this is UNCONDITIONAL --
        not gated on self.algorithm. A signing identity is orthogonal
        to which KEM algorithm (KYBER or RSA) is currently active; both
        need one persisted signing identity.

        Integrity check: when a persisted keypair is loaded, the
        public key re-derived from the loaded private seed is compared
        against the separately-persisted public key. A mismatch means
        the persisted identity record is internally inconsistent --
        e.g. truncated/corrupted storage, or a manually edited file --
        and this fails closed with ValueError rather than silently
        proceeding with a keypair whose halves don't actually match
        (which would make every future signature this session produces
        fail to verify against the public key this session's peers
        already trust). Deliberately a plain ValueError, not
        storage.secure_key_store.KeyStoreError: crypto/key_manager.py
        does not otherwise import from storage/, and this failure is
        precisely a "the value is invalid" condition, not a storage
        I/O condition.

        Raises:
            ValueError -- the persisted public key does not match the
                          public key derived from the persisted private
                          seed.
        """

        persisted = key_store.get_own_signing_keypair()

        if persisted is not None:
            persisted_public_key, persisted_private_seed = persisted

            self.ml_dsa.import_private_key(persisted_private_seed)

            if self.ml_dsa.export_public_key() != persisted_public_key:
                raise ValueError(
                    "Persisted ML-DSA public key does not match the "
                    "public key derived from the persisted private "
                    "seed; the signing identity record is corrupted."
                )
        else:
            key_store.save_own_signing_keypair(
                self.ml_dsa.export_public_key(),
                self.ml_dsa.export_private_key(),
            )

    # =====================================================
    # Public Key Management
    # =====================================================

    def add_public_key(self, username, public_key):
        """
        Store another client's public key for the
        currently active algorithm.
        """

        if isinstance(public_key, str):
            public_key = public_key.encode("utf-8")

        if self.algorithm == "KYBER":
            self.public_keys[username] = (
                self.kyber.import_public_key(public_key)
            )
        else:
            self.public_keys[username] = (
                self.rsa.import_public_key(public_key)
            )

    def get_public_key(self, username):
        """
        Retrieve a user's public key.
        """

        return self.public_keys.get(username)

    # =====================================================
    # Conversation Key Management (Phase 5)
    #
    # The only source of truth for encryption keys across the whole
    # platform. Every conversation -- direct or group, and every
    # future payload type built on top (files, images, voice, calls)
    # -- is addressed here by conversation_id alone. Deliberately no
    # get_direct_key()/get_group_key()-style methods: the cryptographic
    # layer must never know or care which kind of conversation a key
    # belongs to.
    # =====================================================

    def store_key(self, conversation_id, key, epoch=1):
        """
        Store the AES key for a conversation at a given epoch.

        epoch defaults to 1 -- the only epoch a direct conversation, or
        a group before its first rotation, ever has -- so every
        pre-Phase-7 call site (store_key(id, key)) keeps working
        unchanged.

        Never overwrites an existing epoch with a different key: if
        this exact epoch is already stored, this is a no-op. This is
        what makes a retried rotation instruction safe (Phase 7 --
        Group Membership Management) -- an initiator that already
        generated epoch N's key and is asked to redistribute it (e.g.
        after a partial-distribution failure) reuses the same value
        rather than silently replacing it with a second, different
        "epoch N" that would make the two no longer agree.
        """

        with self._lock:

            epochs = self.keys.setdefault(conversation_id, {})

            added = epoch not in epochs

            if added:
                epochs[epoch] = key

            self._current_epoch[conversation_id] = max(
                self._current_epoch.get(conversation_id, 0), epoch
            )

            # BUG 1 -- notify whoever is persisting these keys, but
            # only when something genuinely new was stored. A redundant
            # redelivery of an epoch already held changes nothing on
            # disk either. The callback is optional: a KeyManager with
            # no listener behaves exactly as before.
            #
            # Deliberately called INSIDE the lock: the listener exports
            # the map and writes it, and letting a second thread mutate
            # between this thread's export and its write is exactly the
            # lost-update that would drop an epoch from the file.
            if added and self.on_change is not None:
                self.on_change()

    def export_conversation_keys(self):
        """
        A plain ``{conversation_id: {epoch: key_bytes}}`` snapshot, for
        persisting to the local encrypted key store (BUG 1).

        A copy, not the live dict, so a caller serialising it cannot be
        affected by -- or affect -- concurrent key arrivals.
        """

        with self._lock:
            return {
                conversation_id: dict(epochs)
                for conversation_id, epochs in self.keys.items()
            }

    def import_conversation_keys(self, conversation_keys):
        """
        Restore keys read back from the local encrypted key store
        (BUG 1), returning how many epochs were actually added.

        Routed through store_key() deliberately, rather than assigning
        self.keys directly: that keeps the no-overwrite rule and the
        "current epoch is the highest" bookkeeping in exactly one
        place. Restoring can therefore only ever ADD epochs this
        client did not already hold -- it can never replace a live key
        with a stale one from disk.
        """

        restored = 0

        with self._lock:
            for conversation_id, epochs in (conversation_keys or {}).items():
                for epoch, key in (epochs or {}).items():
                    if not self.has_key(conversation_id, epoch=epoch):
                        self.store_key(conversation_id, key, epoch=epoch)
                        restored += 1

        return restored

    def get_key(self, conversation_id, epoch=None):
        """
        Retrieve the AES key for a conversation.

        epoch=None (default) returns the CURRENT (highest-numbered)
        epoch's key -- what encrypting a new outgoing message, or
        decrypting a live-arriving one, wants. An explicit epoch
        retrieves exactly that epoch's key (for decrypting a stored
        historical message), or None if this client never received it
        -- never silently substitutes a different epoch's key.
        """

        epochs = self.keys.get(conversation_id)

        if not epochs:
            return None

        if epoch is None:
            epoch = self._current_epoch.get(conversation_id)

        return epochs.get(epoch)

    def has_key(self, conversation_id, epoch=None):
        """
        Check whether a key already exists for a conversation.

        epoch=None (default) checks the current epoch, matching
        get_key()'s default -- every pre-Phase-7 call site keeps
        working unchanged.
        """

        return self.get_key(conversation_id, epoch) is not None

    def current_epoch(self, conversation_id):
        """
        The highest epoch this client has ever stored a key for, in
        this conversation, or None if it has never had a key at all
        (Phase 7 -- Group Membership Management). Used to stamp an
        outgoing group message with the epoch that encrypted it.
        """

        return self._current_epoch.get(conversation_id)

    def remove_key(self, conversation_id):
        """
        Remove every epoch of a conversation's key material.
        """

        self.keys.pop(conversation_id, None)
        self._current_epoch.pop(conversation_id, None)

    # =====================================================
    # Kyber Encapsulation / Decapsulation
    # =====================================================

    def encapsulate_session_key(self, username):
        """
        Generate a new AES session key by encapsulating a
        shared secret with another client's Kyber public key.

        Returns:
            (ciphertext_b64, shared_secret)
        """

        public_key = self.get_public_key(username)

        if public_key is None:
            raise ValueError(
                f"No public key found for {username}"
            )

        return self.kyber.encapsulate(public_key)

    def decapsulate_session_key(self, ciphertext_b64):
        """
        Recover the AES session key from a received
        Kyber ciphertext using this client's private key.
        """

        return self.kyber.decapsulate(ciphertext_b64)

    # =====================================================
    # RSA Encryption / Decryption
    # =====================================================

    def encrypt_session_key(self, username, session_key):
        """
        Encrypt an AES session key using another
        client's RSA public key.
        """

        public_key = self.get_public_key(username)

        if public_key is None:
            raise ValueError(
                f"No public key found for {username}"
            )

        return self.rsa.encrypt(
            session_key,
            public_key
        )

    def decrypt_session_key(self, encrypted_key):
        """
        Decrypt an AES session key using
        this client's RSA private key.
        """

        return self.rsa.decrypt(
            encrypted_key
        )

    # =====================================================
    # Group Key Wrapping (Phase 4 -- Secure Group Messaging
    # Foundation)
    #
    # Distributes one arbitrary, already-chosen 32-byte AES key (the
    # group key) to a member. Composes the same primitives above --
    # no new cryptography is introduced.
    # =====================================================

    def wrap_key_for_member(self, username, key_bytes):
        """
        Wrap a pre-chosen key (the group key) for one member.

        RSA mode: RSA-OAEP is true public-key encryption, so it can
        encrypt the caller-chosen key_bytes directly -- the same
        operation encrypt_session_key() already performs.

        KYBER mode: ML-KEM is a KEM, not a PKE -- encapsulate() always
        generates its own fresh secret, it cannot target a
        caller-chosen one. So a fresh per-member secret is
        encapsulated (the same operation encapsulate_session_key()
        already performs) and used to AES-GCM-encrypt key_bytes --
        standard KEM-then-DEM hybrid composition, not a new protocol.

        Returns (encapsulation, wrapped_key): encapsulation is the
        Kyber ciphertext in KYBER mode, or None in RSA mode (nothing
        to decapsulate); wrapped_key is always a base64 string.
        """

        public_key = self.get_public_key(username)

        if public_key is None:
            raise ValueError(
                f"No public key found for {username}"
            )

        if self.algorithm == "KYBER":

            encapsulation, wrapping_secret = self.kyber.encapsulate(
                public_key
            )

            wrapped_key = AESCipher(wrapping_secret).encrypt(
                base64.b64encode(key_bytes).decode("ascii")
            )

            return encapsulation, wrapped_key

        encrypted = self.rsa.encrypt(key_bytes, public_key)

        return None, base64.b64encode(encrypted).decode("utf-8")

    def unwrap_received_key(self, encapsulation, wrapped_key):
        """
        Reverse of wrap_key_for_member(), using this client's own
        private key material -- the recipient's decapsulation/RSA
        private key, never anything from the sender.
        """

        if self.algorithm == "KYBER":

            wrapping_secret = self.kyber.decapsulate(encapsulation)

            key_b64 = AESCipher(wrapping_secret).decrypt(wrapped_key)

            return base64.b64decode(key_b64)

        encrypted = base64.b64decode(wrapped_key)

        return self.rsa.decrypt(encrypted)
