import base64
import hashlib
import threading

from config import KEY_EXCHANGE_ALGORITHM
from crypto.aes import AESCipher
from crypto.kyber import KyberKEM
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

    digest = hashlib.sha256(bytes(public_key_bytes)).hexdigest().upper()

    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


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
