import base64

from config import KEY_EXCHANGE_ALGORITHM
from crypto.aes import AESCipher
from crypto.kyber import KyberKEM
from crypto.rsa import RSAEncryption


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
        # Example:
        # {
        #     "3fa8...": b"...32 bytes...",  # a direct conversation
        #     "9c21...": b"...32 bytes...",  # a group conversation
        # }
        self.keys = {}

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

    def store_key(self, conversation_id, key):
        """
        Store the AES key for a conversation.
        """

        self.keys[conversation_id] = key

    def get_key(self, conversation_id):
        """
        Retrieve the AES key for a conversation.
        """

        return self.keys.get(conversation_id)

    def has_key(self, conversation_id):
        """
        Check whether a key already exists for a conversation.
        """

        return conversation_id in self.keys

    def remove_key(self, conversation_id):
        """
        Remove a conversation's key.
        """

        self.keys.pop(conversation_id, None)

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
