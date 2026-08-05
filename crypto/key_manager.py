from config import KEY_EXCHANGE_ALGORITHM
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

        # Store AES session keys for each user
        # Example:
        # {
        #     "Ramya": b"...32 bytes...",
        #     "Hari": b"...32 bytes..."
        # }
        self.session_keys = {}

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
    # AES Session Key Management
    # =====================================================

    def add_session_key(self, username, key):
        """
        Store the AES session key shared with a user.
        """

        self.session_keys[username] = key

    def get_session_key(self, username):
        """
        Retrieve the AES session key for a user.
        """

        return self.session_keys.get(username)

    def has_session_key(self, username):
        """
        Check whether a session key already exists.
        """

        return username in self.session_keys

    def remove_session_key(self, username):
        """
        Remove a user's session key.
        """

        self.session_keys.pop(username, None)

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
