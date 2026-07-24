from crypto.rsa import RSAEncryption


class KeyManager:
    """
    Handles RSA keys and AES session keys.
    """

    def __init__(self):

        # RSA helper
        self.rsa = RSAEncryption()

        # Generate RSA key pair
        self.rsa.generate_keys()

        # Export own public key
        self.public_key = self.rsa.export_public_key()

        # Store other clients' public keys
        self.public_keys = {}

        # Store AES session keys for each user
        # Example:
        # {
        #     "Ramya": b"...32 bytes...",
        #     "Hari": b"...32 bytes..."
        # }
        self.session_keys = {}

    # =====================================================
    # Public Key Management
    # =====================================================

    def add_public_key(self, username, public_key):
        """
        Store another client's RSA public key.
        """

        if isinstance(public_key, str):
            public_key = public_key.encode("utf-8")

        self.public_keys[username] = (
            self.rsa.import_public_key(public_key)
        )

    def get_public_key(self, username):
        """
        Retrieve a user's RSA public key.
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