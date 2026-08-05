import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AESCipher:
    """
    AES-256-GCM Encryption and Decryption Utility.

    GCM is an AEAD (Authenticated Encryption with Associated Data)
    mode: it provides confidentiality AND integrity/authenticity in
    one pass, unlike CBC which provides confidentiality only and is
    vulnerable to undetected ciphertext tampering (padding-oracle /
    bit-flipping attacks). Any tampering with the wire format below
    causes decrypt() to raise instead of silently returning corrupted
    or attacker-controlled plaintext.

    Wire format (all base64 of the concatenation):
        nonce (12 bytes) + tag (16 bytes) + ciphertext (variable)
    """

    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key=None):
        """
        Initialize the AES-GCM cipher context.

        If no key is supplied, fall back to a fixed development key.
        This fallback exists only for standalone/manual testing of
        this module (see tests/test_aes.py) and must never be reached
        in the real client/server flow, where a session key always
        comes from the Kyber/RSA key exchange.
        """

        if key is None:
            key = b"12345678901234567890123456789012"

        if not isinstance(key, bytes):
            raise TypeError("AES key must be bytes.")

        if len(key) != 32:
            raise ValueError(
                "AES-256 key must be exactly 32 bytes."
            )

        self.key = key

    def encrypt(self, plaintext):
        """
        Encrypt a plaintext string with AES-256-GCM.

        Returns:
            Base64 encoded string containing
            Nonce (12 bytes) + Tag (16 bytes) + Ciphertext.
        """

        # Use an explicit 12-byte nonce (the GCM-standard, most
        # efficient size) instead of PyCryptodome's 16-byte default.
        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=self._generate_nonce()
        )

        ciphertext, tag = cipher.encrypt_and_digest(
            plaintext.encode("utf-8")
        )

        encrypted_data = cipher.nonce + tag + ciphertext

        return base64.b64encode(
            encrypted_data
        ).decode("utf-8")

    def decrypt(self, encrypted_text):
        """
        Decrypt a Base64 encoded AES-256-GCM payload.

        Verifies the authentication tag before returning plaintext.
        Raises ValueError if the ciphertext has been tampered with,
        truncated, or was encrypted under a different key.

        Returns:
            Original plaintext string.
        """

        encrypted_data = base64.b64decode(
            encrypted_text
        )

        if len(encrypted_data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError(
                "Ciphertext too short to contain a valid "
                "nonce and authentication tag."
            )

        nonce = encrypted_data[:self.NONCE_SIZE]
        tag = encrypted_data[
            self.NONCE_SIZE:self.NONCE_SIZE + self.TAG_SIZE
        ]
        ciphertext = encrypted_data[self.NONCE_SIZE + self.TAG_SIZE:]

        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=nonce
        )

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise ValueError(
                "AES-GCM authentication failed: message has been "
                "tampered with, corrupted, or encrypted under a "
                "different key."
            ) from exc

        return plaintext.decode("utf-8")

    def _generate_nonce(self):
        """
        Generate a cryptographically secure 12-byte GCM nonce.
        """

        return get_random_bytes(self.NONCE_SIZE)