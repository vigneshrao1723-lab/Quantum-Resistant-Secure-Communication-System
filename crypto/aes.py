import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    """
    AES-256 Encryption and Decryption Utility
    """

    def __init__(self, key=None):
        """
        Initialize the AES cipher.

        If no key is supplied, use the temporary shared key.
        This fallback will be removed after RSA session-key
        exchange is fully implemented.
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
        Encrypt a plaintext string.

        Returns:
            Base64 encoded string containing IV + Ciphertext.
        """

        cipher = AES.new(
            self.key,
            AES.MODE_CBC
        )

        ciphertext = cipher.encrypt(
            pad(
                plaintext.encode("utf-8"),
                AES.block_size
            )
        )

        encrypted_data = cipher.iv + ciphertext

        return base64.b64encode(
            encrypted_data
        ).decode("utf-8")

    def decrypt(self, encrypted_text):
        """
        Decrypt a Base64 encoded ciphertext.

        Returns:
            Original plaintext string.
        """

        encrypted_data = base64.b64decode(
            encrypted_text
        )

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = AES.new(
            self.key,
            AES.MODE_CBC,
            iv
        )

        plaintext = unpad(
            cipher.decrypt(ciphertext),
            AES.block_size
        )

        return plaintext.decode("utf-8")