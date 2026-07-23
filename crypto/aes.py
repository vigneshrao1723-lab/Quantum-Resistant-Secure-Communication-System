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

        Module 4:
        Use a temporary shared 256-bit key.
        This will later be replaced by RSA/Kyber key exchange.
        """
        if key is None:
            # 32-byte (256-bit) shared key
            self.key = b"12345678901234567890123456789012"
        else:
            self.key = key

    def encrypt(self, plaintext):
        """
        Encrypt a plaintext string.

        Returns:
            Base64 encoded string containing IV + Ciphertext.
        """
        cipher = AES.new(self.key, AES.MODE_CBC)

        ciphertext = cipher.encrypt(
            pad(plaintext.encode("utf-8"), AES.block_size)
        )

        encrypted_data = cipher.iv + ciphertext

        return base64.b64encode(encrypted_data).decode("utf-8")

    def decrypt(self, encrypted_text):
        """
        Decrypt a Base64 encoded ciphertext.

        Returns:
            Original plaintext string.
        """
        encrypted_data = base64.b64decode(encrypted_text)

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        plaintext = unpad(
            cipher.decrypt(ciphertext),
            AES.block_size
        )

        return plaintext.decode("utf-8")