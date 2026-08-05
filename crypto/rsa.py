"""
RSA Cryptography Module

Handles RSA key generation, encryption, and decryption.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class RSAEncryption:
    """
    RSA helper class.
    """

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """
        Generate a 2048-bit RSA key pair.
        """

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        self.public_key = self.private_key.public_key()

    def export_public_key(self):
        """
        Export the public key as PEM bytes.
        """

        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def import_public_key(public_key_bytes):
        """
        Load a public key from PEM bytes.
        """

        return serialization.load_pem_public_key(
            public_key_bytes
        )

    def encrypt(self, data, public_key):
        """
        Encrypt data using a public key.
        """

        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, encrypted_data):
        """
        Decrypt data using the private key.
        """

        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )