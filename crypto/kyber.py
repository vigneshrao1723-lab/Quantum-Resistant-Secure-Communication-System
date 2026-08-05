"""
Kyber Cryptography Module

Handles Kyber (ML-KEM) key generation, encapsulation, and
decapsulation for post-quantum secure key exchange.

Kyber is a Key Encapsulation Mechanism (KEM), not a public-key
encryption scheme like RSA. Instead of encrypting an existing
AES key, the sender uses the receiver's public key to jointly
derive a brand-new shared secret and a ciphertext ("encapsulation")
that only the receiver's private key can unwrap ("decapsulation").

This module uses ML-KEM-768 (the FIPS 203 standardised version of
Kyber768), which targets NIST Security Level 3 (roughly equivalent
to AES-192) and produces a 32-byte shared secret -- a perfect fit
for direct use as an AES-256 key.
"""

import base64

from kyber_py.ml_kem import ML_KEM_768


class KyberKEM:
    """
    Kyber (ML-KEM-768) helper class.
    """

    def __init__(self):
        self.encapsulation_key = None
        self.decapsulation_key = None

    def generate_keys(self):
        """
        Generate an ML-KEM-768 key pair.

        encapsulation_key -> public key   (shared with others)
        decapsulation_key -> private key  (kept secret)
        """

        (
            self.encapsulation_key,
            self.decapsulation_key
        ) = ML_KEM_768.keygen()

    def export_public_key(self):
        """
        Export the encapsulation (public) key as a
        Base64 encoded string, ready for network transport.
        """

        return base64.b64encode(
            self.encapsulation_key
        ).decode("utf-8")

    @staticmethod
    def import_public_key(public_key_data):
        """
        Load a Base64 encoded encapsulation key received
        from another client.
        """

        if isinstance(public_key_data, str):
            public_key_data = public_key_data.encode("utf-8")

        return base64.b64decode(public_key_data)

    def encapsulate(self, public_key):
        """
        Encapsulate a new shared secret using another
        client's Kyber public key.

        Returns:
            (ciphertext_b64, shared_secret)

            ciphertext_b64  -> Base64 string, safe to send
                               over the network to the owner
                               of `public_key`.
            shared_secret   -> 32 raw bytes, usable directly
                               as an AES-256 key.
        """

        shared_secret, ciphertext = ML_KEM_768.encaps(
            public_key
        )

        ciphertext_b64 = base64.b64encode(
            ciphertext
        ).decode("utf-8")

        return ciphertext_b64, shared_secret

    def decapsulate(self, ciphertext_b64):
        """
        Recover the shared secret from a received
        ciphertext, using this client's private
        decapsulation key.

        Returns:
            32 raw bytes, usable directly as an AES-256 key.
        """

        if isinstance(ciphertext_b64, str):
            ciphertext = base64.b64decode(ciphertext_b64)
        else:
            ciphertext = ciphertext_b64

        return ML_KEM_768.decaps(
            self.decapsulation_key,
            ciphertext
        )