"""
RSA Cryptography Module

Handles RSA key generation, encryption, and decryption.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Minimum accepted RSA modulus size, in bits.
#
# Not a new policy: 2048 is the level this project already states for
# its RSA mode. config.py documents KEY_EXCHANGE_ALGORITHM's "RSA"
# option as "classical RSA-2048 encryption (kept for benchmarking)",
# and generate_keys() below hardcodes key_size=2048, so every
# conforming client already produces exactly this. Enforcing it at
# import simply makes the stated level actually hold for keys arriving
# from a peer, which is the one place it was never checked.
#
# Larger moduli (3072, 4096) are accepted -- this is a minimum, not an
# equality check, and OAEP/SHA-256 wrapping works unchanged at those
# sizes.
RSA_MINIMUM_KEY_SIZE_BITS = 2048


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
        Load a public key from PEM bytes (D6.5 -- Public-Key Input
        Validation).

        load_pem_public_key() already rejects malformed, truncated, and
        empty PEM input with ValueError, so unlike the Kyber path this
        one never silently accepted garbage. It does, however, load ANY
        supported public key type -- a structurally valid PEM carrying
        an EC (or DSA, Ed25519, ...) key is returned happily. That key
        then reaches encrypt() below, which calls .encrypt() on it: a
        method non-RSA key objects do not have, producing an
        AttributeError deep inside key wrapping rather than at import.

        AttributeError is deliberately NOT caught by
        ClientSession._distribute_group_key() -- it is exactly the
        signature of a programming error, and treating it as "this peer
        sent a bad key" would disguise real bugs. So the wrong-type key
        is rejected here instead, as the ValueError it actually is,
        keeping the "unusable peer key material" contract identical
        across both algorithms.

        Also enforces RSA_MINIMUM_KEY_SIZE_BITS. A weak-but-well-formed
        key (RSA-1024, say) is not malformed -- it wraps and unwraps
        correctly -- so unlike the checks above this one is a strength
        floor rather than input validation. It is enforced anyway
        because 2048 is the level this project already states for its
        RSA mode (see the constant's comment), and a smaller key can
        only reach here from a peer that does not follow the project's
        own key generation. Accepting it would silently weaken the
        session-key wrapping that RSA mode exists to benchmark.

        Raises:
            ValueError -- input is not a valid PEM public key, is a
                          valid public key of a non-RSA type, or is an
                          RSA key weaker than
                          RSA_MINIMUM_KEY_SIZE_BITS.
        """

        public_key = serialization.load_pem_public_key(
            public_key_bytes
        )

        # ValueError, not TypeError, despite the isinstance() check:
        # the ARGUMENT's type (bytes) was correct -- it is the value
        # those bytes encode that is wrong. This also matches
        # load_pem_public_key()'s own ValueError for unusable PEM
        # input, so every "bad peer key" failure from this module is a
        # single, consistently-catchable class.
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError(  # noqa: TRY004
                f"Expected an RSA public key, got "
                f"{type(public_key).__name__}."
            )

        if public_key.key_size < RSA_MINIMUM_KEY_SIZE_BITS:
            raise ValueError(
                f"RSA public key must be at least "
                f"{RSA_MINIMUM_KEY_SIZE_BITS} bits; got "
                f"{public_key.key_size}."
            )

        return public_key

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