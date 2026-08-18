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
import binascii

from kyber_py.ml_kem import ML_KEM_768

# Size, in bytes, of an ML-KEM-768 encapsulation ("public") key.
#
# Fixed by the FIPS 203 parameter set: 384 * k + 32, with k = 3 for
# ML-KEM-768. A byte string of any other length cannot be an
# ML-KEM-768 encapsulation key, so this is a complete length check,
# not a heuristic. Used by import_public_key() to reject malformed
# key material at the point it enters this process, rather than
# letting it reach ML_KEM_768.encaps() much later (D6.5).
ML_KEM_768_PUBLIC_KEY_BYTES = 1184


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
        Load a Base64 encoded encapsulation key received from another
        client, validating it before it is returned (D6.5 -- Public-Key
        Input Validation).

        Accepts the Base64 form produced by export_public_key(), either
        as a str or as its UTF-8/ASCII bytes -- both remain supported
        exactly as before, and a valid key round-trips unchanged.

        Anything else is rejected here, at the boundary where untrusted
        remote key material first enters this process. Previously this
        was a bare base64.b64decode() with no validation at all, which
        silently accepted garbage: b64decode() defaults to
        validate=False, so non-alphabet characters are discarded rather
        than reported. Measured against the previous implementation,
        "!!!!" and "" both decoded to 0 bytes, "AAAA" to 3, and a
        truncated key to 75 -- each cached as if it were a real key and
        only failing later, inside ML_KEM_768.encaps(), where it broke
        group key distribution for unrelated members.

        Raises:
            TypeError  -- input is neither str nor bytes-like.
            ValueError -- input is not strictly valid Base64, or does
                          not decode to exactly an ML-KEM-768
                          encapsulation key's length.

        Both are data errors describing untrusted input, never a bug in
        this codebase, which is what makes them safe for callers to
        catch narrowly (see ClientSession.handle_public_key() and
        _distribute_group_key()).
        """

        if isinstance(public_key_data, str):
            public_key_data = public_key_data.encode("utf-8")

        if not isinstance(public_key_data, (bytes, bytearray)):
            raise TypeError(
                f"Kyber public key must be str or bytes-like, not "
                f"{type(public_key_data).__name__}."
            )

        # validate=True is the whole point: it makes a key containing
        # characters outside the Base64 alphabet an error instead of
        # something quietly discarded. binascii.Error is itself a
        # ValueError subclass; it is re-raised with context so the
        # message names the actual problem.
        try:
            decoded = base64.b64decode(public_key_data, validate=True)
        except binascii.Error as error:
            raise ValueError(
                f"Kyber public key is not valid Base64: {error}"
            ) from error

        if len(decoded) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"Kyber public key must decode to exactly "
                f"{ML_KEM_768_PUBLIC_KEY_BYTES} bytes "
                f"(ML-KEM-768 encapsulation key); got {len(decoded)}."
            )

        return decoded

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