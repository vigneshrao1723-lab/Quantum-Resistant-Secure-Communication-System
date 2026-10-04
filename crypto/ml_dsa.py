"""
ML-DSA Signing Module

Handles ML-DSA-65 (FIPS 204) key generation, signing, and verification
-- the post-quantum signature primitive used to authenticate the
origin of key-distribution packets (crypto/key_manager.py::
wrap_key_for_member()'s output), never to authenticate message
content itself (that remains AES-256-GCM, crypto/aes.py, unchanged).

ML-DSA is a signature scheme, not a KEM like ML-KEM/Kyber
(crypto/kyber.py) -- the two are complementary, not interchangeable:
ML-KEM establishes a shared secret between two parties; ML-DSA proves
that a specific party, and only that party, produced a specific piece
of data. This module does not touch, wrap, or duplicate anything
crypto/kyber.py already does.

Backed by this project's existing `cryptography` dependency
(cryptography.hazmat.primitives.asymmetric.mldsa), confirmed present
and fully functional in the installed environment (cryptography
49.0.0) by direct, hands-on verification -- not assumed from
documentation. No new dependency was introduced for this module.

ML-DSA-65 targets NIST Security Level 3, matching ML-KEM-768's own
security level -- a deliberate, consistent pairing.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

# Size, in bytes, of an ML-DSA-65 public key. Confirmed empirically
# (MLDSA65PublicKey.public_bytes_raw()), not taken from documentation
# alone. Used by import_public_key() to reject malformed key material
# at the point it enters this process, mirroring crypto/kyber.py::
# KyberKEM.import_public_key()'s exact-length-check convention (D6.5
# -- Public-Key Input Validation).
ML_DSA_65_PUBLIC_KEY_BYTES = 1952

# Size, in bytes, of an ML-DSA-65 private key's raw SEED (not an
# expanded private key -- cryptography's private_bytes_raw() returns
# the 32-byte seed FIPS 204 private keys are canonically derived from,
# confirmed empirically). Small and stable to persist, unlike a fully
# expanded private key would be.
ML_DSA_65_PRIVATE_SEED_BYTES = 32

# Size, in bytes, of an ML-DSA-65 signature. Confirmed empirically to
# be FIXED regardless of message content or length (tested against
# empty, single-byte, 1000-byte, 50000-byte, and full-byte-range
# messages, all producing exactly this length) -- unlike a DER-encoded
# classical signature (e.g. ECDSA), which is variable-length. Used by
# verify() to reject a malformed signature before ever attempting a
# cryptographic operation on it.
ML_DSA_65_SIGNATURE_BYTES = 3309

# Domain-separation context for every signature this application ever
# produces or verifies (Server-Untrusted Identity Verification, key-
# distribution origin authentication). Kept in exactly this one place
# -- every caller reaches it only through MLDSASigner.sign()/.verify(),
# never by passing a context string of their own, so a signature
# produced for this specific purpose can never be misinterpreted as
# valid for some other, future signing context this application might
# add later.
_CONTEXT = b"qrscs-key-distribution-v1"


class MLDSASigner:
    """
    ML-DSA-65 helper class.

    Deliberately thin: every method here does nothing except translate
    between this project's raw-bytes interface (matching crypto/
    kyber.py::KyberKEM's own external contract exactly) and
    `cryptography`'s own ML-DSA object API. No cryptographic logic is
    implemented, re-implemented, or altered here -- key generation,
    signing, and verification are all performed entirely by
    `cryptography`'s own, audited implementation.
    """

    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        """
        Generate an ML-DSA-65 key pair.

        public_key  -> verification key (shared with others)
        private_key -> signing key (kept secret)
        """

        self.private_key = mldsa.MLDSA65PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def export_public_key(self):
        """
        Export this instance's public key as raw bytes, ready for a
        caller to base64-encode for wire transport or persistence --
        matching how storage/secure_key_store.py already base64-
        encodes crypto/kyber.py's raw encapsulation_key/
        decapsulation_key attributes itself, at the persistence
        boundary, rather than expecting the crypto primitive to know
        about base64 at all.
        """

        return self.public_key.public_bytes_raw()

    def export_private_key(self):
        """
        Export this instance's private key as its raw 32-byte seed --
        the canonical, minimal representation this key can be
        losslessly reconstructed from (see import_private_key()).
        """

        return self.private_key.private_bytes_raw()

    def import_private_key(self, raw):
        """
        Reconstruct this instance's keypair from a previously
        exported, persisted seed -- the signing counterpart of
        crypto/kyber.py::KyberKEM's direct encapsulation_key/
        decapsulation_key assignment in load_or_create_kyber_keypair().
        Sets both self.private_key and self.public_key (the public key
        is always re-derivable from the seed, confirmed empirically:
        the reconstructed private key's own .public_key() output is
        byte-for-byte identical to the original public key).

        Raises:
            TypeError  -- ``raw`` is neither bytes nor bytes-like.
            ValueError -- ``raw`` is not exactly
                          ML_DSA_65_PRIVATE_SEED_BYTES long, or is
                          not a well-formed seed.
        """

        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(
                f"ML-DSA private key seed must be bytes-like, not "
                f"{type(raw).__name__}."
            )

        if len(raw) != ML_DSA_65_PRIVATE_SEED_BYTES:
            raise ValueError(
                f"ML-DSA private key seed must be exactly "
                f"{ML_DSA_65_PRIVATE_SEED_BYTES} bytes; got {len(raw)}."
            )

        try:
            self.private_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(raw))
        except ValueError as error:
            raise ValueError(
                f"ML-DSA private key seed is not well-formed: {error}"
            ) from error

        self.public_key = self.private_key.public_key()

    @staticmethod
    def import_public_key(raw):
        """
        Validate a peer's raw ML-DSA public key before it is trusted
        anywhere in this process (Server-Untrusted Identity
        Verification -- key-distribution origin authentication),
        mirroring crypto/kyber.py::KyberKEM.import_public_key()'s
        exact validation shape and reasoning: a malformed key must be
        rejected here, at the boundary where untrusted remote key
        material first enters this process, rather than reaching
        verify() and failing there in a way that could be confused
        with "the signature was merely wrong."

        Deliberately raw bytes, not base64: unlike KyberKEM's
        equivalent (which decodes a base64 wire string), this
        project's key-distribution packets carry the ML-DSA public key
        already base64-decoded by the caller before this is reached --
        keeping this class's contract uniformly raw-bytes-in,
        raw-bytes-out.

        Returns the validated raw bytes unchanged (not a key object --
        this class never leaks `cryptography`'s own types across its
        boundary; verify() reconstructs a real key object internally,
        exactly when it needs one).

        Raises:
            TypeError  -- input is not bytes-like.
            ValueError -- input is not exactly
                          ML_DSA_65_PUBLIC_KEY_BYTES long, or the
                          library itself rejects it as malformed.
        """

        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(
                f"ML-DSA public key must be bytes-like, not "
                f"{type(raw).__name__}."
            )

        if len(raw) != ML_DSA_65_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"ML-DSA public key must be exactly "
                f"{ML_DSA_65_PUBLIC_KEY_BYTES} bytes; got {len(raw)}."
            )

        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(bytes(raw))
        except ValueError as error:
            raise ValueError(
                f"ML-DSA public key is not well-formed: {error}"
            ) from error

        return bytes(raw)

    def sign(self, message):
        """
        Sign ``message`` (already-canonicalized bytes -- this method
        performs no canonicalization of its own; see the Phase-9
        canonical-envelope design, applied by callers before this is
        reached) with this instance's private key, under this
        application's single, fixed signing context (_CONTEXT).

        Raises:
            TypeError   -- ``message`` is not bytes-like.
            ValueError  -- no private key is available yet (generate_
                           keys()/import_private_key() was never
                           called).
        """

        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(
                f"Message to sign must be bytes-like, not "
                f"{type(message).__name__}."
            )

        if self.private_key is None:
            raise ValueError(
                "No ML-DSA private key available; call generate_keys() "
                "or import_private_key() first."
            )

        return self.private_key.sign(bytes(message), _CONTEXT)

    @staticmethod
    def verify(message, signature, public_key):
        """
        Verify ``signature`` over ``message`` under ``public_key``
        (raw bytes -- validated the same way import_public_key()
        does), using this application's single, fixed signing context
        (_CONTEXT).

        Deliberately never lets malformed network input crash a
        caller (e.g. the receiver thread): a well-formed public key
        and a well-formed signature that simply do not match return
        False -- they never raise. Only a structurally malformed
        input (wrong type, wrong length) raises, exactly mirroring
        crypto/kyber.py's own established convention (a data error
        describing untrusted input, never a bug in this codebase, and
        therefore safe for a caller to catch narrowly) and this
        project's own already-established security-critical
        convention (see client/session.py::handle_session_key()'s
        algorithm-mismatch hardening and crypto/key_manager.py::
        wrap_key_for_member()'s ValueError/TypeError-only contract).

        Returns:
            True  -- the signature is valid for this exact message,
                     under this exact public key, in this exact
                     context.
            False -- the signature does not verify (wrong message,
                     wrong key, wrong context, or a tampered
                     signature) -- never raised for this case.

        Raises:
            TypeError  -- ``message``, ``signature``, or
                          ``public_key`` is not bytes-like.
            ValueError -- ``public_key`` or ``signature`` is not the
                          correct fixed length for ML-DSA-65, or
                          ``public_key`` does not decode to a
                          well-formed key.
        """

        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(
                f"Message to verify must be bytes-like, not "
                f"{type(message).__name__}."
            )

        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError(
                f"Signature must be bytes-like, not "
                f"{type(signature).__name__}."
            )

        if len(signature) != ML_DSA_65_SIGNATURE_BYTES:
            raise ValueError(
                f"ML-DSA signature must be exactly "
                f"{ML_DSA_65_SIGNATURE_BYTES} bytes; got {len(signature)}."
            )

        validated_public_key = MLDSASigner.import_public_key(public_key)

        public_key_object = mldsa.MLDSA65PublicKey.from_public_bytes(
            validated_public_key
        )

        try:
            public_key_object.verify(bytes(signature), bytes(message), _CONTEXT)
        except InvalidSignature:
            return False

        return True
