"""
Phase 15 -- Web Interoperability, Stage 1: cryptographic
interoperability proof.

Proves that the actual JavaScript the web client (web/client/) loads
in a browser -- vendored, unmodified @noble/post-quantum (ML-KEM-768,
ML-DSA-65) and @noble/ciphers (AES-256-GCM), see web/client/vendor/
VENDOR.md -- is byte-level interoperable with this project's own
Python implementations (crypto/kyber.py, crypto/ml_dsa.py,
crypto/aes.py), in BOTH directions, for every primitive a client needs
for the minimal secure-messaging flow.

Executed via a real JavaScript engine (quickjs, embedded from Python --
see tests/web_crypto_test_support.py), not mocked and not merely
inspected. No Node.js/browser was available in this project's test
environment (confirmed absent during Phase 15's own investigation);
quickjs is a real, spec-compliant ES2020 engine, and the JS files it
executes here are byte-identical to what web/client/index.html loads
into an actual browser -- see web_crypto_test_support.py's own
docstring for the precise, honest scope of what this does and does not
prove.

Run with:
    pytest tests/test_web_client_crypto_interop.py -v
"""

import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto.aes import AESCipher
from crypto.kyber import KyberKEM
from crypto.ml_dsa import MLDSASigner

from crypto.group_key_protocol import canonical_group_key_payload
from crypto.identity_protocol import canonical_identity_payload
from crypto.message_protocol import canonical_message_payload
from crypto.device_protocol import (
    canonical_device_authorization_payload,
    canonical_device_enrollment_payload,
    canonical_device_key_sync_payload,
    canonical_device_revocation_payload,
    canonical_device_session_binding_payload,
)

from tests.web_crypto_test_support import build_web_crypto_context, load_crypto_js_canonical_helpers

# The one, fixed ML-DSA signing context this whole application ever
# uses (crypto/ml_dsa.py::_CONTEXT) -- the web client must sign/verify
# under the exact same context, or every cross-side signature would
# correctly fail (this IS what domain separation is for), not merely
# fail to interoperate by accident.
ML_DSA_CONTEXT = b"qrscs-key-distribution-v1"


def _js_eval_hex(ctx, js_expr_returning_bytes):
    """Evaluate a JS expression producing a Uint8Array and return it
    as Python bytes, via the hex-string marshalling convention
    web_crypto_test_support.py establishes (quickjs's Python binding
    can only return strings/numbers/booleans across the boundary)."""

    ctx.eval(f"globalThis.__evalResultHex = __bytesToHex({js_expr_returning_bytes});")
    return bytes.fromhex(ctx.eval("__evalResultHex"))


def _js_set_bytes(ctx, name, data: bytes):
    ctx.eval(f"globalThis.{name} = __hexToBytes({data.hex()!r});")


# ========================================================================
# TEST A -- ML-KEM-768: Python public key -> web-client-JS encapsulation
# -> Python decapsulation -> same shared secret (and the reverse).
# ========================================================================


def test_A_ml_kem_python_pubkey_js_encapsulate_python_decapsulate():
    ctx = build_web_crypto_context()

    python_kyber = KyberKEM()
    python_kyber.generate_keys()
    python_public_key_raw = python_kyber.encapsulation_key

    _js_set_bytes(ctx, "__pyPub", python_public_key_raw)
    ctx.eval("globalThis.__enc = ml_kem768.encapsulate(__pyPub);")

    js_ciphertext = _js_eval_hex(ctx, "__enc.cipherText")
    js_shared_secret = _js_eval_hex(ctx, "__enc.sharedSecret")

    assert len(js_ciphertext) == 1088  # FIPS 203 ML-KEM-768 ciphertext size
    assert len(js_shared_secret) == 32

    python_shared_secret = python_kyber.decapsulate(js_ciphertext)

    assert python_shared_secret == js_shared_secret


def test_A_reverse_ml_kem_js_pubkey_python_encapsulate_js_decapsulate():
    ctx = build_web_crypto_context()

    ctx.eval("globalThis.__jskp = ml_kem768.keygen();")
    js_public_key = _js_eval_hex(ctx, "__jskp.publicKey")

    assert len(js_public_key) == 1184  # FIPS 203 ML-KEM-768 public key size

    python_kyber = KyberKEM()
    python_ciphertext_b64, python_shared_secret = python_kyber.encapsulate(js_public_key)
    python_ciphertext_raw = base64.b64decode(python_ciphertext_b64)

    _js_set_bytes(ctx, "__pyCt", python_ciphertext_raw)
    ctx.eval("globalThis.__jsDec = ml_kem768.decapsulate(__pyCt, __jskp.secretKey);")
    js_recovered_secret = _js_eval_hex(ctx, "__jsDec")

    assert python_shared_secret == js_recovered_secret


# ========================================================================
# TEST B -- ML-DSA-65: Python-signed message verified by web-client JS.
# ========================================================================


def test_B_ml_dsa_python_signs_js_verifies():
    ctx = build_web_crypto_context()

    signer = MLDSASigner()
    signer.generate_keys()
    python_public_key = signer.export_public_key()

    message = b"cross-language ML-DSA interop message (Python -> JS)"
    python_signature = signer.sign(message)

    assert len(python_public_key) == 1952  # FIPS 204 ML-DSA-65 public key size
    assert len(python_signature) == 3309  # FIPS 204 ML-DSA-65 signature size

    _js_set_bytes(ctx, "__msg", message)
    _js_set_bytes(ctx, "__ctx", ML_DSA_CONTEXT)
    _js_set_bytes(ctx, "__pyPub", python_public_key)
    _js_set_bytes(ctx, "__pySig", python_signature)

    ctx.eval(
        "globalThis.__verified = "
        "ml_dsa65.verify(__pySig, __msg, __pyPub, {context: __ctx});"
    )

    assert ctx.eval("__verified") is True


def test_B_tampered_message_is_rejected_by_js_verification():
    """The same signature, over a DIFFERENT message, must fail --
    proving the JS side is actually checking the signature, not
    trivially returning True."""

    ctx = build_web_crypto_context()

    signer = MLDSASigner()
    signer.generate_keys()
    python_public_key = signer.export_public_key()

    message = b"the real message"
    tampered_message = b"a different message"
    python_signature = signer.sign(message)

    _js_set_bytes(ctx, "__msg", tampered_message)
    _js_set_bytes(ctx, "__ctx", ML_DSA_CONTEXT)
    _js_set_bytes(ctx, "__pyPub", python_public_key)
    _js_set_bytes(ctx, "__pySig", python_signature)

    ctx.eval(
        "globalThis.__verified = "
        "ml_dsa65.verify(__pySig, __msg, __pyPub, {context: __ctx});"
    )

    assert ctx.eval("__verified") is False


# ========================================================================
# TEST C -- ML-DSA-65: web-client-JS-signed message verified by Python.
# ========================================================================


def test_C_ml_dsa_js_signs_python_verifies():
    ctx = build_web_crypto_context()

    ctx.eval("globalThis.__dkp = ml_dsa65.keygen();")
    js_public_key = _js_eval_hex(ctx, "__dkp.publicKey")

    message = b"cross-language ML-DSA interop message (JS -> Python)"

    _js_set_bytes(ctx, "__msg", message)
    _js_set_bytes(ctx, "__ctx", ML_DSA_CONTEXT)
    ctx.eval("globalThis.__sig = ml_dsa65.sign(__msg, __dkp.secretKey, {context: __ctx});")

    js_signature = _js_eval_hex(ctx, "__sig")

    assert len(js_public_key) == 1952
    assert len(js_signature) == 3309

    python_verified = MLDSASigner.verify(message, js_signature, js_public_key)

    assert python_verified is True


def test_C_tampered_signature_is_rejected_by_python_verification():
    ctx = build_web_crypto_context()

    ctx.eval("globalThis.__dkp = ml_dsa65.keygen();")
    js_public_key = _js_eval_hex(ctx, "__dkp.publicKey")

    message = b"a message the JS side genuinely signed"

    _js_set_bytes(ctx, "__msg", message)
    _js_set_bytes(ctx, "__ctx", ML_DSA_CONTEXT)
    ctx.eval("globalThis.__sig = ml_dsa65.sign(__msg, __dkp.secretKey, {context: __ctx});")

    js_signature = bytearray(_js_eval_hex(ctx, "__sig"))
    js_signature[0] ^= 0xFF  # flip a bit -- must invalidate the signature

    assert MLDSASigner.verify(message, bytes(js_signature), js_public_key) is False


# ========================================================================
# TEST D -- AES-256-GCM: web-client-JS-encrypted payload decrypted by
# Python (crypto/aes.py's exact wire format: nonce[12] + tag[16] +
# ciphertext, base64).
# ========================================================================


def test_D_aes_gcm_js_encrypts_python_decrypts():
    ctx = build_web_crypto_context()

    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = "hello from the web client -- AES-256-GCM interop"

    _js_set_bytes(ctx, "__key", key)
    _js_set_bytes(ctx, "__nonce", nonce)
    ctx.eval(
        f"globalThis.__pt = __hexToBytes({plaintext.encode('utf-8').hex()!r});"
        "globalThis.__cipher = __aesGcm(__key, __nonce);"
        "globalThis.__ct = __cipher.encrypt(__pt);"
    )
    js_ciphertext_with_tag = _js_eval_hex(ctx, "__ct")

    # @noble/ciphers appends the 16-byte GCM tag to the ciphertext
    # (the same layout WebCrypto's AES-GCM uses); crypto/aes.py's own
    # wire format instead puts nonce + tag + ciphertext, tag BEFORE
    # ciphertext -- this rearrangement is exactly what the real web
    # client's crypto.js does before putting a packet on the wire (see
    # web/client/crypto.js::encryptForWire()), reproduced here so this
    # test proves the same adaptation the shipped client performs.
    tag = js_ciphertext_with_tag[-16:]
    ciphertext = js_ciphertext_with_tag[:-16]
    wire_bytes = nonce + tag + ciphertext
    wire_b64 = base64.b64encode(wire_bytes).decode("ascii")

    decrypted = AESCipher(key).decrypt(wire_b64)

    assert decrypted == plaintext


def test_D_tampered_ciphertext_fails_python_gcm_authentication():
    ctx = build_web_crypto_context()

    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = "integrity must be enforced, not merely confidentiality"

    _js_set_bytes(ctx, "__key", key)
    _js_set_bytes(ctx, "__nonce", nonce)
    ctx.eval(
        f"globalThis.__pt = __hexToBytes({plaintext.encode('utf-8').hex()!r});"
        "globalThis.__cipher = __aesGcm(__key, __nonce);"
        "globalThis.__ct = __cipher.encrypt(__pt);"
    )
    js_ciphertext_with_tag = bytearray(_js_eval_hex(ctx, "__ct"))
    js_ciphertext_with_tag[0] ^= 0xFF  # flip a ciphertext bit

    tag = bytes(js_ciphertext_with_tag[-16:])
    ciphertext = bytes(js_ciphertext_with_tag[:-16])
    wire_b64 = base64.b64encode(nonce + tag + ciphertext).decode("ascii")

    import pytest

    with pytest.raises(ValueError):
        AESCipher(key).decrypt(wire_b64)


# ========================================================================
# TEST E -- AES-256-GCM: Python-encrypted payload (crypto/aes.py's real
# wire format) decrypted by web-client JS.
# ========================================================================


def test_E_aes_gcm_python_encrypts_js_decrypts():
    ctx = build_web_crypto_context()

    key = os.urandom(32)
    plaintext = "hello from the desktop client -- AES-256-GCM interop"

    wire_b64 = AESCipher(key).encrypt(plaintext)
    wire_bytes = base64.b64decode(wire_b64)

    nonce = wire_bytes[:12]
    tag = wire_bytes[12:28]
    ciphertext = wire_bytes[28:]

    # The reverse of TEST D's rearrangement: web/client/crypto.js's
    # decryptFromWire() parses nonce+tag+ciphertext off the wire and
    # re-appends the tag to the ciphertext, since that is the layout
    # @noble/ciphers (and WebCrypto) expect for decryption.
    _js_set_bytes(ctx, "__key", key)
    _js_set_bytes(ctx, "__nonce", nonce)
    _js_set_bytes(ctx, "__ctWithTag", ciphertext + tag)

    ctx.eval(
        "globalThis.__cipher2 = __aesGcm(__key, __nonce);"
        "globalThis.__decrypted = __cipher2.decrypt(__ctWithTag);"
    )
    js_decrypted_hex = ctx.eval("__bytesToHex(__decrypted)")

    assert bytes.fromhex(js_decrypted_hex).decode("utf-8") == plaintext


# ========================================================================
# Canonical signed-payload byte-encoding parity.
#
# Tests A-E above prove the underlying primitives (ML-KEM/ML-DSA/AES)
# interoperate on ARBITRARY bytes. They do NOT, by themselves, prove
# web/client/crypto.js's own canonical*Payload() functions build the
# EXACT same bytes crypto/identity_protocol.py / crypto/
# group_key_protocol.py / crypto/message_protocol.py do -- an off-by-
# one in field order or length-prefix encoding here would silently
# break real interoperability even though every primitive above works
# perfectly. These tests load the REAL web/client/crypto.js (not a
# reimplementation -- see web_crypto_test_support.py::
# load_crypto_js_canonical_helpers()'s own docstring) and compare its
# output, byte-for-byte, against the real Python functions.
# ========================================================================


def _crypto_js_context():
    ctx = build_web_crypto_context()
    load_crypto_js_canonical_helpers(ctx)
    return ctx


def test_canonical_identity_payload_matches_python_byte_for_byte():
    ctx = _crypto_js_context()

    username = "alice"
    kem_public_key_wire = base64.b64encode(os.urandom(1184)).decode("ascii")
    signing_public_key = os.urandom(1952)

    _js_set_bytes(ctx, "__signingKey", signing_public_key)
    ctx.eval(
        f"globalThis.__p = canonicalIdentityPayload("
        f"{username!r}, {kem_public_key_wire!r}, __signingKey);"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_identity_payload(username, kem_public_key_wire, signing_public_key)

    assert js_payload == python_payload


def test_canonical_group_key_payload_matches_python_byte_for_byte():
    ctx = _crypto_js_context()

    sender, conversation_id, recipient = "alice", str(base64.b16encode(os.urandom(8))), "bob"
    encapsulation_b64 = base64.b64encode(os.urandom(1088)).decode("ascii")
    wrapped_key_b64 = base64.b64encode(os.urandom(60)).decode("ascii")
    epoch = 7

    ctx.eval(
        f"globalThis.__p = canonicalGroupKeyPayload("
        f"{sender!r}, {conversation_id!r}, {recipient!r}, "
        f"{encapsulation_b64!r}, {wrapped_key_b64!r}, {epoch});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_group_key_payload(
        sender, conversation_id, recipient, encapsulation_b64, wrapped_key_b64, epoch
    )

    assert js_payload == python_payload


def test_canonical_message_payload_direct_matches_python_byte_for_byte():
    """A direct message: receiver set, conversation_id empty."""

    ctx = _crypto_js_context()

    sender, receiver = "alice", "bob"
    ciphertext_b64 = base64.b64encode(os.urandom(48)).decode("ascii")
    epoch = 3

    ctx.eval(
        f"globalThis.__p = canonicalMessagePayload("
        f"{sender!r}, {receiver!r}, null, 'text', {ciphertext_b64!r}, null, {epoch});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_message_payload(
        sender, receiver, None, "text", ciphertext_b64, None, epoch
    )

    assert js_payload == python_payload


def test_canonical_message_payload_group_matches_python_byte_for_byte():
    """A group message: conversation_id set, receiver empty -- the
    OTHER field-emptiness combination, proving the two are bound as
    genuinely separate fields (see canonical_message_payload()'s own
    docstring on why collapsing them would be unsafe)."""

    ctx = _crypto_js_context()

    sender, conversation_id = "alice", str(base64.b16encode(os.urandom(8)))
    ciphertext_b64 = base64.b64encode(os.urandom(48)).decode("ascii")
    epoch = 1

    ctx.eval(
        f"globalThis.__p = canonicalMessagePayload("
        f"{sender!r}, null, {conversation_id!r}, 'text', {ciphertext_b64!r}, null, {epoch});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_message_payload(
        sender, None, conversation_id, "text", ciphertext_b64, None, epoch
    )

    assert js_payload == python_payload


# ========================================================================
# Phase 18 Step 8 -- Web Multi-Device Identity: crypto/device_protocol.py's
# five canonical payloads, mirrored field-for-field in crypto.js
# (canonicalDeviceEnrollmentPayload/canonicalDeviceAuthorizationPayload/
# canonicalDeviceRevocationPayload/canonicalDeviceSessionBindingPayload/
# canonicalDeviceKeySyncPayload) -- same byte-for-byte proof pattern as
# the three payloads above.
# ========================================================================


def test_canonical_device_enrollment_payload_matches_python_byte_for_byte():
    ctx = _crypto_js_context()

    username, device_id = "alice", str(base64.b16encode(os.urandom(8)))
    kem_public_key_wire = base64.b64encode(os.urandom(1184)).decode("ascii")
    ml_dsa_public_key = os.urandom(1952)
    device_name, platform = "Alice's Laptop", "linux"

    _js_set_bytes(ctx, "__mlDsaKey", ml_dsa_public_key)
    ctx.eval(
        f"globalThis.__p = canonicalDeviceEnrollmentPayload("
        f"{username!r}, {device_id!r}, {kem_public_key_wire!r}, __mlDsaKey, "
        f"{device_name!r}, {platform!r});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_device_enrollment_payload(
        username, device_id, kem_public_key_wire, ml_dsa_public_key, device_name, platform
    )

    assert js_payload == python_payload


def test_canonical_device_authorization_payload_matches_python_byte_for_byte():
    ctx = _crypto_js_context()

    username = "alice"
    target_device_id = str(base64.b16encode(os.urandom(8)))
    target_fingerprint = "AAAA BBBB CCCC DDDD"
    authorizer_device_id = str(base64.b16encode(os.urandom(8)))

    ctx.eval(
        f"globalThis.__p = canonicalDeviceAuthorizationPayload("
        f"{username!r}, {target_device_id!r}, {target_fingerprint!r}, {authorizer_device_id!r});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_device_authorization_payload(
        username, target_device_id, target_fingerprint, authorizer_device_id
    )

    assert js_payload == python_payload


def test_canonical_device_revocation_payload_matches_python_byte_for_byte():
    ctx = _crypto_js_context()

    username = "alice"
    target_device_id = str(base64.b16encode(os.urandom(8)))
    revoker_device_id = str(base64.b16encode(os.urandom(8)))

    ctx.eval(
        f"globalThis.__p = canonicalDeviceRevocationPayload("
        f"{username!r}, {target_device_id!r}, {revoker_device_id!r});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_device_revocation_payload(username, target_device_id, revoker_device_id)

    assert js_payload == python_payload


def test_canonical_device_session_binding_payload_matches_python_byte_for_byte():
    ctx = _crypto_js_context()

    username = "alice"
    device_id = str(base64.b16encode(os.urandom(8)))
    session_nonce = str(base64.b16encode(os.urandom(16)))

    ctx.eval(
        f"globalThis.__p = canonicalDeviceSessionBindingPayload("
        f"{username!r}, {device_id!r}, {session_nonce!r});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_device_session_binding_payload(username, device_id, session_nonce)

    assert js_payload == python_payload


def test_canonical_device_key_sync_payload_matches_python_byte_for_byte():
    ctx = _crypto_js_context()

    username = "alice"
    source_device_id = str(base64.b16encode(os.urandom(8)))
    target_device_id = str(base64.b16encode(os.urandom(8)))
    target_fingerprint = "AAAA BBBB CCCC DDDD"
    conversation_id = str(base64.b16encode(os.urandom(8)))
    epoch = 3
    package_type = "direct"
    encapsulation_b64 = base64.b64encode(os.urandom(1088)).decode("ascii")
    wrapped_key_b64 = base64.b64encode(os.urandom(60)).decode("ascii")

    ctx.eval(
        f"globalThis.__p = canonicalDeviceKeySyncPayload("
        f"{username!r}, {source_device_id!r}, {target_device_id!r}, {target_fingerprint!r}, "
        f"{conversation_id!r}, {epoch}, {package_type!r}, {encapsulation_b64!r}, {wrapped_key_b64!r});"
    )
    js_payload = _js_eval_hex(ctx, "__p")

    python_payload = canonical_device_key_sync_payload(
        username, source_device_id, target_device_id, target_fingerprint,
        conversation_id, epoch, package_type, encapsulation_b64, wrapped_key_b64,
    )

    assert js_payload == python_payload
