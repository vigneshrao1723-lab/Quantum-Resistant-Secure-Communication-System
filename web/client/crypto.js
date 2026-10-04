// Phase 15 -- Web Interoperability, Stage 1.
//
// Cryptographic core for the web client. Every primitive here is the
// real, vendored, unmodified library code proven interoperable with
// this project's Python implementation in
// tests/test_web_client_crypto_interop.py (ML-KEM-768, ML-DSA-65,
// AES-256-GCM) -- nothing here is a from-scratch cryptographic
// implementation. See web/client/vendor/VENDOR.md for provenance and
// docs/architecture/web_interoperability.md for the full design.
//
// Canonical byte encodings below are copied field-for-field from
// their Python originals (crypto/identity_protocol.py,
// crypto/group_key_protocol.py, crypto/message_protocol.py,
// crypto/key_manager.py::fingerprint_combined_identity()) -- NOT
// reinvented. A signature produced here must verify under the exact
// same bytes Python would reconstruct, or the two sides could never
// interoperate; that is exactly what
// tests/test_web_client_crypto_interop.py exists to prove.

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { gcm as aesGcm } from "@noble/ciphers/aes.js";

// crypto/ml_dsa.py::_CONTEXT -- the one, fixed ML-DSA signing context
// this entire application uses, regardless of which of the four
// signed-payload purposes below is being signed. Must match exactly,
// or every signature this client ever produces would be rejected.
const ML_DSA_CONTEXT = new TextEncoder().encode("qrscs-key-distribution-v1");

// The four domain-separation purpose constants, one per signed
// payload type -- crypto/identity_protocol.py, crypto/
// message_protocol.py, crypto/group_key_protocol.py. Only these three
// are needed for the Stage-1 minimal flow (no RSA session-key path --
// this client is Kyber/ML-KEM-only, matching the project's own
// default algorithm).
const IDENTITY_PAYLOAD_PURPOSE = new TextEncoder().encode("qrscs-public-identity-v1");
const MESSAGE_PAYLOAD_PURPOSE = new TextEncoder().encode("qrscs-message-v1");
// Continued Phase 19.24 -- Message Lifecycle Events receiver-side
// verification. Mirrors crypto/message_protocol.py::EDIT_PAYLOAD_
// PURPOSE/REACTION_PAYLOAD_PURPOSE exactly -- distinct domain-
// separation tags so an edit/reaction signature can never be confused
// with an ordinary chat message's, or with each other.
const EDIT_PAYLOAD_PURPOSE = new TextEncoder().encode("qrscs-edit-v1");
const REACTION_PAYLOAD_PURPOSE = new TextEncoder().encode("qrscs-reaction-v1");
const GROUP_KEY_PAYLOAD_PURPOSE = new TextEncoder().encode("qrscs-group-key-v1");

// Phase 18 Step 8 -- Web Multi-Device Identity: crypto/device_
// protocol.py's own two purpose constants + four per-operation
// suffixes, mirrored field-for-field (see canonicalDevice*Payload()
// below). DEVICE_PAYLOAD_PURPOSE covers account-management
// (enroll/authorize/revoke/session_bind, disambiguated from each
// other only by the appended op suffix); DEVICE_KEY_SYNC_PAYLOAD_
// PURPOSE is a genuinely separate top-level purpose for key-delivery
// packets, exactly like the Python module's own docstring explains.
const DEVICE_PAYLOAD_PURPOSE = new TextEncoder().encode("qrscs-device-v1");
const DEVICE_KEY_SYNC_PAYLOAD_PURPOSE = new TextEncoder().encode("qrscs-device-key-sync-v1");
const OP_ENROLL = new TextEncoder().encode("enroll");
const OP_AUTHORIZE = new TextEncoder().encode("authorize");
const OP_REVOKE = new TextEncoder().encode("revoke");
const OP_SESSION_BIND = new TextEncoder().encode("session_bind");

// ---------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------

export function utf8(value) {
  if (value instanceof Uint8Array) return value;
  return new TextEncoder().encode(value ?? "");
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function framed(bytes) {
  return concatBytes(u32be(bytes.length), bytes);
}

// ---------------------------------------------------------------
// Canonical signed-payload constructions
// (crypto/identity_protocol.py, crypto/message_protocol.py,
//  crypto/group_key_protocol.py -- mirrored field-for-field)
// ---------------------------------------------------------------

export function canonicalIdentityPayload(username, kemPublicKeyWire, signingPublicKey) {
  return concatBytes(
    IDENTITY_PAYLOAD_PURPOSE,
    framed(utf8(username)),
    framed(utf8(kemPublicKeyWire)),
    framed(signingPublicKey)
  );
}

export function canonicalGroupKeyPayload(
  sender, conversationId, recipient, encapsulationB64, wrappedKeyB64, epoch
) {
  return concatBytes(
    GROUP_KEY_PAYLOAD_PURPOSE,
    framed(utf8(sender)),
    framed(utf8(conversationId)),
    framed(utf8(recipient)),
    framed(utf8(encapsulationB64 || "")),
    framed(utf8(wrappedKeyB64)),
    u32be(epoch || 1)
  );
}

function canonicalContentMetadata(contentMetadata) {
  // Mirrors crypto/message_protocol.py::_canonical_content_metadata():
  // JSON with sorted keys, no incidental whitespace. This client's
  // Stage-1 messages never carry attachment metadata, so this is
  // always {} in practice -- implemented in full anyway so a future
  // file/image message (out of Stage-1 scope) would already sign
  // correctly against Python's own encoding.
  const obj = contentMetadata || {};
  const keys = Object.keys(obj).sort();
  const sorted = {};
  for (const k of keys) sorted[k] = obj[k];
  return utf8(JSON.stringify(sorted).replace(/\s/g, ""));
}

export function canonicalMessagePayload(
  sender, receiver, conversationId, payloadType, ciphertext, contentMetadata, epoch,
  purpose = MESSAGE_PAYLOAD_PURPOSE
) {
  return concatBytes(
    purpose,
    framed(utf8(sender)),
    framed(utf8(receiver || "")),
    framed(utf8(conversationId || "")),
    framed(utf8(payloadType)),
    framed(utf8(ciphertext)),
    framed(canonicalContentMetadata(contentMetadata)),
    u32be(epoch || 1)
  );
}

export { EDIT_PAYLOAD_PURPOSE, REACTION_PAYLOAD_PURPOSE };

// ---------------------------------------------------------------
// Phase 18 Step 8 -- Web Multi-Device Identity.
// (crypto/device_protocol.py -- mirrored field-for-field; see that
// module's own docstring for what each payload proves and why the
// per-operation suffixes exist.)
// ---------------------------------------------------------------

export function canonicalDeviceEnrollmentPayload(
  username, deviceId, kemPublicKeyWire, mlDsaPublicKey, deviceName, platform
) {
  return concatBytes(
    DEVICE_PAYLOAD_PURPOSE,
    OP_ENROLL,
    framed(utf8(username)),
    framed(utf8(deviceId)),
    framed(utf8(kemPublicKeyWire)),
    framed(mlDsaPublicKey),
    framed(utf8(deviceName || "")),
    framed(utf8(platform || ""))
  );
}

export function canonicalDeviceAuthorizationPayload(
  username, targetDeviceId, targetFingerprint, authorizerDeviceId
) {
  return concatBytes(
    DEVICE_PAYLOAD_PURPOSE,
    OP_AUTHORIZE,
    framed(utf8(username)),
    framed(utf8(targetDeviceId)),
    framed(utf8(targetFingerprint)),
    framed(utf8(authorizerDeviceId))
  );
}

export function canonicalDeviceRevocationPayload(username, targetDeviceId, revokerDeviceId) {
  return concatBytes(
    DEVICE_PAYLOAD_PURPOSE,
    OP_REVOKE,
    framed(utf8(username)),
    framed(utf8(targetDeviceId)),
    framed(utf8(revokerDeviceId))
  );
}

export function canonicalDeviceSessionBindingPayload(username, deviceId, sessionNonce) {
  return concatBytes(
    DEVICE_PAYLOAD_PURPOSE,
    OP_SESSION_BIND,
    framed(utf8(username)),
    framed(utf8(deviceId)),
    framed(utf8(sessionNonce))
  );
}

export function canonicalDeviceKeySyncPayload(
  username, sourceDeviceId, targetDeviceId, targetFingerprint,
  conversationId, epoch, packageType, encapsulationB64, wrappedKeyB64
) {
  return concatBytes(
    DEVICE_KEY_SYNC_PAYLOAD_PURPOSE,
    framed(utf8(username)),
    framed(utf8(sourceDeviceId)),
    framed(utf8(targetDeviceId)),
    framed(utf8(targetFingerprint)),
    framed(utf8(conversationId)),
    u32be(epoch || 1),
    framed(utf8(packageType)),
    framed(utf8(encapsulationB64 || "")),
    framed(utf8(wrappedKeyB64))
  );
}

// ---------------------------------------------------------------
// Combined-identity fingerprint
// (crypto/key_manager.py::fingerprint_combined_identity())
// ---------------------------------------------------------------

export async function fingerprintCombinedIdentity(kemPublicKeyWire, signingPublicKey) {
  const kemBytes = utf8(kemPublicKeyWire);
  const payload = concatBytes(framed(kemBytes), framed(signingPublicKey));
  const digest = new Uint8Array(await window.crypto.subtle.digest("SHA-256", payload));
  const hex = bytesToHex(digest).toUpperCase();
  // Same "AAAA BBBB ..." 4-char-grouped presentation as
  // crypto/key_manager.py::_format_fingerprint().
  return hex.match(/.{1,4}/g).join(" ");
}

// ---------------------------------------------------------------
// ML-DSA-65 (identity + signing)
// ---------------------------------------------------------------

export function generateSigningKeypair() {
  return ml_dsa65.keygen();
}

export function signPayload(secretKey, payloadBytes) {
  return ml_dsa65.sign(payloadBytes, secretKey, { context: ML_DSA_CONTEXT });
}

export function verifyPayload(signature, payloadBytes, publicKey) {
  try {
    return ml_dsa65.verify(signature, payloadBytes, publicKey, { context: ML_DSA_CONTEXT });
  } catch {
    // Mirrors crypto/ml_dsa.py::MLDSASigner.verify()'s own contract:
    // a structurally malformed signature/key is untrusted network
    // input, not a bug -- treated identically to "does not verify".
    return false;
  }
}

// ---------------------------------------------------------------
// ML-KEM-768 (key establishment)
// ---------------------------------------------------------------

export function generateKemKeypair() {
  return ml_kem768.keygen();
}

export function kemEncapsulate(peerPublicKeyRaw) {
  // Returns { cipherText, sharedSecret } -- cipherText must be
  // base64-encoded by the caller before it goes on the wire (matches
  // crypto/kyber.py::KyberKEM.encapsulate()'s own return contract).
  return ml_kem768.encapsulate(peerPublicKeyRaw);
}

export function kemDecapsulate(cipherTextRaw, secretKey) {
  return ml_kem768.decapsulate(cipherTextRaw, secretKey);
}

// ---------------------------------------------------------------
// AES-256-GCM
// (crypto/aes.py's exact wire format: base64(nonce[12]+tag[16]+ciphertext))
// ---------------------------------------------------------------

export function encryptForWire(key, plaintext) {
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const cipher = aesGcm(key, nonce);
  const ciphertextWithTag = cipher.encrypt(utf8(plaintext));
  // @noble/ciphers (like WebCrypto) appends the 16-byte tag to the
  // ciphertext; crypto/aes.py instead puts nonce + tag + ciphertext,
  // tag BEFORE ciphertext -- rearranged here, once, at the wire
  // boundary, exactly as tests/test_web_client_crypto_interop.py's
  // TEST D proves is correct.
  const tag = ciphertextWithTag.slice(-16);
  const ciphertext = ciphertextWithTag.slice(0, -16);
  return bytesToBase64(concatBytes(nonce, tag, ciphertext));
}

export function decryptFromWire(key, wireBase64) {
  const wireBytes = base64ToBytes(wireBase64);
  if (wireBytes.length < 28) {
    throw new Error("Ciphertext too short to contain a valid nonce and authentication tag.");
  }
  const nonce = wireBytes.slice(0, 12);
  const tag = wireBytes.slice(12, 28);
  const ciphertext = wireBytes.slice(28);
  const cipher = aesGcm(key, nonce);
  const plaintextBytes = cipher.decrypt(concatBytes(ciphertext, tag));
  return new TextDecoder().decode(plaintextBytes);
}

export function randomAesKey() {
  return window.crypto.getRandomValues(new Uint8Array(32));
}
