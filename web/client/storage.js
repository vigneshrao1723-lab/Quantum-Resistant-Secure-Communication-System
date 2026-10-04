// Phase 17 -- Web Persistence + Reconnect.
//
// Minimal secure browser persistence for the web client's own
// cryptographic identity, peer-trust state, and established session
// keys -- so a page reload does not look, to every peer who has
// already VERIFIED this browser, like a brand-new device with a
// brand-new key (the Stage-1 gap this phase exists to close; see
// docs/architecture/web_interoperability.md's "Known limitations
// (Stage 1)" and its Phase 17 section for the full design writeup).
//
// SECURITY MODEL -- read before touching this file:
//
//   This is NOT the same security property as the desktop's
//   storage/secure_key_store.py, and this module must never be
//   described as equivalent to it. The differences:
//
//     - The desktop store is a single encrypted FILE, protected by
//       OS file permissions AND a password-derived key (Argon2id),
//       readable only by code that can both reach the file on disk
//       AND derive the right key.
//     - This module is IndexedDB, same-origin-isolated by the
//       browser (a different website's JavaScript cannot read it),
//       encrypted at rest with AES-256-GCM using a key derived (via
//       WebCrypto's native PBKDF2, SHA-256, 210000 iterations -- an
//       OWASP-recommended-range iteration count for PBKDF2-SHA256)
//       from the SAME password the user already typed to log in.
//     - Consequence: any JavaScript that runs on THIS ORIGIN (i.e.
//       an XSS vulnerability in this exact page) can call the same
//       WebCrypto APIs this module calls and, if it can also observe
//       the password (e.g. by reading the password <input> field,
//       which any same-origin script already can), decrypt this
//       store the same way this module does. IndexedDB's origin
//       isolation stops a DIFFERENT site from reading it; it does
//       NOT stop malicious code already running on THIS site. The
//       desktop store's threat model is stronger in that respect
//       (compromising the desktop APP process is a materially higher
//       bar than compromising ONE web page's script context).
//     - Deriving the wrapping key from the login password (rather
//       than a second, separate local passphrase) mirrors the
//       desktop store's own choice to derive its wrapping key from
//       the user's password -- in THAT one specific respect the two
//       designs are similar; in every other respect (storage medium,
//       OS-level protection, primitive choice) they are not, and
//       this module never claims otherwise.
//
//   What is deliberately NEVER persisted here, anywhere: the raw
//   login password itself (used once, in memory, to derive the
//   wrapping key -- never written to IndexedDB); the server's access
//   token/JWT (see web/client/app.js's own comment on this choice --
//   summary: persisting a live bearer credential at rest is a real
//   security trade-off for convenience this phase deliberately does
//   not make, so a page reload still requires re-entering
//   credentials, exactly like the desktop client already does).

const DB_NAME = "qrscs-web-client";
const DB_VERSION = 1;
const STORE_NAME = "identity_state";
const PBKDF2_ITERATIONS = 210000;

function _openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "username" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Failed to open IndexedDB."));
  });
}

async function _deriveWrappingKey(password, saltBytes) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt and persist `stateObject` (already-serializable plain data --
 * see app.js::_serializeState()/_deserializeState() for exactly what
 * goes in it) under `username`, wrapped with a key derived from
 * `password`. Overwrites any previously-persisted state for this same
 * username. Never throws past this function uncaught for a storage
 * failure that should not crash the caller -- callers treat
 * persistence as best-effort (see app.js's own callers: a failed
 * _persistState() logs and continues, it never blocks messaging).
 */
export async function saveEncryptedState(username, password, stateObject) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await _deriveWrappingKey(password, salt);

  const plaintext = new TextEncoder().encode(JSON.stringify(stateObject));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

  const db = await _openDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put({
        username,
        salt: Array.from(salt),
        iv: Array.from(iv),
        ciphertext: Array.from(new Uint8Array(ciphertext)),
        savedAt: Date.now(),
      });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

/**
 * Load and decrypt the state persisted for `username`, using a key
 * derived from `password`. Returns `null` if nothing was persisted
 * for this username, OR if decryption fails (wrong password, or the
 * persisted record is corrupt/tampered) -- a decryption failure is
 * treated exactly like "nothing persisted": the caller falls back to
 * generating a fresh identity, never surfaces raw crypto errors to
 * the user, and never partially applies a state object it could not
 * fully authenticate (AES-GCM's own tag verification is what
 * guarantees "fully decrypts" and "is authentic" are the same check).
 */
export async function loadEncryptedState(username, password) {
  const db = await _openDb();
  let record;
  try {
    record = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).get(username);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }

  if (!record) return null;

  try {
    const salt = new Uint8Array(record.salt);
    const iv = new Uint8Array(record.iv);
    const ciphertext = new Uint8Array(record.ciphertext);
    const key = await _deriveWrappingKey(password, salt);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    // Wrong password, or corrupt/tampered ciphertext -- AES-GCM tag
    // verification failed. Never distinguish the two in the return
    // value (both must fall back to "no usable state"), and never
    // surface the raw WebCrypto error (it carries no useful detail
    // and this is not a place to log anything sensitive).
    return null;
  }
}

/** Explicit wipe, for a user-initiated logout that should also forget
 * this browser's locally-persisted identity/trust state (not wired to
 * the minimal UI by default in this phase -- see app.js's logout(),
 * which deliberately does NOT call this, so an ordinary logout/
 * reconnect keeps the user's peer-verification work intact; this
 * exists for completeness and for tests). */
export async function clearState(username) {
  const db = await _openDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).delete(username);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
