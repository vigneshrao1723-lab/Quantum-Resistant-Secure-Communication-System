# Vendored Cryptography (Phase 15 -- Web Interoperability)

These files are unmodified* redistributions of real, independently
published, audited cryptography libraries by Paul Miller
(paulmillr.com), all MIT-licensed. Nothing in this directory is a
reimplementation, mock, or simplified stand-in for a cryptographic
primitive -- see the project's own STEP 3 rule ("Do NOT implement
cryptographic algorithms from scratch").

| File | Source package | Version | Provides |
|---|---|---|---|
| `pq-ml-kem.js` | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) | 0.7.1 | ML-KEM-768 (FIPS 203) |
| `pq-ml-dsa.js` | `@noble/post-quantum` | 0.7.1 | ML-DSA-65 (FIPS 204) |
| `ciphers-aes.js` | [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) | 2.0.1 | AES-256-GCM |
| `hashes-sha3.js`, `hashes-utils.js` | [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) | 2.4.0 | SHA3/SHAKE + shared utilities (dependency of the above) |
| `curves-fft.js`, `curves-utils.js` | [`@noble/curves`](https://github.com/paulmillr/noble-curves) | 2.4.0 | NTT/FFT + shared utilities (dependency of `pq-ml-kem.js`/`pq-ml-dsa.js`) |

\* "Unmodified" means the cryptographic logic itself: these are
jsDelivr's own `+esm` bundled build of each package (Rollup + esbuild,
jsDelivr's standard, publicly documented build service) -- the same
bytes any web page loading `https://cdn.jsdelivr.net/npm/<pkg>/+esm`
would receive. They are vendored here (fetched once, committed as
static files) rather than fetched from a CDN at page-load time so the
web client has no runtime dependency on jsDelivr's availability and so
`web/client/index.html`'s import map can resolve every crypto import
to a local, reviewable file.

## Reproducing this vendoring

```bash
curl -L "https://cdn.jsdelivr.net/npm/@noble/post-quantum@0.7.1/ml-kem.js/+esm" -o pq-ml-kem.js
curl -L "https://cdn.jsdelivr.net/npm/@noble/post-quantum@0.7.1/ml-dsa.js/+esm" -o pq-ml-dsa.js
curl -L "https://cdn.jsdelivr.net/npm/@noble/hashes@2.4.0/sha3.js/+esm" -o hashes-sha3.js
curl -L "https://cdn.jsdelivr.net/npm/@noble/hashes@2.4.0/utils.js/+esm" -o hashes-utils.js
curl -L "https://cdn.jsdelivr.net/npm/@noble/curves@2.4.0/abstract/fft.js/+esm" -o curves-fft.js
curl -L "https://cdn.jsdelivr.net/npm/@noble/curves@2.4.0/utils.js/+esm" -o curves-utils.js
curl -L "https://cdn.jsdelivr.net/npm/@noble/ciphers@2.0.1/aes.js/+esm" -o ciphers-aes.js
```

## Correctness, not just provenance

Provenance alone is not proof these files behave correctly against
THIS project's own Python implementation. See
`tests/test_web_client_crypto_interop.py`, which actually executes
these exact files (via a real JavaScript engine, `quickjs`, run from
Python -- see `tests/web_crypto_test_support.py`) and proves
byte-level interoperability against `crypto/kyber.py`, `crypto/
ml_dsa.py`, and `crypto/aes.py` in both directions.
