# TLS Transport Security

Introduced in the TLS Transport Security phase, immediately after the
sender-authentication and group-membership-authorization hardening
phase, in two stages: Stage 1 built and proved the TLS layer in
isolation (`security/tls.py`, certificate generation, the dedicated
`tests/test_tls_transport.py` suite); Stage 2 (this revision) wires it
into the real application — `server/server.py` and
`client/session.py` — so the actual client and server are TLS-only,
not merely provably-capable-of-TLS in a parallel test harness. This
document explains why TLS was added, how it's wired in, how the
development certificate works, and — most importantly — how it
relates to the application's existing Kyber/AES-256-GCM end-to-end
encryption. **TLS does not provide end-to-end message encryption.**
See "TLS + Kyber/AES relationship" below.

## TLS infrastructure vs. production wiring vs. test-only helpers

Three distinct layers, so it's always clear which file is responsible
for what:

1. **Infrastructure** (`security/tls.py`) — the single authoritative
   implementation of TLS context construction
   (`build_server_context()`, `build_client_context()`). Contains all
   certificate/verification configuration. Nothing else in the
   codebase builds an `ssl.SSLContext` for real client/server use.
2. **Production wiring** (`server/server.py`, `client/session.py`) —
   the two, and only two, places `security/tls.py`'s functions are
   called for the actual application:
   - `server/server.py::start_server()` calls `build_server_context()`
     once at startup and passes it to `_serve_client()`, the function
     used as every accepted connection's per-thread target.
   - `client/session.py::ClientSession.connect()` calls
     `build_client_context()` and wraps the socket before the method
     returns.
3. **Test-only helpers** (`tests/tls_test_support.py`) — thin wrappers
   around the *same* `security/tls.py` functions
   (`wrap_server_socket()`, `wrap_client_socket()`,
   `serve_tls_client()`, `serve_once_with_context()`), used by every
   socket-based test so none of them construct their own `SSLContext`.
   Contains no independent certificate or verification logic.

## Why TLS was added

Before this phase, the client-server connection was plain TCP. The
architecture audit that preceded this phase found that while message
*content* was already protected end-to-end (Kyber key exchange +
AES-256-GCM), the *transport carrying that key exchange* had no
protection of its own: the JWT access token (`create_auth_packet`) and
the public-key exchange (`create_public_key_packet`) both travelled in
cleartext. A network-position attacker — not just a curious server —
could observe or tamper with that exchange, undermining the guarantee
the post-quantum key exchange was supposed to provide.

TLS closes that gap: it authenticates the server, and encrypts and
integrity-protects everything on the wire, including the JWT and the
public-key exchange, before either is ever sent.

## Connection flow

```
Server (server/server.py)                  Client (client/session.py)
--------------------------                  --------------------------
start_server():                             ClientSession.connect():
  build_server_context()  (once, startup)     raw_socket.connect((HOST, PORT))
  │                                             │
  ▼                                             ▼
accept() (unchanged loop)                    build_client_context()
  │                                             │  (security/tls.py)
  ▼                                             ▼
spawn thread: _serve_client(...)             tls_context.wrap_socket(...)
  │                                             -- handshake + certificate
  ▼                                             verification + SAN match
tls_context.wrap_socket(                       │
    client_socket, server_side=True)           ▼ (raises ssl.SSLError on
  │  -- on failure: log, close socket,             failure; raw_socket closed,
  │     return (handle_client() never called)      self.client_socket untouched)
  ▼                                             ▼
handle_client(state, tls_socket, addr)       self.client_socket = tls_socket
  (server/client_handler.py -- UNCHANGED)        │
  │                                              ▼
  ▼                                            login()           -- JWT, over TLS
utils/network.py send/receive                 send_public_key()  -- Kyber public key, over TLS
  (UNCHANGED -- sendall()/recv() work           start_receiver()
   identically on ssl.SSLSocket)                  │
                                                   ▼
                                               utils/network.py send/receive (UNCHANGED)
```

A failed handshake (wrong protocol, untrusted certificate, wrong
hostname, or a plaintext client) is caught in `_serve_client()`,
logged, and the raw socket is closed — `handle_client()` is never
invoked, so no plaintext socket ever reaches application code. Because
the handshake happens inside the per-connection thread (`_serve_client`
is the thread's target, not code running inside the shared `accept()`
loop), one slow or failing handshake never blocks other connections
from being accepted.

**No application packet is ever sent before TLS is established** —
`ClientSession.connect()` performs the wrap and returns only once the
handshake (including certificate verification) has succeeded;
everything downstream (`login()`, `send_public_key()`,
`start_receiver()`) already only knows `self.client_socket` as
"whatever socket-like object `connect()` produced," so this ordering
falls out of the existing call sequence rather than requiring it to be
rearranged.

## Server TLS context

`security/tls.py::build_server_context()`:
- `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`
- `minimum_version = TLSVersion.TLSv1_2` (TLS 1.3 is negotiated
  automatically when both sides support it — nothing disables it)
- `load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)`

Built **once**, at server startup (`server/server.py`), and reused for
every accepted connection — never rebuilt per client.

## Client TLS context

`security/tls.py::build_client_context()`:
- `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`
- `minimum_version = TLSVersion.TLSv1_2`
- `verify_mode = ssl.CERT_REQUIRED` and `check_hostname = True` — both
  set explicitly even though they're `PROTOCOL_TLS_CLIENT`'s defaults,
  so the security posture is visible in code rather than implicit
- `load_verify_locations(TLS_CA_FILE)` — trusts only the configured CA

`ssl.CERT_NONE` and `check_hostname = False` are never used anywhere
in this codebase.

## Certificate hierarchy

A two-tier hierarchy, generated by `scripts/generate_dev_certs.py`:

1. **Development CA** (`certs/dev/ca.crt` / `ca.key`) — a self-signed
   certificate authority, valid 730 days (~2 years).
2. **Server certificate** (`certs/dev/server.crt` / `server.key`) —
   signed by the development CA, valid 365 days (~1 year), with:
   - **SAN**: `IP:127.0.0.1`, `DNS:localhost`

Both validity periods are deliberately short-lived for a development
certificate rather than an unnecessarily long-lived one (e.g. 10
years) — long enough not to expire mid-project, short enough that an
expired certificate is noticed quickly and (since the script is
idempotent) trivially regenerated with one command.

**SAN, not CN**: Python's `ssl` module (3.7+) matches only Subject
Alternative Name entries, never the Common Name. Since every client in
this codebase connects via `config.HOST = "127.0.0.1"`, the server
certificate's SAN must include an `IP Address` entry for exactly that
value — a `DNS` SAN for `"127.0.0.1"` would not match. `localhost` is
included as a convenience for manual testing in a browser/tool that
prefers a hostname.

## Development certificate generation

```
python scripts/generate_dev_certs.py
```

Run once, manually, after cloning. Writes `ca.crt`, `ca.key`,
`server.crt`, `server.key` into `certs/dev/`. Safe to re-run — it
always overwrites with a fresh CA and server certificate (e.g. after
expiry, or if the key material is ever suspected compromised). Uses
the `cryptography` package, already a project dependency.

The certificate-construction functions (`generate_dev_ca()`,
`generate_server_cert()`) are parameterized and reused directly by
`tests/test_tls_transport.py` to build throwaway certificates for its
negative-path tests (an untrusted CA, a wrong-hostname certificate) —
there is exactly one certificate-generation implementation, not one
for the real dev environment and a second for tests.

## Private-key handling / Git exclusions

`certs/` is gitignored in its entirety (`.gitignore`) — not just the
`.key` files. Verified directly (not assumed): `git status` shows
nothing under `certs/` after generation, and `git check-ignore -v` on
each of the four generated files confirms all four match the
`certs/` rule. Nothing under `certs/` — public certificate or private
key — is ever committed; regenerating it locally is a one-command
step, so there's no benefit to committing even the public dev CA
certificate.

## TLS + Kyber/AES relationship

These are two independent layers with different jobs, and neither
replaces the other:

| | **TLS** | **Kyber + AES-256-GCM** |
|---|---|---|
| Protects | The TCP connection itself | Message *content* |
| Provides | Transport confidentiality, transport integrity, **server authentication** | Application-level confidentiality and integrity of chat payloads |
| Who can see plaintext | The two TLS endpoints (client, server) — meaning the **server** sees decrypted TLS traffic | Only the sender and intended recipient(s) — the server never sees plaintext message content or AES keys, TLS or not |
| Trust anchor | The development/production CA | The Kyber key exchange between clients |

Concretely: TLS means a network attacker can no longer read or tamper
with the JWT token or the Kyber public-key exchange in transit. It
does **not** mean the server can now read message content — the
server terminates the TLS connection and then immediately relays
already-AES-GCM-encrypted ciphertext exactly as it always did (see
`server/client_handler.py::persist_message()`, unmodified by this
phase). The server remains zero-knowledge with respect to message
content and keys; TLS only removes the *network*, not the *server*,
from the set of parties who could otherwise interfere with the
connection.

## Testing architecture

One authoritative TLS implementation, `security/tls.py`, used
everywhere:

- **Production**: `server/server.py` and `client/session.py` call
  `build_server_context()`/`build_client_context()` directly.
- **Tests**: `tests/tls_test_support.py` wraps those same functions
  (`wrap_server_socket()`, `wrap_client_socket()`, `serve_tls_client()`,
  `serve_once_with_context()`) — it contains no independent TLS logic.
  Every socket-based integration test imports from here rather than
  constructing its own `SSLContext`.
- **Dedicated TLS tests** (`tests/test_tls_transport.py`, 13 tests)
  prove the layer in isolation, via `tests/tls_test_support.py`:
  trusted-CA success, untrusted-CA rejection, wrong-hostname rejection,
  the TLS 1.2 floor (both that it's met and that it's enforced against
  an older client), the critical property that a plaintext TCP client
  can never complete application authentication against the TLS-only
  server, and that JWT/Kyber/direct/group messaging and AES
  confidentiality/tamper-detection all work unchanged over TLS.
- **Production-wiring tests** (`tests/test_tls_production_integration.py`,
  3 tests) exercise the actual production code directly rather than
  the test-harness mirror of it: `server/server.py::_serve_client()`
  (imported and called, not reimplemented) and a real, unmodified
  `ClientSession.connect()`/`.login()`/`.send_public_key()`. Proves
  trusted-connection success, untrusted-certificate rejection, and the
  full JWT+Kyber-public-key handshake, all through the real classes —
  closing the gap the harness-based tests above don't reach on their
  own. Full live messaging round trips are deliberately left to the
  suites below rather than re-proven a third time.
- **Migrated integration tests** (`test_private_messaging_integration.py`,
  `test_group_messaging_integration.py`,
  `test_message_persistence_integration.py`,
  `test_chat_encryption_integration.py`,
  `test_message_routing_security.py` — 38 tests total) reuse the same
  `tests/tls_test_support.py` helpers so their sockets simply speak
  TLS; their assertions about application behavior (routing,
  persistence, AES confidentiality/tamper-detection, sender-spoofing
  and group-membership hardening) are otherwise unchanged.
- **Deliberately not migrated**: `tests/test_server_auth_integration.py`
  calls `server.client_handler.handle_client()` directly to test its
  JWT-gated authentication logic in isolation — it never goes through
  `server/server.py`'s accept loop, so the "is the transport TLS"
  question doesn't apply to it, and adding TLS there would test
  nothing new.

## Production deployment differences

Not implemented in this phase — documented as the delta for a real
deployment:

- A certificate from a real CA (public CA or an organization-internal
  one) for the actual public hostname, instead of the self-signed dev
  CA.
- `TLS_CERT_FILE`/`TLS_KEY_FILE`/`TLS_CA_FILE` are already
  environment-overridable (`config.py`, matching the existing
  `DATABASE_URL` pattern), so switching environments is a
  configuration change, not a code change.
- A production client would typically trust the system's default CA
  bundle (`SSLContext.load_default_certs()`) rather than pinning a
  single CA file, since a real CA's root is already broadly trusted.
- Certificate renewal/rotation becomes the issuing CA's/ops process's
  responsibility, not a manually re-run development script.
