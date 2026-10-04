# Authentication Flow

Written Phase 19.19, closing the documentation gap Limitation L-8
named ("L. Authentication flow — Missing"). Traces registration,
login, token issuance/validation, and account lockout end to end,
citing the actual code at each step. Password strength, account
verification cryptography (Argon2id for the account password —
distinct from the LOCAL key-store password covered in
`key_management_lifecycle.md`) and JWT signing are all pre-existing,
unmodified; this document describes them, it does not change them.

## 1. The two-connection model

Authentication is deliberately split across **two separate TCP/TLS
connections**, not one continuous session:

```
Connection 1 (short-lived, closed immediately after)
  Client -> login_request {identifier, password}     [phone number + password]
  Server -> AuthenticationService.authenticate_user()
         -> login_result {access_token, refresh_token, user_id, username}
  Client closes this connection.

Connection 2 (the real, persistent session connection)
  Client -> connect() again (a fresh TLS handshake)
  Client -> auth {access_token}
  Server -> authenticate_connection(): validates the JWT, resolves `user`
         -> auth_result {success, username}
  ... this connection now carries every subsequent packet, with
      `user` (the authenticated identity) fixed for its whole lifetime.
```

`client/session.py::authenticate_credentials()` performs connection 1;
`connect()` + `login(username)` perform connection 2. This shape is
not an accident — `authenticate_credentials()`'s own docstring records
why: it runs before any receiver thread exists, so it talks to the
server directly rather than through `send_request()`'s correlated-
response machinery (which requires `start_receiver()` already
running). Password verification and token issuance happen ONLY on
connection 1, server-side, inside `AuthenticationService.
authenticate_user()` — nothing client-side duplicates or second-
guesses that decision, and the password hash is never part of any
response.

Registration (`register_request`/`AuthenticationService.
register_user()`) follows the identical connection-1 shape.

## 2. Login identifier

**Phone number + password only.** Username and email are
registration/display identifiers, never accepted as login credentials
— `AuthenticationService.authenticate_user()` normalizes the supplied
identifier (`security/phone_number.py::normalize_phone_number()`, the
same normalization registration applies) so `"+91 98765 43210"` and
`"+919876543210"` resolve to the same account, then looks the account
up by phone number specifically.

## 3. Password storage and verification

Account passwords are hashed with Argon2id (`security/password_
handler.py`) — the same algorithm family `key_management_lifecycle.md`
§7 describes for the LOCAL key-store password, but a completely
separate hash, separate salt, and separate purpose: this one lives in
`users.password_hash` server-side and gates account login; that one
never leaves the client and gates the local encrypted key file. Never
conflate the two — a compromised database exposes only Argon2id
hashes of account passwords (already expensive to brute-force), never
any key material.

## 4. Failure handling — deliberately uninformative

Every rejection on connection 1 (`invalid identifier`, `user not
found`, `wrong password`) returns the SAME generic message,
`"Invalid phone number or password."` — `authenticate_user()` never
reveals which half was wrong, a standard enumeration-hardening
measure (an attacker probing for valid phone numbers learns nothing
from the response shape). This is a deliberate design choice, not an
oversight — do not "improve" the error message to be more specific
without re-deriving why it currently isn't.

## 5. Account lockout

`MAX_FAILED_LOGIN_ATTEMPTS` (from `config.py`) failed attempts in a
row locks the account (`user.status = "locked"`) — `UserRepository.
increment_failed_logins()`/`set_locked()`. A locked account's own
correct password no longer succeeds; the account requires separate
unlock handling (out of scope for this document — see `auth/
authentication_service.py::authenticate_user()`'s own `locked` branch
for the exact current behavior). A successful login resets the
failed-attempt counter (`reset_failed_logins()`).

## 6. Tokens

Two JWTs (`security/jwt_handler.py::JWTHandler`), issued together on
successful login:

- **Access token** (`create_access_token()`) — short-lived
  (`ACCESS_TOKEN_EXPIRE_MINUTES`, `config.py`), carried in the `auth`
  packet on connection 2 and validated by `authenticate_connection()`
  server-side on every new connection. This is what fixes `user` for
  the rest of that connection's lifetime — every subsequent handler in
  `server/client_handler.py` reads the authenticated identity from
  this resolved `user` object, never from anything a later packet
  claims.
- **Refresh token** (`create_refresh_token()`) — long-lived
  (`REFRESH_TOKEN_EXPIRE_DAYS`), its HASH (never the raw token) stored
  in the corresponding `sessions.refresh_token_hash` row
  (`AuthenticationService.refresh_access_token()` looks it up by hash,
  never by comparing raw tokens). Used to obtain a new access token
  without re-entering the password once the access token expires — not
  otherwise covered further here.

`decode_token()`/`is_token_valid()` verify the JWT signature and
expiry; `TokenExpiredError`/`TokenValidationError` are raised for an
expired or malformed/forged token respectively, both resulting in a
rejected `auth_result` server-side — never a partial or best-effort
acceptance.

## 7. Sessions vs. devices — two different tables, two different lifetimes

`sessions` (one row per login, `database/models/session.py`) is
**ephemeral, per-login** metadata (`device_name`, `platform`,
`is_active`, `revoked`, `expires_at`) — it is not, and was never meant
to be, a device's *cryptographic* identity. `devices` (Phase 16,
`database/models/device.py`) is the separate, persistent table that
IS a device's cryptographic identity (its ML-KEM/ML-DSA public keys,
fingerprint, PENDING/AUTHORIZED/REVOKED state). Logging out and back
in creates a new `sessions` row every time; it does not touch
`devices` at all. See `key_management_lifecycle.md` and `multi_device_
identity.md` for the full device model this document deliberately
does not duplicate.

## 8. Change username / change password

`AuthenticationService.change_username()`/`change_password()` are the
server-side implementations `client/session.py::change_username()`/
`change_password()` (Desktop, Phase 19.18), `mobile/session.py`'s
identical methods, and `web/client/app.js`'s `changeUsername()`/
`changePassword()` (Phase 19.18) all call unchanged, through the
normal `send_request()` path on the already-authenticated connection
2 — never a second, parallel authentication mechanism. `change_
password()` still requires the CURRENT password, verified the same
way login verifies it, before accepting a new one.

## 9. Cross-client consistency

Desktop and Android both call the literal same `AuthenticationService`
server-side implementation over the identical wire packets
(`login_request`/`register_request`/`auth`/`change_username_request`/
`change_password_request` — `utils/protocol.py`); there is exactly one
authentication implementation, never a client-specific variant. Web
goes through `web/gateway.py`'s WebSocket bridge to the same server,
same packets, same `AuthenticationService` — proven end to end by
`tests/test_web_settings_and_inbox.py`'s real change-username/
change-password tests (Phase 19.18) alongside the pre-existing
`tests/test_registration_integration.py`/`test_login_logout_
integration.py`/`test_authentication_service.py` covering the
Desktop/server side directly.
