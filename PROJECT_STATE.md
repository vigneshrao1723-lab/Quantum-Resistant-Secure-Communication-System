# Project state and hand-off

Kept current at each checkpoint. Facts only: every result below names the command or test that produced it.
Anything not listed as verified is not verified. The first section is the current state; everything after "History" is dated and may be out of date.

## Final validation (2026-11-15)

Run on the owner's laptop on 2026-11-15, the day before the interview. This section is newer than "Current state (2026-10-26)" below and supersedes its test counts; nothing below it was edited. Every result names the command that produced it. Anything not listed here as verified is not verified.

### F1-F8 (definitions from the owner's hand-over)

| ID | Item | Status | Where (verified in the code, and by tests) |
|---|---|---|---|
| F1 | Device ids must be canonical UUIDs | Fixed | `client/session.py:154` `_is_device_id()`; `web/client/app.js:90` `isDeviceId()` |
| F2 | Wrong target (device id and fingerprint) rejected | Fixed | `client/session.py` `handle_device_key_sync()` (`WRONG_RECEIVER`); `web/client/app.js` `wrong_receiver` |
| F3 | Epoch must be a real integer (bool, string, float and values below 1 rejected) | Fixed | `client/session.py:1967`; `web/client/app.js:2731` |
| F4 | The Website never overwrites a key it already holds for an epoch | Fixed | `web/client/app.js:1504-1513` (`_installSessionKey`) |
| F5 | Replay freshness of key-sync packages | **NOT fixed (open)** | The signed key-sync payload carries no nonce or timestamp (`crypto/device_protocol.py:184` `canonical_device_key_sync_payload`; `web/client/app.js:2762`) |
| F6 | No plaintext or key material in logs | Fixed and audited | Every f-string log call in client, server and gateway, and the Website's `this.log` calls, was read; `tests/test_cross_device_review_fixes.py:400` |
| F7 | The safety-number dialog defaults to "No" | Fixed | `gui/device_management_dialog.py:288-289` |
| F8 | Epoch upper bound 4294967295, checked before signature verification and before the key store is touched | Fixed | `client/session.py:151,1967`; `web/client/app.js:95,2731` |

Committed as `f43a0b9` on `work/desktop-web-completion-2026-10-20` and pushed (fast-forward). `master` and the preservation branch were not touched.

### Results (current runs only)

| What | Command | Result |
|---|---|---|
| Focused F1-F8 tests | `pytest` on `test_cross_device_*`, `test_device_key_sync*`, `test_epoch_and_domain_security`, `test_device_identity`; and the two `test_web_cross_device_*_e2e` files | 93 passed (non-Website) + 9 passed (Website e2e) |
| Full regression, run 1 | `python scripts/run_regression_batches.py` | 2,186 passed, 4 failed. All four passed when re-run alone, and their batch passed 177/177 on re-run. Not reproduced; the cause was not established (another project's test and server processes were running at the time). |
| Full regression, run 2 | `python scripts/run_regression_batches.py` (15 batches, with the four new test files added to `BATCHES`) | **2,244 passed, 0 failed**, 2,177 s. The new files add 54 collected tests (4 + 41 + 1 + 8) |
| Desktop build | `scripts/build_desktop_exe.py` on the pinned venv | 314 files; the package validator passed; the old build was copied to `qrscs-artifacts/backup-20261115` first |
| Acceptance suite against the fresh exe | `python -m pytest tests/acceptance` on the isolated database `qrscs_accept` | **33 passed of 33** (295 s). With Smart App Control on, the same suite gave 8 passed, 24 errors (all blocked, see below) and 1 failed (a precondition of the confidentiality scan that needs the exe scenarios) |
| Demo stack cold start | `scripts/start_demo.py`, then logins through the real apps | Listening in 7 s; Website HTTP 200; server TLS 1.3 verified against the dev CA; Website login restored the browser's identity; Desktop logged in twice with an app restart and no new key store was created; 0 server errors |
| Release archive | `scripts/package_release.py` | `dist/qrscs-source-20261115.zip`, 513 files, `--verify` OK (source only, not the exe) |

Tests were run against an isolated PostgreSQL database (`qrscs_accept`, and `qrscs_demo` for the demo), never the development database `qrscs`, on the pinned interpreter `venvs\qrscs312` (the repository's own `venv\` has no `kivy`, `quickjs` or `PyInstaller`).

Not yet committed at the time of writing: `scripts/run_regression_batches.py` (adds the four new test files) and the new scripts `start_demo`, `stop_demo`, `seed_demo_accounts` (`.py`/`.cmd`), `launch_desktop_fallback.cmd` and `open_demo_website.cmd`.

### Limitation: Windows Smart App Control blocks the unsigned executable

With Smart App Control on, Windows refuses to start `QRSCS-Desktop.exe` (`OSError [WinError 4551]`, Code Integrity event 3077). Both the 29 Oct build and the 15 Nov build are `NotSigned`. The owner turned Smart App Control off on 2026-11-15; it cannot be turned on again without resetting Windows. On a machine where it is on, either run the Desktop from source with `scripts/launch_desktop_fallback.cmd` (the virtual environment's `pythonw.exe` is signed by the Python Software Foundation), or sign the executable with a certificate Windows trusts. A self-signed certificate does not satisfy Smart App Control.

### Still open

* **F5**: replay freshness is not addressed (above).
* **V6e (revoked-device reconnect)**: recorded as a known limitation by the label in the owner's hand-over. Its defect description is not in this repository and it was **not reproduced or re-tested in this run (NOT VERIFIED)**. No backend behaviour was changed. The related, tested rule is in `docs/architecture/multi_device_identity.md:445` (a revoked device cannot bind a session on reconnect).
* A second physical computer was not used: **NOT VERIFIED**.

### Code review of five questions (read-only; nothing was changed)

| # | Question | Verdict | Evidence |
|---|---|---|---|
| 1 | AES-GCM nonce | PASS | Fresh random 12-byte nonce per encryption, `crypto/aes.py:63,126` (`get_random_bytes`); the Website uses `crypto.getRandomValues` (`web/client/crypto.js:306`). There is no counter, so a repeat is not impossible, only negligible (about 2^-33 after 2^32 messages under one key); no per-key message limit exists in the code. **Finding:** `AESCipher(key=None)` silently uses a fixed, public 32-byte key (`crypto/aes.py:36-37`); every Desktop call site checks for `None` first (`client/session.py:2529, 2684, 2763, 2937, 3004, 3808, 6827`), the mobile client was not checked. |
| 2 | PQC libraries | ML-KEM-768: FAIL as a production claim. ML-DSA-65: NOT VERIFIED | ML-KEM-768 is `kyber-py==1.2.0` (`requirements.txt:15`, `crypto/kyber.py:22`). Its own packaged documentation says "Under no circumstances should this be used for cryptographic applications", calls itself an educational tool, and says the code is not constant time and not designed against side-channel attacks. ML-DSA-65 is the `cryptography` 49.0.0 `mldsa` module (`crypto/ml_dsa.py:28`, backed by OpenSSL through the library's Rust bindings); the installed files contain no production-readiness statement for ML-DSA specifically. The Website uses `@noble/post-quantum` (`web/client/crypto.js:20-21`), whose documentation was not checked. |
| 3 | Desktop reconnect after a server restart | FAIL (it does not reconnect by itself) | `client/receiver.py` ends the receive loop and emits `connection_changed(False)`; the Desktop shows a banner "...until you sign in again" with a "Sign in again" button (`gui/chat_window.py:851-876`); there is no reconnect loop in `client/` or `gui/`. The Website does reconnect by itself (`web/client/app.js:540-596`). Pinned by `tests/acceptance/test_reconnect.py` (passed). |
| 4 | Website key sync: all earlier epochs or only the current one | NOT VERIFIED | By code, "blank = all" sends every epoch the browser holds (`syncAllConversationKeysToDevice`, `web/client/app.js:2656-2672`, called from `web/client/main.js:5587`); typing a conversation id sends only the current epoch, always labelled "direct" (`main.js:5592`). No test syncs two or more epochs of one conversation (the tests assert `sent >= 1` for a single key). |
| 5 | Do login or registration reveal which accounts exist? | PASS for login replies; FAIL for the rest | A wrong password and an unknown phone number get the same reply (`server/client_handler.py:3976-3982`; `test_a_wrong_password_and_an_unknown_phone_number_look_identical` passed). Not hidden: locked and inactive accounts have their own messages (`auth/authentication_service.py:275, 285`); registration says a phone number already has an account (`:51, :138`) and a username is taken (`:618, :625`). Timing: an unknown phone returns before any password hash is checked (`:257-267` against `:289`), so the paths differ; the size of the difference was **not measured**. |

### Known limitations recorded by the code review (none fixed; no code was changed)

* **`AESCipher` default key** (`crypto/aes.py:36-37`): `AESCipher(key=None)` silently uses a fixed, public 32-byte key instead of raising. Every Desktop call site checks for `None` before constructing the cipher (`client/session.py:2529, 2684, 2763, 2937, 3004, 3808, 6827`), so it is not reachable there today; the mobile client was not checked. `tests/test_aes.py:33` relies on the fallback, so removing it means changing that test too.
* **The Desktop does not reconnect by itself** after the server restarts: the receive loop ends (`client/receiver.py`) and the person must click "Sign in again" (`gui/chat_window.py:851-876`). The Website does reconnect by itself (`web/client/app.js:540-596`). The behaviour is pinned by `tests/acceptance/test_reconnect.py`.
* **Account enumeration is not fully closed.** A wrong password and an unknown phone number get the same login reply (tested), but: a locked or inactive account gets its own message (`auth/authentication_service.py:275, 285`); registration says a phone number already has an account and that a username is taken (`:51, :138, :618, :625`); and an unknown phone number returns before any password hash is checked (`:257-267` against `:289`), so response timing can differ. The size of the timing difference was not measured.
* **Website multi-epoch key sync is untested.** By code, "blank = all" sends every epoch the browser holds (`web/client/app.js:2656-2672`, `web/client/main.js:5587`), but no test syncs two or more epochs of one conversation (the tests assert `sent >= 1`), so earlier group epochs reaching another device is not verified. Typing a conversation id sends only the current epoch and always labels it "direct" (`web/client/main.js:5592`).
* **`scripts/stop_demo.py` can report a failure after a successful stop.** Observed once: `taskkill /T` exited non-zero because some child processes had already exited, so the script printed an error and returned 3 although the stack and its ports were gone; the leftover record `logs/demo/stack.json` was removed by the next stop run. Earlier stop runs exited 0. The fix (treat the stop as done once the recorded root process is gone and the ports are free) was not applied in this documentation-only pass.

### PostgreSQL exposure

`listen_addresses = '*'` (`postgresql.conf`), so PostgreSQL 17 listens on all interfaces (`0.0.0.0:5432` and `[::]:5432`), **not** on loopback only. `pg_hba.conf` allows only `127.0.0.1/32`, `::1/128` and local connections (all `scram-sha-256`), so a remote client could open a connection but not authenticate. No enabled inbound Windows Firewall rule for port 5432 or PostgreSQL was found; reachability from another host was not tested (NOT VERIFIED). A Docker container belonging to another project also publishes host port 5432; `scripts/start_demo.py` reports that clash and pins the demo stack to `127.0.0.1`. Deliberately unchanged until after the interview; the minimal fix is `listen_addresses = 'localhost'` plus a service restart.

### Demo deployment (this laptop is the server)

Start with `scripts/start_demo.cmd` (checks the PostgreSQL service and ports 5000, 8765 and 8010, then runs `run.py --no-desktop --web-port 8010` against the demo database `qrscs_demo`); stop with `scripts/stop_demo.cmd`. The demo accounts `demo_alice` (Desktop) and `demo_bob` (Website, Chrome profile `~/.qrscs/demo-chrome-bob`, opened by `scripts/open_demo_website.cmd`) were created through the real applications; their phone numbers and passwords are in `~/.qrscs/demo_accounts.txt`, outside the repository.

---

## Current state (2026-10-26)

### Branches (verified with `git ls-remote --heads origin` on 2026-10-26)

| Branch | Purpose | Remote head |
|---|---|---|
| `master` | **Default branch.** Includes the merged pull request from `work/desktop-web-completion-2026-10-20` (`merge pull request #2`) | `594a9d0` |
| `work/desktop-web-completion-2026-10-20` | The merged Desktop/Website/setup work branch; its setup/dependency fixes are now contained in `master` via the PR merge | `2805318` |
| `preservation/android-desktop-web-baseline-2026-10-20` | Safety checkpoint of everything before the Desktop/Website completion work, including all Android sources. **Do not delete.** Unchanged | `3861769` |
| `main` | An older, unrelated prototype history on the remote (no common ancestor with `master`). Untouched; nothing merged from it | `a97ceb5` |

History of `master`: `22a6a73` (earlier baseline) -> `8f376f4` (merge PR #1) -> `594a9d0` (merge PR #2, bringing in `2805318` / the fresh-clone setup fixes).
Remote: `https://github.com/vigneshrao1723-lab/Quantum-Resistant-Secure-Communication-System`

A fresh clone of `master` now includes the work-branch fixes because the PR has already been merged; the work branch is preserved and kept for reference.

### Scope

Active: Desktop application and its Windows executable, Website (+ WebSocket gateway), server, database setup, GitHub handoff and clone reproducibility.
**Paused: Android/APK** (sources preserved and unchanged, no hardware validation, not built or tested in this phase). Phase 20 has not been started.

Manual acceptance by the owner is still the gate for any further release step (`docs/owner_manual_test_checklist.md`; full reference `docs/manual_acceptance_checklist.md`). Report data for the project report: `docs/report/`.

### Handoff / fresh-clone audit (2026-10-26)

Done from a fresh clone of `master` (`8f376f4`) in a scratch directory, with a new Python 3.12.10 venv, a throwaway PostgreSQL 17.11 cluster (own data directory, port 55432 -- the owner's database and roles were not touched), a new `.env`, new TLS certificates, on Windows 11. The fixes below were applied to the clone as a patch.

| Step | Result |
|---|---|
| `pip install -r requirements.txt -r requirements-dev.txt` on 3.12.10, then `pip check` | VERIFIED: installs, no broken requirements |
| `python -m alembic upgrade head` on the empty database | VERIFIED: 17 migrations, head `e8c2a6d4f1b9` |
| `scripts/setup_database_roles.py` after the migrations | VERIFIED: 12 of 12 checks pass, re-run is idempotent, Alembic works as `qrscs_migrator` |
| `scripts/generate_dev_certs.py` | VERIFIED (after fix 2) |
| `python run.py` (server, gateway, Website, Desktop window) on alternate ports | VERIFIED: all four start; the Desktop window opens |
| Website: two accounts register, log in, verify each other, establish a key and exchange a message each way (Chrome, headless) | VERIFIED |
| `python scripts/build_desktop_exe.py` | VERIFIED: builds and self-validates (314 files; the owner's last build reported 316 -- difference not investigated) |
| Regression batch `crypto_unit` | VERIFIED: 421 passed. The other 14 batches were **not** run in the clone (stopped on request) |
| After fix 6: Kivy installs, `pip check` clean, the 8 Kivy test files collect (35 tests, not run) | VERIFIED |
| Desktop sign-in / messaging driven in the clone; the acceptance suite; the built executable launched; a second physical computer | **NOT VERIFIED** |

Defects found and fixed:

1. **README order was wrong**: `setup_database_roles.py` before `alembic upgrade head` crashes on an empty database (after creating the roles and losing their passwords). The README now migrates first; the script now refuses, changing nothing, if the schema is missing.
2. `python scripts/generate_dev_certs.py` failed with `No module named 'config'` (repository root not on `sys.path`). Fixed in the script.
3. `.env.example` pre-filled `MIGRATION_DATABASE_URL` with `REPLACE_PASSWORD`, which Alembic would have tried to use, and `DATABASE_URL` did not match the bootstrap step. Both corrected; JWT issuer/audience now carry their real defaults.
4. `run.py` ignored `SERVER_PORT`, hard-coded the Website/gateway ports, and reported success when another program already held a port. It now reads `SERVER_PORT`, offers `--web-port`, `--gateway-port`, `--no-desktop`, and checks `.env`, certificates and ports first.
5. `tests/test_configuration_separation.py` asserted the default port 5000 against the machine's real `.env`, so changing `SERVER_PORT` (the documented port-conflict fix) failed two tests. Now independent of `.env`.
6. **`kivy` is imported by 8 mobile test files and pinned in `buildozer.spec` but was declared in neither requirements file**; the `mobile` regression batch could not even be collected on a fresh install. Kivy 2.3.1 and its resolved dependencies are now in `requirements-dev.txt` (test-only; Android itself untouched).
7. The owner's checklists and two script docstrings hard-coded the owner's personal venv path and clone folder; now generic.

Dependency inventory (source imports vs manifests): every third-party package imported by production code (PySide6, SQLAlchemy, alembic, psycopg2, argon2-cffi, PyJWT, pycryptodome, cryptography, kyber-py, python-dotenv, websockets) is in `requirements.txt`. Test/build-only packages (pytest, quickjs, playwright, PyInstaller, Kivy) are in `requirements-dev.txt`. `prompt_toolkit` is imported only by the unused terminal prototype (`utils/terminal_ui.py`, no supported entry point) and is deliberately not declared. No `pyproject.toml`, lock file, CI configuration or frontend package manifest exists (the Website has no build step or npm dependency); the two pinned requirements files are the single source. System prerequisites that pip cannot install: PostgreSQL 17, Python 3.12, Git, and Chrome (tests only). No system FFmpeg is needed.

Latest test counts, recorded on the owner's machine and **not re-run in this audit**: 2,188 passed over 15 regression batches and 33 acceptance tests passed (2026-10-22, see the history below).

### Needs the owner

* Review and merge the work branch into `master` (pull request) so a fresh clone receives the fixes above.
* Follow the README on a second Windows computer; sign in on the Desktop and Website and send messages (the NOT VERIFIED items).
* Manual acceptance round 2 (`docs/owner_manual_test_checklist.md`).

---

# History (superseded by the section above)

The checkpoints below are dated records of earlier work. Statements in them about what was merged, uncommitted or pushed describe **that** moment only; the branch and merge state is the table above.

## Checkpoint 2026-10-22 (third part) — joining a group by invitation; the Desktop adopts the Website's look and navigation

Owner request: when an admin creates a group or adds people, each person must get a notice in their Inbox ("A wants to add you to
the group X") and **only the people who approve are added**; after that they chat and the key establishment and secure connection
happen automatically. And: bring every design and function of the Website to the Desktop.

* **Invitations** (new `group_invitation` inbox type, no migration; `consent_invitations` flag from the Desktop and Website so Android and
  the session-level API keep the immediate add). Design, authorization and limits: `docs/architecture/inbox_approval_workflow.md` §4c and the
  third 2026-10-22 section of `security/feature_security_matrix.md`. Approving verifies the inviter from the identity the invitee has itself
  observed (refused for a changed key); the inviter's side verifies the invitee when the approval arrives; the admin then sends the key;
  the server now asks the admin first to distribute a new epoch. Invitations expire after 14 days or when the inviter leaves.
* **Why "I cannot add a user I never chatted with" happened** (screenshot): the Website page was still running the old `main.js` (same
  `?v=1.9.0`), so the phone number was sent to the server as if it were a username and silently dropped. The asset version is now `1.10.0`
  and the page's add flow resolves a phone number to a person first. Reload with Ctrl+F5.
* **Desktop:** light/dark/follow-Windows theme from the Website's tokens (Settings → Appearance, applied at the next start), the rail with
  names under the icons and Log out, a "Connected" pill beside Chats, All/Unread/Direct/Groups chips, Enter in the search box looks up a phone
  number or @handle, a handle shown only for namesakes, a non-blocking notice banner, the Inbox as a scrolling stack of real cards (reachable
  by a screen reader and UI automation), the invitation card/notice, group info showing who is still deciding.

| Evidence | Result |
|---|---|
| `python scripts/run_regression_batches.py` (15 batches, Python 3.12 venv, real PostgreSQL, Chrome) | **2,188 passed**: 421 / 284 / 354 / 177 / 194 / 104 / 162 / 127 / 108 / 36 / 43 / 44 / 74 / 45 / 15. In the first full run `web_a` had 1 setup error (a page load timed out) and `web_b` had 1 failure (the Login button was still disabled): both passed 3 of 3 alone and both batches passed in full on the rerun (44, 74) — treated as a transient page-load stall, not reproduced |
| After the last Desktop edits (Inbox cards, notice) | the five Desktop batches were rerun: see the next line |
| `python -m pytest tests/acceptance` (real EXE + Chrome) | **33 passed** (6 min 11 s), including the group scenario where the Website members approve in the Website Inbox and the **Desktop member approves in the real Desktop Inbox through UI automation** |
| `python scripts/build_desktop_exe.py` | builds and self-validates, 316 files; `dist\desktop` is complete again (the earlier failed build is repaired) |
| `python scripts/capture_screenshots.py` | 35 captured, 0 failed (`screenshots/preliminary/`), plus the Desktop in the dark theme (`screenshots/preliminary/desktop_dark/`) |

New tests: `test_group_invitation_flow.py` (12), `test_web_group_invitations.py` (3), `test_desktop_group_invitations.py` (3),
`test_desktop_theme_and_navigation_parity.py` (7). Tests changed on purpose: the rail is no longer icon-only; Website group tests that
assumed an immediate add now approve the invitation; the acceptance group scenario approves invitations; the bio test no longer races the page.

**Not verified:** manual acceptance; Android (an invited Android person sees a group request and can approve, but Android does not verify
the inviter, so they would verify by hand); a real microphone/camera (T11/T20 still need the owner's `scripts/audio_selftest.py` run).

## Checkpoint 2026-10-22 (second part) — group member addition, request approval, key follow-through

Owner-reported: a person never spoken to could not be added to a group and read it; the approval workflow did not finish
securing the connection. Root causes, files and tests: `docs/architecture/security/feature_security_matrix.md` (2026-10-22 section)
and `docs/architecture/inbox_approval_workflow.md` §4b. In short: a skipped group-key distribution was forgotten (now remembered
and retried after genuine verification, plus a member-initiated `group_key_request`); the Website did not complete the requester's
half of an approved request (now does, and reports establishing/ready/failed); approving or auto-completing a KEY_CHANGED identity
re-trusted it (now refused on both clients).

Files: `client/session.py`, `server/client_handler.py`, `utils/protocol.py`, `web/client/{app.js,main.js,protocol.js,index.html,style.css}`,
`gui/group_info_dialog.py`, `scripts/run_regression_batches.py`; new tests `tests/test_group_key_late_verification.py` (9),
`tests/test_contact_request_approval_flow.py` (8), `tests/test_web_late_verification_and_approval.py` (8),
`tests/test_web_group_member_lookup.py` (now 6); one test made race-free (`test_web_bio_can_be_edited_and_is_seen_by_desktop`).
No migration. Android untouched.

Results: see the security-matrix section (12 batches run; 11 passed; web_b had 1 failure, a race in the test itself, fixed and reran
6/6; the batches were not repeated after the final two small changes, the 57 group/inbox tests and 14 new Website tests were).

**Desktop executable:** a rebuild into `dist\desktop` once failed while two Desktop windows were running from it (Windows locks their
files) and removed 10 of 316 files; it was rebuilt with no Desktop window running and is complete again (see the third part above).

## Checkpoint 2026-10-22 — owner's manual acceptance round 1 and the fixes made for it

The owner ran the 20-item checklist: **14 PASS, 6 FAIL** (T11, T12, T14, T17, T20; T05's note asked for the Website's picture-editing
method on the Desktop). Nothing was marked NOT TESTED. Fixes below were committed with the rest of the branch in `eb886fd`.

| Reported | Cause | Change | Focused evidence |
|---|---|---|---|
| T14 (Website): add a person to a group **by phone number**, showing their name first | The member box accepted usernames only | A phone number is looked up and shown by name and @handle with **Add**; nothing is added until then; unknown numbers say so; a phone number is never sent as a username. Same in Group info → Add members | `tests/test_web_group_member_lookup.py` (5) |
| T12 / screenshots 3–5: Desktop should look and work like the Website | Desktop Chat settings was a window; the gallery and the file/voice cards looked different | Gear → **dropdown menu** with the Website's entries and order (Contact info / Group details opens the detailed window); gallery = the Website's card with rows that jump to the message; file card = type tile, name over size, round download button; voice card = titled "Voice message", rounded player pill, play, time, progress, **volume and mute** | `tests/test_desktop_website_parity_fixes.py` (14) |
| T17 / T05 note: Desktop picture editor like the Website's, with the circle | The Desktop crop was a plain square with no circle and no checks | Dimmed outside a circle with a ring, the Website's wording, zoom slider, arrow/+/- keys, "Save picture"; the Website's file checks (PNG/JPEG/WebP/GIF, ≤10 MB, 64–8192 px) before the editor opens | same file |
| T11 / T20: recordings cannot be heard (real hardware) | **Not diagnosed.** The automated tests used synthetic signals and never the real microphone path | Added `scripts/audio_selftest.py` for the owner to run (plays a tone, records 3 s from each microphone with the app's settings, measures loudness, plays it back through the app's playback path). Nothing was changed in the recorder or player for this | none yet: needs the owner's run |
| T14 (b): group members "unable to chat with themselves" | **Unclear** (screenshot is a direct chat showing "Not verified / Establish key"). Messaging stays blocked until identity verification — by design | Not changed; a question is open (see the report) | — |

Regression after these changes (not the full suite): Desktop batches `desktop_gui` 162, `desktop_gui_b` 117, `desktop_gui_lifecycle_a` 108, `_b1` 36,
`_b2` 43, and `web_c` 33 — all passed. The 2026-10-21 totals below are from before this round. The Desktop EXE must be rebuilt
(`python scripts/build_desktop_exe.py`) to carry the Desktop changes; the Website changes need only a page reload.

## Checkpoint 2026-10-21 (second window) — Phase 19.24 cycle done, ready for manual acceptance

Desktop/Website UI parity, chat media fixes, duplicate display names, group membership events and group attachments (the 20 owner
corrections) are implemented and tested. Per-requirement map: `docs/architecture/ui_parity_requirement_map.md`; behaviours:
`feature_parity_matrix.md`; security notes: the second 2026-10-21 section of `security/feature_security_matrix.md`;
checks for the owner: `docs/manual_acceptance_checklist.md` section 0b.

| Evidence | Result |
|---|---|
| `python scripts/run_regression_batches.py` (15 batches, Python 3.12 venv, real PostgreSQL, Chrome) | **2,118 passed, 0 failed, 0 skipped** (1,957 before; +161, none removed). Per batch: 421 / 284 / 325 / 177 / 194 / 104 / 162 / 103 / 108 / 36 / 43 / 44 / 74 / 28 / 15. 185 test files, each in exactly one batch |
| `python scripts/build_desktop_exe.py` | builds, 316 files, self-validates; QtMultimedia + FFmpeg plugin present |
| `python -m pytest tests/acceptance` (built EXE + Chrome, isolated DB) | **33 passed** (3 min 36 s) |
| `python scripts/package_release.py` | 460 files; no forbidden names, secret patterns or live secret values |
| `python scripts/capture_screenshots.py` | 34 captured, 0 failed → `screenshots/preliminary/` |
| Migration | `e8c2a6d4f1b9` (group_events), **already applied to the development database `qrscs`** (checked read-only on 2026-10-21 with `alembic current` → `e8c2a6d4f1b9 (head)`; the table exists and the runtime role `qrscs_app` has SELECT/INSERT/UPDATE/DELETE on it). An earlier version of this line said it had not been applied; that was wrong. Nothing needs to be run before manual testing. The migration only adds a table and two indexes |

Desktop batches were re-run after the last Desktop change (status-bar accessible name): 162 / 103 / 108 passed.

*Not verified:* manual acceptance (nothing has been done by a person); a real microphone/camera (fake devices and synthetic signals
only; audibility proven by decoding, not by listening); Android (unchanged, no hardware); the executable on another machine (unsigned;
Windows Application Control may block a freshly built unsigned executable the first time it is launched — it did once here, and the
same file ran on the next attempt).

*Not changed:* Android sources, the cryptography and key management, TLS, database roles, `master`, the preservation branch.
Nothing is staged or committed.

## Checkpoint 2026-10-21 — ready for manual acceptance

### Verified (command → result)

| Evidence | Result |
|---|---|
| `python scripts/run_regression_batches.py` (12 batches, Python 3.12 venv, real PostgreSQL, Chrome) | **1,957 passed, 0 failed, 0 skipped** (1,919 before this phase: +38, none removed or weakened). Per batch: 420 / 253 / 305 / 177 / 194 / 104 / 207 / 108 / 36 / 43 / 44 / 66. 171 test files, each in exactly one batch |
| `python -m pytest tests/acceptance` at 10, 20, 30 standing accounts | **32/32 at each size**; every population account registered and logged in through the real forms (10, 20, 30); ~89–169 messages per run |
| Registration through the Website form, repeated | 100/100 (200/200 earlier); 3 of 60 failed before the TLS fix |
| Web batches repeated 5 times, twice | 20 of 20 batch runs passed (before: 5 of 11 full runs had failures) |
| Confidentiality scan after the run | 713,873 log bytes, 436 database rows, 2 blobs, 439 patterns → **0 hits** |
| `python scripts/build_desktop_exe.py` | builds and self-validates; EXE exercised by the acceptance suite |
| `python scripts/package_release.py` | 435 files; no forbidden names, secret patterns or live secret values |
| 31 real screenshots (`python scripts/capture_screenshots.py`) | in `screenshots/preliminary/` (website 18, desktop 13) |

Details, per-batch table, the defect list and the residual risks are in the 2026-10-21 section of
`docs/architecture/security/feature_security_matrix.md`. The audited feature table is `docs/architecture/feature_parity_matrix.md`;
the acceptance suite is described in `docs/architecture/acceptance_testing.md`.

### What changed since the preservation commit

*Defects found and fixed* (each with a test that fails without the fix): login replies revealed whether a phone number is registered;
a repeated send was delivered twice and a repeated group send broke the sender's connection; a Website user stayed "online" after
logging out; ~0.5% of first requests after a WebSocket opened were lost (TLS 1.3 session tickets — likely the cause of the old
intermittent Web failures); the Website never recovered from a server outage; the Web client could not read group history from before
a key rotation. *Also:* own safety number visible on Desktop and Website; Desktop rows readable by assistive technology; Desktop brand
mark and executable icon; Desktop banner with "Sign in again" after a lost connection; Desktop header no longer clips at the default
window size; Desktop Settings scrolls on a small screen.

*New tooling:* Desktop executable build (`scripts/build_desktop_exe.py`, `scripts/qrscs_desktop.spec`); isolated test database
(`scripts/acceptance_db.py`); the acceptance suite (`tests/acceptance/`) with a Windows UI Automation driver and a Playwright driver;
`scripts/acceptance_report.py`, `scripts/capture_screenshots.py`; the regression runner now prints test counts.

### Faults in my own test harness found along the way (so nobody re-investigates them)

* A 20-account run failed because a stale server from an interrupted run still held the ports; the harness now refuses to start on a
  busy port.
* Every launched Desktop window was invisible once a test module forced Qt's "offscreen" platform into the environment; the driver
  now removes that variable.
* A concurrency scenario at 30 accounts put the same browser user in two conversations; pairs are now disjoint.
* Several scenarios clicked before the application had finished (e.g. binding a device before enrollment was confirmed).
* UI Automation `Invoke` blocks while a modal dialog opened by the click is open; the agent runs it on its own thread and focuses the
  window first (Qt buttons only act on the active window).

### Open items and known limits

* Account enumeration closed only for credential errors (locked/inactive accounts and login timing still differ).
* Desktop Devices, Inbox and group-member dialogs cannot be driven by UI Automation or reached by assistive technology (buttons inside
  list rows); the Desktop does not reconnect by itself; Web device key sync sends only the current group key.
* The executable is unsigned and has only run on this machine.
* Group pictures do not exist on any platform; Android is paused and unvalidated on hardware; Desktop has no dark theme.
* Loopback only: no real-network testing.

### Next actions

1. **Manual acceptance by the project owner** using `docs/manual_acceptance_checklist.md`; record what works and what does not.
2. Fix what that finds; repeat the affected acceptance scenarios and the full regression.
3. Only after an explicit green signal: cleanup review, final secret scan, commit on this branch, push, merge to `master`, and refresh
   `screenshots/final_release/`. Keep the preservation branch.

### How to reproduce

```
python scripts/setup_database_roles.py          # once
python scripts/acceptance_db.py create          # (the acceptance suite does this itself)
python scripts/build_desktop_exe.py
python -m pytest tests/acceptance -p no:cacheprovider
python scripts/run_regression_batches.py        # all batches, with counts
```
