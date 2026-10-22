# Multi-user acceptance testing

The regression batches (`scripts/run_regression_batches.py`) test each component against a real server
with in-process clients. The acceptance suite in `tests/acceptance/` is different: it drives the
**built Desktop executable** and the **Website in Chrome** through their real user interfaces, as many
different people would, against a separate, isolated deployment.

## What is real, what is not

| | |
|---|---|
| Accounts | Created through the real registration forms of the Website and of `QRSCS-Desktop.exe`. Nothing is inserted into the database. Names, phone numbers and passwords are synthetic and random per run; passwords exist only in memory. |
| Clients | Website: Playwright with the system Chrome, one **browser context per user** (separate storage, keys and device). Desktop: the packaged EXE, one **process per user** with its own key store, driven through Windows UI Automation (`uia_agent.ps1`, no extra dependency). |
| Server | The real server, gateway and static web server as separate processes, connecting to the isolated database `qrscs_accept` as the least-privilege `qrscs_app` role, with a throw-away blob directory and non-default ports (15000 / 18765 / 18000). Refuses to start if a port is already in use. |
| Cryptography | Unmodified: ML-KEM-768, ML-DSA-65, AES-256-GCM, Argon2id, TLS. No mocks anywhere. |
| Protocol clients | Used only for the authorization-boundary checks in `test_security_negative.py`, which need to send things a UI never would. |

Run it (build the executable first; the database is recreated for every session):

```
python scripts/build_desktop_exe.py
python -m pytest tests/acceptance -p no:cacheprovider
python scripts/acceptance_report.py          # Markdown summary of the newest run
python scripts/capture_screenshots.py        # real screenshots of the EXE and the Website
```

`QRSCS_ACCEPT_WEB` / `QRSCS_ACCEPT_DESKTOP` set the size of the standing population (default 8 + 2 = 10;
26 + 4 = 30 has been run). Evidence for each run is written to `dist/acceptance/run-*/`:
`accounts.json` (who registered / logged in, no credentials), `test_results.json` and the server logs.

## Scenario inventory

| Module | Scenarios | Clients exercised |
|---|---|---|
| `test_population.py` | every account registers and logs in through the UI; every account has its own identity keys | Website + Desktop |
| `test_desktop_exe_roundtrip.py` | EXE registers, logs in, finds a user by phone, verifies identity (independently computed number), messages both ways with the Website | Desktop + Website |
| `test_pairs.py` | verify and message in all four combinations (web-web, web-desktop, desktop-web, desktop-desktop) | both |
| `test_sessions.py` | wrong password refused then correct one accepted (both clients); logout/login restores history without duplicates; messages sent while offline arrive exactly once; Desktop restart keeps identity and history | both |
| `test_message_lifecycle.py` | reply (with quote), edit, react, delete-for-everyone as the recipient sees them; edit and delete reach a Desktop recipient | Website, Desktop |
| `test_groups.py` | create with Website+Desktop members; messages reach exactly the members; add member; remove member; leave; non-member sees nothing | both |
| `test_attachments.py` | image arrives byte-for-byte and lists in the gallery; file reaches a Desktop recipient by name; oversized file refused and never delivered | both |
| `test_social.py` | verification request approved from the Inbox; block/unblock; pin, search, draft; mute/archive; presence | Website |
| `test_devices.py` | second device enrolled, authorized, revoked and refused | Website |
| `test_concurrency.py` | five pairs (web-web and web-desktop) exchange bursts simultaneously: every message once, to the right person, none from another pair | both |
| `test_security_negative.py` | non-member cannot read or post to a group; unauthenticated connection cannot send; a replayed `client_message_id` is stored once **and delivered once** | protocol |
| `test_reconnect.py` | stop the server under live clients: the Website says "Reconnecting" and recovers by itself, the Desktop shows its "Connection lost" banner and **Sign in again** gets the user back; messages flow both ways afterwards | both |
| `test_registration_stress.py` | repeated browser registrations all succeed (found the TLS-ticket loss) | Website |
| `test_zz_confidentiality.py` | runs last: no sent plaintext, password, identity secret key or conversation key in the logs, any database row, or any blob | server side |

## Re-run for the UI-parity cycle (2026-10-21)

The built executable was rebuilt (316 files; QtMultimedia and the FFmpeg plugin are in the bundle) and the whole suite re-run:
**33 passed** (32 scenarios + the registration stress test; the confidentiality scan ran last and found nothing). The drivers were
updated for the new UI, not loosened: the Desktop's own safety number is read from a contact's Verify Identity window behind
"Show my safety number"; Website chat tools are run from the Chat settings menu; the gateway address is a collapsed field; the
Website's "Establish key" button is skipped when it is hidden because the key already exists. One real defect was found by the
suite: the Desktop status bar's accessible name had been set to a fixed "Connection status", hiding "Disconnected" from assistive
technology and UI Automation; the name now carries the state ("Connection status: Disconnected").

A failing scenario that stops the server (`test_reconnect.py`) leaves the stack down for the scenarios after it, so one failure there
appears as a cascade of failures. Read the first failure only.

## Defects this suite found (all fixed, each with a regression test in the normal batches)

* Login replies distinguished "no such account" from "wrong password" (account enumeration).
* A repeated send was delivered twice; a repeated group send broke the sender's connection.
* A browser that logged out stayed "online" on the server.
* About 0.5% of first requests after a WebSocket opened were lost (TLS 1.3 session tickets).
* The Website never recovered from a server outage (its reconnect hung forever).
* Desktop rows were unreadable to assistive technology; the Desktop gave no way back after a lost connection; its header
  clipped buttons at the default window size and its Settings dialog was taller than a small screen.

Failures that were the suite's own fault are recorded in `PROJECT_STATE.md` (for example a harness that trusted a stale
server on a busy port, and a pair builder that reused the same browser user in two conversations).

## Known limits of this suite (stated, not hidden)

* The Desktop's **Devices** and **Inbox** dialogs, the group member list and other dialogs put buttons inside list
  rows. Qt does not expose those to UI Automation (or to screen readers), so they cannot be driven here; they are
  covered by widget-level tests (`test_device_management.py`, `test_group_admin_and_inbox.py`) and by the manual
  acceptance checklist. Desktop sending of attachments goes through the operating system's file dialog and is
  likewise not automated.
* Desktop message **context menus** (reply/edit/react/forward) are not driven through UI Automation; the Desktop
  *receiving* those events is checked from the Website side.
* The key-material part of the confidentiality scan covers the browsers' secret keys and conversation keys; a
  Desktop's keys live in its encrypted key store and are not extracted, so for Desktop only plaintext and password
  checks apply.
* Everything runs on one machine over loopback. Latency, packet loss and a real network are not exercised.
