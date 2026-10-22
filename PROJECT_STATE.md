# Project state and hand-off

Kept current at each checkpoint. Facts only: every result below names the command or test that produced it.
Anything not listed as verified is not verified.

## Branches

| Branch | Purpose | Commit |
|---|---|---|
| `master` | Baseline; unchanged by this work | `22a6a73` |
| `preservation/android-desktop-web-baseline-2026-10-20` | Safety checkpoint of everything before the Desktop/Website completion work, including all Android sources. **Do not delete.** Pushed to `origin`; remote hash verified with `git ls-remote` and by reading the remote tree | `3861769` (`38617690cc7437a789cc7c0252d0d8a151d6fbae`) |
| `work/desktop-web-completion-2026-10-20` | Active branch for the Desktop executable and Website work | based on `3861769`; the Phase 19.24 work is **committed and pushed to `origin`** (commit `eb886fd`, 2026-10-22) |
| `origin/main` | An older, unrelated 10-commit prototype history (RSA-era, 38 files; no common ancestor with `master`). Untouched; nothing merged from it | `a97ceb5` |

Remote: `https://github.com/vigneshrao1723-lab/Quantum-Resistant-Secure-Communication-System`
Preservation branch: `.../tree/preservation/android-desktop-web-baseline-2026-10-20`

## Scope

Active: Desktop application and its Windows executable, Website, multi-user acceptance testing. **Paused:** Android (sources
preserved and unchanged; no hardware validation done). Phase 20 has not been started.

**Gate:** automated testing is complete and the applications are ready for **manual acceptance**
(`docs/owner_manual_test_checklist.md`, with `docs/manual_acceptance_checklist.md` as the full reference). The work branch has been committed and pushed (`eb886fd`); nothing has been merged into `master` or `main`, and the preservation branch is unchanged. No manual acceptance has happened.

**For the owner now:** the short ordered checklist with a result sheet is `docs/owner_manual_test_checklist.md`; the test-result values and charts for
the project report are in `docs/report/` (`test_results_summary.md`, `test_results_values.csv`, `charts/*.png|svg`; regenerate with
`python scripts/make_report_charts.py`).

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
