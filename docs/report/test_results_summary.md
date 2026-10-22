# Test result values for the project report

Run of **2026-10-22**, branch `work/desktop-web-completion-2026-10-20`.
Environment: Windows 11, Python 3.12 virtual environment, PostgreSQL 17, Google Chrome (Playwright), PySide6 6.9.1; official runner scripts/run_regression_batches.py.

> Numbers are copied from the runner's own output of 2026-10-22 (first full run, then the reruns noted below). Nothing here is estimated.

## Headline values

| Value | Result |
|---|---|
| Automated regression tests (final run) | **2,188 passed, 0 failed, 0 errors** |
| Final pass rate | **100%** (2,188 / 2,188) |
| First full run | 2,186 passed, 1 failed, 1 error, 99.91% — transient page-load stalls, not reproduced; both batches passed on the rerun |
| Automated test files | 194 in 15 runner batches |
| Total batch time | 33.1 minutes (1,988 s) |
| UI-driven acceptance suite | **33 of 33 passed** in 6.2 minutes (real Desktop executable + Chrome) |
| Suite growth | 1,919 → 2,188 tests (+269, +14.0%) since 2026-10-20 |
| Tests added in the latest round | 70 in 9 new files |

## Tests by batch

| Batch | Area | Files | Passed | Seconds |
|---|---|---:|---:|---:|
| crypto_unit | Cryptography | 25 | 421 | 65.2 |
| device_security | Device and identity security | 30 | 284 | 271.5 |
| messaging_groups_a | Messaging and groups | 28 | 354 | 479.5 |
| messaging_groups_b1 | Messaging and groups | 11 | 177 | 154.2 |
| messaging_groups_b2 | Messaging and groups | 11 | 194 | 96.8 |
| mobile | Android client logic | 20 | 104 | 97.2 |
| desktop_gui | Desktop application | 13 | 162 | 22.9 |
| desktop_gui_b | Desktop application | 15 | 127 | 83.5 |
| desktop_gui_lifecycle_a | Desktop application | 8 | 108 | 13.5 |
| desktop_gui_lifecycle_b1 | Desktop application | 5 | 36 | 51.7 |
| desktop_gui_lifecycle_b2 | Desktop application | 7 | 43 | 47.3 |
| web_a | Website | 9 | 44 | 105.3 |
| web_b | Website | 5 | 74 | 290.2 |
| web_c | Website | 6 | 45 | 188.8 |
| media_interop | Media interoperability | 1 | 15 | 20.4 |
| **Total** | | **194** | **2,188** | **1,988.0** |

Each row is the final passing run of that batch. web_a and web_b are the reruns (44 and 74 passed); the five desktop batches are the reruns after the last Desktop edit.

## Tests by area of the system

| Area | Tests | Share |
|---|---:|---:|
| Messaging and groups | 725 | 33.1% |
| Desktop application | 476 | 21.8% |
| Cryptography | 421 | 19.2% |
| Device and identity security | 284 | 13.0% |
| Website | 163 | 7.4% |
| Android client logic | 104 | 4.8% |
| Media interoperability | 15 | 0.7% |

## Growth of the suite

| Date | Checkpoint | Tests |
|---|---|---:|
| 2026-10-20 | Start of the Desktop/Web completion work | 1,919 |
| 2026-10-21 | After the executable and multi-user acceptance work | 1,957 |
| 2026-10-21 | After UI parity, media fixes, group events and attachments | 2,118 |
| 2026-10-22 | After late-verification fixes and group invitations | 2,188 |

## Acceptance suite (real executable + Chrome)

| Module | Passed |
|---|---:|
| sessions | 5 |
| social | 5 |
| pairs | 4 |
| security_negative | 4 |
| attachments | 3 |
| message_lifecycle | 2 |
| population | 2 |
| confidentiality_scan | 2 |
| groups | 1 |
| devices | 1 |
| concurrency | 1 |
| desktop_exe_roundtrip | 1 |
| reconnect | 1 |
| registration_stress | 1 |
| **Total** | **33** |

## Tests added in the latest round

| File | Tests |
|---|---:|
| test_group_key_late_verification.py | 9 |
| test_contact_request_approval_flow.py | 8 |
| test_web_late_verification_and_approval.py | 8 |
| test_web_group_member_lookup.py | 6 |
| test_desktop_website_parity_fixes.py | 14 |
| test_group_invitation_flow.py | 12 |
| test_web_group_invitations.py | 3 |
| test_desktop_group_invitations.py | 3 |
| test_desktop_theme_and_navigation_parity.py | 7 |

## What these numbers do not cover (say so in the report)

* Manual acceptance by a person (see docs/owner_manual_test_checklist.md)
* A real microphone or camera (automated runs use synthetic signals and Chrome's fake devices)
* Android on a physical device (sources preserved, not validated)
* The executable on another computer, over a real network, or code-signed

## Charts

| File | Shows |
|---|---|
| `charts/01_tests_by_batch.png` | tests passed in each of the 15 batches |
| `charts/02_tests_by_area.png` | the same, by area of the system, with shares |
| `charts/03_test_growth.png` | growth of the suite across the checkpoints |
| `charts/04_batch_duration.png` | how long each batch takes |
| `charts/05_acceptance_by_module.png` | the acceptance suite, per module |
| `charts/06_result_summary.png` | the headline values as one picture |

Regenerate everything with `python scripts/make_report_charts.py` (SVG and PNG; no plotting library needed).
