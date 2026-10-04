# Testing Strategy

Written Phase 19.18, closing the documentation gap Limitation L-8 named
("S. Testing strategy — Missing"). Describes what actually exists in
`tests/` and how it's actually run — not an aspirational plan.

## 1. Shape of the suite

122 test files, ~1541+ individual test functions (exact count drifts
as phases add tests; see the note on L-7 below for why no single
number is ever quoted as gospel). There is deliberately **no test
double / mock layer for cryptography, the database, or the network**
anywhere in this suite: every test that exercises a security property
does so against real `ML-KEM-768`/`ML-DSA-65`/AES-256-GCM code, a real
TLS-wrapped socket, and a real (test) PostgreSQL-backed
`SessionLocal()`. The one thing consistently faked is *time* (real
clocks, no fixed clock injection) and *external I/O the feature itself
doesn't own* (e.g. a picked file's bytes are synthesized in-test rather
than read from a real file picker dialog).

## 2. Categories

**Unit / component tests** — a single module in isolation: crypto
primitives (`test_ml_dsa.py`, `test_message_protocol.py`), payload
classification (`test_attachment_classification.py`), repository
methods against a real DB session. No server, no socket.

**Integration tests** — the large majority of the suite. A real
`start_test_server()` harness (`tests/tls_test_support.py`, an
ephemeral-port TLS server running the actual `server/client_handler.py`
dispatch loop, unmodified) plus one or more real `ClientSession` /
`MobileClientSession` / `WebClientSession` instances, talking over the
real wire protocol. This is the layer that proves cross-client
interoperability, since the *same* server code path serves every
client type — e.g. `test_mobile_client_session.py::
test_mobile_desktop_direct_messaging_bidirectional` is a real Desktop
`ClientSession` and a real `MobileClientSession` exchanging real
ML-DSA-signed, AES-GCM-encrypted messages through one real server.

**GUI tests** — real `PySide6` widgets under a real (offscreen)
`QApplication`, real Qt signal/slot wiring, real clicks via
`QTest`/direct method calls on real dialogs (`test_create_group_dialog_
gui.py`, `test_group_member_selection_clicks.py`,
`test_security_rejection_gui.py`, etc.) — not screenshots, not visual
diffing; assertions read real widget state (text, visibility, item
counts).

**Web / Playwright tests** (`test_web_browser_e2e.py`,
`test_web_persistence_reconnect.py`,
`test_web_feature_completion_e2e.py`,
`test_web_settings_and_inbox.py`, `test_web_gateway_interop.py`,
`test_web_client_crypto_interop.py`) — a real headless Chrome
(Playwright), a real `web/gateway/gateway.py` WebSocket↔TCP relay
process, and the real, unmodified `web/client/app.js` running inside
that real browser. Two sub-styles: (a) real DOM interaction
(`page.fill`/`page.click`) driving the actual shipped UI, used
wherever a test's whole point is proving the UI itself works, and (b)
`window.__session` direct calls for tests whose point is proving the
underlying `WebClientSession` API/crypto is correct independent of any
particular UI — both call into the exact same, single implementation
(see `web/client/main.js`'s own header comment: it is DOM-wiring only,
zero protocol logic of its own).

**Security-negative tests** — spread throughout rather than one file:
tampered signatures, wrong fingerprints, replayed/stale epochs,
unverified senders, non-members, revoked/pending devices, forged
identities. Named explicitly per scenario (e.g.
`test_revoked_device_cannot_send_group_key_distribution`,
`test_revoked_device_cannot_send_ordinary_direct_chat`,
`test_gateway_rejects_malformed_frame_without_crashing`). The
convention: assert the *absence* of an effect (key never installed,
message never received, state never promoted) rather than only
asserting an error was raised — proves the rejection actually stopped
something, not just that it complained.

**Cross-client tests** — any test file importing more than one of
`client.session` / `mobile.session` / the Web `WebClientSession`
JS module in the same test. Confirmed present in
`tests/test_mobile_client_session.py` (Desktop+Mobile) and the
`test_web_*` files with a `desktop_app` fixture (Desktop+Web). These
are the tests that actually prove "three different codebases speak
the same wire protocol correctly," not just that each one is
internally consistent.

**Physical-device tests** — not automatable from this repository: real
taps/typing on the real Vivo V2036 Android hardware, performed by a
person, logged in `docs/architecture/mobile_client.md` and this
project's own phase reports. The feature matrix in the Phase 19.17
freeze report records, per feature, whether physical Android
verification exists and when — never asserted here as "done" without
that citation.

**Regression suite** — "run everything" is exactly the union of the
categories above; there is no separate regression-only test set.

## 3. Known environment-related test limitation (L-7)

A full, single-process `pytest` run mixing ~120 files' worth of real
TLS socket servers and real `PySide6 QApplication` instances is
**not reliable as one continuous process on this Windows development
environment** — three separate sessions have hit a native-level crash
or hang at different points (a CPython `ssl.py` teardown fault, a
genuine deadlock, and a PySide6 `processEvents()` access violation
that only reproduces after enough other Qt-heavy tests have already
run in the same interpreter). The *tests themselves* are not at
fault — every one of them passes cleanly when run in isolation or in
smaller batches; this is resource/state accumulation across hundreds
of thread+socket+Qt-singleton creations in one long-lived process, not
a defect in any test's own logic or the code it exercises.

**Working practice, used throughout Phase 19.17/19.18**: run in
topic-scoped batches (e.g. `pytest tests/test_web_*.py`,
`pytest tests/test_mobile_*.py`, `pytest tests/test_device_identity.py
tests/test_group_*.py ...`) rather than one unbounded `pytest -q`
across the whole `tests/` directory. If a batch hangs, it is killed,
the specific hanging test is isolated and re-run alone to confirm it
passes there, and the run continues from the next batch — never
silently skipped, never left unresolved without a note in the phase
report that produced it.

**Not required to fix for the FYP itself** (per L-7's own
recommendation); a `pytest-forked`/per-file-subprocess CI setup would
close this permanently if the suite is relied on unattended
long-term.

### 3.1 The official batched regression procedure (Phase 19.19)

The manual "run in topic-scoped batches" practice above is now also a
real, checked-in, reproducible script: `scripts/run_regression_
batches.py`. It does not attempt to solve the underlying Windows/Qt/
native-extension resource-accumulation problem (out of this
application's control, per L-7's own scope) — it automates the
WORKAROUND: six curated batches (`crypto_unit`, `device_security`,
`messaging_groups`, `mobile`, `desktop_gui`, `web`), each run as its
own isolated `pytest` subprocess, in order from lightest/fastest to
heaviest/slowest, with a per-batch timeout (`--timeout-seconds`,
default 900s) so a hung batch is treated as a failure and the run
continues, never awaited indefinitely.

```
python scripts/run_regression_batches.py            # every batch, in order
python scripts/run_regression_batches.py --list      # show batch membership, don't run
python scripts/run_regression_batches.py --batch web  # one named batch only
```

The batch groupings are not arbitrary — `web` (real Playwright/Chrome)
is always run alone, never concurrently with anything else, matching
this project's own repeatedly-confirmed finding (see the Phase 19.18/
19.19 reports) that concurrent real-browser + real-Qt-GUI pytest
invocations cause genuine slowdown even though the underlying server/
gateway fixtures are port-isolated. This script is now **the official
FYP regression procedure on Windows** — a phase report's "full
regression" claim should cite this script's own summary output, not a
single unbounded `pytest tests/` invocation.

## 4. What "passing" means in this project's phase reports

A phase report's test count is always the output of an actually-run
`pytest` invocation quoted in that same report, batched per the
practice above if the full suite wasn't run as one process that
session. A claim of physical verification always names the specific
device/session it came from. Neither is ever asserted from memory or
extrapolated from a previous phase's numbers.
