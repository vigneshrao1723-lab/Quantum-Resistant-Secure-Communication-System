# FYP Presentation Guide

Seven short demonstrations for the FYP presentation/viva, each naming
exactly what is shown, what the examiner should observe, and which
security property it proves. Demos 1–2 are live and interactive
(`python main.py`); Demos 3–6 use this project's own, already-reviewed
automated infrastructure — named explicitly so nothing here overstates
what was actually tested. Demo 7 is a live, standalone script
(`demo/multi_device_demo.py`) exercising the real production
multi-device API against a real running server. Full technical detail behind each demo lives
in [System Architecture](../architecture/system_architecture.md),
[Security Architecture](../architecture/security/security_architecture.md),
and [docs/demo/security_rejection_demo.md](security_rejection_demo.md).

## DEMO 1 — Normal secure communication (live)

**Shown:** Start the server (`python -m server.server`) and two
clients (`python main.py`), register/log in as two users, open a
direct conversation, send a message.

**Examiner observes:** The message appears in both windows; the
status bar shows the active algorithm (Kyber/ML-KEM-768 by default,
or RSA in comparison mode).

**Property demonstrated:** End-to-end message confidentiality
(AES-256-GCM) over a key established via post-quantum ML-KEM-768 (or
classical RSA), relayed but never decrypted by the server — see
[Secure Message Flow](../architecture/message_flow.md).

## DEMO 2 — Identity verification / fingerprint comparison (live)

**Shown:** In the open conversation's header, click **Verify
Identity**. `VerifyIdentityDialog` displays the combined-identity
fingerprint; compare it on both windows (or read it aloud, simulating
an out-of-band channel) and confirm.

**Examiner observes:** The peer's trust indicator moves from
unverified to verified; re-running verification after a genuine key
change would instead show `KEY_CHANGED`, not silent acceptance.

**Property demonstrated:** Trust is an explicit, local, human decision
— never automatic, never made by the server — see
[Security Architecture](../architecture/security/security_architecture.md#trust-state-machine).

## DEMO 3 — ML-DSA benchmark (live)

**Shown:** Run `python -m benchmark.benchmark_ml_dsa` live in a
terminal.

**Examiner observes:** Console output measuring key generation,
signing, and verification against the project's real ML-DSA-65
implementation, each timed sample individually correctness-checked,
finishing with the sizes table (1952/32/3309 bytes) and an explicit
caveat that timings are environment-dependent, not universal.

**Property demonstrated:** The post-quantum signature primitive
underlying every origin-authentication check in this system is real,
functional, and has a measured, bounded cost — see
[ML-DSA Benchmark](../benchmark/ml_dsa_benchmark.md).

## DEMO 4 — Malicious relay / security rejection (tested harness)

**Shown:** Run, live:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest \
  tests/test_key_establishment_rejection_observability.py::test_malicious_relay_group_key_receiver_survives_and_recovers \
  -v -s --log-cli-level=WARNING
```

**Not claimed:** This is not a live third attacker process splicing
into a running two-GUI session's traffic — that capability was not
built (deliberately out of scope, no new network-attack tooling). This
is the existing, already-reviewed test harness, which forges a real
`group_key_distribution` packet at the exact trust boundary (client↔
server relay) this project's threat model treats as untrusted — see
[docs/demo/security_rejection_demo.md](security_rejection_demo.md)'s
own honesty note.

**Examiner observes:** `PASSED`, plus (with `--log-cli-level=WARNING`)
the live `SECURITY: rejected key establishment (invalid_signature)...`
log line.

**Property demonstrated:** A forged key-establishment packet — from a
relay that does not hold the real sender's private signing key — is
rejected before decapsulation/decryption, and no key is installed. See
[Attack → Rejection → Recovery](../architecture/security/attack_rejection_recovery.md).

## DEMO 5 — GUI security warning (tested harness)

**Shown:** Run, live:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest \
  tests/test_security_rejection_gui.py::test_gui_notice_does_not_alter_peer_verification_or_key_state \
  -v -s
```

**Examiner observes:** `PASSED` — this test drives a real forged
packet through the real production `ClientSession.handle_group_key_
distribution()`, with a real `ChatWindow` attached, and asserts the
status-bar security notice becomes visible with safe, non-alarming
text, while peer-verification state and key state are provably
unchanged by the notice itself.

**Property demonstrated:** The GUI is a consumer of an already-made
security decision, never a second place where trust is decided — see
[Security Architecture](../architecture/security/security_architecture.md#gui-is-a-consumer-not-an-authority-phase-141).
For a live two-GUI look at the same notice text/timing without a
forged packet, the `security_rejection` Signal can also be emitted
directly — see `tests/test_security_rejection_gui.py::
test_security_rejection_signal_reaches_gui_and_shows_a_notice` for the
exact mechanism, reused rather than rebuilt here.

## DEMO 6 — Recovery / continued legitimate communication

**Shown:** Continuing the same DEMO 4 test run: after the tamper is
switched off, Alice sends one more genuine message, and the test
asserts it is delivered to Bob's conversation store.

**Examiner observes:** The same `PASSED` result from DEMO 4 already
covers this — no separate command is needed. For the live DEMO 1/2
windows: since the DEMO 4/5 harness runs against its own isolated
test server and session pair, the live windows from DEMO 1/2 were
never actually disrupted and can simply continue being used normally
afterward, which is itself the point being demonstrated.

**Property demonstrated:** A rejected attack leaves the receiver fully
operational — no crash, no reconnect, no re-verification required —
and legitimate communication resumes immediately. See
[Attack → Rejection → Recovery](../architecture/security/attack_rejection_recovery.md).

## DEMO 7 — Multi-device identity, synchronization & revocation (live)

**Shown:** With the server running, run
`python demo/multi_device_demo.py` (see
[demo/multi_device_demo.py](../../demo/multi_device_demo.py) for full
prerequisites and the exact command). It registers its own throwaway
demo accounts, prints a numbered PASS/FAIL trace, and cleans up after
itself.

**Examiner observes:** A single account enrolling three cryptographically
distinct devices (three separate ML-KEM/ML-DSA keypairs, three
device_ids); a second device authorized by the first; an EXISTING
conversation's key synchronized to it (`device_key_sync`) and used to
send a real message a third party (Bob) decrypts; a third device
enrolled and shown to hold its own distinct identity, never confused
with its siblings; the second device revoked, and a subsequent
device-sync attempt from it rejected by the server; the first and
third devices remaining unaffected; the revoked device's
already-synchronized key confirmed still present locally (revocation
is prospective, never retroactive erasure).

**Property demonstrated:** Per-device post-quantum cryptographic
identity, device authorization, ML-DSA-authenticated conversation-key
synchronization between an account's own devices, multi-device
identity separation, and honest, prospective-only revocation — this
project's strongest technical contribution. See
[Multi-Device Identity](../architecture/multi_device_identity.md).

## Summary table

| Demo | Live or harness | Property |
|---|---|---|
| 1. Normal communication | Live | Confidentiality (AES-GCM) + key establishment (ML-KEM/RSA) |
| 2. Identity verification | Live | Explicit, local, human trust decisions |
| 3. ML-DSA benchmark | Live | Real, functional, measured PQ signature primitive |
| 4. Malicious relay rejection | Tested harness | Origin authentication (ML-DSA) rejects forged key-establishment |
| 5. GUI security warning | Tested harness | GUI is a consumer, never a trust authority |
| 6. Recovery | Tested harness (same run as 4) | Fail-closed rejection does not disrupt legitimate operation |
| 7. Multi-device identity/sync/revocation | Live (`demo/multi_device_demo.py`) | Per-device identity, authorized device-to-device key sync, prospective revocation |
