# Security Rejection Demonstration

A reproducible procedure for showing, live, that this application
detects and rejects a forged/malicious key-establishment packet
without corrupting trust state or interrupting legitimate
communication — and that the rejection is visible to the user, not
just to a log file.

This demonstrates the application's **defensive behavior**. It is not
an offensive attack tool: the "attacker" step below reuses this
project's own existing, already-reviewed test harness
(`tests/test_key_establishment_rejection_observability.py` and
`tests/test_security_rejection_gui.py`) rather than any new network
attack tooling, packet-sniffing, or offensive automation. Nothing in
this document requires — or should be extended to require — anything
beyond the local development machine.

## What this demonstrates

```
security validation (client/session.py)
        |
        v
  ClientSession.security_rejection  Signal(reason, sender, conversation_id)
        |
        v
  ChatWindow.handle_security_rejection()   (Phase 14.1)
        |
        v
  StatusBarWidget.set_security_notice()    non-blocking status-bar warning
```

The rejection decision itself (is this packet's origin authenticated?)
is made once, entirely inside `ClientSession`
(`handle_group_key_distribution()` / `handle_session_key()`), before
any signal is ever emitted. The GUI is purely a **consumer** of that
already-made decision (Phase 14.1) — it never re-implements, second-
guesses, or overrides it. This document exercises that whole chain,
end to end, using the real production code at every step.

## Components involved

| Component | Role |
|---|---|
| PostgreSQL | Backing store (as in normal operation) |
| `python -m server.server` | The real server — an untrusted relay, per this project's threat model (see `README.md`'s "Threat model" section) |
| Client "Alice" | Legitimate user, `python main.py` |
| Client "Bob" | Legitimate user (the one who will observe the attack), `python main.py` |
| Attacker | Not a separate process — a monkeypatched relay inside the existing pytest harness (see Part 2) |

---

## Part 1 — Legitimate setup (Steps 1–4)

This part is fully interactive and uses nothing but the shipped
application.

**Step 1 — Start the system.**

```bash
python scripts/generate_dev_certs.py   # once, if certs/ is empty
python -m server.server
```

In a second and third terminal, start two clients:

```bash
python main.py      # register/log in as "alice"
python main.py      # register/log in as "bob"
```

**Step 2 — Establish communication.**

From Alice's window, find Bob (Find User dialog, by username or phone
number) and open a direct conversation. Bob's client will receive
Alice's Kyber/ML-DSA public key material automatically (existing
public-key exchange, unchanged by this phase).

**Step 3 — Identity verification (normal project workflow).**

In the open conversation's header, click **Verify Identity**. Both
Alice and Bob compare the combined-identity fingerprint shown by
`VerifyIdentityDialog` (out-of-band — read it aloud, compare on a
second channel, etc., exactly as the existing verification workflow
requires) and confirm. This moves the peer's trust state to
**VERIFIED** on each side — the same `observe_peer_identity()` /
`confirm_combined_peer_verification()` calls the automated tests below
also drive.

**Step 4 — Send a normal legitimate message.**

Alice sends an ordinary chat message to Bob.

*Expected:* the message is delivered and decrypts normally on Bob's
side. Nothing about Parts 2–3 below requires redoing this by hand
during a live demo — it is here to establish the "before" state.

---

## Part 2 — Malicious-relay / forged key-establishment (Steps 5–7)

**Honesty note:** a real two-GUI live attack (a third process actively
splicing itself into Alice ↔ server ↔ Bob's live TCP/TLS traffic and
rewriting packets in flight) was not built or tested in this phase,
per this phase's explicit scope (no new network-attack tooling). What
*is* built, tested, and fully reproducible is the equivalent at the
same trust boundary this project's own threat model treats as
untrusted: the relay point between client and server. The existing
test harness simulates exactly that relay position by monkeypatching
`client.session.send_message` — the one function every outgoing packet
passes through — so it forges a `group_key_distribution` packet's
`wrapped_key` in flight, using an attacker-controlled `KeyManager` that
never had access to either legitimate party's private key material.
This is the same technique `test_rsa_session_key_authentication.py`'s
and `test_group_key_authentication.py`'s own malicious-relay tests
already use and that Phase 13's audits already reviewed — reused here
verbatim, not reinvented.

**Step 5 — Run the existing tested attack harness.**

```bash
QT_QPA_PLATFORM=offscreen \
  python -m pytest tests/test_key_establishment_rejection_observability.py::test_malicious_relay_group_key_receiver_survives_and_recovers \
  -v -s
```

What this test does (readable in full at
`tests/test_key_establishment_rejection_observability.py`, function
`test_malicious_relay_group_key_receiver_survives_and_recovers`):

1. Starts a real local TLS test server and connects real Alice/Bob
   `ClientSession`s to it (the same production `ClientSession` class
   `main.py` uses).
2. Alice and Bob verify each other's identity (Step 3's programmatic
   equivalent — `observe_peer_identity()` +
   `confirm_combined_peer_verification()`).
3. Installs the relay tamper on `send_message`: any
   `group_key_distribution` packet has its `wrapped_key` field
   replaced with one re-wrapped under an attacker's own `KeyManager`
   (the attacker has Bob's real *public* key — broadcast by design —
   but not his private key).
4. Alice creates a group conversation containing Bob, which triggers a
   real group-key distribution packet — intercepted and forged in
   flight by the step above.
5. Asserts the forged packet was rejected with
   `SecurityRejectionReason.INVALID_SIGNATURE`, observable on Bob's
   own `security_rejection` signal.
6. Asserts no key was installed anywhere in Bob's `key_manager`.
7. Asserts Bob's connection and receiver thread are still alive.
8. Turns the tamper off and sends one more, genuine message from Alice
   to Bob — Step 8, see Part 3.

**Step 6 — Observe the rejection (console).**

By default, pytest only prints captured log output for a *failing*
test. To see the real log line live (the test still passes — this
only changes what's printed), add `--log-cli-level=WARNING`:

```bash
QT_QPA_PLATFORM=offscreen \
  python -m pytest tests/test_key_establishment_rejection_observability.py::test_malicious_relay_group_key_receiver_survives_and_recovers \
  -v -s --log-cli-level=WARNING
```

This surfaces the real log line
`handle_group_key_distribution()` already emits on every rejection
(`client/session.py::_report_security_rejection()`), verified verbatim
by actually running this command:

```
WARNING  client_logger:session.py:3464 SECURITY: rejected key establishment (invalid_signature) for conversation 817c77e7-..., claimed sender kero_alice_....
```

**Step 7 — Confirm the security invariants (this is what the test's
assertions prove, and what to point at during a viva):**

- **Trusted peer key is not overwritten** — Bob's already-VERIFIED
  identity record for Alice is untouched; the test never re-checks
  Alice's trust state because nothing about this attack could have
  changed it (the attack targets a group-key packet, not the identity
  record itself), and Part 2 of `test_key_establishment_rejection_observability.py`'s
  wider suite (not re-run here to avoid duplicating Phase 13) proves
  this class of invariant exhaustively.
- **Forged key is not installed** —
  `assert all(not epochs for epochs in bob.key_manager.keys.values())`.
- **Application does not crash** —
  `assert bob.is_connected()` and
  `assert bob.receiver_thread.is_alive()`.
- **GUI displays the security warning** — this exact scenario (a real,
  production-path forged `group_key_distribution` packet, delivered to
  a real `ChatWindow`-attached session) is proven separately by
  `tests/test_security_rejection_gui.py::test_gui_notice_does_not_alter_peer_verification_or_key_state`,
  which additionally asserts `window.status.security_label.isVisible()
  is True` and that its text contains `"unknown sender"` (that test's
  scenario differs slightly — the forging identity is entirely
  unknown to Bob rather than a re-signed packet from an already-known
  sender — so the exact displayed reason differs, but the GUI
  consumption path being exercised is identical). Run it explicitly to
  see the GUI side of the chain:

  ```bash
  QT_QPA_PLATFORM=offscreen \
    python -m pytest tests/test_security_rejection_gui.py::test_gui_notice_does_not_alter_peer_verification_or_key_state \
    -v -s
  ```

  In a live two-GUI session, the equivalent visible behavior is a
  status-bar line reading *"Security warning: an incoming packet was
  rejected — \<reason\>. No trusted key or identity state was
  changed."*, appearing on Bob's window and auto-clearing after six
  seconds (`gui/status_bar.py::SECURITY_NOTICE_DURATION_MS`) — see
  `gui/chat_window.py::SECURITY_REJECTION_MESSAGES` for the exact,
  attacker-content-free text shown for every reason.

---

## Part 3 — Recovery (Step 8)

Still within the same `test_malicious_relay_group_key_receiver_survives_and_recovers`
run: after the tamper is switched off, Alice sends one more, genuine
chat message, and the test waits for it to arrive in Bob's
conversation store:

```python
assert _wait_for(
    lambda: any(
        s.latest_message and s.latest_message.text == "legitimate message after the attack"
        for s in bob.conversation_store.get_all()
    )
)
```

*Expected:* this assertion passes — normal secure communication
resumes immediately after the rejected attack, with no reconnect, no
re-verification, and no manual recovery step required.

For a live two-GUI demo, the equivalent is: after Part 2's automated
run completes (proving the rejection), simply continue using the
Alice/Bob windows from Part 1 exactly as before — Parts 1 and 3 were
never actually disrupted by anything in Part 2, since Part 2 runs
against its own isolated test server/session pair. This is itself the
point: the attack (run in complete isolation) cannot and does not
touch the live demo session's state.

---

## Reproducing the whole thing in one command

```bash
QT_QPA_PLATFORM=offscreen python -m pytest \
  tests/test_key_establishment_rejection_observability.py::test_malicious_relay_group_key_receiver_survives_and_recovers \
  tests/test_security_rejection_gui.py::test_gui_notice_does_not_alter_peer_verification_or_key_state \
  -v -s
```

Expected result: `2 passed`. Both tests are part of this project's
permanent, already-reviewed regression suite (Phase 13.7 and Phase
14.1 respectively) — this command does not add any new test, it
simply points at the two that together cover the full attack→reject→
notify→recover chain.

## Verification checklist

- [ ] Server and both clients start cleanly (Part 1, Step 1).
- [ ] Bob receives Alice's public key material automatically (Step 2).
- [ ] Identity verification fingerprint matches on both sides (Step 3).
- [ ] A normal message is delivered before any attack (Step 4).
- [ ] `test_malicious_relay_group_key_receiver_survives_and_recovers`
      passes (Steps 5–7 backend proof).
- [ ] `test_gui_notice_does_not_alter_peer_verification_or_key_state`
      passes (Step 7 GUI proof).
- [ ] Neither test's console output contains the forged key material,
      a signature, or any other secret (see each test's own file for
      the exact assertions covering this).
- [ ] A legitimate message after the attack is still delivered (Step
      8).
