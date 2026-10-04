# Attack → Rejection → Recovery Sequence

The authoritative source for this document is the completed Phase 14.2
demonstration: [docs/demo/security_rejection_demo.md](../../demo/security_rejection_demo.md),
and the tests it points at —
`tests/test_key_establishment_rejection_observability.py::test_malicious_relay_group_key_receiver_survives_and_recovers`
and
`tests/test_security_rejection_gui.py::test_gui_notice_does_not_alter_peer_verification_or_key_state`.
Both were re-run while writing this document and pass (`2 passed`) —
see the demo document's own "Reproducing the whole thing in one
command" section for the exact command.

This is written for an FYP viva: a single sequence, from a normal
message through an attack, to full recovery, that an examiner can
follow end to end.

## The sequence

```
NORMAL MESSAGE
      │  Alice sends an ordinary chat message to Bob; it decrypts
      │  and displays normally (see message_flow.md).
      ▼
KEY/SECURITY PACKET
      │  A group-key distribution (or RSA session-key) packet is
      │  produced and sent — see key_establishment_flow.md.
      ▼
MALICIOUS RELAY MODIFICATION
      │  The relay point (server, or anything positioned there —
      │  see threat_model.md) rewrites the packet's wrapped_key
      │  field using an attacker-controlled KeyManager that has
      │  Bob's real PUBLIC key but not his private key.
      ▼
BOB RECEIVES FORGED PACKET
      │  ClientSession.handle_group_key_distribution() begins
      │  processing it exactly like any other incoming packet.
      ▼
AUTHENTICATION/SIGNATURE CHECK
      │  The ML-DSA signature is verified against Bob's own,
      │  LOCALLY held trusted signing key for the claimed sender —
      │  never a key carried in the packet.
      ▼
FAIL
      │  The forged packet's signature does not verify under
      │  Bob's trusted key for "alice".
      ▼
SECURITY REJECTION
      │  handle_group_key_distribution() returns
      │  SecurityRejectionReason.INVALID_SIGNATURE and calls
      │  _report_security_rejection() (one safe WARNING log line;
      │  no key material, signature, or ciphertext logged).
      ▼
NO KEY INSTALLATION
      │  KeyManager.store_key() is never reached — verified
      │  empirically: bob.key_manager.keys stays empty for this
      │  conversation.
      ▼
TRUST STATE PRESERVED
      │  Bob's VERIFIED record for Alice is untouched — nothing
      │  about this rejection alters peer-identity state.
      ▼
GUI SECURITY WARNING
      │  ClientSession.security_rejection Signal → ChatWindow.
      │  handle_security_rejection() → StatusBarWidget.
      │  set_security_notice() — a non-blocking, self-clearing
      │  status-bar line, e.g. "Security warning: an incoming
      │  packet was rejected -- it failed authentication. No
      │  trusted key or identity state was changed."
      ▼
RECEIVER REMAINS ALIVE
      │  bob.is_connected() and bob.receiver_thread.is_alive()
      │  both remain true — rejection is an ordinary return path,
      │  never an exception that could kill the receiver thread.
      ▼
LEGITIMATE MESSAGE
      │  Alice sends another, genuine message — no reconnect, no
      │  re-verification, no manual recovery step performed.
      ▼
SUCCESS
      │  The message is delivered and appears in Bob's
      │  conversation store normally.
```

## Honest limitation, carried forward from the Phase 14.2 demo

The "malicious relay" step above is demonstrated through the existing,
already-reviewed test harness (a monkeypatch on `client.session.
send_message`, the single function every outgoing packet passes
through) — **not** a separate, live third attacker process actively
splicing itself into a running two-GUI session's network traffic. That
specific capability was not built or tested (deliberately out of scope
for Phase 14.2 — no new network-attack tooling), and this document
does not claim otherwise. See
[docs/demo/security_rejection_demo.md](../../demo/security_rejection_demo.md)'s
own "Honesty note" for the full reasoning: the harness simulates the
exact trust boundary this project's threat model treats as untrusted
(the client↔server relay point), using the same technique already
reviewed across Phase 13's audits.

## Where each step is proven, precisely

| Sequence step | Proven by |
|---|---|
| Normal message / legitimate recovery | `test_malicious_relay_group_key_receiver_survives_and_recovers`'s final assertion |
| Malicious relay modification | Same test's `tampering_send_message` monkeypatch |
| Authentication check / fail / rejection | Same test's `SecurityRejectionReason.INVALID_SIGNATURE` assertion |
| No key installation | Same test's `assert all(not epochs for epochs in bob.key_manager.keys.values())` |
| Trust state preserved | `test_gui_notice_does_not_alter_peer_verification_or_key_state`'s before/after peer-verification-state assertion |
| GUI security warning | Same test's `window.status.security_label.isVisible() is True` assertion |
| Receiver remains alive | `test_malicious_relay_...`'s `bob.is_connected()` / `bob.receiver_thread.is_alive()` assertions |
