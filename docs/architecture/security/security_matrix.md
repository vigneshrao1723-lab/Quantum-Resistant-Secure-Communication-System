# Security Matrix

The canonical, tracked record of this project's negative-path/attack
security testing, referenced by every phase report rather than
re-derived from scratch each time. Last compiled Phase 19.19, closing
the Phase 19.18 report's one outstanding "PARTIALLY TESTED" row (7 —
pending source device sync).

Every row cites a real, currently-passing test — not a claim. "TESTED/
PASS" means a negative-path test exists, runs against real code (a
real server, real ML-KEM/ML-DSA/AES-GCM, never a mock of the security
boundary itself), and currently passes. "STRUCTURALLY IMPOSSIBLE"
means the attack has no reachable wire representation to even attempt
(explained per-row, not asserted). This document does not claim
security for anything not tested — see each row's evidence.

| # | Case | Status | Evidence |
|---|---|---|---|
| 1 | Forged device identity | TESTED/PASS | `tests/test_device_identity.py::test_forged_enrollment_signature_rejected` |
| 2 | Forged account identity | STRUCTURALLY IMPOSSIBLE | The account is always server-resolved from the authenticated JWT (`authenticate_connection()`), never a client-supplied wire field — there is no field to forge as literally stated. Closest real analogue, TESTED/PASS: `tests/test_group_key_distribution_authorization.py::test_forged_sender_field_is_overwritten_with_authenticated_username`. |
| 3 | Forged target identity | TESTED/PASS | `tests/test_device_identity.py::test_modified_target_device_id_after_signing_rejected`, `tests/test_device_key_sync_hardening.py::test_replayed_package_cannot_be_redirected_to_a_different_target_device` |
| 4 | Wrong target fingerprint | TESTED/PASS | `tests/test_device_identity.py::test_modified_fingerprint_in_authorization_rejected`, `tests/test_device_key_sync_hardening.py::test_modified_target_fingerprint_after_signing_rejected` |
| 5 | Revoked source | TESTED/PASS | `tests/test_device_key_sync.py::test_sync_from_revoked_source_device_rejected`; ordinary-chat-relay case (L-1, Phase 19.18): `tests/test_device_identity.py::test_revoked_device_cannot_send_ordinary_direct_chat`, `test_revoked_device_cannot_send_ordinary_group_chat` |
| 6 | Revoked target | TESTED/PASS | `tests/test_device_key_sync.py::test_sync_to_revoked_target_device_rejected`; ordinary-chat-relay case: `tests/test_device_identity.py::test_revoked_device_cannot_receive_ordinary_direct_chat` |
| 7 | Pending source | TESTED/PASS *(Phase 19.19 — was PARTIALLY TESTED in the Phase 19.18 report)* | Authorization path: `tests/test_device_identity.py::test_pending_device_cannot_authorize_another`. Device-key-sync path (the specific gap the Phase 19.18 report named): `tests/test_device_key_sync.py::test_pending_source_device_cannot_sync`, added this phase — a never-authorized second device attempting `sync_conversation_key_to_device()` is rejected server-side and delivers nothing. |
| 8 | Pending target | TESTED/PASS | `tests/test_device_key_sync.py::test_pending_target_device_cannot_receive_sync` |
| 9 | Non-member source | TESTED/PASS | `tests/test_message_routing_security.py::test_non_member_cannot_inject_group_message`, `tests/test_group_key_distribution_authorization.py::test_non_member_sender_cannot_distribute_group_key` |
| 10 | Non-member target | TESTED/PASS | `tests/test_group_key_distribution_authorization.py::test_member_cannot_distribute_group_key_to_non_member`, `tests/test_group_re_add_membership.py::test_non_member_cannot_send_to_the_group` |
| 11 | Cross-conversation redirect | TESTED/PASS | `tests/test_conversation_redirect_security.py` |
| 12 | Cross-group redirect | TESTED/PASS | `tests/test_conversation_redirect_security.py` (same file; both conversation types covered) |
| 13 | Stale epoch | TESTED/PASS | `tests/test_device_key_sync_hardening.py::test_stale_epoch_sync_cannot_roll_back_already_advanced_local_epoch`, `tests/test_key_lifecycle_stale_state.py::test_stale_epoch_confirmation_cannot_regress_state` |
| 14 | Rollback | TESTED/PASS | `crypto/key_manager.py::KeyManager.store_key()`'s monotonic `max(current, epoch)` — same tests as row 13 exercise this directly |
| 15 | Modified ciphertext | TESTED/PASS | `tests/test_device_key_sync_hardening.py::test_modified_ciphertext_after_signing_rejected`, `tests/test_aes.py::test_tampered_ciphertext_byte_raises`, `tests/test_file_image_transfer_integration.py::test_oversized_attachment_bypassing_the_client_is_rejected_server_side_and_server_stays_responsive` (size-boundary variant, Phase 19.19) |
| 16 | Modified authentication tag | TESTED/PASS | `tests/test_aes.py::test_tampered_tag_raises` |
| 17 | Modified package type | TESTED/PASS | `tests/test_device_key_sync_hardening.py::test_modified_package_type_after_signing_rejected` |
| 18 | Modified conversation ID | TESTED/PASS | `tests/test_device_key_sync_hardening.py::test_modified_conversation_id_after_signing_rejected`, `tests/test_message_protocol.py::test_forgery_4b_modified_conversation_id_fails` |
| 19 | Simultaneous device race | TESTED/PASS | `tests/test_multi_device_concurrency.py::test_simultaneous_sync_from_two_source_devices_to_a_third_is_safe` |
| 20 | Three-device identity collision | TESTED/PASS | `tests/test_three_device_identity.py::test_bob_distinguishes_three_alice_devices_independently` |
| 21 | Three-device revocation | TESTED/PASS | `tests/test_three_device_identity.py::test_device_revocation_with_three_devices_is_prospective_and_honest` |
| 22 | Already-connected revoked-device traffic | TESTED/PASS | `tests/test_device_identity.py::test_revoked_device_cannot_send_ordinary_direct_chat`, `test_revoked_device_cannot_receive_ordinary_direct_chat`, `test_revoked_device_cannot_send_ordinary_group_chat`, `test_unrelated_users_unaffected_by_a_revoked_third_party_device` — the L-1 fix itself (Phase 19.18, `server/client_handler.py`) |

## Related, phase-specific security work not itself one of the 22 rows

- **Android peer-verification persistence** (Phase 19.19): a fail-
  closed persistence model, not a new attack-rejection case — see
  `docs/architecture/multi_device_identity.md`'s Phase 19.19 section
  and `tests/test_mobile_peer_verification_persistence.py` (3 tests:
  persists across relaunch, survives logout/login, correctly rejects
  — never silently trusts — a changed key discovered after relaunch).
- **Production TLS material rejection** (L-3, Phase 19.19): not a
  wire-protocol attack, but the same "fail closed on a real
  misconfiguration" posture — see `config.py::validate_config()` and
  `tests/test_production_tls_safety.py`.
- **Server-side file-size enforcement** (L-4, Phase 19.19): row 15's
  size-boundary variant, specifically proving the server stays
  responsive (does not crash or hang) after rejecting a bypassed
  client's oversized attachment — `tests/test_file_image_transfer_
  integration.py::test_oversized_attachment_bypassing_the_client_is_
  rejected_server_side_and_server_stays_responsive`.
- **Read receipt authenticity** (L-2, re-examined Phase 19.19): not a
  rejection case (there is no forgeable field to reject) — see
  `docs/architecture/security/threat_model.md`'s "Worked example: read
  receipts" section for the full, honest threat-boundary analysis.

## What this matrix does not claim

Consistent with `threat_model.md`'s own "Honest scope limitation":
this matrix proves rejection of the 22 named attack shapes at the
protocol/relay layer. It does not claim TLS itself is unbreakable,
that an already-compromised endpoint is defended against, or that a
fully Byzantine server (one willing to simply not relay messages,
rather than forge them) can be prevented from degrading service —
those are explicitly out of scope, stated plainly rather than left
for a reader to assume were tested.
