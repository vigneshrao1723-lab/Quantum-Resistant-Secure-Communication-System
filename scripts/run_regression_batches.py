"""
Batched regression test runner (Phase 19.19 -- L-7 closure).

L-7's own finding (docs/architecture/testing_strategy.md) is that the
full pytest suite is unreliable as ONE continuous Windows process --
three distinct native-level crash/hang classes were observed across
sessions (an ssl.py teardown fault, a genuine deadlock, and a PySide6
processEvents() access violation once enough Qt tests accumulate in
one process), never a defect in the test logic itself. That is not
fixable from application code -- it is a Windows/Qt/native-extension
resource-accumulation problem in the test *process*, not a bug this
project's own source can patch.

What IS fixable, and is what this script provides: a reliable,
reproducible, documented BATCHING procedure, so the full logical
regression suite can still be run to completion, in bounded, isolated
pytest subprocesses, without ever needing to fall back to "run
everything in one process and hope." This is the official FYP
regression procedure on Windows referenced by
docs/architecture/testing_strategy.md.

Each batch below is a real, curated grouping by actual resource
profile (pure crypto/protocol unit tests never open a Qt widget or a
socket; Desktop GUI tests construct real QDialog/QWidget instances;
Web tests drive a real Playwright/Chromium browser -- the heaviest and
most contention-prone category, always run alone, never concurrently
with anything else) -- not an arbitrary alphabetical split. The
grouping itself is the product of this project's own accumulated,
empirical experience running these exact files together, repeatedly,
across many sessions (see the "regression" sections of the various
phase reports under docs/ and this repository's own commit history for
that evidence) -- not a guess.

Usage:
    python scripts/run_regression_batches.py            # every batch
    python scripts/run_regression_batches.py --list      # show batches, don't run
    python scripts/run_regression_batches.py --batch web  # run one named batch only

Exit code is 0 only if every batch's pytest process itself exited 0.
A batch that hangs is bounded by --timeout-seconds per batch (default
900s / 15 minutes) rather than left to hang the whole run indefinitely
-- consistent with this project's own repeated instruction never to
wait indefinitely on a suspected-hung Windows test process.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------
# Batch definitions -- name -> list of test files (relative to
# REPO_ROOT). Order matters: lighter, faster batches first, so a
# quick "did I break something obvious" signal comes back early.
# ---------------------------------------------------------------

BATCHES: dict[str, list[str]] = {
    "crypto_unit": [
        "tests/test_aes.py",
        "tests/test_kyber.py",
        "tests/test_ml_dsa.py",
        "tests/test_message_protocol.py",
        "tests/test_identity_protocol.py",
        "tests/test_combined_identity_fingerprint.py",
        "tests/test_jwt_handler.py",
        "tests/test_password_handler.py",
        "tests/test_public_key_fingerprint.py",
        "tests/test_public_key_validation.py",
        "tests/test_request_registry.py",
        "tests/test_session_repository.py",
        "tests/test_user_repository.py",
        "tests/test_authentication_service.py",
        "tests/test_phase12a_downgrade_audit.py",
        "tests/test_key_distribution_origin_authentication.py",
        "tests/test_kyber_session_key_forgery_remediation.py",
        "tests/test_rsa_key_exchange_integration.py",
        "tests/test_rsa_session_key_authentication.py",
        "tests/test_production_tls_safety.py",
        "tests/test_configuration_separation.py",
        "tests/test_client_import_boundary.py",
    ],
    "device_security": [
        "tests/test_device_identity.py",
        "tests/test_device_key_sync.py",
        "tests/test_device_key_sync_hardening.py",
        "tests/test_multi_device_concurrency.py",
        "tests/test_multi_device_peer_identity.py",
        "tests/test_three_device_identity.py",
        "tests/test_same_account_multi_device_routing.py",
        "tests/test_epoch_and_domain_security.py",
        "tests/test_key_lifecycle_stale_state.py",
        "tests/test_conversation_redirect_security.py",
        "tests/test_message_routing_security.py",
        "tests/test_key_establishment_rejection_observability.py",
        "tests/test_peer_identity_state_transitions.py",
        "tests/test_peer_key_verification.py",
        "tests/test_public_key_identity_binding.py",
        "tests/test_first_contact_verification.py",
        "tests/test_verify_late_key_recovery.py",
        "tests/test_invalid_key_recovery.py",
        "tests/test_direct_key_desync_recovery.py",
        "tests/test_read_receipt_relay_race.py",
        "tests/test_tls_production_integration.py",
        "tests/test_tls_transport.py",
        "tests/test_server_auth_integration.py",
        "tests/test_server_connection_limits.py",
        "tests/test_network_frame_limits.py",
        "tests/test_registration_integration.py",
    ],
    # Split 2026-10-04 (final acceptance pass) from a single 44-file
    # "messaging_groups" batch: that combined batch, which had always
    # passed cleanly before (349.7s-527.4s across several earlier
    # sessions), reproducibly hung past the 900s bound twice in a row
    # this pass -- the SAME class this file's own docstring already
    # names for Desktop GUI/Qt (real-resource accumulation across many
    # tests in one process), just newly observed on a large enough
    # pure-backend/real-socket batch instead of a GUI one. Bisection
    # (confirmed by direct re-run, not guessed): the first 22 files
    # always pass together (199.2s); of the remaining 22, the 22-file
    # combination hangs but EITHER 11-file half passes cleanly alone
    # (88.6s / 48.6s) -- not one bad file, the same "accumulates across
    # enough real sockets/threads in one process" mechanism. Same
    # sanctioned fix as desktop_gui_lifecycle's own a/b1/b2 split: three
    # smaller, reliable batches beat one large unreliable one.
    "messaging_groups_a": [
        "tests/test_message_persistence_integration.py",
        "tests/test_message_history_request_response.py",
        "tests/test_message_authentication.py",
        "tests/test_private_messaging_integration.py",
        "tests/test_chat_encryption_integration.py",
        "tests/test_conversation_repository.py",
        "tests/test_conversation_list_request_response.py",
        "tests/test_conversation_store_key_resolution.py",
        "tests/test_direct_conversation_relay_resolution.py",
        "tests/test_direct_conversation_request_response.py",
        "tests/test_group_messaging_integration.py",
        "tests/test_group_membership_integration.py",
        "tests/test_group_add_members_integration.py",
        "tests/test_group_admin_and_inbox.py",
        "tests/test_group_creation_multi_member.py",
        "tests/test_group_device_key_sync.py",
        "tests/test_group_history_reconnect_recovery.py",
        "tests/test_group_key_authentication.py",
        "tests/test_group_key_distribution_authorization.py",
        "tests/test_group_key_distribution_resilience.py",
        "tests/test_group_key_protocol.py",
        "tests/test_group_re_add_membership.py",
    ],
    "messaging_groups_b1": [
        "tests/test_read_receipts_integration.py",
        "tests/test_read_receipts_realtime.py",
        "tests/test_receiver_thread_conversation_id_consumption.py",
        "tests/test_offline_first_contact.py",
        "tests/test_offline_messaging.py",
        "tests/test_offline_unread_notification.py",
        "tests/test_presence_synchronization.py",
        "tests/test_phone_number_discovery.py",
        "tests/test_key_manager.py",
        "tests/test_key_manager_group_keys.py",
        "tests/test_key_store_persistence.py",
    ],
    "messaging_groups_b2": [
        "tests/test_own_kyber_keypair_persistence.py",
        "tests/test_own_signing_keypair_persistence.py",
        "tests/test_payload_pipeline.py",
        "tests/test_file_payload_pipeline.py",
        "tests/test_file_image_transfer_integration.py",
        "tests/test_attachment_classification.py",
        "tests/test_attachment_hardening.py",
        "tests/test_desktop_settings.py",
        "tests/test_phase19_24_message_lifecycle_security.py",
        "tests/test_phase19_24_presence_last_seen.py",
        "tests/test_phase19_24_block_user_security.py",
    ],
    "mobile": [
        "tests/test_mobile_client_session.py",
        "tests/test_mobile_device_key_sync.py",
        "tests/test_mobile_key_desync_recovery.py",
        "tests/test_mobile_peer_verification_persistence.py",
        "tests/test_mobile_settings.py",
        "tests/test_phase19_24_mobile_lifecycle_wiring.py",
        "tests/test_phase19_24_mobile_bubble_ui.py",
        "tests/test_phase19_24_mobile_typing_indicator.py",
        "tests/test_phase19_24_mobile_drafts.py",
        "tests/test_phase19_24_mobile_mute.py",
        "tests/test_phase19_24_mobile_archive.py",
        "tests/test_phase19_24_mobile_retry.py",
        "tests/test_phase19_24_mobile_block.py",
        "tests/test_phase19_24_mobile_wallpaper.py",
        "tests/test_phase19_24_mobile_message_search.py",
        "tests/test_phase19_24_mobile_pinned_messages.py",
        "tests/test_phase19_24_mobile_forward_media.py",
        "tests/test_phase19_24_mobile_media_gallery.py",
        "tests/test_phase19_24_mobile_voice_video.py",
        "tests/test_phase19_24_mobile_presence_last_seen.py",
    ],
    # Split from a single 29-file "desktop_gui" batch (2026-09-19): that
    # combined batch had started reliably timing out at the 900s bound
    # (not merely flaking) once test_phase19_24_desktop_{ui_wiring,
    # mute,archive,block,wallpaper}.py accumulated in ONE process
    # alongside everything else -- confirmed by bisection (see this
    # repo's own investigation: the first ~15 lighter GUI-construction
    # files pass together in 18s flat; the remaining files, all of
    # which build real multi-window ClientSession pairs and send real
    # messages over a real socket, are what accumulates the native Qt/
    # Windows resource exhaustion this project's testing_strategy.md
    # already documents). Two smaller, reliable batches beat one large
    # unreliable one -- the same "what IS fixable" principle this
    # script's own module docstring states.
    "desktop_gui": [
        "tests/test_attachment_gui.py",
        "tests/test_add_members_dialog_search.py",
        "tests/test_create_group_dialog_gui.py",
        "tests/test_find_user_dialog_gui.py",
        "tests/test_group_member_selection_clicks.py",
        "tests/test_security_rejection_gui.py",
        "tests/test_read_receipts_gui.py",
        "tests/test_chat_window_connection_status.py",
        "tests/test_chat_window_read_receipt_on_receive.py",
        "tests/test_composer_to_bubble_character_fidelity.py",
        "tests/test_composer_public_key_availability.py",
        "tests/test_date_separators.py",
        "tests/test_image_viewing.py",
        "tests/test_initial_chat_state.py",
        "tests/test_internal_messages_not_shown_as_chat.py",
    ],
    # Split further (from a single "desktop_gui_lifecycle" batch) after
    # THAT batch itself started reliably timing out at the 900s hard
    # bound even run standalone with nothing else competing for Qt/
    # Windows resources -- i.e. a genuine per-batch accumulation
    # problem, not merely contention with other concurrent test runs.
    # Same sanctioned fix as the original desktop_gui/desktop_gui_
    # lifecycle split: halve the file list, not the timeout.
    "desktop_gui_lifecycle_a": [
        "tests/test_list_row_height_not_clipped.py",
        "tests/test_login_window_phone_identifier.py",
        "tests/test_login_logout_integration.py",
        "tests/test_message_status_indicators.py",
        "tests/test_message_timestamp_local_display.py",
        "tests/test_conversation_store_sidebar_visibility.py",
        "tests/test_rich_text_injection.py",
        "tests/test_user_id_search.py",
    ],
    # Split further after desktop_gui_lifecycle_b itself started
    # reliably timing out at the 900s hard bound (standalone, nothing
    # else competing for Qt/Windows resources) -- same class of
    # per-batch GUI-resource-accumulation issue this project's own
    # batching scheme exists to work around (see this file's own
    # module docstring), not a regression in any individual file
    # (every one of these passes standalone).
    "desktop_gui_lifecycle_b1": [
        "tests/test_device_management.py",
        "tests/test_peer_profile_picture_viewing.py",
        "tests/test_phase19_24_desktop_ui_wiring.py",
        "tests/test_phase19_24_desktop_mute.py",
        "tests/test_phase19_24_desktop_archive.py",
    ],
    "desktop_gui_lifecycle_b2": [
        "tests/test_phase19_24_desktop_block.py",
        "tests/test_phase19_24_desktop_wallpaper.py",
        "tests/test_phase19_24_desktop_message_search.py",
        "tests/test_phase19_24_desktop_pinned_messages.py",
        "tests/test_phase19_24_desktop_voice_video.py",
    ],
    "web": [
        "tests/test_web_browser_e2e.py",
        "tests/test_web_client_crypto_interop.py",
        "tests/test_web_feature_completion_e2e.py",
        "tests/test_web_gateway_interop.py",
        "tests/test_web_persistence_reconnect.py",
        "tests/test_web_settings_and_inbox.py",
        "tests/test_web_phase19_24_lifecycle_ui.py",
    ],
}


def _kill_process_tree(pid: int) -> None:
    """Kill this process AND every descendant it spawned.

    A plain Popen.kill() only signals the single PID it's given. On
    this project's Windows dev environment, `sys.executable` (the
    venv's python.exe) is a thin launcher that spawns the real base
    interpreter as a CHILD process -- confirmed directly: every long-
    running service started this way (server/gateway/static web/any
    pytest batch) shows up as TWO distinct PIDs with identical
    command-line arguments, one under venv/Scripts, one under the base
    install. Killing only the top PID can leave that real child --
    and anything IT spawned in turn (a hung Qt event loop, an orphaned
    Playwright/Chromium process) -- running indefinitely with the
    output pipe still open. taskkill's /T flag kills the whole tree
    rooted at this PID in one call, which is the only reliable way to
    make a stated timeout an actual bound rather than a best-effort
    hint.
    """
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
        return
    import signal

    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_batch(name: str, files: list[str], timeout_seconds: int) -> tuple[bool, float, str]:
    existing = [f for f in files if (REPO_ROOT / f).exists()]
    missing = [f for f in files if f not in existing]
    if missing:
        print(f"  (skipping missing files in batch {name!r}: {missing})")

    started = time.perf_counter()
    popen_kwargs = {}
    if sys.platform == "win32":
        # Own process group, so the tree-kill below can't accidentally
        # take this script itself down with it.
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    process = subprocess.Popen(
        [sys.executable, "-u", "-m", "pytest", "-q", *existing],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        **popen_kwargs,
    )
    try:
        stdout, _ = process.communicate(timeout=timeout_seconds)
        elapsed = time.perf_counter() - started
        # Phase 19.20: a failure needs enough of the tail to show the
        # actual assertion/traceback, not just the summary line -- 15
        # lines was too short to diagnose a real failure without a
        # separate, manual re-run (see test_web_inbox_approve_
        # verification_request_real_ui's own Phase 19.20 flake for the
        # concrete case that found this).
        lines = stdout.strip().splitlines()
        tail = "\n".join(lines[-80:] if process.returncode != 0 else lines[-15:])
        return process.returncode == 0, elapsed, tail
    except subprocess.TimeoutExpired:
        # Do NOT fall back to the stdlib's own default Windows timeout
        # cleanup here (a second, UNBOUNDED process.communicate() call)
        # -- that is the exact, confirmed mechanism behind this
        # project's own repeatedly observed "TIMED OUT after 900s"
        # label carrying an ACTUAL measured elapsed time of multiple
        # hours (one measured instance: 174359.8s, ~48 hours) instead
        # of the stated bound. Kill the whole tree first, then bound
        # the final drain read too, so this really is a hard ceiling.
        _kill_process_tree(process.pid)
        try:
            stdout, _ = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            stdout = ""
        elapsed = time.perf_counter() - started
        return False, elapsed, f"TIMED OUT after {timeout_seconds}s -- process tree killed, not hung indefinitely"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", help="Run only this named batch")
    parser.add_argument("--list", action="store_true", help="List batches and file counts, then exit")
    parser.add_argument(
        "--timeout-seconds", type=int, default=900,
        help="Per-batch timeout (default 900s/15min) -- a batch that exceeds this is treated as failed, never awaited indefinitely",
    )
    args = parser.parse_args()

    selected = {args.batch: BATCHES[args.batch]} if args.batch else BATCHES

    if args.list:
        for name, files in selected.items():
            print(f"{name}: {len(files)} files")
        return 0

    results: list[tuple[str, bool, float, str]] = []

    for name, files in selected.items():
        print(f"\n=== Batch: {name} ({len(files)} files) ===")
        ok, elapsed, tail = run_batch(name, files, args.timeout_seconds)
        results.append((name, ok, elapsed, tail))
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name} in {elapsed:.1f}s")
        if not ok:
            print(tail)

    print("\n=== Summary ===")
    overall_ok = True
    for name, ok, elapsed, _tail in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {status:4s}  {name:20s}  {elapsed:7.1f}s")
        overall_ok = overall_ok and ok

    print(f"\nOverall: {'PASS' if overall_ok else 'FAIL'}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
