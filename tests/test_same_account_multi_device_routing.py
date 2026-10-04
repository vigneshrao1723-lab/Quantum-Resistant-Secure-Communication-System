"""
Phase 18.5 -- Closure Audit, Step 3: Same-Account Multi-Device Routing.

Before this phase, server/client_handler.py's live "chat" relay for a
DIRECT message stopped at the FIRST connected socket it found matching
the receiver's username (an unconditional ``break``) -- so if an
account had two devices connected simultaneously (desktop + browser,
or desktop + a second desktop), only ONE of them ever received a live
direct message; the other was silently skipped. Group messaging never
had this limitation (handle_group_chat_delivery() already fans out to
every currently-connected socket belonging to a member -- confirmed by
reading it before writing this fix). This file proves the direct-chat
relay now does the same thing, using the SAME precedented per-socket
fan-out pattern, not a new routing mechanism.

Deliberately NOT attempting to also solve "a third party (Alice)
recognizing Bob's two devices as one identity" -- that is a genuinely
separate, harder problem crypto/identity_protocol.py's own fail-closed
KEY_CHANGED behavior already handles correctly (each of Bob's devices
generates its own independent KEM/ML-DSA keypair; Alice's peer-trust
slot for "bob" is keyed by username, so a second device's own public-
key broadcast is correctly flagged KEY_CHANGED against whatever Alice
already verified) and which tests/test_device_key_sync.py::
test_newly_authorized_device_receives_existing_conversation_key_and_
messages_bob's own docstring already explicitly scopes out ("reconciling
THAT is a harder, separate problem ... this phase does not claim to
solve").

A real, concrete consequence of that (discovered while writing this
test, not previously documented): establish_session_key()'s Server-
Untrusted Identity Verification Stage-3 check re-verifies "is this
peer currently VERIFIED" on EVERY send, not only the first one that
creates a conversation's key (see that method's own docstring/
comments) -- so once Bob's second device's own public-key broadcast
flips Alice's peer-trust record for "bob" to KEY_CHANGED, Alice's VERY
NEXT send_chat_message() to "bob" raises PeerNotVerifiedError, even
though the AES conversation key itself is already cached and would
otherwise still work. This is correct, intentional, fail-closed
behavior, not a routing bug -- exactly the same prompt a real user
would see and needs to act on (re-verify the changed fingerprint)
before continuing to message that account. This test's own scenario
below re-verifies "bob" after desktop2 joins, precisely mirroring what
a real user does, so that the ROUTING fix can be demonstrated on its
own terms without being confused with -- or attempting to silently
route around -- this separate, intentional identity-layer behavior.

Run with:
    pytest tests/test_same_account_multi_device_routing.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from crypto.key_manager import fingerprint_combined_identity
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_VERIFIED
from tests.test_device_key_sync import (
    _delete,
    _mutually_verify_devices,
    _new_device_session,
    _register,
    _verify_peers,
    _wait_for,
    account,
    running_server,
)

_app = QApplication.instance() or QApplication([])


def test_direct_message_reaches_both_of_the_same_accounts_connected_devices(
    running_server, monkeypatch, account, tmp_path
):
    """
    Bob has two devices connected at once (desktop1, desktop2 -- the
    SAME account). Alice, a third, unrelated account, already has an
    established conversation with Bob (via desktop1) before desktop2
    ever connects. Once desktop2 is authorized and has synced the
    conversation's real key (the existing, already-proven Phase 16C/18
    mechanism), a NEW live message from Alice must reach -- and be
    independently decryptable by -- BOTH of Bob's connected devices,
    not just whichever one happens to win an internal server dict
    iteration.
    """

    desktop1 = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop1")

    alice_payload = _register("alice_")
    alice = _new_device_session(running_server, monkeypatch, alice_payload, tmp_path / "alice")

    eve_payload = _register("eve_")
    eve = _new_device_session(running_server, monkeypatch, eve_payload, tmp_path / "eve")

    desktop2 = None
    try:
        desktop1.enroll_device(device_name="Desktop1", platform="linux")  # bootstrap -> AUTHORIZED
        desktop1.bind_device_session()

        # Alice <-> Bob (desktop1): ordinary, unmodified peer
        # verification and session-key establishment.
        assert _wait_for(lambda: alice.key_manager.get_public_key(desktop1.username) is not None)
        assert _wait_for(lambda: desktop1.key_manager.get_public_key(alice.username) is not None)
        _verify_peers(alice, desktop1, desktop1.username)
        _verify_peers(desktop1, alice, alice.username)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=desktop1.username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: desktop1.key_manager.has_key(conversation_id))

        received_by_1 = {}
        desktop1.message_received.connect(
            lambda identity_key, sender, text: received_by_1.update(sender=sender, text=text)
        )
        alice.send_chat_message("before second device exists")
        assert _wait_for(lambda: received_by_1.get("text") == "before second device exists")

        # Eve (unrelated account) must never see any of this.
        received_by_eve = {}
        eve.message_received.connect(
            lambda identity_key, sender, text: received_by_eve.update(sender=sender, text=text)
        )

        # Bob's SECOND device joins the SAME account, is authorized by
        # desktop1, binds, and syncs the SAME conversation's real key --
        # the existing, already-proven Phase 16C/18 mechanism, not
        # something this test invents.
        desktop2 = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop2")
        desktop2.enroll_device(device_name="Desktop2", platform="linux")
        pending = next(d for d in desktop1.list_devices() if d["device_id"] == desktop2.device_id)
        desktop1.authorize_device(desktop2.device_id, pending["fingerprint"])
        desktop2.bind_device_session()
        _mutually_verify_devices(desktop1, desktop2)

        assert not desktop2.key_manager.has_key(conversation_id)  # not yet synced

        sync_result = desktop1.sync_conversation_key_to_device(desktop2.device_id, conversation_id)
        assert sync_result["success"] is True
        assert _wait_for(lambda: desktop2.key_manager.has_key(conversation_id))
        assert desktop2.key_manager.get_key(conversation_id) == desktop1.key_manager.get_key(conversation_id)

        # --- Real-user step: desktop2's own public-key broadcast
        #     flipped Alice's peer-trust record for "bob" to
        #     KEY_CHANGED (a separate, intentional, fail-closed
        #     identity-layer behavior -- see this file's own module
        #     docstring). A real user re-verifies the changed
        #     fingerprint before continuing; this test does the same,
        #     against whichever identity Alice currently has cached
        #     (deliberately not asserted to be one device or the
        #     other -- which one wins is exactly the unsolved "one
        #     identity slot per username" limitation this test does
        #     not claim to fix). Re-verification does not touch the
        #     ALREADY-cached AES conversation key at all -- only
        #     unblocks the Stage-3 send-time check.
        assert alice.key_manager.get_public_key(desktop1.username) is not None
        alice.confirm_combined_peer_verification(
            desktop1.username,
            alice.get_peer_fingerprint_for_verification(desktop1.username),
        )
        assert alice.get_peer_verification_state(desktop1.username) == PEER_STATE_VERIFIED

        # --- The actual routing proof: BOTH of Bob's devices are
        #     connected RIGHT NOW. A single new message from Alice must
        #     reach -- and be independently decrypted by -- both. ---
        received_by_2 = {}
        desktop2.message_received.connect(
            lambda identity_key, sender, text: received_by_2.update(sender=sender, text=text)
        )

        alice.send_chat_message("after sync, routed to both devices")

        assert _wait_for(lambda: received_by_1.get("text") == "after sync, routed to both devices")
        assert _wait_for(lambda: received_by_2.get("text") == "after sync, routed to both devices")
        assert received_by_1.get("sender") == alice.username
        assert received_by_2.get("sender") == alice.username

        # Negative: Eve, an unrelated, unauthorized account, received
        # nothing at all from this exchange.
        assert received_by_eve == {}
    finally:
        desktop1.disconnect()
        if desktop2 is not None:
            desktop2.disconnect()
        alice.disconnect()
        eve.disconnect()
        _delete(alice_payload["username"])
        _delete(eve_payload["username"])
