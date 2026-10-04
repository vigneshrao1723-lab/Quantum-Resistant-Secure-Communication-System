"""
Phase 16E -- Steps 3/4/5: server-side conversation-membership
authorization for device_key_sync, and the conversation/group redirect
attacks it (together with the existing ML-DSA signature binding) must
defeat.

server/device_handler.py::handle_device_key_sync() (Phase 16E, Step 3)
now additionally verifies -- from the server's own ConversationMember
rows, never from anything the client claims -- that the AUTHENTICATED
account is actually a member of ``conversation_id`` before relaying
anything. This closes the "arbitrary/guessed conversation_id" case: an
account with two AUTHORIZED devices could previously address a sync
packet to ANY conversation_id string, real or not, since the server
only ever validated device state, never conversation membership.

That check alone does not defeat a redirect BETWEEN two conversations
the account is legitimately a member of (Alice really is in both
Conversation A with Bob and Conversation B with Charlie) -- for that,
this file proves the PRE-EXISTING protection already does the job:
canonical_device_key_sync_payload() binds conversation_id into the
ML-DSA signature alongside encapsulation/wrapped_key, so a package
genuinely signed for Conversation A's key under conversation_id=A
cannot be relabeled to conversation_id=B after signing without
invalidating the signature -- proven here with TWO real, distinct,
account-associated conversations (a stronger case than Phase 16D's
version, which used one real id and one fabricated one).

Run with:
    pytest tests/test_conversation_redirect_security.py -v
"""

import base64
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from crypto.device_protocol import canonical_device_key_sync_payload, sign_device_payload
from crypto.key_manager import fingerprint_combined_identity
from database.models.device import DEVICE_STATE_AUTHORIZED
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_VERIFIED
from utils.protocol import create_device_key_sync_packet
from tests.test_device_key_sync import (
    _delete,
    _get_device_row,
    _mutually_verify_devices,
    _new_device_session,
    _register,
    _verify_peers,
    _wait_for,
    account,
    running_server,
)


def _enroll_and_authorize(desktop, other_device, name, platform):
    other_device.enroll_device(device_name=name, platform=platform)
    pending = next(d for d in desktop.list_devices() if d["device_id"] == other_device.device_id)
    desktop.authorize_device(other_device.device_id, pending["fingerprint"])
    other_device.bind_device_session()
    return pending


def _real_direct_conversation(desktop, peer):
    assert _wait_for(lambda: desktop.key_manager.get_public_key(peer.username) is not None)
    assert _wait_for(lambda: peer.key_manager.get_public_key(desktop.username) is not None)
    _verify_peers(desktop, peer, peer.username)
    _verify_peers(peer, desktop, desktop.username)
    desktop.set_current_chat(
        ConversationSummary(conversation_id=None, username=peer.username, is_online=True, latest_message=None)
    )
    desktop.establish_session_key()
    return desktop.current_conversation_id


# ========================================================================
# Step 3: an arbitrary/never-joined conversation_id is rejected outright,
# regardless of device authorization state (the core new check).
# ========================================================================


def test_sync_to_never_joined_conversation_id_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()
        _enroll_and_authorize(desktop, browser, "Browser", "web")
        _mutually_verify_devices(desktop, browser)

        never_joined_conversation_id = "11111111-1111-1111-1111-111111111111"
        desktop.key_manager.store_key(never_joined_conversation_id, os.urandom(32), epoch=1)

        result = desktop.sync_conversation_key_to_device(browser.device_id, never_joined_conversation_id)

        assert result["success"] is False
        assert not browser.key_manager.has_key(never_joined_conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


# ========================================================================
# Step 4: direct-conversation redirect attack -- two REAL, distinct,
# account-associated conversations.
# ========================================================================


def test_direct_conversation_a_key_cannot_be_relabeled_as_conversation_b(
    running_server, monkeypatch, account, tmp_path
):
    """
    Alice owns Conversation A (with Bob) and Conversation B (with
    Charlie). Desktop genuinely holds A's key. A device_key_sync
    package is signed for A, then its conversation_id field is
    rewritten to B post-signing before being sent -- simulating a
    malicious relay (this project's whole threat model for the server)
    attempting to make an authorized-Browser sync of A's key masquerade
    as B's key. Must be rejected; B's (separate, real) conversation
    state must be completely unaffected, and no peer identity state
    changes as a side effect of the rejected attempt.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    charlie_payload = _register("charlie_")
    charlie = _new_device_session(running_server, monkeypatch, charlie_payload, tmp_path / "charlie")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()

        conversation_a = _real_direct_conversation(desktop, bob)
        conversation_b = _real_direct_conversation(desktop, charlie)
        assert conversation_a != conversation_b

        browser_pending = _enroll_and_authorize(desktop, browser, "Browser", "web")
        _mutually_verify_devices(desktop, browser)

        epoch_a = desktop.key_manager.current_epoch(conversation_a)
        key_a = desktop.key_manager.get_key(conversation_a, epoch=epoch_a)

        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_a)
        payload = canonical_device_key_sync_payload(
            desktop.username, desktop.device_id, browser.device_id, browser_pending["fingerprint"],
            conversation_a, epoch_a, "direct", encapsulation, wrapped_key,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)

        # Redirect: conversation_id rewritten to B post-signing. Alice
        # IS genuinely a member of B (so Phase 16E's new membership
        # check alone would let this through) -- it is the signature
        # binding that must catch it.
        redirected_packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_b, epoch=epoch_a, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        )
        result = desktop.send_request(redirected_packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_b)
        # Conversation A's key was never even the one under attack
        # here (only its material, relabeled) -- it remains correct
        # and untouched on Desktop's own side.
        assert desktop.key_manager.get_key(conversation_a, epoch=epoch_a) == key_a

        # No peer identity state was modified by the rejected attempt.
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED
        assert charlie.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED
    finally:
        desktop.disconnect()
        bob.disconnect()
        charlie.disconnect()
        browser.disconnect()
        _delete(bob_payload["username"])
        _delete(charlie_payload["username"])


# ========================================================================
# Step 5: group-conversation redirect attack.
# ========================================================================


def test_group_a_key_cannot_be_relabeled_as_group_b(running_server, monkeypatch, account, tmp_path):
    """
    Group A: Alice, Bob, Charlie. Group B: Alice, Dave, Eve. Alice
    Desktop has Group A's current key. A device_key_sync package
    genuinely signed for Group A is relabeled to Group B's
    conversation_id post-signing -- must be rejected, and Group B's
    real key state (which Desktop separately, legitimately has as an
    actual member of B too) is completely unaffected.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    charlie_payload = _register("charlie_")
    charlie = _new_device_session(running_server, monkeypatch, charlie_payload, tmp_path / "charlie")
    dave_payload = _register("dave_")
    dave = _new_device_session(running_server, monkeypatch, dave_payload, tmp_path / "dave")
    eve_payload = _register("eve_")
    eve = _new_device_session(running_server, monkeypatch, eve_payload, tmp_path / "eve")
    browser = None
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()

        for peer in (bob, charlie, dave, eve):
            assert _wait_for(lambda p=peer: desktop.key_manager.get_public_key(p.username) is not None)
            assert _wait_for(lambda p=peer: p.key_manager.get_public_key(desktop.username) is not None)
            _verify_peers(desktop, peer, peer.username)
            _verify_peers(peer, desktop, desktop.username)

        desktop.create_group_conversation("Group A", [bob.username, charlie.username])
        desktop.create_group_conversation("Group B", [dave.username, eve.username])

        group_a = group_b = None

        def _both_groups_created():
            nonlocal group_a, group_b
            for summary in desktop.conversation_store.get_all():
                if summary.is_group and summary.group_name == "Group A":
                    group_a = summary.conversation_id
                if summary.is_group and summary.group_name == "Group B":
                    group_b = summary.conversation_id
            return group_a is not None and group_b is not None

        assert _wait_for(_both_groups_created)
        assert group_a != group_b
        assert _wait_for(lambda: bob.key_manager.get_key(group_a) is not None)
        assert _wait_for(lambda: dave.key_manager.get_key(group_b) is not None)

        # Browser connects only AFTER both groups already exist --
        # handle_group_create_result() dispatches "if creator ==
        # self.username" (matched against the CONNECTION's own
        # username, not which socket actually created the group), so a
        # second device of the SAME account online DURING group
        # creation would independently generate and distribute its own
        # separate copy of the group key -- a genuine, pre-existing,
        # orthogonal multi-device behavior this phase's scope does not
        # touch (device_key_sync exists precisely so a device that
        # was NOT online at creation time can catch up safely instead).
        browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
        browser_pending = _enroll_and_authorize(desktop, browser, "Browser", "web")
        _mutually_verify_devices(desktop, browser)

        epoch_a = desktop.key_manager.current_epoch(group_a)
        key_a = desktop.key_manager.get_key(group_a, epoch=epoch_a)

        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_a)
        payload = canonical_device_key_sync_payload(
            desktop.username, desktop.device_id, browser.device_id, browser_pending["fingerprint"],
            group_a, epoch_a, "group", encapsulation, wrapped_key,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)

        redirected_packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=group_b, epoch=epoch_a, package_type="group",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        )
        result = desktop.send_request(redirected_packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(group_b)
        assert desktop.key_manager.get_key(group_b) is not None  # Group B's own real key, untouched

        # Non-member-account target: device_key_sync's target must
        # belong to the SAME account as the source, checked
        # unconditionally server-side (Phase 16C's own "Unknown target
        # device for this account" branch) -- Bob's account has no
        # device enrolled under Alice's account at all, so there is no
        # reachable target_device_id for Alice's Desktop to even
        # construct here; already proven directly by Phase 16C's
        # test_sync_to_device_on_different_account_rejected, not
        # re-derived here.

        # Revoked target -> group key sync rejected.
        desktop.revoke_device(browser.device_id)
        revoked_result = desktop.sync_conversation_key_to_device(browser.device_id, group_a)
        assert revoked_result["success"] is False
        assert not browser.key_manager.has_key(group_a)
    finally:
        for session in (desktop, bob, charlie, dave, eve, browser):
            try:
                session.disconnect()
            except Exception:
                pass
        for payload in (bob_payload, charlie_payload, dave_payload, eve_payload):
            _delete(payload["username"])
