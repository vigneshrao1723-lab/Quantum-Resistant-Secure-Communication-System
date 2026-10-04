"""
Phase 19.10 -- regression tests for the mobile key-desynchronization
bug found during physical Android testing: establish_session_key()/
_create_and_distribute_group_key() always store a newly generated key
locally FIRST, and only attempt delivery if the recipient's public key
is already cached. When it is not (the recipient was never online
while the sender generated the key), delivery is silently skipped
with no error and no retry -- the sender's own _has_conversation_key()
check then reports "established" regardless, so send_message()/
send_group_message() go on to encrypt and "successfully" send messages
the recipient can never decrypt.

The server has always run a matching recovery mechanism for exactly
this (see server/client_handler.py::_recover_direct_keys_for_
reconnecting_user() and _ensure_group_keys_current_for_reconnecting_
user(), both unconditional on every login) and client/session.py (the
desktop client) has always implemented both client-side halves of it.
mobile/session.py implemented neither, so the mechanism the server
already ran on every mobile login was previously a complete no-op.
This suite proves the newly added mobile/session.py handlers
(handle_direct_key_recovery_available(), _handle_direct_key_
redelivery_required(), _handle_group_key_rotation_required()) close
that gap -- with no server or protocol change, and no change to
client/session.py's already-working behavior.

Run with:
    pytest tests/test_mobile_key_desync_recovery.py -v
"""

import time

from crypto.key_manager import fingerprint_combined_identity
from tests.test_device_key_sync import PASSWORD, _delete, _register, _wait_for, running_server  # noqa: F401
from tests.test_mobile_client_session import _confirm, _new_mobile_session  # noqa: F401


def _observe_and_verify(a, b):
    """a observes b's identity (as the real receiver-thread handler
    would, from a live public_key broadcast) and marks it VERIFIED --
    the explicit user action (Verify Identity) a real app requires
    before either direction of key redelivery is allowed. Mirrors
    _mutual_verify() in test_mobile_client_session.py but one-
    directional, since these tests need to verify each side only once
    its peer has actually come online."""

    a.observe_peer_identity(b.username, b.key_manager.public_key.decode("utf-8"), b.key_manager.ml_dsa.export_public_key())
    fingerprint = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    _confirm(a, b.username, fingerprint)


def test_direct_key_lost_on_restart_is_recovered_while_partner_stays_online(
    running_server, monkeypatch, tmp_path,
):
    """Reproduces the physically-observed class of bug and proves the
    fix: establish_session_key() requires the peer to already be
    VERIFIED (mobile/session.py's own precondition), and verifying a
    peer always implies their public key is already cached in the SAME
    call -- so "recipient's key was literally never observed" cannot
    occur for a direct conversation in the current architecture.
    What CAN and did occur physically is the scenario mobile/
    session.py's new handlers exist to fix (mirroring client/
    session.py's own long-established "BUG 4 -- Fix B", per that
    module's docstring): bob's local KeyManager is lost (an app
    reinstall, a fresh storage_dir, or -- as reproduced physically --
    a second device on the same account that never received this
    conversation's key at all) while alice, still online, holds it.
    Bob's reconnect must recover the historical key from alice with no
    other action, and a fresh message afterward must decrypt too --
    receiver-side decryption, not sender-side display."""

    alice_payload = _register("mkda_")
    bob_payload = _register("mkdb_")
    alice = None
    bob = None
    bob2 = None
    try:
        alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile")
        bob = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify(alice, bob)
        _observe_and_verify(bob, alice)

        conversation_id = alice.open_direct_conversation(bob.username)
        key_info = alice.establish_session_key(bob.username)
        assert key_info is not None
        pre_restart_epoch = key_info["epoch"]
        pre_restart_key = key_info["key"]
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id, epoch=pre_restart_epoch))

        alice.send_message(bob.username, "message before bob's restart")
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id, epoch=pre_restart_epoch))
        time.sleep(0.2)

        # --- Bob "restarts": a brand new session/storage_dir with an
        # empty KeyManager, same account, still holding the SAME
        # persisted server-side conversation -- exactly a second
        # device that never received this conversation's key, which is
        # what Phase 19.10's physical group-messaging reproduction
        # actually was. Alice stays online throughout, holding the
        # key. ---
        bob.disconnect()
        time.sleep(0.2)
        bob2 = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile_restarted")
        assert bob2.key_manager.get_key(conversation_id) is None

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob2.username) is not None)
        assert _wait_for(lambda: bob2.key_manager.get_public_key(alice.username) is not None)
        # Bob's restart raced the server's reconnect-triggered
        # redelivery attempt (it runs synchronously as part of login
        # processing, before this test can possibly verify anything) --
        # exactly like a genuinely new device, that first attempt is
        # correctly REFUSED (alice's new _handle_direct_key_redelivery_
        # required() must never hand a key to an unverified peer). Only
        # after verifying do we reconnect once more below, so the
        # mechanism's own documented guarantee is what's under test:
        # "once verified, that later attempt succeeds with no other
        # change" (mobile/session.py::
        # _handle_direct_key_redelivery_required()'s docstring).
        _observe_and_verify(alice, bob2)
        _observe_and_verify(bob2, alice)

        bob2.disconnect()
        time.sleep(0.2)
        bob2.connect()
        bob2.login(bob_payload["username"])
        bob2.send_public_key()
        bob2.start_receiver()

        # --- The fix under test: bob2's (second) login triggers the
        # server's existing (previously-inert-for-mobile) recovery
        # announcement, mobile/session.py's new handle_direct_key_
        # recovery_available() asks for the missing epoch, the server
        # relays that to alice (online, holding the key, now verified
        # of bob2), and alice's new _handle_direct_key_redelivery_
        # required() wraps and resends it -- landing on bob2's EXISTING
        # _handle_group_key_distribution() handler, unchanged. ---
        assert _wait_for(
            lambda: bob2.key_manager.has_key(conversation_id, epoch=pre_restart_epoch)
        ), "bob never recovered the pre-existing direct key after restarting"

        assert bob2.key_manager.get_key(conversation_id, epoch=pre_restart_epoch) == pre_restart_key

        # Bob can now read the message that was sent before his
        # restart -- receiver-side decryption, not sender-side display.
        # The listener is connected BEFORE the first load_history()
        # call: message_received fires synchronously as each historical
        # entry is processed, so connecting afterward would miss it.
        received = []
        bob2.message_received.connect(lambda identity_key, sender, text, historical, status=None: received.append(text))
        n = bob2.load_history(conversation_id, is_group=False)
        assert n >= 1
        assert any(t == "message before bob's restart" for t in received)

        # A fresh, live message must also decrypt correctly now.
        received.clear()
        alice.send_message(bob.username, "sent after bob's restart recovered the key")
        assert _wait_for(lambda: "sent after bob's restart recovered the key" in received)
    finally:
        if alice is not None:
            alice.disconnect()
        if bob is not None:
            bob.disconnect()
        if bob2 is not None:
            bob2.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_direct_messaging_works_normally_when_recipient_already_online(
    running_server, monkeypatch, tmp_path,
):
    """Baseline/guard: the ordinary case (recipient already online
    when the key is established) must keep working unchanged -- the
    new recovery machinery must never interfere with, delay, or
    duplicate normal same-session delivery."""

    alice_payload = _register("mkdc_")
    bob_payload = _register("mkdd_")
    alice = None
    bob = None
    try:
        alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile2")
        bob = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile2")

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify(alice, bob)
        _observe_and_verify(bob, alice)

        conversation_id = alice.open_direct_conversation(bob.username)
        alice.establish_session_key(bob.username)
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        received = []
        bob.message_received.connect(lambda identity_key, sender, text, historical, status=None: received.append(text))
        alice.send_message(bob.username, "hello bob, normal case")
        assert _wait_for(lambda: "hello bob, normal case" in received)
    finally:
        if alice is not None:
            alice.disconnect()
        if bob is not None:
            bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_group_key_established_before_recipient_online_is_recovered_on_reconnect(
    running_server, monkeypatch, tmp_path,
):
    """Group equivalent of the direct-message recovery test: alice
    creates a group naming bob as a member while bob has never been
    online, so the group key is generated and stored but never wrapped
    for him. Bob then logs in for the first time; the server's
    reconnect-triggered group-key catch-up (unconditional on every
    login for every active group membership, regardless of whether any
    message was ever sent) must get him the current epoch's key via
    mobile/session.py's new _handle_group_key_rotation_required(), and
    a subsequently sent group message must decrypt on his side --
    receiver-side decryption, not sender-side display."""

    alice_payload = _register("mkga_")
    bob_payload = _register("mkgb_")
    alice = None
    bob = None
    try:
        alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile3")

        assert alice.key_manager.get_public_key(bob_payload["username"]) is None

        alice.create_group("mobile-desync-group", [bob_payload["username"]])

        conversation_id = None

        def _group_ready():
            nonlocal conversation_id
            for cid, group in alice.groups.items():
                if group.get("name") == "mobile-desync-group":
                    conversation_id = cid
                    return True
            return False

        assert _wait_for(_group_ready)
        assert alice.key_manager.has_key(conversation_id)
        pre_recovery_key = alice.key_manager.get_key(conversation_id)

        # --- Bob logs in for the very first time. ---
        bob = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile3")

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify(alice, bob)
        _observe_and_verify(bob, alice)

        # As with the direct-message test: bob's first login already
        # raced the server's reconnect-triggered group-key catch-up
        # (unconditional on every login, before verification was
        # possible) and was correctly refused. Reconnect once more now
        # that both sides are verified, exactly as a real user's app
        # would on their next session.
        bob.disconnect()
        time.sleep(0.2)
        bob.connect()
        bob.login(bob_payload["username"])
        bob.send_public_key()
        bob.start_receiver()

        assert _wait_for(
            lambda: bob.key_manager.has_key(conversation_id)
        ), "bob never received the group key on reconnect"
        assert bob.key_manager.get_key(conversation_id) == pre_recovery_key

        received = []
        bob.message_received.connect(lambda identity_key, sender, text, historical, status=None: received.append((sender, text)))
        alice.send_group_message(conversation_id, "hello group, after bob's recovery")
        assert _wait_for(lambda: any(t == "hello group, after bob's recovery" for _s, t in received))
    finally:
        if alice is not None:
            alice.disconnect()
        if bob is not None:
            bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_mobile_add_group_members_delivers_key_and_new_member_decrypts(
    running_server, monkeypatch, tmp_path,
):
    """Phase 19.10 -- proves mobile/session.py's new add_group_members()/
    _handle_group_members_added() (Section 14's "existing group Add
    Members" gap). The server reuses group_key_rotation_required to
    deliver key material to a newly added member -- the exact mechanism
    Priority 1's fix above already implements and proves -- so this
    test is deliberately small: it only needs to show the add itself
    reaches the group and the new member ends up with a working,
    receiver-side-decryptable channel."""

    alice_payload = _register("mkma_")
    bob_payload = _register("mkmb_")
    carol_payload = _register("mkmc_")
    alice = None
    carol = None
    try:
        alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile4")
        alice.create_group("mobile-add-members-group", [bob_payload["username"]])

        conversation_id = None

        def _group_ready():
            nonlocal conversation_id
            for cid, group in alice.groups.items():
                if group.get("name") == "mobile-add-members-group":
                    conversation_id = cid
                    return True
            return False

        assert _wait_for(_group_ready)

        # --- Carol joins after the group already exists. ---
        carol = _new_mobile_session(running_server, monkeypatch, carol_payload, tmp_path / "carol_mobile")
        assert _wait_for(lambda: alice.key_manager.get_public_key(carol.username) is not None)
        assert _wait_for(lambda: carol.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify(alice, carol)
        _observe_and_verify(carol, alice)

        alice.add_group_members(conversation_id, [carol_payload["username"]])

        assert _wait_for(lambda: conversation_id in carol.groups), "carol never received group_members_added"
        assert carol_payload["username"] in carol.groups[conversation_id]["members"]
        assert bob_payload["username"] in carol.groups[conversation_id]["members"]

        assert _wait_for(lambda: carol.key_manager.has_key(conversation_id)), (
            "carol never received the group key after being added"
        )
        assert carol.key_manager.get_key(conversation_id) == alice.key_manager.get_key(conversation_id)

        received = []
        carol.message_received.connect(lambda identity_key, sender, text, historical, status=None: received.append(text))
        alice.send_group_message(conversation_id, "welcome carol, from alice")
        assert _wait_for(lambda: "welcome carol, from alice" in received), (
            "carol never decrypted a group message sent after being added"
        )
    finally:
        if alice is not None:
            alice.disconnect()
        if carol is not None:
            carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_direct_conversation_id_resolves_after_restart_via_open_direct_conversation(
    running_server, monkeypatch, tmp_path,
):
    """Regression test for a second bug found during Phase 19.10's
    physical Desktop -> Android file-transfer testing: a genuinely
    real device app-restart (not a lost keystore -- the SAME
    storage_dir/identity, exactly what happens on a force-stop,
    reboot, or background kill) loses direct_conversation_ids (a
    plain in-memory dict, mobile/session.py's own map from peer
    username -> conversation UUID). It is normally repopulated only
    as a side effect of *this device* either establishing a session
    key itself or receiving a brand-new group_key_distribution
    install packet -- neither of which happens when a peer simply
    sends a further message using a key that was already established
    in a *prior* process lifetime. _handle_chat() (mobile/session.py)
    decrypts and emits message_received correctly in that case (proven
    below), but never records the sender -> conversation_id mapping,
    so mobile/app.py's open_chat() previously found nothing to pass to
    load_history() and silently rendered an empty chat -- confirmed
    physically: the Chats list correctly showed the decrypted file
    name, but opening the conversation showed no bubbles at all, even
    after re-verifying the peer.

    The fix (mobile/app.py::open_chat()) falls back to
    session.open_direct_conversation(), the same find-or-create server
    round trip establish_session_key() already relies on, whenever
    direct_conversation_ids has no entry yet. This test proves that
    fallback resolves to the correct, pre-existing conversation_id
    with no key event required first, and that load_history() then
    recovers the message receiver-side."""

    alice_payload = _register("mkde_")
    bob_payload = _register("mkdf_")
    alice = None
    bob = None
    bob2 = None
    try:
        alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile5")
        bob_storage = tmp_path / "bob_mobile5"
        bob = _new_mobile_session(running_server, monkeypatch, bob_payload, bob_storage)

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify(alice, bob)
        _observe_and_verify(bob, alice)

        conversation_id = alice.open_direct_conversation(bob.username)
        alice.establish_session_key(bob.username)
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))
        # bob received the initial key-install packet in this process
        # lifetime, so the map is populated the "old" way already --
        # this is the case that already worked and must keep working.
        assert bob.direct_conversation_ids.get(alice.username) == conversation_id

        alice.send_message(bob.username, "message before bob's app restart")
        time.sleep(0.2)

        # --- Bob's app restarts: SAME storage_dir/identity (unlike the
        # lost-keystore test above), so the persisted key survives on
        # disk, but direct_conversation_ids is a fresh, empty dict. ---
        bob.disconnect()
        time.sleep(0.2)
        bob2 = _new_mobile_session(running_server, monkeypatch, bob_payload, bob_storage)
        assert bob2.key_manager.get_key(conversation_id) is not None, (
            "the persisted key must survive a restart with the same storage_dir"
        )
        assert bob2.direct_conversation_ids.get(alice.username) is None, (
            "direct_conversation_ids must NOT survive a restart (it is in-memory only) -- "
            "this is the precondition the bug and its fix both depend on"
        )

        # Alice, still holding the peer-verification state from before
        # (also persisted), sends a further message using the SAME
        # already-established key -- no new key-distribution packet is
        # involved, exactly the physically-reproduced scenario.
        received = []
        bob2.message_received.connect(lambda identity_key, sender, text, historical, status=None: received.append(text))
        alice.send_message(bob.username, "message after bob's app restart, before any local key event")
        assert _wait_for(lambda: "message after bob's app restart, before any local key event" in received), (
            "bob2 must still decrypt and receive this live message even though its "
            "conversation_id mapping has not been resolved yet"
        )
        # This is the exact bug: the message decrypts and is delivered,
        # but the id map is still empty, so mobile/app.py's open_chat()
        # would previously find nothing to load history with.
        assert bob2.direct_conversation_ids.get(alice.username) is None, (
            "confirms _handle_chat() does not itself populate direct_conversation_ids -- "
            "if this now fails, the underlying handler changed and this test (and the "
            "app.py fallback it validates) should be revisited"
        )

        # --- The fix under test: the same server round trip
        # establish_session_key() already uses, called directly (as
        # mobile/app.py::open_chat() now does whenever the local map
        # has no entry), resolves the SAME pre-existing conversation_id
        # with no key event required. ---
        resolved_id = bob2.open_direct_conversation(alice.username)
        assert resolved_id == conversation_id
        assert bob2.direct_conversation_ids.get(alice.username) == conversation_id

        # History now loads correctly -- receiver-side. Only the
        # pre-restart message is expected from load_history() itself:
        # the post-restart message was already delivered live above and
        # is correctly deduplicated by message_id (mirrors WebClientSession.
        # loadHistory()'s own dedup), exactly as it would be in the real
        # app if the user had already seen it arrive before opening the
        # chat. That live delivery is what was actually broken before the
        # fix (direct_conversation_ids had no entry at all until now), so
        # the assertion above already proves the fix's necessary effect;
        # this proves load_history() also works once the id is resolved.
        received.clear()
        n = bob2.load_history(resolved_id, is_group=False)
        assert n >= 1
        assert any(t == "message before bob's app restart" for t in received)
    finally:
        if alice is not None:
            alice.disconnect()
        if bob is not None:
            bob.disconnect()
        if bob2 is not None:
            bob2.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
