"""
Phase 19.10 -- proves the device key-sync chain end-to-end for a
mobile device, mirroring tests/test_device_key_sync.py::
test_newly_authorized_device_receives_existing_conversation_key_and_
messages_bob() exactly (that test already proves the server + desktop
client side of this mechanism work correctly), but with the newly-
authorized second device being a REAL mobile/session.py::
MobileClientSession -- the same class the Android app ships -- instead
of a browser.

This closes the "last 20%" a real physical device test on this phase
could not conclusively prove: not just that enrollment -> pending ->
authorization -> bind -> key-sync REQUEST succeeds and the server
relays it (confirmed physically via server logs), but that the
receiving mobile device actually verifies the sending device, stores
the synced key via its own real handle_packet() dispatch (never
planted directly into key_manager.keys by the test), and can decrypt a
post-sync conversation message -- receiver-side decryption, not
sender-side display.

Run with:
    pytest tests/test_mobile_device_key_sync.py -v
"""

import base64
import time

from crypto.key_manager import fingerprint_combined_identity
from tests.test_device_key_sync import (  # noqa: F401 -- fixtures/helpers reused, not re-implemented
    PASSWORD,
    _delete,
    _get_device_row,
    _register,
    _wait_for,
    account,
    running_server,
)
from tests.test_mobile_client_session import _confirm, _new_mobile_session  # noqa: F401
from database.models.device import DEVICE_STATE_AUTHORIZED


def _mutually_verify_devices(a, b):
    """Both directions of device-peer verification, mirroring tests/
    test_device_key_sync.py::_mutually_verify_devices() exactly, using
    MobileClientSession's own observe_device_peer_identity()/
    confirm_device_peer_verified() naming.

    Unlike observe_peer_identity() (regular username peers, which takes
    the ML-DSA signing key as raw bytes), observe_device_peer_identity()
    takes it as a base64 STRING and decodes internally -- matching its
    real call site, list_devices()'s wire response, where device rows
    are always base64-encoded (see database/models/device.py). Passing
    raw bytes here (an earlier version of this helper's own mistake,
    copied from the username-peer pattern) silently decodes as garbage
    and produces a fingerprint mismatch, not a clean error."""

    a.observe_device_peer_identity(
        b.device_id, b.key_manager.public_key.decode("utf-8"),
        base64.b64encode(b.key_manager.ml_dsa.export_public_key()).decode("ascii"),
    )
    fp_b = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    a.confirm_device_peer_verified(b.device_id, fp_b)

    b.observe_device_peer_identity(
        a.device_id, a.key_manager.public_key.decode("utf-8"),
        base64.b64encode(a.key_manager.ml_dsa.export_public_key()).decode("ascii"),
    )
    fp_a = fingerprint_combined_identity(a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key())
    b.confirm_device_peer_verified(a.device_id, fp_a)


def _observe_and_verify_peer(a, b):
    a.observe_peer_identity(b.username, b.key_manager.public_key.decode("utf-8"), b.key_manager.ml_dsa.export_public_key())
    fingerprint = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    _confirm(a, b.username, fingerprint)


def test_mobile_device_receives_synced_key_and_decrypts_post_sync_message(
    running_server, monkeypatch, account, tmp_path,
):
    """The full chain, on the account's real Android device role:

    Device A (an already-authorized MobileClientSession, standing in
    for a first device on the account -- physically, the "Desktop
    (script stand-in)" identity) has an existing encrypted conversation
    with bob. A second MobileClientSession on the SAME account (the
    "Android" device) enrolls, is authorized by Device A, mutually
    verifies with Device A, and receives the conversation key via
    sync_conversation_key_to_device(). It must then be able to decrypt
    a NEW message sent to that conversation after the sync -- proven
    by bob's own message_received signal firing with the correct
    plaintext on the Android session, never by inspecting Device A's
    or bob's own view of what was sent.
    """

    device_a = _new_mobile_session(running_server, monkeypatch, account, tmp_path / "device_a")
    bob_payload = _register("mdksbob_")
    bob = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    android = _new_mobile_session(running_server, monkeypatch, account, tmp_path / "android")
    try:
        device_a.enroll_device(device_name="Desktop (script stand-in)", platform="linux")  # first device -> auto-AUTHORIZED
        device_a.bind_device_session()

        # 1. Device A has an existing encrypted conversation with bob.
        assert _wait_for(lambda: device_a.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(device_a.username) is not None)
        _observe_and_verify_peer(device_a, bob)
        _observe_and_verify_peer(bob, device_a)

        conversation_id = device_a.open_direct_conversation(bob.username)
        device_a.establish_session_key(bob.username)
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        device_a.send_message(bob.username, "hello before device sync")
        received_by_bob = []
        bob.message_received.connect(lambda identity_key, sender, text, historical, status=None: received_by_bob.append(text))
        assert _wait_for(lambda: "hello before device sync" in received_by_bob)

        # 2. The Android device enrolls under the SAME account and is
        # authorized by Device A -- mirrors the real mobile/app.py flow
        # (enroll_device()/bind_device_session() run automatically at
        # login; authorization happens via the Devices-tab detail
        # dialog's Authorize action).
        android.enroll_device(device_name="Android", platform="android")
        pending = next(d for d in device_a.list_devices() if d["device_id"] == android.device_id)
        assert pending["state"] == "PENDING"
        device_a.authorize_device(android.device_id, pending["fingerprint"])
        android.bind_device_session()
        assert _get_device_row(android.device_id).state == DEVICE_STATE_AUTHORIZED

        # 3. Mutual device verification -- mobile/app.py's Devices-tab
        # "Verify" action on both sides (Phase 19.9's own fix for the
        # physically-found "unverified_sender" rejection).
        _mutually_verify_devices(device_a, android)

        assert not android.key_manager.has_key(conversation_id)  # not yet synced

        sync_result = device_a.sync_conversation_key_to_device(android.device_id, conversation_id)
        assert sync_result["success"] is True

        # Android stores the conversation key via the REAL production
        # receive path (handle_packet() -> _handle_device_key_sync()),
        # never planted directly into key_manager.keys by the test.
        assert _wait_for(lambda: android.key_manager.has_key(conversation_id)), (
            "the Android device never received/stored the synced conversation key"
        )
        assert android.key_manager.get_key(conversation_id) == device_a.key_manager.get_key(conversation_id)

        # 4. Bob must also trust Android as a peer before secure
        # messaging works in that direction -- ordinary, unmodified
        # peer verification, unrelated to device sync. Device A is
        # disconnected first so bob's re-verification of the shared
        # username is the single, already-covered KEY_CHANGED -> re-
        # verify transition (matching test_device_key_sync.py's own
        # documented reasoning for the identical desktop/browser case).
        device_a.disconnect()

        assert _wait_for(lambda: android.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(android.username) is not None)
        _observe_and_verify_peer(android, bob)
        _observe_and_verify_peer(bob, android)

        # 5. THE critical, previously-unproven step: a NEW message sent
        # to this conversation AFTER the sync must decrypt correctly on
        # the Android device -- receiver-side decryption, proven by the
        # real message_received signal, not sender-side "sent" display.
        received_by_android = []
        android.message_received.connect(lambda identity_key, sender, text, historical, status=None: received_by_android.append((sender, text)))
        bob.send_message(android.username, "post-sync message for the newly synced android device")
        assert _wait_for(
            lambda: any(t == "post-sync message for the newly synced android device" for _s, t in received_by_android)
        ), "the Android device never decrypted a post-sync conversation message"

        # And the reverse direction, completing the proof this is a
        # genuinely usable, bidirectional secure channel post-sync.
        received_by_bob_after = []
        bob.message_received.connect(lambda identity_key, sender, text, historical, status=None: received_by_bob_after.append(text))
        android.establish_session_key(bob.username)
        android.send_message(bob.username, "reply from the synced android device")
        assert _wait_for(lambda: "reply from the synced android device" in received_by_bob_after)
    finally:
        device_a.disconnect()
        bob.disconnect()
        android.disconnect()
        _delete(bob_payload["username"])
