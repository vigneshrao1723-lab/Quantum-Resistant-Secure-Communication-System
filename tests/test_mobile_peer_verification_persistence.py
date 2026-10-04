"""
Phase 19.19 -- Android peer-verification persistence.

Before this phase, mobile/session.py::MobileClientSession.peers was a
plain in-memory dict, never written to or read from the same
storage/secure_key_store.py::SecureKeyStore Desktop already uses for
this exact purpose -- so a peer verified in one run always came back
UNVERIFIED after the app process restarted, even though the identical
on-disk, encrypted store was sitting right there with the answer.

These tests drive the REAL MobileClientSession/ClientSession against a
REAL server -- no internal dict manipulation, no mocked crypto -- and
simulate "force-stop/relaunch" and "logout/login" the same way this
codebase's own existing restart tests do (e.g. client/session.py's
test_restart_preserves_device_id_fingerprint_and_avoids_duplicate_
enrollment): construct a genuinely NEW session object pointed at the
SAME on-disk storage_dir, never reuse or mutate the original object.

Run with:
    pytest tests/test_mobile_peer_verification_persistence.py -v
"""

import time

import mobile.session as mobile_session_module
import client.session as client_session_module
from client.session import ClientSession
from crypto.key_manager import fingerprint_combined_identity
from mobile.session import MobileClientSession
from tests.test_device_key_sync import PASSWORD, _delete, _register, _wait_for, running_server  # noqa: F401


def _new_mobile(running_server, monkeypatch, payload, storage_dir):
    _state, port = running_server
    monkeypatch.setattr(mobile_session_module, "SERVER_PORT", port)

    session = MobileClientSession(storage_dir=str(storage_dir))
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _new_desktop(running_server, monkeypatch, payload, key_store_dir):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", key_store_dir)

    session = ClientSession()
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _observe_and_verify_mobile_of_desktop(mobile, desktop):
    mobile.observe_peer_identity(
        desktop.username,
        desktop.key_manager.public_key.decode("utf-8"),
        desktop.key_manager.ml_dsa.export_public_key(),
    )
    fingerprint = fingerprint_combined_identity(
        desktop.key_manager.public_key, desktop.key_manager.ml_dsa.export_public_key()
    )
    mobile.confirm_peer_verified(desktop.username, fingerprint)
    return fingerprint


def test_mobile_peer_verification_persists_across_relaunch(running_server, monkeypatch, tmp_path):
    """The core Phase 19.19 requirement: verify a peer, tear down the
    session entirely (simulating force-stop), construct a genuinely
    fresh MobileClientSession against the SAME on-disk storage_dir
    (simulating relaunch), reconnect, and -- without any new confirm
    call -- the peer is already VERIFIED the moment their identity is
    (re)observed via the server's own catch-up broadcast."""

    alice_payload = _register("mpvp_alice_")
    bob_payload = _register("mpvp_bob_")
    mobile_dir = tmp_path / "bob_mobile"
    try:
        alice = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_desktop")
        bob = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        fingerprint = _observe_and_verify_mobile_of_desktop(bob, alice)
        assert bob.is_peer_verified(alice.username) is True

        bob.disconnect()

        # "Relaunch" -- a brand-new MobileClientSession object, same
        # on-disk storage_dir, nothing carried over from the old
        # in-memory session.peers.
        # _new_mobile() itself already starts the receiver thread, which
        # can race ahead and process the server's catch-up identity
        # broadcast before this function even returns -- there is no
        # reliable "before observing" instant to assert against here
        # (unlike a synchronous call), so this test only asserts the
        # actual property that matters: the state IS restored, whenever
        # the observation happens to land.
        bob_relaunched = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        # Waits for the actual condition under test, not a proxy for
        # it -- key_manager.add_public_key() and _upsert_peer_
        # observation() both run inside the same receiver-thread
        # callback, but polling the former only is indirect and
        # racy against this test's own immediately-following assertion.
        assert _wait_for(lambda: bob_relaunched.get_peer_verification_state(alice.username) is not None)

        # No confirm_peer_verified() call here -- restoration from
        # SecureKeyStore must happen purely from observing the SAME,
        # unchanged identity again.
        assert bob_relaunched.is_peer_verified(alice.username) is True
        assert bob_relaunched.get_peer_fingerprint_for_verification(alice.username) == fingerprint

        bob_relaunched.disconnect()
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_mobile_peer_verification_survives_logout_login(running_server, monkeypatch, tmp_path):
    """Logout/login (mandate Section 4, requirement 1) -- modeled the
    same way as force-stop/relaunch, since this project's key store is
    tied to the local device install/password, not to a server-side
    session -- explicitly re-derived here rather than assumed
    identical without proof."""

    alice_payload = _register("mpvl_alice_")
    bob_payload = _register("mpvl_bob_")
    mobile_dir = tmp_path / "bob_mobile"
    try:
        alice = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_desktop")
        bob = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify_mobile_of_desktop(bob, alice)
        bob.disconnect()

        bob_after_login = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)
        assert _wait_for(lambda: bob_after_login.get_peer_verification_state(alice.username) is not None)
        assert bob_after_login.is_peer_verified(alice.username) is True

        bob_after_login.disconnect()
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_mobile_peer_verification_rejects_changed_key_after_relaunch(running_server, monkeypatch, tmp_path):
    """The fail-closed half of the requirement: if the peer's identity
    genuinely changed while this device was offline (modeled here as
    the SAME account reconnecting from a different, freshly-generated
    keypair -- e.g. a reinstalled/compromised-credential scenario),
    the relaunched session must NOT silently inherit the old VERIFIED
    state for the new key. Never same-account-implies-trust; never a
    blind restore of a stale claim."""

    alice_payload = _register("mpvc_alice_")
    bob_payload = _register("mpvc_bob_")
    mobile_dir = tmp_path / "bob_mobile"
    try:
        alice_original = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_original")
        bob = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        assert _wait_for(lambda: bob.key_manager.get_public_key(alice_original.username) is not None)
        original_fingerprint = _observe_and_verify_mobile_of_desktop(bob, alice_original)
        assert bob.is_peer_verified(alice_original.username) is True

        alice_original.disconnect()
        bob.disconnect()

        # A genuinely different keypair, same account/username --
        # simulates "Alice's identity changed while Bob was offline".
        alice_changed = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_changed")
        changed_fingerprint = fingerprint_combined_identity(
            alice_changed.key_manager.public_key, alice_changed.key_manager.ml_dsa.export_public_key()
        )
        assert changed_fingerprint != original_fingerprint

        bob_relaunched = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)
        # Waits for the actual condition under test -- the state
        # becoming KEY_CHANGED specifically, not merely "is not None".
        # A weaker "is not None" wait is a real, proven race: mobile/
        # session.py::_rehydrate_peers_from_key_store() (Phase 19.19)
        # synchronously seeds self.peers[alice] with the OLD, STALE
        # VERIFIED entry from SecureKeyStore the instant bob_relaunched
        # is constructed -- before the receiver thread has had any
        # chance to process the live re-observation of Alice's actually
        # CHANGED key and correct it to KEY_CHANGED. "is not None" is
        # satisfied immediately by that stale VERIFIED entry, so a
        # `_wait_for` on it can return before the live correction lands,
        # intermittently letting the assertions below run against the
        # stale, still-VERIFIED state -- confirmed by direct tracing:
        # the implementation itself always converges to KEY_CHANGED
        # correctly, but this test's own wait didn't actually wait for
        # that convergence. Waiting on the exact state value closes the
        # race without changing the security contract being tested.
        assert _wait_for(lambda: bob_relaunched.get_peer_verification_state(alice_changed.username) == "KEY_CHANGED")

        assert bob_relaunched.is_peer_verified(alice_changed.username) is False
        assert bob_relaunched.get_peer_verification_state(alice_changed.username) == "KEY_CHANGED"

        alice_changed.disconnect()
        bob_relaunched.disconnect()
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def _pending_verification_for(session, requester_username):
    for entry in session.load_inbox():
        if (
            entry.get("type") == "verification_request"
            and entry.get("status") == "pending"
            and entry.get("requester_username") == requester_username
        ):
            return entry
    return None


def test_mobile_requester_side_verification_completes_after_desktop_approval(
    running_server, monkeypatch, tmp_path
):
    """
    Phase 19.22C, Android half. client/session.py::ClientSession's own
    _complete_requester_side_verification() is proven in tests/
    test_group_admin_and_inbox.py; MobileClientSession's identically-
    named method mirrors it exactly (see its own docstring). Proves the
    SAME requester-side completion path works when the REQUESTER is
    Android (MobileClientSession) and the APPROVER is Desktop
    (ClientSession), reusing the existing confirm_peer_verified()/
    get_peer_fingerprint_for_verification() gate this file's own
    persistence tests above already exercise -- no new crypto path, no
    duplicated logic, and asserts the final requester-side VERIFIED
    state, not merely that a notification arrived.
    """

    android_payload = _register("mrsv_android_")
    desktop_payload = _register("mrsv_desktop_")
    try:
        android = _new_mobile(running_server, monkeypatch, android_payload, tmp_path / "android")
        desktop = _new_desktop(running_server, monkeypatch, desktop_payload, tmp_path / "desktop")

        assert _wait_for(lambda: android.key_manager.get_public_key(desktop.username) is not None)
        assert _wait_for(lambda: android.username in desktop._observed_peer_signing_public_keys)

        assert android.is_peer_verified(desktop.username) is False
        assert desktop._peer_key_is_verified(android.username) is False

        android.request_verification(desktop.username)

        notification = None
        for _ in range(150):
            notification = _pending_verification_for(desktop, android.username)
            if notification is not None:
                break
            time.sleep(0.05)
        assert notification is not None

        desktop.respond_to_inbox(notification, True)
        assert desktop._peer_key_is_verified(android.username) is True

        # The actual thing under test: Android's OWN side must reach
        # VERIFIED too, driven purely by the pushed inbox_response_
        # result packet arriving on its own receiver thread -- not by
        # this test calling confirm_peer_verified() itself.
        assert _wait_for(lambda: android.is_peer_verified(desktop.username) is True)

        android.disconnect()
        desktop.disconnect()
    finally:
        _delete(android_payload["username"])
        _delete(desktop_payload["username"])
