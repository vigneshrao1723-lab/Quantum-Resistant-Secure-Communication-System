"""
Phase 16E -- Steps 9/10: three-device identity recognition and
revocation, extending Phase 16D's two-device
(tests/test_multi_device_peer_identity.py) proof to a third device.

Reuses the exact same (username, device_id)-composite peer-trust
mechanism (client/session.py::_peer_identity_key()) unmodified -- this
file proves it scales past two devices without any new code, since the
mechanism was never limited to two in the first place (a plain dict
keyed by an arbitrary string has no such limit).

Run with:
    pytest tests/test_three_device_identity.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from client.session import PEER_KEY_STATE_CHANGED
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from database.models.device import DEVICE_STATE_AUTHORIZED
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED
from tests.test_device_key_sync import (
    _delete,
    _get_device_row,
    _new_device_session,
    _register,
    _verify_peers,
    account,
    running_server,
)
from tests.test_multi_device_peer_identity import _new_pre_enrolled_device_session

_app = QApplication.instance() or QApplication([])


def _wait_for(predicate, attempts=150, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


def test_bob_distinguishes_three_alice_devices_independently(
    running_server, monkeypatch, account, tmp_path
):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    browser = None
    phone = None

    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")  # bootstrap -> AUTHORIZED
        desktop.bind_device_session()

        # 1/7. Bob VERIFIES Desktop first.
        assert _wait_for(lambda: bob.key_manager.get_public_key(desktop.username) is not None)
        assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
        _verify_peers(bob, desktop, desktop.username)
        _verify_peers(desktop, bob, bob.username)
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        desktop.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        desktop.establish_session_key()
        desktop.send_chat_message("hello from desktop")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "hello from desktop"
            for s in bob.conversation_store.get_all()
        ))

        # Browser and Phone -- both must enroll BEFORE their first
        # identity broadcast (see test_multi_device_peer_identity.py's
        # own finding: a plain broadcast from an already-VERIFIED
        # username would otherwise be indistinguishable from a key-
        # substitution attack).
        browser = _new_pre_enrolled_device_session(
            running_server, monkeypatch, account, tmp_path / "browser", "Browser", "web"
        )
        phone = _new_pre_enrolled_device_session(
            running_server, monkeypatch, account, tmp_path / "phone", "Phone", "android"
        )

        # 2/3. Browser and Phone each get their OWN, separate, distinct
        # device identity slot.
        assert _wait_for(
            lambda: bob.get_peer_verification_state(browser.username, browser.device_id) is not None
        )
        assert _wait_for(
            lambda: bob.get_peer_verification_state(phone.username, phone.device_id) is not None
        )
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_STATE_UNVERIFIED
        assert bob.get_peer_verification_state(phone.username, phone.device_id) == PEER_STATE_UNVERIFIED

        # 8. No same-username auto-trust: neither new device is
        # anything but UNVERIFIED merely for sharing Desktop's account.
        # 7. Desktop remains independently VERIFIED throughout.
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        # 7. Bob can still message Desktop with Browser/Phone present
        # but unverified.
        desktop.send_chat_message("still desktop, siblings unverified")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "still desktop, siblings unverified"
            for s in bob.conversation_store.get_all()
        ))

        # 9. Verifying Browser does NOT automatically verify Phone (or
        # vice versa) -- explicit, separate human confirmation for
        # each.
        browser_fp = fingerprint_combined_identity(
            browser.key_manager.public_key, browser.key_manager.ml_dsa.export_public_key()
        )
        bob.confirm_combined_peer_verification(browser.username, browser_fp, device_id=browser.device_id)
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_STATE_VERIFIED
        # Phone is UNTOUCHED by verifying Browser.
        assert bob.get_peer_verification_state(phone.username, phone.device_id) == PEER_STATE_UNVERIFIED
        # 4. Browser and Phone do not overwrite each other -- Desktop
        # is also still untouched.
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        phone_fp = fingerprint_combined_identity(
            phone.key_manager.public_key, phone.key_manager.ml_dsa.export_public_key()
        )
        bob.confirm_combined_peer_verification(phone.username, phone_fp, device_id=phone.device_id)
        assert bob.get_peer_verification_state(phone.username, phone.device_id) == PEER_STATE_VERIFIED
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_STATE_VERIFIED
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        # 10. Messages from all three legitimately verified devices
        # remain independently decryptable. Browser/Phone reach Bob
        # through the SAME conversation Desktop already established
        # with him -- real device_key_sync (device authorization +
        # device-peer verification + sync), exactly the proven Phase
        # 16D pattern, NOT an independent establish_session_key() call:
        # conversation_id is resolved from the two ACCOUNTS, so Browser
        # and Phone would otherwise resolve to the exact same
        # conversation_id Desktop already has an epoch for, racing it
        # (see tests/test_multi_device_peer_identity.py's own
        # documented discovery of this exact collision).
        conversation_id = desktop.current_conversation_id

        from tests.test_device_key_sync import _mutually_verify_devices

        for device, name, platform in ((browser, "Browser", "web"), (phone, "Phone", "android")):
            pending = next(d for d in desktop.list_devices() if d["device_id"] == device.device_id)
            desktop.authorize_device(device.device_id, pending["fingerprint"])
            device.bind_device_session()
            _mutually_verify_devices(desktop, device)

            # send_chat_message() also requires the SENDER to already
            # trust the recipient (ordinary, unmodified precondition) --
            # each device's OWN peer-trust view of Bob, independent of
            # Bob's device-scoped trust of it.
            assert _wait_for(lambda d=device: d.key_manager.get_public_key(bob.username) is not None)
            _verify_peers(device, bob, bob.username)

            sync_result = desktop.sync_conversation_key_to_device(device.device_id, conversation_id)
            assert sync_result["success"] is True
            assert _wait_for(lambda d=device: d.key_manager.has_key(conversation_id))

            device.set_current_chat(
                ConversationSummary(
                    conversation_id=conversation_id, username=bob.username, is_online=True, latest_message=None
                )
            )

        browser.send_chat_message("hello from browser")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "hello from browser"
            for s in bob.conversation_store.get_all()
        ))

        # 5. Browser key rotation changes only Browser's state.
        rotated_browser_identity = KeyManager()
        bob.observe_peer_identity(
            browser.username,
            rotated_browser_identity.public_key.decode("utf-8"),
            rotated_browser_identity.ml_dsa.export_public_key(),
            device_id=browser.device_id,
        )
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_KEY_STATE_CHANGED
        # Phone and Desktop are both completely unaffected.
        assert bob.get_peer_verification_state(phone.username, phone.device_id) == PEER_STATE_VERIFIED
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        # Phone can still be messaged despite Browser's KEY_CHANGED --
        # already set up (device_key_sync'd + current chat set) in the
        # loop above.
        phone.send_chat_message("hello from phone")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "hello from phone"
            for s in bob.conversation_store.get_all()
        ))

        # 6. Phone key rotation changes only Phone's state (Browser is
        # already KEY_CHANGED from above; confirm Phone's own rotation
        # doesn't touch it OR Desktop).
        rotated_phone_identity = KeyManager()
        bob.observe_peer_identity(
            phone.username,
            rotated_phone_identity.public_key.decode("utf-8"),
            rotated_phone_identity.ml_dsa.export_public_key(),
            device_id=phone.device_id,
        )
        assert bob.get_peer_verification_state(phone.username, phone.device_id) == PEER_KEY_STATE_CHANGED
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_KEY_STATE_CHANGED
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        desktop.send_chat_message("desktop still fine after both siblings key-changed")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "desktop still fine after both siblings key-changed"
            for s in bob.conversation_store.get_all()
        ))
    finally:
        for session in (desktop, bob, browser, phone):
            if session is None:
                continue
            try:
                session.disconnect()
            except Exception:
                pass
        _delete(account["username"])
        _delete(bob_payload["username"])


def test_device_revocation_with_three_devices_is_prospective_and_honest(
    running_server, monkeypatch, account, tmp_path
):
    """
    Step 10: Desktop/Browser/Phone all AUTHORIZED; Browser is revoked.
    Desktop and Phone keep working; Browser cannot sync/receive new
    material; Browser's already-local material is not falsely claimed
    to be remotely erased; Browser does not become re-trusted merely
    because Desktop/Phone remain trusted.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    phone = _new_device_session(running_server, monkeypatch, account, tmp_path / "phone")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")
        desktop.bind_device_session()

        for other, name, platform in ((browser, "Browser", "web"), (phone, "Phone", "android")):
            other.enroll_device(device_name=name, platform=platform)
            pending = next(d for d in desktop.list_devices() if d["device_id"] == other.device_id)
            desktop.authorize_device(other.device_id, pending["fingerprint"])
            other.bind_device_session()
            assert _get_device_row(other.device_id).state == DEVICE_STATE_AUTHORIZED

        from tests.test_device_key_sync import _mutually_verify_devices
        _mutually_verify_devices(desktop, browser)
        _mutually_verify_devices(desktop, phone)
        _mutually_verify_devices(browser, phone)  # needed below: Browser attempts to sync to Phone post-revocation

        assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(desktop.username) is not None)
        _verify_peers(desktop, bob, bob.username)
        _verify_peers(bob, desktop, desktop.username)
        desktop.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        desktop.establish_session_key()
        conversation_id = desktop.current_conversation_id
        genuine_key = desktop.key_manager.get_key(conversation_id)

        # Browser legitimately receives the key BEFORE revocation.
        result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        assert result["success"] is True
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
        key_browser_already_has = browser.key_manager.get_key(conversation_id)

        # Revoke Browser.
        desktop.revoke_device(browser.device_id)
        assert _get_device_row(browser.device_id).state != DEVICE_STATE_AUTHORIZED

        # Desktop still works (messaging Bob).
        desktop.send_chat_message("desktop fine after revoking browser")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "desktop fine after revoking browser"
            for s in bob.conversation_store.get_all()
        ))

        # Phone still works: receives a FRESH sync from Desktop for a
        # NEW conversation, proving Desktop's own AUTHORIZED status
        # (and Phone's) is unaffected by Browser's revocation.
        charlie_payload = _register("charlie_")
        charlie = _new_device_session(running_server, monkeypatch, charlie_payload, tmp_path / "charlie")
        try:
            assert _wait_for(lambda: desktop.key_manager.get_public_key(charlie.username) is not None)
            assert _wait_for(lambda: charlie.key_manager.get_public_key(desktop.username) is not None)
            _verify_peers(desktop, charlie, charlie.username)
            _verify_peers(charlie, desktop, desktop.username)
            desktop.set_current_chat(
                ConversationSummary(conversation_id=None, username=charlie.username, is_online=True, latest_message=None)
            )
            desktop.establish_session_key()
            second_conversation_id = desktop.current_conversation_id

            phone_sync_result = desktop.sync_conversation_key_to_device(phone.device_id, second_conversation_id)
            assert phone_sync_result["success"] is True
            assert _wait_for(lambda: phone.key_manager.has_key(second_conversation_id))
        finally:
            charlie.disconnect()
            _delete(charlie_payload["username"])

        # Browser cannot perform new sync (as source).
        blocked_as_source = browser.sync_conversation_key_to_device(phone.device_id, conversation_id)
        assert blocked_as_source["success"] is False

        # Browser cannot RECEIVE new synchronized key material (as
        # target) -- a fresh, never-before-synced conversation.
        browser.key_manager.remove_key(second_conversation_id)
        blocked_as_target = desktop.sync_conversation_key_to_device(browser.device_id, second_conversation_id)
        assert blocked_as_target["success"] is False
        assert not browser.key_manager.has_key(second_conversation_id)

        # Browser's EXISTING local material (received before
        # revocation) is not falsely erased -- honest, prospective-only
        # revocation.
        assert browser.key_manager.get_key(conversation_id) == key_browser_already_has

        # Browser does not become re-trusted (as a DEVICE) merely
        # because Desktop/Phone remain AUTHORIZED -- its own row is
        # still REVOKED regardless of its siblings' state.
        assert _get_device_row(browser.device_id).state != DEVICE_STATE_AUTHORIZED
        assert _get_device_row(desktop.device_id).state == DEVICE_STATE_AUTHORIZED
        assert _get_device_row(phone.device_id).state == DEVICE_STATE_AUTHORIZED
    finally:
        for session in (desktop, bob, browser, phone):
            try:
                session.disconnect()
            except Exception:
                pass
        _delete(bob_payload["username"])
