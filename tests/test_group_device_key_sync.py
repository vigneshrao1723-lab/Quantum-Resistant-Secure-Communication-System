"""
Phase 16D -- Step 11: group conversation key synchronization.

Phase 16C's sync_conversation_key_to_device()/handle_device_key_sync()
were built generic on conversation_id + epoch from the start --
KeyManager itself "has no notion of 'direct' or 'group' at all" (see
crypto/key_manager.py's own module comment); ``package_type`` is
opaque, relayed metadata that neither the server
(server/device_handler.py::handle_device_key_sync()) nor the receiving
client (client/session.py::handle_device_key_sync()) branch on for any
security or logic decision. That means a GROUP conversation's key
already flows through the exact same, unmodified code path a DIRECT
conversation's does -- no new sync mechanism, no duplicated
implementation, exactly what Step 11 asked for ("do NOT duplicate the
direct sync implementation blindly").

This file proves that generic design actually holds for a real group:
Alice Desktop creates a real, server-authorized group with Bob and
Charlie, Alice Browser is newly authorized and receives the group's
key via ordinary sync_conversation_key_to_device(..., package_type=
"group"), and can then send a real encrypted group message Bob and
Charlie both decrypt, and receive their replies -- all through real
production code paths.

Security: a revoked device must not receive NEW group-key material via
sync (reuses the exact same revocation checks direct sync already has
-- proven in tests/test_device_key_sync.py and test_device_key_sync_
hardening.py; not re-proven here to avoid duplicating that coverage).
A device outside the group is never sent anything: sync is addressed
device-to-device, never broadcast, so this is structural rather than
something requiring its own extra check.

Run with:
    pytest tests/test_group_device_key_sync.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from database.models.device import DEVICE_STATE_AUTHORIZED
from domain.conversation_summary import ConversationSummary
from tests.test_device_key_sync import (
    _delete,
    _get_device_row,
    _mutually_verify_devices,
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


def test_newly_authorized_device_receives_existing_group_key_and_messages_members(
    running_server, monkeypatch, account, tmp_path
):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    charlie_payload = _register("charlie_")
    charlie = _new_device_session(running_server, monkeypatch, charlie_payload, tmp_path / "charlie")
    browser = None

    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")  # bootstrap -> AUTHORIZED
        desktop.bind_device_session()

        # 1. Alice Desktop has an existing, real, server-authorized
        # group with Bob and Charlie (mutual verification required --
        # handle_group_key_distribution() requires the RECEIVER to
        # have the SENDER verified too, same as every other group-key
        # test in this codebase).
        assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(desktop.username) is not None)
        _verify_peers(desktop, bob, bob.username)
        _verify_peers(bob, desktop, desktop.username)

        assert _wait_for(lambda: desktop.key_manager.get_public_key(charlie.username) is not None)
        assert _wait_for(lambda: charlie.key_manager.get_public_key(desktop.username) is not None)
        _verify_peers(desktop, charlie, charlie.username)
        _verify_peers(charlie, desktop, desktop.username)

        desktop.create_group_conversation(
            "device-sync-group", [bob.username, charlie.username]
        )

        conversation_id = None

        def _group_created():
            nonlocal conversation_id
            for summary in desktop.conversation_store.get_all():
                if summary.is_group and summary.group_name == "device-sync-group":
                    conversation_id = summary.conversation_id
                    return True
            return False

        assert _wait_for(_group_created)
        assert _wait_for(lambda: bob.key_manager.get_key(conversation_id) is not None)
        assert _wait_for(lambda: charlie.key_manager.get_key(conversation_id) is not None)

        # 2. Alice Browser is newly authorized -- must never send a
        # plain (device_id-less) identity broadcast, since Bob/Charlie
        # already hold a VERIFIED plain-username slot for Desktop (see
        # tests/test_multi_device_peer_identity.py's own finding).
        browser = _new_pre_enrolled_device_session(
            running_server, monkeypatch, account, tmp_path / "browser", "Browser", "web"
        )
        browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
        desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
        browser.bind_device_session()
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_AUTHORIZED

        _mutually_verify_devices(desktop, browser)

        assert not browser.key_manager.has_key(conversation_id)  # not yet synced

        # 3. The GROUP key, synced through the exact same
        # sync_conversation_key_to_device() a DIRECT conversation uses
        # -- package_type="group" is opaque metadata, not a different
        # code path.
        sync_result = desktop.sync_conversation_key_to_device(
            browser.device_id, conversation_id, package_type="group"
        )
        assert sync_result["success"] is True

        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
        assert browser.key_manager.get_key(conversation_id) == desktop.key_manager.get_key(conversation_id)

        # 4. Browser can decrypt the group's EXISTING history-relevant
        # key state (proven by having the same key bytes desktop/bob/
        # charlie already share) and can send a NEW group message that
        # Bob and Charlie both receive and decrypt for real.
        browser_received = {}
        charlie_received = {}
        bob.message_received.connect(
            lambda identity_key, sender, text: browser_received.update(sender=sender, text=text)
            if identity_key == conversation_id else None
        )
        charlie.message_received.connect(
            lambda identity_key, sender, text: charlie_received.update(sender=sender, text=text)
            if identity_key == conversation_id else None
        )

        browser.set_current_chat(
            ConversationSummary(
                conversation_id=conversation_id, username=None, is_online=True,
                latest_message=None, is_group=True, group_name="device-sync-group",
            )
        )

        browser.send_chat_message("hello group, from the synced browser")

        assert _wait_for(lambda: browser_received.get("text") == "hello group, from the synced browser")
        assert _wait_for(lambda: charlie_received.get("text") == "hello group, from the synced browser")

        # 5. Bob replies; Browser decrypts it for real.
        bob.set_current_chat(
            ConversationSummary(
                conversation_id=conversation_id, username=None, is_online=True,
                latest_message=None, is_group=True, group_name="device-sync-group",
            )
        )

        browser_reply_received = {}
        browser.message_received.connect(
            lambda identity_key, sender, text: browser_reply_received.update(sender=sender, text=text)
            if identity_key == conversation_id else None
        )
        bob.send_chat_message("reply from bob to the synced browser")
        assert _wait_for(lambda: browser_reply_received.get("text") == "reply from bob to the synced browser")

    finally:
        for session in (desktop, bob, charlie, browser):
            if session is None:
                continue
            try:
                session.disconnect()
            except Exception:
                pass
        _delete(account["username"])
        _delete(bob_payload["username"])
        _delete(charlie_payload["username"])
