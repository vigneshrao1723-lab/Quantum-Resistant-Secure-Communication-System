"""
Phase 16E -- Step 8: simultaneous multi-device synchronization race.

Alice has three AUTHORIZED devices (Desktop, Browser, Phone). Desktop
establishes a real conversation with Bob and syncs its key to Browser
first (sequential, real production path) -- so Desktop AND Browser
each independently, legitimately hold the SAME real key. Both then
attempt, AT THE SAME TIME, to sync that key onward to Phone (the
architecture's actual concurrency-allowing scenario: any AUTHORIZED
device may sync to any other AUTHORIZED device of the same account:
there is no "only one device may sync at a time" restriction anywhere
in server/device_handler.py::handle_device_key_sync()).

Uses two real Python threads, each blocked on a real, separate
ClientSession's blocking send_request() -- i.e., two genuinely
concurrent connections through the REAL server (which already handles
one thread per connection; this only exercises two of those threads
at once, never an artificial bypass of the server path).

Run with:
    pytest tests/test_multi_device_concurrency.py -v
"""

import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from domain.conversation_summary import ConversationSummary
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
from database.models.device import DEVICE_STATE_AUTHORIZED


def test_simultaneous_sync_from_two_source_devices_to_a_third_is_safe(
    running_server, monkeypatch, account, tmp_path
):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    phone = _new_device_session(running_server, monkeypatch, account, tmp_path / "phone")
    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")  # bootstrap -> AUTHORIZED
        desktop.bind_device_session()

        for other, name, platform in ((browser, "Browser", "web"), (phone, "Phone", "android")):
            other.enroll_device(device_name=name, platform=platform)
            pending = next(d for d in desktop.list_devices() if d["device_id"] == other.device_id)
            desktop.authorize_device(other.device_id, pending["fingerprint"])
            other.bind_device_session()
            assert _get_device_row(other.device_id).state == DEVICE_STATE_AUTHORIZED

        # All three device-peer pairs mutually verified -- Desktop<->
        # Browser, Desktop<->Phone, AND Browser<->Phone (Browser is
        # about to independently sync to Phone too).
        _mutually_verify_devices(desktop, browser)
        _mutually_verify_devices(desktop, phone)
        _mutually_verify_devices(browser, phone)

        # Real conversation with Bob.
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
        genuine_epoch = desktop.key_manager.current_epoch(conversation_id)

        # Browser catches up first (sequential, real) -- now Desktop
        # AND Browser both legitimately hold the identical key.
        first_sync = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        assert first_sync["success"] is True
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
        assert browser.key_manager.get_key(conversation_id) == genuine_key

        # The race: Desktop AND Browser BOTH sync the SAME conversation
        # key to Phone, submitted at the same time from two real,
        # concurrently-running threads.
        results = {}
        errors = {}

        def _sync_from(source_session, label):
            try:
                results[label] = source_session.sync_conversation_key_to_device(
                    phone.device_id, conversation_id
                )
            except Exception as error:  # noqa: BLE001
                errors[label] = error

        t1 = threading.Thread(target=_sync_from, args=(desktop, "desktop"))
        t2 = threading.Thread(target=_sync_from, args=(browser, "browser"))

        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

        # No deadlock: both threads genuinely finished within the
        # bound (join() with a timeout that returns silently on
        # timeout -- is_alive() is the only reliable way to tell
        # "finished" from "still blocked").
        assert not t1.is_alive(), "desktop's sync thread deadlocked"
        assert not t2.is_alive(), "browser's sync thread deadlocked"

        # No crash: neither thread raised.
        assert errors == {}, errors

        # Both requests were individually accepted (both source
        # devices are genuinely AUTHORIZED, genuinely device-peer-
        # verified with Phone, and genuinely hold the same real key --
        # there is no server-side "only one concurrent sync" lock to
        # make either one spuriously fail).
        assert results.get("desktop", {}).get("success") is True
        assert results.get("browser", {}).get("success") is True

        # No lost update / no key overwrite with stale state / no
        # inconsistent current_epoch(): Phone ends up with EXACTLY the
        # one genuine key, at the one genuine epoch -- KeyManager.
        # store_key()'s pre-existing same-epoch idempotency (see
        # tests/test_device_key_sync_hardening.py's own docstring)
        # is what makes two concurrent, content-identical deliveries
        # safe by construction, never a race to "win."
        assert _wait_for(lambda: phone.key_manager.has_key(conversation_id))
        assert phone.key_manager.get_key(conversation_id) == genuine_key
        assert phone.key_manager.current_epoch(conversation_id) == genuine_epoch

        # Desktop's and Browser's own local state are themselves
        # unaffected by the race (they were sources, not targets).
        assert desktop.key_manager.get_key(conversation_id) == genuine_key
        assert browser.key_manager.get_key(conversation_id) == genuine_key
    finally:
        for session in (desktop, bob, browser, phone):
            try:
                session.disconnect()
            except Exception:
                pass
        _delete(bob_payload["username"])
