"""
Phase 16D -- Multi-Device Security Hardening + Device-Aware Peer
Identity: third-party multi-device recognition.

Before this phase, ClientSession's peer-trust state (VERIFIED /
UNVERIFIED / KEY_CHANGED -- storage/secure_key_store.py) was keyed
purely by username. That is correct for one device per account, but
collapses every device of the same account into ONE trust slot: a
second device (e.g. a browser) presenting a genuinely different ML-KEM
/ ML-DSA keypair under the SAME username as an already-VERIFIED first
device (e.g. a desktop) was indistinguishable from an attacker (or a
compromised server) substituting Desktop's key -- both looked exactly
like KEY_CHANGED against the SAME slot.

client/session.py::_peer_identity_key(username, device_id) (Phase 16D)
composes a (username, device_id) key that every peer-trust-state
method now optionally routes through -- see that method's own comment
for the full design. This is the smallest possible extension of the
EXISTING VERIFIED/UNVERIFIED/KEY_CHANGED state machine (reused, not
reimplemented, not weakened): a second device gets its OWN
independently-tracked slot instead of colliding with the first.

This test proves the resulting behavior end-to-end using ONLY real
ClientSession/network code -- connect(), login(), enroll_device(), and
the real "chat"/"key_exchange" wire packets a genuine client sends --
never internal dictionary manipulation. Alice Desktop and Alice
Browser share one account/username; Bob is a separate, independent
account acting as the observing third party.

Run with:
    pytest tests/test_multi_device_peer_identity.py -v
"""

import time

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from client.session import PEER_KEY_STATE_CHANGED, ClientSession
from crypto.key_manager import fingerprint_combined_identity
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED
from database.models.device import DEVICE_STATE_AUTHORIZED
from tests.test_device_key_sync import (
    PASSWORD,
    _delete,
    _get_device_row,
    _mutually_verify_devices,
    _new_device_session,
    _register,
    _verify_peers,
    account,
    running_server,
)

_app = QApplication.instance() or QApplication([])


def _wait_for(predicate, attempts=150, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


def _new_pre_enrolled_device_session(
    running_server, monkeypatch, payload, key_store_dir, device_name, platform
):
    """
    Like test_device_key_sync.py's _new_device_session(), but never
    sends a PLAIN (device_id=None) identity broadcast at all -- it
    calls enroll_device() immediately after start_receiver(), which
    (Phase 16D) resolves self.device_id and sends this device's
    ONLY-EVER identity broadcast already carrying it.

    This is a genuine, documented finding of this phase (see
    docs/architecture/multi_device_identity.md's Phase 16D section):
    a plain, device_id-less broadcast from the SAME username as an
    already-VERIFIED sibling device is cryptographically
    indistinguishable from a key-substitution attack against that
    single (username)-keyed slot -- only a device_id lets a receiver
    tell the two apart, so a device-aware client (any device enrolled
    AFTER an account's first) must have one attached from its very
    first broadcast onward, never introduced only after the fact. A
    real client's startup sequence should call enroll_device() as part
    of connecting, not defer it -- exactly what this helper models.
    """

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
    session.start_receiver()
    session.enroll_device(device_name=device_name, platform=platform)
    return session


def test_bob_distinguishes_alice_desktop_and_alice_browser_as_separate_devices(
    running_server, monkeypatch, account, tmp_path
):
    """
    Step 5 (Phase 16D) -- the full 10-point scenario: Bob has already
    VERIFIED Alice Desktop. Alice Browser (same account, different
    device) then connects. Bob must never conflate the two, must be
    able to keep messaging Desktop throughout, and must be able to
    separately, independently verify and message Browser -- with a
    later Browser key change producing KEY_CHANGED for Browser alone.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    browser = None

    try:
        desktop.enroll_device(device_name="Desktop", platform="linux")  # bootstrap -> AUTHORIZED
        desktop.bind_device_session()

        # ------------------------------------------------------------
        # 1/5. Bob VERIFIES Alice Desktop (ordinary, unmodified peer
        # verification -- ML-KEM + ML-DSA combined identity, exactly
        # as every pre-16D peer verification already worked).
        # ------------------------------------------------------------
        assert _wait_for(lambda: bob.key_manager.get_public_key(desktop.username) is not None)
        assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
        _verify_peers(bob, desktop, desktop.username)
        _verify_peers(desktop, bob, bob.username)

        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        # Bob can already receive real, live messages from Desktop.
        desktop.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        desktop.establish_session_key()
        conversation_id = desktop.current_conversation_id
        desktop.send_chat_message("hello from desktop, before browser exists")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "hello from desktop, before browser exists"
            for s in bob.conversation_store.get_all()
        ))

        # ------------------------------------------------------------
        # Alice Browser -- a SECOND device of the SAME account --
        # connects and enrolls for real. This is what makes its
        # identity broadcast carry a device_id distinct from
        # Desktop's, over the real wire protocol (send_public_key()/
        # handle_public_key() -- see client/session.py's Phase 16D
        # comments).
        # ------------------------------------------------------------
        browser = _new_pre_enrolled_device_session(
            running_server, monkeypatch, account, tmp_path / "browser", "Browser", "web"
        )

        # 3. Browser is represented as a DISTINCT device identity --
        # Bob must be able to resolve a (username, device_id)-scoped
        # verification state for it at all (None would mean nothing
        # was ever recorded under that composite key).
        assert _wait_for(
            lambda: bob.get_peer_verification_state(browser.username, browser.device_id) is not None
        )

        # 4. Browser is UNVERIFIED, never auto-trusted merely for
        # sharing Desktop's username.
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_STATE_UNVERIFIED

        # 1/2/5/10. Bob does NOT silently replace Desktop's identity,
        # does NOT interpret Browser as a key replacement for Desktop,
        # and Desktop's own (plain-username-keyed, no device_id) trust
        # state is completely untouched -- still exactly VERIFIED,
        # never KEY_CHANGED.
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        # 6. Bob can continue receiving valid messages from Desktop,
        # proving Desktop's signing-key resolution was never disturbed
        # by Browser's arrival.
        desktop.send_chat_message("still desktop, browser is unverified")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "still desktop, browser is unverified"
            for s in bob.conversation_store.get_all()
        ))

        # ------------------------------------------------------------
        # 7. Browser is separately, explicitly verified by Bob --
        # ordinary human-verification action, scoped to THIS device_id
        # only, never to the account/username as a whole.
        # ------------------------------------------------------------
        # NOTE: this is THIRD-PARTY (Bob-to-another-account's-device)
        # verification, keyed by (username, device_id) via
        # confirm_combined_peer_verification()'s device_id kwarg --
        # NOT confirm_device_peer_verification()/observe_device_peer_
        # identity(), which are the Phase 16C DEVICE-PEER trust wrapper
        # methods reserved for an account verifying its OWN sibling
        # devices (keyed purely by device_id, used for device_key_sync)
        # and would be the wrong tool here.
        browser_signing_key = browser.key_manager.ml_dsa.export_public_key()
        browser_fingerprint = fingerprint_combined_identity(
            browser.key_manager.public_key, browser_signing_key
        )
        bob.confirm_combined_peer_verification(
            browser.username, browser_fingerprint, device_id=browser.device_id
        )
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_STATE_VERIFIED

        # Desktop's own state is STILL untouched by verifying a
        # completely independent device slot.
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        # ------------------------------------------------------------
        # 8. Once Browser is verified, Bob can accept real Browser
        # messages.
        #
        # Browser must reuse the SAME conversation Desktop already has
        # with Bob, not independently call establish_session_key() for
        # itself: conversation_id is resolved server-side from the two
        # ACCOUNTS' (not devices') user_ids, so Browser and Desktop
        # necessarily resolve to the exact same conversation_id Bob
        # already holds an epoch for -- a second, independent
        # establish_session_key() call for that same conversation_id
        # would race/rotate the epoch Bob already has, which is a
        # conversation/key-management concern Phase 16C's device_key_
        # sync protocol already exists to solve correctly (see
        # tests/test_device_key_sync.py's own happy-path test), not
        # something this identity-focused test should reinvent.
        # Browser therefore receives the EXISTING key the same way any
        # newly-authorized device would: real device authorization +
        # real device-peer verification + real device_key_sync,
        # exactly Phase 16C's production path.
        # ------------------------------------------------------------
        browser_device_row = next(
            d for d in desktop.list_devices() if d["device_id"] == browser.device_id
        )
        desktop.authorize_device(browser.device_id, browser_device_row["fingerprint"])
        browser.bind_device_session()
        assert _get_device_row(browser.device_id).state == DEVICE_STATE_AUTHORIZED

        _mutually_verify_devices(desktop, browser)

        sync_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        assert sync_result["success"] is True
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))

        # send_chat_message() also requires the SENDER to already
        # trust the recipient (ordinary, unmodified precondition --
        # see Phase 16B's own discovery of this symmetric requirement)
        # -- Browser verifying Bob as an ordinary peer, independent of
        # (and unaffected by) the device-peer verification with
        # Desktop just above.
        assert _wait_for(lambda: browser.key_manager.get_public_key(bob.username) is not None)
        _verify_peers(browser, bob, bob.username)

        browser.set_current_chat(
            ConversationSummary(conversation_id=conversation_id, username=bob.username, is_online=True, latest_message=None)
        )
        browser.send_chat_message("hello from the verified browser")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "hello from the verified browser"
            for s in bob.conversation_store.get_all()
        ))

        # ------------------------------------------------------------
        # 9. A later Browser key change produces KEY_CHANGED for
        # Browser's OWN slot only -- simulated the same way every
        # other KEY_CHANGED test in this codebase does: a fresh
        # identity observation for the SAME (username, device_id) that
        # disagrees with the just-VERIFIED fingerprint. Uses the real
        # observe_device_peer_identity() entry point (device-peer
        # trust reuses combined-identity machinery keyed by device_id,
        # exactly like Phase 16C's device_key_sync trust already does)
        # with genuinely different, freshly generated key material --
        # never a hand-edited dict.
        # ------------------------------------------------------------
        from crypto.key_manager import KeyManager

        rotated = KeyManager()  # fresh, genuinely different KEM + ML-DSA keypair

        bob.observe_peer_identity(
            browser.username,
            rotated.public_key.decode("utf-8"),
            rotated.ml_dsa.export_public_key(),
            device_id=browser.device_id,
        )

        # 9. KEY_CHANGED for Browser's slot...
        assert bob.get_peer_verification_state(browser.username, browser.device_id) == PEER_KEY_STATE_CHANGED

        # 10. ...and Desktop's independent, unrelated slot is
        # completely unaffected.
        assert bob.get_peer_verification_state(desktop.username) == PEER_STATE_VERIFIED

        # Desktop can still be messaged after Browser's key change --
        # the two devices' trust states never interact.
        desktop.send_chat_message("desktop still fine after browser key changed")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "desktop still fine after browser key changed"
            for s in bob.conversation_store.get_all()
        ))

    finally:
        for session in (desktop, bob, browser):
            if session is None:
                continue
            try:
                session.disconnect()
            except Exception:
                pass
        _delete(account["username"])
        _delete(bob_payload["username"])
