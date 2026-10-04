"""
Phase 17 -- Web Persistence + Reconnect: real browser E2E proof.

Reuses tests/test_web_browser_e2e.py's own fixtures (running_server,
gateway_url, static_url, browser_page, desktop_app) and helper
functions unchanged -- this file adds only the NEW scenarios Phase 17
introduces (page-reload persistence, reconnect after a dropped
WebSocket, logout stopping reconnect), never duplicating Phase 15B's
already-proven first-connection/messaging/verification coverage.

Every scenario drives the REAL shipped web/client/{index.html,main.js,
app.js,storage.js,crypto.js,protocol.js} files in a REAL browser
(Chromium via Playwright, the system's installed Google Chrome) against
the REAL gateway and REAL server -- consistent with this whole test
suite's "never mock the browser" rule.

Run with:
    pytest tests/test_web_persistence_reconnect.py -v -s
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from crypto.key_manager import fingerprint_combined_identity
from domain.conversation_summary import ConversationSummary
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    PASSWORD,
    _connect_browser,
    _delete,
    _open_direct,
    _register,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)

_app = QApplication.instance() or QApplication([])


def _verify_alice_observes_bob(alice, page, bob_username):
    """Alice's (desktop) side of peer verification against the real,
    currently-running browser session -- identical pattern to test_web_
    browser_e2e.py's own test, not a second implementation."""

    bob_kem_wire = page.evaluate(
        "(() => { "
        "const b=window.__session.kemKeypair.publicKey; "
        "let s=''; for (let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); "
        "return btoa(s); })()"
    )
    bob_signing_key_hex = page.evaluate(
        "(() => { "
        "const b=window.__session.signingKeypair.publicKey; "
        "let s=''; for (let i=0;i<b.length;i++) s+= b[i].toString(16).padStart(2,'0'); "
        "return s; })()"
    )
    bob_signing_key = bytes.fromhex(bob_signing_key_hex)

    alice.observe_peer_identity(bob_username, bob_kem_wire, bob_signing_key)
    combined_fp = fingerprint_combined_identity(bob_kem_wire, bob_signing_key)
    alice.confirm_combined_peer_verification(bob_username, combined_fp)
    return bob_kem_wire, bob_signing_key


def test_page_reload_restores_identity_and_trust_state(
    running_server, gateway_url, browser_page, desktop_app
):
    """
    Steps 2/3/12 -- Login -> connect -> establish secure session ->
    verify peer -> send message -> reload page -> restore session ->
    continue communication, WITHOUT the browser's identity/fingerprint
    changing and WITHOUT needing to re-verify Alice.
    """

    alice_payload = desktop_app["register"]("alice_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        # Real identity established, real fingerprint verification
        # (Bob -> Alice, via the real UI), real session key, real
        # message -- identical setup to test_web_browser_e2e.py's own
        # happy path, condensed.
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        page.fill("#peerUsername", alice.username)
        assert _wait_for(lambda: alice.username in page.inner_text("#fingerprintDisplay"))
        page.click("#confirmVerifiedBtn")
        assert _wait_for(lambda: "marked VERIFIED" in page.inner_text("#log"))

        _verify_alice_observes_bob(alice, page, bob_username)
        assert alice.get_peer_verification_state(bob_username) == "VERIFIED"

        page.click("#establishKeyBtn")
        assert _wait_for(lambda: "Session key established" in page.inner_text("#log"))

        conversation_id = page.evaluate("Array.from(window.__session.sessionKeys.keys())[0]")
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        kem_public_before = page.evaluate(
            "Array.from(window.__session.kemKeypair.publicKey).join(',')"
        )
        signing_public_before = page.evaluate(
            "Array.from(window.__session.signingKeypair.publicKey).join(',')"
        )

        # --- The Phase 17 scenario: reload the page. ---
        page.reload()
        page.wait_for_selector("#connectBtn")

        # Re-enter credentials (the password itself is never persisted
        # -- see storage.js/app.js's own documented design) and
        # reconnect through the real UI, exactly like a first login.
        # page.reload()'s default wait-until="load" should already
        # guarantee main.js's module script (and therefore its click
        # listeners) has executed, but wait_for_load_state() is added
        # explicitly and defensively here anyway -- a real, reproducible
        # race was observed without it: the reload+immediate-click
        # sequence occasionally fired the click before the module
        # script had attached its listener, silently no-opping it.
        page.wait_for_load_state("load")
        _connect_browser(browser_page, gateway_url, bob_payload)

        # 1. The restored identity is the SAME identity, not a freshly
        # generated one -- this is the actual property Phase 17 exists
        # to prove: a reload must not look like a new device.
        assert "Restored this browser's persisted identity" in page.inner_text("#log")
        kem_public_after = page.evaluate(
            "Array.from(window.__session.kemKeypair.publicKey).join(',')"
        )
        signing_public_after = page.evaluate(
            "Array.from(window.__session.signingKeypair.publicKey).join(',')"
        )
        assert kem_public_after == kem_public_before
        assert signing_public_after == signing_public_before

        # 2. Peer-trust state (Alice, VERIFIED) survived the reload --
        # no re-verification needed.
        fingerprint_after_reload = page.evaluate(
            f"window.__session.peers.get({alice.username!r})?.state"
        )
        assert fingerprint_after_reload == "VERIFIED"

        # 3. The session key survived the reload -- messaging resumes
        # immediately, without re-establishing a key.
        restored_conversation_ids = page.evaluate("Array.from(window.__session.sessionKeys.keys())")
        assert conversation_id in restored_conversation_ids

        received = {}
        alice.message_received.connect(
            lambda identity_key, sender, text: received.update(sender=sender, text=text)
        )
        # #peerUsername is plain UI input state (who to message), never
        # part of the persisted SESSION state -- a fresh page load
        # naturally starts with it empty, exactly like every other form
        # field, and must be re-filled the same way a real user would.
        page.fill("#peerUsername", alice.username)
        page.fill("#messageText", "Hello again, after reload")
        page.click("#sendBtn")
        assert _wait_for(lambda: received.get("text") == "Hello again, after reload")

        # Alice, whose trust of Bob was never disturbed, can still send
        # to the restored browser session too.
        _open_direct(alice, bob_username)
        alice.send_chat_message("Still fine after your reload")
        assert _wait_for(
            lambda: "Still fine after your reload" in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        )
    finally:
        _delete(bob_payload["username"])


def test_reconnect_after_dropped_websocket_resumes_messaging(
    running_server, gateway_url, browser_page, desktop_app
):
    """
    Step 4/5/9 -- a dropped WebSocket (simulated here by force-closing
    the real, live socket from real browser JS -- indistinguishable,
    from the browser's own WebSocket API, from a genuine network
    interruption) is detected, triggers a bounded automatic reconnect,
    and messaging resumes without any human action and without losing
    the already-established identity/trust/session-key state.
    """

    alice_payload = desktop_app["register"]("alice2_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob2_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        page.fill("#peerUsername", alice.username)
        assert _wait_for(lambda: alice.username in page.inner_text("#fingerprintDisplay"))
        page.click("#confirmVerifiedBtn")
        assert _wait_for(lambda: "marked VERIFIED" in page.inner_text("#log"))
        _verify_alice_observes_bob(alice, page, bob_username)

        page.click("#establishKeyBtn")
        assert _wait_for(lambda: "Session key established" in page.inner_text("#log"))
        conversation_id = page.evaluate("Array.from(window.__session.sessionKeys.keys())[0]")
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        assert page.evaluate("document.getElementById('connectionStatus').dataset.state") == "connected"

        # --- Simulate a dropped connection: force-close the REAL, live
        # WebSocket from real browser JS. The browser's WebSocket API
        # cannot tell this apart from the network actually dropping --
        # this is not a mock, it is the real socket really closing.
        page.evaluate("window.__session.ws.close()")

        assert _wait_for(
            lambda: page.evaluate("document.getElementById('connectionStatus').dataset.state") == "reconnecting",
            attempts=100, interval=0.1,
        )

        # Bounded wait for the default backoff (1s, 2s, 4s, ... capped)
        # to produce a successful reconnect -- generous but still
        # bounded (this test does not wait indefinitely). The window is
        # wider than the ~15s theoretical worst case (1+2+4+8) to
        # absorb this environment's own documented resource-contention
        # slowdown under back-to-back real-browser tests (see e.g.
        # tests/test_web_gateway_interop.py's own long-standing note),
        # not because reconnect itself is expected to be this slow.
        assert _wait_for(
            lambda: "Reconnected." in page.inner_text("#log"),
            attempts=300, interval=0.2,  # up to 60s
        )
        assert page.evaluate("document.getElementById('connectionStatus').dataset.state") == "connected"

        # No duplicate connections: exactly one OPEN socket.
        assert page.evaluate("window.__session.ws && window.__session.ws.readyState") == 1  # WebSocket.OPEN

        # Identity/trust/session-key state survived the reconnect
        # in-memory (never lost, since this was the same page/tab, no
        # reload) -- and messaging resumes without re-verification.
        peer_state = page.evaluate(f"window.__session.peers.get({alice.username!r})?.state")
        assert peer_state == "VERIFIED"
        assert conversation_id in page.evaluate("Array.from(window.__session.sessionKeys.keys())")

        received = {}
        alice.message_received.connect(
            lambda identity_key, sender, text: received.update(sender=sender, text=text)
        )
        page.fill("#messageText", "Message after reconnect")
        page.click("#sendBtn")
        assert _wait_for(lambda: received.get("text") == "Message after reconnect")
    finally:
        _delete(bob_payload["username"])


def test_logout_stops_reconnect(running_server, gateway_url, browser_page):
    """Step 4 -- an explicit logout (disconnect()) must never be
    silently followed by an automatic reconnect."""

    payload = _register("erin_")
    try:
        _connect_browser(browser_page, gateway_url, payload)
        page = browser_page["page"]

        assert page.evaluate("document.getElementById('connectionStatus').dataset.state") == "connected"

        page.click("#logoutBtn")

        assert _wait_for(
            lambda: page.evaluate("document.getElementById('connectionStatus').dataset.state") == "disconnected",
            attempts=100, interval=0.1,
        )

        # Wait past what would have been at least one reconnect
        # attempt's worth of time (default base delay 1000ms) and
        # confirm the state never moved to "reconnecting" and no
        # "Reconnected." log line ever appeared.
        time.sleep(3)
        assert page.evaluate("document.getElementById('connectionStatus').dataset.state") == "disconnected"
        assert "Reconnected." not in page.inner_text("#log")
        assert "reconnecting" not in page.inner_text("#log").lower()
    finally:
        _delete(payload["username"])
