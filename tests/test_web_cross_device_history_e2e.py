"""
The reported failure, end to end with the real Website code: an account
chats on the Website (Chrome); the same account's Desktop (a real
ClientSession) must be able to read that history -- and the Website must
read what the Desktop then sends -- once the Desktop is authorized,
verified and sent the keys.

Run with:
    pytest tests/test_web_cross_device_history_e2e.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from crypto.key_manager import fingerprint_combined_identity
from domain.conversation_summary import ConversationSummary
from tests.test_web_browser_e2e import (  # noqa: F401 -- reused fixtures/helpers, not re-implemented
    _connect_browser,
    _open_direct,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)


def _browser_keys(page):
    kem_wire = page.evaluate(
        "(() => { const b=window.__session.kemKeypair.publicKey; "
        "let s=''; for (let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); return btoa(s); })()"
    )
    signing_hex = page.evaluate(
        "(() => { const b=window.__session.signingKeypair.publicKey; "
        "let s=''; for (let i=0;i<b.length;i++) s+= b[i].toString(16).padStart(2,'0'); return s; })()"
    )
    return kem_wire, bytes.fromhex(signing_hex)


def _texts(history):
    return [(entry["text"], entry["is_own"]) for entry in history]


def test_website_history_is_readable_on_the_desktop_and_back(
    running_server, gateway_url, browser_page, desktop_app
):
    account = desktop_app["register"]("acct_")
    peer_payload = desktop_app["register"]("peer_")
    peer = desktop_app["launch"](peer_payload)
    page = browser_page["page"]

    # --- The account chats with the peer on the Website. ---
    _connect_browser(browser_page, gateway_url, account)
    assert _wait_for(lambda: peer.key_manager.get_public_key(account["username"]) is not None)

    page.fill("#peerUsername", peer.username)
    page.press("#peerUsername", "Enter")
    assert _wait_for(lambda: peer.username in page.inner_text("#fingerprintDisplay"), attempts=200, interval=0.1)
    page.click("#confirmVerifiedBtn")
    assert _wait_for(lambda: "marked VERIFIED" in page.inner_text("#log"))

    web_kem, web_signing = _browser_keys(page)
    peer.observe_peer_identity(account["username"], web_kem, web_signing)
    peer.confirm_combined_peer_verification(
        account["username"], fingerprint_combined_identity(web_kem, web_signing)
    )

    page.click("#establishKeyBtn")
    assert _wait_for(lambda: "Session key established" in page.inner_text("#log"))
    conversation_id = page.evaluate("Array.from(window.__session.sessionKeys.keys())[0]")
    assert _wait_for(lambda: peer.key_manager.has_key(conversation_id))

    page.fill("#messageText", "Hello from the website")
    page.click("#sendBtn")
    assert _wait_for(lambda: any(
        s.latest_message and s.latest_message.text == "Hello from the website"
        for s in peer.conversation_store.get_all()
    ))
    _open_direct(peer, account["username"])
    peer.send_chat_message("Hello from the peer")
    assert _wait_for(lambda: "Hello from the peer" in page.inner_text("#messages"), attempts=200, interval=0.1)

    # The Website is the account's first device.
    page.evaluate("(async () => window.__session.enrollDevice('Website', 'web'))()")
    page.evaluate("(async () => window.__session.bindDeviceSession())()")

    # --- The same account signs in on the Desktop: a new device with no keys. ---
    desktop = desktop_app["launch"](account)
    assert _wait_for(lambda: desktop.key_manager.get_public_key(peer.username) is not None)
    desktop.set_current_chat(
        ConversationSummary(
            conversation_id=conversation_id, username=peer.username, is_online=True, latest_message=None
        )
    )
    before = desktop.load_conversation_history(peer.username)
    assert [e["text"].startswith("Message unavailable") for e in before] == [True, True]

    # --- Enroll, authorize from the Website, verify both ways, send keys from the Website. ---
    desktop.enroll_device(device_name="Desktop", platform="Desktop")
    desktop_id = desktop.device_id
    desktop_fingerprint = fingerprint_combined_identity(
        desktop.key_manager.public_key, desktop.key_manager.ml_dsa.export_public_key()
    )

    web_fingerprint_of_desktop = page.evaluate(
        """(async (id) => {
            const s = window.__session;
            const target = (await s.listDevices()).find((d) => d.device_id === id);
            const peer = await s.observeDevicePeerIdentity(id, target.kem_public_key, target.ml_dsa_public_key);
            s.confirmDevicePeerVerified(id, peer.fingerprint);
            await s.authorizeDevice(id, peer.fingerprint);
            return peer.fingerprint;
        })""",
        desktop_id,
    )
    # Both implementations compute the same safety number for the same keys.
    assert web_fingerprint_of_desktop == desktop_fingerprint

    assert desktop.bind_device_session()["success"]
    web_entry = next(d for d in desktop.list_devices() if d["device_id"] != desktop_id)
    desktop_computed = desktop.observe_own_device(web_entry)
    desktop.confirm_device_peer_verification(web_entry["device_id"], desktop_computed)

    sync = page.evaluate(
        "(async (id) => window.__session.syncAllConversationKeysToDevice(id))", desktop_id
    )
    assert sync["sent"] >= 1 and sync["failures"] == []
    assert _wait_for(lambda: desktop.key_manager.has_key(conversation_id), attempts=200, interval=0.1)

    # --- Web -> Desktop: the existing history now reads. ---
    after = desktop.load_conversation_history(peer.username)
    assert _texts(after) == [("Hello from the website", True), ("Hello from the peer", False)]

    # --- Desktop -> Web: what the Desktop sends reads on the Website's history. ---
    desktop.observe_peer_identity(
        peer.username, peer.key_manager.public_key, peer.key_manager.ml_dsa.export_public_key()
    )
    desktop.confirm_combined_peer_verification(
        peer.username,
        fingerprint_combined_identity(peer.key_manager.public_key, peer.key_manager.ml_dsa.export_public_key()),
    )
    desktop.send_chat_message("Hello from the desktop")

    page.evaluate("document.getElementById('messages').innerHTML = ''")
    assert _wait_for(
        lambda: page.evaluate(
            """(async (id) => {
                window.__session.forgetRenderedHistory(id);
                document.getElementById('messages').innerHTML = '';
                await window.__session.loadHistory(id, false);
                return document.getElementById('messages').innerText;
            })""",
            conversation_id,
        ).count("Hello from the desktop") >= 1,
        attempts=100, interval=0.2,
    )

    severe = [m for m in browser_page["console"] if m[0] == "error"]
    assert not browser_page["errors"], f"Uncaught page errors: {browser_page['errors']}"
    assert not severe, f"Console errors: {severe}"
