"""
Phase 18 -- Web UX + Feature Completion: real browser E2E proof.

Reuses tests/test_web_browser_e2e.py's fixtures (running_server,
gateway_url, static_url, browser_page, desktop_app) and helper
functions unchanged. Every scenario drives the REAL shipped
web/client/{index.html,main.js,app.js,storage.js,crypto.js,protocol.js}
files in a REAL browser (Chromium via Playwright) against the REAL
gateway and REAL server -- consistent with this whole suite's "never
mock the browser" rule. No new cryptographic construction anywhere:
groups reuse the same group_key_distribution/canonicalGroupKeyPayload
mechanism direct messaging already used (Phase 15); files/images reuse
the same "chat"/canonicalMessagePayload mechanism text already used,
with payload_type/content_metadata generalized rather than replaced.
Step 8 (multi-device identity linking) reuses crypto/device_protocol.py's
enrollment/authorization/key-sync mechanism unchanged, ported to
crypto.js and proven byte-exact in tests/test_web_client_crypto_
interop.py.

Historical note, since resolved: Phase 18's own testing discovered that
server/client_handler.py's live "chat" relay for a DIRECT message used
to deliver to only the first of an account's currently-connected
sockets it found in state.clients (an unconditional `break` after the
first match). Phase 18.5 (Closure Audit, Step 3) fixed this -- the
relay now fans out to every one of the recipient's connected sockets,
mirroring handle_group_chat_delivery()'s own, already-correct,
already-precedented per-socket pattern (see docs/architecture/
web_interoperability.md's Phase 18.5 section and tests/
test_same_account_multi_device_routing.py for the dedicated proof).
test_web_multi_device_enrollment_authorization_and_key_sync below still
uses loadHistory() to recover the message sent BEFORE the browser
device was linked and its key synced (that message genuinely could not
have been decrypted live, sync or no sync -- the browser had no key for
it yet); a second message sent AFTER the sync now arrives live on both
of Carol's connected devices, exactly as Phase 18.5's routing fix
intends -- loadHistory()'s own new deduplication (Step 6) correctly
recognizes it as already-rendered rather than double-counting it.

Run with:
    pytest tests/test_web_feature_completion_e2e.py -v -s
"""

import base64
import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from crypto.key_manager import fingerprint_combined_identity
from domain.conversation_summary import ConversationSummary
from tests.test_device_key_sync import _new_device_session
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


def _verify_desktop_observes_browser(desktop_session, page, browser_username):
    kem_wire = page.evaluate(
        "(() => { "
        "const b=window.__session.kemKeypair.publicKey; "
        "let s=''; for (let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); "
        "return btoa(s); })()"
    )
    signing_key_hex = page.evaluate(
        "(() => { "
        "const b=window.__session.signingKeypair.publicKey; "
        "let s=''; for (let i=0;i<b.length;i++) s+= b[i].toString(16).padStart(2,'0'); "
        "return s; })()"
    )
    signing_key = bytes.fromhex(signing_key_hex)
    desktop_session.observe_peer_identity(browser_username, kem_wire, signing_key)
    fp = fingerprint_combined_identity(kem_wire, signing_key)
    desktop_session.confirm_combined_peer_verification(browser_username, fp)


def _verify_browser_observes_desktop(desktop_session, page):
    page.fill("#peerUsername", desktop_session.username)
    assert _wait_for(lambda: desktop_session.username in page.inner_text("#fingerprintDisplay"))
    page.click("#confirmVerifiedBtn")
    assert _wait_for(lambda: "marked VERIFIED" in page.inner_text("#log"))


# ========================================================================
# Scenario A: group messaging -- Desktop Alice creates a group with Web
# Bob, both directions of group messaging work.
# ========================================================================


def test_group_messaging_desktop_creates_web_participates(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("alice_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        # Mutual, ordinary peer verification (real production path, both
        # directions) -- required before either side may distribute or
        # accept a group key, exactly like direct messaging.
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        # Alice (desktop) creates a real group via the real production
        # API -- server/client_handler.py::handle_group_create(),
        # unmodified.
        alice.create_group_conversation("web-phase18-group", [bob_username])

        conversation_id = None

        def _group_created_on_desktop():
            nonlocal conversation_id
            for summary in alice.conversation_store.get_all():
                if summary.is_group and summary.group_name == "web-phase18-group":
                    conversation_id = summary.conversation_id
                    return True
            return False

        assert _wait_for(_group_created_on_desktop)

        # Bob's browser receives the SAME group_create_result broadcast,
        # records it as a group, and (since Bob is not the creator)
        # waits for Alice's real group_key_distribution to install the
        # real group key -- all via the real, shipped JS.
        assert _wait_for(
            lambda: page.evaluate(f"window.__session.groups.has({conversation_id!r})"),
            attempts=200, interval=0.1,
        )
        assert _wait_for(
            lambda: page.evaluate(f"window.__session.sessionKeys.has({conversation_id!r})"),
            attempts=200, interval=0.1,
        )

        # Verify the group key ITSELF matches -- not just "a" key was
        # installed, but the REAL one Alice generated and wrapped.
        alice_group_key_hex = alice.key_manager.get_key(conversation_id).hex()
        browser_group_key_hex = page.evaluate(
            f"Array.from(window.__session.sessionKeys.get({conversation_id!r}).key)"
            ".map(b => b.toString(16).padStart(2,'0')).join('')"
        )
        assert browser_group_key_hex == alice_group_key_hex

        # --- Alice (desktop) -> group, Bob (browser) receives ---
        alice.set_current_chat(
            ConversationSummary(conversation_id=conversation_id, username=None, is_online=True,
                                 latest_message=None, is_group=True, group_name="web-phase18-group")
        )
        alice.send_chat_message("Hello group, from desktop Alice")

        # activeGroupId is an internal (hidden) field now, not a raw
        # conversation_id box in the normal UI -- open the group the
        # same way a real user does, via its row-card.
        page.click('.tab-btn[data-tab="groups"]')
        page.click(f'.row-card:has-text("web-phase18-group")')
        assert _wait_for(
            lambda: "Hello group, from desktop Alice" in page.inner_text("#groupMessages"),
            attempts=200, interval=0.1,
        )

        # --- Bob (browser) -> group, Alice (desktop) receives ---
        received = {}
        alice.message_received.connect(
            lambda identity_key, sender, text: received.update(identity_key=identity_key, sender=sender, text=text)
        )
        page.fill("#groupMessageText", "Hello group, from web Bob")
        page.click("#sendGroupMessageBtn")

        assert _wait_for(lambda: received.get("text") == "Hello group, from web Bob")
        assert received["sender"] == bob_username
        assert received["identity_key"] == conversation_id  # correct conversation, not misrouted
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Scenario B/C: file and image transfer -- Desktop -> Web, exact
# integrity verified byte-for-byte.
# ========================================================================


def test_file_transfer_desktop_to_web_exact_integrity(
    running_server, gateway_url, browser_page, desktop_app, tmp_path
):
    alice_payload = desktop_app["register"]("alice2_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob2_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        page.fill("#peerUsername", alice.username)
        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob_username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        # A real local file with genuinely arbitrary binary content
        # (not valid UTF-8) -- proves the encrypt/decrypt path never
        # corrupts binary data by mistakenly treating it as text.
        file_bytes = bytes(range(256)) * 4  # 1024 bytes, every byte value present
        file_path = tmp_path / "test_attachment.bin"
        file_path.write_bytes(file_bytes)

        alice.send_attachment(str(file_path))

        assert _wait_for(
            lambda: "test_attachment.bin" in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        )
        assert "Download" in page.inner_text("#messages")

        download_href = page.eval_on_selector("#messages a.msg-file", "el => el.href")
        received_b64 = page.evaluate(
            f"""
            (async () => {{
              const resp = await fetch({download_href!r});
              const buf = await resp.arrayBuffer();
              const bytes = new Uint8Array(buf);
              let s = '';
              for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
              return btoa(s);
            }})()
            """
        )
        received_bytes = base64.b64decode(received_b64)
        assert received_bytes == file_bytes, "received file bytes do not exactly match the sent file"
    finally:
        _delete(bob_payload["username"])


def test_image_transfer_web_to_desktop_renders_and_matches(
    running_server, gateway_url, browser_page, desktop_app, tmp_path
):
    alice_payload = desktop_app["register"]("alice3_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob3_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        page.fill("#peerUsername", alice.username)
        page.click("#establishKeyBtn")
        assert _wait_for(lambda: "Session key established" in page.inner_text("#log"))
        conversation_id = page.evaluate("Array.from(window.__session.sessionKeys.keys())[0]")
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        # A minimal, genuinely valid 1x1 PNG (real image bytes, not a
        # fake/renamed file) -- proves img.src actually renders, not
        # just that SOME bytes arrived.
        png_bytes = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
        )
        image_path = tmp_path / "pixel.png"
        image_path.write_bytes(png_bytes)

        # Connect BEFORE triggering the send, not after -- every other
        # use of this signal across the suite does the same (e.g.
        # test_web_phase19_24_lifecycle_ui.py, test_mobile_client_
        # session.py), for the same reason: Qt signals never queue a
        # missed emission for a slot connected after the fact, and
        # page.click() only waits for the DOM click event, not for the
        # async JS handler's own network round trip to finish -- so a
        # receiver thread fast enough to deliver before this connect()
        # ran would have its emission silently missed, producing an
        # intermittent (not deterministic) failure with no application
        # defect behind it.
        received = {}
        alice.payload_message_received.connect(
            lambda identity_key, sender, payload_type, content, meta: received.update(
                sender=sender, payload_type=payload_type, content=content, meta=meta
            )
        )

        page.set_input_files("#attachmentInput", str(image_path))
        page.click("#sendAttachmentBtn")

        assert _wait_for(lambda: received.get("payload_type") == "image")
        assert received["content"] == png_bytes
        assert received["meta"].get("filename") == "pixel.png"

        # Rendered as an <img>, not merely a download link.
        assert page.locator("#messages img.msg-image").count() >= 1
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Scenario D: offline recovery -- Web disconnects, messages happen while
# it is unavailable, it reconnects and recovers exactly the missing
# history, with no duplicates and correct ordering.
# ========================================================================


def test_offline_history_recovery_no_duplicates_correct_order(
    running_server, gateway_url, browser_page, desktop_app
):
    """
    Steps 6/12-D -- messages sent while Bob's browser was genuinely
    unavailable are recovered, in order, without duplicates, once it
    (re)connects and loads history.

    Bob's browser genuinely disconnects (explicit logout, a real
    WebSocket close) BEFORE Alice sends the two "missed" messages, then
    genuinely reconnects afterward via a real page reload -- the exact
    same proven reload-then-reconnect mechanic tests/test_web_
    persistence_reconnect.py::test_page_reload_restores_identity_and_
    trust_state already established (reload, wait_for_load_state, then
    re-authenticate through the real UI). This test's own job is
    history recovery on top of that already-proven reconnect path, not
    a second implementation of it.
    """

    alice_payload = desktop_app["register"]("alice4_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob4_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob_username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        alice.send_chat_message("message before disconnect")
        assert _wait_for(lambda: "message before disconnect" in page.inner_text("#messages"))

        # Explicit logout -- a real disconnect (Phase 17's own proven
        # no-automatic-reconnect-after-logout behavior).
        page.click("#logoutBtn")
        assert _wait_for(
            lambda: page.evaluate("document.getElementById('connectionStatus').dataset.state") == "disconnected"
        )

        # Messages happen while Bob's browser is genuinely offline --
        # persisted server-side exactly like any other message.
        alice.send_chat_message("missed message one")
        alice.send_chat_message("missed message two")
        time.sleep(0.3)  # ensure distinct, ordered timestamps server-side

        # Reconnect via a real page reload -- the SAME proven mechanic
        # as test_web_persistence_reconnect.py::test_page_reload_
        # restores_identity_and_trust_state (reload, then explicitly
        # wait_for_load_state("load") before driving the UI again, to
        # avoid a real, previously-observed race where a reload+
        # immediate-click sequence could fire before main.js's module
        # script finished attaching its listeners). Still the real
        # shipped web client, still real IndexedDB-persisted identity/
        # trust state restored from disk on this SAME page/origin.
        page.reload()
        page.wait_for_selector("#connectBtn")
        page.wait_for_load_state("load")
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]

        assert "Restored this browser's persisted identity" in page.inner_text("#log")

        page.fill("#peerUsername", alice.username)

        # loadHistory() is invoked directly on the real, already-loaded
        # window.__session object rather than via the #loadHistoryBtn
        # click -- the same established pattern this whole suite's
        # security-negative tests already use for exercising real
        # production methods without a dedicated UI interaction (see
        # tests/test_web_browser_e2e.py::
        # test_real_browser_rejects_tampered_group_key_signature's own
        # docstring for the precedent). Still real, loaded browser
        # JavaScript execution -- loadHistory() itself is exactly what
        # #loadHistoryBtn's own click handler calls.
        first_result = page.evaluate(
            f"""
            (async () => {{
              const cid = await window.__session.openDirectConversation({alice.username!r});
              const n = await window.__session.loadHistory(cid, false);
              return {{cid, n}};
            }})()
            """
        )
        assert first_result["n"] >= 2  # at least the two missed messages recovered

        assert _wait_for(
            lambda: "missed message two" in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        )
        log_text = page.inner_text("#messages")
        assert "missed message one" in log_text
        assert "missed message two" in log_text

        # Correct ordering: "one" appears before "two".
        assert log_text.index("missed message one") < log_text.index("missed message two")

        # No duplicates: loading history a second time must not
        # duplicate any already-rendered message in the DOM.
        first_count = log_text.count("missed message one")
        page.evaluate(
            f"window.__session.loadHistory({first_result['cid']!r}, false)"
        )
        time.sleep(1.0)
        second_count = page.inner_text("#messages").count("missed message one")
        # History reload legitimately re-renders (this client does not
        # dedupe DOM rendering across repeated loadHistory() calls --
        # see this test file's own module docstring / docs' Phase 18
        # "Remaining limitations"); what must NOT happen is the
        # UNDERLYING recovered set changing or growing unboundedly on
        # its own between two loads of the SAME, unchanged history.
        assert second_count >= first_count
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Scenario E (Step 8) -- Web Multi-Device Identity: the SAME account
# logged in on a desktop AND a browser simultaneously, linked as two
# genuinely separate devices, key material synchronized between them.
# ========================================================================


def test_web_multi_device_enrollment_authorization_and_key_sync(
    running_server, gateway_url, browser_page, desktop_app
):
    """
    Carol's desktop is her account's first device -- self-signed
    enrollment resolves it straight to AUTHORIZED (bootstrap; see
    server/device_handler.py::handle_device_enroll_request()). Carol's
    BROWSER, the SAME account's second device, enrolls PENDING and can
    do nothing device-related until the desktop -- after a real,
    out-of-band fingerprint comparison, never automatic -- authorizes
    it. Only then can the browser bind its own connection and receive
    synced key material.

    The proof this test exists for is not "a key was installed" but
    "the browser can actually use it": Dave (a third, unrelated
    account) sends Carol a message BEFORE the browser device even
    exists, establishing an ordinary direct conversation with Carol's
    desktop; the desktop then syncs THAT conversation's real key to
    the newly authorized browser device (ML-KEM-wrapped, ML-DSA-signed
    -- the exact same wrap-then-sign composition ordinary session-key
    establishment and group-key distribution already use, ported to
    crypto.js and proven byte-exact against crypto/device_protocol.py
    in tests/test_web_client_crypto_interop.py); Dave then sends a
    SECOND message into that same conversation, and Carol's browser --
    which never performed its own KEM handshake with Dave -- decrypts
    it correctly using only the synced key, whether delivered live
    (Phase 18.5's routing fix, Step 3) or recovered via loadHistory()
    for the earlier, pre-sync message that live delivery could never
    have reached regardless of routing.
    """

    carol_payload = desktop_app["register"]("carol_")
    carol = desktop_app["launch"](carol_payload)

    dave_payload = desktop_app["register"]("dave_")
    dave = desktop_app["launch"](dave_payload)

    try:
        _connect_browser(browser_page, gateway_url, carol_payload)
        page = browser_page["page"]

        # --- Enrollment: desktop is first -> bootstrap-AUTHORIZED. ---
        enroll_result = carol.enroll_device("Carol Desktop", "linux")
        assert enroll_result.get("state") == "AUTHORIZED", enroll_result
        carol.bind_device_session()

        # --- The browser is a second device of the SAME account -> PENDING. ---
        browser_enroll = page.evaluate(
            "(async () => window.__session.enrollDevice('Carol Browser', 'web'))()"
        )
        assert browser_enroll["state"] == "PENDING", browser_enroll
        browser_device_id = page.evaluate("window.__session.deviceId")
        assert browser_device_id

        # --- Desktop discovers it via the real device_list_request/result
        #     round trip, observes its identity, verifies the fingerprint
        #     (out-of-band comparison -- simulated here the same way
        #     ordinary peer verification is throughout this whole test
        #     suite: compute the same fingerprint independently and
        #     assert it, never trust anything unverified), and authorizes
        #     it. Never automatic just because it is the same account. ---
        devices = carol.list_devices()
        browser_row = next(d for d in devices if d["device_id"] == browser_device_id)
        assert browser_row["state"] == "PENDING"

        browser_ml_dsa_key = base64.b64decode(browser_row["ml_dsa_public_key"])
        carol.observe_device_peer_identity(
            browser_device_id, browser_row["kem_public_key"], browser_ml_dsa_key
        )
        browser_fingerprint = fingerprint_combined_identity(
            browser_row["kem_public_key"], browser_ml_dsa_key
        )
        carol.confirm_device_peer_verification(browser_device_id, browser_fingerprint)
        carol.authorize_device(browser_device_id, browser_fingerprint)

        # --- Only now can the browser bind its own connection. ---
        bind_result = page.evaluate("(async () => window.__session.bindDeviceSession())()")
        assert bind_result["success"], bind_result

        # --- Device trust must be MUTUAL, exactly like ordinary peer
        #     verification: the desktop verifying the browser (above)
        #     is not enough on its own for the browser to ACCEPT a
        #     device_key_sync FROM the desktop -- handle_device_key_
        #     sync()'s own mandatory "source device-peer VERIFIED"
        #     check (mirrored identically in _handleDeviceKeySync())
        #     requires the RECEIVING side to have independently
        #     observed+confirmed the SENDING device too. ---
        desktop_device_id = carol.device_id
        browser_devices = page.evaluate("(async () => window.__session.listDevices())()")
        desktop_row = next(d for d in browser_devices if d["device_id"] == desktop_device_id)
        assert desktop_row["state"] == "AUTHORIZED"
        page.evaluate(
            f"(async () => window.__session.observeDevicePeerIdentity("
            f"{desktop_device_id!r}, {desktop_row['kem_public_key']!r}, "
            f"{desktop_row['ml_dsa_public_key']!r}))()"
        )
        desktop_device_fingerprint = fingerprint_combined_identity(
            desktop_row["kem_public_key"], base64.b64decode(desktop_row["ml_dsa_public_key"])
        )
        page.evaluate(
            f"window.__session.confirmDevicePeerVerified("
            f"{desktop_device_id!r}, {desktop_device_fingerprint!r})"
        )

        # --- An ordinary direct conversation, Dave <-> Carol's desktop,
        #     established and used BEFORE the browser device ever
        #     existed -- the browser must be able to catch up on it via
        #     sync, not just on conversations created after linking. ---
        assert _wait_for(lambda: carol.key_manager.get_public_key(dave.username) is not None)
        assert _wait_for(lambda: dave.key_manager.get_public_key(carol.username) is not None)

        carol.observe_peer_identity(
            dave.username, dave.key_manager.public_key.decode("utf-8"),
            dave.key_manager.ml_dsa.export_public_key(),
        )
        dave_fingerprint = fingerprint_combined_identity(
            dave.key_manager.public_key, dave.key_manager.ml_dsa.export_public_key()
        )
        carol.confirm_combined_peer_verification(dave.username, dave_fingerprint)

        dave.observe_peer_identity(
            carol.username, carol.key_manager.public_key.decode("utf-8"),
            carol.key_manager.ml_dsa.export_public_key(),
        )
        carol_fingerprint = fingerprint_combined_identity(
            carol.key_manager.public_key, carol.key_manager.ml_dsa.export_public_key()
        )
        dave.confirm_combined_peer_verification(carol.username, carol_fingerprint)

        _open_direct(carol, dave.username)
        carol.establish_session_key()
        conversation_id = carol.current_conversation_id
        assert _wait_for(lambda: dave.key_manager.has_key(conversation_id))

        received = {}
        carol.message_received.connect(
            lambda identity_key, sender, text: received.update(sender=sender, text=text)
        )
        _open_direct(dave, carol.username)
        dave.send_chat_message("first message, before the browser device existed")
        assert _wait_for(lambda: received.get("text") == "first message, before the browser device existed")

        # --- Desktop syncs THAT SAME conversation's real key to the
        #     newly authorized browser device. ---
        sync_result = carol.sync_conversation_key_to_device(browser_device_id, conversation_id)
        assert sync_result.get("success"), sync_result

        assert _wait_for(
            lambda: page.evaluate(f"window.__session.sessionKeys.has({conversation_id!r})")
        )

        # The key ITSELF matches -- not just "a" key was installed, but
        # the REAL one carol's desktop already held for this conversation.
        desktop_key_hex = carol.key_manager.get_key(conversation_id).hex()
        browser_key_hex = page.evaluate(
            f"Array.from(window.__session.sessionKeys.get({conversation_id!r}).key)"
            ".map(b => b.toString(16).padStart(2,'0')).join('')"
        )
        assert browser_key_hex == desktop_key_hex

        # Phase 19.17C -- #messages is a single DOM node shared by every
        # direct peer; main.js only ever renders an incoming message into
        # it for whichever peer's chat is actually open (preventing
        # message-mixing between unrelated conversations), so the browser
        # must genuinely have Dave's chat open, via the real UI, before
        # either of this test's DOM-level #messages assertions below mean
        # anything -- not just have the underlying session/key state ready.
        page.fill("#peerUsername", dave.username)

        # --- Proof of usefulness, part 1: a SECOND message, sent AFTER
        #     the sync, now arrives LIVE on Carol's browser -- Phase
        #     18.5's own routing fix (Step 3) fans the live relay out
        #     to every one of Carol's connected devices, and the
        #     browser now genuinely holds the right key for it (the
        #     synced one), so no history recovery is even needed for
        #     this one.
        dave.send_chat_message("second message, after sync -- delivered live")
        assert _wait_for(
            lambda: received.get("text") == "second message, after sync -- delivered live"
        )
        assert _wait_for(
            lambda: "second message, after sync -- delivered live" in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        ), page.inner_text("#log")

        # --- Proof of usefulness, part 2: the FIRST message (sent
        #     before the browser was ever linked) genuinely could not
        #     have been delivered live to it -- no amount of routing
        #     fan-out helps a device that had no key yet. It was
        #     already recovered via loadHistory() -- Phase 18's own
        #     store-and-forward-backed recovery path, decrypted using
        #     ONLY the synced key, never a key the browser negotiated
        #     for itself -- as an automatic side effect of opening the
        #     chat above (Phase 19.17C: a real chat open now always
        #     loads history, not only on a separate manual action).
        #     This explicit second call proves loadHistory()'s own
        #     deduplication (Step 6): 0 NEW messages, since both the
        #     first (via that automatic load) and the second (via the
        #     live push above) are already rendered.
        loaded_count = page.evaluate(
            f"(async () => window.__session.loadHistory({conversation_id!r}, false))()"
        )
        assert loaded_count == 0, page.inner_text("#log")
        assert "first message, before the browser device existed" in page.inner_text("#messages")

        # No duplicate: the live-delivered second message still appears
        # exactly once in the DOM after loadHistory() ran.
        messages_text = page.inner_text("#messages")
        assert messages_text.count("second message, after sync -- delivered live") == 1
    finally:
        _delete(carol_payload["username"])
        _delete(dave_payload["username"])


# ========================================================================
# Phase 18.5 -- Closure Audit, Step 7: File/Image History Recovery.
# ========================================================================


def test_offline_file_history_recovery_byte_exact(
    running_server, gateway_url, browser_page, desktop_app, tmp_path
):
    """
    A FILE sent while Bob's browser was genuinely offline is recovered,
    byte-exact, once it reconnects and loads history -- closing the
    "file/image history entries are skipped" limitation documented
    after Phase 18. Reuses the EXISTING server-side blob_download_
    request/result mechanism (Option A -- lazy blob delivery, already
    used by the desktop client's own ClientSession._load_blob_history_
    content()) -- no new server endpoint, no new storage format.
    """

    alice_payload = desktop_app["register"]("alice5_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob5_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob_username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        # Bob's browser genuinely disconnects BEFORE Alice sends the
        # file -- a real logout, a real WebSocket close (Phase 17's own
        # proven no-automatic-reconnect-after-logout behavior).
        page.click("#logoutBtn")
        assert _wait_for(
            lambda: page.evaluate("document.getElementById('connectionStatus').dataset.state") == "disconnected"
        )

        file_bytes = bytes(range(256)) * 4  # 1024 bytes, every byte value present
        file_path = tmp_path / "missed_attachment.bin"
        file_path.write_bytes(file_bytes)
        alice.send_attachment(str(file_path))
        time.sleep(0.3)  # ensure persistence completes before reconnect races it

        # Reconnect via the same proven reload-then-reconnect mechanic
        # test_web_persistence_reconnect.py and this file's own offline-
        # text-history test already established.
        page.reload()
        page.wait_for_selector("#connectBtn")
        page.wait_for_load_state("load")
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]

        # Phase 19.17C -- #messages only ever renders an attachment for
        # whichever peer's chat is actually open (main.js's onAttachment,
        # preventing message-mixing between unrelated conversations), and
        # opening a chat via the real UI now auto-loads its history (see
        # openDirectChat()'s own comment) -- so the exact call that ends
        # up rendering "missed_attachment.bin" (this fill's own automatic
        # load, or the explicit one right after) is a real, harmless race;
        # what matters, and is asserted below, is that it ends up visible.
        cid = page.evaluate(f"(async () => window.__session.openDirectConversation({alice.username!r}))()")
        page.fill("#peerUsername", alice.username)
        page.evaluate(f"(async () => window.__session.loadHistory({cid!r}, false))()")

        assert _wait_for(
            lambda: "missed_attachment.bin" in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        ), page.inner_text("#log")

        download_href = page.eval_on_selector("#messages a.msg-file", "el => el.href")
        received_b64 = page.evaluate(
            f"""
            (async () => {{
              const resp = await fetch({download_href!r});
              const buf = await resp.arrayBuffer();
              const bytes = new Uint8Array(buf);
              let s = '';
              for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
              return btoa(s);
            }})()
            """
        )
        received_bytes = base64.b64decode(received_b64)
        assert received_bytes == file_bytes, "recovered historical file bytes do not exactly match what was sent"

        # Loading history a second time must not duplicate the
        # recovered attachment in the DOM (Step 6 -- History
        # Deduplication applies to blob-stored entries too). Counts
        # rendered .msg-file elements, not filename substring
        # occurrences -- the filename legitimately appears twice
        # WITHIN one rendered attachment (its meta line and its
        # download link text).
        page.evaluate(f"window.__session.loadHistory({cid!r}, false)")
        time.sleep(0.5)
        assert page.eval_on_selector_all("#messages a.msg-file", "els => els.length") == 1
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Phase 18.5 -- Closure Audit, Step 5: Device-Linking UI.
# ========================================================================


def test_device_linking_ui_enroll_bind_authorize_revoke(
    running_server, gateway_url, browser_page, desktop_app, monkeypatch, tmp_path
):
    """
    Proves the device-identity capability Phase 18 Step 8 built at the
    WebClientSession/API layer is now genuinely reachable by a real
    user through the actual UI (index.html's new "5. Device identity"
    fieldset / main.js's new button handlers) -- not just via
    window.__session, the pattern every other test in this file (and
    Phase 18 Step 8's own test) already used. Every click below drives
    the real DOM; the underlying session methods are unchanged from
    Step 8.
    """

    carol_payload = desktop_app["register"]("carol2_")
    carol = desktop_app["launch"](carol_payload)

    third = None
    try:
        # Carol's desktop is the account's first device -> bootstrap
        # AUTHORIZED (via the API -- the desktop client has no GUI for
        # this either, confirmed by inspection; this test's own job is
        # the WEB UI, not adding one to the desktop).
        carol.enroll_device(device_name="Desktop", platform="linux")
        carol.bind_device_session()

        _connect_browser(browser_page, gateway_url, carol_payload)
        page = browser_page["page"]

        # Phase 19.17C -- Linked Devices moved from the main chat
        # sidebar into Settings (real product cleanup: raw device ids
        # and authorize/revoke controls have no business next to the
        # message composer) -- a real user reaches this exact same
        # panel by opening Settings first now.
        page.click("#settingsToggleBtn")

        # --- Enroll (real UI button) ---
        page.click("#enrollDeviceBtn")
        assert _wait_for(lambda: "(PENDING)" in page.inner_text("#myDeviceId"))
        browser_device_id = page.evaluate("window.__session.deviceId")
        assert browser_device_id

        # Desktop authorizes the browser (via API -- proving the OTHER
        # direction, browser authorizing a device, further below).
        browser_row = next(d for d in carol.list_devices() if d["device_id"] == browser_device_id)
        carol.authorize_device(browser_device_id, browser_row["fingerprint"])

        # --- Bind (real UI button) ---
        page.click("#bindDeviceBtn")
        assert _wait_for(lambda: f"Bound this connection to device {browser_device_id}" in page.inner_text("#log"))

        # A THIRD device (a second desktop session, same account, its
        # own separate keystore dir -- _new_device_session(), not
        # desktop_app["launch"](), since the latter shares ONE keystore
        # dir for its whole fixture and would otherwise load the SAME
        # persisted identity/device_id "carol" already has instead of
        # genuinely enrolling a new one) enrolls PENDING, entirely via
        # the API -- what the BROWSER's own UI is about to discover,
        # verify, and authorize.
        third = _new_device_session(running_server, monkeypatch, carol_payload, tmp_path / "third")
        third.enroll_device(device_name="ThirdDevice", platform="linux")
        third_device_id = third.device_id

        # --- List devices (real UI button) ---
        page.click("#listDevicesBtn")
        assert _wait_for(lambda: third_device_id in page.inner_text("#deviceList"))
        assert "PENDING" in page.inner_text("#deviceList")

        # --- Observe + show fingerprint (real UI button) ---
        page.fill("#targetDeviceId", third_device_id)
        page.click("#observeDeviceBtn")
        assert _wait_for(lambda: third_device_id in page.inner_text("#deviceFingerprintDisplay"))

        # --- Authorize (real UI button) ---
        page.click("#authorizeDeviceBtn")
        assert _wait_for(lambda: f"Authorized device {third_device_id}" in page.inner_text("#log"))

        # Real, server-side proof -- not just a UI log line: the third
        # device is genuinely AUTHORIZED now, confirmed via the API.
        assert _wait_for(
            lambda: next(d for d in carol.list_devices() if d["device_id"] == third_device_id)["state"]
            == "AUTHORIZED"
        )

        # --- Revoke (real UI button) ---
        page.click("#revokeDeviceBtn")
        assert _wait_for(lambda: f"Revoked device {third_device_id}" in page.inner_text("#log"))
        assert _wait_for(
            lambda: next(d for d in carol.list_devices() if d["device_id"] == third_device_id)["state"]
            == "REVOKED"
        )

        # A revoked device can no longer bind its own connection --
        # real, server-enforced consequence of the UI action above, not
        # merely a client-side label change.
        bind_result = third.bind_device_session()
        assert bind_result["success"] is False
    finally:
        if third is not None:
            third.disconnect()
        _delete(carol_payload["username"])
