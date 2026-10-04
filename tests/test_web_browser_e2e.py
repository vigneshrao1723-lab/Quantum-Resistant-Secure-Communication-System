"""
Phase 15B -- Real Browser End-to-End Proof.

Phase 15 Stage 1 proved the web client's cryptography and the
gateway's transport bridging with real code, but used a Python
`websockets` client as a transport-level stand-in for the browser
itself (see docs/architecture/web_interoperability.md's "What was and
was not dynamically executed"). This file closes that gap: it launches
a REAL browser (Chromium, via Playwright, driving the system's
installed Google Chrome -- no Playwright-managed browser download was
needed or used) and executes the ACTUAL shipped
web/client/{index.html,main.js,app.js,protocol.js,crypto.js} files,
unmodified except for one race-condition fix and one unhandled-
rejection fix made during this phase's own audit (see this phase's
final report for exactly what and why).

Every step below drives the real page through its real UI (typing
into real form fields, clicking real buttons) except the security
negative tests, which call the same page's already-loaded, real
`window.__session` object's methods directly via Playwright's
`page.evaluate()` -- this is still the real, loaded browser JavaScript
executing its real verification logic, just invoked without first
building a dedicated "attack" button in the minimal UI (out of this
phase's own "smallest viable secure path" scope).

Run with:
    pytest tests/test_web_browser_e2e.py -v -s
"""

import asyncio
import http.server
import os
import socket
import threading
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from playwright.sync_api import sync_playwright
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
import web.gateway.gateway as gateway_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_combined_identity
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"
WEB_CLIENT_DIR = os.path.join(os.path.dirname(__file__), "..", "web", "client")


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Web Browser E2E Test",
            "username": f"webe2e_{hint}{suffix}",
            "email": f"webe2e_{hint}{suffix}@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete(username):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(username)
        if user is not None:
            for session in SessionRepository(db).get_active_sessions_for_user(user.id):
                db.delete(session)
            db.delete(user)
            db.commit()
    finally:
        db.close()


def _wait_for(predicate, attempts=300, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


def _open_direct(session, partner_username):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=None, username=partner_username,
            is_online=True, latest_message=None,
        )
    )


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


@pytest.fixture()
def gateway_url(running_server, monkeypatch):
    _state, server_port = running_server
    monkeypatch.setattr(gateway_module, "SERVER_PORT", server_port)

    port = _free_port()
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    stop_future = None

    def _run():
        nonlocal stop_future
        asyncio.set_event_loop(loop)

        async def _serve_and_signal():
            nonlocal stop_future
            stop_future = loop.create_future()
            import websockets
            async with websockets.serve(
                gateway_module.handle_browser_connection, "127.0.0.1", port,
                max_size=gateway_module.MAX_FRAME_BYTES,
            ):
                ready.set()
                await stop_future

        loop.run_until_complete(_serve_and_signal())

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    assert ready.wait(timeout=5), "gateway did not start"

    yield f"ws://127.0.0.1:{port}"

    loop.call_soon_threadsafe(lambda: stop_future.set_result(None))
    thread.join(timeout=5)


@pytest.fixture()
def static_url():
    port = _free_port()
    handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(
        *args, directory=WEB_CLIENT_DIR, **kwargs
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # ?debug=1 arms the developer log the normal production UI hides
    # (see main.js's own startup check) -- every test in this suite
    # still reads #log directly, exactly as before; only an ordinary
    # user visiting the plain URL never sees it.
    yield f"http://127.0.0.1:{port}/index.html?debug=1"
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture()
def desktop_app(running_server, monkeypatch, tmp_path):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", tmp_path / "keystore")

    opened = []
    created = []

    def _launch(payload):
        session = ClientSession()
        opened.append(session)
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

    def _register_fn(hint):
        payload = _register(hint)
        created.append(payload)
        return payload

    yield {"launch": _launch, "register": _register_fn}

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001
            pass
    for payload in created:
        _delete(payload["username"])


@pytest.fixture()
def browser_page(static_url):
    console_messages = []
    page_errors = []

    with sync_playwright() as p:
        # Phase 19.24 -- Voice/Video Messages: --use-fake-device-for-
        # media-stream/--use-fake-ui-for-media-stream are Chromium's own
        # standard flags for testing getUserMedia()/MediaRecorder in
        # headless automation -- a synthetic but genuinely functional
        # audio tone + video test pattern, with the permission prompt
        # auto-granted, so a real MediaRecorder pipeline (not a mock)
        # is exercised end to end. Inert for every other test in this
        # suite that never calls getUserMedia().
        browser = p.chromium.launch(
            channel="chrome", headless=True,
            args=["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"],
        )
        page = browser.new_page()
        page.context.grant_permissions(["microphone", "camera"])
        # index.html declares no favicon; Chrome's own automatic GET
        # /favicon.ico would otherwise 404 and be indistinguishable,
        # after the fact, from a real application console error --
        # short-circuited here at the source instead of filtered by
        # (unreliable) text matching afterward.
        page.route("**/favicon.ico", lambda route: route.fulfill(status=204, body=""))
        page.on("console", lambda msg: console_messages.append((msg.type, msg.text)))
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.goto(static_url)
        page.fill("#gatewayUrl", "")  # placeholder; real value set per-test before connecting
        yield {"page": page, "console": console_messages, "errors": page_errors}
        browser.close()


def _connect_browser(page_ctx, gateway_url, payload):
    page = page_ctx["page"]
    page.fill("#gatewayUrl", gateway_url)
    page.fill("#phoneNumber", payload["phone_number"])
    page.fill("#password", PASSWORD)
    page.click("#connectBtn")
    _wait_for(lambda: "Ready." in page.inner_text("#log"), attempts=200, interval=0.1)


# ========================================================================
# Steps 4-10: real browser application execution, real crypto, real
# identity exchange, real fingerprint verification, real session key
# establishment, real bidirectional encrypted messaging.
# ========================================================================


def test_real_browser_end_to_end_desktop_and_browser_messaging(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("alice_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob_")
    try:
        # --- Step 5: real browser login, through the real UI ---
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]

        log_text = page.inner_text("#log")
        assert "Connected and authenticated as" in log_text
        bob_username = bob_payload["username"]
        assert bob_username in log_text

        # --- Step 4/6: real browser crypto already ran inside
        # _sendPublicKey() (ML-KEM-768 + ML-DSA-65 keygen, real
        # signing) as part of connecting -- confirmed indirectly here
        # by Alice actually observing a real, well-formed announcement
        # from Bob below (a mock/absent keypair could not produce one
        # that verifies).
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)

        # --- Step 7: real fingerprint verification, via the real
        # browser UI (Bob observes Alice, compares, clicks confirm).
        page.fill("#peerUsername", alice.username)
        assert _wait_for(
            lambda: alice.username in page.inner_text("#fingerprintDisplay"),
            attempts=200, interval=0.1,
        )
        fingerprint_text = page.inner_text("#fingerprintDisplay")
        assert "UNVERIFIED" in fingerprint_text

        page.click("#confirmVerifiedBtn")
        assert _wait_for(lambda: "marked VERIFIED" in page.inner_text("#log"))

        # Alice's desktop side of Step 7: verify Bob back, using the
        # exact same production peer-identity API every other test
        # file in this suite already uses (see e.g. tests/
        # test_key_establishment_rejection_observability.py::
        # _verify_peer()). Bob's real, browser-generated public keys
        # are read directly off the real, running browser session --
        # not reconstructed or guessed -- via one page.evaluate() call.
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
        assert alice.get_peer_verification_state(bob_username) == "VERIFIED"

        # --- Step 8: real session key establishment, driven entirely
        # by the real browser button, real ML-KEM encapsulation, real
        # ML-DSA signature -- and the real, unmodified desktop
        # ClientSession.handle_group_key_distribution() installing it.
        page.click("#establishKeyBtn")
        assert _wait_for(lambda: "Session key established" in page.inner_text("#log"))

        # The browser itself is the authoritative source for which
        # conversation_id it just used (it resolved/created it via a
        # real direct_conversation_request round trip) -- read it back
        # from the real, running session rather than guessing at
        # Alice's own conversation_store bookkeeping, which has no
        # reason to have an entry yet (Alice hasn't sent anything, and
        # Bob's key delivery alone doesn't create one).
        conversation_id = page.evaluate("Array.from(window.__session.sessionKeys.keys())[0]")
        assert conversation_id, "browser session has no established conversation_id"
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id))

        # --- Step 9: Browser -> Desktop encrypted message ---
        # A TEXT message is emitted via message_received (identity_key,
        # sender, text -- all str), NOT payload_message_received (which
        # client/session.py::handle_chat() only emits for the binary/
        # file-or-image branch -- see that method's own code around the
        # PayloadType.TEXT check). Found by running this real test:
        # connecting to the wrong signal produced a silent, zero-error
        # non-delivery in the TEST ONLY, never in the real application
        # (Alice's log already showed genuine decryption succeeding).
        received = {}

        def _on_message(identity_key, sender, text):
            received["sender"] = sender
            received["text"] = text

        alice.message_received.connect(_on_message)

        page.fill("#messageText", "Hello from the browser")
        page.click("#sendBtn")

        assert _wait_for(lambda: received.get("text") == "Hello from the browser")
        assert received["sender"] == bob_username

        # --- Step 9 (reverse): Desktop -> Browser encrypted message ---
        _open_direct(alice, bob_username)
        alice.send_chat_message("Hello from desktop")

        assert _wait_for(
            lambda: "alice" in page.inner_text("#messages").lower()
            and "Hello from desktop" in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        )

        # --- Step 12: no unexplained console/page errors ---
        # (the one previously-observed, intentional exception --
        # Chrome's automatic GET /favicon.ico -- is short-circuited at
        # the source by the browser_page fixture's route handler, so
        # this assertion is a strict, no-exceptions check.)
        severe = [m for m in browser_page["console"] if m[0] == "error"]
        assert not browser_page["errors"], f"Uncaught page errors: {browser_page['errors']}"
        assert not severe, f"Console errors: {severe}"

    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Step 11: security negative tests, via the real, already-loaded
# browser session object (window.__session) -- still real browser
# JavaScript execution, not a Python bypass.
# ========================================================================


def test_real_browser_login_rejected_with_wrong_password(gateway_url, browser_page):
    payload = _register("carol_")
    try:
        page = browser_page["page"]
        page.fill("#gatewayUrl", gateway_url)
        page.fill("#phoneNumber", payload["phone_number"])
        page.fill("#password", "WrongPassword!123")
        page.click("#connectBtn")

        assert _wait_for(lambda: "ERROR" in page.inner_text("#log"))
        assert "Connected and authenticated" not in page.inner_text("#log")
    finally:
        _delete(payload["username"])


def test_real_browser_rejects_tampered_group_key_signature(gateway_url, browser_page):
    payload = _register("dave_")
    try:
        _connect_browser(browser_page, gateway_url, payload)
        page = browser_page["page"]

        # A forged group_key_distribution packet, claiming to be from
        # an unknown/unverified sender -- run through the REAL,
        # already-loaded browser session's REAL production method.
        result = page.evaluate(
            """
            () => {
              const before = window.__session.peers.size;
              window.__session._handleGroupKeyDistribution({
                type: "group_key_distribution",
                sender: "totally-unknown-attacker",
                recipient: window.__session.username,
                conversation_id: "fake-conversation-id",
                encapsulation: "AAAA",
                wrapped_key: "AAAA",
                epoch: 1,
                group_key_signature: "AAAA",
              });
              return { peersUnchanged: window.__session.peers.size === before };
            }
            """
        )
        assert result["peersUnchanged"] is True

        assert _wait_for(lambda: "Security warning" in page.inner_text("#securityWarning"))
    finally:
        _delete(payload["username"])
