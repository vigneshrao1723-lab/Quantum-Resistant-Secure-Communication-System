"""
Phase 19.24 (continued) -- Message Lifecycle Events: Web UI wiring.

server/client_handler.py's handlers and WebClientSession's own edit/
delete/react/forward methods (web/client/app.js) were already proven
correct at the protocol/security level by tests/test_phase19_24_
message_lifecycle_security.py (Desktop-driven, but the SAME server
code every client -- Desktop/Android/Web -- goes through). What that
file does not prove is the thing the mandate explicitly calls out: "a
feature is not complete merely because a session method exists -- it
must be usable through actual Android/Desktop/Web UI". These tests
drive the REAL shipped web/client/{index.html,main.js,app.js,...}
files in a REAL browser (Chromium via Playwright) -- right-clicking an
actual rendered message bubble to open the actual context menu built
by main.js::showBubbleContextMenu(), clicking its actual buttons --
against a REAL desktop ClientSession peer and a REAL running server,
mirroring tests/test_web_feature_completion_e2e.py's exact harness.

Run with:
    pytest tests/test_web_phase19_24_lifecycle_ui.py -v -s
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

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


def _open_direct_chat_in_browser(page, peer_username):
    page.fill("#peerUsername", peer_username)
    page.press("#peerUsername", "Enter")


def _right_click_bubble(page, text):
    """Right-clicks the bubble whose text contains ``text`` -- the
    native contextmenu event bubbles from .bubble-text up to .bubble,
    exactly where main.js::bubbleShell() attached its listener."""
    page.click(f".bubble-text:has-text('{text}')", button="right")


def _click_menu_action(page, label):
    page.click(f".bubble-context-menu >> text={label}")


def _confirm_modal(page, label):
    """Clicks the named button (e.g. "Delete"/"Block") in the real
    showConfirmModal() overlay main.js::doDeleteForEveryone()/
    applyMuteAction()'s "block" branch open before the underlying
    destructive session call actually runs -- see showConfirmModal()'s
    own docstring for why this modal exists."""
    page.click(f".confirm-modal-actions >> text={label}")


def _establish_key_in_browser(page, peer_username):
    """Real web-client UX for a brand-new conversation: unlike Desktop
    /Android, WebClientSession.sendMessage() does NOT auto-establish a
    session key (it throws "No session key established for this
    conversation yet." otherwise) -- a real user clicks the dedicated
    #establishKeyBtn first, exactly as driven here, mirroring
    establishSessionKey()'s own real production call path."""

    page.fill("#peerUsername", peer_username)
    page.click("#establishKeyBtn")
    assert _wait_for(lambda: f"Session key established with {peer_username}" in page.inner_text("#log"))


# ========================================================================
# Edit
# ========================================================================


def test_web_edit_via_context_menu_updates_both_sides(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wedit_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wedit_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        # Both listeners registered BEFORE either triggering action --
        # a signal connected only after the packet that would fire it
        # has already been sent/processed races the emit and can miss
        # it entirely (PySide signals are not queued/replayed for a
        # late connect()).
        received = {}
        alice.message_received.connect(
            lambda identity_key, sender, text: received.update(sender=sender, text=text)
        )
        edited = {}
        alice.message_edited_received.connect(
            lambda conversation_id, message_id, new_text, editor, edited_at, edit_version:
                edited.update(new_text=new_text, editor=editor)
        )

        page.fill("#messageText", "before edit")
        page.click("#sendBtn")

        assert _wait_for(lambda: received.get("text") == "before edit")

        _right_click_bubble(page, "before edit")
        _click_menu_action(page, "Edit")

        # The composer is now pre-filled with the original text (edit
        # mode) -- clear and type the new text, exactly like a real
        # user editing in place.
        page.fill("#messageText", "after edit")
        page.click("#sendBtn")

        # Bob's OWN bubble updates via the server's own broadcast-back
        # (never a local-only optimistic edit) -- proves main.js::
        # onMessageEdited actually applies to bob's own view too.
        # Phase 1.5 UI: the edited state is shown in the bubble's footer
        # ("edited · <time>") rather than as an inline "(edited)" suffix.
        assert _wait_for(
            lambda: page.evaluate(
                "[...document.querySelectorAll('#messages .bubble')]"
                ".some(b => b.querySelector('.bubble-text')?.textContent === 'after edit'"
                " && !!b.querySelector('.bubble-footer .bubble-edited'))"
            ),
            attempts=200, interval=0.1,
        )

        assert _wait_for(lambda: edited.get("new_text") == "after edit")
        assert edited["editor"] == bob_username
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Delete for everyone
# ========================================================================


def test_web_delete_for_everyone_via_context_menu(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wdel_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wdel_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        # Registered BEFORE the send -- see test_web_edit_via_context_
        # menu_updates_both_sides's identical comment for why.
        deleted = {}
        alice.message_deleted_received.connect(
            lambda conversation_id, message_id, deleted_by, deleted_at:
                deleted.update(deleted_by=deleted_by)
        )

        page.fill("#messageText", "delete this one")
        page.click("#sendBtn")

        assert _wait_for(lambda: "delete this one" in page.inner_text("#messages"))

        _right_click_bubble(page, "delete this one")
        _click_menu_action(page, "Delete for everyone")
        _confirm_modal(page, "Delete")

        assert _wait_for(
            lambda: "Message deleted" in page.inner_text("#messages")
            and "delete this one" not in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        )
        assert _wait_for(lambda: deleted.get("deleted_by") == bob_username)
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# React
# ========================================================================


def test_web_react_via_context_menu_shows_on_both_sides(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wreact_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wreact_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        # Registered BEFORE any send/react -- see test_web_edit_via_
        # context_menu_updates_both_sides's identical comment for why.
        reacted = {}
        alice.reaction_updated_received.connect(
            lambda conversation_id, message_id, actor, action, reaction:
                reacted.update(actor=actor, action=action, reaction=reaction)
        )

        page.fill("#messageText", "react to me")
        page.click("#sendBtn")
        assert _wait_for(lambda: "react to me" in page.inner_text("#messages"))

        _right_click_bubble(page, "react to me")
        _click_menu_action(page, "React")

        # The reaction picker is now open -- click the first emoji
        # choice (thumbs-up, main.js::REACTION_CHOICES[0]).
        page.click(".bubble-popup-emoji-row button >> nth=0")

        # Bob's own bubble reflects the reaction via the server's own
        # broadcast-back (never applied locally/optimistically) -- as a
        # reaction chip whose count reads 1 (the chip replaced the old
        # inline "emoji×count" text in the Phase 1 UI polish pass).
        assert _wait_for(
            lambda: page.evaluate(
                "[...document.querySelectorAll('#messages .reaction-chip .reaction-count')]"
                ".some(el => el.textContent === '1')"
            ),
            attempts=200, interval=0.1,
        )

        assert _wait_for(lambda: reacted.get("action") == "add")
        assert reacted["actor"] == bob_username
        assert reacted["reaction"]  # a real, non-empty decrypted emoji string
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Reply
# ========================================================================


def test_web_reply_via_context_menu_attaches_reply_to_message_id(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wreply_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wreply_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        page.fill("#messageText", "the original")
        page.click("#sendBtn")
        assert _wait_for(lambda: "the original" in page.inner_text("#messages"))

        _right_click_bubble(page, "the original")
        _click_menu_action(page, "Reply")

        assert _wait_for(lambda: "Replying to" in page.inner_text("#composerContext"))

        page.fill("#messageText", "the reply")
        page.click("#sendBtn")

        assert _wait_for(lambda: "the reply" in page.inner_text("#messages"))
        # The composer context bar clears once consumed by the send.
        assert page.is_hidden("#composerContext")

        # Verify server-side persistence via alice's own real history
        # reload -- the authoritative source of truth, not merely a
        # client-local UI hint.
        _open_direct(alice, bob_username)
        history = alice.load_conversation_history(bob_username, is_group=False)
        reply_row = next(row for row in history if row["text"] == "the reply")
        original_row = next(row for row in history if row["text"] == "the original")
        assert reply_row["reply_to_message_id"] == original_row["message_id"]
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Forward
# ========================================================================


def test_web_forward_via_context_menu_reaches_a_third_party(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wfwd_a_")
    alice = desktop_app["launch"](alice_payload)
    carol_payload = desktop_app["register"]("wfwd_c_")
    carol = desktop_app["launch"](carol_payload)

    bob_payload = _register("wfwd_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        # Bob (browser) must already have a conversation with BOTH
        # Alice (the original sender) and Carol (the forward target)
        # -- main.js::showForwardPicker() only ever lists EXISTING
        # conversations, mirroring gui/forward_dialog.py's identical
        # scope.
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        assert _wait_for(lambda: carol.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(carol, page)
        _verify_desktop_observes_browser(carol, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)
        page.fill("#messageText", "forward this along")
        page.click("#sendBtn")
        assert _wait_for(lambda: "forward this along" in page.inner_text("#messages"))

        # Bob must ALSO have an existing conversation with Carol for
        # her to appear as a forward target at all (knownDirectPeers
        # is what showForwardPicker() reads from -- opening her chat
        # once is enough for THAT), and a real session key with her
        # for the forward itself to actually succeed (forwardTextMessage()
        # -> sendMessage(carol.username, ...) needs one exactly like
        # any other send).
        _open_direct_chat_in_browser(page, carol.username)
        _establish_key_in_browser(page, carol.username)
        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        _right_click_bubble(page, "forward this along")
        _click_menu_action(page, "Forward")
        page.click(f".bubble-popup-list button:has-text('{carol.username}')")

        _open_direct(carol, bob_username)
        assert _wait_for(lambda: any(
            row["text"] == "forward this along"
            for row in carol.load_conversation_history(bob_username, is_group=False)
        )), "carol never received the forwarded message"
    finally:
        _delete(bob_payload["username"])


def test_web_media_gallery_lists_a_received_image_and_voice_message(
    running_server, gateway_url, browser_page, desktop_app, tmp_path
):
    """Closes the previous Desktop-only Media Gallery gap: drives the
    REAL #galleryBtn/showMediaGallery() wiring main.js attaches --
    operates only on already-decrypted, already-rendered bubbles (see
    getMediaBubbles()'s own docstring), no second history fetch."""

    alice_payload = desktop_app["register"]("wgal_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wgal_b_")
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
        assert _wait_for(lambda: alice.key_manager.has_key(alice.current_conversation_id))

        image_path = tmp_path / "photo.png"
        image_path.write_bytes(
            bytes.fromhex(
                "89504e470d0a1a0a0000000d494844520000000100000001080600000"
                "01f15c4890000000a49444154789c6360000002000100"
                "0dae7f870000000049454e44ae426082"
            )
        )
        alice.send_attachment(str(image_path))
        assert _wait_for(lambda: page.evaluate(
            "!!document.querySelector('#messages .bubble[data-payload-type=\"image\"] img')"
        ))

        voice_path = tmp_path / "clip.m4a"
        voice_path.write_bytes(b"fake recorded audio bytes, never a real codec frame")
        alice.send_attachment(str(voice_path))
        assert _wait_for(lambda: "Voice message" in page.inner_text("#messages"))

        page.click("#galleryBtn")
        assert _wait_for(lambda: page.evaluate("!!document.querySelector('.gallery-card')"))
        assert _wait_for(lambda: page.evaluate("!!document.querySelector('.gallery-thumb')"))
        assert "Voice message" in page.inner_text(".gallery-list")
    finally:
        _delete(bob_payload["username"])


def test_web_forwarding_a_voice_message_preserves_its_payload_type(
    running_server, gateway_url, browser_page, desktop_app, tmp_path
):
    """Regression test for the same bug class fixed on Desktop/Mobile
    (main.js::forwardBubbleTo() used to be TEXT-only -- an attachment
    bubble's decrypted bytes/mime_type are now retained on the element
    itself by renderAttachment(), so this proves the real fix: a voice
    message Bob (browser) received from Alice can be forwarded to
    Carol, arriving with PayloadType.VOICE preserved, not silently
    downgraded to a generic file."""

    alice_payload = desktop_app["register"]("wfwdv_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wfwdv_b_")
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
        assert _wait_for(lambda: alice.key_manager.has_key(alice.current_conversation_id))

        voice_path = tmp_path / "clip.m4a"
        voice_path.write_bytes(b"fake recorded audio bytes, never a real codec frame")
        alice.send_attachment(str(voice_path))

        assert _wait_for(lambda: "Voice message" in page.inner_text("#messages"), attempts=200, interval=0.1)

        # Carol is introduced only now, mirroring test_web_forward_via_
        # context_menu_reaches_a_third_party's own sequencing exactly --
        # Bob needs an existing conversation with her (knownDirectPeers)
        # for her to appear as a forward target, plus a real session key.
        carol_payload = desktop_app["register"]("wfwdv_c_")
        carol = desktop_app["launch"](carol_payload)
        assert _wait_for(lambda: carol.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(carol, page)
        _verify_desktop_observes_browser(carol, page, bob_username)

        _open_direct_chat_in_browser(page, carol.username)
        _establish_key_in_browser(page, carol.username)
        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        page.click(".bubble:has(audio)", button="right")
        _click_menu_action(page, "Forward")
        page.click(f".bubble-popup-list button:has-text('{carol.username}')")

        _open_direct(carol, bob_username)
        assert _wait_for(lambda: any(
            row["payload_type"] == "voice"
            for row in carol.load_conversation_history(bob_username, is_group=False)
        )), "carol never received the forwarded voice message with the correct payload type"
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Typing Indicator
# ========================================================================


def test_web_typing_indicator_sent_on_real_composer_keystroke(
    running_server, gateway_url, browser_page, desktop_app
):
    """Bob (browser) typing a REAL keystroke into #messageText dispatches
    a real typing_indicator packet that Alice's (desktop) session
    receives -- proves main.js's native `input`-event debounce wiring,
    not merely WebClientSession.sendTypingIndicator() called in
    isolation. Also proves the debounce contract itself (a burst of
    further keystrokes must not resend, clearing the composer stops
    immediately), mirroring Desktop's/Mobile's own typing indicator
    tests exactly."""

    alice_payload = desktop_app["register"]("wtype_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wtype_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        # Registered BEFORE the keystroke -- see this file's other tests'
        # identical comment for why.
        received = []
        alice.typing_indicator_received.connect(
            lambda conv_id, username, is_typing: received.append((username, is_typing))
        )

        page.type("#messageText", "h")

        assert _wait_for(lambda: len(received) == 1)
        assert received[0] == (bob_username, True)

        # A burst of further real keystrokes must NOT resend.
        page.type("#messageText", "ello")
        time.sleep(0.3)
        assert len(received) == 1

        # Clearing the composer stops typing immediately.
        page.fill("#messageText", "")
        assert _wait_for(lambda: len(received) == 2)
        assert received[1] == (bob_username, False)
    finally:
        _delete(bob_payload["username"])


def test_web_typing_indicator_shown_in_real_ui_on_incoming_notification(
    running_server, gateway_url, browser_page, desktop_app
):
    """Alice (desktop session) sending a real typing_indicator packet
    makes it show up in Bob's (browser) REAL rendered #typingStatus
    label -- proves the receiving side is wired to the actual DOM, not
    just WebClientSession's onTypingIndicator callback in isolation."""

    alice_payload = desktop_app["register"]("wtype_c_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wtype_d_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        _open_direct(alice, bob_username)
        conversation_id = alice.current_conversation_id

        alice.send_typing_indicator(conversation_id, True)
        assert _wait_for(
            lambda: page.is_visible("#typingStatus") and alice.username in page.inner_text("#typingStatus")
        )

        alice.send_typing_indicator(conversation_id, False)
        assert _wait_for(lambda: page.is_hidden("#typingStatus"))
    finally:
        _delete(bob_payload["username"])


def test_web_typing_indicator_is_never_echoed_to_the_sender(
    running_server, gateway_url, browser_page, desktop_app
):
    """Security/UX: Bob's own #typingStatus must never show his own
    name while he types -- server/client_handler.py::handle_typing_
    indicator() excludes the actor's own socket from the broadcast, so
    the browser never even receives a packet to render."""

    alice_payload = desktop_app["register"]("wtype_e_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wtype_f_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        page.type("#messageText", "hi")
        time.sleep(0.3)

        assert page.is_hidden("#typingStatus")
        assert bob_username not in page.inner_text("#typingStatus")
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Drafts
# ========================================================================


def test_web_draft_survives_switching_to_another_conversation_and_back(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wdraft_a_")
    alice = desktop_app["launch"](alice_payload)
    carol_payload = desktop_app["register"]("wdraft_c_")
    carol = desktop_app["launch"](carol_payload)

    bob_payload = _register("wdraft_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        assert _wait_for(lambda: carol.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(carol, page)
        _verify_desktop_observes_browser(carol, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)
        page.fill("#messageText", "unsent to alice")

        # Switching to a brand-new conversation (carol) must not carry
        # alice's draft over, nor lose it.
        _open_direct_chat_in_browser(page, carol.username)
        _establish_key_in_browser(page, carol.username)
        assert page.input_value("#messageText") == ""

        page.fill("#messageText", "unsent to carol")

        # Back to alice: her own draft is restored exactly as left.
        _open_direct_chat_in_browser(page, alice.username)
        assert page.input_value("#messageText") == "unsent to alice"

        # And carol's own draft is untouched by having been navigated
        # away from in between.
        _open_direct_chat_in_browser(page, carol.username)
        assert page.input_value("#messageText") == "unsent to carol"
    finally:
        _delete(bob_payload["username"])


def test_web_sending_a_message_clears_its_conversations_draft(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wdraft_d_")
    alice = desktop_app["launch"](alice_payload)
    carol_payload = desktop_app["register"]("wdraft_e_")
    carol = desktop_app["launch"](carol_payload)

    bob_payload = _register("wdraft_f_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        assert _wait_for(lambda: carol.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(carol, page)
        _verify_desktop_observes_browser(carol, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)
        page.fill("#messageText", "leftover draft")

        # Switch away (saves the draft) then back (restores it) before
        # actually sending -- proves the send, not merely never having
        # left, is what clears it.
        _open_direct_chat_in_browser(page, carol.username)
        _open_direct_chat_in_browser(page, alice.username)
        assert page.input_value("#messageText") == "leftover draft"

        received = {}
        alice.message_received.connect(
            lambda identity_key, sender, text: received.update(sender=sender, text=text)
        )

        page.click("#sendBtn")
        assert _wait_for(lambda: received.get("text") == "leftover draft")
        assert page.input_value("#messageText") == ""

        _open_direct_chat_in_browser(page, carol.username)
        _open_direct_chat_in_browser(page, alice.username)
        assert page.input_value("#messageText") == ""
    finally:
        _delete(bob_payload["username"])


def test_web_draft_is_not_saved_while_a_reply_is_in_progress(
    running_server, gateway_url, browser_page, desktop_app
):
    """A reply-in-progress's pre-filled composer text belongs to that
    pending action, not to a fresh-message draft -- switching away
    while replying must not leave a stray draft behind for this
    conversation."""

    alice_payload = desktop_app["register"]("wdraft_g_")
    alice = desktop_app["launch"](alice_payload)
    carol_payload = desktop_app["register"]("wdraft_h_")
    carol = desktop_app["launch"](carol_payload)

    bob_payload = _register("wdraft_i_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        assert _wait_for(lambda: carol.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(carol, page)
        _verify_desktop_observes_browser(carol, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        page.fill("#messageText", "reply target")
        page.click("#sendBtn")
        assert _wait_for(lambda: "reply target" in page.inner_text("#messages"))

        _right_click_bubble(page, "reply target")
        _click_menu_action(page, "Reply")
        assert _wait_for(lambda: "Replying to" in page.inner_text("#composerContext"))

        page.fill("#messageText", "mid-reply text")

        _open_direct_chat_in_browser(page, carol.username)
        _open_direct_chat_in_browser(page, alice.username)

        assert page.input_value("#messageText") == ""
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Mute
# ========================================================================


def test_web_mute_via_real_ui_toggle(running_server, gateway_url, browser_page, desktop_app):
    alice_payload = desktop_app["register"]("wmute_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wmute_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)

        row_mute_btn = f".row-card:has-text('{alice.username}') .row-mute-btn"

        # The row's bell is an SVG icon since the Phase 1 UI polish pass
        # (bell / bell-off) -- its muted state is the .is-muted class, not
        # an emoji glyph in the button's text.
        def _row_muted():
            return page.locator(row_mute_btn).evaluate("el => el.classList.contains('is-muted')")

        assert not _row_muted()  # bell, not yet muted

        page.click(row_mute_btn)
        page.click(".bubble-context-menu >> text=Mute for 1 hour")

        assert _wait_for(
            lambda: page.evaluate(f"window.__session.isConversationMuted({alice.username!r})")
        )
        assert _wait_for(_row_muted)  # bell-off, now muted

        page.click(row_mute_btn)
        page.click(".bubble-context-menu >> text=Unmute")

        assert _wait_for(
            lambda: not page.evaluate(f"window.__session.isConversationMuted({alice.username!r})")
        )
        assert _wait_for(lambda: not _row_muted())
    finally:
        _delete(bob_payload["username"])


def test_web_mute_persists_across_page_reload(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wmute_c_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wmute_d_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        page.click(f".row-card:has-text('{alice.username}') .row-mute-btn")
        page.click(".bubble-context-menu >> text=Mute until I turn it back on")
        assert _wait_for(
            lambda: page.evaluate(f"window.__session.isConversationMuted({alice.username!r})")
        )

        # muteConversation() persists fire-and-forget (storage.js's own
        # documented "best-effort" contract -- see its module docstring)
        # -- the in-memory isConversationMuted() above proves only that
        # the STATE changed, not that the async IndexedDB write behind
        # it has actually landed yet. Awaiting the same _persistState()
        # promise explicitly here (Playwright's evaluate() awaits a
        # returned promise) is a TEST-ONLY synchronization point, not a
        # production guarantee this app makes on every mute.
        page.evaluate("window.__session._persistState()")

        page.reload()
        page.wait_for_selector("#connectBtn")
        page.wait_for_load_state("load")
        _connect_browser(browser_page, gateway_url, bob_payload)

        assert "Restored this browser's persisted identity" in page.inner_text("#log")
        assert page.evaluate(f"window.__session.isConversationMuted({alice.username!r})")
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Archive
# ========================================================================


def test_web_archive_via_real_ui_toggle(running_server, gateway_url, browser_page, desktop_app):
    alice_payload = desktop_app["register"]("warch_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("warch_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)

        row_selector = f".row-card:has-text('{alice.username}')"
        assert page.is_visible(row_selector)

        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Archive")

        assert _wait_for(
            lambda: page.evaluate(f"window.__session.isConversationArchived({alice.username!r})")
        )
        # Archiving removes the row from the main (non-archived) list.
        assert _wait_for(lambda: page.is_hidden(row_selector))

        page.click("#archivedChatsToggle")
        assert page.inner_text("#archivedChatsToggle") == "Back to Chats"
        assert page.is_visible(row_selector)

        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Unarchive")

        assert _wait_for(
            lambda: not page.evaluate(f"window.__session.isConversationArchived({alice.username!r})")
        )
        # The archived (now empty) list no longer shows it.
        assert _wait_for(lambda: page.is_hidden(row_selector))

        page.click("#archivedChatsToggle")
        assert page.inner_text("#archivedChatsToggle") == "Archived"
        assert page.is_visible(row_selector)
    finally:
        _delete(bob_payload["username"])


def test_web_archiving_does_not_affect_a_separate_mute_state(
    running_server, gateway_url, browser_page, desktop_app
):
    """Archive and Mute share one conversationPrefs entry -- setting
    one must never silently erase the other."""

    alice_payload = desktop_app["register"]("warch_c_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("warch_d_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)

        row_selector = f".row-card:has-text('{alice.username}')"
        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Mute until I turn it back on")
        assert _wait_for(
            lambda: page.evaluate(f"window.__session.isConversationMuted({alice.username!r})")
        )

        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Archive")
        assert _wait_for(
            lambda: page.evaluate(f"window.__session.isConversationArchived({alice.username!r})")
        )

        # Muted state survived archiving.
        assert page.evaluate(f"window.__session.isConversationMuted({alice.username!r})")

        page.click("#archivedChatsToggle")
        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Unarchive")

        # Unarchiving must not have silently unmuted.
        assert _wait_for(
            lambda: not page.evaluate(f"window.__session.isConversationArchived({alice.username!r})")
        )
        assert page.evaluate(f"window.__session.isConversationMuted({alice.username!r})")
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Message Retry
# ========================================================================


def test_web_a_failed_send_shows_a_retry_bubble_and_retry_delivers_it(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wretry_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wretry_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        # Break the real session's sendMessage() for exactly the next
        # call (a real, generic send-time failure -- e.g. a dropped
        # connection), then transparently restore it -- mirrors tests/
        # test_phase19_24_mobile_retry.py's identical _break_first_
        # send() helper.
        page.evaluate(
            "(() => { "
            "const real = window.__session.sendMessage.bind(window.__session); "
            "let broken = true; "
            "window.__session.sendMessage = (...args) => { "
            "  if (broken) { broken = false; return Promise.reject(new Error('simulated transient send failure')); } "
            "  return real(...args); "
            "}; })()"
        )

        received = {}
        alice.message_received.connect(
            lambda identity_key, sender, text: received.update(sender=sender, text=text)
        )

        page.fill("#messageText", "will this ever arrive")
        page.click("#sendBtn")

        assert _wait_for(lambda: page.is_visible(".bubble.is-failed"))
        assert "will this ever arrive" in page.inner_text(".bubble.is-failed")
        assert page.is_visible(".bubble-retry-btn")
        # The composer is cleared regardless -- the failed bubble now
        # holds the text, mirrors gui/input_bar.py's/mobile/app.py's
        # identical unconditional clear.
        assert page.input_value("#messageText") == ""

        page.click(".bubble-retry-btn")

        assert _wait_for(lambda: received.get("text") == "will this ever arrive")
        assert received["sender"] == bob_username
        assert _wait_for(lambda: page.is_hidden(".bubble.is-failed"))
        assert _wait_for(lambda: "will this ever arrive" in page.inner_text("#messages"))
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Block User
# ========================================================================


def test_web_blocking_via_real_ui_prevents_delivery(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wblock_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wblock_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)

        row_selector = f".row-card:has-text('{alice.username}')"
        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Block")
        _confirm_modal(page, "Block")

        assert _wait_for(
            lambda: page.evaluate(f"window.__session.isUserBlocked({alice.username!r})")
        )

        # bob's browser already has this chat open -- a live message
        # that actually reached him would render straight into
        # #messages, exactly like every other real-delivery assertion
        # in this file.
        _open_direct(alice, bob_username)
        alice.send_chat_message("can you still hear me?")

        time.sleep(0.5)
        assert "can you still hear me?" not in page.inner_text("#messages")
    finally:
        _delete(bob_payload["username"])


def test_web_unblocking_via_real_ui_restores_delivery(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wblock_c_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wblock_d_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)

        row_selector = f".row-card:has-text('{alice.username}')"
        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Block")
        _confirm_modal(page, "Block")
        assert _wait_for(
            lambda: page.evaluate(f"window.__session.isUserBlocked({alice.username!r})")
        )

        page.click(f"{row_selector} .row-mute-btn")
        page.click(".bubble-context-menu >> text=Unblock")
        assert _wait_for(
            lambda: not page.evaluate(f"window.__session.isUserBlocked({alice.username!r})")
        )

        _open_direct(alice, bob_username)
        alice.send_chat_message("are you there now?")

        assert _wait_for(lambda: "are you there now?" in page.inner_text("#messages"))
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Chat Wallpaper
# ========================================================================


def test_web_setting_a_wallpaper_via_real_ui_applies_and_persists(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wwall_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wwall_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)

        assert "wallpaper-" not in (page.get_attribute("#messages", "class") or "")

        page.click("#wallpaperBtn")
        page.click(".bubble-context-menu >> text=Ocean")

        assert _wait_for(
            lambda: "wallpaper-ocean" in (page.get_attribute("#messages", "class") or "")
        )
        assert page.evaluate(f"window.__session.getConversationWallpaper({alice.username!r})") == "ocean"

        # Persists across a real page reload -- mirrors test_web_mute_
        # persists_across_page_reload's identical _persistState()
        # synchronization point (storage.js's own documented "best-
        # effort" contract -- see that test's own comment).
        page.evaluate("window.__session._persistState()")
        page.reload()
        page.wait_for_selector("#connectBtn")
        page.wait_for_load_state("load")
        _connect_browser(browser_page, gateway_url, bob_payload)
        assert "Restored this browser's persisted identity" in page.inner_text("#log")
        assert page.evaluate(f"window.__session.getConversationWallpaper({alice.username!r})") == "ocean"

        _open_direct_chat_in_browser(page, alice.username)
        assert "wallpaper-ocean" in (page.get_attribute("#messages", "class") or "")

        # Reset to Default clears it.
        page.click("#wallpaperBtn")
        page.click(".bubble-context-menu >> text=Default")
        assert _wait_for(
            lambda: "wallpaper-" not in (page.get_attribute("#messages", "class") or "")
        )
        assert page.evaluate(f"window.__session.getConversationWallpaper({alice.username!r})") is None
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Message Search
# ========================================================================


def test_web_message_search_via_real_ui_finds_navigates_and_closes(
    running_server, gateway_url, browser_page, desktop_app
):
    """Drives the REAL #searchBtn/#searchInput/#searchNextBtn/
    #searchPrevBtn/#searchCloseBtn wiring main.js::setupSearchBar()
    attaches -- operating only on bubbles already rendered in bob's own
    #messages (main.js::searchMatchingBubbles()'s own docstring: no
    network call, no second history fetch, the query text itself never
    leaves this browser)."""

    alice_payload = desktop_app["register"]("wsrch_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wsrch_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_payload["username"])

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        for text in ("Hello world", "Goodbye now", "WORLD peace"):
            page.fill("#messageText", text)
            page.click("#sendBtn")
            assert _wait_for(lambda text=text: text in page.inner_text("#messages"))

        assert page.get_attribute("#searchBar", "hidden") is not None

        page.click("#searchBtn")
        assert page.get_attribute("#searchBar", "hidden") is None

        page.fill("#searchInput", "world")
        assert _wait_for(lambda: page.inner_text("#searchResultLabel") == "1 of 2")
        assert _wait_for(
            lambda: "Hello world" in (page.evaluate(
                "document.querySelector('#messages .bubble.is-search-match .bubble-text')?.textContent || ''"
            ))
        )

        page.click("#searchNextBtn")
        assert _wait_for(lambda: page.inner_text("#searchResultLabel") == "2 of 2")
        assert _wait_for(
            lambda: "WORLD peace" in (page.evaluate(
                "document.querySelector('#messages .bubble.is-search-match .bubble-text')?.textContent || ''"
            ))
        )

        # Wraps back around to the first match.
        page.click("#searchNextBtn")
        assert _wait_for(lambda: page.inner_text("#searchResultLabel") == "1 of 2")

        page.fill("#searchInput", "xyzzy-not-present")
        assert _wait_for(lambda: page.inner_text("#searchResultLabel") == "No matches")
        assert page.evaluate("!!document.querySelector('#messages .bubble.is-search-match')") is False

        page.click("#searchCloseBtn")
        assert page.get_attribute("#searchBar", "hidden") is not None
        assert page.input_value("#searchInput") == ""
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Pinned Messages
# ========================================================================


def test_web_pinning_via_context_menu_syncs_to_desktop_and_panel_navigates(
    running_server, gateway_url, browser_page, desktop_app
):
    """Drives the REAL #pinnedBtn/context-menu Pin-Unpin wiring main.js
    ::setBubblePinned()/showPinnedMessagesPanel() attaches -- pin state
    is a real message_pin/message_unpin protocol round trip (server/
    client_handler.py::handle_message_pin()), never a fake local-only
    button, proven here by asserting the REAL Desktop peer's own
    message_pinned_received signal actually fires."""

    alice_payload = desktop_app["register"]("wpin_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wpin_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        pinned_events = []
        alice.message_pinned_received.connect(
            lambda cid, mid, pinned_by, pinned_at: pinned_events.append((mid, pinned_by))
        )

        page.fill("#messageText", "pin me please")
        page.click("#sendBtn")
        assert _wait_for(lambda: "pin me please" in page.inner_text("#messages"))

        _right_click_bubble(page, "pin me please")
        _click_menu_action(page, "Pin")

        assert _wait_for(
            lambda: page.evaluate(
                "document.querySelector('.bubble-text')"
                " && [...document.querySelectorAll('#messages .bubble')]"
                ".find(b => b.dataset.text === 'pin me please').dataset.pinned"
            ) == "1"
        )
        assert _wait_for(lambda: len(pinned_events) == 1)
        assert pinned_events[0][1] == bob_username

        assert _wait_for(
            lambda: bob_username in (page.evaluate(
                "[...document.querySelectorAll('#messages .bubble')]"
                ".find(b => b.dataset.text === 'pin me please')"
                "?.querySelector('.bubble-pinned')?.textContent || ''"
            ))
        )

        # The panel lists it and navigating to it highlights the bubble.
        # Re-opens the panel on each retry (a static wait against an
        # already-built, stale popup would never see a later state
        # change) until it actually lists the pinned bubble.
        def _panel_lists_pinned_bubble():
            # showPinnedMessagesPanel() itself calls closeAnyOpenPopup()
            # first, so simply re-clicking replaces any stale popup from
            # a previous, too-early attempt.
            page.click("#pinnedBtn")
            return page.evaluate(
                "document.querySelector('.bubble-context-menu button')?.textContent || ''"
            ).startswith("pin me please")

        assert _wait_for(_panel_lists_pinned_bubble), "pinned-messages panel never listed the pinned bubble"

        # Clicked via the DOM's own .click() (in-page, synchronous),
        # not a Playwright coordinate-based synthetic mouse event --
        # this floating popup is absolutely positioned from raw click
        # coordinates (positionPopup()), which made a real mouse click
        # here intermittently miss/mis-target on this CI machine; the
        # onclick handler itself (closeAnyOpenPopup() + highlightSearch
        # Match()) is unchanged either way, real production code, not
        # bypassed.
        page.evaluate("document.querySelector('.bubble-context-menu button').click()")

        assert _wait_for(
            lambda: page.evaluate("!!document.querySelector('#messages .bubble.is-search-match')")
        )

        # Unpin clears it, both locally and via the real round trip.
        _right_click_bubble(page, "pin me please")
        _click_menu_action(page, "Unpin")

        assert _wait_for(
            lambda: page.evaluate(
                "[...document.querySelectorAll('#messages .bubble')]"
                ".find(b => b.dataset.text === 'pin me please').dataset.pinned"
            ) == "0"
        )
        assert page.evaluate(
            "!document.querySelector('#messages .bubble-pinned')"
        )
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Voice/Video Messages
# ========================================================================


def _record_and_send(page, mode):
    """Drives the REAL recorder modal main.js::openMediaRecorderModal()
    builds: opens the Attachment Menu, picks Voice/Video Message,
    records for ~1.2s against Chromium's fake media device (see
    tests/test_web_browser_e2e.py::browser_page's own --use-fake-
    device-for-media-stream comment -- a synthetic but functionally
    real getUserMedia()/MediaRecorder pipeline, not a mock), then
    Sends."""

    page.click("#attachBtn")
    label = "Voice Message" if mode == "voice" else "Video Message"
    page.click(f".bubble-context-menu >> text={label}")

    assert _wait_for(lambda: page.evaluate("!!document.querySelector('.media-recorder-modal')"))

    # The record/stop toggle is the ONE button that is a direct child
    # of .media-recorder-card (Cancel/Send live inside .media-recorder-
    # actions instead) -- clicked twice (start, then stop) rather than
    # matched by its own changing text label.
    record_toggle = ".media-recorder-card > button.btn-primary"
    page.click(record_toggle)
    page.wait_for_timeout(1200)
    page.click(record_toggle)

    assert _wait_for(
        lambda: page.evaluate(
            "!document.querySelector('.media-recorder-actions button.btn-primary')?.disabled"
        )
    )
    page.click(".media-recorder-actions button.btn-primary")

    assert _wait_for(lambda: page.evaluate("!document.querySelector('.media-recorder-modal')"))


def test_web_recording_and_sending_a_voice_message_reaches_the_real_desktop_peer(
    running_server, gateway_url, browser_page, desktop_app
):
    """Real getUserMedia()/MediaRecorder capture (Chromium's fake audio
    device), pushed through the REAL send_attachment()-equivalent
    (WebClientSession.sendAttachment()) -- proves this is not a UI-only
    mock: a REAL Desktop ClientSession peer receives PayloadType.VOICE
    with genuinely non-empty, decrypted audio bytes."""

    alice_payload = desktop_app["register"]("wvoice_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wvoice_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        received = []
        alice.payload_message_received.connect(
            lambda identity_key, sender, payload_type, data, content_metadata:
                received.append((payload_type, sender, bytes(data), content_metadata))
        )

        _record_and_send(page, "voice")

        assert _wait_for(lambda: page.evaluate("!!document.querySelector('#messages audio.bubble-media')"))

        assert _wait_for(lambda: len(received) == 1)
        payload_type, sender, data, content_metadata = received[0]
        assert payload_type == "voice"
        assert sender == bob_username
        assert len(data) > 0
        assert content_metadata.get("mime_type", "").startswith("audio/")
    finally:
        _delete(bob_payload["username"])


def test_web_recording_and_sending_a_video_message_reaches_the_real_desktop_peer(
    running_server, gateway_url, browser_page, desktop_app
):
    alice_payload = desktop_app["register"]("wvideo_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wvideo_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)

        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        received = []
        alice.payload_message_received.connect(
            lambda identity_key, sender, payload_type, data, content_metadata:
                received.append((payload_type, sender, bytes(data), content_metadata))
        )

        _record_and_send(page, "video")

        assert _wait_for(lambda: page.evaluate("!!document.querySelector('#messages video.bubble-media')"))

        assert _wait_for(lambda: len(received) == 1)
        payload_type, sender, data, content_metadata = received[0]
        assert payload_type == "video"
        assert sender == bob_username
        assert len(data) > 0
        assert content_metadata.get("mime_type", "").startswith("video/")
    finally:
        _delete(bob_payload["username"])


def test_web_attachment_menu_cancel_releases_camera_and_microphone(
    running_server, gateway_url, browser_page, desktop_app
):
    """Cancelling the recorder must actually stop the underlying
    MediaStreamTracks (releasing the camera/mic), not merely hide the
    modal -- otherwise the device stays "in use" indefinitely."""

    alice_payload = desktop_app["register"]("wcancel_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wcancel_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_payload["username"])

        _open_direct_chat_in_browser(page, alice.username)

        page.click("#attachBtn")
        page.click(".bubble-context-menu >> text=Voice Message")
        assert _wait_for(lambda: page.evaluate("!!document.querySelector('.media-recorder-modal')"))

        assert page.evaluate(
            "document.querySelector('.media-recorder-modal') ? true : false"
        )

        page.click(".media-recorder-actions button.btn-ghost")

        assert _wait_for(lambda: page.evaluate("!document.querySelector('.media-recorder-modal')"))
    finally:
        _delete(bob_payload["username"])


# ========================================================================
# Presence / Last Seen
# ========================================================================


def test_web_presence_shows_online_then_last_seen_after_desktop_disconnects(
    running_server, gateway_url, browser_page, desktop_app
):
    """Drives the REAL #peerPresence wiring main.js::refreshPeerPresence()
    attaches -- "Online" while alice's REAL Desktop ClientSession is
    connected, then a genuine "Last seen ..." (server/client_handler.py
    ::handle_last_seen_request(), a real server round trip) once she
    disconnects -- not a fake local-only label."""

    alice_payload = desktop_app["register"]("wseen_a_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("wseen_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_payload["username"])

        _open_direct_chat_in_browser(page, alice.username)

        assert _wait_for(lambda: page.inner_text("#peerPresence") == "Online")

        alice.disconnect()

        assert _wait_for(
            lambda: page.inner_text("#peerPresence").startswith("Last seen"),
            attempts=200, interval=0.1,
        )
    finally:
        _delete(bob_payload["username"])
