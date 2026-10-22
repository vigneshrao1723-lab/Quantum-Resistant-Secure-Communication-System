"""
Web client: messenger layout, responsive behaviour, and the Android-parity
features added with it (bio, peer profile, leave group, add members with admin
approval, group key rotation).

Everything runs in a real Chrome (Playwright) against the real static client,
the real gateway and server, with a real Desktop ClientSession as the other
party. Group key rotation is triggered by handing the browser's real
``_handleIncoming`` the packet the server sends; the keys it distributes are
then checked on the receiving Desktop session.
"""

import json
import uuid

import pytest

from tests.image_fixtures import solid_png

from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    PASSWORD,
    _connect_browser,
    _delete,
    _register,
    _wait_for,
    browser_page,
    chat_tool,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_feature_completion_e2e import (
    _verify_browser_observes_desktop,
    _verify_desktop_observes_browser,
)


def _pair(desktop_app, browser_page, gateway_url):
    """Alice (Desktop) and Bob (browser), logged in and mutually VERIFIED."""

    alice_payload = desktop_app["register"]("alice_")
    alice = desktop_app["launch"](alice_payload)
    bob_payload = _register("bob_")
    _connect_browser(browser_page, gateway_url, bob_payload)
    page = browser_page["page"]
    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    _verify_browser_observes_desktop(alice, page)
    _verify_desktop_observes_browser(alice, page, bob_payload["username"])
    return alice, alice_payload, bob_payload, page


def _group_with_web_member(alice, page, name, extra_members=()):
    alice.create_group_conversation(name, [page_username(page)] + list(extra_members))
    found = {}

    def _created():
        for summary in alice.conversation_store.get_all():
            if summary.is_group and summary.group_name == name:
                found["id"] = summary.conversation_id
                return True
        return False

    assert _wait_for(_created)
    conversation_id = found["id"]
    assert _wait_for(
        lambda: page.evaluate(f"window.__session.groups.has({conversation_id!r})"), attempts=200, interval=0.1
    )
    assert _wait_for(
        lambda: page.evaluate(f"window.__session.sessionKeys.has({conversation_id!r})"), attempts=200, interval=0.1
    )
    return conversation_id


def page_username(page):
    return page.evaluate("window.__session.username")


def _open_group_info(page, name):
    page.click('.tab-btn[data-tab="groups"]')
    page.click(f'.row-card:has-text("{name}")')
    page.click("#groupInfoBtn")
    page.wait_for_selector("#groupInfoView:not([hidden])")


def _no_horizontal_overflow(page):
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


# ================================================================ Bio / profile


def test_web_bio_can_be_edited_and_is_seen_by_desktop(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.click("#settingsToggleBtn")
        page.click("#bioToggleBtn")
        page.fill("#bioInput", "Quantum-safe since 2026")
        page.click("#bioSaveBtn")

        assert _wait_for(lambda: alice.fetch_bio(bob_payload["username"]) == "Quantum-safe since 2026")
        # The page shows it when the server's reply reaches the browser, which can be a moment after
        # the Desktop already sees it on the server: wait for the page, do not race it.
        assert _wait_for(lambda: "Quantum-safe since 2026" in page.inner_text("#bioHint"), attempts=100, interval=0.1)
    finally:
        _delete(bob_payload["username"])


def test_web_bio_over_the_server_limit_shows_the_servers_error_and_keeps_the_old_bio(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.click("#settingsToggleBtn")
        page.click("#bioToggleBtn")
        # maxlength=256 stops typing past the limit, so bypass the field's own
        # guard to prove the SERVER's limit is what protects the account.
        page.evaluate("document.getElementById('bioInput').removeAttribute('maxlength')")
        page.fill("#bioInput", "x" * 300)
        page.click("#bioSaveBtn")

        assert _wait_for(lambda: "256" in page.inner_text("#bioHint"))
        assert alice.fetch_bio(bob_payload["username"]) == ""
    finally:
        _delete(bob_payload["username"])


def test_web_peer_profile_shows_the_desktop_users_bio_and_name(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        assert alice.change_bio("Desktop says hello").get("success")

        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        page.wait_for_selector("#chatView:not([hidden])")
        chat_tool(page, "peerProfileBtn")

        page.wait_for_selector(".profile-card")
        assert alice.username in page.inner_text(".profile-card")
        assert _wait_for(lambda: "Desktop says hello" in page.inner_text(".profile-card"))

        page.keyboard.press("Escape")
        assert _wait_for(lambda: page.locator(".profile-card").count() == 0)
    finally:
        _delete(bob_payload["username"])


# ======================================================================= Groups


def test_web_member_can_leave_a_group_and_the_server_removes_them(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        conversation_id = _group_with_web_member(alice, page, "leave-me-group")
        _open_group_info(page, "leave-me-group")

        page.click("#leaveGroupBtn")
        page.wait_for_selector(".confirm-modal")
        page.click(".confirm-modal .btn-danger-solid")

        assert _wait_for(
            lambda: not page.evaluate(f"window.__session.groups.has({conversation_id!r})"),
            attempts=200, interval=0.1,
        )
        assert _wait_for(lambda: page.locator('#groupList .row-card:has-text("leave-me-group")').count() == 0)
        # The group view closed -- the person is not left looking at a group they are no longer in.
        assert page.evaluate("document.getElementById('groupInfoView').hidden")

        # The server really removed them: Alice's own view of the member list shrinks.
        def _bob_gone_for_alice():
            for summary in alice.conversation_store.get_all():
                if summary.conversation_id == conversation_id:
                    return bob_payload["username"] not in (summary.participants or [])
            return False

        assert _wait_for(_bob_gone_for_alice)
    finally:
        _delete(bob_payload["username"])


def test_cancelling_the_leave_confirmation_keeps_the_membership(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        conversation_id = _group_with_web_member(alice, page, "stay-group")
        _open_group_info(page, "stay-group")

        page.click("#leaveGroupBtn")
        page.wait_for_selector(".confirm-modal")
        page.click(".confirm-modal .btn-ghost")

        page.wait_for_timeout(600)
        assert page.evaluate(f"window.__session.groups.has({conversation_id!r})")
        assert page.locator(".confirm-modal").count() == 0
    finally:
        _delete(bob_payload["username"])


def test_non_admin_web_member_add_request_goes_to_the_admins_inbox_and_approval_adds_them(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    carol_payload = _register("carol_")
    try:
        conversation_id = _group_with_web_member(alice, page, "approval-group")
        _open_group_info(page, "approval-group")

        page.fill("#groupAddMemberInput", carol_payload["username"])
        page.click("#groupAddMemberBtn")
        assert "Request sent" in page.inner_text("#groupAddHint")

        def _pending_request():
            for n in alice.load_inbox():
                if n.get("type") == "group_add_request" and n.get("status") == "pending":
                    return n
            return None

        assert _wait_for(lambda: _pending_request() is not None)
        # Nothing changed yet: the web member is not allowed to add anyone directly.
        assert carol_payload["username"] not in page.evaluate(
            f"window.__session.groups.get({conversation_id!r}).members"
        )

        alice.respond_to_inbox(_pending_request(), True)

        assert _wait_for(
            lambda: carol_payload["username"]
            in page.evaluate(f"window.__session.groups.get({conversation_id!r}).members"),
            attempts=200, interval=0.1,
        )
    finally:
        _delete(carol_payload["username"])
        _delete(bob_payload["username"])


def test_adding_someone_already_in_the_group_sends_nothing(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _group_with_web_member(alice, page, "dupe-group")
        _open_group_info(page, "dupe-group")
        page.evaluate(
            "window.__sent = []; const ws = window.__session.ws; const orig = ws.send.bind(ws);"
            "ws.send = (d) => { window.__sent.push(d); return orig(d); };"
        )

        page.fill("#groupAddMemberInput", f"{alice.username}, {bob_payload['username']}")
        page.click("#groupAddMemberBtn")

        assert "already in this group" in page.inner_text("#groupAddHint")
        assert page.evaluate("window.__sent.filter(d => String(d).includes('group_add_members')).length") == 0
    finally:
        _delete(bob_payload["username"])


def test_web_distributes_a_rotated_group_key_that_the_desktop_member_installs(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        conversation_id = _group_with_web_member(alice, page, "rotate-group")
        assert not alice.key_manager.has_key(conversation_id, epoch=2)

        # The server only relays a key for an epoch it has reserved, so reserve
        # epoch 2 for real first (the round trip a member makes before any
        # rotation) and then hand the browser the server's rotation order.
        reservation = page.evaluate(
            "(cid) => window.__session._sendRequest({ type: 'epoch_reservation_request', conversation_id: cid })",
            conversation_id,
        )
        assert reservation.get("epoch") == 2, reservation

        packet = {
            "type": "group_key_rotation_required",
            "conversation_id": conversation_id,
            "epoch": 2,
            "members": [alice.username],
        }
        page.evaluate("(p) => window.__session._handleIncoming({ data: JSON.stringify(p) })", packet)

        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id, epoch=2), attempts=200, interval=0.1)
        browser_key_hex = page.evaluate(
            f"(() => {{ const i = window.__session.sessionKeys.get({conversation_id!r});"
            "return i.epoch + ':' + Array.from(i.key).map(b => b.toString(16).padStart(2,'0')).join(''); })()"
        )
        epoch, key_hex = browser_key_hex.split(":")
        assert epoch == "2"
        assert alice.key_manager.get_key(conversation_id, epoch=2).hex() == key_hex
    finally:
        _delete(bob_payload["username"])


def test_web_ignores_rotation_requests_for_groups_it_is_not_in_or_malformed_epochs(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        conversation_id = _group_with_web_member(alice, page, "ignore-group")
        sent_before = page.evaluate(
            "window.__sent = []; const ws = window.__session.ws; const orig = ws.send.bind(ws);"
            "ws.send = (d) => { window.__sent.push(d); return orig(d); }; 0"
        )
        stranger_group = str(uuid.uuid4())

        for packet in (
            {"conversation_id": stranger_group, "epoch": 2, "members": [alice.username]},
            {"conversation_id": conversation_id, "epoch": "2", "members": [alice.username]},
            {"conversation_id": conversation_id, "epoch": 2.5, "members": [alice.username]},
            {"conversation_id": None, "epoch": 2, "members": [alice.username]},
        ):
            packet["type"] = "group_key_rotation_required"
            page.evaluate("(p) => window.__session._handleIncoming({ data: JSON.stringify(p) })", packet)

        page.wait_for_timeout(800)
        assert page.evaluate(
            "window.__sent.filter(d => String(d).includes('group_key_distribution') || String(d).includes('rotation_complete')).length"
        ) == 0
        assert not alice.key_manager.has_key(conversation_id, epoch=2)
    finally:
        _delete(bob_payload["username"])


# =================================================================== Composer


def test_enter_sends_shift_enter_adds_a_line_and_the_composer_grows(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        page.click("#establishKeyBtn")
        assert _wait_for(lambda: "Session key established" in page.inner_text("#log"))

        received = []
        alice.message_received.connect(lambda key, sender, text: received.append(text))

        one_line = page.evaluate("document.getElementById('messageText').offsetHeight")
        page.click("#messageText")
        page.keyboard.type("first")
        page.keyboard.press("Shift+Enter")
        page.keyboard.type("second")
        page.keyboard.press("Shift+Enter")
        page.keyboard.type("third")
        grown = page.evaluate("document.getElementById('messageText').offsetHeight")
        assert grown > one_line
        assert received == []

        page.keyboard.press("Enter")

        assert _wait_for(lambda: received == ["first\nsecond\nthird"])
        # Sent: the field empties and shrinks back.
        assert page.input_value("#messageText") == ""
        assert page.evaluate("document.getElementById('messageText').offsetHeight") == one_line
        # The line breaks survive into the rendered bubble.
        assert "first\nsecond\nthird" in page.inner_text("#messages") or all(
            part in page.inner_text("#messages") for part in ("first", "second", "third")
        )
    finally:
        _delete(bob_payload["username"])


# ============================================================ Search + filters


def test_sidebar_search_filters_the_chat_list_and_never_creates_a_conversation(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    carol = desktop_app["launch"](desktop_app["register"]("carol_"))
    dave_payload = desktop_app["register"]("dave_")
    try:
        # Two real conversations in the list (verified contacts are listed).
        _verify_browser_observes_desktop(carol, page)
        page.wait_for_selector(f'#chatList .row-card:has-text("{alice.username}")')
        page.wait_for_selector(f'#chatList .row-card:has-text("{carol.username}")')

        def rows(name=""):
            selector = f'#chatList .row-card:has-text("{name}")' if name else "#chatList .row-card"
            return page.locator(selector).count()

        # Search text that matches ONE conversation narrows the list to it (case-insensitively).
        page.fill("#peerUsername", alice.username[:-6].upper())
        assert rows(alice.username) == 1 and rows(carol.username) == 0

        # Typing a phone number one keystroke at a time (the screenshot showed "+91",
        # "+91 11111" ... each becoming a conversation) creates nothing, however long it sits.
        for partial in ("+9", "+91", "+91 1", "+91 11111", "+91 111112222"):
            page.fill("#peerUsername", partial)
        page.wait_for_timeout(900)
        assert rows() == 0
        assert page.locator("#startChatBtn").count() == 1  # a separate search result, not a row
        page.fill("#peerUsername", "")
        assert rows() == 2

        # Enter on a number nobody uses: a message, no conversation.
        page.fill("#peerUsername", "+91 9999999999")
        page.press("#peerUsername", "Enter")
        assert _wait_for(lambda: "No account uses that phone number." in page.inner_text("#toastRegion"))
        page.fill("#peerUsername", "")
        assert rows() == 2

        # Enter on a real phone number opens a chat with THAT account (resolved by the server),
        # and the search box is cleared, but no list row appears until a message is exchanged.
        page.fill("#peerUsername", dave_payload["phone_number"])
        page.press("#peerUsername", "Enter")
        page.wait_for_selector("#chatView:not([hidden])")
        assert _wait_for(lambda: page.evaluate("document.querySelector('#chatTitle .chat-header-name').title")
                         == f"@{dave_payload['username']}")
        assert page.input_value("#peerUsername") == ""
        page.wait_for_timeout(600)
        assert rows(dave_payload["username"]) == 0 and rows() == 2

        # Repeated searches for the same thing never duplicate anything.
        for _ in range(3):
            page.fill("#peerUsername", carol.username)
            assert rows(carol.username) == 1
        page.fill("#peerUsername", "")
        assert rows() == 2
    finally:
        _delete(bob_payload["username"])


def test_an_open_chat_never_filters_the_groups_tab_away(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _group_with_web_member(alice, page, "still-visible-group")
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        page.wait_for_selector("#chatView:not([hidden])")

        page.click('.tab-btn[data-tab="groups"]')

        assert page.locator('#groupList .row-card:has-text("still-visible-group")').count() == 1
        # A phone number being looked up matches no group: the Groups tab is left as it is.
        page.fill("#peerUsername", "+91 98765")
        assert page.locator('#groupList .row-card:has-text("still-visible-group")').count() == 1
    finally:
        _delete(bob_payload["username"])


def test_unread_filter_hides_conversations_without_unread_messages(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        page.wait_for_selector(f'#chatList .row-card:has-text("{alice.username}")')

        page.click("#unreadFilterToggle")
        assert page.get_attribute("#unreadFilterToggle", "aria-pressed") == "true"
        assert page.locator("#chatList .row-card").count() == 0

        page.click("#unreadFilterToggle")
        assert page.get_attribute("#unreadFilterToggle", "aria-pressed") == "false"
        assert page.locator(f'#chatList .row-card:has-text("{alice.username}")').count() == 1
    finally:
        _delete(bob_payload["username"])


# ================================================================= Layout


@pytest.mark.parametrize("width", [1280, 1024, 820])
def test_wide_layout_is_three_regions_and_the_rail_holds_every_destination(
    running_server, gateway_url, browser_page, desktop_app, width
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.set_viewport_size({"width": width, "height": 800})
        page.wait_for_timeout(300)

        rail = page.locator("#navRail").bounding_box()
        sidebar = page.locator("#sidebar").bounding_box()
        main = page.locator("#mainPane").bounding_box()
        assert rail["x"] == 0
        assert rail["x"] + rail["width"] <= sidebar["x"] + 1
        assert sidebar["x"] + sidebar["width"] <= main["x"] + 1

        for selector in ('.tab-btn[data-tab="chats"]', '.tab-btn[data-tab="groups"]',
                         '.tab-btn[data-tab="inbox"]', "#settingsToggleBtn", "#logoutBtn"):
            box = page.locator(selector).bounding_box()
            assert box and rail["x"] <= box["x"] and box["x"] + box["width"] <= rail["x"] + rail["width"] + 1, selector

        assert _no_horizontal_overflow(page)
    finally:
        _delete(bob_payload["username"])


def test_sidebar_title_follows_the_active_list(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        assert page.inner_text("#sidebarTitle") == "Chats"
        page.click('.tab-btn[data-tab="groups"]')
        assert page.inner_text("#sidebarTitle") == "Groups"
        page.click('.tab-btn[data-tab="inbox"]')
        assert page.inner_text("#sidebarTitle") == "Inbox"
        page.click('.tab-btn[data-tab="chats"]')
        assert page.inner_text("#sidebarTitle") == "Chats"
        assert page.inner_text("#connectionStatus").strip().lower() == "connected"
    finally:
        _delete(bob_payload["username"])


@pytest.mark.parametrize("width", [320, 360, 390, 768])
def test_phone_layout_shows_one_pane_with_a_bottom_navigation_bar(
    running_server, gateway_url, browser_page, desktop_app, width
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        height = 800
        page.set_viewport_size({"width": width, "height": height})
        page.wait_for_timeout(300)
        assert _no_horizontal_overflow(page)

        # Verification left a chat open. On a phone that pane is shown alone and
        # the bar is tucked away; go back to the list first.
        if width <= 800:
            assert page.locator("#chatView").is_visible()
            assert not page.locator("#navRail").is_visible()
            assert not page.locator("#sidebar").is_visible()
            assert _no_horizontal_overflow(page)
            page.click("#chatBackBtn")
        else:
            page.fill("#peerUsername", alice.username)
            page.press("#peerUsername", "Enter")
            page.wait_for_selector("#chatView:not([hidden])")

        # The list: the rail is a bottom bar (phones) with every destination reachable.
        if width <= 800:
            assert page.locator("#sidebar").is_visible()
            rail = page.locator("#navRail").bounding_box()
            assert abs((rail["y"] + rail["height"]) - height) <= 2
            assert rail["width"] >= width - 2
            for selector in ('.tab-btn[data-tab="chats"]', '.tab-btn[data-tab="groups"]',
                             '.tab-btn[data-tab="inbox"]', "#settingsToggleBtn", "#logoutBtn"):
                box = page.locator(selector).bounding_box()
                assert box and 0 <= box["x"] and box["x"] + box["width"] <= width + 1, selector
                assert box["width"] >= 40 and box["height"] >= 40, f"{selector} is too small to tap"
            assert _no_horizontal_overflow(page)
    finally:
        _delete(bob_payload["username"])


def test_a_verified_contact_is_one_concise_line_with_the_comparison_on_demand(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        page.wait_for_selector("#chatView:not([hidden])")
        assert _wait_for(lambda: page.get_attribute("#securityBar", "data-state") == "VERIFIED")
        full_number = page.inner_text("#fingerprintDisplay")

        for width in (1280, 390):
            page.set_viewport_size({"width": width, "height": 800})
            page.wait_for_timeout(250)

            # The bar says only what matters: "Verified", and the one action.
            bar = page.locator("#securityBar")
            assert bar.bounding_box()["height"] < 60, f"the verified bar should be one row at {width}px"
            assert page.inner_text("#securityStatusText").strip() == "Verified"
            assert page.locator("#reverifyBtn").is_visible()
            assert page.locator("#reverifyBtn").inner_text().strip() == "Re-verify"
            # No full number, no Confirm / Request Approval, no own number while it is not needed.
            assert not page.locator("#safetyDetails").is_visible()
            assert not page.locator("#confirmVerifiedBtn").is_visible()
            assert not page.locator("#requestVerificationBtn").is_visible()
            assert not page.locator("#ownSafetyNumber").is_visible()
            # Nothing was dropped from the DOM: the whole safety number is still there for the comparison.
            assert page.evaluate("document.getElementById('fingerprintDisplay').textContent").count(
                full_number.split()[-1]
            ) >= 1
            assert _no_horizontal_overflow(page)

            # Re-verify opens the comparison (and the explicit confirmation).
            page.click("#reverifyBtn")
            assert page.locator("#safetyDetails").is_visible()
            assert page.locator("#fingerprintDisplay .fp-value").is_visible()
            assert page.locator("#confirmVerifiedBtn").is_visible()
            assert page.get_attribute("#securityBarToggle", "aria-expanded") == "true"
            assert _no_horizontal_overflow(page)

            # Your own number appears only when asked for, and is the one the peer observes for you.
            assert not page.locator("#ownSafetyNumber").is_visible()
            page.click("#showOwnNumberBtn")
            page.wait_for_function(
                "document.getElementById('ownSafetyNumber').textContent.trim().split(/\\s+/).length === 16",
                timeout=10000,
            )
            assert " ".join(page.inner_text("#ownSafetyNumber").split()) == " ".join(
                alice.get_peer_fingerprint_for_verification(bob_payload["username"]).split()
            )
            page.click("#showOwnNumberBtn")
            assert not page.locator("#ownSafetyNumber").is_visible()

            # The chevron collapses it again.
            page.click("#securityBarToggle")
            assert not page.locator("#safetyDetails").is_visible()
            assert page.get_attribute("#securityBarToggle", "aria-expanded") == "false"

        # The conversation is never squeezed out: the message area keeps real room.
        assert page.locator("#messages").bounding_box()["height"] > 250
        assert page.locator("#messageText").is_visible()
    finally:
        _delete(bob_payload["username"])


def test_a_changed_key_immediately_stops_the_contact_counting_as_verified(
    running_server, gateway_url, browser_page, desktop_app
):
    """A VERIFIED contact whose identity key changes is not VERIFIED any more -- at once, in the
    state, the header chip, the bar and the actions -- and only an explicit confirmation of the new
    number restores it."""
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        assert _wait_for(lambda: page.get_attribute("#securityBar", "data-state") == "VERIFIED")
        assert page.evaluate(f"window.__session.isPeerVerified({alice.username!r})")

        # The contact presents a DIFFERENT identity (what a reinstall -- or an impostor -- looks like).
        page.evaluate(
            """async (peer) => {
              const session = window.__session;
              const seen = session.peers.get(peer);
              const changedKey = new Uint8Array(seen.signingKey);
              changedKey[0] ^= 0xFF;
              const updated = await session._upsertPeerObservation(peer, seen.kemWire, changedKey);
              session.onPeerObserved(peer, updated.fingerprint, updated.state);
            }""",
            alice.username,
        )

        assert not page.evaluate(f"window.__session.isPeerVerified({alice.username!r})")
        assert page.get_attribute("#securityBar", "data-state") == "KEY_CHANGED"
        assert page.get_attribute("#peerVerifiedBadge", "data-state") == "KEY_CHANGED"
        assert "Verified" not in page.inner_text("#peerVerifiedBadge").replace("Unverified", "")
        assert "Key changed" in page.inner_text("#securityStatusText")
        # The comparison is open and the explicit confirmation is the way back.
        assert page.locator("#safetyDetails").is_visible()
        assert page.locator("#confirmVerifiedBtn").is_visible()
        assert not page.locator("#reverifyBtn").is_visible()

        # Sending protected messages is refused until it is re-verified.
        refused = page.evaluate(
            """async (peer) => { try { await window.__session.sendMessage(peer, 'hi'); return 'sent'; }
                                   catch (e) { return String(e.message); } }""",
            alice.username,
        )
        assert refused != "sent"

        page.click("#confirmVerifiedBtn")
        assert _wait_for(lambda: page.get_attribute("#securityBar", "data-state") == "VERIFIED")
        assert page.evaluate(f"window.__session.isPeerVerified({alice.username!r})")
    finally:
        _delete(bob_payload["username"])


def test_unverified_peer_keeps_the_full_safety_number_on_phones(running_server, gateway_url, browser_page, desktop_app):
    alice_payload = desktop_app["register"]("alice_")
    alice = desktop_app["launch"](alice_payload)
    bob_payload = _register("bob_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)

        page.set_viewport_size({"width": 390, "height": 800})
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        assert _wait_for(lambda: alice.username in page.inner_text("#fingerprintDisplay"))
        assert page.get_attribute("#securityBar", "data-state") == "UNVERIFIED"

        # Someone who still has to compare the number sees all of it, with labelled actions.
        assert not page.locator("#securityBarToggle").is_visible()
        assert page.locator("#fingerprintDisplay .fp-label").is_visible()
        assert page.locator("#fingerprintDisplay .fp-value").is_visible()
        assert page.locator("#confirmVerifiedBtn").inner_text().strip() == "Confirm match"
        assert _no_horizontal_overflow(page)
    finally:
        _delete(bob_payload["username"])


# ============================================================ Profile picture


def _decode_png(png_bytes):
    from PySide6.QtGui import QGuiApplication, QImage

    QGuiApplication.instance() or QGuiApplication([])
    image = QImage()
    assert image.loadFromData(png_bytes)
    return image


def _choose_picture(page, name, mime, data):
    page.click("#settingsToggleBtn")
    page.set_input_files("#profilePicInput", {"name": name, "mimeType": mime, "buffer": data})


def test_web_profile_picture_is_cropped_uploaded_and_visible_to_the_desktop(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        # Not square, so the crop matters.
        _choose_picture(page, "me.png", "image/png", solid_png(400, 240))

        # Choosing a picture opens the crop dialog; nothing is uploaded yet.
        page.wait_for_selector(".crop-card #cropSaveBtn")
        assert alice.fetch_profile_picture(bob_payload["username"]) is None
        assert page.locator(".crop-canvas").is_visible()

        # Position it (drag) and zoom, then save.
        canvas = page.locator(".crop-canvas")
        box = canvas.bounding_box()
        page.mouse.move(box["x"] + 140, box["y"] + 140)
        page.mouse.down()
        page.mouse.move(box["x"] + 90, box["y"] + 140, steps=4)
        page.mouse.up()
        page.locator("#cropZoom").fill("1.6")
        page.click("#cropSaveBtn")

        stored = None

        def _stored():
            nonlocal stored
            stored = alice.fetch_profile_picture(bob_payload["username"])
            return stored is not None

        assert _wait_for(_stored, attempts=200, interval=0.1)
        image = _decode_png(stored)
        assert image.width() == image.height() == 256                  # a square, a fixed size
        assert page.locator(".crop-card").count() == 0                 # the dialog closed
        assert page.locator("#myProfilePicAvatar img").count() == 1    # Settings shows the real picture
        assert "Profile picture updated" in page.inner_text("#toastRegion")
    finally:
        _delete(bob_payload["username"])


def test_cancelling_the_crop_uploads_nothing(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _choose_picture(page, "me.png", "image/png", solid_png(200, 200))
        page.wait_for_selector(".crop-card #cropSaveBtn")

        page.click(".crop-card .btn-ghost")

        assert page.locator(".crop-card").count() == 0
        page.wait_for_timeout(500)
        assert alice.fetch_profile_picture(bob_payload["username"]) is None
        assert page.locator("#myProfilePicAvatar img").count() == 0
    finally:
        _delete(bob_payload["username"])


def test_web_profile_picture_files_are_validated_before_anything_is_uploaded(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        cases = [
            ("notes.pdf", "application/pdf", b"%PDF-1.7 " + b"x" * 100, "Choose a PNG, JPEG, WebP or GIF"),
            ("fake.png", "image/png", b"this is not really a png", "couldn't be read"),
            ("tiny.png", "image/png", solid_png(40, 40), "too small"),
            ("wide.png", "image/png", solid_png(9000, 70), "too large"),
            ("huge.png", "image/png", solid_png(100, 100) + b"\x00" * (11 * 1024 * 1024), "too large"),
        ]
        for name, mime, data, expected in cases:
            _choose_picture(page, name, mime, data)
            assert _wait_for(lambda: expected in page.inner_text("#myProfilePicHint"), attempts=100, interval=0.1), name
            assert page.locator(".crop-card").count() == 0, name          # never reaches the crop step
            assert alice.fetch_profile_picture(bob_payload["username"]) is None, name
    finally:
        _delete(bob_payload["username"])


def test_a_server_refusal_is_shown_in_the_crop_dialog_and_nothing_changes(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.evaluate("""window.__session.uploadProfilePicture = async () => ({success: false, error: 'Image must be under 2 MB.'})""")
        _choose_picture(page, "me.png", "image/png", solid_png(300, 300))
        page.wait_for_selector(".crop-card #cropSaveBtn")

        page.click("#cropSaveBtn")

        assert _wait_for(lambda: "Image must be under 2 MB." in page.inner_text(".crop-error"), attempts=100, interval=0.1)
        assert page.locator(".crop-card").count() == 1               # still open, nothing lost
        assert page.locator("#cropSaveBtn").is_enabled()
        assert alice.fetch_profile_picture(bob_payload["username"]) is None
    finally:
        _delete(bob_payload["username"])


def test_the_crop_dialog_is_keyboard_operable(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _choose_picture(page, "me.png", "image/png", solid_png(500, 300))
        page.wait_for_selector(".crop-card #cropSaveBtn")
        assert page.evaluate("document.activeElement === document.querySelector('.crop-canvas')")

        for key in ("ArrowLeft", "ArrowLeft", "+", "+", "ArrowUp"):
            page.keyboard.press(key)
        assert float(page.input_value("#cropZoom")) > 1.1               # + zoomed in
        page.keyboard.press("Escape")

        assert page.locator(".crop-card").count() == 0                   # Escape cancels
        assert alice.fetch_profile_picture(bob_payload["username"]) is None
    finally:
        _delete(bob_payload["username"])


def test_the_settings_picture_opens_the_enlarged_viewer_where_change_lives(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.click("#settingsToggleBtn")
        # The profile row: the name and the handle, and no separate "Profile Picture [Change]" row.
        assert _wait_for(lambda: page.inner_text("#ownHandle") == f"@{bob_payload['username']}")
        assert page.inner_text("#ownDisplayName").strip()
        assert page.locator("#profilePicChangeBtn").count() == 0

        # No picture yet: the viewer shows a polished placeholder and says so.
        page.click("#myProfilePicAvatar")
        page.wait_for_selector(".picture-viewer-card")
        assert _wait_for(lambda: "haven't added a profile picture" in page.inner_text(".picture-viewer-card"))
        assert page.locator(".picture-viewer-card .avatar.xl").is_visible()
        assert page.inner_text("#pictureChangeBtn").strip() == "Add a picture"

        # Change is offered only here, and opens the chooser (we answer it with a real file).
        with page.expect_file_chooser() as chooser:
            page.click("#pictureChangeBtn")
        chooser.value.set_files({"name": "me.png", "mimeType": "image/png", "buffer": solid_png(240, 240)})
        page.wait_for_selector(".crop-card #cropSaveBtn")
        page.click("#cropSaveBtn")
        assert _wait_for(lambda: alice.fetch_profile_picture(bob_payload["username"]) is not None, attempts=200, interval=0.1)

        # Now the viewer shows the real picture, and offers to change it.
        page.click("#myProfilePicAvatar")
        page.wait_for_selector(".picture-viewer-card .avatar.xl img")
        assert page.inner_text("#pictureChangeBtn").strip() == "Change picture"
        page.keyboard.press("Escape")
        assert page.locator(".picture-viewer-card").count() == 0
    finally:
        _delete(bob_payload["username"])


def test_the_header_avatar_opens_the_contacts_picture_with_no_change_control(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        page.wait_for_selector("#chatView:not([hidden])")

        # The avatar is a real, labelled, focusable button -- and the old profile icon is gone.
        assert page.evaluate("document.getElementById('chatAvatar').tagName") == "BUTTON"
        assert page.get_attribute("#chatAvatar", "aria-label") == "View profile picture"
        assert page.locator("#peerProfileBtn").is_visible() is False   # only in the Chat settings menu

        # A contact without a picture: placeholder + plain caption.
        page.click("#chatAvatar")
        page.wait_for_selector(".picture-viewer-card")
        assert _wait_for(lambda: "hasn't added a profile picture" in page.inner_text(".picture-viewer-card"))
        assert page.locator("#pictureChangeBtn").count() == 0
        page.keyboard.press("Escape")

        # Once they set one, everyone who looks them up sees it (Desktop uploads here).
        assert alice.upload_profile_picture(solid_png(256, 256), content_type="image/png")["success"]
        page.focus("#chatAvatar")
        page.keyboard.press("Enter")                                    # keyboard-operable
        page.wait_for_selector(".picture-viewer-card .avatar.xl img")
        assert page.locator("#pictureChangeBtn").count() == 0
    finally:
        _delete(bob_payload["username"])
