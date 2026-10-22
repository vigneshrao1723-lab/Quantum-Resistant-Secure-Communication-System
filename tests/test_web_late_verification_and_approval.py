"""
Website: a person added to a group before anyone has verified anyone, and the contact-request
(verification request) workflow, with a real Desktop peer and real Chrome.

* the group key reaches a member once BOTH sides have genuinely verified, in either order, and
  never before (a key is only ever wrapped for, and accepted from, a VERIFIED identity);
* a request made from the Website reaches the Desktop person's Inbox; their Approve verifies the
  requester, the Website then verifies them back from the identity it observed itself and secures
  the connection -- reported as it happens, not assumed -- and messages flow;
* a denial verifies nothing and secures nothing; a changed identity is never re-trusted by an
  approval.
"""

import time

from storage.secure_key_store import PEER_STATE_VERIFIED
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _delete,
    _open_direct,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_feature_completion_e2e import _verify_browser_observes_desktop, _verify_desktop_observes_browser
from tests.test_web_messenger_layout_and_parity import _connect_browser, _register


def _login(desktop_app, browser_page, gateway_url):
    alice_payload = desktop_app["register"]("alice_")
    alice = desktop_app["launch"](alice_payload)
    bob_payload = _register("bob_")
    _connect_browser(browser_page, gateway_url, bob_payload)
    page = browser_page["page"]
    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    return alice, bob_payload, page


def _group_id(session, name):
    for summary in session.conversation_store.get_all():
        if summary.is_group and summary.group_name == name:
            return summary.conversation_id
    return None


def _web_has_key(page, conversation_id):
    return page.evaluate("(c) => window.__session.sessionKeys.has(c)", conversation_id)


def _web_state(page, peer):
    return page.evaluate("(p) => window.__session.peers.get(p)?.state ?? null", peer)


def _open_chat(page, peer):
    page.fill("#peerUsername", peer)
    page.press("#peerUsername", "Enter")
    page.wait_for_selector("#chatView:not([hidden])")


def _web_group_known(page, conversation_id):
    return page.evaluate("(c) => window.__session.groups.has(c)", conversation_id)


# ====================================================================== group key after late verification


def test_a_web_member_added_before_verification_gets_the_key_after_both_sides_verify(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    try:
        alice.create_group_conversation("Late Web", [bob_payload["username"]])
        assert _wait_for(lambda: _group_id(alice, "Late Web") is not None)
        conversation_id = _group_id(alice, "Late Web")
        assert _wait_for(lambda: _web_group_known(page, conversation_id), attempts=200, interval=0.1)
        page.wait_for_timeout(800)
        assert not _web_has_key(page, conversation_id)                      # nobody verified: no key may move

        _verify_browser_observes_desktop(alice, page)                       # the Website verifies the Desktop ...
        page.wait_for_timeout(800)
        assert not _web_has_key(page, conversation_id)                      # ... the Desktop has not verified back
        _verify_desktop_observes_browser(alice, page, bob_payload["username"])

        assert _wait_for(lambda: _web_has_key(page, conversation_id), attempts=300, interval=0.1)
    finally:
        _delete(bob_payload["username"])


def test_the_desktop_holder_verified_first_then_the_web_member_verifies(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    try:
        _verify_desktop_observes_browser(alice, page, bob_payload["username"])   # the holder trusts the member first
        alice.create_group_conversation("Late Web 2", [bob_payload["username"]])
        assert _wait_for(lambda: _group_id(alice, "Late Web 2") is not None)
        conversation_id = _group_id(alice, "Late Web 2")
        assert _wait_for(lambda: _web_group_known(page, conversation_id), attempts=200, interval=0.1)
        page.wait_for_timeout(800)
        assert not _web_has_key(page, conversation_id)                      # the member rejects an unverified sender

        _verify_browser_observes_desktop(alice, page)                       # now the member verifies -> asks again

        assert _wait_for(lambda: _web_has_key(page, conversation_id), attempts=300, interval=0.1)
    finally:
        _delete(bob_payload["username"])


def test_a_web_admin_adds_a_desktop_member_before_verification_and_the_key_follows(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    try:
        page.click('.tab-btn[data-tab="groups"]')
        page.click("#openCreateGroupBtn")
        page.fill("#groupName", "Web Admin Group")
        page.fill("#groupMembers", alice.username)
        page.press("#groupMembers", "Enter")
        page.click("#createGroupBtn")
        # The group exists on the Website (with only its creator); the Desktop person has not joined.
        def _web_group_id():
            return page.evaluate(
                "() => { const e = [...window.__session.groups.entries()].find(([, g]) => g.name === 'Web Admin Group'); return e ? e[0] : null; }"
            )

        assert _wait_for(lambda: _web_group_id() is not None, attempts=200, interval=0.1)
        conversation_id = _web_group_id()
        page.wait_for_timeout(800)
        assert _group_id(alice, "Web Admin Group") is None                  # invited, not yet approved: not a member
        assert not alice.key_manager.has_key(conversation_id)               # ... and nothing was sent

        # The Desktop person approves the invitation in their Inbox: both sides then verify each other
        # from the identities they observed, and the key follows without anyone pressing anything.
        def _invitation():
            return next(
                (e for e in alice.load_inbox() if e.get("type") == "group_invitation" and e.get("status") == "pending"),
                None,
            )

        assert _wait_for(lambda: _invitation() is not None, attempts=200, interval=0.1)
        alice.respond_to_inbox(_invitation(), True)

        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id), attempts=300, interval=0.1)
    finally:
        _delete(bob_payload["username"])


# ====================================================================== contact request


def _pending_for_alice(alice, bob_username):
    for entry in alice.load_inbox():
        if (
            entry.get("type") == "verification_request"
            and entry.get("status") == "pending"
            and entry.get("requester_username") == bob_username
        ):
            return entry
    return None


def test_a_web_request_reaches_the_desktop_inbox_and_approval_secures_the_connection(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    bob = bob_payload["username"]
    try:
        _open_chat(page, alice.username)
        assert page.inner_text("#securityStatusText").strip() == "Not verified"
        page.click("#requestVerificationBtn")

        # It reaches the person asked, names who asked, and changed nothing yet.
        assert _wait_for(lambda: _pending_for_alice(alice, bob) is not None, attempts=200, interval=0.1)
        assert _web_state(page, alice.username) != "VERIFIED"
        assert alice.get_peer_verification_state(bob) != PEER_STATE_VERIFIED

        alice.respond_to_inbox(_pending_for_alice(alice, bob), True)

        # The Website verifies them back from the identity it observed, then secures the connection.
        assert _wait_for(lambda: _web_state(page, alice.username) == "VERIFIED", attempts=300, interval=0.1)
        assert _wait_for(lambda: page.evaluate(
            "(p) => { const c = window.__session.directConversationIds.get(p); return !!c && window.__session.sessionKeys.has(c); }",
            alice.username,
        ), attempts=300, interval=0.1)
        assert _wait_for(lambda: page.locator("#establishKeyBtn").is_hidden(), attempts=100, interval=0.1)
        assert page.inner_text("#securityStatusText").strip() == "Verified"
        assert alice.get_peer_verification_state(bob) == PEER_STATE_VERIFIED

        # And encrypted messages flow, both ways.
        received = []
        alice.message_received.connect(lambda _key, sender, text: received.append((sender, text)))
        page.fill("#messageText", "after approval, web to desktop")
        page.click("#sendBtn")
        assert _wait_for(lambda: (bob, "after approval, web to desktop") in received, attempts=300, interval=0.1)

        _open_direct(alice, bob)
        alice.send_chat_message("after approval, desktop to web")
        assert _wait_for(lambda: "after approval, desktop to web" in page.inner_text("#messages"), attempts=300, interval=0.1)
    finally:
        _delete(bob)


def test_a_denied_web_request_verifies_nothing_and_secures_nothing(running_server, gateway_url, browser_page, desktop_app):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    bob = bob_payload["username"]
    try:
        _open_chat(page, alice.username)
        page.click("#requestVerificationBtn")
        assert _wait_for(lambda: _pending_for_alice(alice, bob) is not None, attempts=200, interval=0.1)

        alice.respond_to_inbox(_pending_for_alice(alice, bob), False)

        assert _wait_for(lambda: "declined" in page.inner_text("#toastRegion"), attempts=200, interval=0.1)
        page.wait_for_timeout(600)
        assert _web_state(page, alice.username) != "VERIFIED"
        assert alice.get_peer_verification_state(bob) != PEER_STATE_VERIFIED
        assert not page.evaluate(
            "(p) => { const c = window.__session.directConversationIds.get(p); return !!c && window.__session.sessionKeys.has(c); }",
            alice.username,
        )
    finally:
        _delete(bob)


def test_a_desktop_request_is_approved_from_the_web_inbox(running_server, gateway_url, browser_page, desktop_app):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    bob = bob_payload["username"]
    try:
        alice.request_verification(bob)

        page.click('.tab-btn[data-tab="inbox"]')
        page.wait_for_selector(".notif-card .notif-actions .btn-primary")
        assert alice.username in page.inner_text(".notif-card .notif-body")
        page.click(".notif-card .notif-actions .btn-primary")

        # The Website verified the requester (their explicit approval) and the Desktop verified back.
        assert _wait_for(lambda: _web_state(page, alice.username) == "VERIFIED", attempts=300, interval=0.1)
        assert _wait_for(lambda: alice.get_peer_verification_state(bob) == PEER_STATE_VERIFIED, attempts=300, interval=0.1)
    finally:
        _delete(bob)


def test_a_web_request_to_another_website_user_is_approved_in_their_inbox(
    running_server, gateway_url, browser_page, static_url, desktop_app
):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    carol_payload = _register("carol_")
    bob, carol = bob_payload["username"], carol_payload["username"]
    page2 = page.context.browser.new_page()
    try:
        page2.route("**/favicon.ico", lambda route: route.fulfill(status=204, body=""))
        page2.goto(static_url)
        _connect_browser({"page": page2}, gateway_url, carol_payload)
        assert _wait_for(lambda: page.evaluate("(p) => window.__session.peers.has(p)", carol), attempts=200, interval=0.1)

        _open_chat(page, carol)                               # never spoken to, found by their handle
        page.click("#requestVerificationBtn")
        page2.click('.tab-btn[data-tab="inbox"]')
        page2.wait_for_selector(".notif-card .notif-actions .btn-primary")
        page2.click(".notif-card .notif-actions .btn-primary")

        assert _wait_for(lambda: page2.evaluate("(p) => window.__session.peers.get(p)?.state", bob) == "VERIFIED", attempts=300, interval=0.1)
        assert _wait_for(lambda: _web_state(page, carol) == "VERIFIED", attempts=300, interval=0.1)
        assert _wait_for(lambda: page.evaluate(
            "(p) => { const c = window.__session.directConversationIds.get(p); return !!c && window.__session.sessionKeys.has(c); }",
            carol,
        ), attempts=300, interval=0.1)

        # The secured connection carries a message both ways.
        page.fill("#messageText", "web to web")
        page.click("#sendBtn")
        _open_chat(page2, bob)
        assert _wait_for(lambda: "web to web" in page2.inner_text("#messages"), attempts=300, interval=0.1)
    finally:
        page2.close()
        _delete(carol)
        _delete(bob)


def test_group_info_says_who_is_verified_and_why_the_group_cannot_be_read_yet(
    running_server, gateway_url, browser_page, desktop_app
):
    from tests.test_web_messenger_layout_and_parity import _open_group_info

    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    try:
        alice.create_group_conversation("Info Web", [bob_payload["username"]])
        assert _wait_for(lambda: _group_id(alice, "Info Web") is not None)
        conversation_id = _group_id(alice, "Info Web")
        assert _wait_for(lambda: _web_group_known(page, conversation_id), attempts=200, interval=0.1)

        _open_group_info(page, "Info Web")
        assert page.locator("#groupKeyNotice").is_visible()
        assert "do not have this group's key yet" in page.inner_text("#groupKeyNotice")
        admin_row = page.locator(f'#groupInfoMembers .member-row:has-text("{alice.username}")')
        assert "Not verified" in admin_row.inner_text()
        # "Verify" takes the person to that member's verification, creating nothing by itself.
        admin_row.locator("button:has-text('Verify')").click()
        page.wait_for_selector("#chatView:not([hidden])")
        assert "Not verified" in page.inner_text("#securityStatusText")

        page.click("#confirmVerifiedBtn")                    # the comparison is open: the person confirms it
        _verify_desktop_observes_browser(alice, page, bob_payload["username"])
        assert _wait_for(lambda: _web_has_key(page, conversation_id), attempts=300, interval=0.1)

        _open_group_info(page, "Info Web")
        assert page.locator("#groupKeyNotice").is_hidden()
        assert "Verified" in page.locator(f'#groupInfoMembers .member-row:has-text("{alice.username}")').inner_text()
    finally:
        _delete(bob_payload["username"])
