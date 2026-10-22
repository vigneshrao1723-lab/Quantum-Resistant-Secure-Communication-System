"""
Website: joining a group by invitation. Real Chrome, gateway, server and a real Desktop peer.

* an invitation reaches the invited person's Inbox with a toast and a badge, naming who invited them
  and to which group, and they are NOT in the group until they approve;
* approving (the Website's own explicit act) adds them, both sides verify each other from the
  identities they observed, the group key arrives without anyone pressing anything, and group
  messages are readable both ways; declining leaves everything as it was;
* the inviter sees who is still deciding, and is told what each person decided.
"""

from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _delete,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_late_verification_and_approval import _login, _web_has_key, _web_state
from tests.test_web_messenger_layout_and_parity import _connect_browser, _register


def _desktop_group_id(session, name):
    for summary in session.conversation_store.get_all():
        if summary.is_group and summary.group_name == name:
            return summary.conversation_id
    return None


def _web_group_id(page, name):
    return page.evaluate(
        "(n) => { const e = [...window.__session.groups.entries()].find(([, g]) => g.name === n); return e ? e[0] : null; }",
        name,
    )


def test_an_invitation_reaches_the_inbox_and_approving_in_the_ui_joins_and_secures_the_group(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    bob = bob_payload["username"]
    try:
        alice.create_group_conversation("#LAB", [bob], consent_invitations=True)
        assert _wait_for(lambda: _desktop_group_id(alice, "#LAB") is not None)
        conversation_id = _desktop_group_id(alice, "#LAB")

        # It arrives: a toast, a badge on the Inbox tab, and a card saying who and which group.
        assert _wait_for(lambda: "invited you" in page.inner_text("#toastRegion"), attempts=200, interval=0.1)
        assert _wait_for(lambda: page.locator("#inboxBadge").is_visible(), attempts=100, interval=0.1)
        assert page.inner_text("#inboxBadge").strip() == "1"
        page.click('.tab-btn[data-tab="inbox"]')
        page.wait_for_selector(".notif-card .notif-actions .btn-primary")
        assert "GROUP INVITATION" in page.inner_text(".notif-card .notif-title")
        assert "#LAB" in page.inner_text(".notif-card .notif-body")
        assert alice.username in page.inner_text(".notif-card .notif-body")

        # Not a member yet: no group, no key.
        assert _web_group_id(page, "#LAB") is None
        assert not _web_has_key(page, conversation_id)

        page.click(".notif-card .notif-actions .btn-primary")                # Approve

        assert _wait_for(lambda: _web_group_id(page, "#LAB") == conversation_id, attempts=300, interval=0.1)
        assert _wait_for(lambda: _web_state(page, alice.username) == "VERIFIED", attempts=300, interval=0.1)
        assert _wait_for(lambda: alice.get_peer_verification_state(bob) == "VERIFIED", attempts=300, interval=0.1)
        assert _wait_for(lambda: _web_has_key(page, conversation_id), attempts=300, interval=0.1)

        # The group carries messages both ways, with nothing pressed by anyone.
        got = []
        alice.message_received.connect(lambda _key, sender, text: got.append((sender, text)))
        page.click('.tab-btn[data-tab="groups"]')
        page.click('.row-card:has-text("#LAB")')
        page.wait_for_selector("#groupChatView:not([hidden])")
        page.fill("#groupMessageText", "joined and secure")
        page.click("#sendGroupMessageBtn")
        assert _wait_for(lambda: (bob, "joined and secure") in got, attempts=300, interval=0.1)
        alice.set_current_chat(alice.conversation_store.get(conversation_id))
        alice.send_chat_message("welcome to the lab")
        assert _wait_for(lambda: "welcome to the lab" in page.inner_text("#groupMessages"), attempts=300, interval=0.1)
    finally:
        _delete(bob)


def test_declining_in_the_ui_keeps_the_person_out_and_secures_nothing(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, bob_payload, page = _login(desktop_app, browser_page, gateway_url)
    bob = bob_payload["username"]
    try:
        alice.create_group_conversation("#NOPE", [bob], consent_invitations=True)
        assert _wait_for(lambda: _desktop_group_id(alice, "#NOPE") is not None)
        conversation_id = _desktop_group_id(alice, "#NOPE")
        page.click('.tab-btn[data-tab="inbox"]')
        page.wait_for_selector(".notif-card .notif-actions .btn-ghost")

        page.click(".notif-card .notif-actions .btn-ghost")                  # Deny

        assert _wait_for(lambda: any(
            e.get("type") == "group_invitation" and e.get("status") == "denied" for e in alice.load_inbox()
        ), attempts=200, interval=0.1)
        page.wait_for_timeout(800)
        assert _web_group_id(page, "#NOPE") is None
        assert not _web_has_key(page, conversation_id)
        assert _web_state(page, alice.username) != "VERIFIED"
        assert alice.get_peer_verification_state(bob) != "VERIFIED"
    finally:
        _delete(bob)


def test_a_website_admin_invites_a_website_user_and_sees_who_is_still_deciding(
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

        page.click('.tab-btn[data-tab="groups"]')
        page.click("#openCreateGroupBtn")
        page.fill("#groupName", "#WEB2WEB")
        page.fill("#groupMembers", carol)
        page.press("#groupMembers", "Enter")
        page.click("#createGroupBtn")
        assert _wait_for(lambda: _web_group_id(page, "#WEB2WEB") is not None, attempts=200, interval=0.1)
        conversation_id = _web_group_id(page, "#WEB2WEB")

        # The inviter sees who is still deciding.
        page.click('.row-card:has-text("#WEB2WEB")')
        page.click("#groupInfoBtn")
        assert _wait_for(lambda: carol in page.inner_text("#groupPendingInvitations"), attempts=100, interval=0.1)
        assert carol not in page.inner_text("#groupInfoMembers")

        # The invited person approves on their own Website.
        assert _wait_for(lambda: page2.locator("#inboxBadge").is_visible(), attempts=100, interval=0.1)
        page2.click('.tab-btn[data-tab="inbox"]')
        page2.wait_for_selector(".notif-card .notif-actions .btn-primary")
        page2.click(".notif-card .notif-actions .btn-primary")

        assert _wait_for(lambda: _web_group_id(page2, "#WEB2WEB") == conversation_id, attempts=300, interval=0.1)
        assert _wait_for(lambda: _web_has_key(page2, conversation_id), attempts=300, interval=0.1)
        # The inviter is told, and the member list now includes them.
        assert _wait_for(lambda: "approved and joined" in page.inner_text("#toastRegion"), attempts=100, interval=0.1)
        assert _wait_for(lambda: carol in page.inner_text("#groupInfoMembers"), attempts=100, interval=0.1)
    finally:
        page2.close()
        _delete(carol)
        _delete(bob)
