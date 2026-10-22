"""Verification requests, blocking, pins, search, drafts, mute/archive and presence (Website UI)."""

import uuid

from tests.acceptance.parties import converse, verify_pair
from tests.acceptance.web_driver import wait_until


def _row(username):
    return f".row-card:has-text('{username}')"


def test_verification_request_is_approved_from_the_inbox(party):
    a, b = party("web", "vr_a"), party("web", "vr_b")
    a.open_chat_with(b)
    b.open_chat_with(a)  # B observes A's identity, as a person opening the chat would

    a.user.page.click("#requestVerificationBtn")

    b.user.page.click('.tab-btn[data-tab="inbox"]')
    wait_until(lambda: a.username in b.user.page.inner_text("#inboxList"), 30, what="the request in B's Inbox")
    b.user.page.click("#inboxList .notif-card .btn-primary")

    wait_until(lambda: b.user.page.evaluate(f"window.__session.isPeerVerified({a.username!r})"), 20,
               what="B to be marked as having verified A")


def test_blocking_stops_delivery_without_telling_the_blocked_user_and_unblocking_restores_it(party):
    a, b = party("web", "bl_a"), party("web", "bl_b")
    verify_pair(a, b)
    converse(a, b, "before-block")

    a.user.page.click(f"{_row(b.username)} .row-mute-btn")
    a.user.page.click(".bubble-context-menu >> text=Block")
    a.user.confirm_dialog("Block")

    blocked_text = f"while-blocked-{uuid.uuid4().hex[:6]}"
    b.send(blocked_text)
    # B's own screen shows nothing unusual (no 'you are blocked' leak) ...
    b.wait_for_text(blocked_text)
    assert not any(phrase in b.visible_text().lower()
                   for phrase in ("blocked you", "you are blocked", "has blocked", "been blocked"))
    # ... and A, who blocked B, never sees it.
    a.user.page.wait_for_timeout(1500)
    assert blocked_text not in a.visible_text()

    a.user.page.click(f"{_row(b.username)} .row-mute-btn")
    a.user.page.click(".bubble-context-menu >> text=Unblock")
    after = f"after-unblock-{uuid.uuid4().hex[:6]}"
    b.send(after)
    a.wait_for_text(after)


def test_pin_search_and_draft(party):
    a, b = party("web", "ps_a"), party("web", "ps_b")
    verify_pair(a, b)
    a.start_secure_session()
    tag = uuid.uuid4().hex[:6]
    needle, other = f"needle-{tag}", f"hay-{tag}"
    a.send(other)
    a.send(needle)
    b.wait_for_text(needle)

    # Pin: B pins A's message; it appears in the pinned bar on both sides.
    b.user.message_action(needle, "Pin")
    wait_until(lambda: needle in b.user.page.inner_text("#pinnedBar"), 20, what="the pinned message on B")
    wait_until(lambda: needle in a.user.page.inner_text("#pinnedBar"), 20, what="the pinned message on A")

    # Search within the conversation finds exactly the needle.
    b.user.chat_tool("searchBtn")
    b.user.page.fill("#searchInput", needle)
    wait_until(lambda: "1" in b.user.page.inner_text("#searchResultLabel"), 20, what="a search result")
    b.user.page.click("#searchCloseBtn")

    # Draft: unsent text survives leaving the conversation and coming back.
    draft = f"unsent-{tag}"
    b.user.page.fill("#messageText", draft)
    b.user.page.fill("#peerUsername", "")
    b.open_chat_with(a)
    wait_until(lambda: b.user.page.input_value("#messageText") == draft, 20, what="the draft to be restored")


def test_archive_and_mute_are_per_user_and_reversible(party):
    a, b = party("web", "am_a"), party("web", "am_b")
    verify_pair(a, b)
    converse(a, b, "setup")

    a.user.page.click(f"{_row(b.username)} .row-mute-btn")
    a.user.page.click(".bubble-context-menu >> text=Mute until I turn it back on")
    wait_until(lambda: a.user.page.locator(f"{_row(b.username)} .row-mute-btn").evaluate(
        "el => el.classList.contains('is-muted')"), 20, what="the muted indicator")

    a.user.page.click(f"{_row(b.username)} .row-mute-btn")
    a.user.page.click(".bubble-context-menu >> text=Archive")
    wait_until(lambda: a.user.page.locator(f"#chatList {_row(b.username)}").count() == 0, 20,
               what="the row to leave the main list")
    # B's list is unaffected by A's archiving.
    assert b.user.page.locator(f"#chatList {_row(a.username)}").count() == 1

    a.user.page.click("#archivedChatsToggle")
    a.user.page.click(f"{_row(b.username)} .row-mute-btn")
    a.user.page.click(".bubble-context-menu >> text=Unarchive")


def test_presence_follows_the_other_user_going_offline(party):
    a, b = party("web", "pr_a"), party("web", "pr_b")
    verify_pair(a, b)
    converse(a, b, "setup")
    wait_until(lambda: "online" in a.user.page.inner_text("#peerPresence").lower(), 20, what="B shown online")

    b.logout()
    wait_until(lambda: "online" not in a.user.page.inner_text("#peerPresence").lower()
               or "offline" in a.user.page.inner_text("#peerPresence").lower()
               or "last seen" in a.user.page.inner_text("#peerPresence").lower(),
               30, what="B to stop being shown as online")
