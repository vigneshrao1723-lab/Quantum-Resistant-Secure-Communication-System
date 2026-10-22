"""
Website: adding a person to a group by phone number shows who they are first.

* Create group: a phone number typed into the member box is looked up and shown by name (and
  @handle) with an Add button; nothing is added until that is pressed (or Enter is pressed again);
  an unknown number says so and adds nothing; a phone number is never sent as if it were a username.
* Group info > Add members: the same preview before the request is sent.

Real Chrome, gateway, server and a real Desktop peer.
"""

from sqlalchemy import text

from database.connection import SessionLocal
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _delete,
    _register,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_messenger_layout_and_parity import _group_with_web_member, _open_group_info, _pair


def _pending_invitations(username):
    """Pending group invitations addressed to ``username``, read from the database (works for a person
    who is offline)."""
    db = SessionLocal()
    try:
        return db.execute(
            text(
                "SELECT count(*) FROM inbox_notifications n JOIN users u ON u.id = n.recipient_user_id "
                "WHERE u.username = :u AND n.type = 'group_invitation' AND n.status = 'pending'"
            ),
            {"u": username},
        ).scalar()
    finally:
        db.close()


def _name_account(username, display_name):
    db = SessionLocal()
    try:
        db.execute(text("UPDATE users SET display_name = :n WHERE username = :u"), {"n": display_name, "u": username})
        db.commit()
    finally:
        db.close()


def _group_members(page, name):
    return page.evaluate(
        "(n) => { const g = [...window.__session.groups.values()].find((x) => x.name === n); return g ? g.members : null; }",
        name,
    )


def _open_create_modal(page):
    page.click('.tab-btn[data-tab="groups"]')
    page.click("#openCreateGroupBtn")
    page.wait_for_selector("#groupCreateModal:not([hidden])")


def test_a_phone_number_is_shown_by_name_before_the_person_is_added_to_a_new_group(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    carol = _register("carol_")
    _name_account(carol["username"], "Carol Preview")
    try:
        _open_create_modal(page)
        page.fill("#groupName", "Phone Group")

        # Unknown number: a message, nothing added.
        page.fill("#groupMembers", "+91 9999999999")
        page.press("#groupMembers", "Enter")
        assert _wait_for(lambda: "No account uses that phone number." in page.inner_text("#groupMemberLookup"))
        assert page.locator("#groupMemberChips .member-chip").count() == 0

        # A real number: shown by name and handle, still NOT a member.
        page.fill("#groupMembers", carol["phone_number"])
        page.press("#groupMembers", "Enter")
        page.wait_for_selector("#groupMemberLookup .member-lookup-name")
        assert page.inner_text("#groupMemberLookup .member-lookup-name") == "Carol Preview"
        assert page.inner_text("#groupMemberLookup .member-lookup-handle") == f"@{carol['username']}"
        assert page.locator("#groupMemberChips .member-chip").count() == 0

        # Add: a chip that shows the name; the box is cleared; the preview is gone.
        page.click("#groupMemberLookup button.btn-primary")
        assert page.locator("#groupMemberChips .member-chip").count() == 1
        assert "Carol Preview" in page.inner_text("#groupMemberChips")
        assert page.input_value("#groupMembers") == ""
        assert page.locator("#groupMemberLookup").is_hidden()

        # A username still works as before, and the group is created with HANDLES, never phone numbers.
        page.fill("#groupMembers", alice.username)
        page.press("#groupMembers", "Enter")
        assert page.locator("#groupMemberChips .member-chip").count() == 2
        page.click("#createGroupBtn")

        # The group exists with only its creator; the two people are INVITED (by handle, never by phone
        # number) and join only when they approve in their own Inbox.
        assert _wait_for(lambda: _group_members(page, "Phone Group") is not None, attempts=200, interval=0.1)
        assert _group_members(page, "Phone Group") == [bob_payload["username"]]
        assert _wait_for(lambda: _pending_invitations(carol["username"]) == 1)
        assert _wait_for(lambda: _pending_invitations(alice.username) == 1)
    finally:
        _delete(carol["username"])
        _delete(bob_payload["username"])


def test_enter_a_second_time_adds_the_person_who_is_being_shown(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    carol = _register("carol_")
    try:
        _open_create_modal(page)
        page.fill("#groupMembers", carol["phone_number"])
        page.press("#groupMembers", "Enter")
        page.wait_for_selector("#groupMemberLookup .member-lookup-name")
        assert page.locator("#groupMemberChips .member-chip").count() == 0

        page.press("#groupMembers", "Enter")

        assert page.locator("#groupMemberChips .member-chip").count() == 1
        assert page.locator("#groupMemberLookup").is_hidden()
    finally:
        _delete(carol["username"])
        _delete(bob_payload["username"])


def test_a_phone_number_that_was_never_looked_up_is_not_sent_as_a_username(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    carol = _register("carol_")
    try:
        _open_create_modal(page)
        page.fill("#groupName", "Never Created")
        page.fill("#groupMembers", carol["phone_number"])
        page.click("#createGroupBtn")

        assert _wait_for(lambda: "look up that phone number" in page.inner_text("#toastRegion"))
        page.wait_for_timeout(700)
        assert _group_members(page, "Never Created") is None
        assert not page.locator("#groupCreateModal").is_hidden()          # still open for the person to finish
    finally:
        _delete(carol["username"])
        _delete(bob_payload["username"])


def test_adding_to_an_existing_group_by_phone_number_shows_the_name_first(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    carol = _register("carol_")
    _name_account(carol["username"], "Carol Preview")
    try:
        # The browser user creates (so is admin of) the group and adds Alice by username.
        _open_create_modal(page)
        page.fill("#groupName", "Admin Group")
        page.fill("#groupMembers", alice.username)
        page.press("#groupMembers", "Enter")
        page.click("#createGroupBtn")
        assert _wait_for(lambda: _group_members(page, "Admin Group") is not None, attempts=200, interval=0.1)

        _open_group_info(page, "Admin Group")
        page.fill("#groupAddMemberInput", carol["phone_number"])
        page.click("#groupAddMemberBtn")
        page.wait_for_selector("#groupAddLookup .member-lookup-name")
        assert page.inner_text("#groupAddLookup .member-lookup-name") == "Carol Preview"
        assert carol["username"] not in (_group_members(page, "Admin Group") or [])    # shown, not yet added

        page.click("#groupAddLookup button.btn-primary")

        # An invitation went to Carol; she is not a member until she approves it.
        assert _wait_for(lambda: _pending_invitations(carol["username"]) == 1, attempts=200, interval=0.1)
        assert carol["username"] not in (_group_members(page, "Admin Group") or [])
        assert page.input_value("#groupAddMemberInput") == ""
        assert page.locator("#groupAddLookup").is_hidden()
        assert _wait_for(lambda: "Carol Preview" in page.inner_text("#groupPendingInvitations"), attempts=100, interval=0.1)
    finally:
        _delete(carol["username"])
        _delete(bob_payload["username"])


def test_an_unknown_number_in_group_info_says_so_and_adds_nobody(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _group_with_web_member(alice, page, "Existing Group")
        _open_group_info(page, "Existing Group")
        before = _group_members(page, "Existing Group")

        page.fill("#groupAddMemberInput", "+91 9999999999")
        page.click("#groupAddMemberBtn")

        assert _wait_for(lambda: "No account uses that phone number." in page.inner_text("#groupAddLookup"))
        page.wait_for_timeout(500)
        assert _group_members(page, "Existing Group") == before
    finally:
        _delete(bob_payload["username"])


def test_the_preview_says_whether_the_person_is_verified_and_can_ask_them_without_a_conversation(
    running_server, gateway_url, browser_page, desktop_app
):
    from tests.test_web_browser_e2e import _connect_browser

    alice_payload = desktop_app["register"]("alice_")
    alice = desktop_app["launch"](alice_payload)
    bob_payload = _register("bob_")
    _connect_browser(browser_page, gateway_url, bob_payload)
    page = browser_page["page"]
    bob = bob_payload["username"]
    try:
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob) is not None)
        _open_create_modal(page)
        page.fill("#groupMembers", alice_payload["phone_number"])      # never spoken to, found by phone number
        page.press("#groupMembers", "Enter")
        page.wait_for_selector("#groupMemberLookup .member-lookup-name")
        assert "Not verified yet" in page.inner_text("#groupMemberLookup")
        assert page.locator("#groupMemberChips .member-chip").count() == 0

        page.click("#groupMemberLookup button:has-text('Ask to verify')")

        # The request reaches only the person asked, names who asked, and verifies nothing by itself.
        def _pending():
            return any(
                e.get("type") == "verification_request" and e.get("status") == "pending" and e.get("requester_username") == bob
                for e in alice.load_inbox()
            )

        assert _wait_for(_pending, attempts=200, interval=0.1)
        assert alice.get_peer_verification_state(bob) != "VERIFIED"
        assert page.evaluate("(p) => window.__session.peers.get(p)?.state", alice.username) != "VERIFIED"
        assert page.locator("#groupMemberChips .member-chip").count() == 0   # asking did not add anyone
    finally:
        _delete(bob)
