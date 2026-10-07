"""
Phase 19.18 -- L-5 closure: real-browser proof that Web's Change
Username, Change Password, Inbox (verification approve/deny), and
Group Info remove-member all actually work end-to-end through the
real UI -- not just that the underlying WebClientSession methods
exist. Mirrors tests/test_web_browser_e2e.py's own fixtures and
patterns exactly (same running_server/gateway_url/browser_page/
desktop_app fixtures, same real desktop_app for the cross-client
half of the Inbox test).

Run with:
    pytest tests/test_web_settings_and_inbox.py -v
"""

from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest
from database.connection import SessionLocal
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    running_server, gateway_url, browser_page, desktop_app, static_url,
    _connect_browser, _register, _delete, _wait_for, PASSWORD,
)


def test_web_change_username_and_password_real_ui(gateway_url, browser_page):
    payload = _register("wsettings_")
    try:
        _connect_browser(browser_page, gateway_url, payload)
        page = browser_page["page"]

        page.click("#settingsToggleBtn")

        # --- Change Username, through the real form ---
        page.click("#changeUsernameToggleBtn")
        new_username = f"renamed_{payload['username'][-10:]}"
        page.fill("#newUsernameInput", new_username)
        page.click("#changeUsernameSubmitBtn")
        assert _wait_for(lambda: "Username changed." in page.inner_text("#changeUsernameHint"))
        assert page.evaluate("window.__session.username") == new_username

        # --- Change Password, through the real form ---
        new_password = "N3w!StrongerPassw0rd"
        page.click("#changePasswordToggleBtn")
        page.fill("#currentPasswordInput", PASSWORD)
        page.fill("#newPasswordInput", new_password)
        page.fill("#confirmNewPasswordInput", new_password)
        page.click("#changePasswordSubmitBtn")
        assert _wait_for(lambda: "Password changed." in page.inner_text("#changePasswordHint"))

        # Real, server-side proof -- not just a UI message: the OLD
        # password now fails, a fresh authentication with the NEW one
        # works. Checked directly against AuthenticationService (no
        # browser/socket involved) -- a real server-side hash change,
        # not a client-local flag.
        db = SessionLocal()
        try:
            old_result = AuthenticationService(db).authenticate_user(
                LoginRequest(identifier=payload["phone_number"], password=PASSWORD)
            )
            assert not old_result.success

            new_result = AuthenticationService(db).authenticate_user(
                LoginRequest(identifier=payload["phone_number"], password=new_password)
            )
            assert new_result.success, new_result.errors
        finally:
            db.close()
    finally:
        _delete(payload["username"])


def test_web_inbox_approve_verification_request_real_ui(running_server, gateway_url, browser_page, desktop_app):
    """Alice (real desktop) requests verification from Bob (real
    browser). Bob observes Alice's real identity, verifies the
    fingerprint via the real chat UI, then approves the request from
    the real Inbox tab -- proving the whole round trip, not just that
    a button exists."""

    alice_payload = desktop_app["register"]("alice_ibx_")
    alice = desktop_app["launch"](alice_payload)

    bob_payload = _register("bob_ibx_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        # Bob observes Alice's identity (a real, unforged broadcast) --
        # required before Bob's own confirmPeerVerified() can succeed.
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        page.fill("#peerUsername", alice.username)
        assert _wait_for(lambda: alice.username in page.inner_text("#fingerprintDisplay"))

        # Alice requests verification from Bob via the real production
        # path (server/client_handler.py::handle_verification_request()).
        alice.request_verification(bob_username)

        page.click('.tab-btn[data-tab="inbox"]')
        assert _wait_for(lambda: alice.username in page.inner_text("#inboxList"), attempts=200, interval=0.1)

        page.click('#inboxList .notif-card .btn-primary')

        # Bob is now genuinely VERIFIED of Alice, via the real
        # confirmPeerVerified() call respondToInbox() makes internally
        # -- not a fake local flag.
        assert _wait_for(lambda: page.evaluate(f"window.__session.isPeerVerified({alice.username!r})"))
    finally:
        alice.disconnect()
        _delete(bob_payload["username"])


def test_web_group_info_remove_member_real_ui(running_server, gateway_url, browser_page, desktop_app):
    """The web admin creates a group, then removes a member from the
    real Group Info panel -- server-confirmed, not a client-only
    illusion."""

    admin_payload = _register("wadmin_")
    member_payload = desktop_app["register"]("wmember_")
    member = desktop_app["launch"](member_payload)

    try:
        _connect_browser(browser_page, gateway_url, admin_payload)
        page = browser_page["page"]

        page.click('.tab-btn[data-tab="groups"]')
        # Phase 1.5 UI: the create-group form lives in a modal opened
        # from the Groups panel (it is no longer permanently on screen).
        page.click("#openCreateGroupBtn")
        page.fill("#groupName", "remove-member-group")
        page.fill("#groupMembers", member.username)
        page.click("#createGroupBtn")

        def _group_exists():
            groups = page.evaluate("Array.from(window.__session.groups.values()).map(g => g.name)")
            return "remove-member-group" in groups

        assert _wait_for(_group_exists)

        page.click('.row-card:has-text("remove-member-group")')
        page.click("#groupInfoBtn")
        assert _wait_for(lambda: member.username in page.inner_text("#groupInfoMembers"))

        page.click(f'#groupInfoMembers .member-row:has-text("{member.username}") .btn-danger')

        # UI reflects the removal...
        assert _wait_for(lambda: member.username not in page.inner_text("#groupInfoMembers"))
        # ...and so does the REMOVED member's own, completely separate
        # real desktop session, via the real group_member_left server
        # broadcast -- proving this was a genuine, server-enforced
        # removal, not a client-only illusion on the admin's screen.
        assert _wait_for(lambda: not any(
            s.is_group and s.group_name == "remove-member-group"
            for s in member.conversation_store.get_all()
        ))
    finally:
        member.disconnect()
        _delete(admin_payload["username"])
        _delete(member_payload["username"])
