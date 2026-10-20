"""
Web client: registration and login through the real page.

Registration is a one-shot request on its own throwaway connection and is
never followed by an automatic login (the same contract Desktop and Android
have), so a registered account is proven by logging in with it, and a rejected
registration is proven by the database not containing the account.
"""

import uuid

from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    PASSWORD,
    _register,
    _wait_for,
    browser_page,
    gateway_url,
    running_server,
    static_url,
)


def _user(username):
    db = SessionLocal()
    try:
        return UserRepository(db).get_by_username(username)
    finally:
        db.close()


def _purge(username):
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


def _new_identity():
    suffix = uuid.uuid4().hex[:10]
    return {
        "username": f"webreg_{suffix}",
        "phone": f"+91{uuid.uuid4().int % 10**12:012d}",
    }


def _open_register_form(page, gateway_url):
    page.fill("#gatewayUrl", gateway_url)
    page.click("#toggleModeBtn")
    assert page.is_visible("#regUsername")
    assert page.is_visible("#regConfirmPassword")
    assert page.inner_text("#connectBtn") == "Register"


def _fill_register(page, username, phone, password, confirm):
    page.fill("#regUsername", username)
    page.fill("#phoneNumber", phone)
    page.fill("#password", password)
    page.fill("#regConfirmPassword", confirm)


def _status(page):
    return page.inner_text("#authStatus").strip()


def test_register_then_login_through_the_page(running_server, gateway_url, browser_page):
    page = browser_page["page"]
    identity = _new_identity()
    try:
        _open_register_form(page, gateway_url)
        _fill_register(page, identity["username"], identity["phone"], PASSWORD, PASSWORD)
        page.click("#connectBtn")

        assert _wait_for(lambda: "Account created" in _status(page), attempts=200, interval=0.1)
        # Back on the login form, no session started yet, account really exists.
        assert page.inner_text("#connectBtn") == "Login"
        assert not page.is_visible("#regUsername")
        assert page.evaluate("window.__session === undefined || window.__session === null")
        assert _user(identity["username"]) is not None

        page.fill("#phoneNumber", identity["phone"])
        page.fill("#password", PASSWORD)
        page.click("#connectBtn")

        assert _wait_for(lambda: "Connected and authenticated as" in page.inner_text("#log"), attempts=300, interval=0.1)
        assert page.evaluate("window.__session.username") == identity["username"]
        assert page.is_visible("#screen-app")
    finally:
        _purge(identity["username"])


def test_registration_rejects_mismatched_passwords_and_creates_nothing(running_server, gateway_url, browser_page):
    page = browser_page["page"]
    identity = _new_identity()
    try:
        _open_register_form(page, gateway_url)
        _fill_register(page, identity["username"], identity["phone"], PASSWORD, PASSWORD + "x")
        page.click("#connectBtn")

        assert _wait_for(lambda: _status(page) != "" and "Creating" not in _status(page), attempts=200, interval=0.1)
        assert "is-error" in page.get_attribute("#authStatus", "class")
        assert "Account created" not in _status(page)
        assert _user(identity["username"]) is None
        assert page.inner_text("#connectBtn") == "Register"  # still on the form, nothing half-done
    finally:
        _purge(identity["username"])


def test_registration_rejects_a_weak_password_and_creates_nothing(running_server, gateway_url, browser_page):
    page = browser_page["page"]
    identity = _new_identity()
    try:
        _open_register_form(page, gateway_url)
        _fill_register(page, identity["username"], identity["phone"], "weak", "weak")
        page.click("#connectBtn")

        assert _wait_for(lambda: "is-error" in page.get_attribute("#authStatus", "class"), attempts=200, interval=0.1)
        assert _user(identity["username"]) is None
    finally:
        _purge(identity["username"])


def test_registering_an_existing_username_is_refused_and_keeps_the_original_account(
    running_server, gateway_url, browser_page
):
    page = browser_page["page"]
    existing = _register("dupe_")  # a real, already-registered account
    try:
        _open_register_form(page, gateway_url)
        _fill_register(page, existing["username"], f"+91{uuid.uuid4().int % 10**12:012d}", PASSWORD, PASSWORD)
        page.click("#connectBtn")

        assert _wait_for(lambda: "is-error" in page.get_attribute("#authStatus", "class"), attempts=200, interval=0.1)
        assert "Account created" not in _status(page)

        # The original account is untouched: its own phone number + password still log in.
        db = SessionLocal()
        try:
            users = [u for u in [UserRepository(db).get_by_username(existing["username"])] if u]
        finally:
            db.close()
        assert len(users) == 1
    finally:
        _purge(existing["username"])


def test_the_form_toggles_between_login_and_register_and_clears_the_status(running_server, gateway_url, browser_page):
    page = browser_page["page"]

    assert page.inner_text("#connectBtn") == "Login"
    assert not page.is_visible("#regUsername")

    page.click("#toggleModeBtn")
    assert page.inner_text("#connectBtn") == "Register"
    assert page.inner_text("#toggleModeBtn") == "Already have an account? Login"
    assert page.is_visible("#regUsername") and page.is_visible("#regConfirmPassword")

    page.click("#toggleModeBtn")
    assert page.inner_text("#connectBtn") == "Login"
    assert not page.is_visible("#regUsername") and not page.is_visible("#regConfirmPassword")
    assert _status(page) == ""


def test_login_with_an_unreachable_gateway_shows_an_error_and_stays_on_the_login_screen(
    running_server, gateway_url, browser_page
):
    page = browser_page["page"]
    page.fill("#gatewayUrl", "ws://127.0.0.1:1")  # nothing listens on port 1
    page.fill("#phoneNumber", "+910000000000")
    page.fill("#password", PASSWORD)
    page.click("#connectBtn")

    assert _wait_for(lambda: "is-error" in page.get_attribute("#authStatus", "class"), attempts=300, interval=0.1)
    assert page.is_visible("#screen-login")
    assert not page.is_visible("#screen-app")
