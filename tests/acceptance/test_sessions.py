"""Sign-in, sign-out, restart and offline recovery as users experience them."""

import uuid

from tests.acceptance import desktop_driver as dd
from tests.acceptance.conftest import new_identity
from tests.acceptance.parties import DesktopParty, WebParty, converse, verify_pair
from tests.acceptance.web_driver import WebUser, wait_until


def _count(text, needle):
    return text.count(needle)


def test_website_rejects_a_wrong_password_then_accepts_the_right_one(browser, stack):
    ident = new_identity("badpw")
    user = WebUser(browser, stack, ident["username"], ident["phone"], ident["password"])
    try:
        user.register()
        user.page.fill("#phoneNumber", ident["phone"])
        user.page.fill("#password", ident["password"] + "x")
        user.page.click("#connectBtn")
        wait_until(lambda: "is-error" in (user.page.get_attribute("#authStatus", "class") or ""), 20,
                   what="an error for the wrong password")
        assert not user.page.is_visible("#screen-app")

        user.page.fill("#password", ident["password"])
        user.page.click("#connectBtn")
        wait_until(lambda: user.page.is_visible("#screen-app"), 30, what="the app after the correct password")
    finally:
        user.close()


def test_desktop_rejects_a_wrong_password_then_accepts_the_right_one(desktop_user):
    app = desktop_user("badpw")
    dd.register(app, app.username, app.phone, app.password)

    app.set_text(app.phone, id="PhoneInput")
    app.set_text(app.password + "x", id="PasswordInput")
    app.click(id="AuthPrimaryAction")
    app.wait_for(lambda: any("Invalid phone number or password" in e["name"]
                             for e in app.tree() if "LoginWindow" in e["id"]),
                 timeout=30, what="the 'Invalid phone number or password' message")
    assert not any("StatusBarWidget" in e["id"] for e in app.tree()), "the wrong password signed in"

    dd.login(app, app.phone, app.password)


def test_logout_then_login_restores_history_without_duplicates(party):
    a, b = party("web", "relog_a"), party("web", "relog_b")
    verify_pair(a, b)
    converse(a, b, "before-logout")
    tag = uuid.uuid4().hex[:6]
    sent = f"kept-{tag}"
    a.send(sent)
    b.wait_for_text(sent)

    b.logout()
    b.login()
    b.open_chat_with(a)
    b.user.chat_tool("loadHistoryBtn")
    wait_until(lambda: sent in b.visible_text(), 30, what="history after logging back in")
    assert _count(b.visible_text(), sent) == 1, "a message was shown twice after reconnecting"


def test_messages_sent_while_offline_arrive_once_on_return(party):
    a, b = party("web", "off_a"), party("web", "off_b")
    verify_pair(a, b)
    converse(a, b, "warm-up")

    b.logout()
    tag = uuid.uuid4().hex[:6]
    missed = [f"missed-{i}-{tag}" for i in range(3)]
    for text in missed:
        a.send(text)

    b.login()
    b.open_chat_with(a)
    b.user.chat_tool("loadHistoryBtn")
    for text in missed:
        wait_until(lambda t=text: t in b.visible_text(), 30, what=f"{text} after returning")
        assert _count(b.visible_text(), text) == 1


def test_desktop_restart_keeps_identity_and_history(party):
    a, d = party("web", "rs_web"), party("desktop", "rs_desk")
    verify_pair(a, d)
    converse(a, d, "before-restart")
    tag = uuid.uuid4().hex[:6]
    sent = f"survives-{tag}"
    a.send(sent)
    d.wait_for_text(sent)

    identity_before = d.own_fingerprint()
    d.restart()
    d.login()
    d.open_chat_with(a)  # already verified: no verification dialog needed
    assert d.own_fingerprint() == identity_before, "the Desktop identity changed across a restart"
    d.wait_for_text(sent, timeout=40)
    assert _count(d.visible_text(), sent) == 1
