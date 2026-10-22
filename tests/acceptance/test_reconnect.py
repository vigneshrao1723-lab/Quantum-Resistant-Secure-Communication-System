"""The server going away and coming back, as live users experience it."""

from tests.acceptance import desktop_driver as dd
from tests.acceptance.parties import converse, verify_pair
from tests.acceptance.web_driver import wait_until


def _web_status(party):
    return party.user.page.inner_text("#connectionStatus").strip().lower()


def test_clients_notice_an_outage_and_recover_when_the_server_returns(stack, party):
    web, desktop = party("web", "rc_web"), party("desktop", "rc_desk")
    verify_pair(web, desktop)
    converse(web, desktop, "before-outage")

    stack.stop_server()

    # Both tell the user. The Website says it is reconnecting; the Desktop says "Disconnected" and
    # offers a way back.
    wait_until(lambda: _web_status(web) == "reconnecting", 60, what="the Website to say it is reconnecting")
    desktop.app.wait_for(lambda: dd._exists(desktop.app, name="Sign in again"), timeout=60,
                         what="the Desktop's 'Sign in again' offer")
    assert any("Disconnected" in (e["name"] or "") for e in desktop.app.tree() if "StatusBarWidget" in (e["id"] or ""))

    stack.start_server()

    # The Website reconnects by itself.
    wait_until(lambda: _web_status(web) == "connected", 150, what="the Website to reconnect")

    # On the Desktop the user takes the offer, signs in again and carries on where they left off.
    desktop.app.click(name="Sign in again")
    desktop.app.wait_for(lambda: dd._exists(desktop.app, id="AuthPrimaryAction"), timeout=30, what="the login form")
    desktop.login()
    desktop.open_chat_with(web)
    converse(web, desktop, "after-outage")

    assert not web.errors() and not desktop.errors()
