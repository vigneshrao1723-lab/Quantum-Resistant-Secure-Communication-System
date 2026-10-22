"""
Closing the browser's WebSocket must close its connection to the server.

The gateway used to wait for BOTH directions to finish. When a browser closed
its WebSocket cleanly (Logout, closing the tab) with no server traffic pending,
the server-bound connection stayed open: the user kept showing as online to
everyone else, and the server held the connection, until some unrelated event
happened to make the gateway try a send. Found by the acceptance suite (a
contact still "Online" after logging out).
"""

from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _connect_browser,
    _delete,
    _register,
    _wait_for,
    browser_page,
    gateway_url,
    running_server,
    static_url,
)


def _usernames_on_server(state):
    return {record.get("username") for record in list(state.clients.values())}


def test_logging_out_of_the_website_drops_the_server_connection_promptly(running_server, gateway_url, browser_page):
    state, _port = running_server
    payload = _register("teardown_")
    try:
        _connect_browser(browser_page, gateway_url, payload)
        page = browser_page["page"]
        assert _wait_for(lambda: payload["username"] in _usernames_on_server(state))

        page.click("#logoutBtn")

        assert _wait_for(lambda: payload["username"] not in _usernames_on_server(state), attempts=100, interval=0.1), (
            "the server still holds the connection of a user who logged out"
        )
    finally:
        _delete(payload["username"])


def test_closing_the_page_also_drops_the_server_connection(running_server, gateway_url, browser_page):
    state, _port = running_server
    payload = _register("teardown2_")
    try:
        _connect_browser(browser_page, gateway_url, payload)
        page = browser_page["page"]
        assert _wait_for(lambda: payload["username"] in _usernames_on_server(state))

        page.goto("about:blank")  # leaves the page, which closes its WebSocket

        assert _wait_for(lambda: payload["username"] not in _usernames_on_server(state), attempts=100, interval=0.1), (
            "the server still holds the connection of a user whose page is gone"
        )
    finally:
        _delete(payload["username"])
