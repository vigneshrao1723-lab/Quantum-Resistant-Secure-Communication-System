"""
The Website reconnects by itself when the server comes back after an outage.

A reconnect attempt re-authenticates over a short-lived WebSocket. While the server is down the gateway
closes that socket at once; the request helper used to wait for a reply that could never come, so the
first failed attempt hung forever, no further attempt was ever made, and the page showed "Reconnecting"
for good. Found by the acceptance suite's outage scenario.
"""

from tests.tls_test_support import start_test_server
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _connect_browser,
    _delete,
    _register,
    _wait_for,
    browser_page,
    gateway_module,
    gateway_url,
    running_server,
    static_url,
)


def _status(page):
    return page.inner_text("#connectionStatus").strip().lower()


def test_the_page_reconnects_on_its_own_after_the_server_was_down_and_returns(
    running_server, gateway_url, browser_page, monkeypatch
):
    payload = _register("outage_")
    second_server = None
    try:
        _connect_browser(browser_page, gateway_url, payload)
        page = browser_page["page"]
        assert _wait_for(lambda: _status(page) == "connected")

        running_server.shutdown()  # the server goes away under a live page
        assert _wait_for(lambda: _status(page) == "reconnecting", attempts=200, interval=0.1)

        # Let at least one reconnect attempt fail while the server is still down -- the case that used to hang.
        assert _wait_for(lambda: "Reconnect attempt failed" in page.inner_text("#log"), attempts=300, interval=0.1), (
            "a reconnect attempt against a down server never failed: it is hanging"
        )

        second_server = start_test_server()  # the server returns (a new instance, same database)
        _state, new_port = second_server
        monkeypatch.setattr(gateway_module, "SERVER_PORT", new_port)

        assert _wait_for(lambda: _status(page) == "connected", attempts=400, interval=0.1), (
            "the page did not reconnect after the server returned: " + page.inner_text("#log")[-300:]
        )
        assert "Reconnected." in page.inner_text("#log")
    finally:
        if second_server is not None:
            second_server.shutdown()
        _delete(payload["username"])
