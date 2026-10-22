"""
A request sent the instant a WebSocket opens must always get its reply.

A browser sends its first request (registration, login) the moment the socket
opens, while the gateway is still finishing its TLS connection to the server.
On the acceptance stack about one request in two hundred never got an answer:
the browser waited, the server logged a connection that never sent a frame.
Controlled comparison of the same loop against the real gateway and server:

    TLS 1.3 session tickets on  (before):  2 / 400, then 10+ / 2000 unanswered
    session tickets off         (after) :  0 / 2000 unanswered

The cause is the server's post-handshake session tickets arriving on the
connection while the gateway's reader thread is blocked on it and its other
thread is starting the first write; this application never resumes TLS
sessions, so the server now sends none (security/tls.py).

The loop below is statistical by nature (the failure was ~0.5%), so it uses
enough connections to expose a regression in almost every run, and gives up
after a few misses rather than waiting out each timeout.
"""

import json
import uuid

from websockets.sync.client import connect

from security.tls import build_server_context
from tests.test_web_browser_e2e import gateway_url, running_server  # noqa: F401 -- fixtures reused

CONNECTIONS = 800
REPLY_TIMEOUT_SECONDS = 3
GIVE_UP_AFTER_MISSES = 3


def test_server_issues_no_tls_session_tickets():
    assert build_server_context().num_tickets == 0


def test_first_request_sent_as_the_socket_opens_is_always_answered(running_server, gateway_url):
    missed = []

    for attempt in range(CONNECTIONS):
        # A registration the server rejects during validation: a real round trip, no account created.
        packet = {
            "type": "register_request",
            "request_id": str(uuid.uuid4()),
            "full_name": "x",
            "username": f"gw_probe_{attempt}",
            "email": "",
            "phone_number": "",
            "password": "short",
            "confirm_password": "different",
        }
        with connect(gateway_url, open_timeout=10) as socket_to_gateway:
            socket_to_gateway.send(json.dumps(packet))  # sent immediately, no waiting for anything
            try:
                reply = json.loads(socket_to_gateway.recv(timeout=REPLY_TIMEOUT_SECONDS))
            except TimeoutError:
                missed.append(attempt)
                if len(missed) >= GIVE_UP_AFTER_MISSES:
                    break
                continue

        assert reply.get("type") == "register_result" and reply.get("success") is False

    assert not missed, f"first requests with no reply: connections {missed} (of {CONNECTIONS})"
