"""
Web: group messages from before a key rotation stay readable.

The Web client used to keep only the newest group key, so after a rotation (and
a page reload) every older group message was skipped as undecryptable. Desktop
and Android have always kept every epoch. The Web client now keeps each key by
epoch (and persists them), selecting the key by the message's epoch -- which is
covered by the message signature that is verified before any key is used.

Real Chrome, real gateway and server, a real Desktop session as the other member.
"""

from domain.conversation_summary import ConversationSummary
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _connect_browser,
    _delete,
    _wait_for,
    browser_page,
    chat_tool,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_messenger_layout_and_parity import _group_with_web_member, _pair


def _desktop_opens_group(alice, conversation_id, name):
    alice.set_current_chat(
        ConversationSummary(conversation_id=conversation_id, username=None, is_online=True,
                            latest_message=None, is_group=True, group_name=name)
    )


def _rotate_to_epoch_two(page, conversation_id, members):
    """The browser answers the server's order to distribute the group's next key epoch."""
    reservation = page.evaluate(
        "(cid) => window.__session._sendRequest({ type: 'epoch_reservation_request', conversation_id: cid })",
        conversation_id,
    )
    assert reservation.get("epoch") == 2, reservation
    page.evaluate(
        "(p) => window.__session._handleIncoming({ data: JSON.stringify(p) })",
        {"type": "group_key_rotation_required", "conversation_id": conversation_id, "epoch": 2, "members": list(members)},
    )


def test_messages_from_before_a_rotation_are_still_readable_after_reload(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        conversation_id = _group_with_web_member(alice, page, "history-group")
        _desktop_opens_group(alice, conversation_id, "history-group")

        before = "sent under epoch one"
        alice.send_chat_message(before)
        page.click('.tab-btn[data-tab="groups"]')
        page.click('.row-card:has-text("history-group")')
        assert _wait_for(lambda: before in page.inner_text("#groupMessages"), attempts=200, interval=0.1)

        # The browser rotates the key to epoch 2; the Desktop member installs it.
        _rotate_to_epoch_two(page, conversation_id, [alice.username])
        assert _wait_for(lambda: alice.key_manager.has_key(conversation_id, epoch=2), attempts=200, interval=0.1)
        assert page.evaluate(f"window.__session.sessionKeys.get({conversation_id!r}).epoch") == 2

        after = "sent under epoch two"
        alice.send_chat_message(after)
        assert _wait_for(lambda: after in page.inner_text("#groupMessages"), attempts=200, interval=0.1)


        # Reload: only the server's history and the persisted state remain.
        page.reload()
        page.wait_for_load_state("load")
        _connect_browser(browser_page, gateway_url, bob_payload)
        page.click('.tab-btn[data-tab="groups"]')
        page.click('.row-card:has-text("history-group")')
        chat_tool(page, "loadGroupHistoryBtn")

        assert _wait_for(lambda: before in page.inner_text("#groupMessages"), attempts=300, interval=0.1), (
            "a message from before the rotation was dropped"
        )
        assert _wait_for(lambda: after in page.inner_text("#groupMessages"), attempts=300, interval=0.1)
        assert page.evaluate(f"window.__session.sessionKeys.get({conversation_id!r}).epoch") == 2
        # Both epochs' keys are held, and the SENDING key is still the newest.
        assert sorted(page.evaluate(f"Array.from(window.__session.keyHistory.get({conversation_id!r}).keys())")) == [1, 2]
    finally:
        _delete(bob_payload["username"])


def test_a_late_older_key_never_replaces_the_sending_key(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        conversation_id = _group_with_web_member(alice, page, "order-group")
        _rotate_to_epoch_two(page, conversation_id, [alice.username])
        assert page.evaluate(f"window.__session.sessionKeys.get({conversation_id!r}).epoch") == 2

        result = page.evaluate(
            """(cid) => {
                const s = window.__session;
                const newest = s.sessionKeys.get(cid).key;
                s._installSessionKey(cid, new Uint8Array(32).fill(7), 1);   // an old key arrives late
                const now = s.sessionKeys.get(cid);
                return { epoch: now.epoch, sameKey: now.key === newest, stillHasOld: s.keyHistory.get(cid).has(1) };
            }""",
            conversation_id,
        )

        assert result == {"epoch": 2, "sameKey": True, "stillHasOld": True}
    finally:
        _delete(bob_payload["username"])


def test_a_message_of_an_unknown_epoch_is_not_decrypted_with_the_wrong_key(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        conversation_id = _group_with_web_member(alice, page, "unknown-epoch-group")

        key_for = page.evaluate(
            "(cid) => ({ known: window.__session._keyForEpoch(cid, 1) !== null,"
            " unknown: window.__session._keyForEpoch(cid, 9) })",
            conversation_id,
        )

        assert key_for == {"known": True, "unknown": None}
    finally:
        _delete(bob_payload["username"])
