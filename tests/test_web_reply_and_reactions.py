"""
Website: replies quote the right message (text, or a label for media) and reactions show on every
kind of message, consistently with the Desktop, through reload, without duplicates.

Real Chrome, gateway, server and a real Desktop peer.
"""

import pytest

from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _delete,
    _open_direct,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_messenger_layout_and_parity import _pair
from tests.test_web_phase19_24_lifecycle_ui import (
    _click_menu_action,
    _confirm_modal,
    _establish_key_in_browser,
)

THUMBS = "\U0001F44D"


@pytest.fixture()
def chat(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    page.fill("#peerUsername", alice.username)
    page.press("#peerUsername", "Enter")
    page.wait_for_selector("#chatView:not([hidden])")
    _establish_key_in_browser(page, alice.username)
    _open_direct(alice, bob_payload["username"])
    yield alice, bob_payload, page
    _delete(bob_payload["username"])


def _send(page, text):
    page.fill("#messageText", text)
    page.click("#sendBtn")
    assert _wait_for(lambda: page.locator(f"#messages .bubble:has(.bubble-text:text-is('{text}'))").count() == 1)


def _reply_to(page, locator, text):
    page.locator(locator).first.click(button="right")
    _click_menu_action(page, "Reply")
    assert _wait_for(lambda: "Replying to" in page.inner_text("#composerContext"))
    _send(page, text)


def _quote(page, text):
    """The quote block of the bubble whose own text is ``text``: (author, excerpt, is_link)."""
    bubble = page.locator(f"#messages .bubble:has(.bubble-text:text-is('{text}'))")
    return bubble.evaluate("""(el) => {
      const q = el.querySelector('.bubble-reply-preview');
      if (!q) return null;
      return [q.querySelector('.reply-author').textContent, q.querySelector('.reply-text').textContent,
              q.classList.contains('is-link'), q.classList.contains('is-unavailable')];
    }""")


def _message_id_of(alice, text):
    return next(r["message_id"] for r in alice.load_conversation_history(alice.current_chat, is_group=False) if r["text"] == text)


# ====================================================================== replies


def test_a_reply_quotes_its_original_with_the_right_author_and_jumps_to_it(chat):
    alice, bob_payload, page = chat
    _send(page, "the original")
    page.wait_for_timeout(400)                                           # the original gets its server id

    _reply_to(page, ".bubble-text:text-is('the original')", "the reply")

    author, excerpt, is_link, unavailable = _quote(page, "the reply")
    assert author == "You" and excerpt == "the original" and is_link and not unavailable

    # Clicking (and Enter on) the quote scrolls to and highlights the original.
    page.wait_for_timeout(700)                                           # (let the new bubble settle)
    page.locator("#messages .bubble:has(.bubble-text:text-is('the reply')) .bubble-reply-preview").click()
    assert page.locator("#messages .bubble.is-flash .bubble-text:text-is('the original')").count() == 1
    assert page.evaluate("document.querySelector('.bubble-reply-preview').getAttribute('role')") == "button"
    assert page.evaluate("document.querySelector('.bubble-reply-preview').tabIndex") == 0


def test_a_reply_from_the_desktop_names_the_desktop_user_and_quotes_the_right_message(chat):
    alice, bob_payload, page = chat
    _send(page, "first thing")
    _send(page, "second thing")
    page.wait_for_timeout(400)
    first_id = _message_id_of(alice, "first thing")

    alice.send_chat_message("answering the first", reply_to_message_id=first_id)

    assert _wait_for(lambda: page.locator("#messages .bubble:has(.bubble-text:text-is('answering the first'))").count() == 1,
                     attempts=200, interval=0.1)
    author, excerpt, is_link, _unavailable = _quote(page, "answering the first")
    assert excerpt == "first thing"                                      # by id -- not "second thing", not guessed by text
    assert author == "You" and is_link
    # The reply's own sender label is the Desktop user.
    assert page.locator("#messages .bubble:has(.bubble-text:text-is('answering the first')) .bubble-sender").count() == 1


def test_replies_to_media_quote_a_label_never_the_media(chat, tmp_path):
    alice, bob_payload, page = chat
    voice, photo, doc = tmp_path / "voice-message.m4a", tmp_path / "pic.png", tmp_path / "report.pdf"
    voice.write_bytes(b"\x00 voice " * 50)
    photo.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    doc.write_bytes(b"%PDF-1.7 " + b"x" * 80)
    for path in (voice, photo, doc):
        alice.send_attachment(str(path))
    assert _wait_for(lambda: page.locator("#messages .bubble.is-attachment").count() == 3, attempts=200, interval=0.1)

    expectations = [
        ("#messages .bubble[data-payload-type='voice']", "\U0001F3A4 Voice message"),
        ("#messages .bubble[data-payload-type='image']", "\U0001F4F7 Photo"),
        ("#messages .bubble[data-payload-type='file']", "\U0001F4C4 report.pdf"),
    ]
    for index, (selector, label) in enumerate(expectations):
        text = f"re media {index}"
        _reply_to(page, selector, text)
        author, excerpt, is_link, _ = _quote(page, text)
        assert excerpt == label and is_link
        assert author != "You"                                          # the media was the Desktop user's


def test_a_deleted_original_is_quoted_as_deleted(chat):
    alice, bob_payload, page = chat
    _send(page, "about to vanish")
    page.wait_for_timeout(400)
    _reply_to(page, ".bubble-text:text-is('about to vanish')", "reply to it")
    assert _quote(page, "reply to it")[1] == "about to vanish"

    page.locator(".bubble-text:text-is('about to vanish')").click(button="right")
    _click_menu_action(page, "Delete for everyone")
    _confirm_modal(page, "Delete")

    assert _wait_for(lambda: _quote(page, "reply to it")[1] == "Message deleted", attempts=100, interval=0.1)


def test_a_reply_to_a_message_that_is_not_here_says_so_and_never_guesses(chat):
    alice, bob_payload, page = chat
    _send(page, "an unrelated message")
    conversation_id = page.evaluate(f"window.__session.directConversationIds.get({alice.username!r})")

    # A reply whose original is not in this conversation (e.g. older than what is loaded, or never
    # visible to this account): resolved by id, so it is shown as unavailable -- NOT matched by text.
    page.evaluate(
        """([cid, sender]) => window.__session.onMessage(cid, sender, 'a reply to something elsewhere',
                               {replyToMessageId: crypto.randomUUID(), messageId: crypto.randomUUID()})""",
        [conversation_id, alice.username],
    )

    author, excerpt, is_link, unavailable = _quote(page, "a reply to something elsewhere")
    assert excerpt == "Original message unavailable" and not is_link and unavailable
    assert "unrelated" not in excerpt


def test_replies_still_resolve_after_the_history_is_reloaded(chat):
    alice, bob_payload, page = chat
    _send(page, "kept original")
    page.wait_for_timeout(400)
    _reply_to(page, ".bubble-text:text-is('kept original')", "kept reply")
    page.wait_for_timeout(400)

    page.click("#settingsToggleBtn")
    page.fill("#peerUsername", alice.username)
    page.press("#peerUsername", "Enter")
    page.wait_for_selector("#chatView:not([hidden])")

    assert _wait_for(lambda: _quote(page, "kept reply") is not None, attempts=200, interval=0.1)
    assert _quote(page, "kept reply")[:3] == ["You", "kept original", True]


# ====================================================================== reactions


def _chips(page, selector):
    return page.eval_on_selector_all(
        f"{selector} + .bubble-reactions .reaction-chip, {selector} ~ .bubble-reactions .reaction-chip",
        "els => els.map(e => e.textContent.replace(/\\s+/g, ''))",
    )


def test_a_reaction_on_a_media_message_shows_on_the_website_and_the_desktop_and_survives_reload(chat, tmp_path):
    alice, bob_payload, page = chat
    clip = tmp_path / "voice-message.m4a"
    clip.write_bytes(b"\x00 voice " * 50)
    alice.send_attachment(str(clip))
    assert _wait_for(lambda: page.locator("#messages .bubble[data-payload-type='voice']").count() == 1, attempts=200, interval=0.1)
    message_id = page.locator("#messages .bubble[data-payload-type='voice']").get_attribute("data-message-id")
    seen = []
    alice.reaction_updated_received.connect(lambda cid, mid, actor, action, reaction: seen.append((mid, actor, action)))

    page.locator("#messages .bubble[data-payload-type='voice']").click(button="right")
    _click_menu_action(page, "React")
    page.click(".bubble-popup-emoji-row button >> nth=0")

    assert _wait_for(lambda: page.locator("#messages .reaction-chip").count() == 1, attempts=200, interval=0.1)
    assert page.inner_text("#messages .reaction-chip .reaction-count") == "1"
    assert _wait_for(lambda: any(a == "add" for _m, _u, a in seen), attempts=200, interval=0.1)
    assert (message_id, bob_payload["username"], "add") in seen

    # Reload the conversation: the chip is restored from history, once.
    page.click("#settingsToggleBtn")
    page.fill("#peerUsername", alice.username)
    page.press("#peerUsername", "Enter")
    page.wait_for_selector("#chatView:not([hidden])")
    assert _wait_for(lambda: page.locator("#messages .reaction-chip").count() == 1, attempts=200, interval=0.1)
    page.wait_for_timeout(500)
    assert page.locator("#messages .reaction-chip").count() == 1
    assert page.inner_text("#messages .reaction-chip .reaction-count") == "1"


def test_the_same_reaction_applied_repeatedly_is_one_chip_with_a_count_of_one(chat):
    alice, bob_payload, page = chat
    _send(page, "react to this")
    page.wait_for_timeout(400)
    message_id = page.locator(".bubble:has(.bubble-text:text-is('react to this'))").get_attribute("data-message-id")

    # The server can replay the same reaction (reconnect, history reload): never doubled.
    for _ in range(4):
        page.evaluate(
            """([mid, user, emoji]) => window.__session.onReactionUpdated(null, mid, user, 'add', emoji)""",
            [message_id, bob_payload["username"], THUMBS],
        )

    assert page.locator("#messages .reaction-chip").count() == 1
    assert page.inner_text("#messages .reaction-chip .reaction-count") == "1"
