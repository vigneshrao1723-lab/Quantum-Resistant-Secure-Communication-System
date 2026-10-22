"""
Desktop: replies and reactions on every kind of message, like the Website.

* A reply quotes its original by the original's stable id -- the right sender, a short excerpt for
  text or a label for media -- on text, image, file, voice and video bubbles alike.
* An original that is deleted, or that is not in this conversation, is shown as such; a reply never
  resolves by matching text.
* Clicking the quote asks the transcript to scroll to the original; the keyboard can do the same.
* Reactions show as one pill per emoji with a count, on every kind of bubble, without duplicates.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QApplication

from domain.payload_type import PayloadType
from gui.message_widget import MessageWidget

_app = QApplication.instance() or QApplication([])

THUMBS, HEART = "\U0001F44D", "❤️"


def _png():
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    image = QImage(40, 30, QImage.Format_RGB32)
    image.fill(0xFF3366CC)
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(buffer.data())


@pytest.fixture()
def transcript():
    widget = MessageWidget()
    widget.resize(700, 600)
    widget.own_username = "me_handle"
    widget.peer_display_name = "Alice"
    widget.show()
    yield widget
    widget.clear_messages()
    widget.close()


def _text(widget, text, message_id, kind="received", sender="alice_handle"):
    if kind == "sent":
        bubble = widget.add_sent_message(text, message_id=message_id)
    else:
        bubble = widget.add_received_message(sender, text, message_id=message_id)
    return bubble


def _voice(widget, message_id):
    return widget.add_received_file(
        "alice_handle", b"\x00" * 64, {"filename": "voice-message.m4a", "mime_type": "audio/mp4"},
        message_id=message_id, payload_type=PayloadType.VOICE,
    )


# ------------------------------------------------------------------ replies


def test_a_reply_to_a_text_message_shows_who_wrote_it_and_an_excerpt(transcript):
    _text(transcript, "see you at noon", "m1")
    reply = _text(transcript, "ok!", "m2", kind="sent")

    transcript.set_reply_reference(reply, "m1")

    quote = reply._reply_quote
    assert not quote.isHidden()
    assert quote.author_label.text() == "alice_handle"   # the sender label the original carries
    assert quote.text == "see you at noon"
    assert quote._clickable


def test_a_reply_to_your_own_message_names_you(transcript):
    _text(transcript, "my own words", "m1", kind="sent")
    reply = _text(transcript, "and again", "m2")

    transcript.set_reply_reference(reply, "m1")

    assert reply._reply_quote.author_label.text() == "You"


def test_a_long_original_is_cut_to_a_short_excerpt(transcript):
    _text(transcript, "word " * 100, "m1")
    reply = _text(transcript, "ok", "m2", kind="sent")

    transcript.set_reply_reference(reply, "m1")

    assert len(reply._reply_quote.text) <= 80
    assert reply._reply_quote.text.endswith("…")


def test_replies_to_media_quote_a_label_never_the_media(transcript):
    transcript.add_received_image("alice_handle", _png(), message_id="img", content_metadata={"filename": "p.png"})
    _voice(transcript, "voice")
    transcript.add_received_file(
        "alice_handle", b"data", {"filename": "report.pdf"}, message_id="doc", payload_type=PayloadType.FILE
    )
    transcript.add_received_file(
        "alice_handle", b"\x00" * 64, {"filename": "v.mp4", "mime_type": "video/mp4"}, message_id="vid",
        payload_type=PayloadType.VIDEO,
    )

    expected = {
        "img": "\U0001F4F7 Photo",
        "voice": "\U0001F3A4 Voice message",
        "vid": "\U0001F3AC Video message",
        "doc": "\U0001F4C4 report.pdf",
    }
    for original_id, label in expected.items():
        reply = _text(transcript, f"re {original_id}", f"r-{original_id}", kind="sent")
        transcript.set_reply_reference(reply, original_id)
        assert reply._reply_quote.text == label, original_id


def test_every_kind_of_bubble_can_itself_be_a_reply(transcript):
    _text(transcript, "original", "m1")
    image = transcript.add_sent_image(_png(), message_id="i2", content_metadata={"filename": "p.png"})
    voice = transcript.add_sent_file(
        b"\x00" * 64, {"filename": "v.m4a", "mime_type": "audio/mp4"}, message_id="v2",
        payload_type=PayloadType.VOICE,
    )
    doc = transcript.add_sent_file(b"d", {"filename": "d.txt"}, message_id="d2")

    for bubble in (image, voice, doc):
        transcript.set_reply_reference(bubble, "m1")
        assert bubble._reply_quote.text == "original"
        assert bubble._reply_quote.author_label.text() == "alice_handle"


def test_a_deleted_original_is_quoted_as_deleted_and_not_clickable(transcript):
    original = _text(transcript, "secret text", "m1")
    reply = _text(transcript, "reply", "m2", kind="sent")
    transcript.set_reply_reference(reply, "m1")
    assert reply._reply_quote.text == "secret text"

    transcript.mark_message_deleted("m1")  # delete-for-everyone arrives later

    assert original.is_deleted
    assert reply._reply_quote.text == "Message deleted"
    assert "secret" not in reply._reply_quote.text
    assert not reply._reply_quote._clickable


def test_an_edited_original_updates_the_quote(transcript):
    _text(transcript, "first draft", "m1")
    reply = _text(transcript, "reply", "m2", kind="sent")
    transcript.set_reply_reference(reply, "m1")

    transcript.apply_edit_to_message("m1", "final wording", 1)

    assert reply._reply_quote.text == "final wording"


def test_an_original_outside_this_conversation_is_unavailable_never_guessed(transcript):
    # Another bubble happens to carry the very same text -- a reply must not be resolved by text.
    _text(transcript, "same words", "m-other-text")
    reply = _text(transcript, "reply", "m2", kind="sent")

    transcript.set_reply_reference(reply, "an-id-from-another-conversation")

    assert reply._reply_quote.text == "Original message unavailable"
    assert reply._reply_quote.author_label.text() == "Reply"
    assert not reply._reply_quote._clickable
    assert "same words" not in reply._reply_quote.text


def test_a_quote_resolves_when_the_original_arrives_later(transcript):
    reply = _text(transcript, "reply", "m2", kind="sent")
    transcript.set_reply_reference(reply, "m1")  # original not loaded yet
    assert reply._reply_quote.text == "Original message unavailable"

    _text(transcript, "now loaded", "m1")

    assert reply._reply_quote.text == "now loaded"
    assert reply._reply_quote._clickable


def test_the_quote_is_remembered_by_the_stable_id_for_navigation(transcript):
    _text(transcript, "target", "m1")
    reply = _text(transcript, "reply", "m2", kind="sent")
    transcript.set_reply_reference(reply, "m1")

    assert reply.reply_to_message_id == "m1"


def test_clicking_or_pressing_enter_on_a_quote_scrolls_to_and_highlights_the_original(transcript):
    for index in range(30):  # enough history that the original is off screen
        _text(transcript, f"filler {index}", f"f{index}")
    target = _text(transcript, "the original", "m1")
    for index in range(30, 60):
        _text(transcript, f"filler {index}", f"f{index}")
    reply = _text(transcript, "reply", "m2", kind="sent")
    transcript.set_reply_reference(reply, "m1")

    scrolled_to = []
    real = transcript.scroll_to_bubble
    transcript.scroll_to_bubble = lambda bubble: (scrolled_to.append(bubble), real(bubble))[1]

    reply._reply_quote.activated.emit()          # a click
    assert scrolled_to == [target]
    assert transcript._highlighted_bubble is target

    from PySide6.QtGui import QKeyEvent
    from PySide6.QtCore import QEvent
    reply._reply_quote.keyPressEvent(QKeyEvent(QEvent.KeyPress, Qt.Key_Return, Qt.NoModifier))
    assert scrolled_to == [target, target]       # the keyboard does the same
    assert reply._reply_quote.focusPolicy() == Qt.StrongFocus


def test_quoted_text_is_displayed_literally_not_parsed(transcript):
    _text(transcript, '<b>bold</b><img src="file:///etc/passwd">', "m1")
    reply = _text(transcript, "reply", "m2", kind="sent")

    transcript.set_reply_reference(reply, "m1")

    assert reply._reply_quote.text_label.textFormat() == Qt.PlainText
    assert "<b>bold</b>" in reply._reply_quote.text


def test_a_reply_grows_its_row_so_the_quote_is_not_clipped(transcript):
    _text(transcript, "original", "m1")
    reply = _text(transcript, "reply", "m2", kind="sent")
    before = reply._list_item.sizeHint().height()

    transcript.set_reply_reference(reply, "m1")

    assert reply._list_item.sizeHint().height() > before


def test_the_row_text_for_assistive_technology_includes_the_quote(transcript):
    _text(transcript, "see you at noon", "m1")
    reply = _text(transcript, "ok!", "m2", kind="sent")

    transcript.set_reply_reference(reply, "m1")

    assert "Reply to: see you at noon" in reply._list_item.data(Qt.AccessibleTextRole)


def test_switching_conversations_forgets_pending_quotes(transcript):
    _text(transcript, "original", "m1")
    reply = _text(transcript, "reply", "m2", kind="sent")
    transcript.set_reply_reference(reply, "m1")

    transcript.clear_messages()
    _text(transcript, "different chat", "m1")  # same id in another conversation's transcript

    assert transcript._replies_by_target == {}


# ------------------------------------------------------------------ reactions


def _reaction(user, emoji):
    return {"user": user, "reaction": emoji}


def test_reactions_show_one_pill_per_emoji_with_a_count_on_every_bubble_kind(transcript):
    bubbles = [
        _text(transcript, "text", "t1"),
        transcript.add_received_image("alice_handle", _png(), message_id="i1", content_metadata={"filename": "p.png"}),
        _voice(transcript, "v1"),
        transcript.add_received_file("alice_handle", b"d", {"filename": "d.txt"}, message_id="d1"),
    ]
    reactions = [_reaction("alice_handle", THUMBS), _reaction("bob", THUMBS), _reaction("alice_handle", HEART)]

    for bubble in bubbles:
        bubble.update_reactions(reactions)
        strip = bubble._reactions_strip
        assert not strip.isHidden()
        assert [pill.text() for pill in strip.pills] == [f"{THUMBS} 2", f"{HEART} 1"]


def test_applying_the_same_reactions_again_never_duplicates_pills(transcript):
    bubble = _text(transcript, "hello", "t1")
    reactions = [_reaction("alice_handle", THUMBS)]

    for _ in range(5):          # history reload, repeated notifications
        bubble.update_reactions(reactions)

    assert [pill.text() for pill in bubble._reactions_strip.pills] == [f"{THUMBS} 1"]


def test_the_same_person_reacting_with_the_same_emoji_twice_counts_once(transcript):
    bubble = _text(transcript, "hello", "t1")

    bubble.update_reactions([_reaction("bob", THUMBS), _reaction("bob", THUMBS)])

    assert [pill.text() for pill in bubble._reactions_strip.pills] == [f"{THUMBS} 1"]


def test_removing_the_last_reaction_hides_the_strip(transcript):
    bubble = _text(transcript, "hello", "t1")
    bubble.update_reactions([_reaction("alice_handle", THUMBS)])
    bubble.update_reactions([])

    assert bubble._reactions_strip.isHidden()
    assert bubble.reactions == []


def test_reaction_pill_tooltips_name_who_reacted_by_display_name(transcript):
    transcript.name_for = {"alice_handle": "Alice", "bob_handle": "Bob"}.get
    transcript.own_username = "me_handle"
    bubble = _text(transcript, "hello", "t1")
    bubble._name_for, bubble._own_username = transcript.name_for, transcript.own_username

    bubble.update_reactions([_reaction("alice_handle", THUMBS), _reaction("me_handle", THUMBS)])

    assert bubble._reactions_strip.pills[0].toolTip() == "Alice, You"


def test_a_reaction_update_arriving_by_message_id_reaches_a_media_bubble(transcript):
    voice = _voice(transcript, "v1")

    transcript.update_message_reactions("v1", [_reaction("alice_handle", THUMBS)])

    assert [pill.text() for pill in voice._reactions_strip.pills] == [f"{THUMBS} 1"]


def test_reactions_and_pins_are_cleared_when_a_media_message_is_deleted(transcript):
    voice = _voice(transcript, "v1")
    voice.update_reactions([_reaction("alice_handle", THUMBS)])
    voice.set_pinned(True, "alice_handle")

    transcript.mark_message_deleted("v1")

    assert voice._reactions_strip.isHidden()
    assert voice.reactions == []
    assert not voice.is_pinned and voice._pinned_label.isHidden()


def test_a_pin_marker_shows_on_media_bubbles_and_names_the_pinner(transcript):
    transcript.name_for = {"alice_handle": "Alice"}.get
    voice = _voice(transcript, "v1")
    voice._name_for = transcript.name_for

    voice.set_pinned(True, "alice_handle")

    assert not voice._pinned_label.isHidden()
    assert voice._pinned_label.text().endswith("Pinned by Alice")
