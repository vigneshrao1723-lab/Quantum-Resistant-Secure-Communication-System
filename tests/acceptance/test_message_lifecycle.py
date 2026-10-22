"""Reply, edit, react and delete as the *recipient* sees them, through the real UIs."""

import uuid

from tests.acceptance.parties import converse, verify_pair
from tests.acceptance.web_driver import wait_until


def _tag():
    return uuid.uuid4().hex[:6]


def test_website_pair_reply_edit_react_and_delete(party):
    a, b = party("web", "lca"), party("web", "lcb")
    verify_pair(a, b)
    a.start_secure_session()
    tag = _tag()

    original = f"original-{tag}"
    a.send(original)
    b.wait_for_text(original)

    # Reply: B replies to A's message; A sees the reply with the quoted original.
    reply = f"reply-{tag}"
    b.user.reply_to(original, reply)
    a.wait_for_text(reply)
    wait_until(lambda: any(original in p for p in a.user.reply_previews()), 20, what="the quoted original on A")

    # Edit: A edits their own message; B sees the new text marked as edited, the old text gone.
    edited = f"edited-{tag}"
    a.user.edit_message(original, edited)
    wait_until(lambda: edited in b.user.edited_texts(), 20, what="the edited text on B")
    assert original not in [t for t in b.user.edited_texts()]

    # React: B reacts to A's (edited) message; A sees the reaction.
    b.user.react_to(edited)
    wait_until(lambda: a.user.reaction_counts() == ["1"], 20, what="the reaction on A")

    # Delete for everyone: B deletes their reply; A no longer sees its text.
    b.user.delete_for_everyone(reply)
    wait_until(lambda: reply not in a.visible_text() and "Message deleted" in a.visible_text(), 20,
               what="the deleted reply on A")

    assert not a.errors() and not b.errors(), (a.errors(), b.errors())


def test_edit_and_delete_reach_a_desktop_recipient(party):
    a, d = party("web", "lcsender"), party("desktop", "lcdesk")
    verify_pair(a, d)
    converse(a, d, "warm-up")
    tag = _tag()

    original = f"first-{tag}"
    a.send(original)
    d.wait_for_text(original)

    edited = f"second-{tag}"
    a.user.edit_message(original, edited)
    d.wait_for_text(f"{edited} (edited)")
    assert original not in d.visible_text()

    a.user.delete_for_everyone(edited)
    d.wait_for_text("Message deleted")
    assert edited not in d.visible_text()

    assert not a.errors() and not d.errors(), (a.errors(), d.errors())
