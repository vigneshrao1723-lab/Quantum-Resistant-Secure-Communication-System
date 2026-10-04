"""
Phase 19.24 (continued) -- Message Lifecycle Events: mobile/app.py's
``Bubble`` widget and its context-menu action set.

No existing test in this project constructs a Kivy widget at all --
every prior mobile test (test_mobile_client_session.py and siblings)
exercises mobile/session.py::MobileClientSession directly, never
mobile/app.py's UI layer. This is new coverage for that layer,
following the same "drive the real thing" philosophy: a REAL Bubble
widget is constructed (Kivy lazily opens a real window the first time
a widget is built in a process -- this machine has a display attached,
so this is a genuine SDL2 window, not a mock), and its own real
methods (apply_edit/mark_deleted/update_reactions/set_reply_preview)
and the module-level _bubble_context_actions() are called and their
actual resulting widget state is asserted on.

Run with:
    pytest tests/test_phase19_24_mobile_bubble_ui.py -v
"""

import pytest

from mobile.app import Bubble, _bubble_context_actions


@pytest.fixture(scope="module", autouse=True)
def _keep_alive():
    """Bubbles are held for the module's lifetime -- a Bubble built
    inline in an expression can be garbage-collected before an
    assertion reads its Kivy-owned children, which raises on some
    platforms once the underlying widget is torn down (mirrors gui/
    tests' own identical _KEEP_ALIVE convention on Desktop)."""

    keep = []
    yield keep


def _sent(text="hello world", **kwargs):
    return Bubble(text, kind="sent", timestamp="10:00", status="Sent", **kwargs)


def _received(text="hi there", **kwargs):
    return Bubble(text, kind="received", sender_label="alice", timestamp="10:01", **kwargs)


# ----------------------------------------------------------------------
# Construction / attribute defaults
# ----------------------------------------------------------------------


def test_sent_bubble_defaults(_keep_alive):
    b = _sent()
    _keep_alive.append(b)

    assert b.message_text == "hello world"
    assert b.message_id is None
    assert b.client_message_id is None
    assert b.reply_to_message_id is None
    assert b.is_deleted is False
    assert b.edit_version == 0
    assert b.reactions == []
    assert b.supports_edit is True  # TEXT (no attachment) -- edit-capable


def test_attachment_bubble_never_supports_edit(_keep_alive):
    b = Bubble(
        None, kind="sent", timestamp="10:00", status="Sent",
        attachment=("file.txt", b"hello", "text/plain", None),
    )
    _keep_alive.append(b)

    assert b.supports_edit is False
    assert b.message_text is None


# ----------------------------------------------------------------------
# _bubble_context_actions() -- mirrors gui/message_widget.py::
# _build_message_context_menu()'s exact action set/conditions.
# ----------------------------------------------------------------------


def test_no_actions_offered_without_a_real_message_id(_keep_alive):
    b = _sent()
    _keep_alive.append(b)

    assert _bubble_context_actions(b) == []


def test_sent_text_bubble_offers_edit_and_both_deletes(_keep_alive):
    b = _sent()
    _keep_alive.append(b)
    b.message_id = "msg-1"

    action_names = [a for a, _ in _bubble_context_actions(b)]

    # Phase 19.24 -- Pinned Messages: "pin" (a fresh, never-pinned
    # bubble offers Pin, not Unpin) is inserted right after "react",
    # mirroring gui/message_widget.py::_build_message_context_menu()'s
    # identical placement.
    assert action_names == [
        "reply", "copy", "forward", "react", "pin", "edit", "delete_me", "delete_everyone",
    ]


def test_sent_attachment_bubble_never_offers_edit(_keep_alive):
    b = Bubble(
        None, kind="sent", timestamp="10:00", status="Sent",
        attachment=("file.txt", b"hello", "text/plain", None),
    )
    _keep_alive.append(b)
    b.message_id = "msg-2"

    action_names = [a for a, _ in _bubble_context_actions(b)]

    assert "edit" not in action_names
    assert action_names == [
        "reply", "copy", "forward", "react", "pin", "delete_me", "delete_everyone",
    ]


def test_received_bubble_never_offers_edit_or_delete_everyone(_keep_alive):
    b = _received()
    _keep_alive.append(b)
    b.message_id = "msg-3"

    action_names = [a for a, _ in _bubble_context_actions(b)]

    assert action_names == ["reply", "copy", "forward", "react", "pin", "delete_me"]
    assert "edit" not in action_names
    assert "delete_everyone" not in action_names


def test_deleted_bubble_offers_only_delete_for_me(_keep_alive):
    b = _sent()
    _keep_alive.append(b)
    b.message_id = "msg-4"
    b.mark_deleted()

    assert _bubble_context_actions(b) == [("delete_me", "Delete for me")]


def test_system_bubble_offers_nothing(_keep_alive):
    b = Bubble("System notice", kind="system")
    _keep_alive.append(b)
    b.message_id = "msg-5"  # even if somehow set, system bubbles never offer actions

    assert _bubble_context_actions(b) == []


# ----------------------------------------------------------------------
# apply_edit()
# ----------------------------------------------------------------------


def test_apply_edit_appends_edited_suffix_and_updates_state(_keep_alive):
    b = _sent()
    _keep_alive.append(b)
    b.message_id = "msg-6"

    b.apply_edit("hello world v2", 1)

    assert b.message_text == "hello world v2"
    assert b.edit_version == 1
    assert b._body.text == "hello world v2 (edited)"


def test_apply_edit_is_a_noop_for_a_system_bubble(_keep_alive):
    b = Bubble("System notice", kind="system")
    _keep_alive.append(b)

    b.apply_edit("ignored", 1)  # must not raise (no ._body on a system bubble)

    assert b.message_text == "System notice"


# ----------------------------------------------------------------------
# update_reactions()
# ----------------------------------------------------------------------


def test_update_reactions_renders_grouped_counts(_keep_alive):
    b = _sent()
    _keep_alive.append(b)

    b.update_reactions([
        {"user": "alice", "reaction": "A"},
        {"user": "bob", "reaction": "A"},
        {"user": "carol", "reaction": "B"},
    ])

    assert b.reactions[0]["user"] == "alice"
    assert "A×2" in b._reactions_label.text
    assert "B×1" in b._reactions_label.text
    assert b._reactions_label.height > 0


def test_update_reactions_with_empty_list_hides_the_row(_keep_alive):
    b = _sent()
    _keep_alive.append(b)

    b.update_reactions([{"user": "alice", "reaction": "A"}])
    assert b._reactions_label.height > 0

    b.update_reactions([])

    assert b.reactions == []
    assert b._reactions_label.text == ""
    assert b._reactions_label.height == 0


# ----------------------------------------------------------------------
# set_reply_preview()
# ----------------------------------------------------------------------


def test_set_reply_preview_shows_the_quoted_text(_keep_alive):
    b = _received()
    _keep_alive.append(b)

    b.set_reply_preview("the original message")

    assert b._reply_preview_label.text == "the original message"
    assert b._reply_preview_label.height > 0


def test_set_reply_preview_truncates_long_text_at_80_chars(_keep_alive):
    b = _received()
    _keep_alive.append(b)

    long_text = "x" * 200
    b.set_reply_preview(long_text)

    assert len(b._reply_preview_label.text) == 78  # 77 chars + the ellipsis glyph
    assert b._reply_preview_label.text.endswith("…")


def test_set_reply_preview_is_a_noop_for_empty_text(_keep_alive):
    b = _received()
    _keep_alive.append(b)

    b.set_reply_preview("")

    assert b._reply_preview_label.text == ""
    assert b._reply_preview_label.height == 0


# ----------------------------------------------------------------------
# mark_deleted()
# ----------------------------------------------------------------------


def test_mark_deleted_renders_tombstone_and_clears_state(_keep_alive):
    b = _sent()
    _keep_alive.append(b)
    b.message_id = "msg-7"
    b.set_reply_preview("original")
    b.update_reactions([{"user": "alice", "reaction": "A"}])

    b.mark_deleted()

    assert b.is_deleted is True
    assert b.message_text == ""
    assert b._body.text == "Message deleted"
    assert b._reply_preview_label.text == ""
    assert b._reply_preview_label.height == 0
    assert b.reactions == []
    assert b._reactions_label.height == 0


def test_mark_deleted_is_a_noop_for_a_system_bubble(_keep_alive):
    b = Bubble("System notice", kind="system")
    _keep_alive.append(b)

    b.mark_deleted()  # must not raise

    assert b.is_deleted is False
    assert b.message_text == "System notice"


# ----------------------------------------------------------------------
# Long-press gesture state (no real touch simulated -- just proves the
# armed/cancelled bookkeeping starts in the expected, inert state and
# that firing it with no on_context_action set is a safe no-op).
# ----------------------------------------------------------------------


def test_fresh_bubble_has_no_armed_long_press_timer(_keep_alive):
    b = _sent()
    _keep_alive.append(b)

    assert b._press_event is None


def test_firing_long_press_with_no_handler_set_does_not_raise(_keep_alive):
    b = _sent()
    _keep_alive.append(b)
    b.message_id = "msg-8"

    class _FakeTouch:
        pos = (0, 0)

    # collide_point(*touch.pos) will be False for (0, 0) against a
    # freshly-constructed, unpositioned widget -- proving _fire_long_
    # press() itself never raises even when the popup path is skipped
    # is exactly what this asserts; on_context_action is also None
    # here (never wired), matching a bubble ChatScreen never attached
    # a handler to.
    b._fire_long_press(_FakeTouch())
