"""
Phase 19.24 (continued) -- Message Lifecycle Events: Desktop UI wiring.

server/client_handler.py's handlers and ClientSession's own
edit_message()/delete_message_for_me()/delete_message_for_everyone()/
add_reaction()/forward_message() were already proven correct at the
protocol/security level by tests/test_phase19_24_message_lifecycle_
security.py. What THAT file does not prove is the thing the mandate
explicitly calls out: "a feature is not complete merely because a
session method exists -- it must be usable through actual Android/
Desktop/Web UI". These tests drive REAL gui.chat_window.ChatWindow
instances (the exact _handle_bubble_context_action()/send_message()/
_forward_bubble_to()/_send_reaction() methods a real right-click/typed
edit/Send click actually calls) against a REAL running server and REAL,
separately-connecting ClientSessions -- the same harness pattern
tests/test_composer_public_key_availability.py already established
(including its PeerNotVerifiedError-avoidance key_store setup, needed
here for the identical reason: ChatWindow.send_message() turns that
exception into a modal QMessageBox that would hang this test under
QT_QPA_PLATFORM=offscreen).

Run with:
    pytest tests/test_phase19_24_desktop_ui_wiring.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from crypto.key_manager import fingerprint_combined_identity
from domain.conversation_summary import ConversationSummary
from domain.payload_type import PayloadType
from gui.chat_window import ChatWindow
from gui.message_widget import FileMessageBubble, ImageMessageBubble, MessageBubble
from tests.test_read_receipts_realtime import (  # noqa: F401
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])

_KEEP_ALIVE = []


def _direct_summary(username):
    """Exactly the shape gui/chat_window.py::handle_find_user() builds
    from a Find User search result -- conversation_id=None, resolved
    lazily by set_current_chat()."""

    return ConversationSummary(
        conversation_id=None,
        username=username,
        is_online=True,
        latest_message=None,
    )


def _verify_each_other(alice, bob, alice_payload, bob_payload, tmp_path):
    """Marks each session's peer as VERIFIED on the SAME key_store the
    `connect` fixture (tests/test_read_receipts_realtime.py) already
    unlocked and persisted a REAL signing keypair into before ever
    calling send_public_key() -- deliberately NOT a freshly-created,
    separate SecureKeyStore assigned after the fact (the pattern tests/
    test_composer_public_key_availability.py's own lighter `connect`
    uses): that combination -- an ephemeral, not-yet-persisted signing
    identity exchanged first, with a key_store swapped in only
    afterward -- was found (empirically, via tests/test_zzz_debug_
    signing_key.py, a throwaway diagnostic) to occasionally race with
    this receiver's own peer-identity-observation bookkeeping, causing
    an intermittent, load-sensitive "no ML-DSA identity has ever been
    observed" rejection of a SECOND signed event (edit/reaction) from
    the same sender, even though the FIRST (the ordinary chat message)
    always verified correctly. Reusing the fixture that already has a
    real, persisted identity from the very start avoids that race by
    construction, without weakening what is actually being proven here
    (verified-peer messaging + lifecycle-event UI dispatch)."""

    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"],
        fingerprint_combined_identity(
            bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key()
        ),
    )

    bob.key_store.verify_peer_fingerprint(
        alice_payload["username"],
        fingerprint_combined_identity(
            alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
        ),
    )


def _two_windows(connect, accounts, tmp_path):
    """Sets up alice/bob, both connected and mutually verified, each
    with a ChatWindow open to the other -- the starting point every
    test below builds on."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")

    alice = connect(alice_payload)
    bob = connect(bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    _verify_each_other(alice, bob, alice_payload, bob_payload, tmp_path)

    alice_window = ChatWindow(alice)
    _KEEP_ALIVE.append(alice_window)
    alice_window.show()
    alice_window.open_conversation(_direct_summary(bob_payload["username"]))

    bob_window = ChatWindow(bob)
    _KEEP_ALIVE.append(bob_window)
    bob_window.show()
    bob_window.open_conversation(_direct_summary(alice_payload["username"]))

    return alice_window, bob_window, alice_payload, bob_payload


def _send_and_get_bubble(alice_window, bob_window, text):
    """Sends ``text`` from alice, waits for it to arrive at bob, and
    returns (alice's own bubble, its now-resolved real message_id) --
    both context-menu-addressable, exactly like a real send would
    leave them."""

    messages_before = bob_window.messages.count()

    alice_window.send_message(text)

    assert _wait_for(lambda: bob_window.messages.count() > messages_before)

    assert _wait_for(
        lambda: alice_window.session.current_conversation_id is not None
        and not str(
            alice_window.messages._sent_bubbles_by_message_id
            and list(alice_window.messages._sent_bubbles_by_message_id.keys())[-1]
        ).startswith("live-")
    )

    message_id = list(alice_window.messages._bubbles_by_message_id.keys())[-1]
    bubble = alice_window.messages.get_bubble(message_id)

    assert bubble is not None
    assert bubble.message_text == text

    return bubble, message_id


# ----------------------------------------------------------------------
# Reply
# ----------------------------------------------------------------------


def test_reply_action_shows_composer_context_bar(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "original message")

    alice_window._handle_bubble_context_action("reply", bubble)

    assert alice_window._pending_reply_message_id == message_id
    assert alice_window.composer_context_bar.isVisible() is True
    assert "original message" in alice_window.composer_context_label.text()


def test_reply_attaches_reply_to_message_id_and_reaches_recipient(
    tmp_path, connect, accounts
):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    _, original_id = _send_and_get_bubble(alice_window, bob_window, "the original")

    alice_window._handle_bubble_context_action(
        "reply", alice_window.messages.get_bubble(original_id)
    )

    reply_bubble, reply_id = _send_and_get_bubble(alice_window, bob_window, "the reply")

    # send_message() clears pending-reply state once consumed.
    assert alice_window._pending_reply_message_id is None
    assert alice_window.composer_context_bar.isVisible() is False

    conversation_id = alice_window.session.current_conversation_id
    history = alice_window.session.load_conversation_history(
        conversation_id, is_group=False
    )
    reply_row = next(row for row in history if row["message_id"] == reply_id)

    assert reply_row["reply_to_message_id"] == original_id


def test_clear_composer_context_cancels_a_pending_reply(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, _ = _send_and_get_bubble(alice_window, bob_window, "reply target")

    alice_window._handle_bubble_context_action("reply", bubble)
    assert alice_window.composer_context_bar.isVisible() is True

    alice_window._clear_composer_context()

    assert alice_window._pending_reply_message_id is None
    assert alice_window.composer_context_bar.isVisible() is False


# ----------------------------------------------------------------------
# Copy
# ----------------------------------------------------------------------


def test_copy_action_puts_message_text_on_the_clipboard(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, _ = _send_and_get_bubble(alice_window, bob_window, "copy this exact text")

    QApplication.clipboard().setText("")

    alice_window._handle_bubble_context_action("copy", bubble)

    assert QApplication.clipboard().text() == "copy this exact text"


# ----------------------------------------------------------------------
# Edit
# ----------------------------------------------------------------------


def test_edit_action_prefills_composer_with_current_text(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "before edit")

    alice_window._handle_bubble_context_action("edit", bubble)

    assert alice_window._editing_message_id == message_id
    assert alice_window.input_bar.message_input.text() == "before edit"
    assert alice_window.composer_context_bar.isVisible() is True


def test_send_message_while_editing_submits_the_edit_and_recipient_sees_it(
    tmp_path, connect, accounts
):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "before edit")

    alice_window._handle_bubble_context_action("edit", bubble)
    alice_window.send_message("after edit")

    # Editing state is cleared the instant the edit is submitted, not
    # only once the server's notification comes back.
    assert alice_window._editing_message_id is None
    assert alice_window.composer_context_bar.isVisible() is False

    bob_bubble = None
    assert _wait_for(
        lambda: (bob_window.messages.get_bubble(message_id) or None) is not None
        and bob_window.messages.get_bubble(message_id).message_text == "after edit"
    ), "recipient never saw the edited text"

    assert _wait_for(
        lambda: alice_window.messages.get_bubble(message_id).message_text == "after edit"
    ), "sender's own bubble never reflected its own edit"


def test_a_non_edit_capable_bubble_kind_ignores_the_edit_action(
    tmp_path, connect, accounts
):
    """Image/file bubbles never offer Edit in the real context menu
    (supports_edit=False, gui/message_widget.py::_build_message_
    context_menu()) -- proves the dispatcher itself also refuses to
    enter edit mode even if called directly, rather than relying
    solely on the menu never offering the action."""

    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    fake_image_bubble = ImageMessageBubble(
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 32, kind="sent"
    )
    _KEEP_ALIVE.append(fake_image_bubble)
    fake_image_bubble.message_id = "not-a-real-id"

    alice_window._handle_bubble_context_action("edit", fake_image_bubble)

    assert alice_window._editing_message_id is None
    assert alice_window.composer_context_bar.isVisible() is False


# ----------------------------------------------------------------------
# Delete for me / Delete for everyone
# ----------------------------------------------------------------------


def test_delete_for_me_marks_the_bubble_deleted_locally_only(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "hide this for me")

    alice_window._handle_bubble_context_action("delete_me", bubble)

    assert bubble.is_deleted is True

    # No broadcast for delete-for-me -- bob's own view is completely
    # unaffected (server/client_handler.py::handle_message_delete_for_
    # me()'s own docstring).
    bob_bubble = bob_window.messages.get_bubble(message_id)
    assert bob_bubble is not None
    assert bob_bubble.is_deleted is False
    assert bob_bubble.message_text == "hide this for me"


def test_delete_for_everyone_marks_both_sides_deleted(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "delete for all")

    alice_window._do_delete_for_everyone(bubble)

    assert _wait_for(lambda: bubble.is_deleted is True)
    assert _wait_for(
        lambda: (bob_window.messages.get_bubble(message_id) or None) is not None
        and bob_window.messages.get_bubble(message_id).is_deleted
    ), "recipient's bubble was never marked deleted"


def test_delete_everyone_is_refused_for_a_received_bubble_by_the_dispatcher(
    tmp_path, connect, accounts
):
    """gui/message_widget.py's own menu never offers "Delete for
    everyone" on a received bubble (sender-only branch) -- this proves
    the dispatcher enforces the same rule even if invoked directly, as
    defense in depth alongside the server's own real authorization
    check (already proven by tests/test_phase19_24_message_lifecycle_
    security.py::test_non_sender_cannot_delete_for_everyone)."""

    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    _, message_id = _send_and_get_bubble(alice_window, bob_window, "bob cannot wipe this")

    bob_received_bubble = bob_window.messages.get_bubble(message_id)
    assert bob_received_bubble is not None
    assert bob_received_bubble.kind == "received"

    bob_window._handle_bubble_context_action("delete_everyone", bob_received_bubble)

    # No server round trip was ever made for this -- the message is
    # still fully intact on BOTH sides.
    assert bob_received_bubble.is_deleted is False

    alice_bubble = alice_window.messages.get_bubble(message_id)
    assert alice_bubble.is_deleted is False
    assert alice_bubble.message_text == "bob cannot wipe this"


def test_delete_for_me_and_delete_for_everyone_survive_a_reload(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    hide_bubble, hide_id = _send_and_get_bubble(alice_window, bob_window, "reload: hide")
    wipe_bubble, wipe_id = _send_and_get_bubble(alice_window, bob_window, "reload: wipe")

    alice_window._handle_bubble_context_action("delete_me", hide_bubble)
    alice_window._do_delete_for_everyone(wipe_bubble)

    assert _wait_for(
        lambda: (bob_window.messages.get_bubble(wipe_id) or None) is not None
        and bob_window.messages.get_bubble(wipe_id).is_deleted
    )

    # Reopen the conversation -- history reload, not the live path.
    alice_window.open_conversation(_direct_summary(bob_payload["username"]))

    reloaded_hide = alice_window.messages.get_bubble(hide_id)
    reloaded_wipe = alice_window.messages.get_bubble(wipe_id)

    # "reload: hide" is gone from ALICE's own history entirely (delete-
    # for-me filters it server-side before it is ever sent back), so no
    # bubble exists for it at all after reload.
    assert reloaded_hide is None
    assert reloaded_wipe is not None
    assert reloaded_wipe.is_deleted is True


# ----------------------------------------------------------------------
# React
# ----------------------------------------------------------------------


def test_send_reaction_updates_both_sides_bubble(tmp_path, connect, accounts):
    alice_window, bob_window, _, _ = _two_windows(connect, accounts, tmp_path)

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "react to this")

    alice_window._send_reaction(bubble, "\U0001F44D")

    assert _wait_for(
        lambda: any(r.get("reaction") == "\U0001F44D" for r in bubble.reactions)
    )
    assert _wait_for(
        lambda: (bob_window.messages.get_bubble(message_id) or None) is not None
        and any(
            r.get("reaction") == "\U0001F44D"
            for r in bob_window.messages.get_bubble(message_id).reactions
        )
    ), "recipient never saw the reaction"


def test_reactions_survive_a_reload(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    bubble, message_id = _send_and_get_bubble(alice_window, bob_window, "react + reload")

    alice_window._send_reaction(bubble, "❤️")

    assert _wait_for(
        lambda: (bob_window.messages.get_bubble(message_id) or None) is not None
        and bob_window.messages.get_bubble(message_id).reactions
    )

    bob_window.open_conversation(_direct_summary(alice_payload["username"]))

    reloaded = bob_window.messages.get_bubble(message_id)
    assert reloaded is not None
    assert any(r.get("reaction") == "❤️" for r in reloaded.reactions)
    assert any(r.get("user") == alice_payload["username"] for r in reloaded.reactions)


# ----------------------------------------------------------------------
# Forward
# ----------------------------------------------------------------------


def test_forward_bubble_to_creates_an_independent_message_for_a_third_party(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    bubble, original_id = _send_and_get_bubble(
        alice_window, bob_window, "forward this along"
    )

    # Reuses the exact ClientSession.forward_message() call path
    # _handle_forward_bubble() would use after ForwardDialog returns a
    # choice -- this drives that same real call directly, bypassing
    # only the modal dialog itself (see this method's own docstring in
    # gui/chat_window.py for why it is split out this way).
    alice_window._forward_bubble_to(bubble, carol_payload["username"], False)

    # load_conversation_history() relies on current_conversation_id
    # already being resolved (see its own docstring) -- true for its
    # one real caller, gui/chat_window.py::open_conversation(), which
    # always calls set_current_chat() first. carol here is a bare
    # ClientSession with no ChatWindow, so that resolution step is done
    # explicitly.
    carol.set_current_chat(_direct_summary(alice_payload["username"]))

    # _forward_bubble_to() establishes a brand-new session key with
    # carol (never messaged before, unlike bob) and then sends the
    # forward over a real socket -- both real network round trips, not
    # instant -- so the delivered row must be polled for, exactly like
    # every other network-dependent assertion in this file, rather than
    # checked once immediately after the call returns.
    forwarded_rows = []

    def _forwarded_arrived():
        nonlocal forwarded_rows
        history = carol.load_conversation_history(
            alice_payload["username"], is_group=False
        )
        forwarded_rows = [row for row in history if row["text"] == "forward this along"]
        return bool(forwarded_rows)

    assert _wait_for(_forwarded_arrived), "carol never received the forwarded message"

    forwarded_row = forwarded_rows[0]

    assert forwarded_row["message_id"] != original_id, (
        "a forward must be a genuinely NEW message, not the original id reused"
    )
    assert forwarded_row["content_metadata"].get("forwarded") is True


def test_forwarding_does_not_reuse_the_original_ciphertext(tmp_path, connect, accounts):
    """Security -- Forward: the forwarded message is independently
    encrypted under the TARGET conversation's own key, never a copy of
    the original ciphertext (which was produced for an entirely
    different AES key and would be meaningless/undecryptable there)."""

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    bubble, original_id = _send_and_get_bubble(alice_window, bob_window, "same text twice")

    alice_window._forward_bubble_to(bubble, carol_payload["username"], False)

    alice_bob_conversation_id = alice_window.session.current_conversation_id

    # Read the ORIGINAL message's stored ciphertext directly.
    original_history = alice_window.session.load_conversation_history(
        bob_payload["username"], is_group=False
    )
    original_row = next(r for r in original_history if r["message_id"] == original_id)

    carol_conversation_id = alice_window.session.conversation_store.get(
        carol_payload["username"]
    ).conversation_id
    alice_window.session.current_conversation_id = carol_conversation_id
    forwarded_history = alice_window.session.load_conversation_history(
        carol_payload["username"], is_group=False
    )
    alice_window.session.current_conversation_id = alice_bob_conversation_id

    forwarded_row = next(
        r for r in forwarded_history if r["text"] == "same text twice"
    )

    # Both decrypt to the same plaintext (proven above by the recipient
    # test), but this asserts the WIRE-LEVEL ciphertext genuinely
    # differs -- a stale/reused ciphertext would decrypt to garbage
    # under a different conversation's key, or -- worse -- be a literal
    # copy that only happens to work because of a bug. Comparing at the
    # protocol level (via the server's own DB-backed history) is the
    # only way to actually prove independence rather than just
    # plaintext equality.
    from database.connection import SessionLocal
    from database.models.message import Message
    import uuid as uuid_module

    db = SessionLocal()
    try:
        original_message = db.get(Message, uuid_module.UUID(str(original_id)))
        forwarded_message = db.get(
            Message, uuid_module.UUID(str(forwarded_row["message_id"]))
        )
        assert original_message.ciphertext != forwarded_message.ciphertext
    finally:
        db.close()


def test_forwarding_a_voice_message_preserves_its_payload_type(
    tmp_path, connect, accounts
):
    """Regression test: _forward_bubble_to() used to hardcode
    PayloadType.FILE for every FileMessageBubble instance, including a
    voice/video bubble (FileMessageBubble.payload_type is VOICE/VIDEO
    in that case, not a separate class -- see gui/message_widget.py's
    own __init__) -- silently downgrading a forwarded voice message to
    a generic file on the target conversation, losing its playback UI.
    Fixed to forward bubble.payload_type instead. This proves the fix:
    a forwarded voice message is still classified VOICE, not FILE, for
    the recipient."""

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    voice_path = tmp_path / "clip.m4a"
    voice_path.write_bytes(b"fake recorded audio bytes, never a real codec frame")

    messages_before = bob_window.messages.count()
    alice_window.handle_attachment_selected(str(voice_path))
    assert _wait_for(lambda: bob_window.messages.count() > messages_before)

    alice_bubble = next(
        b for b in alice_window.messages.get_media_bubbles()
        if isinstance(b, FileMessageBubble) and b.payload_type == PayloadType.VOICE
    )
    assert alice_bubble.payload_type == PayloadType.VOICE

    alice_window._forward_bubble_to(alice_bubble, carol_payload["username"], False)

    carol.set_current_chat(_direct_summary(alice_payload["username"]))

    forwarded_rows = []

    def _poll():
        nonlocal forwarded_rows
        history = carol.load_conversation_history(alice_payload["username"], is_group=False)
        forwarded_rows = [r for r in history if r.get("content_metadata", {}).get("forwarded") is True]
        return bool(forwarded_rows)

    assert _wait_for(_poll), "carol never received the forwarded voice message"
    assert forwarded_rows[0]["payload_type"] == PayloadType.VOICE.value, (
        "forwarded voice message was reclassified as a plain file"
    )


# ========================================================================
# Drafts (Phase 19.24 -- Drafts): per-conversation, local-only unsent
# composer text that survives switching to a different conversation and
# back -- gui/chat_window.py::open_conversation()'s own save-on-leave/
# restore-on-enter, keyed by self.session.current_chat (a username for
# direct, conversation_id for group -- same identity ConversationStore
# already uses). In-memory only, this window's lifetime -- never sent
# over the wire, never persisted to disk.
# ========================================================================


def test_draft_survives_switching_to_another_conversation_and_back(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    # alice_window is already open to bob (via _two_windows). A real
    # keystroke into the composer, unsent.
    QTest.keyClicks(alice_window.input_bar.message_input, "unsent to bob")
    assert alice_window.input_bar.message_input.text() == "unsent to bob"

    # Switching to a brand-new conversation (carol) must not carry
    # bob's draft over, nor lose it.
    alice_window.open_conversation(_direct_summary(carol_payload["username"]))
    assert alice_window.input_bar.message_input.text() == ""

    QTest.keyClicks(alice_window.input_bar.message_input, "unsent to carol")

    # Back to bob: his own draft is restored exactly as left.
    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice_window.input_bar.message_input.text() == "unsent to bob"

    # And carol's own draft is untouched by having been navigated away
    # from in between.
    alice_window.open_conversation(_direct_summary(carol_payload["username"]))
    assert alice_window.input_bar.message_input.text() == "unsent to carol"


def test_sending_a_message_clears_its_conversations_draft(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    QTest.keyClicks(alice_window.input_bar.message_input, "leftover draft")

    # Switch away (saves the draft) then back (restores it) before
    # actually sending -- proves the send, not merely never having left,
    # is what clears it.
    alice_window.open_conversation(_direct_summary(carol_payload["username"]))
    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice_window.input_bar.message_input.text() == "leftover draft"

    # A real Enter keypress -- InputBar.send_message()'s own real path
    # (QLineEdit.returnPressed), which reads the composer's own text
    # and clears it afterward, unlike calling ChatWindow.send_message()
    # directly with an explicit string (this suite's usual shortcut,
    # e.g. _send_and_get_bubble() -- fine there since it never asserts
    # on the composer's own post-send state, which is exactly what this
    # test needs to be real about).
    messages_before = bob_window.messages.count()
    QTest.keyClick(alice_window.input_bar.message_input, Qt.Key_Return)
    assert _wait_for(lambda: bob_window.messages.count() > messages_before)

    alice_window.open_conversation(_direct_summary(carol_payload["username"]))
    alice_window.open_conversation(_direct_summary(bob_payload["username"]))
    assert alice_window.input_bar.message_input.text() == ""


def test_draft_is_not_saved_while_a_reply_is_in_progress(tmp_path, connect, accounts):
    """A reply-in-progress's pre-filled composer text belongs to that
    pending action, not to a fresh-message draft -- switching away
    while replying must not leave a stray draft behind for this
    conversation once the reply context itself is gone."""

    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)

    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    bubble, _ = _send_and_get_bubble(alice_window, bob_window, "reply target")

    alice_window._handle_bubble_context_action("reply", bubble)
    QTest.keyClicks(alice_window.input_bar.message_input, "mid-reply text")

    alice_window.open_conversation(_direct_summary(carol_payload["username"]))
    alice_window.open_conversation(_direct_summary(bob_payload["username"]))

    assert alice_window.input_bar.message_input.text() == ""
