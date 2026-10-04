"""
Phase 19.24 (continued) -- Drafts: mobile ChatScreen UI wiring.

No prior test in this codebase constructs a real mobile/app.py
``ChatScreen`` (every message-lifecycle/typing-indicator mobile test --
test_phase19_24_mobile_lifecycle_wiring.py, test_phase19_24_mobile_
typing_indicator.py -- deliberately stayed session-layer-only, per
their own docstrings, precisely because ChatScreen had no existing
harness). Drafts has no session-layer surface at all -- the feature is
entirely ChatScreen.open_chat()'s own composer save/restore, so a
session-layer-only test would prove nothing real here.

The blocker that kept ChatScreen untested until now was concrete, not
hypothetical: open_chat() calls ``App.get_running_app().back_action =
...``, which raises on ``None`` with no Kivy App ever started in a test
process. Resolved below with ``_StubApp``, a minimal App subclass that
is never ``.run()`` (no real window/event loop, exactly like this
project's existing ``QApplication.instance() or QApplication([])``
one-liner for PySide6 desktop tests) -- just enough for ``App.get_
running_app()`` to resolve to something real. Everything else here is
the actual production path: a real ChatScreen wrapping a real
MobileClientSession, driving open_chat()/composer text/on_text_validate
against a real running server and real peer sessions.

Run with:
    pytest tests/test_phase19_24_mobile_drafts.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from kivy.app import App
from PySide6.QtWidgets import QApplication

import mobile.session as mobile_session_module
from crypto.key_manager import fingerprint_combined_identity
from mobile.app import ChatScreen
from mobile.session import MobileClientSession
from tests.test_device_key_sync import PASSWORD, _delete, _register, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


class _StubApp(App):
    """Exists only so App.get_running_app() (called by ChatScreen.
    open_chat()) resolves to something real -- never .run(), no window,
    no event loop."""

    def build(self):
        return None


def _new_mobile_session(running_server, monkeypatch, payload, storage_dir):
    _state, port = running_server
    monkeypatch.setattr(mobile_session_module, "SERVER_PORT", port)

    session = MobileClientSession(storage_dir=str(storage_dir))
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _mutual_verify(a, b):
    a.observe_peer_identity(b.username, b.key_manager.public_key.decode("utf-8"), b.key_manager.ml_dsa.export_public_key())
    fp_b = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    a.confirm_peer_verified(b.username, fp_b)

    b.observe_peer_identity(a.username, a.key_manager.public_key.decode("utf-8"), a.key_manager.ml_dsa.export_public_key())
    fp_a = fingerprint_combined_identity(a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key())
    b.confirm_peer_verified(a.username, fp_a)


def _three_mobile_sessions(running_server, monkeypatch, tmp_path, hint):
    App._running_app = _StubApp()

    alice_payload = _register(f"{hint}a_")
    bob_payload = _register(f"{hint}b_")
    carol_payload = _register(f"{hint}c_")

    alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile")
    bob = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")
    carol = _new_mobile_session(running_server, monkeypatch, carol_payload, tmp_path / "carol_mobile")

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: alice.key_manager.get_public_key(carol.username) is not None)

    _mutual_verify(alice, bob)
    _mutual_verify(alice, carol)

    return alice, alice_payload, bob, bob_payload, carol, carol_payload


def test_draft_survives_switching_to_another_conversation_and_back(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mdrafta"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        # A real text assignment on the real composer TextInput fires the
        # exact same bound `text` observer a real keystroke would (Kivy's
        # own IME/keyboard input updates this same property -- there is
        # no separate "user typed" event, per _on_composer_text_changed()'s
        # own docstring).
        screen._active_message_input.text = "unsent to bob"
        assert screen._active_message_input.text == "unsent to bob"

        # Switching to a brand-new conversation (carol) must not carry
        # bob's draft over, nor lose it.
        screen.open_chat(carol.username)
        assert screen._active_message_input.text == ""

        screen._active_message_input.text = "unsent to carol"

        # Back to bob: his own draft is restored exactly as left.
        screen.open_chat(bob.username)
        assert screen._active_message_input.text == "unsent to bob"

        # And carol's own draft is untouched by having been navigated
        # away from in between.
        screen.open_chat(carol.username)
        assert screen._active_message_input.text == "unsent to carol"
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_sending_a_message_clears_its_conversations_draft(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mdraftb"
    )
    try:
        alice.establish_session_key(bob.username)

        screen = ChatScreen(alice)
        screen.open_chat(bob.username)
        screen._active_message_input.text = "leftover draft"

        # Switch away (saves the draft) then back (restores it) before
        # actually sending -- proves the send, not merely never having
        # left, is what clears it.
        screen.open_chat(carol.username)
        screen.open_chat(bob.username)
        assert screen._active_message_input.text == "leftover draft"

        received = []
        bob.message_received.connect(
            lambda identity_key, sender, text, historical, status: received.append(text)
        )

        # The real send path: Enter/return on the real composer, bound
        # to the same _send() closure the Send button uses.
        screen._active_message_input.dispatch("on_text_validate")

        assert _wait_for(lambda: len(received) == 1)
        assert received[0] == "leftover draft"
        assert screen._active_message_input.text == ""

        screen.open_chat(carol.username)
        screen.open_chat(bob.username)
        assert screen._active_message_input.text == ""
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_draft_is_not_saved_while_a_reply_is_in_progress(
    running_server, monkeypatch, tmp_path
):
    """A reply-in-progress's pre-filled composer text belongs to that
    pending action, not to a fresh-message draft -- switching away
    while replying must not leave a stray draft behind for this
    conversation once open_chat()'s own reply-state reset has already
    cleared it."""

    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mdraftc"
    )
    try:
        alice.establish_session_key(bob.username)

        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        # A pending reply, mirroring _handle_bubble_context_action()'s own
        # "reply" case shape (message_id doesn't need to resolve to a
        # real bubble for this test -- only the pending-reply STATE, not
        # its delivery, is what's under test).
        screen._pending_reply_message_id = "00000000-0000-0000-0000-000000000000"
        screen._active_message_input.text = "mid-reply text"

        screen.open_chat(carol.username)
        screen.open_chat(bob.username)

        assert screen._active_message_input.text == ""
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
