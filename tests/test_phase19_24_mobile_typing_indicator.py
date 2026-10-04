"""
Phase 19.24 -- Typing Indicator: mobile session-layer wiring.

Mirrors tests/test_phase19_24_mobile_lifecycle_wiring.py's exact
harness (real MobileClientSession against a real server, real mutual
peer verification) -- proves the DATA mobile/session.py::send_typing_
indicator()/typing_indicator_received carries and its security
(membership authorization, self-echo exclusion) is correct end to end.
mobile/app.py's ChatScreen (the actual UI consumer) has no existing
Kivy-widget test harness in this codebase (see tests/test_phase19_24_
mobile_bubble_ui.py's own docstring for the one exception -- Bubble
construction alone, no ChatScreen/session/server involved) -- this
file follows the SAME session-layer-only convention every other
mobile test already uses.

Run with:
    pytest tests/test_phase19_24_mobile_typing_indicator.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

import mobile.session as mobile_session_module
from crypto.key_manager import fingerprint_combined_identity
from mobile.session import MobileClientSession
from tests.test_device_key_sync import PASSWORD, _delete, _register, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


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


def _two_mobile_sessions(running_server, monkeypatch, tmp_path, hint):
    alice_payload = _register(f"{hint}a_")
    bob_payload = _register(f"{hint}b_")

    alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile")
    bob = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    _mutual_verify(alice, bob)

    alice.establish_session_key(bob.username)

    return alice, alice_payload, bob, bob_payload


def test_typing_indicator_live_send_and_receive(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "typinga"
    )
    try:
        conversation_id = bob.open_direct_conversation(alice.username)

        received = []
        bob.typing_indicator_received.connect(
            lambda conv_id, username, is_typing: received.append((conv_id, username, is_typing))
        )

        alice.send_typing_indicator(conversation_id, True)

        assert _wait_for(lambda: len(received) == 1)
        assert received[0] == (conversation_id, alice.username, True)

        alice.send_typing_indicator(conversation_id, False)

        assert _wait_for(lambda: len(received) == 2)
        assert received[1] == (conversation_id, alice.username, False)
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_typing_indicator_is_never_echoed_back_to_the_sender(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "typingb"
    )
    try:
        conversation_id = alice.open_direct_conversation(bob.username)

        received_by_alice = []
        alice.typing_indicator_received.connect(
            lambda conv_id, username, is_typing: received_by_alice.append(is_typing)
        )

        received_by_bob = []
        bob.typing_indicator_received.connect(
            lambda conv_id, username, is_typing: received_by_bob.append(is_typing)
        )

        alice.send_typing_indicator(conversation_id, True)

        assert _wait_for(lambda: received_by_bob == [True])
        assert received_by_alice == []
    finally:
        alice.disconnect()
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_send_typing_indicator_is_a_safe_noop_after_disconnect(running_server, monkeypatch, tmp_path):
    """A Clock event that legitimately fires after the session has
    already disconnected (mirrors gui/chat_window.py's identical
    QTimer-after-disconnect scenario) must never raise."""

    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "typingc"
    )
    conversation_id = alice.open_direct_conversation(bob.username)
    try:
        alice.disconnect()
        alice.send_typing_indicator(conversation_id, True)  # must not raise
    finally:
        bob.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_non_member_cannot_broadcast_typing_into_a_conversation(running_server, monkeypatch, tmp_path):
    """Security-negative: a user who is not a member of a conversation
    cannot make its real members see a typing indicator, even by
    directly sending a forged conversation_id -- server/client_
    handler.py::handle_typing_indicator()'s own membership check."""

    alice, alice_payload, bob, bob_payload = _two_mobile_sessions(
        running_server, monkeypatch, tmp_path, "typingd"
    )
    mallory_payload = _register("typingd_m_")
    mallory = _new_mobile_session(running_server, monkeypatch, mallory_payload, tmp_path / "mallory_mobile")
    try:
        conversation_id = alice.open_direct_conversation(bob.username)

        received_by_bob = []
        bob.typing_indicator_received.connect(
            lambda conv_id, username, is_typing: received_by_bob.append((conv_id, username, is_typing))
        )

        mallory.send_typing_indicator(conversation_id, True)

        # A real, deterministic wait for the (rejected) packet to have
        # had a genuine chance to arrive.
        alice.send_typing_indicator(conversation_id, True)
        assert _wait_for(lambda: len(received_by_bob) == 1)
        assert received_by_bob == [(conversation_id, alice.username, True)]
    finally:
        alice.disconnect()
        bob.disconnect()
        mallory.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(mallory_payload["username"])
