"""
Phase 19.24 -- Chat Wallpaper: mobile ChatScreen UI wiring.

Reuses tests/test_phase19_24_mobile_drafts.py's ChatScreen harness.
Drives the REAL _apply_wallpaper()/_open_wallpaper_picker() code
against a REAL running server and REAL MobileClientSession.

Run with:
    pytest tests/test_phase19_24_mobile_wallpaper.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mobile.app import BG, ChatScreen, WALLPAPER_PRESETS
from storage.secure_key_store import SecureKeyStore
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def test_setting_a_wallpaper_persists_and_repaints_the_scroll_background(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mwpa"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        assert alice.get_conversation_wallpaper(bob.username) is None
        assert tuple(screen._wallpaper_color.rgba) == BG

        # The real state change a real picker selection applies.
        alice.set_conversation_wallpaper(bob.username, "ocean")
        screen._apply_wallpaper(bob.username)

        assert alice.get_conversation_wallpaper(bob.username) == "ocean"
        assert tuple(screen._wallpaper_color.rgba) == WALLPAPER_PRESETS["ocean"][1]
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_wallpaper_applies_fresh_when_reopening_a_conversation(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mwpb"
    )
    try:
        alice.set_conversation_wallpaper(bob.username, "midnight")

        screen = ChatScreen(alice)
        screen.open_chat(carol.username)
        assert tuple(screen._wallpaper_color.rgba) == BG

        screen.open_chat(bob.username)
        assert tuple(screen._wallpaper_color.rgba) == WALLPAPER_PRESETS["midnight"][1]
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_wallpaper_persists_across_a_key_store_reload(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mwpc"
    )
    try:
        alice.set_conversation_wallpaper(bob.username, "mint")

        reopened = SecureKeyStore(
            alice.key_store._user_id, storage_dir=str(alice.key_store._dir)
        )
        reopened.unlock("Str0ng!Passw0rd")

        assert reopened.get_conversation_wallpaper(bob.username) == "mint"
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
