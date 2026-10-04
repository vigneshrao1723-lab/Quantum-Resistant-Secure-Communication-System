"""
Phase 19.24 -- Chat Wallpaper: Desktop UI wiring and local persistence.

Local-only, per-conversation (storage/secure_key_store.py, same
mechanism as Mute/Archive) -- never sent to or stored by the server.
Drives the REAL gui.chat_window.ChatWindow.handle_open_wallpaper_
picker()/gui.message_widget.MessageWidget.set_wallpaper() code a real
header button + real menu selection actually run (bypassing only the
modal QMenu.exec() call itself, exactly like this suite's existing
Mute/Archive/Block tests).

Run with:
    pytest tests/test_phase19_24_desktop_wallpaper.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from gui.styles import WALLPAPER_PRESETS
from storage.secure_key_store import SecureKeyStore
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _direct_summary,
    _KEEP_ALIVE,
    _two_windows,
    accounts,
    connect,
    running_server,
)


def _choose_wallpaper(chat_window, wallpaper_id):
    """The real state change a real menu selection applies -- factored
    the same way Mute/Archive/Block's own popup handlers are, bypassing
    only the modal QMenu.exec() call itself."""

    key = chat_window.session.get_current_chat()
    chat_window.session.set_conversation_wallpaper(key, wallpaper_id)
    chat_window.messages.set_wallpaper(wallpaper_id)


def test_setting_a_wallpaper_persists_and_applies_to_the_message_list(
    tmp_path, connect, accounts
):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    assert alice_window.session.get_conversation_wallpaper(bob_username) is None

    _choose_wallpaper(alice_window, "ocean")

    assert alice_window.session.get_conversation_wallpaper(bob_username) == "ocean"
    # A real QSS stylesheet was actually applied to the real widget.
    assert "background" in alice_window.messages.styleSheet()


def test_wallpaper_is_isolated_per_conversation(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)
    from tests.test_phase19_24_desktop_ui_wiring import _verify_each_other, _wait_for
    assert _wait_for(
        lambda: alice_window.session.key_manager.get_public_key(
            carol_payload["username"]
        ) is not None
    )
    _verify_each_other(alice_window.session, carol, alice_payload, carol_payload, tmp_path)

    _choose_wallpaper(alice_window, "sunset")

    alice_window.open_conversation(_direct_summary(carol_payload["username"]))
    assert alice_window.session.get_conversation_wallpaper(carol_payload["username"]) is None

    alice_window.open_conversation(_direct_summary(bob_username))
    assert alice_window.session.get_conversation_wallpaper(bob_username) == "sunset"


def test_resetting_to_default_clears_the_wallpaper(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    _choose_wallpaper(alice_window, "mint")
    assert alice_window.session.get_conversation_wallpaper(bob_username) == "mint"

    _choose_wallpaper(alice_window, None)
    assert alice_window.session.get_conversation_wallpaper(bob_username) is None


def test_wallpaper_persists_across_a_key_store_reload(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    _choose_wallpaper(alice_window, "midnight")

    reopened = SecureKeyStore(
        alice_window.session.key_store._user_id,
        storage_dir=str(alice_window.session.key_store._dir),
    )
    reopened.unlock("Str0ng!Passw0rd")

    assert reopened.get_conversation_wallpaper(bob_username) == "midnight"


def test_every_preset_id_is_a_real_choosable_option(tmp_path, connect, accounts):
    alice_window, bob_window, alice_payload, bob_payload = _two_windows(
        connect, accounts, tmp_path
    )
    bob_username = bob_payload["username"]

    for wallpaper_id in WALLPAPER_PRESETS:
        _choose_wallpaper(alice_window, wallpaper_id)
        assert alice_window.session.get_conversation_wallpaper(bob_username) == wallpaper_id
