"""
Desktop, matched to the Website's navigation and look:

* a light and a dark theme from the Website's own colour tokens, chosen in Settings -> Appearance
  (light / dark / follow Windows) and applied at the next start; the automated (offscreen) runs stay
  light unless told otherwise;
* the rail names every destination under its icon and has Log out at its foot;
* the connection state is shown beside the list title, as a pill;
* All / Unread / Direct / Groups chips filter the list;
* Enter in the sidebar search on a phone number (or @handle) looks that person up -- typing alone only
  ever filters, and creates nothing.

Real windows, real server, real sessions (the same fixtures as the other Desktop chat tests).
"""

import json
import os
import subprocess
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QRadioButton, QToolButton

from gui.account_settings_dialog import AccountSettingsDialog
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401 -- fixtures and helpers reused
    _KEEP_ALIVE,
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _palette_in_a_fresh_process(env_extra):
    """(THEME, COLOR_BG, COLOR_ON_ACCENT) as a new process sees them with the given environment."""

    env = {k: v for k, v in os.environ.items() if k not in ("QRSCS_THEME", "QRSCS_THEME_FILE", "QT_QPA_PLATFORM")}
    env.update(env_extra)
    code = (
        "import json, gui.styles as s; "
        "print(json.dumps([s.THEME, s.COLOR_BG, s.COLOR_ON_ACCENT, sorted(s.WALLPAPER_PRESETS)[0]]))"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


# ------------------------------------------------------------------ the theme


def test_the_light_and_dark_palettes_are_the_websites_tokens():
    light = _palette_in_a_fresh_process({"QRSCS_THEME": "light"})
    dark = _palette_in_a_fresh_process({"QRSCS_THEME": "dark"})

    assert light[:3] == ["light", "#F3F3F6", "#FFFFFF"]
    assert dark[:3] == ["dark", "#0F1016", "#14121F"]      # the Website's --app-bg and --text-on-accent


def test_a_saved_choice_is_used_at_the_next_start_and_headless_runs_stay_light(tmp_path):
    saved = tmp_path / "theme.json"
    saved.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")

    assert _palette_in_a_fresh_process({"QRSCS_THEME_FILE": str(saved)})[0] == "dark"
    # An automated (offscreen) run never picks up the choice saved in the person's home folder ...
    home = tmp_path / "home"
    (home / ".qrscs").mkdir(parents=True)
    (home / ".qrscs" / "desktop_theme.json").write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
    assert _palette_in_a_fresh_process({"HOME": str(home), "USERPROFILE": str(home), "QT_QPA_PLATFORM": "offscreen"})[0] == "light"
    # ... unless a test names a file explicitly.
    assert _palette_in_a_fresh_process({"QRSCS_THEME_FILE": str(saved), "QT_QPA_PLATFORM": "offscreen"})[0] == "dark"
    saved.write_text(json.dumps({"theme": "system"}), encoding="utf-8")
    assert _palette_in_a_fresh_process({"QRSCS_THEME_FILE": str(saved), "QT_QPA_PLATFORM": "offscreen"})[0] == "light"
    saved.write_text("not json", encoding="utf-8")
    assert _palette_in_a_fresh_process({"QRSCS_THEME_FILE": str(saved)})[0] in ("light", "dark")   # never raises


def test_settings_offers_light_dark_and_follow_windows_and_saves_the_choice(connect, accounts, tmp_path, monkeypatch):
    monkeypatch.delenv("QRSCS_THEME", raising=False)
    monkeypatch.setenv("QRSCS_THEME_FILE", str(tmp_path / "theme.json"))
    alice_window, *_ = _two_windows(connect, accounts, tmp_path)
    dialog = AccountSettingsDialog(alice_window.session)
    _KEEP_ALIVE.append(dialog)

    buttons = {b.objectName(): b for b in dialog.findChildren(QRadioButton)}
    assert [buttons[k].text() for k in ("Appearance_light", "Appearance_dark", "Appearance_system")] == [
        "Light", "Dark", "Follow Windows",
    ]
    assert buttons["Appearance_system"].isChecked()                          # the default follows Windows

    buttons["Appearance_dark"].setChecked(True)

    assert json.loads((tmp_path / "theme.json").read_text(encoding="utf-8")) == {"theme": "dark"}
    from PySide6.QtWidgets import QLabel

    assert any("next time the app starts" in l.text() for l in dialog.findChildren(QLabel))


# ------------------------------------------------------------------ navigation and list chrome


def test_the_rail_names_every_destination_and_ends_with_log_out(connect, accounts, tmp_path):
    alice_window, *_ = _two_windows(connect, accounts, tmp_path)

    for attribute, label in (
        ("chats_nav_button", "Chats"), ("archived_toggle_button", "Archived"), ("inbox_button", "Inbox"),
        ("device_management_button", "Devices"), ("account_settings_button", "Settings"),
        ("logout_nav_button", "Log out"),
    ):
        button = getattr(alice_window, attribute)
        assert isinstance(button, QToolButton)
        assert button.text() == label
        assert button.toolButtonStyle() == Qt.ToolButtonTextUnderIcon        # the name is drawn under the icon

    requested = []
    alice_window.logout_requested.connect(lambda: requested.append(True))
    alice_window.logout_nav_button.click()
    assert requested == [True]


def test_the_connection_state_is_shown_in_a_pill_beside_the_list_title(connect, accounts, tmp_path):
    alice_window, *_ = _two_windows(connect, accounts, tmp_path)

    alice_window.status.set_connected(False)
    assert alice_window.connection_pill.text() == "● Disconnected"
    assert alice_window.connection_pill.property("connected") is False

    alice_window.status.set_connected(True)
    assert alice_window.connection_pill.text() == "● Connected"
    assert alice_window.connection_pill.property("connected") is True


def test_the_filter_chips_filter_the_list_and_stay_in_step_with_the_filter_button(connect, accounts, tmp_path):
    alice_window, *_ = _two_windows(connect, accounts, tmp_path)
    chips = alice_window.filter_chips
    assert list(chips) == ["all", "unread", "direct", "groups"]
    assert chips["all"].isChecked()

    chips["groups"].click()
    assert alice_window._conversation_filter_mode == "groups"
    assert chips["groups"].isChecked() and not chips["all"].isChecked()
    assert "Groups" in alice_window.conversation_filter_button.toolTip()

    chips["all"].click()
    assert alice_window._conversation_filter_mode == "all"
    assert alice_window.conversation_filter_button.toolTip() == "Filter chats"


def test_enter_on_a_phone_number_looks_the_person_up_and_typing_alone_creates_nothing(
    connect, accounts, tmp_path, monkeypatch
):
    alice_window, *_ = _two_windows(connect, accounts, tmp_path)
    looked_up = []
    monkeypatch.setattr(alice_window, "handle_find_user", lambda initial_query="": looked_up.append(initial_query))
    before = len(alice_window.session.conversation_store.get_all())

    alice_window.conversation_search.setText("+91 98765 43210")          # typing only filters
    assert looked_up == []
    alice_window.conversation_search.returnPressed.emit()                # Enter on a phone number: look it up
    assert looked_up == ["+91 98765 43210"]
    assert alice_window.conversation_search.text() == ""

    alice_window.conversation_search.setText("just some words")           # Enter on a name: nothing is looked up
    alice_window.conversation_search.returnPressed.emit()
    assert looked_up == ["+91 98765 43210"]

    assert len(alice_window.session.conversation_store.get_all()) == before   # nothing was created
