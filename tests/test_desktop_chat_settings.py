"""
Desktop: Chat settings, the header, the status bar, and the account Settings screen.

* the status bar shows only the connection (the encryption badge, own phone number and
  "User:" moved to where a person looks for them);
* the header shows the contact, one verification status with ONE action, and one Chat settings icon
  -- the contact's picture opens from the avatar, there is no separate profile icon;
* Chat settings holds the contact info, the verification detail, the chat tools and (for a group)
  the members and the actions the person's role allows;
* no private details of the contact (their phone number) are shown anywhere in it;
* Settings has a profile row whose picture opens the enlarged viewer, inline forms on the card's
  own background, and no standing safety-number panel.

Real windows, real server, real sessions.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFrame, QLabel, QPushButton

from client.session import PEER_KEY_STATE_CHANGED
from domain.conversation_summary import ConversationSummary
from gui.account_settings_dialog import AccountSettingsDialog
from gui.avatar import AvatarButton
from gui.chat_details_dialog import ChatDetailsDialog
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401 -- fixtures and helpers reused
    _KEEP_ALIVE,
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])


def _all_text(widget):
    return " | ".join(label.text() for label in widget.findChildren(QLabel))


@pytest.fixture()
def pair(connect, accounts, tmp_path):
    return _two_windows(connect, accounts, tmp_path)


# ------------------------------------------------------------------ status bar and header


def test_the_status_bar_shows_only_the_connection(pair):
    alice_window, _bob, alice_payload, _bp = pair
    alice_window.initialize_ui()
    bar = alice_window.status

    assert not bar.connection_label.isHidden()
    for detail in (bar.algorithm_label, bar.phone_label, bar.user_label):
        assert detail.isHidden(), detail.text()
    # The values are still recorded for the screens that show them.
    assert "Kyber" in bar.algorithm_label.text()
    assert alice_payload["username"] in bar.user_label.text()


def test_the_header_has_one_chat_settings_icon_and_no_profile_or_tool_icons(pair):
    alice_window, _bob, _ap, _bp = pair

    assert alice_window.chat_settings_button.accessibleName() == "Chat settings"
    header_buttons = [
        b.accessibleName() or b.toolTip()
        for b in alice_window.findChildren(QPushButton)
        if b.objectName() == "IconButton" and b.isVisible()
    ]
    for gone in ("View profile", "Search in this conversation", "Pinned messages", "Media gallery", "Chat wallpaper"):
        assert gone not in header_buttons


def test_the_header_avatar_opens_the_contacts_picture_viewer(pair, monkeypatch):
    alice_window, _bob, _ap, bob_payload = pair
    opened = []
    monkeypatch.setattr(
        "gui.chat_window.ProfilePictureDialog",
        lambda session, parent=None, target_username=None: type(
            "Viewer", (), {"exec": lambda self: opened.append(target_username)}
        )(),
    )

    assert isinstance(alice_window.header_avatar, AvatarButton)
    alice_window.header_avatar.click()

    assert opened == [bob_payload["username"]]


def test_the_header_avatar_is_keyboard_operable(pair, monkeypatch):
    from PySide6.QtCore import QEvent
    from PySide6.QtGui import QKeyEvent

    alice_window, *_ = pair
    monkeypatch.setattr(alice_window, "handle_view_peer_profile", lambda: None)  # not the modal viewer
    clicks = []
    alice_window.header_avatar.clicked.connect(lambda: clicks.append(1))

    for key in (Qt.Key_Return, Qt.Key_Space):
        alice_window.header_avatar.keyPressEvent(QKeyEvent(QEvent.KeyPress, key, Qt.NoModifier))
        if key == Qt.Key_Space:  # a space activates on release, like any button
            alice_window.header_avatar.keyReleaseEvent(QKeyEvent(QEvent.KeyRelease, key, Qt.NoModifier))

    assert len(clicks) == 2
    assert alice_window.header_avatar.focusPolicy() == Qt.StrongFocus


def test_the_header_shows_a_compact_verified_status_with_one_action(pair):
    alice_window, *_ = pair

    assert alice_window.verification_status_label.text() == "✓ Verified"
    assert alice_window.verify_identity_button.text() == "Re-verify"
    assert not hasattr(alice_window, "request_verification_button")


def test_a_changed_key_is_shown_as_changed_and_not_verified(pair, monkeypatch):
    alice_window, _bob, _ap, bob_payload = pair
    monkeypatch.setattr(
        alice_window.session, "get_peer_verification_state", lambda peer: PEER_KEY_STATE_CHANGED
    )

    alice_window._update_verification_status()

    assert alice_window.verification_status_label.text() == "⚠ Identity changed"
    assert "Verified" not in alice_window.verification_status_label.text()
    assert alice_window.verify_identity_button.text() == "Verify New Identity"


# ------------------------------------------------------------------ Chat settings (direct)


def _open_details(window):
    dialog = ChatDetailsDialog(window)
    _KEEP_ALIVE.append(dialog)
    return dialog


def test_chat_settings_shows_the_contact_security_and_tools(pair):
    alice_window, _bob, _ap, bob_payload = pair
    dialog = _open_details(alice_window)

    assert dialog.name_label.text() == alice_window.name_for(bob_payload["username"])
    assert dialog.sub_label.text() == f"@{bob_payload['username']}"
    assert dialog.status_label.text().startswith("✓ Verified")
    assert dialog.verify_button.text() == "Re-verify"
    assert not dialog.verify_button.isHidden()
    assert dialog.request_button.isHidden()                       # nothing left to ask once verified
    assert "Kyber" in dialog.encryption_label.text()

    tools = {b.text() for b in dialog.findChildren(QPushButton)}
    assert {"Search in conversation", "Pinned messages", "Media gallery", "Chat wallpaper",
            "Mute notifications…", "Archive chat", "Block", "Close"} <= tools


def test_chat_settings_shows_none_of_the_contacts_private_details(pair):
    alice_window, _bob, alice_payload, bob_payload = pair
    dialog = _open_details(alice_window)
    text = _all_text(dialog)

    for private in (bob_payload["phone_number"], alice_payload["phone_number"], bob_payload["password"]):
        assert private not in text


def test_a_unverified_contact_offers_verify_and_request_approval(pair, monkeypatch):
    alice_window, _bob, _ap, bob_payload = pair
    from storage.secure_key_store import PEER_STATE_UNVERIFIED

    monkeypatch.setattr(alice_window.session, "get_peer_verification_state", lambda peer: PEER_STATE_UNVERIFIED)
    dialog = _open_details(alice_window)

    assert dialog.status_label.text().startswith("Not verified")
    assert dialog.verify_button.text() == "Verify identity"
    assert not dialog.request_button.isHidden()


def test_a_changed_identity_blocks_trust_and_says_so_in_chat_settings(pair, monkeypatch):
    alice_window, *_ = pair
    monkeypatch.setattr(alice_window.session, "get_peer_verification_state", lambda peer: PEER_KEY_STATE_CHANGED)
    dialog = _open_details(alice_window)

    assert "identity changed" in dialog.status_label.text()
    assert "✓" not in dialog.status_label.text()
    assert dialog.verify_button.text() == "Verify new identity"


def test_a_tool_button_closes_the_window_and_runs_its_handler_afterwards(pair):
    alice_window, *_ = pair
    dialog = _open_details(alice_window)
    dialog.show()

    dialog.search_button.click()

    assert not dialog.isVisible()
    assert dialog.chosen == alice_window.handle_toggle_search_bar
    assert alice_window.search_bar.isHidden()           # not run yet...
    dialog.chosen()
    assert not alice_window.search_bar.isHidden()       # ...runs once the window has closed


def test_ctrl_f_opens_the_conversation_search(pair):
    alice_window, *_ = pair
    assert alice_window.search_bar.isHidden()

    alice_window._find_shortcut.activated.emit()

    assert not alice_window.search_bar.isHidden()


def test_blocking_from_chat_settings_uses_the_existing_block_flow(pair, monkeypatch):
    alice_window, _bob, _ap, bob_payload = pair
    blocked = []
    monkeypatch.setattr(alice_window, "_confirm_block_user", lambda username: True)
    monkeypatch.setattr(alice_window, "_do_block_user", lambda username: blocked.append(username))
    dialog = _open_details(alice_window)

    dialog.block_button.click()
    dialog.chosen()

    assert blocked == [bob_payload["username"]]


def test_the_contacts_bio_shows_in_chat_settings(pair):
    alice_window, bob_window, _ap, bob_payload = pair
    assert bob_window.session.change_bio("Quantum-safe since 2026").get("success")

    dialog = _open_details(alice_window)

    assert dialog.bio_label.text() == "Quantum-safe since 2026"
    assert not dialog.bio_label.isHidden()


def test_a_contact_with_no_picture_gets_a_placeholder_avatar_in_chat_settings(pair):
    alice_window, *_ = pair
    dialog = _open_details(alice_window)

    assert not dialog.avatar_button.has_picture
    assert dialog.avatar_button.accessibleName()


# ------------------------------------------------------------------ Chat settings (group)


def _group_windows(pair):
    alice_window, bob_window, alice_payload, bob_payload = pair
    alice, bob = alice_window.session, bob_window.session
    alice.create_group_conversation("Settings Group", [bob_payload["username"]])

    def _summary_in(session):
        for summary in session.conversation_store.get_all():
            if summary.is_group and summary.group_name == "Settings Group":
                return summary
        return None

    assert _wait_for(lambda: _summary_in(alice) is not None and _summary_in(bob) is not None)
    alice_window.open_conversation(_summary_in(alice))
    bob_window.open_conversation(_summary_in(bob))
    return alice_window, bob_window, alice_payload, bob_payload


def test_a_groups_chat_settings_show_members_and_limit_actions_by_role(pair):
    alice_window, bob_window, alice_payload, bob_payload = _group_windows(pair)

    admin = _open_details(alice_window)
    member = _open_details(bob_window)

    assert admin.sub_label.text().startswith("Group ·")
    texts = [label.text() for label in admin.member_labels]
    assert any(alice_payload["username"] in t and "admin" in t and "you" in t for t in texts)
    assert any(bob_payload["username"] in t for t in texts)

    # The admin adds members directly; another member can only ask (the admin approves in the Inbox).
    assert admin.add_members_button.text() == "Add members"
    assert member.add_members_button.text() == "Request to add a member"
    assert member.is_admin is False
    for dialog in (admin, member):
        assert not dialog.group_info_button.isHidden()
        assert dialog.leave_button.text() == "Leave group"
        assert not hasattr(dialog, "block_button")        # blocking is a one-to-one action


def test_the_group_header_shows_add_members_to_the_admin_only(pair):
    alice_window, bob_window, *_ = _group_windows(pair)

    assert not alice_window.add_members_button.isHidden()
    assert bob_window.add_members_button.isHidden()
    assert not alice_window.group_info_button.isHidden()
    assert not hasattr(alice_window, "leave_group_button")


def test_a_groups_header_avatar_opens_chat_settings_not_a_picture(pair, monkeypatch):
    alice_window, *_ = _group_windows(pair)
    opened = []
    monkeypatch.setattr(alice_window, "handle_open_chat_settings", lambda: opened.append(True))

    alice_window.header_avatar.click()

    assert opened == [True]


# ------------------------------------------------------------------ account Settings


def test_settings_has_a_profile_row_with_the_picture_name_and_handle(pair):
    alice_window, _bob, alice_payload, _bp = pair
    alice_window.session.phone_number = alice_payload["phone_number"]   # set at login by the app
    dialog = AccountSettingsDialog(alice_window.session)
    _KEEP_ALIVE.append(dialog)

    assert dialog.profile_name_label.text() == dialog._own_display_name()
    assert f"@{alice_payload['username']}" in dialog.profile_details_label.text()
    assert alice_payload["phone_number"] in dialog.profile_details_label.text()   # your own number, in your own settings
    assert isinstance(dialog.avatar_button, AvatarButton)
    assert dialog.avatar_button.focusPolicy() == Qt.StrongFocus
    assert "profile picture" in dialog.avatar_button.accessibleName().lower()
    # The old "Profile Picture [View / Change]" row is gone: the picture itself is the control.
    assert not any(b.text() == "View / Change" for b in dialog.findChildren(QPushButton))


def test_selecting_the_settings_picture_opens_the_enlarged_viewer(pair, monkeypatch):
    alice_window, *_ = pair
    dialog = AccountSettingsDialog(alice_window.session)
    _KEEP_ALIVE.append(dialog)
    opened = []
    monkeypatch.setattr(
        "gui.account_settings_dialog.ProfilePictureDialog",
        lambda session, parent=None, target_username=None: type(
            "Viewer", (), {"exec": lambda self: opened.append(parent is dialog)}
        )(),
    )

    dialog.avatar_button.click()

    assert opened == [True]


def test_inline_settings_forms_sit_on_the_cards_own_background(pair):
    alice_window, *_ = pair
    dialog = AccountSettingsDialog(alice_window.session)
    _KEEP_ALIVE.append(dialog)

    forms = [dialog.bio_form, dialog.password_form, dialog.display_name_form]
    for form in forms:
        assert isinstance(form, QFrame)
        assert form.objectName() == "SettingsForm"
        assert "background: transparent" in form.styleSheet()   # no grey band behind the fields

    dialog.display_name_change_button.click()
    assert not dialog.display_name_form.isHidden()


def test_the_display_name_form_changes_the_name_everywhere_but_not_the_handle(pair):
    alice_window, bob_window, alice_payload, _bp = pair
    dialog = AccountSettingsDialog(alice_window.session)
    _KEEP_ALIVE.append(dialog)

    dialog.display_name_change_button.click()
    dialog.display_name_input.setText("  Renamed Alice  ")
    dialog._handle_change_display_name()

    assert dialog.display_name_label.text() == "Renamed Alice"
    assert dialog.profile_name_label.text() == "Renamed Alice"
    assert dialog.display_name_form.isHidden()
    assert alice_window.session.username == alice_payload["username"]      # the handle never changes
    assert alice_window.session.display_name_for(alice_payload["username"]) == "Renamed Alice"
    # Another person's client learns the new name when it asks.
    bob_window.session.fetch_display_names([alice_payload["username"]])
    assert bob_window.session.display_name_for(alice_payload["username"]) == "Renamed Alice"


def test_an_empty_display_name_is_refused(pair):
    alice_window, *_ = pair
    dialog = AccountSettingsDialog(alice_window.session)
    _KEEP_ALIVE.append(dialog)
    before = dialog.display_name_label.text()

    dialog.display_name_change_button.click()
    dialog.display_name_input.setText("   ")
    dialog._handle_change_display_name()

    assert dialog.display_name_status.text() == "Enter a name."
    assert dialog.display_name_label.text() == before
