"""
Desktop chat window: navigation rail, conversation search/filter, multi-line
composer, message-bubble footer.

The composer tests drive the real widgets with real key events. The sidebar
tests drive a real ChatWindow connected to a real server and two real
ClientSessions (no mocked session), and click the real buttons.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import QApplication, QLabel, QToolButton

from gui.input_bar import ComposerTextEdit, InputBar
from gui.message_widget import MessageBubble
from tests.test_phase19_24_desktop_mute import _row_for  # noqa: F401
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401
    _direct_summary,
    _send_and_get_bubble,
    _two_windows,
    _verify_each_other,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])


# ------------------------------------------------------------------ composer


def _key(widget, key, modifier=Qt.NoModifier):
    QTest.keyClick(widget, key, modifier)


def test_enter_sends_and_shift_enter_inserts_a_line_break():
    bar = InputBar()
    sent = []
    bar.message_sent.connect(sent.append)
    bar.show()

    QTest.keyClicks(bar.message_input, "first line")
    _key(bar.message_input, Qt.Key_Return, Qt.ShiftModifier)
    QTest.keyClicks(bar.message_input, "second line")

    assert bar.message_input.text() == "first line\nsecond line"
    assert sent == []

    _key(bar.message_input, Qt.Key_Return)

    assert sent == ["first line\nsecond line"]
    assert bar.message_input.text() == ""


def test_the_composer_grows_with_its_content_and_stops_at_the_maximum():
    field = ComposerTextEdit()
    field.resize(300, 30)
    field.show()
    one_line = field.height()

    field.setText("a\nb\nc")
    three_lines = field.height()
    field.setText("\n".join("x" for _ in range(40)))
    capped = field.height()
    field.setText("")

    assert three_lines > one_line
    assert capped > three_lines
    assert capped < 40 * field.fontMetrics().lineSpacing()
    assert field.height() == one_line


def test_a_whitespace_only_message_is_never_sent_and_leaves_send_disabled():
    bar = InputBar()
    bar.set_enabled(True)
    sent = []
    bar.message_sent.connect(sent.append)

    bar.message_input.setText("   \n  ")

    assert not bar.send_button.isEnabled()
    _key(bar.message_input, Qt.Key_Return)
    assert sent == []


def test_composer_keeps_the_lineedit_api_the_rest_of_the_app_uses():
    field = ComposerTextEdit()

    field.setText("hello")
    field.setCursorPosition(2)

    assert field.text() == "hello"
    assert field.cursorPosition() == 2
    field.clear()
    assert field.text() == ""


def test_send_button_follows_the_composer_enabled_state():
    bar = InputBar()
    bar.set_enabled(False)
    bar.message_input.setText("typed while disabled")
    assert not bar.send_button.isEnabled()

    bar.set_enabled(True)
    assert bar.send_button.isEnabled()


# ---------------------------------------------------------------- bubble footer


def test_bubble_footer_keeps_its_height_whether_or_not_the_actions_button_shows():
    bubble = MessageBubble("wrapped text " * 12, "received", sender="bob")
    bubble.show()
    _app.processEvents()
    before = bubble.sizeHint().height()

    bubble.actions_button.setVisible(True)
    _app.processEvents()

    assert bubble.sizeHint().height() == before
    assert bubble.actions_button.accessibleName() == "Message actions"


def test_every_bubble_label_stays_readable_not_clipped_by_its_footer():
    bubble = MessageBubble("Hi! Did the safety number match on your side?", "received", sender="bob")
    bubble.show()
    _app.processEvents()

    text_label = bubble._text_label

    assert text_label.height() >= text_label.heightForWidth(text_label.width())
    labels = [label for label in bubble.findChildren(QLabel) if label.objectName() == "TimestampLabel"]
    assert labels and labels[0].isVisible()


# ----------------------------------------------------------- rail + sidebar


def test_navigation_rail_destinations_are_real_buttons_with_labels(tmp_path, connect, accounts):
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)

    expected = {
        "chats_nav_button": "Chats",
        "archived_toggle_button": "Archived",
        "inbox_button": "Inbox",
        "device_management_button": "Devices",
        "account_settings_button": "Settings",
    }

    for attribute, label in expected.items():
        button = getattr(window, attribute)
        assert isinstance(button, QToolButton)
        assert button.text().startswith(label.split()[0])
        # (2026-10-22) the rail now draws each destination's name under its icon, like the Website's.
        assert button.toolButtonStyle() == Qt.ToolButtonTextUnderIcon
        assert button.accessibleName() == label
        assert not button.icon().isNull()

    # Every rail control is a real workflow; there is no calling feature.
    rail_texts = {getattr(window, a).text().lower() for a in expected}
    assert not any("call" in text for text in rail_texts)


def test_chats_and_archived_rail_entries_are_mutually_exclusive(tmp_path, connect, accounts):
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)

    assert window.chats_nav_button.isChecked()
    assert not window.archived_toggle_button.isChecked()

    window.archived_toggle_button.setChecked(True)
    assert not window.chats_nav_button.isChecked()
    assert window.sidebar_title.text() == "Archived"

    window.chats_nav_button.click()
    assert window.chats_nav_button.isChecked()
    assert not window.archived_toggle_button.isChecked()
    assert window.sidebar_title.text() == "Chats"


def test_conversation_search_and_filters_narrow_the_real_list(tmp_path, connect, accounts):
    window, bob_window, alice_payload, bob_payload = _two_windows(connect, accounts, tmp_path)
    bob_username = bob_payload["username"]
    _send_and_get_bubble(window, bob_window, "dinner on thursday")

    carol_payload = accounts("carol_")
    carol = connect(carol_payload)
    assert _wait_for(lambda: window.session.key_manager.get_public_key(carol_payload["username"]) is not None)
    _verify_each_other(window.session, carol, alice_payload, carol_payload, tmp_path)
    window.open_conversation(_direct_summary(carol_payload["username"]))
    window.send_message("seed carol")
    window.open_conversation(_direct_summary(bob_username))

    window.render_conversations()
    assert _row_for(window.conversation_list, bob_username) is not None
    assert _row_for(window.conversation_list, carol_payload["username"]) is not None

    # By name.
    window.conversation_search.setText(carol_payload["username"][:12])
    assert _row_for(window.conversation_list, bob_username) is None
    assert _row_for(window.conversation_list, carol_payload["username"]) is not None

    # By message preview.
    window.conversation_search.setText("thursday")
    assert _row_for(window.conversation_list, bob_username) is not None
    assert _row_for(window.conversation_list, carol_payload["username"]) is None

    # No match -> empty list, not stale rows.
    window.conversation_search.setText("zzzzzz-no-such-chat")
    assert _row_for(window.conversation_list, bob_username) is None
    assert _row_for(window.conversation_list, carol_payload["username"]) is None

    # Clearing restores everything.
    window.conversation_search.clear()
    assert _row_for(window.conversation_list, bob_username) is not None
    assert _row_for(window.conversation_list, carol_payload["username"]) is not None

    # Mode filters: groups-only hides both direct chats; direct-only keeps them.
    window._conversation_filter_mode = "groups"
    window.render_conversations()
    assert _row_for(window.conversation_list, bob_username) is None
    window._conversation_filter_mode = "direct"
    window.render_conversations()
    assert _row_for(window.conversation_list, bob_username) is not None
    window._conversation_filter_mode = "all"


def test_unread_filter_shows_only_conversations_with_unread_messages(tmp_path, connect, accounts):
    window, bob_window, _ap, bob_payload = _two_windows(connect, accounts, tmp_path)
    bob_username = bob_payload["username"]
    _send_and_get_bubble(window, bob_window, "seed")
    window.render_conversations()

    window._conversation_filter_mode = "unread"
    window.session.set_unread_count(bob_username, 0)
    window.render_conversations()
    assert _row_for(window.conversation_list, bob_username) is None

    window.session.set_unread_count(bob_username, 3)
    window.render_conversations()
    row = _row_for(window.conversation_list, bob_username)
    assert row is not None
    assert row.unread_badge.text() == "3"

    window._conversation_filter_mode = "all"
    window.session.set_unread_count(bob_username, 0)


def test_inbox_badge_is_hidden_when_nothing_is_waiting(tmp_path, connect, accounts):
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)

    window.refresh_inbox_badge()

    assert not window.inbox_badge.isVisible()
    assert window.inbox_button.toolTip() == "Inbox"


def test_inbox_badge_counts_only_requests_waiting_for_this_account(tmp_path, connect, accounts, monkeypatch):
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)
    me = window.session.username
    notifications = [
        {"status": "pending", "requester_username": "someone_else"},
        {"status": "pending", "requester_username": "another"},
        {"status": "pending", "requester_username": me},      # sent by me: not waiting on me
        {"status": "approved", "requester_username": "old"},  # already answered
    ]
    monkeypatch.setattr(window.session, "load_inbox", lambda: notifications)

    window.show()
    window.refresh_inbox_badge()

    assert window.inbox_badge.text() == "2"
    assert window.inbox_badge.isVisible()
    assert "2 waiting" in window.inbox_button.toolTip()


def test_inbox_badge_failure_leaves_the_window_usable(tmp_path, connect, accounts, monkeypatch):
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)

    def boom():
        raise RuntimeError("server unavailable")

    monkeypatch.setattr(window.session, "load_inbox", boom)

    window.refresh_inbox_badge()  # must not raise

    assert window.isEnabled()


# ------------------------------------------------------ connection loss


def test_losing_the_connection_offers_a_way_back_and_regaining_it_hides_the_offer(connect, accounts, tmp_path):
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)

    assert not window.connection_banner.isVisible()

    window.session.connection_changed.emit(False)
    assert window.connection_banner.isVisible()
    assert "lost" in window.findChild(QLabel, "ConnectionBannerText").text()
    assert window.status.connection_label.text() == "● Disconnected"

    window.session.connection_changed.emit(True)
    assert not window.connection_banner.isVisible()


def test_the_connection_banner_button_signs_the_user_out_so_they_can_log_in_again(connect, accounts, tmp_path):
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)
    spy = QSignalSpy(window.logout_requested)
    window.session.connection_changed.emit(False)

    QTest.mouseClick(window.connection_banner_button, Qt.LeftButton)

    assert spy.count() == 1


# ------------------------------------------------------ header fits the default window


def test_the_header_for_an_unverified_contact_stays_compact_enough_to_fit(connect, accounts, tmp_path):
    """At the default window width the unverified-contact header (badge + two actions + four icons)
    used to overflow: buttons and the badge were clipped mid-letter and the name cut. It now keeps
    only the status and its one action as text, shows the name with an ellipsis, and the other chat
    tools live behind one Chat settings icon (the header avatar opens the contact's picture)."""
    window, _bob, _ap, _bp = _two_windows(connect, accounts, tmp_path)

    badge = window.verification_status_label.text()
    assert badge in ("Not verified", "✓ Verified", "⚠ Identity changed"), badge
    assert len(badge) <= 20

    # One Chat settings icon replaces the four tool icons and the separate profile icon.
    assert window.chat_settings_button.text() == ""
    assert window.chat_settings_button.accessibleName() == "Chat settings"
    assert not window.chat_settings_button.icon().isNull()
    for removed in ("view_profile_button", "search_button", "pinned_messages_button", "gallery_button",
                    "wallpaper_button", "request_verification_button", "leave_group_button"):
        assert not hasattr(window, removed), removed
    # The avatar is the picture viewer, and is keyboard-reachable.
    assert window.header_avatar.accessibleName()
    assert window.header_avatar.focusPolicy() != Qt.NoFocus

    # The name gives way (with an ellipsis) instead of pushing the buttons out of the row.
    assert window.chat_partner_label.minimumSizeHint().width() == 0
    assert window.chat_partner_label.text()  # the full name is still what text() reports
