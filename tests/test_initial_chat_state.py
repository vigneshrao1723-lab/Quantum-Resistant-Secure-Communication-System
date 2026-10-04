"""
UI Finalization -- Initial Chat State.

Before any conversation has ever been opened in a ChatWindow, the
right-hand panel must show the application's own name, not the old
"select a user" prompt, and message history/the composer must be
genuinely hidden -- not merely empty -- until the user actually clicks
a conversation. open_conversation() (fired by
ConversationListWidget.conversation_selected, whether from a sidebar
click or from Find User -- see gui/chat_window.py::handle_find_user())
is the one thing that reveals them, and there is no "close
conversation" action to hide them again.

ChatWindow's constructor needs a session it can call methods on
(register_callbacks() -> session.load_conversations(), initialize_ui()
-> session.key_manager.algorithm / session.get_username(), etc.), but
none of them need to be real for this file's purpose -- these tests
are about widget visibility, not backend behavior -- so a MagicMock
configured just enough to avoid a bare-MagicMock TypeError (iterating
or f-string-ing an unconfigured one can raise/look wrong) stands in,
the same convention tests/test_group_member_selection_clicks.py
already uses for the member-picker dialogs. Whether opening a
conversation ACTUALLY avoids polluting the sidebar (searching/presence
must not, by itself, create a visible conversation) is tested with a
real session/server instead, in
tests/test_conversation_list_request_response.py::
test_opening_a_found_user_does_not_make_them_appear_in_the_list -- that
is backend behavior this file's mocked session cannot exercise.

Run with:
    pytest tests/test_initial_chat_state.py -v
"""

from unittest.mock import MagicMock

import pytest
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from domain.conversation_summary import ConversationSummary
from gui.chat_window import ChatWindow

_KEEP_ALIVE = []


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def _make_session():
    session = MagicMock()
    session.key_manager.algorithm = "Kyber"
    session.get_username.return_value = "me"
    session.phone_number = "+919876543210"
    session.get_online_users.return_value = []
    session.conversation_store.get_all.return_value = []
    session.get_unread_count.return_value = 0
    session.load_conversation_history.return_value = []
    session.current_conversation_id = None
    # Phase 19.22 -- Part G: open_conversation() now also fetches the
    # header avatar's real picture bytes via this method, feeding the
    # result straight into QPixmap.loadFromData() -- unlike the
    # verification-state MagicMock default (safely falls through every
    # `==` comparison), an unconfigured MagicMock return value here
    # would fail there with a real TypeError, since that call has a
    # strict bytes-like signature. None is the documented "no picture
    # set" contract fetch_profile_picture() already promises.
    session.fetch_profile_picture.return_value = None
    return session


@pytest.fixture()
def chat_window(qt_app):
    window = ChatWindow(_make_session())
    _KEEP_ALIVE.append(window)
    window.show()
    QTest.qWaitForWindowExposed(window)

    yield window

    window.close()


def _direct_summary(username, is_online=True):
    return ConversationSummary(
        conversation_id=f"conv-{username}",
        username=username,
        is_online=is_online,
        latest_message=None,
    )


def test_initial_state_shows_the_app_name_not_a_select_user_prompt(chat_window):
    assert chat_window.chat_partner_label.text() == (
        "Quantum-Resistant Secure Communication System"
    )
    assert "select a user" not in chat_window.chat_partner_label.text().lower()


def test_initial_state_hides_message_history_and_composer(chat_window):
    assert chat_window.empty_state_panel.isVisible() is True
    assert chat_window.chat_content.isVisible() is False
    # The message list and composer live inside chat_content -- hidden
    # along with their container, not merely empty.
    assert chat_window.messages.isVisibleTo(chat_window) is False
    assert chat_window.input_bar.isVisibleTo(chat_window) is False


def test_opening_an_existing_conversation_reveals_chat_content(chat_window):
    chat_window.open_conversation(_direct_summary("ramya"))

    assert chat_window.empty_state_panel.isVisible() is False
    assert chat_window.chat_content.isVisible() is True
    assert chat_window.messages.isVisibleTo(chat_window) is True
    assert chat_window.input_bar.isVisibleTo(chat_window) is True
    assert chat_window.chat_partner_label.text() == "ramya"


def test_opening_a_second_conversation_keeps_chat_content_visible(chat_window):
    """Once revealed, chat_content stays revealed for every subsequent
    conversation -- a fresh ChatWindow (constructed on every login --
    see gui/main_window.py::show_chat()) is the only way back to the
    empty state, there is no in-session "close conversation" action."""
    chat_window.open_conversation(_direct_summary("ramya"))
    chat_window.open_conversation(_direct_summary("alex", is_online=False))

    assert chat_window.chat_content.isVisible() is True
    assert chat_window.empty_state_panel.isVisible() is False
    assert chat_window.chat_partner_label.text() == "alex"


def test_a_freshly_constructed_window_always_starts_in_the_empty_state(qt_app):
    """Independent of the fixture above -- proves the empty state is
    this class's actual default, not an artifact of fixture ordering."""
    window = ChatWindow(_make_session())
    _KEEP_ALIVE.append(window)
    window.show()
    QTest.qWaitForWindowExposed(window)

    try:
        assert window.empty_state_panel.isVisible() is True
        assert window.chat_content.isVisible() is False
        assert window.chat_partner_label.text() == (
            "Quantum-Resistant Secure Communication System"
        )
    finally:
        window.close()
