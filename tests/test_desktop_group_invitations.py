"""
Desktop: joining a group by invitation, through the real windows.

* creating a group from the Desktop INVITES the people chosen (non-blocking notice, no modal box) --
  they are not members until they approve;
* the invited person gets a notice, an Inbox badge and an Inbox card naming who invited them and to
  which group, with Approve / Deny; approving adds them and the inviter is told;
* Group info shows who is still deciding.

Real windows, real server, real sessions (the same fixtures as the other Desktop chat tests).
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QPushButton

from gui.group_info_dialog import GroupInfoDialog
from gui.inbox_dialog import InboxDialog
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401 -- fixtures and helpers reused
    _KEEP_ALIVE,
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])


def _group_in(session, name):
    for summary in session.conversation_store.get_all():
        if summary.is_group and summary.group_name == name:
            return summary
    return None


def _create_from_the_window(alice_window, monkeypatch, name, members):
    """Use the window's own Create group handler, with the dialog answered as a person would."""

    class _Answered:
        def __init__(self, *args, **kwargs):
            pass

        def exec(self):
            from PySide6.QtWidgets import QDialog

            return QDialog.Accepted

        def get_result(self):
            return name, list(members)

    monkeypatch.setattr("gui.chat_window.CreateGroupDialog", _Answered)
    alice_window.handle_create_group()


def test_creating_a_group_invites_people_and_they_join_only_by_approving(connect, accounts, tmp_path, monkeypatch):
    alice_window, bob_window, _ap, bob_payload = _two_windows(connect, accounts, tmp_path)
    alice, bob = alice_window.session, bob_window.session

    _create_from_the_window(alice_window, monkeypatch, "#LAB", [bob_payload["username"]])

    # A non-blocking notice on the inviter's window; the group exists with only them in it.
    assert alice_window.notice_banner.isVisible() or not alice_window.notice_banner.isHidden()
    assert "invitation" in alice_window.notice_label.text()
    assert _wait_for(lambda: _group_in(alice, "#LAB") is not None)
    assert _group_in(bob, "#LAB") is None

    # The invited person is told, and the Inbox badge counts it.
    assert _wait_for(lambda: "invited you" in bob_window.notice_label.text(), attempts=200)
    bob_window.refresh_inbox_badge()
    assert bob_window.inbox_badge.text() == "1" and not bob_window.inbox_badge.isHidden()

    # Opening the Inbox answers the notice (the dialog itself is not shown in this test).
    from PySide6.QtWidgets import QDialog

    monkeypatch.setattr("gui.chat_window.InboxDialog.exec", lambda self: QDialog.Rejected)
    bob_window.handle_open_inbox()
    assert bob_window.notice_banner.isHidden()

    # The Inbox card names who invited them and which group, and offers Approve / Deny.
    dialog = InboxDialog(bob)
    _KEEP_ALIVE.append(dialog)
    dialog.show()
    _app.processEvents()
    row = dialog.rows()[0]
    texts = [l.text() for l in row.findChildren(QLabel)]
    assert "GROUP INVITATION" in texts
    assert any("#LAB" in t and "You join only if you approve" in t for t in texts)
    buttons = {b.text(): b for b in row.findChildren(QPushButton)}
    assert set(buttons) == {"Approve", "Deny"}

    buttons["Approve"].click()

    assert _wait_for(lambda: _group_in(bob, "#LAB") is not None, attempts=300)
    assert _wait_for(lambda: "approved and joined" in alice_window.notice_label.text(), attempts=200)
    conversation_id = _group_in(alice, "#LAB").conversation_id
    assert _wait_for(lambda: bob.key_manager.has_key(conversation_id), attempts=300)


def test_group_info_shows_who_is_still_deciding(connect, accounts, tmp_path, monkeypatch):
    alice_window, bob_window, _ap, bob_payload = _two_windows(connect, accounts, tmp_path)
    alice, bob = alice_window.session, bob_window.session
    _create_from_the_window(alice_window, monkeypatch, "#WAIT", [bob_payload["username"]])
    assert _wait_for(lambda: _group_in(alice, "#WAIT") is not None)
    conversation_id = _group_in(alice, "#WAIT").conversation_id

    dialog = GroupInfoDialog(alice, conversation_id)
    _KEEP_ALIVE.append(dialog)
    dialog.show()
    _app.processEvents()
    assert dialog._pending_label.isVisible()
    assert "Waiting for approval" in dialog._pending_label.text()

    invitation = next(
        e for e in bob.load_inbox() if e.get("type") == "group_invitation" and e.get("status") == "pending"
    )
    bob.respond_to_inbox(invitation, True)
    assert _wait_for(lambda: _group_in(bob, "#WAIT") is not None, attempts=300)

    assert _wait_for(lambda: (dialog._refresh(), not dialog._pending_label.isVisible())[1], attempts=100)
    dialog._refresh_timer.stop()


def test_declining_from_the_inbox_card_adds_nobody_and_the_inviter_is_told(connect, accounts, tmp_path, monkeypatch):
    alice_window, bob_window, _ap, bob_payload = _two_windows(connect, accounts, tmp_path)
    alice, bob = alice_window.session, bob_window.session
    _create_from_the_window(alice_window, monkeypatch, "#NO", [bob_payload["username"]])
    assert _wait_for(lambda: "invited you" in bob_window.notice_label.text(), attempts=200)

    dialog = InboxDialog(bob)
    _KEEP_ALIVE.append(dialog)
    dialog.show()
    _app.processEvents()
    next(b for b in dialog.rows()[0].findChildren(QPushButton) if b.objectName() == "DenyButton").click()

    assert _wait_for(lambda: "declined" in alice_window.notice_label.text(), attempts=200)
    assert _group_in(bob, "#NO") is None
    assert not bob.key_manager.has_key(_group_in(alice, "#NO").conversation_id)
