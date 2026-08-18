"""
BUG 3 -- group member selection via real mouse clicks.

Both member-picker dialogs set ItemIsUserCheckable on their rows AND
connected itemClicked to a handler that toggled the check state by
hand. Qt toggles the checkbox itself when the indicator glyph is
clicked and only then emits itemClicked, so the handler toggled a
second time and cancelled the click.

Measured against the pre-fix code with real mouse events, intending to
select alice and bob:

    click the indicator      -> []                selected nothing
    click the row text       -> ['alice', 'bob']  worked
    indicator then text      -> ['bob']           partial

So a user ticking checkboxes created a group with no members, or with
only the rows they happened to click on the text. Server-side
membership was never at fault: handle_group_create() takes the creator
from the authenticated session and resolves only the usernames it was
sent.

The existing dialog tests could not catch this. They call
_toggle_item_check_state() directly, or emit itemClicked manually --
neither reproduces Qt's own checkbox handling, so both paths looked
correct. These tests therefore drive the widgets with QTest.mouseClick
at real coordinates: on the indicator glyph, on the row text, and in
combination.

Run with:
    pytest tests/test_group_member_selection_clicks.py -v
"""

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from gui.add_members_dialog import AddMembersDialog
from gui.create_group_dialog import CreateGroupDialog

USERS = ["alice", "bob", "carol", "dave"]


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def _show(dialog):
    dialog.show()
    QTest.qWaitForWindowExposed(dialog)
    return dialog


@pytest.fixture()
def create_dialog(qt_app):
    dialog = _show(CreateGroupDialog(list(USERS)))
    dialog.name_input.setText("Demo Group")

    yield dialog

    dialog.close()


@pytest.fixture()
def add_dialog(qt_app):
    dialog = _show(AddMembersDialog(list(USERS)))

    yield dialog

    dialog.close()


def _click_row(dialog, row, where):
    """Click a row with a REAL mouse event.

    ``where`` selects the target: "indicator" lands on the checkbox
    glyph at the left edge of the row, "text" lands on the label. The
    distinction is the whole point -- the pre-fix code behaved
    differently for each.
    """

    widget = dialog.member_list
    rect = widget.visualItemRect(widget.item(row))

    if where == "indicator":
        point = QPoint(rect.left() + 8, rect.center().y())
    else:
        point = QPoint(rect.center().x(), rect.center().y())

    QTest.mouseClick(widget.viewport(), Qt.LeftButton, Qt.NoModifier, point)


def _checked(dialog):
    widget = dialog.member_list
    return [
        widget.item(i).text()
        for i in range(widget.count())
        if widget.item(i).checkState() == Qt.Checked
    ]


# ----------------------------------------------------------------------
# CreateGroupDialog
# ----------------------------------------------------------------------

@pytest.mark.parametrize("where", ["indicator", "text"])
def test_create_single_click_selects_that_member(create_dialog, where):
    """1 + 2: one real click selects, whether it lands on the checkbox
    glyph or the row text."""

    _click_row(create_dialog, 0, where)

    assert _checked(create_dialog) == ["alice"]


@pytest.mark.parametrize("where", ["indicator", "text"])
def test_create_clicking_twice_deselects(create_dialog, where):
    """3: the same row clicked twice ends up unselected."""

    _click_row(create_dialog, 0, where)
    _click_row(create_dialog, 0, where)

    assert _checked(create_dialog) == []


def test_create_mixed_clicks_select_exactly_the_intended_users(create_dialog):
    """4: alice via the indicator, bob via the text -- exactly those
    two, and carol/dave untouched. This is the combination that used to
    yield ['bob'] alone."""

    _click_row(create_dialog, 0, "indicator")
    _click_row(create_dialog, 1, "text")

    assert _checked(create_dialog) == ["alice", "bob"]


def test_create_get_result_returns_exactly_the_selected_usernames(create_dialog):
    """6: the dialog's public contract -- name plus precisely the
    checked usernames, with unselected users excluded."""

    _click_row(create_dialog, 0, "indicator")
    _click_row(create_dialog, 1, "indicator")

    name, selected = create_dialog.get_result()

    assert name == "Demo Group"
    assert selected == ["alice", "bob"]
    assert "carol" not in selected
    assert "dave" not in selected


def test_create_does_not_include_a_creator_entry(create_dialog):
    """7: the dialog only ever reports the rows it was given. The
    creator is added server-side from the authenticated session, so the
    client must not send one -- otherwise handle_group_create() would
    see a duplicate."""

    _click_row(create_dialog, 0, "indicator")

    _name, selected = create_dialog.get_result()

    assert selected == ["alice"]
    assert len(selected) == len(set(selected))


# ----------------------------------------------------------------------
# AddMembersDialog -- same defect, same guarantees
# ----------------------------------------------------------------------

@pytest.mark.parametrize("where", ["indicator", "text"])
def test_add_single_click_selects_that_member(add_dialog, where):
    """5: a real click selects one candidate. Selecting a single member
    (the re-add case) must return exactly that member."""

    _click_row(add_dialog, 2, where)

    assert _checked(add_dialog) == ["carol"]


@pytest.mark.parametrize("where", ["indicator", "text"])
def test_add_clicking_twice_deselects(add_dialog, where):
    _click_row(add_dialog, 2, where)
    _click_row(add_dialog, 2, where)

    assert _checked(add_dialog) == []


def test_add_mixed_clicks_select_exactly_the_intended_users(add_dialog):
    _click_row(add_dialog, 0, "indicator")
    _click_row(add_dialog, 3, "text")

    assert _checked(add_dialog) == ["alice", "dave"]


def test_add_get_result_returns_exactly_the_selected_usernames(add_dialog):
    """7: AddMembersDialog's public contract."""

    _click_row(add_dialog, 2, "indicator")

    selected = add_dialog.get_result()

    assert selected == ["carol"]
    assert "alice" not in selected
    assert "bob" not in selected
    assert "dave" not in selected


def test_add_checkbox_click_does_not_cancel_itself(add_dialog):
    """3 (add-members): the precise regression -- a single indicator
    click must not be undone by a second, internal toggle."""

    _click_row(add_dialog, 1, "indicator")

    assert add_dialog.get_result() == ["bob"], (
        "the indicator click cancelled itself -- the double-toggle is back"
    )


# ----------------------------------------------------------------------
# The checkbox must still be visible
# ----------------------------------------------------------------------

@pytest.mark.parametrize("dialog_name", ["create", "add"])
def test_rows_still_render_a_checkbox(create_dialog, add_dialog, dialog_name):
    """Clearing ItemIsUserCheckable must not remove the visual
    checkbox -- that is driven by setCheckState(), not the flag. Without
    this the fix would leave users with no affordance at all."""

    dialog = create_dialog if dialog_name == "create" else add_dialog
    item = dialog.member_list.item(0)

    assert item.data(Qt.CheckStateRole) is not None
    assert item.checkState() == Qt.Unchecked
