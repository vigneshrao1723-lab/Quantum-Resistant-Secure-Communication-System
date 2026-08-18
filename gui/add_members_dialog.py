"""
Add Members Dialog

Minimal "add members to an existing group" UI (Issue 2 fix -- Add
Members After Group Creation): a checkable list of online users who
are not already in the group. Mirrors gui/create_group_dialog.py's
member-picker exactly, including its click-to-toggle checkbox fix --
duplicated rather than shared, matching this codebase's established
per-file convention (see e.g. the repeated _utc_now() helper across
repository files) for two call sites this small.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
)


class AddMembersDialog(QDialog):
    """
    Collects a member selection from the given candidate usernames
    (already filtered by the caller to exclude existing participants
    and self). get_result() returns [selected_usernames] for the
    caller to hand to ClientSession.add_group_members().
    """

    def __init__(self, candidate_usernames, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Add Members")

        self.build_ui(candidate_usernames)

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self, candidate_usernames):

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Add members (online users)"))

        self.member_list = QListWidget()

        # See gui/create_group_dialog.py::build_ui()'s docstring for
        # why NoSelection + itemClicked-toggles-checkbox is required
        # here, not just SingleSelection's default highlight-only
        # click behavior.
        self.member_list.setSelectionMode(QAbstractItemView.NoSelection)

        for username in candidate_usernames:

            item = QListWidgetItem(username)

            # Cleared, not set -- see gui/create_group_dialog.py's
            # identical line for the full rationale: with the flag set,
            # Qt toggles the indicator itself and then emits
            # itemClicked, so _toggle_item_check_state() cancelled the
            # click. Clearing it makes that handler the single toggle
            # path for a click anywhere on the row.
            item.setFlags(item.flags() & ~Qt.ItemIsUserCheckable)

            item.setCheckState(Qt.Unchecked)

            self.member_list.addItem(item)

        self.member_list.itemClicked.connect(
            self._toggle_item_check_state
        )

        layout.addWidget(self.member_list)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )

        buttons.accepted.connect(self.accept)

        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

    # ==========================================================
    # Events
    # ==========================================================

    def _toggle_item_check_state(self, item):

        item.setCheckState(
            Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked
        )

    # ==========================================================
    # Public Methods
    # ==========================================================

    def get_result(self):
        """
        Returns [selected_usernames].
        """

        selected = []

        for i in range(self.member_list.count()):

            item = self.member_list.item(i)

            if item.checkState() == Qt.Checked:
                selected.append(item.text())

        return selected
