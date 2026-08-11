"""
Create Group Dialog

Minimal group-creation UI: a name field and a checkable list of
currently online users. Phase 4 (Secure Group Messaging Foundation)
fixes membership at creation time -- no invitations, join links, or
post-creation membership changes.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
)


class CreateGroupDialog(QDialog):
    """
    Collects a group name and a member selection from the currently
    online users. get_result() returns (name, [selected_usernames])
    for the caller to hand to ClientSession.create_group_conversation().
    """

    def __init__(self, online_users, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Create Group")

        self.build_ui(online_users)

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self, online_users):

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Group name"))

        self.name_input = QLineEdit()

        self.name_input.setPlaceholderText("Enter a group name")

        layout.addWidget(self.name_input)

        layout.addWidget(QLabel("Members (online users)"))

        self.member_list = QListWidget()

        # Bug fix (real-application testing): QListWidget's default
        # selectionMode is SingleSelection, which only highlights the
        # clicked row -- it does not toggle ItemIsUserCheckable's
        # checkbox unless the user clicks the small checkbox glyph
        # exactly. That made multi-member selection look broken (only
        # whichever checkbox was hit dead-on ever got checked; every
        # other click just moved the highlight). NoSelection removes
        # the misleading highlight entirely -- the checkbox state is
        # the only selection mechanism now, toggled by clicking
        # anywhere on the row via _toggle_item_check_state() below.
        self.member_list.setSelectionMode(QAbstractItemView.NoSelection)

        for username in online_users:

            item = QListWidgetItem(username)

            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)

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
        """
        Toggle a member row's checkbox on click anywhere in the row --
        the fix for the multi-member selection bug (see build_ui()).
        Every checked row survives independently; clicking one member
        never affects another's check state.
        """

        item.setCheckState(
            Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked
        )

    # ==========================================================
    # Public Methods
    # ==========================================================

    def get_result(self):
        """
        Returns (name, [selected_usernames]).
        """

        name = self.name_input.text().strip()

        selected = []

        for i in range(self.member_list.count()):

            item = self.member_list.item(i)

            if item.checkState() == Qt.Checked:
                selected.append(item.text())

        return name, selected
