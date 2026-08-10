"""
Create Group Dialog

Minimal group-creation UI: a name field and a checkable list of
currently online users. Phase 4 (Secure Group Messaging Foundation)
fixes membership at creation time -- no invitations, join links, or
post-creation membership changes.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
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

        for username in online_users:

            item = QListWidgetItem(username)

            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)

            item.setCheckState(Qt.Unchecked)

            self.member_list.addItem(item)

        layout.addWidget(self.member_list)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )

        buttons.accepted.connect(self.accept)

        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

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
