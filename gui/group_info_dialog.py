"""
Group Info Dialog (Phase 19.18 -- Desktop Group Admin parity).

Desktop's client/session.py already has remove_group_member() (Phase
19.13, shared server-side enforcement with Android/Web -- see
server/client_handler.py::handle_group_remove_member()'s own
docstring: caller's admin role is always re-derived server-side,
never trusted from whether this dialog happens to show a Remove
button), and the conversation-list/group-create wire packets already
carry admin_username/creator. Only the Desktop GUI itself had no view
of a group's membership at all, and no way to call the existing
method -- this dialog is that missing piece, mirroring web/client/
main.js::renderGroupInfo()'s member-row-plus-admin-only-Remove-button
shape.

No optimistic local mutation: server/client_handler.py::handle_group_
remove_member() broadcasts group_member_left to every remaining
member's socket, INCLUDING the admin's own, before it replies to the
admin's own remove_group_member() request -- so by the time that
blocking send_request() call returns, ClientSession.handle_group_
member_left() has already refreshed conversation_store for us. This
dialog only ever re-reads conversation_store after a successful
result; it never mutates the member list itself.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class GroupInfoDialog(QDialog):
    """
    Read-only member list for ``conversation_id``, with an admin-only
    "Remove" button per non-self, non-admin member. Not live-updating
    while open beyond what conversation_store's own conversations_
    changed signal already drives (_refresh()) -- there is no separate
    polling or push channel this dialog needs of its own.
    """

    def __init__(self, session, conversation_id, parent=None):
        super().__init__(parent)

        self.session = session
        self.conversation_id = conversation_id

        self.setWindowTitle("Group Info")

        self._status_label = QLabel("")
        self._status_label.setTextFormat(Qt.PlainText)
        self._status_label.setWordWrap(True)

        self._member_list = QListWidget()

        layout = QVBoxLayout(self)
        self._name_label = QLabel("")
        layout.addWidget(self._name_label)
        layout.addWidget(QLabel("Members"))
        layout.addWidget(self._member_list)
        layout.addWidget(self._status_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

        self.session.conversation_store.conversations_changed.connect(self._refresh)

        self._refresh()

    def _refresh(self):
        summary = self.session.conversation_store.get(self.conversation_id)

        if summary is None or not summary.is_group:
            # The group this dialog was opened for no longer exists for
            # this client (e.g. this client itself was removed while the
            # dialog was open) -- reflect that rather than show stale rows.
            self._name_label.setText("")
            self._member_list.clear()
            self._status_label.setText("This group is no longer available.")
            return

        self._name_label.setText(f"Group: {summary.group_name}")

        self._member_list.clear()

        own_username = self.session.get_username()
        is_self_admin = summary.admin is not None and summary.admin == own_username

        members = list(summary.participants or [])
        if own_username not in members:
            members = members + [own_username]

        for username in sorted(members):
            self._add_member_row(username, summary.admin, is_self_admin, own_username)

    def _add_member_row(self, username, admin, is_self_admin, own_username):
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(4, 2, 4, 2)

        label_text = username
        if username == admin:
            label_text += "  (admin)"
        if username == own_username:
            label_text += "  (you)"

        row_layout.addWidget(QLabel(label_text))
        row_layout.addStretch()

        # Admin-only, and never a self-removal button -- the server
        # rejects both a non-admin caller and an admin trying to
        # remove themselves through this path anyway (handle_group_
        # remove_member()'s own docstring), so hiding both here is a
        # convenience for the common case, never the enforcement.
        if is_self_admin and username != admin and username != own_username:
            remove_button = QPushButton("Remove")
            remove_button.setCursor(Qt.PointingHandCursor)
            remove_button.clicked.connect(
                lambda checked=False, target=username: self._handle_remove(target)
            )
            row_layout.addWidget(remove_button)

        item = QListWidgetItem()
        item.setSizeHint(row.sizeHint())
        self._member_list.addItem(item)
        self._member_list.setItemWidget(item, row)

    def _handle_remove(self, target_username):
        self._status_label.setText(f"Removing {target_username}...")

        response = self.session.remove_group_member(self.conversation_id, target_username)

        if not response.get("success"):
            self._status_label.setText(response.get("error") or "Could not remove member.")
            return

        self._status_label.setText(f"Removed {target_username}.")
        # ClientSession.handle_group_member_left() has already updated
        # conversation_store by the time the blocking call above
        # returns (see module docstring) -- conversations_changed has
        # therefore already fired _refresh() for us; nothing further
        # to do here.
