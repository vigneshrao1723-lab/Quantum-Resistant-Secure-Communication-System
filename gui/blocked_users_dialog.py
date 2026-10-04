"""
Blocked Users Dialog (Phase 19.24 -- Block User).

Opened from Settings -- the one place a blocked username can be
unblocked without needing to find their conversation row again (e.g.
after an Archive/leave that no longer shows it, or if it was never a
direct conversation at all). Purely a thin view over ClientSession.
get_blocked_users()/unblock_user() -- no second implementation of the
block relationship itself.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class BlockedUsersDialog(QDialog):

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session

        self.setWindowTitle("Blocked Users")
        self.setMinimumSize(360, 320)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Blocked Users")
        title.setStyleSheet("font-size: 13pt; font-weight: 700;")
        layout.addWidget(title)

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        self.empty_label = QLabel("You haven't blocked anyone.")
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #888;")
        layout.addWidget(self.empty_label)

        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.clicked.connect(self.reject)
        layout.addWidget(close_button)

        self.refresh()

    def refresh(self):
        """Re-fetches the real, current list from the server (not the
        render-time cache render_conversations() reads) -- this dialog
        is opened rarely, so a real round trip here is worth the
        up-to-date answer, unlike the sidebar's own per-row check."""

        usernames = self.session.get_blocked_users()

        self.list_widget.clear()

        self.empty_label.setVisible(not usernames)
        self.list_widget.setVisible(bool(usernames))

        for username in usernames:

            item = QListWidgetItem()
            self.list_widget.addItem(item)

            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(6, 4, 6, 4)

            label = QLabel(username)
            label.setTextFormat(Qt.PlainText)
            row_layout.addWidget(label, stretch=1)

            unblock_button = QPushButton("Unblock")
            unblock_button.setCursor(Qt.PointingHandCursor)
            unblock_button.clicked.connect(
                lambda _checked=False, u=username: self._handle_unblock(u)
            )
            row_layout.addWidget(unblock_button)

            item.setSizeHint(row.sizeHint())
            self.list_widget.setItemWidget(item, row)

    def _handle_unblock(self, username):
        self.session.unblock_user(username)
        self.refresh()
