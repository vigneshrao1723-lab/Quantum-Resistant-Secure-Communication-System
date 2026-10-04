"""
Forward Dialog

Phase 19.24 (continued) -- Message Lifecycle Events UI: lets the user
pick an existing conversation (direct or group) to forward a message
to. Deliberately reuses ConversationStore's already-loaded summaries
(session.conversation_store.get_all()) rather than a fresh lookup --
forwarding targets an EXISTING conversation this account is already a
member of, never an arbitrary new user (that is what Find User /
Start Chat is for).
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)


class ForwardDialog(QDialog):
    """
    Shows every conversation this account currently has (direct or
    group) and returns the chosen one's ``(target_chat, target_is_
    group)`` -- exactly the pair ClientSession.forward_message()
    expects -- via get_result(), or None if cancelled.
    """

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session
        self._result = None

        self.setWindowTitle("Forward Message")

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Forward to:"))

        self.list_widget = QListWidget()
        self.list_widget.itemDoubleClicked.connect(self.accept)

        summaries = self.session.conversation_store.get_all()

        for summary in summaries:

            label = summary.group_name if summary.is_group else summary.username

            if not label:
                continue

            item = QListWidgetItem(
                f"\U0001F465 {label}" if summary.is_group else label
            )
            item.setData(Qt.UserRole, (summary.key, summary.is_group))

            self.list_widget.addItem(item)

        layout.addWidget(self.list_widget)

        forward_button = QPushButton("Forward")
        forward_button.setCursor(Qt.PointingHandCursor)
        forward_button.clicked.connect(self.accept)
        layout.addWidget(forward_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)

    def accept(self):

        item = self.list_widget.currentItem()

        if item is None:
            return

        self._result = item.data(Qt.UserRole)

        super().accept()

    def get_result(self):
        """Returns ``(target_chat, target_is_group)``, or None."""

        return self._result
