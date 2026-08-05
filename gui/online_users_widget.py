"""
Online Users Widget

Displays all users currently connected to
the secure chat server.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QWidget,
    QLabel,
    QHBoxLayout,
)

from gui.styles import COLOR_ACCENT, COLOR_ONLINE, COLOR_TEXT_MUTED


class UserRow(QWidget):
    """
    A single row in the online users list:
    an avatar initial, the username, and an
    online-presence dot.
    """

    def __init__(self, username):
        super().__init__()

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(10)

        initial = username[0].upper() if username else "?"

        avatar = QLabel(initial)
        avatar.setFixedSize(34, 34)
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: #0B0D16; "
            "border-radius: 17px; font-weight: 700;"
        )

        name = QLabel(username)
        name.setStyleSheet("font-size: 10.5pt; font-weight: 500;")

        dot = QLabel("●")
        dot.setStyleSheet(f"color: {COLOR_ONLINE}; font-size: 9pt;")

        layout.addWidget(avatar)
        layout.addWidget(name, stretch=1)
        layout.addWidget(dot)


class OnlineUsersWidget(QListWidget):
    """
    Widget that displays the online users.

    Emits a signal whenever the selected
    chat partner changes.
    """

    user_selected = Signal(str)

    def __init__(self):
        super().__init__()

        self.build_ui()

        self.itemClicked.connect(
            self.on_item_clicked
        )

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):
        """
        Configure the list widget.
        """

        self.setSpacing(4)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def update_users(self, users):
        """
        Refresh the online user list.

        Parameters
        ----------
        users : list[str]
            List of connected usernames.
        """

        current = self.currentItem()

        current_name = (
            current.data(Qt.UserRole)
            if current is not None
            else None
        )

        self.clear()

        if not users:

            placeholder = QListWidgetItem("No other users online")
            placeholder.setFlags(Qt.NoItemFlags)
            placeholder.setForeground(
                self._muted_color()
            )
            self.addItem(placeholder)
            return

        for username in users:

            item = QListWidgetItem()
            item.setData(Qt.UserRole, username)

            self.addItem(item)

            row = UserRow(username)

            item.setSizeHint(row.sizeHint())

            self.setItemWidget(item, row)

            if username == current_name:
                self.setCurrentItem(item)

    def clear_users(self):
        """
        Remove all users.
        """

        self.clear()

    # ==========================================================
    # Events
    # ==========================================================

    def on_item_clicked(self, item):
        """
        Emit the selected username.
        """

        username = item.data(Qt.UserRole)

        if username:
            self.user_selected.emit(username)

    # ==========================================================
    # Helpers
    # ==========================================================

    @staticmethod
    def _muted_color():

        from PySide6.QtGui import QColor

        return QColor(COLOR_TEXT_MUTED)