"""
Online Users Widget

Displays all users currently connected to
the secure chat server.
"""

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QListWidget


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

        self.setAlternatingRowColors(True)

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
            current.text()
            if current is not None
            else None
        )

        self.clear()

        self.addItems(users)

        if current_name:

            matches = self.findItems(
                current_name,
                0
            )

            if matches:
                self.setCurrentItem(matches[0])

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

        self.user_selected.emit(
            item.text()
        )