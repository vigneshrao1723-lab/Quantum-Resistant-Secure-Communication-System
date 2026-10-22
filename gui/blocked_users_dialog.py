"""
Blocked Users Dialog (Phase 19.24 -- Block User).

Opened from Settings -- the one place a blocked username can be
unblocked without needing to find their conversation row again (e.g.
after an Archive/leave that no longer shows it, or if it was never a
direct conversation at all). Purely a thin view over ClientSession.
get_blocked_users()/unblock_user() -- no second implementation of the
block relationship itself.

Layout: a left-aligned title and one-line explanation, a single card that holds either the list
or a centred empty state (the dialog never shows both, and the empty state sits in the middle of
the card, not floating), and a right-aligned Close button.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.styles import COLOR_TEXT, COLOR_TEXT_MUTED


class BlockedUsersDialog(QDialog):

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session

        self.setWindowTitle("Blocked users")
        self.setMinimumSize(400, 360)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(6)

        title = QLabel("Blocked users")
        title.setTextFormat(Qt.PlainText)
        title.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14pt; font-weight: 700;")
        layout.addWidget(title)

        hint = QLabel(
            "People you block can't message you, see when you're online, or verify your identity."
        )
        hint.setTextFormat(Qt.PlainText)
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;")
        layout.addWidget(hint)

        layout.addSpacing(10)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(8, 8, 8, 8)
        card_layout.setSpacing(0)

        self.list_widget = QListWidget()
        self.list_widget.setFrameShape(QFrame.NoFrame)
        self.list_widget.setStyleSheet("QListWidget { background: transparent; border: none; }")
        card_layout.addWidget(self.list_widget, 1)

        self.empty_label = QLabel("You haven't blocked anyone.")
        self.empty_label.setTextFormat(Qt.PlainText)
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 10.5pt;")
        card_layout.addWidget(self.empty_label, 1)

        layout.addWidget(card, 1)

        layout.addSpacing(12)

        button_row = QHBoxLayout()
        button_row.addStretch()
        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.setMinimumWidth(110)
        close_button.clicked.connect(self.reject)
        button_row.addWidget(close_button)
        layout.addLayout(button_row)

        self.refresh()

    def _name_for(self, handle):
        lookup = getattr(self.session, "display_name_for", None)
        try:
            name = lookup(handle) if lookup else None
        except Exception:  # noqa: BLE001
            name = None
        return name if isinstance(name, str) and name else handle

    def refresh(self):
        """Re-fetches the real, current list from the server (not the
        render-time cache render_conversations() reads) -- this dialog
        is opened rarely, so a real round trip here is worth the
        up-to-date answer, unlike the sidebar's own per-row check."""

        usernames = self.session.get_blocked_users()

        fetch = getattr(self.session, "fetch_display_names", None)
        if fetch is not None and usernames:
            try:
                fetch(list(usernames))
            except Exception:  # noqa: BLE001 -- names are cosmetic; fall back to handles
                pass

        self.list_widget.clear()

        self.empty_label.setVisible(not usernames)
        self.list_widget.setVisible(bool(usernames))

        for username in usernames:

            item = QListWidgetItem()
            self.list_widget.addItem(item)

            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(8, 6, 8, 6)
            row_layout.setSpacing(10)

            name = self._name_for(username)
            label = QLabel(name if name == username else f"{name}  (@{username})")
            label.setTextFormat(Qt.PlainText)
            label.setStyleSheet(f"color: {COLOR_TEXT}; background: transparent;")
            row_layout.addWidget(label, stretch=1)

            unblock_button = QPushButton("Unblock")
            unblock_button.setObjectName("SecondaryButton")
            unblock_button.setCursor(Qt.PointingHandCursor)
            unblock_button.setAccessibleName(f"Unblock {name}")
            unblock_button.clicked.connect(
                lambda _checked=False, u=username: self._handle_unblock(u)
            )
            row_layout.addWidget(unblock_button)

            item.setSizeHint(row.sizeHint())
            self.list_widget.setItemWidget(item, row)

    def _handle_unblock(self, username):
        self.session.unblock_user(username)
        self.refresh()
