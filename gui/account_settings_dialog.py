"""
Settings Dialog

Phase 19.22 -- Part D/E/F/G: the real home for account-level actions
that previously either didn't exist (Bio), lived in this dialog with
its edit fields shown unconditionally (Change Username/Password), or
lived somewhere else entirely (Profile Picture and Logout, both moved
here from ChatWindow's own header/sidebar -- see ChatWindow.build_ui()
's own comment on why).

Each of Profile Picture / Change Password / Change Username / Bio is
one row: a short status/summary line plus a single action button.
Password and Username stay pure actions (they open their own already-
reviewed flow -- ProfilePictureDialog for the picture, an inline
expanding form here for password/username) so nothing sensitive is
ever shown by default; clicking "Change" reveals the fields, and a
successful Save or an explicit Cancel collapses them again -- never
left half-open. Bio is simpler (no password confirmation needed) but
follows the same collapsed-by-default, Save/Cancel pattern for a
consistent feel across the whole screen.

Purely presentational throughout: every action still calls the same
already-existing, already-tested ClientSession methods
(change_username()/change_password()/change_bio()/fetch_bio()) with no
second implementation.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from gui.blocked_users_dialog import BlockedUsersDialog
from gui.profile_picture_dialog import ProfilePictureDialog
from gui.styles import COLOR_DANGER, COLOR_ONLINE, COLOR_TEXT_MUTED

_BIO_MAX_CHARS = 256


class AccountSettingsDialog(QDialog):

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session

        self.setWindowTitle("Settings")
        self.setMinimumWidth(420)

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Settings")
        title.setStyleSheet("font-size: 14pt; font-weight: 700;")
        layout.addWidget(title)

        layout.addWidget(self._build_profile_picture_row())
        layout.addWidget(self._build_bio_section())
        layout.addWidget(self._build_password_section())
        layout.addWidget(self._build_username_section())
        layout.addWidget(self._build_blocked_users_row())

        layout.addStretch()

        self.logout_button = QPushButton("Logout")
        self.logout_button.setObjectName("SecondaryButton")
        self.logout_button.setCursor(Qt.PointingHandCursor)
        self.logout_button.clicked.connect(self.accept)
        layout.addWidget(self.logout_button)

        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.clicked.connect(self.reject)
        layout.addWidget(close_button)

    def _row_frame(self):
        frame = QFrame()
        frame.setObjectName("Card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)
        return frame, layout

    # -- Profile Picture -----------------------------------------

    def _build_profile_picture_row(self):
        frame, layout = self._row_frame()

        header_row = QHBoxLayout()
        label = QLabel("Profile Picture")
        label.setStyleSheet("font-weight: 700;")
        header_row.addWidget(label)
        header_row.addStretch()

        button = QPushButton("View / Change")
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(self._handle_open_profile_picture)
        header_row.addWidget(button)

        layout.addLayout(header_row)
        return frame

    def _handle_open_profile_picture(self):
        ProfilePictureDialog(self.session, parent=self).exec()

    # -- Blocked Users (Phase 19.24) --------------------------------

    def _build_blocked_users_row(self):
        frame, layout = self._row_frame()

        header_row = QHBoxLayout()
        label = QLabel("Blocked Users")
        label.setStyleSheet("font-weight: 700;")
        header_row.addWidget(label)
        header_row.addStretch()

        button = QPushButton("Manage")
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(self._handle_open_blocked_users)
        header_row.addWidget(button)

        layout.addLayout(header_row)
        return frame

    def _handle_open_blocked_users(self):
        BlockedUsersDialog(self.session, parent=self).exec()

    # -- Bio -------------------------------------------------------

    def _build_bio_section(self):
        frame, layout = self._row_frame()

        header_row = QHBoxLayout()
        label = QLabel("Bio")
        label.setStyleSheet("font-weight: 700;")
        header_row.addWidget(label)
        header_row.addStretch()
        self.bio_change_button = QPushButton("Change Bio")
        self.bio_change_button.setCursor(Qt.PointingHandCursor)
        self.bio_change_button.clicked.connect(self._show_bio_form)
        header_row.addWidget(self.bio_change_button)
        layout.addLayout(header_row)

        self.bio_display_label = QLabel("")
        self.bio_display_label.setWordWrap(True)
        self.bio_display_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        layout.addWidget(self.bio_display_label)

        self.bio_form = QFrame()
        bio_form_layout = QVBoxLayout(self.bio_form)
        bio_form_layout.setContentsMargins(0, 4, 0, 0)
        bio_form_layout.setSpacing(6)

        self.bio_input = QTextEdit()
        self.bio_input.setPlaceholderText("Tell people a little about yourself...")
        self.bio_input.setFixedHeight(70)
        bio_form_layout.addWidget(self.bio_input)

        self.bio_status = QLabel("")
        self.bio_status.setWordWrap(True)
        bio_form_layout.addWidget(self.bio_status)

        bio_button_row = QHBoxLayout()
        bio_button_row.setSpacing(8)
        bio_cancel = QPushButton("Cancel")
        bio_cancel.setObjectName("SecondaryButton")
        bio_cancel.setCursor(Qt.PointingHandCursor)
        bio_cancel.clicked.connect(self._hide_bio_form)
        bio_button_row.addWidget(bio_cancel)
        bio_save = QPushButton("Save Bio")
        bio_save.setCursor(Qt.PointingHandCursor)
        bio_save.clicked.connect(self._handle_save_bio)
        bio_button_row.addWidget(bio_save)
        bio_form_layout.addLayout(bio_button_row)

        self.bio_form.setVisible(False)
        layout.addWidget(self.bio_form)

        self._refresh_bio_display()

        return frame

    def _refresh_bio_display(self):
        try:
            bio = self.session.fetch_bio(self.session.username)
        except Exception:  # noqa: BLE001
            bio = ""
        self._current_bio = bio
        self.bio_display_label.setText(bio if bio else "No bio set.")

    def _show_bio_form(self):
        self.bio_input.setPlainText(self._current_bio)
        self.bio_status.setText("")
        self.bio_form.setVisible(True)

    def _hide_bio_form(self):
        self.bio_form.setVisible(False)
        self.bio_status.setText("")

    def _handle_save_bio(self):

        new_bio = self.bio_input.toPlainText().strip()

        if len(new_bio) > _BIO_MAX_CHARS:
            self.bio_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.bio_status.setText(f"Bio must be under {_BIO_MAX_CHARS} characters.")
            return

        try:
            result = self.session.change_bio(new_bio)
        except Exception as error:  # noqa: BLE001
            self.bio_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.bio_status.setText(str(error))
            return

        if not result.get("success"):
            self.bio_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.bio_status.setText(result.get("error") or "Could not save bio.")
            return

        self._current_bio = new_bio
        self.bio_display_label.setText(new_bio if new_bio else "No bio set.")
        self._hide_bio_form()

    # -- Change Password --------------------------------------------

    def _build_password_section(self):
        frame, layout = self._row_frame()

        header_row = QHBoxLayout()
        label = QLabel("Password")
        label.setStyleSheet("font-weight: 700;")
        header_row.addWidget(label)
        header_row.addStretch()
        self.password_change_button = QPushButton("Change Password")
        self.password_change_button.setCursor(Qt.PointingHandCursor)
        self.password_change_button.clicked.connect(self._show_password_form)
        header_row.addWidget(self.password_change_button)
        layout.addLayout(header_row)

        self.password_form = QFrame()
        form_layout = QVBoxLayout(self.password_form)
        form_layout.setContentsMargins(0, 4, 0, 0)
        form_layout.setSpacing(6)

        self.current_password_input = QLineEdit()
        self.current_password_input.setPlaceholderText("Current Password")
        self.current_password_input.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.current_password_input)

        self.new_password_input = QLineEdit()
        self.new_password_input.setPlaceholderText("New Password")
        self.new_password_input.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.new_password_input)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm New Password")
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.confirm_password_input)

        self.password_status = QLabel("")
        self.password_status.setWordWrap(True)
        form_layout.addWidget(self.password_status)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self._hide_password_form)
        button_row.addWidget(cancel_button)
        save_button = QPushButton("Save")
        save_button.setCursor(Qt.PointingHandCursor)
        save_button.clicked.connect(self._handle_change_password)
        button_row.addWidget(save_button)
        form_layout.addLayout(button_row)

        self.password_form.setVisible(False)
        layout.addWidget(self.password_form)

        return frame

    def _show_password_form(self):
        self.current_password_input.clear()
        self.new_password_input.clear()
        self.confirm_password_input.clear()
        self.password_status.setText("")
        self.password_form.setVisible(True)

    def _hide_password_form(self):
        self.password_form.setVisible(False)
        self.password_status.setText("")

    def _handle_change_password(self):

        current_password = self.current_password_input.text()
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not current_password or not new_password:
            self.password_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.password_status.setText("Fill in every password field.")
            return

        try:
            result = self.session.change_password(current_password, new_password, confirm_password)
        except Exception as error:  # noqa: BLE001
            self.password_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.password_status.setText(str(error))
            return

        if result.get("success"):
            self._hide_password_form()
        else:
            self.password_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.password_status.setText(result.get("error") or "Could not change password.")

    # -- Change Username ---------------------------------------------

    def _build_username_section(self):
        frame, layout = self._row_frame()

        header_row = QHBoxLayout()
        label = QLabel("Username")
        label.setStyleSheet("font-weight: 700;")
        header_row.addWidget(label)
        header_row.addStretch()
        self.username_change_button = QPushButton("Change Username")
        self.username_change_button.setCursor(Qt.PointingHandCursor)
        self.username_change_button.clicked.connect(self._show_username_form)
        header_row.addWidget(self.username_change_button)
        layout.addLayout(header_row)

        self.username_form = QFrame()
        form_layout = QVBoxLayout(self.username_form)
        form_layout.setContentsMargins(0, 4, 0, 0)
        form_layout.setSpacing(6)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("New username")
        form_layout.addWidget(self.username_input)

        self.username_status = QLabel("")
        self.username_status.setWordWrap(True)
        form_layout.addWidget(self.username_status)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self._hide_username_form)
        button_row.addWidget(cancel_button)
        save_button = QPushButton("Save")
        save_button.setCursor(Qt.PointingHandCursor)
        save_button.clicked.connect(self._handle_change_username)
        button_row.addWidget(save_button)
        form_layout.addLayout(button_row)

        self.username_form.setVisible(False)
        layout.addWidget(self.username_form)

        return frame

    def _show_username_form(self):
        self.username_input.clear()
        self.username_status.setText("")
        self.username_form.setVisible(True)

    def _hide_username_form(self):
        self.username_form.setVisible(False)
        self.username_status.setText("")

    def _handle_change_username(self):

        new_username = self.username_input.text().strip()

        if not new_username:
            self.username_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.username_status.setText("Enter a new username.")
            return

        try:
            result = self.session.change_username(new_username)
        except Exception as error:  # noqa: BLE001
            self.username_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.username_status.setText(str(error))
            return

        if result.get("success"):
            self._hide_username_form()
        else:
            self.username_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.username_status.setText(result.get("error") or "Could not change username.")
