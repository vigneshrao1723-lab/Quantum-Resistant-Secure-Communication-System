"""
Settings Dialog

The account-level screen: who you are (picture, display name, handle, phone number), your bio,
your password, your display name, the people you have blocked, and Logout.

The top row is the profile: your real picture (or the coloured-initial placeholder), your display
name and your handle. The picture is a button -- selecting it opens the enlarged viewer, which is
the one place a picture can be changed. Your safety number is not shown here; it belongs to the
verification screen of a contact (see VerifyIdentityDialog), behind an explicit "Show my safety
number" action.

Each of Bio / Password / Display name is one row: a short summary line plus a single action
button. Clicking it reveals the fields in place (on the card's own background, not on a grey band),
and a successful Save or an explicit Cancel collapses them again -- never left half-open.

Purely presentational throughout: every action calls the same already-existing, already-tested
ClientSession methods (change_display_name()/change_password()/change_bio()/fetch_bio()) with no
second implementation.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui.avatar import AvatarButton
from gui.blocked_users_dialog import BlockedUsersDialog
from gui.profile_picture_dialog import ProfilePictureDialog
from gui.styles import COLOR_DANGER, COLOR_TEXT, COLOR_TEXT_MUTED

_BIO_MAX_CHARS = 256
_DISPLAY_NAME_MAX_CHARS = 64

# Inline forms sit on the card they belong to: without this they picked up the application-wide
# panel colour and showed as a grey band inside the white card.
_FORM_STYLE = "QFrame#SettingsForm { background: transparent; border: none; }"


class AccountSettingsDialog(QDialog):

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session

        self.setWindowTitle("Settings")
        self.setMinimumWidth(420)
        self.setMinimumHeight(420)

        self.build_ui()

        # Fit the screen: as tall as the content wants, but never taller than the screen allows.
        screen = QGuiApplication.primaryScreen()
        available = screen.availableGeometry().height() if screen is not None else 720
        self.resize(460, max(self.minimumHeight(), min(780, available - 100)))

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

        # The sections scroll; Logout and Close stay pinned below, so neither is pushed off the
        # bottom of a small screen.
        body = QWidget()
        body.setObjectName("SettingsBody")
        body.setStyleSheet("QWidget#SettingsBody { background: transparent; }")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 6, 0)
        body_layout.setSpacing(14)

        body_layout.addWidget(self._build_profile_row())
        body_layout.addWidget(self._build_bio_section())
        body_layout.addWidget(self._build_display_name_section())
        body_layout.addWidget(self._build_password_section())
        body_layout.addWidget(self._build_appearance_row())
        body_layout.addWidget(self._build_blocked_users_row())
        body_layout.addStretch()

        scroll = QScrollArea()
        scroll.setObjectName("SettingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea#SettingsScroll { background: transparent; border: none; }"
            "QScrollArea#SettingsScroll > QWidget > QWidget { background: transparent; }"
        )
        scroll.setWidget(body)
        layout.addWidget(scroll, 1)

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

    def _form_frame(self):
        form = QFrame()
        form.setObjectName("SettingsForm")
        form.setStyleSheet(_FORM_STYLE)
        form_layout = QVBoxLayout(form)
        form_layout.setContentsMargins(0, 4, 0, 0)
        form_layout.setSpacing(6)
        return form, form_layout

    def _own_display_name(self):
        lookup = getattr(self.session, "display_name_for", None)
        try:
            name = lookup(self.session.username) if lookup else None
        except Exception:  # noqa: BLE001
            name = None
        return name if isinstance(name, str) and name else (self.session.username or "")

    # -- Profile ------------------------------------------------------

    def _build_profile_row(self):
        frame, layout = self._row_frame()

        fetch = getattr(self.session, "fetch_display_names", None)
        if fetch is not None and self.session.username:
            try:
                fetch([self.session.username])
            except Exception:  # noqa: BLE001 -- the handle is shown until the name is known
                pass

        row = QHBoxLayout()
        row.setSpacing(14)

        self.avatar_button = AvatarButton(
            self._own_display_name(), size=64, accessible_name="Your profile picture. Open to view or change it."
        )
        self.avatar_button.setToolTip("View or change your profile picture")
        self.avatar_button.clicked.connect(self._handle_open_profile_picture)
        row.addWidget(self.avatar_button, 0, Qt.AlignTop)

        text_column = QVBoxLayout()
        text_column.setSpacing(2)

        self.profile_name_label = QLabel(self._own_display_name())
        self.profile_name_label.setTextFormat(Qt.PlainText)
        self.profile_name_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 13pt; font-weight: 700;")
        text_column.addWidget(self.profile_name_label)

        phone = getattr(self.session, "phone_number", "") or ""
        details = f"@{self.session.username}" + (f"  ·  {phone}" if phone else "")
        self.profile_details_label = QLabel(details)
        self.profile_details_label.setTextFormat(Qt.PlainText)
        self.profile_details_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;")
        self.profile_details_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        text_column.addWidget(self.profile_details_label)

        self.profile_hint_label = QLabel("Select your picture to view or change it.")
        self.profile_hint_label.setTextFormat(Qt.PlainText)
        self.profile_hint_label.setWordWrap(True)
        self.profile_hint_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;")
        text_column.addWidget(self.profile_hint_label)

        row.addLayout(text_column, 1)
        layout.addLayout(row)

        self._refresh_avatar()

        return frame

    def _refresh_avatar(self):
        self.avatar_button.set_name(self._own_display_name())
        try:
            data = self.session.fetch_profile_picture(self.session.username)
        except Exception:  # noqa: BLE001 -- the placeholder stands in
            data = None
        if data:
            self.avatar_button.set_picture_bytes(data)
        else:
            self.avatar_button.clear_picture()

    def _handle_open_profile_picture(self):
        ProfilePictureDialog(self.session, parent=self).exec()
        self._refresh_avatar()

    # -- Appearance ------------------------------------------------------

    def _build_appearance_row(self):
        """Light, dark, or follow Windows -- the Website's theme choice. The theme is applied when
        the application starts (every window builds its colours at creation), so the choice is saved
        here and the person is told it takes effect on the next start."""

        from PySide6.QtWidgets import QButtonGroup, QRadioButton

        from gui.styles import THEME, save_theme_preference, saved_theme_preference

        frame, layout = self._row_frame()
        label = QLabel("Appearance")
        label.setStyleSheet("font-weight: 700;")
        layout.addWidget(label)

        hint = QLabel(f"Now showing the {THEME} theme. A change applies the next time the app starts.")
        hint.setObjectName("AppearanceHint")
        hint.setWordWrap(True)
        hint.setTextFormat(Qt.PlainText)
        layout.addWidget(hint)

        self.appearance_group = QButtonGroup(self)
        self.appearance_buttons = {}
        row = QHBoxLayout()
        current = saved_theme_preference()
        for key, text in (("light", "Light"), ("dark", "Dark"), ("system", "Follow Windows")):
            button = QRadioButton(text)
            button.setObjectName(f"Appearance_{key}")
            button.setChecked(key == current)
            button.setAccessibleName(f"{text} theme")
            self.appearance_group.addButton(button)
            self.appearance_buttons[key] = button
            row.addWidget(button)

            def _chosen(checked, choice=key, shown=text):
                if not checked:
                    return
                saved = save_theme_preference(choice)
                hint.setText(
                    f"{shown} will be used the next time the app starts."
                    if saved else "Could not save the choice on this computer."
                )

            button.toggled.connect(_chosen)
        row.addStretch()
        layout.addLayout(row)
        return frame

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

        self.bio_form, bio_form_layout = self._form_frame()

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

        self.password_form, form_layout = self._form_frame()

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

    # -- Display name ---------------------------------------------------
    #
    # The name people see. It does not have to be unique -- your phone number is what identifies
    # you -- so this changes the display name only; the account handle every packet, key and
    # verification is addressed to stays as it is.

    def _build_display_name_section(self):
        frame, layout = self._row_frame()

        header_row = QHBoxLayout()
        label = QLabel("Display name")
        label.setStyleSheet("font-weight: 700;")
        header_row.addWidget(label)
        header_row.addStretch()
        self.display_name_change_button = QPushButton("Change Name")
        self.display_name_change_button.setCursor(Qt.PointingHandCursor)
        self.display_name_change_button.clicked.connect(self._show_display_name_form)
        header_row.addWidget(self.display_name_change_button)
        layout.addLayout(header_row)

        self.display_name_label = QLabel(self._own_display_name())
        self.display_name_label.setTextFormat(Qt.PlainText)
        self.display_name_label.setWordWrap(True)
        self.display_name_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        layout.addWidget(self.display_name_label)

        self.display_name_form, form_layout = self._form_frame()

        self.display_name_input = QLineEdit()
        self.display_name_input.setPlaceholderText("Your name")
        self.display_name_input.setMaxLength(_DISPLAY_NAME_MAX_CHARS)
        form_layout.addWidget(self.display_name_input)

        self.display_name_status = QLabel("")
        self.display_name_status.setWordWrap(True)
        form_layout.addWidget(self.display_name_status)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self._hide_display_name_form)
        button_row.addWidget(cancel_button)
        save_button = QPushButton("Save")
        save_button.setCursor(Qt.PointingHandCursor)
        save_button.clicked.connect(self._handle_change_display_name)
        button_row.addWidget(save_button)
        form_layout.addLayout(button_row)

        self.display_name_form.setVisible(False)
        layout.addWidget(self.display_name_form)

        return frame

    def _show_display_name_form(self):
        self.display_name_input.setText(self._own_display_name())
        self.display_name_status.setText("")
        self.display_name_form.setVisible(True)
        self.display_name_input.setFocus()

    def _hide_display_name_form(self):
        self.display_name_form.setVisible(False)
        self.display_name_status.setText("")

    def _handle_change_display_name(self):

        new_name = self.display_name_input.text().strip()

        if not new_name:
            self.display_name_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.display_name_status.setText("Enter a name.")
            return

        try:
            result = self.session.change_display_name(new_name)
        except Exception as error:  # noqa: BLE001
            self.display_name_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.display_name_status.setText(str(error))
            return

        if result.get("success"):
            shown = result.get("display_name") or new_name
            self.display_name_label.setText(shown)
            self.profile_name_label.setText(shown)
            self.avatar_button.set_name(shown)
            self._hide_display_name_form()
        else:
            self.display_name_status.setStyleSheet(f"color: {COLOR_DANGER};")
            self.display_name_status.setText(result.get("error") or "Could not change your name.")
