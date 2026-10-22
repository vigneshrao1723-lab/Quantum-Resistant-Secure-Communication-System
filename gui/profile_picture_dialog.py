"""
Profile Picture Dialog

The enlarged profile-picture viewer, for this account's own picture and for a contact's.
Purely presentational: it calls ClientSession.upload_profile_picture()/fetch_profile_picture()
directly, with no separate implementation.

``target_username`` (optional) selects whose picture is shown; omitted or equal to this account's
own username shows "my own picture", which is the one place it can be changed. A non-own target is
strictly read-only (no Change button, no upload path reachable at all) -- this dialog never lets a
viewer overwrite someone else's picture, and never surfaces the raw fetch error or any filesystem
path to the viewer.

Someone with no picture gets a polished placeholder (their coloured initial) and a plain caption,
not an empty box.
"""

import os

from PySide6.QtCore import QBuffer, QIODevice, Qt
from PySide6.QtGui import QImageReader, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from gui.avatar import circular_pixmap, placeholder_pixmap
from gui.image_crop_dialog import ImageCropDialog
from gui.styles import COLOR_DANGER, COLOR_TEXT, COLOR_TEXT_MUTED

_PREVIEW_SIZE = 240

# The same limits (and wording) the Website applies before it opens its picture editor. The server
# checks again from the image header, whatever either client says.
_ALLOWED_FORMATS = {"png", "jpeg", "webp", "gif"}
_MAX_INPUT_BYTES = 10 * 1024 * 1024
_MIN_SIDE = 64
_MAX_SIDE = 8192


def _format_bytes(count):
    return f"{count / (1024 * 1024):.1f} MB" if count >= 1024 * 1024 else f"{max(1, round(count / 1024))} KB"


def check_picture_file(path):
    """None if the file may be used as a profile picture, otherwise the reason (never raises)."""

    try:
        size = os.path.getsize(path)
    except OSError:
        return "Could not read this image file."
    if size > _MAX_INPUT_BYTES:
        return f"That image is too large ({_format_bytes(size)}). Choose one under {_format_bytes(_MAX_INPUT_BYTES)}."
    reader = QImageReader(path)
    kind = bytes(reader.format()).decode("ascii", "ignore").lower()
    if not kind:
        return "Could not read this image file."
    if kind not in _ALLOWED_FORMATS:
        return "Choose a PNG, JPEG, WebP or GIF image."
    dimensions = reader.size()
    if dimensions.isValid():
        if dimensions.width() < _MIN_SIDE or dimensions.height() < _MIN_SIDE:
            return f"That image is too small. Use one at least {_MIN_SIDE} × {_MIN_SIDE} pixels."
        if dimensions.width() > _MAX_SIDE or dimensions.height() > _MAX_SIDE:
            return f"That image is too large. Use one no bigger than {_MAX_SIDE} × {_MAX_SIDE} pixels."
    return None


class ProfilePictureDialog(QDialog):
    """
    Shows a profile picture large (or the placeholder when none is set). For the account's own
    picture there is a Change button that opens a native file picker, then the crop dialog, uploads
    the cropped square and refreshes the view on success -- no stretching: what is shown is the
    square the person chose, clipped to a circle exactly like every avatar elsewhere.
    """

    def __init__(self, session, parent=None, target_username=None):
        super().__init__(parent)

        self.session = session
        self.target_username = target_username or session.username
        self.is_own = self.target_username == session.username
        self.is_placeholder = True

        self._display_name = self._name_for(self.target_username)

        self.setWindowTitle("Profile picture" if self.is_own else f"{self._display_name}'s profile picture")
        self.setMinimumWidth(340)

        self.build_ui()
        self.refresh()

    def _name_for(self, handle):
        lookup = getattr(self.session, "display_name_for", None)
        try:
            name = lookup(handle) if lookup else None
        except Exception:  # noqa: BLE001
            name = None
        return name if isinstance(name, str) and name else handle

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 22)
        layout.setSpacing(10)
        layout.setAlignment(Qt.AlignHCenter)

        self.preview_label = QLabel()
        self.preview_label.setFixedSize(_PREVIEW_SIZE, _PREVIEW_SIZE)
        self.preview_label.setAlignment(Qt.AlignCenter)
        self.preview_label.setTextFormat(Qt.PlainText)
        self.preview_label.setStyleSheet("background: transparent;")
        self.preview_label.setAccessibleName("Profile picture")
        layout.addWidget(self.preview_label, alignment=Qt.AlignHCenter)

        self.name_label = QLabel(self._display_name)
        self.name_label.setTextFormat(Qt.PlainText)
        self.name_label.setAlignment(Qt.AlignCenter)
        self.name_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14pt; font-weight: 700;")
        layout.addWidget(self.name_label)

        self.caption_label = QLabel("")
        self.caption_label.setTextFormat(Qt.PlainText)
        self.caption_label.setAlignment(Qt.AlignCenter)
        self.caption_label.setWordWrap(True)
        self.caption_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 10pt;")
        layout.addWidget(self.caption_label)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet(f"color: {COLOR_DANGER};")
        layout.addWidget(self.status_label)

        if self.is_own:
            self.change_button = QPushButton("Change picture")
            self.change_button.setCursor(Qt.PointingHandCursor)
            self.change_button.clicked.connect(self._handle_change)
            layout.addWidget(self.change_button)

        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def refresh(self):

        try:
            image_bytes = self.session.fetch_profile_picture(self.target_username)
        except Exception as error:  # noqa: BLE001
            # Own picture: the original, specific error. A peer's picture: never surface a raw
            # exception/path to the viewer -- just a generic, graceful message, consistent with
            # fetch_profile_picture()'s own "not found" and "no picture set" being
            # indistinguishable by design.
            self._show_placeholder()
            self.status_label.setText(str(error) if self.is_own else "Could not load this profile picture.")
            return

        if image_bytes is None:
            self._show_placeholder()
            return

        self._show_bytes(image_bytes)

    # ==========================================================
    # Events
    # ==========================================================

    def _handle_change(self):

        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Choose Profile Picture",
            "",
            "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)",
        )

        if not path:
            return

        problem = check_picture_file(path)

        if problem:
            self.status_label.setText(problem)
            return

        source_pixmap = QPixmap(path)

        if source_pixmap.isNull():
            self.status_label.setText("Could not read this image file.")
            return

        # A real crop UI, not a silent stretch/auto-crop. Whatever square the user leaves visible
        # in the crop viewport is exactly what gets uploaded -- see ImageCropDialog's docstring.
        crop_dialog = ImageCropDialog(source_pixmap, parent=self)

        if crop_dialog.exec() != QDialog.Accepted:
            return

        cropped_pixmap = crop_dialog.get_result()

        if cropped_pixmap is None:
            return

        buffer = QBuffer()
        buffer.open(QIODevice.WriteOnly)
        cropped_pixmap.save(buffer, "PNG")
        image_bytes = bytes(buffer.data())
        buffer.close()

        if not image_bytes:
            self.status_label.setText("Could not prepare the cropped image.")
            return

        try:
            result = self.session.upload_profile_picture(image_bytes, content_type="image/png")
        except Exception as error:  # noqa: BLE001
            self.status_label.setText(str(error))
            return

        if not result.get("success"):
            self.status_label.setText(result.get("error") or "Upload failed.")
            return

        self.status_label.setText("")
        self._show_bytes(image_bytes)

    # ==========================================================
    # Helpers
    # ==========================================================

    def _show_placeholder(self):
        self.is_placeholder = True
        self.preview_label.setPixmap(placeholder_pixmap(self._display_name, _PREVIEW_SIZE))
        self.caption_label.setText(
            "You haven't added a profile picture yet." if self.is_own
            else f"{self._display_name} hasn't added a profile picture."
        )
        if self.is_own:
            self.change_button.setText("Add a picture")

    def _show_bytes(self, image_bytes):

        pixmap = QPixmap()

        if not pixmap.loadFromData(image_bytes) or pixmap.isNull():
            self._show_placeholder()
            self.status_label.setText("Could not display this image.")
            return

        self.is_placeholder = False
        self.preview_label.setPixmap(circular_pixmap(pixmap, _PREVIEW_SIZE))
        self.caption_label.setText("")
        if self.is_own:
            self.change_button.setText("Change picture")
