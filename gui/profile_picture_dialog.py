"""
Profile Picture Dialog

Desktop's profile-picture view/update UI (Phase 19.17C -- Mobile
already had a full, working client for this; Desktop had none, despite
the backend/protocol already fully supporting it). Purely
presentational: calls ClientSession.upload_profile_picture()/
fetch_profile_picture() directly, no separate implementation.

Phase 19.19: also the peer profile-picture VIEWER -- reuses this exact
same class rather than a second implementation. ``target_username``
(optional) selects whose picture is shown; omitted or equal to this
account's own username keeps the original "my own picture, view +
change" behavior byte-for-byte. A non-None, non-own target is strictly
read-only (no Change button, no upload path reachable at all) -- this
dialog never lets a viewer overwrite someone else's picture, and never
surfaces the raw fetch error or any filesystem path to the viewer.
"""

from PySide6.QtCore import QBuffer, QIODevice, Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from gui.image_crop_dialog import ImageCropDialog
from gui.styles import COLOR_DANGER, COLOR_PANEL_ALT

_PREVIEW_SIZE = 160


class ProfilePictureDialog(QDialog):
    """
    Shows this account's current profile picture (or a neutral
    placeholder if none is set), with a Change button that opens a
    native file picker, uploads the chosen image, and refreshes the
    preview on success -- no stretching: the picked image is always
    center-cropped to a square before display, exactly like the
    circular avatar crop this same picture gets everywhere else it's
    shown (mirrors web/client/style.css's own object-fit: cover
    treatment).
    """

    def __init__(self, session, parent=None, target_username=None):
        super().__init__(parent)

        self.session = session
        self.target_username = target_username or session.username
        self.is_own = self.target_username == session.username

        self.setWindowTitle("Profile Picture" if self.is_own else f"{self.target_username}'s Profile Picture")

        self.build_ui()
        self.refresh()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        self.preview_label = QLabel()
        self.preview_label.setFixedSize(_PREVIEW_SIZE, _PREVIEW_SIZE)
        self.preview_label.setAlignment(Qt.AlignCenter)
        self.preview_label.setStyleSheet(
            f"background-color: {COLOR_PANEL_ALT}; border-radius: {_PREVIEW_SIZE // 2}px;"
        )
        layout.addWidget(self.preview_label, alignment=Qt.AlignCenter)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet(f"color: {COLOR_DANGER};")
        layout.addWidget(self.status_label)

        if self.is_own:
            change_button = QPushButton("Change")
            change_button.setCursor(Qt.PointingHandCursor)
            change_button.clicked.connect(self._handle_change)
            layout.addWidget(change_button)

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
            # Own picture: the original, specific error (unchanged
            # behavior). A peer's picture: never surface a raw
            # exception/path to the viewer -- just a generic, graceful
            # message, consistent with fetch_profile_picture()'s own
            # "not found" and "no picture set" being indistinguishable
            # by design.
            self.status_label.setText(str(error) if self.is_own else "Could not load this profile picture.")
            return

        if image_bytes is None:
            # setText() alone is correct AND necessary here -- QLabel
            # keeps exactly one active content mode (text/pixmap/movie);
            # calling setPixmap() afterward (even an empty QPixmap(), as
            # this line used to) switches the label back into pixmap
            # mode and silently blanks the text right back out. Found
            # via a real test that actually checked the rendered text
            # for a genuinely picture-less account, which nothing did
            # before Phase 19.19 added peer-viewing.
            self.preview_label.setText("No picture set")
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

        source_pixmap = QPixmap(path)

        if source_pixmap.isNull():
            self.status_label.setText("Could not read this image file.")
            return

        # Phase 19.22 -- Part E: a real crop UI, not a silent stretch/
        # auto-crop. Whatever square the user leaves visible in the
        # crop viewport is exactly what gets uploaded -- see
        # ImageCropDialog's own docstring for why this now happens
        # ONCE, here, instead of every viewer independently guessing.
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

    def _show_bytes(self, image_bytes):

        pixmap = QPixmap()

        if not pixmap.loadFromData(image_bytes):
            self.preview_label.setText("Could not display this image")
            return

        # Center-crop to a square before scaling -- KeepAspectRatioByExpanding
        # alone would still leave a non-square rectangle for a non-square
        # source image, which setMask() below would then clip unevenly.
        side = min(pixmap.width(), pixmap.height())
        cropped = pixmap.copy(
            (pixmap.width() - side) // 2,
            (pixmap.height() - side) // 2,
            side,
            side,
        )
        scaled = cropped.scaled(
            _PREVIEW_SIZE, _PREVIEW_SIZE,
            Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation,
        )
        self.preview_label.setPixmap(scaled)
