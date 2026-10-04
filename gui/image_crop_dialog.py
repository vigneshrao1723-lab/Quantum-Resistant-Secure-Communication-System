"""
Image Crop Dialog

Phase 19.22 -- Part E: a real, interactive square-crop UI, used by
ProfilePictureDialog before a picked image is ever uploaded. Before
this, a picked file's raw bytes were uploaded completely unmodified;
each *viewer* of the picture (this dialog's own preview, the chat
header avatar, etc.) then independently auto-center-cropped it purely
for display, which cannot reproduce what a user actually intended to
keep in shot for a non-square source image and can disagree between
call sites.

This dialog crops ONCE, here, before upload: the user can pan (drag)
and zoom (slider or wheel) a square viewport over the source image,
see a live preview, and only the exact visible square is ever turned
into the image that gets stored. Reusable outside profile pictures if
a future feature needs the same interaction -- nothing about it is
profile-picture-specific.
"""

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QPainter, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from gui.styles import COLOR_PANEL_ALT, COLOR_TEXT_MUTED

VIEWPORT_SIZE = 320
OUTPUT_SIZE = 512
_ZOOM_MIN = 100  # percent of "fit" scale
_ZOOM_MAX = 400


class _CropCanvas(QWidget):
    """
    Fixed-size square viewport onto ``source`` (a QPixmap). The
    viewport's own bounds ARE the crop -- whatever is visible here is
    exactly what get_cropped_pixmap() returns, just rendered at a
    higher, fixed output resolution instead of the on-screen size.

    scale is always >= min_scale (the scale at which the source's
    SHORTER side exactly fills the viewport -- "image automatically
    fitted into crop area"), which keeps the clamp math in
    _clamp_offset() always solvable: at min_scale both dimensions are
    already >= VIEWPORT_SIZE, and zooming in only grows that margin.
    """

    def __init__(self, source: QPixmap, parent=None):
        super().__init__(parent)

        self.source = source
        self.min_scale = VIEWPORT_SIZE / min(source.width(), source.height())
        self.scale = self.min_scale
        # offset is a point IN SOURCE-IMAGE COORDINATES that is
        # currently rendered at the viewport's center -- starts at the
        # image's own center, i.e. no pan yet.
        self.offset = QPointF(source.width() / 2.0, source.height() / 2.0)

        self.setFixedSize(VIEWPORT_SIZE, VIEWPORT_SIZE)
        self.setCursor(Qt.OpenHandCursor)
        self._dragging = False
        self._drag_start_pos = QPointF()
        self._drag_start_offset = QPointF()

    def set_scale(self, scale: float):
        self.scale = max(self.min_scale, scale)
        self._clamp_offset()
        self.update()

    def _clamp_offset(self):
        half_w = (VIEWPORT_SIZE / 2.0) / self.scale
        half_h = (VIEWPORT_SIZE / 2.0) / self.scale
        min_x, max_x = half_w, max(half_w, self.source.width() - half_w)
        min_y, max_y = half_h, max(half_h, self.source.height() - half_h)
        self.offset.setX(min(max(self.offset.x(), min_x), max_x))
        self.offset.setY(min(max(self.offset.y(), min_y), max_y))

    def paintEvent(self, event):  # noqa: N802 (Qt override)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)
        self._paint_onto(painter, self.scale, VIEWPORT_SIZE)
        painter.end()

    def _paint_onto(self, painter: QPainter, scale: float, viewport_size: int):
        scaled_w = self.source.width() * scale
        scaled_h = self.source.height() * scale
        top_left_x = viewport_size / 2.0 - self.offset.x() * scale
        top_left_y = viewport_size / 2.0 - self.offset.y() * scale
        painter.drawPixmap(
            QRectF(top_left_x, top_left_y, scaled_w, scaled_h),
            self.source,
            QRectF(self.source.rect()),
        )

    def get_cropped_pixmap(self, output_size: int = OUTPUT_SIZE) -> QPixmap:
        output = QPixmap(output_size, output_size)
        output.fill(Qt.transparent)
        painter = QPainter(output)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)
        output_scale = self.scale * (output_size / VIEWPORT_SIZE)
        self._paint_onto(painter, output_scale, output_size)
        painter.end()
        return output

    # ==========================================================
    # Pan (mouse drag)
    # ==========================================================

    def mousePressEvent(self, event):  # noqa: N802
        if event.button() == Qt.LeftButton:
            self._dragging = True
            self._drag_start_pos = event.position()
            self._drag_start_offset = QPointF(self.offset)
            self.setCursor(Qt.ClosedHandCursor)

    def mouseMoveEvent(self, event):  # noqa: N802
        if not self._dragging:
            return
        delta = event.position() - self._drag_start_pos
        self.offset = QPointF(
            self._drag_start_offset.x() - delta.x() / self.scale,
            self._drag_start_offset.y() - delta.y() / self.scale,
        )
        self._clamp_offset()
        self.update()

    def mouseReleaseEvent(self, event):  # noqa: N802
        if event.button() == Qt.LeftButton:
            self._dragging = False
            self.setCursor(Qt.OpenHandCursor)


class ImageCropDialog(QDialog):
    """
    Pan/zoom a square crop over ``source_pixmap``; Save returns the
    cropped result via get_result(), Cancel/close returns None.
    """

    def __init__(self, source_pixmap: QPixmap, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Crop Profile Picture")
        self._result = None

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(12)

        hint = QLabel("Drag to reposition. Use the slider to zoom.")
        hint.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;")
        hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(hint)

        canvas_frame = QWidget()
        canvas_frame.setFixedSize(VIEWPORT_SIZE, VIEWPORT_SIZE)
        canvas_frame.setStyleSheet(
            f"background-color: {COLOR_PANEL_ALT}; border-radius: 8px;"
        )
        canvas_layout = QVBoxLayout(canvas_frame)
        canvas_layout.setContentsMargins(0, 0, 0, 0)
        self.canvas = _CropCanvas(source_pixmap)
        canvas_layout.addWidget(self.canvas)
        layout.addWidget(canvas_frame, alignment=Qt.AlignCenter)

        zoom_row = QHBoxLayout()
        zoom_label = QLabel("Zoom")
        zoom_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;")
        zoom_row.addWidget(zoom_label)
        self.zoom_slider = QSlider(Qt.Horizontal)
        self.zoom_slider.setRange(_ZOOM_MIN, _ZOOM_MAX)
        self.zoom_slider.setValue(_ZOOM_MIN)
        self.zoom_slider.valueChanged.connect(self._on_zoom_changed)
        zoom_row.addWidget(self.zoom_slider)
        layout.addLayout(zoom_row)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)

        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(cancel_button)

        save_button = QPushButton("Save")
        save_button.setCursor(Qt.PointingHandCursor)
        save_button.clicked.connect(self._handle_save)
        button_row.addWidget(save_button)

        layout.addLayout(button_row)

    def _on_zoom_changed(self, value):
        self.canvas.set_scale(self.canvas.min_scale * (value / 100.0))

    def wheelEvent(self, event):  # noqa: N802
        step = 10 if event.angleDelta().y() > 0 else -10
        self.zoom_slider.setValue(self.zoom_slider.value() + step)

    def _handle_save(self):
        self._result = self.canvas.get_cropped_pixmap()
        self.accept()

    def get_result(self):
        """QPixmap (square, OUTPUT_SIZE x OUTPUT_SIZE) if Save was
        pressed, else None."""
        return self._result
