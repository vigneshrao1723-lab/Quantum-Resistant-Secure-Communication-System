"""
Avatar widget.

A round avatar showing a contact's initial (or a group glyph) on a tone chosen
from the person's name, with an optional presence dot. The tone palette and the
name -> tone hash are the same ones the Web client uses (``--tone-0..5`` and
``avatarTone()`` in web/client), so a contact has the same colour on every
client.
"""

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QAbstractButton, QWidget

from gui.styles import COLOR_ACCENT, COLOR_OFFLINE, COLOR_ONLINE, COLOR_SIDEBAR, avatar_tone_color


class AvatarWidget(QWidget):
    def __init__(self, name, size=44, online=None, is_group=False, ring_color=COLOR_SIDEBAR):
        super().__init__()

        self._name = name or ""
        self._online = online
        self._is_group = is_group
        self._ring = QColor(ring_color)

        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAutoFillBackground(False)
        self.setToolTip("")

    def set_online(self, online):
        if online != self._online:
            self._online = online
            self.update()

    def set_ring_color(self, color):
        self._ring = QColor(color)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        side = min(self.width(), self.height())
        circle = QRectF(0, 0, side, side)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(avatar_tone_color(self._name, group=self._is_group)))
        painter.drawEllipse(circle)

        initial = (self._name.strip()[:1] or "?").upper()
        font = QFont(self.font())
        font.setBold(True)
        font.setPixelSize(max(10, int(side * 0.40)))
        painter.setFont(font)
        painter.setPen(QColor("#FFFFFF"))
        painter.drawText(circle, Qt.AlignCenter, initial)

        if self._online is not None:
            dot = max(10, int(side * 0.27))
            dot_rect = QRectF(side - dot - 1, side - dot - 1, dot, dot)
            painter.setPen(Qt.NoPen)
            painter.setBrush(self._ring)
            painter.drawEllipse(dot_rect.adjusted(-2, -2, 2, 2))
            painter.setBrush(QColor(COLOR_ONLINE) if self._online else QColor(COLOR_OFFLINE))
            painter.drawEllipse(dot_rect)

        painter.end()


def circular_pixmap(source, size, ratio=2):
    """``source`` (a QPixmap, any shape) centre-cropped to a square and clipped to a circle.

    A CSS border-radius on a QLabel rounds the widget's own box, not the pixmap drawn in it, so
    the clip is done here, pixel by pixel."""

    from PySide6.QtGui import QPainterPath, QPixmap

    side = min(source.width(), source.height())
    square = source.copy((source.width() - side) // 2, (source.height() - side) // 2, side, side)
    scaled = square.scaled(size * ratio, size * ratio, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
    result = QPixmap(size * ratio, size * ratio)
    result.setDevicePixelRatio(ratio)
    result.fill(Qt.transparent)
    painter = QPainter(result)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    path = QPainterPath()
    path.addEllipse(QRectF(0, 0, size, size))
    painter.setClipPath(path)
    painter.drawPixmap(QRectF(0, 0, size, size), scaled, QRectF(scaled.rect()))
    painter.end()
    return result


def placeholder_pixmap(name, size, ratio=2):
    """The coloured-initial avatar as a pixmap (same look as AvatarWidget)."""

    from PySide6.QtGui import QPixmap

    pixmap = QPixmap(size * ratio, size * ratio)
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    circle = QRectF(0, 0, size, size)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(avatar_tone_color(name)))
    painter.drawEllipse(circle)
    font = QFont()
    font.setBold(True)
    font.setPixelSize(max(10, int(size * 0.40)))
    painter.setFont(font)
    painter.setPen(QColor("#FFFFFF"))
    painter.drawText(circle, Qt.AlignCenter, (str(name or "").strip()[:1] or "?").upper())
    painter.end()
    return pixmap


class AvatarButton(QAbstractButton):
    """A round avatar that is also a button: the person's real picture when there is one (else the
    coloured-initial placeholder). Keyboard-focusable; Enter, Return and Space activate it."""

    def __init__(self, name="", size=40, accessible_name=""):
        super().__init__()

        self._name = name or ""
        self._size = size
        self._pixmap = None
        self._is_group = False

        self.setFixedSize(size, size)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        if accessible_name:
            self.setAccessibleName(accessible_name)

    @property
    def has_picture(self):
        return self._pixmap is not None

    def set_name(self, name, is_group=False):
        self._name = name or ""
        self._is_group = is_group
        self.update()

    def set_picture_bytes(self, data):
        """Show ``data`` (image bytes); returns False (and shows the placeholder) if it is not an image."""

        from PySide6.QtGui import QPixmap

        pixmap = QPixmap()
        if data and pixmap.loadFromData(bytes(data)) and not pixmap.isNull():
            self._pixmap = pixmap
        else:
            self._pixmap = None
        self.update()
        return self._pixmap is not None

    def clear_picture(self):
        self._pixmap = None
        self.update()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            self.click()
            event.accept()
            return
        super().keyPressEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        side = min(self.width(), self.height())

        if self._pixmap is not None:
            painter.drawPixmap(0, 0, circular_pixmap(self._pixmap, side))
        else:
            painter.drawPixmap(0, 0, placeholder_pixmap(self._name, side))

        if self.underMouse():
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(0, 0, 0, 28))
            painter.drawEllipse(QRectF(0, 0, side, side))

        if self.hasFocus():
            from PySide6.QtGui import QPen

            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(QColor(COLOR_ACCENT), 2))
            painter.drawEllipse(QRectF(1, 1, side - 2, side - 2))

        painter.end()
