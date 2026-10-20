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
from PySide6.QtWidgets import QWidget

from gui.styles import COLOR_ONLINE, COLOR_SIDEBAR, avatar_tone_color


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
            painter.setBrush(QColor(COLOR_ONLINE) if self._online else QColor("#B5B5BA"))
            painter.drawEllipse(dot_rect)

        painter.end()
