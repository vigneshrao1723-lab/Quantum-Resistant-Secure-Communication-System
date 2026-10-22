"""
Toolbar and navigation icons.

A small set of simple stroke icons drawn with QPainter, so every glyph in the
chat window shares one visual weight and takes its colour from the application
palette -- the emoji they replace rendered in a different set of colours each
and ignored the theme.

Every icon is drawn on a 24x24 design grid with a 1.8 stroke, rounded caps and
joins, and rasterised at 2x so it stays crisp on high-DPI screens. Each
returned QIcon carries a muted rendering for the resting state and an accent
rendering for hover/pressed and for the checked ("On") state, so interaction
feedback needs no extra code at the call site.
"""

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

from gui.styles import COLOR_ACCENT, COLOR_TEXT_MUTED

_GRID = 24
_SCALE = 2


def _draw_search(p):
    p.drawEllipse(QRectF(3.5, 3.5, 12, 12))
    p.drawLine(QPointF(13.0, 13.0), QPointF(20.5, 20.5))


def _draw_pin(p):
    # Head, shaft and needle of a push-pin, tilted like the common pin glyph.
    path = QPainterPath()
    path.moveTo(9.0, 3.5)
    path.lineTo(16.0, 3.5)
    path.lineTo(15.0, 9.5)
    path.lineTo(18.0, 12.5)
    path.lineTo(18.0, 14.0)
    path.lineTo(6.0, 14.0)
    path.lineTo(6.0, 12.5)
    path.lineTo(9.0, 9.5)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(12.0, 14.0), QPointF(12.0, 20.5))


def _draw_gallery(p):
    p.drawRoundedRect(QRectF(3.5, 4.5, 17, 15), 2.5, 2.5)
    p.drawEllipse(QRectF(7.0, 8.0, 3.0, 3.0))
    path = QPainterPath()
    path.moveTo(4.5, 17.5)
    path.lineTo(9.5, 13.0)
    path.lineTo(13.0, 16.0)
    path.lineTo(16.0, 13.5)
    path.lineTo(19.5, 17.0)
    p.drawPath(path)


def _draw_wallpaper(p):
    # A paint palette: rounded body with a thumb hole and three colour dots.
    path = QPainterPath()
    path.moveTo(12.0, 3.5)
    path.cubicTo(6.0, 3.5, 3.0, 7.5, 3.0, 11.5)
    path.cubicTo(3.0, 16.5, 7.0, 20.5, 12.0, 20.5)
    path.cubicTo(14.0, 20.5, 14.5, 19.0, 13.5, 17.5)
    path.cubicTo(12.5, 16.0, 13.5, 14.5, 15.5, 14.5)
    path.lineTo(17.5, 14.5)
    path.cubicTo(19.8, 14.5, 21.0, 13.0, 21.0, 11.5)
    path.cubicTo(21.0, 7.0, 17.5, 3.5, 12.0, 3.5)
    p.drawPath(path)
    for x, y in ((7.5, 10.5), (11.0, 7.5), (15.5, 8.5)):
        p.drawEllipse(QPointF(x, y), 1.0, 1.0)


def _draw_chat(p):
    # Speech bubble with a tail at the lower left.
    path = QPainterPath()
    path.moveTo(5.5, 4.5)
    path.lineTo(18.5, 4.5)
    path.cubicTo(19.9, 4.5, 21.0, 5.6, 21.0, 7.0)
    path.lineTo(21.0, 13.5)
    path.cubicTo(21.0, 14.9, 19.9, 16.0, 18.5, 16.0)
    path.lineTo(10.5, 16.0)
    path.lineTo(6.0, 20.0)
    path.lineTo(6.0, 16.0)
    path.lineTo(5.5, 16.0)
    path.cubicTo(4.1, 16.0, 3.0, 14.9, 3.0, 13.5)
    path.lineTo(3.0, 7.0)
    path.cubicTo(3.0, 5.6, 4.1, 4.5, 5.5, 4.5)
    path.closeSubpath()
    p.drawPath(path)


def _draw_archive(p):
    p.drawRoundedRect(QRectF(3.0, 4.5, 18.0, 4.5), 1.5, 1.5)
    path = QPainterPath()
    path.moveTo(4.5, 9.0)
    path.lineTo(4.5, 18.0)
    path.cubicTo(4.5, 19.1, 5.4, 20.0, 6.5, 20.0)
    path.lineTo(17.5, 20.0)
    path.cubicTo(18.6, 20.0, 19.5, 19.1, 19.5, 18.0)
    path.lineTo(19.5, 9.0)
    p.drawPath(path)
    p.drawLine(QPointF(9.5, 13.0), QPointF(14.5, 13.0))


def _draw_inbox(p):
    path = QPainterPath()
    path.moveTo(3.5, 13.5)
    path.lineTo(6.5, 5.5)
    path.lineTo(17.5, 5.5)
    path.lineTo(20.5, 13.5)
    path.lineTo(20.5, 18.0)
    path.cubicTo(20.5, 19.1, 19.6, 20.0, 18.5, 20.0)
    path.lineTo(5.5, 20.0)
    path.cubicTo(4.4, 20.0, 3.5, 19.1, 3.5, 18.0)
    path.closeSubpath()
    p.drawPath(path)
    path = QPainterPath()
    path.moveTo(3.5, 13.5)
    path.lineTo(8.5, 13.5)
    path.lineTo(9.8, 16.0)
    path.lineTo(14.2, 16.0)
    path.lineTo(15.5, 13.5)
    path.lineTo(20.5, 13.5)
    p.drawPath(path)


def _draw_devices(p):
    # A laptop and a phone side by side.
    p.drawRoundedRect(QRectF(2.5, 5.5, 14.0, 9.5), 1.5, 1.5)
    p.drawLine(QPointF(1.5, 18.5), QPointF(17.5, 18.5))
    p.drawRoundedRect(QRectF(15.5, 9.5, 6.0, 10.0), 1.5, 1.5)


def _draw_settings(p):
    # Sliders: three horizontal tracks with a knob each.
    for y, knob in ((6.5, 8.5), (12.0, 15.5), (17.5, 10.5)):
        p.drawLine(QPointF(3.5, y), QPointF(knob - 2.2, y))
        p.drawLine(QPointF(knob + 2.2, y), QPointF(20.5, y))
        p.drawEllipse(QPointF(knob, y), 2.2, 2.2)


def _draw_compose(p):
    # Square with a pencil leaving its top-right corner.
    path = QPainterPath()
    path.moveTo(11.0, 4.5)
    path.lineTo(6.0, 4.5)
    path.cubicTo(4.6, 4.5, 3.5, 5.6, 3.5, 7.0)
    path.lineTo(3.5, 18.0)
    path.cubicTo(3.5, 19.4, 4.6, 20.5, 6.0, 20.5)
    path.lineTo(17.0, 20.5)
    path.cubicTo(18.4, 20.5, 19.5, 19.4, 19.5, 18.0)
    path.lineTo(19.5, 13.0)
    p.drawPath(path)
    pen = QPainterPath()
    pen.moveTo(9.0, 15.0)
    pen.lineTo(9.6, 12.2)
    pen.lineTo(18.2, 3.6)
    pen.cubicTo(18.8, 3.0, 19.8, 3.0, 20.4, 3.6)
    pen.cubicTo(21.0, 4.2, 21.0, 5.2, 20.4, 5.8)
    pen.lineTo(11.8, 14.4)
    pen.closeSubpath()
    p.drawPath(pen)


def _draw_group(p):
    p.drawEllipse(QRectF(5.0, 4.5, 6.0, 6.0))
    path = QPainterPath()
    path.moveTo(2.5, 19.5)
    path.cubicTo(2.5, 15.5, 5.0, 13.5, 8.0, 13.5)
    path.cubicTo(11.0, 13.5, 13.5, 15.5, 13.5, 19.5)
    p.drawPath(path)
    p.drawEllipse(QRectF(13.0, 6.0, 5.0, 5.0))
    path = QPainterPath()
    path.moveTo(15.5, 13.8)
    path.cubicTo(18.8, 13.6, 21.5, 15.4, 21.5, 19.5)
    p.drawPath(path)


def _draw_profile(p):
    p.drawEllipse(QRectF(8.0, 4.0, 8.0, 8.0))
    path = QPainterPath()
    path.moveTo(4.5, 20.0)
    path.cubicTo(4.5, 15.8, 7.8, 14.0, 12.0, 14.0)
    path.cubicTo(16.2, 14.0, 19.5, 15.8, 19.5, 20.0)
    p.drawPath(path)


def _draw_filter(p):
    p.drawLine(QPointF(4.0, 7.0), QPointF(20.0, 7.0))
    p.drawLine(QPointF(7.0, 12.0), QPointF(17.0, 12.0))
    p.drawLine(QPointF(10.0, 17.0), QPointF(14.0, 17.0))


def _draw_attach(p):
    path = QPainterPath()
    path.moveTo(19.5, 11.5)
    path.lineTo(12.2, 18.8)
    path.cubicTo(10.2, 20.8, 7.0, 20.8, 5.0, 18.8)
    path.cubicTo(3.0, 16.8, 3.0, 13.6, 5.0, 11.6)
    path.lineTo(12.6, 4.0)
    path.cubicTo(13.9, 2.7, 16.1, 2.7, 17.4, 4.0)
    path.cubicTo(18.7, 5.3, 18.7, 7.5, 17.4, 8.8)
    path.lineTo(10.4, 15.8)
    path.cubicTo(9.7, 16.5, 8.6, 16.5, 7.9, 15.8)
    path.cubicTo(7.2, 15.1, 7.2, 14.0, 7.9, 13.3)
    path.lineTo(14.2, 7.0)
    p.drawPath(path)


def _draw_send(p):
    path = QPainterPath()
    path.moveTo(3.5, 11.0)
    path.lineTo(20.5, 3.5)
    path.lineTo(13.0, 20.5)
    path.lineTo(10.8, 13.2)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(10.8, 13.2), QPointF(20.5, 3.5))


def _draw_more(p):
    p.setBrush(p.pen().color())
    for x in (5.5, 12.0, 18.5):
        p.drawEllipse(QPointF(x, 12.0), 1.4, 1.4)


def _draw_menu(p):
    for y in (6.5, 12.0, 17.5):
        p.drawLine(QPointF(4.0, y), QPointF(20.0, y))


def _draw_mic(p):
    p.drawRoundedRect(QRectF(9.0, 3.5, 6.0, 10.5), 3.0, 3.0)
    path = QPainterPath()
    path.moveTo(5.5, 11.5)
    path.cubicTo(5.5, 15.4, 8.4, 17.8, 12.0, 17.8)
    path.cubicTo(15.6, 17.8, 18.5, 15.4, 18.5, 11.5)
    p.drawPath(path)
    p.drawLine(QPointF(12.0, 17.8), QPointF(12.0, 21.0))


def _draw_video(p):
    p.drawRoundedRect(QRectF(2.5, 6.5, 13.0, 11.0), 2.5, 2.5)
    path = QPainterPath()
    path.moveTo(15.5, 10.5)
    path.lineTo(21.0, 7.5)
    path.lineTo(21.0, 16.5)
    path.lineTo(15.5, 13.5)
    p.drawPath(path)


def _draw_mute(p):
    path = QPainterPath()
    path.moveTo(6.0, 17.5)
    path.lineTo(18.0, 17.5)
    path.cubicTo(17.0, 16.3, 16.5, 15.0, 16.5, 13.0)
    path.lineTo(16.5, 10.5)
    path.cubicTo(16.5, 7.9, 14.5, 5.8, 12.0, 5.8)
    path.cubicTo(9.5, 5.8, 7.5, 7.9, 7.5, 10.5)
    path.lineTo(7.5, 13.0)
    path.cubicTo(7.5, 15.0, 7.0, 16.3, 6.0, 17.5)
    p.drawPath(path)
    p.drawLine(QPointF(10.5, 20.0), QPointF(13.5, 20.0))
    p.drawLine(QPointF(4.5, 4.5), QPointF(19.5, 19.5))


def _draw_close(p):
    p.drawLine(QPointF(6.0, 6.0), QPointF(18.0, 18.0))
    p.drawLine(QPointF(18.0, 6.0), QPointF(6.0, 18.0))


def _filled(p):
    p.setBrush(p.pen().color())


def _draw_play(p):
    _filled(p)
    path = QPainterPath()
    path.moveTo(8.0, 5.5)
    path.lineTo(18.5, 12.0)
    path.lineTo(8.0, 18.5)
    path.closeSubpath()
    p.drawPath(path)


def _draw_pause(p):
    _filled(p)
    p.drawRoundedRect(QRectF(7.0, 5.5, 3.2, 13.0), 1.0, 1.0)
    p.drawRoundedRect(QRectF(13.8, 5.5, 3.2, 13.0), 1.0, 1.0)


def _draw_download(p):
    p.drawLine(QPointF(12.0, 4.0), QPointF(12.0, 15.0))
    path = QPainterPath()
    path.moveTo(7.5, 10.5)
    path.lineTo(12.0, 15.0)
    path.lineTo(16.5, 10.5)
    p.drawPath(path)
    p.drawLine(QPointF(5.0, 19.5), QPointF(19.0, 19.5))


def _draw_logout(p):
    path = QPainterPath()
    path.moveTo(10.0, 4.5)
    path.lineTo(5.5, 4.5)
    path.lineTo(5.5, 19.5)
    path.lineTo(10.0, 19.5)
    p.drawPath(path)
    p.drawLine(QPointF(9.5, 12.0), QPointF(19.5, 12.0))
    arrow = QPainterPath()
    arrow.moveTo(15.5, 8.0)
    arrow.lineTo(19.5, 12.0)
    arrow.lineTo(15.5, 16.0)
    p.drawPath(arrow)


def _draw_speaker(p):
    path = QPainterPath()
    path.moveTo(4.0, 9.5)
    path.lineTo(8.0, 9.5)
    path.lineTo(13.0, 5.0)
    path.lineTo(13.0, 19.0)
    path.lineTo(8.0, 14.5)
    path.lineTo(4.0, 14.5)
    path.closeSubpath()
    p.drawPath(path)


def _draw_volume(p):
    _draw_speaker(p)
    for radius in (4.0, 7.5):
        arc = QPainterPath()
        arc.arcMoveTo(QRectF(13.0 - radius, 12.0 - radius, radius * 2, radius * 2), 40)
        arc.arcTo(QRectF(13.0 - radius, 12.0 - radius, radius * 2, radius * 2), 40, -80)
        p.drawPath(arc)


def _draw_volume_off(p):
    _draw_speaker(p)
    p.drawLine(QPointF(16.5, 9.5), QPointF(21.5, 14.5))
    p.drawLine(QPointF(21.5, 9.5), QPointF(16.5, 14.5))


def _draw_expand(p):
    for a, b, c in (((4.5, 9.5), (4.5, 4.5), (9.5, 4.5)), ((14.5, 4.5), (19.5, 4.5), (19.5, 9.5)),
                    ((19.5, 14.5), (19.5, 19.5), (14.5, 19.5)), ((9.5, 19.5), (4.5, 19.5), (4.5, 14.5))):
        path = QPainterPath()
        path.moveTo(*a)
        path.lineTo(*b)
        path.lineTo(*c)
        p.drawPath(path)


def _draw_file(p):
    path = QPainterPath()
    path.moveTo(6.0, 3.5)
    path.lineTo(14.0, 3.5)
    path.lineTo(18.5, 8.0)
    path.lineTo(18.5, 20.5)
    path.lineTo(6.0, 20.5)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(14.0, 3.5), QPointF(14.0, 8.0))
    p.drawLine(QPointF(14.0, 8.0), QPointF(18.5, 8.0))


def _draw_info(p):
    p.drawEllipse(QRectF(3.5, 3.5, 17.0, 17.0))
    p.drawLine(QPointF(12.0, 11.0), QPointF(12.0, 16.5))
    p.drawPoint(QPointF(12.0, 7.8))


def _draw_shield(p):
    path = QPainterPath()
    path.moveTo(12.0, 3.0)
    path.lineTo(19.0, 6.0)
    path.lineTo(19.0, 11.5)
    path.cubicTo(19.0, 16.0, 16.0, 19.2, 12.0, 21.0)
    path.cubicTo(8.0, 19.2, 5.0, 16.0, 5.0, 11.5)
    path.lineTo(5.0, 6.0)
    path.closeSubpath()
    p.drawPath(path)
    check = QPainterPath()
    check.moveTo(8.8, 12.0)
    check.lineTo(11.2, 14.4)
    check.lineTo(15.4, 9.6)
    p.drawPath(check)


def _draw_camera(p):
    p.drawRoundedRect(QRectF(3.0, 7.0, 18.0, 13.0), 2.5, 2.5)
    path = QPainterPath()
    path.moveTo(8.5, 7.0)
    path.lineTo(10.0, 4.5)
    path.lineTo(14.0, 4.5)
    path.lineTo(15.5, 7.0)
    p.drawPath(path)
    p.drawEllipse(QRectF(8.5, 9.5, 7.0, 7.0))


_DRAWERS = {
    "search": _draw_search,
    "pin": _draw_pin,
    "gallery": _draw_gallery,
    "wallpaper": _draw_wallpaper,
    "chat": _draw_chat,
    "archive": _draw_archive,
    "inbox": _draw_inbox,
    "devices": _draw_devices,
    "settings": _draw_settings,
    "compose": _draw_compose,
    "group": _draw_group,
    "profile": _draw_profile,
    "filter": _draw_filter,
    "attach": _draw_attach,
    "send": _draw_send,
    "more": _draw_more,
    "menu": _draw_menu,
    "close": _draw_close,
    "mic": _draw_mic,
    "mute": _draw_mute,
    "video": _draw_video,
    "play": _draw_play,
    "pause": _draw_pause,
    "download": _draw_download,
    "expand": _draw_expand,
    "logout": _draw_logout,
    "volume": _draw_volume,
    "volume-off": _draw_volume_off,
    "file": _draw_file,
    "info": _draw_info,
    "shield": _draw_shield,
    "camera": _draw_camera,
}


def _render(name, color):
    pixmap = QPixmap(_GRID * _SCALE, _GRID * _SCALE)
    pixmap.setDevicePixelRatio(_SCALE)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    pen = QPen(QColor(color), 1.8)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    _DRAWERS[name](painter)
    painter.end()
    return pixmap


def toolbar_icon(name, color=COLOR_TEXT_MUTED, active_color=COLOR_ACCENT, disabled_color=None):
    """QIcon for ``name``.

    ``color`` is the resting colour; ``active_color`` is used while hovered or
    pressed and when the button is checked (QIcon's "On" state).
    """

    if name not in _DRAWERS:
        raise KeyError(f"unknown toolbar icon: {name!r}")

    icon = QIcon()
    resting = _render(name, color)
    active = _render(name, active_color)
    icon.addPixmap(resting, QIcon.Normal, QIcon.Off)
    icon.addPixmap(active, QIcon.Active, QIcon.Off)
    icon.addPixmap(active, QIcon.Selected, QIcon.Off)
    icon.addPixmap(active, QIcon.Normal, QIcon.On)
    icon.addPixmap(active, QIcon.Active, QIcon.On)
    disabled = _render(name, disabled_color) if disabled_color else resting
    icon.addPixmap(disabled, QIcon.Disabled, QIcon.Off)
    icon.addPixmap(disabled, QIcon.Disabled, QIcon.On)
    return icon


def brand_pixmap(size=48):
    """The application's brand mark: a white padlock on a rounded accent square.

    The Website's brand mark is the same padlock on the same accent colour. It is drawn rather than
    loaded from a file so the Desktop login screen, the window and the executable's icon always
    exist and always match the palette.
    """

    scale = 4  # rasterised large, then scaled, so every size stays crisp
    side = size * scale
    pixmap = QPixmap(side, side)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(COLOR_ACCENT))
    painter.drawRoundedRect(QRectF(0, 0, side, side), side * 0.24, side * 0.24)

    # Padlock on a 24-unit grid centred in the square.
    unit = side / 24.0
    painter.translate(0, 0)
    pen = QPen(QColor("#FFFFFF"), 1.9 * unit)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)

    shackle = QPainterPath()
    shackle.moveTo(8.2 * unit, 11 * unit)
    shackle.lineTo(8.2 * unit, 8.4 * unit)
    shackle.arcTo(QRectF(8.2 * unit, 4.4 * unit, 7.6 * unit, 8.0 * unit), 180, -180)
    shackle.lineTo(15.8 * unit, 11 * unit)
    painter.drawPath(shackle)

    painter.setBrush(QColor("#FFFFFF"))
    painter.drawRoundedRect(QRectF(6.2 * unit, 11 * unit, 11.6 * unit, 8.2 * unit), 2.0 * unit, 2.0 * unit)

    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(COLOR_ACCENT))
    painter.drawEllipse(QPointF(12 * unit, 14.4 * unit), 1.1 * unit, 1.1 * unit)
    painter.drawRoundedRect(QRectF(11.4 * unit, 14.8 * unit, 1.2 * unit, 2.2 * unit), 0.5 * unit, 0.5 * unit)
    painter.end()

    return pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
