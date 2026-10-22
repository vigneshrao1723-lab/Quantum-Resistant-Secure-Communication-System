"""The Desktop shows its brand mark (the shipped logo.png is an empty file) and can build an icon from it."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication

from gui.icons import brand_pixmap
from gui.login_window import LoginWindow
from gui.styles import COLOR_ACCENT

_app = QApplication.instance() or QApplication([])


def test_brand_mark_is_the_requested_size_with_the_accent_background_and_a_white_padlock():
    image = brand_pixmap(128).toImage()

    assert (image.width(), image.height()) == (128, 128)
    assert image.pixelColor(20, 64).name().upper() == QColor(COLOR_ACCENT).name().upper()  # background
    assert image.pixelColor(45, 84).name().upper() == "#FFFFFF"                             # padlock body
    assert image.pixelColor(0, 0).alpha() == 0                                              # rounded corner


def test_login_screen_shows_the_brand_mark():
    window = LoginWindow()

    assert window.logo.pixmap() is not None and not window.logo.pixmap().isNull()
    assert window.logo.accessibleName()
