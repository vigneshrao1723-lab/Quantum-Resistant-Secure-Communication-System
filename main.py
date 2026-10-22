"""
Quantum-Resistant Secure Communication System

Application Entry Point
"""

import sys

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from gui.icons import brand_pixmap
from gui.main_window import MainWindow
from gui.styles import apply_theme


def main():
    """
    Start the GUI application.
    """

    # Create the Qt application
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(brand_pixmap(256)))

    # Apply the global stylesheet and the theme (light, dark, or follow Windows -- Settings > Appearance)
    apply_theme(app)

    # Create and display the main window
    window = MainWindow()
    window.show()

    # Start the Qt event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()