"""
Quantum-Resistant Secure Communication System

Application Entry Point
"""

import sys

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow
from gui.styles import APP_STYLE


def main():
    """
    Start the GUI application.
    """

    # Create the Qt application
    app = QApplication(sys.argv)

    # Apply the global stylesheet
    app.setStyleSheet(APP_STYLE)

    # Create and display the main window
    window = MainWindow()
    window.show()

    # Start the Qt event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()