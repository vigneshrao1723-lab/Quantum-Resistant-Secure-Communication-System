"""
Application Stylesheet

Contains the global stylesheet for the
Quantum-Resistant Secure Communication System.
"""


APP_STYLE = """
/* ==========================================================
   GLOBAL
   ========================================================== */

QMainWindow,
QWidget {
    background-color: #1E1E1E;
    color: #FFFFFF;
    font-family: "Segoe UI";
    font-size: 11pt;
}


/* ==========================================================
   LABELS
   ========================================================== */

QLabel {
    color: white;
}


/* ==========================================================
   TITLE
   ========================================================== */

QLabel#Title {
    font-size: 28px;
    font-weight: bold;
    color: white;
}

QLabel#Subtitle {
    font-size: 15px;
    color: #A0A0A0;
}


/* ==========================================================
   INPUT
   ========================================================== */

QLineEdit {

    background-color: #2B2B2B;

    border: 2px solid #3C3F41;

    border-radius: 10px;

    padding: 10px;

    color: white;

    selection-background-color: #0078D7;
}

QLineEdit:focus {

    border: 2px solid #0099FF;
}


/* ==========================================================
   BUTTON
   ========================================================== */

QPushButton {

    background-color: #0078D7;

    color: white;

    border: none;

    border-radius: 10px;

    padding: 12px;

    font-weight: bold;
}

QPushButton:hover {

    background-color: #2196F3;
}

QPushButton:pressed {

    background-color: #005A9E;
}


/* ==========================================================
   LIST
   ========================================================== */

QListWidget {

    background-color: #252526;

    border: 1px solid #3C3F41;

    border-radius: 10px;

    padding: 5px;
}

QListWidget::item {

    padding: 10px;

    border-radius: 8px;
}

QListWidget::item:selected {

    background-color: #0078D7;
}


/* ==========================================================
   SCROLLBAR
   ========================================================== */

QScrollBar:vertical {

    background: #2B2B2B;

    width: 12px;

    margin: 0px;
}

QScrollBar::handle:vertical {

    background: #555555;

    border-radius: 6px;
}

QScrollBar::handle:vertical:hover {

    background: #777777;
}

QScrollBar::add-line,
QScrollBar::sub-line {

    height: 0px;
}


/* ==========================================================
   STATUS BAR
   ========================================================== */

QStatusBar {

    background-color: #252526;

    color: white;
}
"""