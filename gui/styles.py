"""
Application Stylesheet

Contains the global stylesheet and colour palette for the
Quantum-Resistant Secure Communication System.
"""


# ==============================================================
# Colour Palette
# ==============================================================

COLOR_BG = "#0F1220"
COLOR_PANEL = "#171A2B"
COLOR_PANEL_ALT = "#1D2136"
COLOR_BORDER = "#2A2E45"

COLOR_TEXT = "#F2F3F7"
COLOR_TEXT_MUTED = "#8B90A8"

COLOR_ACCENT = "#5B8DFF"
COLOR_ACCENT_HOVER = "#7BA3FF"
COLOR_ACCENT_PRESSED = "#3E6FE0"

COLOR_QUANTUM = "#18E5B5"
COLOR_CLASSICAL = "#FFB020"

COLOR_ONLINE = "#18E5B5"
COLOR_OFFLINE = "#FF5C7C"

COLOR_BUBBLE_SENT = "#5B8DFF"
COLOR_BUBBLE_RECEIVED = "#232841"
COLOR_BUBBLE_SYSTEM = "#171A2B"


APP_STYLE = f"""
/* ==========================================================
   GLOBAL
   ========================================================== */

QMainWindow,
QWidget {{
    background-color: {COLOR_BG};
    color: {COLOR_TEXT};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 11pt;
}}


/* ==========================================================
   LABELS
   ========================================================== */

QLabel {{
    color: {COLOR_TEXT};
    background: transparent;
}}

QLabel#Title {{
    font-size: 26px;
    font-weight: 700;
    color: {COLOR_TEXT};
}}

QLabel#Subtitle {{
    font-size: 14px;
    color: {COLOR_TEXT_MUTED};
}}

QLabel#SectionTitle {{
    font-size: 13px;
    font-weight: 600;
    color: {COLOR_TEXT_MUTED};
    letter-spacing: 1px;
    text-transform: uppercase;
}}

QLabel#FieldLabel {{
    font-size: 10.5pt;
    font-weight: 600;
    color: {COLOR_TEXT_MUTED};
}}


/* ==========================================================
   PANELS / CARDS
   ========================================================== */

QFrame#Card {{
    background-color: {COLOR_PANEL};
    border: 1px solid {COLOR_BORDER};
    border-radius: 16px;
}}

QFrame#Panel {{
    background-color: {COLOR_PANEL};
    border: 1px solid {COLOR_BORDER};
    border-radius: 14px;
}}


/* ==========================================================
   INPUT
   ========================================================== */

QLineEdit {{
    background-color: {COLOR_PANEL_ALT};
    border: 2px solid {COLOR_BORDER};
    border-radius: 10px;
    padding: 11px 14px;
    color: {COLOR_TEXT};
    selection-background-color: {COLOR_ACCENT};
}}

QLineEdit:focus {{
    border: 2px solid {COLOR_ACCENT};
}}

QLineEdit:disabled {{
    color: {COLOR_TEXT_MUTED};
}}


/* ==========================================================
   BUTTON
   ========================================================== */

QPushButton {{
    background-color: {COLOR_ACCENT};
    color: #0B0D16;
    border: none;
    border-radius: 10px;
    padding: 12px;
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: {COLOR_ACCENT_HOVER};
}}

QPushButton:pressed {{
    background-color: {COLOR_ACCENT_PRESSED};
}}

QPushButton:disabled {{
    background-color: {COLOR_PANEL_ALT};
    color: {COLOR_TEXT_MUTED};
}}

QPushButton#SecondaryButton {{
    background-color: transparent;
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
}}

QPushButton#SecondaryButton:hover {{
    border: 1px solid {COLOR_ACCENT};
    color: {COLOR_ACCENT};
}}

QPushButton#IconButton {{
    background-color: transparent;
    border-radius: 8px;
    padding: 6px;
}}

QPushButton#IconButton:hover {{
    background-color: {COLOR_PANEL_ALT};
}}


/* ==========================================================
   LIST
   ========================================================== */

QListWidget {{
    background-color: {COLOR_PANEL};
    border: 1px solid {COLOR_BORDER};
    border-radius: 14px;
    padding: 6px;
    outline: none;
}}

QListWidget::item {{
    border-radius: 10px;
    margin: 2px 0px;
}}

QListWidget::item:selected {{
    background-color: {COLOR_PANEL_ALT};
    border: 1px solid {COLOR_ACCENT};
}}

QListWidget::item:hover {{
    background-color: {COLOR_PANEL_ALT};
}}


/* ==========================================================
   SCROLLBAR
   ========================================================== */

QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 4px 0px;
}}

QScrollBar::handle:vertical {{
    background: {COLOR_BORDER};
    border-radius: 5px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background: {COLOR_TEXT_MUTED};
}}

QScrollBar::add-line,
QScrollBar::sub-line {{
    height: 0px;
}}

QScrollBar::add-page,
QScrollBar::sub-page {{
    background: transparent;
}}


/* ==========================================================
   TOOLTIP
   ========================================================== */

QToolTip {{
    background-color: {COLOR_PANEL_ALT};
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px;
}}


/* ==========================================================
   STATUS BAR
   ========================================================== */

QStatusBar {{
    background-color: {COLOR_PANEL};
    color: {COLOR_TEXT};
}}
"""