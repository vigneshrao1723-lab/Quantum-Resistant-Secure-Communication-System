"""
Application Stylesheet

Contains the global stylesheet and colour palette for the
Quantum-Resistant Secure Communication System.
"""


# ==============================================================
# Colour Palette
# ==============================================================

# Phase 19.17A -- UI/UX parity pass: the Android APK (mobile/app.py)
# is now this project's design reference across all three clients, so
# this palette was rebuilt to match it channel-for-channel (its RGBA
# floats converted to hex) rather than kept as its own independent
# dark theme. Every named role below (BG/SURFACE/TEXT/ACCENT/ONLINE/
# OFFLINE/DANGER/border radius) maps 1:1 to mobile/app.py's own
# PURPLE/PURPLE_DARK/BG/SURFACE/TEXT_DARK/TEXT_GRAY/ONLINE_GREEN/
# OFFLINE_GRAY/DANGER/BORDER constants -- this is a light theme now,
# not a retint of the old dark one, because Android's reference design
# is light. Structural QSS selectors below are unchanged; only values.
COLOR_BG = "#F3F3F6"
COLOR_PANEL = "#FFFFFF"
COLOR_PANEL_ALT = "#ECECF2"
COLOR_BORDER = "#E6E6ED"

COLOR_TEXT = "#1D1D2E"
COLOR_TEXT_MUTED = "#8E8E98"

COLOR_ACCENT = "#765CF2"
COLOR_ACCENT_HOVER = "#8B74F5"
COLOR_ACCENT_PRESSED = "#5E44E0"

# PQC/Kyber vs. RSA/classical stay on two unrelated hues (cyan vs.
# amber) so the two remain distinguishable at a glance regardless of
# which accent color the rest of the UI uses.
COLOR_QUANTUM = "#1C9C96"
COLOR_CLASSICAL = "#C97A0A"

COLOR_ONLINE = "#2DC8A4"
COLOR_OFFLINE = "#B5B5BA"

# Deliberately NOT COLOR_OFFLINE: the unread badge and the offline dot
# render on the same conversation row, and reusing red for both let one
# color mean two unrelated things ("they're offline" vs "you have
# unread messages"). The accent is otherwise used for interactive/
# highlight elements, which "needs your attention" fits naturally.
COLOR_UNREAD = COLOR_ACCENT

COLOR_DANGER = "#D95252"

# Android's own PillButton sent-bubble color IS the plain accent
# purple (mobile/app.py Bubble: `bg, radius = PURPLE, [16,16,4,16]`
# for kind == "sent") -- matched exactly, not approximated.
COLOR_BUBBLE_SENT = COLOR_ACCENT

# Android's own read-tick color (mobile/app.py Bubble._READ_TICK_COLOR
# = (0.35, 0.68, 0.97, 1)), matched exactly rather than re-derived --
# reads clearly as "the read state" against the purple sent bubble
# without being confusable with the accent purple itself.
COLOR_READ_RECEIPT = "#59ADF7"

COLOR_BUBBLE_FAILED = "#FBE6EA"
COLOR_SEND_FAILED = COLOR_DANGER
# Android's own received-bubble color (mobile/app.py Bubble: bg =
# (0.85, 0.85, 0.90, 1) for kind == "received"), matched exactly.
COLOR_BUBBLE_RECEIVED = "#D9D9E6"
COLOR_BUBBLE_SYSTEM = COLOR_PANEL_ALT

# ==============================================================
# Chat Wallpaper (Phase 19.24)
# ==============================================================
#
# Local-only per-conversation preference (storage/secure_key_store.py
# ::get/set_conversation_wallpaper()), never sent to or stored by the
# server. A small, deliberately bounded set of PRESET gradients rather
# than arbitrary custom images -- no new file-storage/upload handling
# per platform, and every preset is chosen soft/low-contrast enough
# that the existing solid, opaque bubble colors above (COLOR_BUBBLE_
# SENT/RECEIVED) stay fully readable on top of it, unchanged. Mirrored
# by mobile/app.py's own WALLPAPER_PRESETS and web/client/style.css's
# .wallpaper-* classes -- same ids, same colors, so switching clients
# feels like the same app. "default" (id None) means no wallpaper --
# the plain panel background every conversation already had.
WALLPAPER_PRESETS = {
    "lavender": ("Lavender", f"qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #EDE9FE, stop:1 #DCD3FB)"),
    "ocean": ("Ocean", "qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #E3F2FD, stop:1 #BBDEFB)"),
    "sunset": ("Sunset", "qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #FFF3E0, stop:1 #FFE0B2)"),
    "mint": ("Mint", "qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #E0F5EC, stop:1 #C8ECDE)"),
    "midnight": ("Midnight", "qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #2A2A3D, stop:1 #1D1D2E)"),
}

# QListWidget::item below reserves this many px on both the top and
# bottom of every row's rect. Every QListWidget that embeds a widget
# via setItemWidget() (message bubbles in gui/message_widget.py,
# sidebar rows in gui/conversation_list_widget.py) must add
# LIST_ITEM_VERTICAL_MARGIN back onto the height it passes to
# QListWidgetItem.setSizeHint() -- that margin is carved out of the
# SAME rect the embedded widget is given on top of its own sizeHint(),
# so without compensating, the widget is silently granted less height
# than it asked for. Invisible for cap-height text, but enough to crop
# the descender off a lowercase "y"/"g"/"j"/"p"/"q", which then reads
# as an unrelated letter -- a "y" missing its tail is easily misread
# as "v"/"V".
_LIST_ITEM_MARGIN_PX = 2
LIST_ITEM_VERTICAL_MARGIN = _LIST_ITEM_MARGIN_PX * 2


APP_STYLE = f"""
/* ==========================================================
   GLOBAL
   ========================================================== */

QMainWindow,
QWidget {{
    background-color: {COLOR_BG};
    color: {COLOR_TEXT};
    font-family: "Segoe UI", "Roboto", sans-serif;
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
    border-radius: 14px;
    padding: 11px 16px;
    color: {COLOR_TEXT};
    selection-background-color: {COLOR_ACCENT};
}}

QLineEdit:focus {{
    border: 2px solid {COLOR_ACCENT};
    background-color: {COLOR_PANEL};
}}

QLineEdit:disabled {{
    color: {COLOR_TEXT_MUTED};
}}


/* ==========================================================
   BUTTON
   ========================================================== */

/* Android's own PillButton is fully rounded (corner radius =
   height/2); QSS has no live height-relative radius, so a generous
   fixed radius + the padding/min-height below approximates the same
   true-pill silhouette at this button's typical rendered size. */
QPushButton {{
    background-color: {COLOR_ACCENT};
    color: #FFFFFF;
    border: none;
    border-radius: 21px;
    padding: 12px 22px;
    min-height: 20px;
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

/* Android's GhostButton: no fill, accent-colored text/border. */
QPushButton#SecondaryButton {{
    background-color: transparent;
    color: {COLOR_ACCENT};
    border: 1.5px solid {COLOR_BORDER};
}}

QPushButton#SecondaryButton:hover {{
    border: 1.5px solid {COLOR_ACCENT};
    background-color: {COLOR_PANEL_ALT};
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
    border-radius: 16px;
    padding: 6px;
    outline: none;
}}

QListWidget::item {{
    border-radius: 12px;
    margin: {_LIST_ITEM_MARGIN_PX}px 0px;
}}

QListWidget::item:selected {{
    background-color: {COLOR_PANEL_ALT};
    border: 1px solid {COLOR_ACCENT};
}}

QListWidget::item:hover {{
    background-color: {COLOR_PANEL_ALT};
}}


/* ==========================================================
   MEMBER PICKER (create group / add members)

   Scoped to #MemberList on purpose. The conversation sidebar is
   also a QListWidget, but its rows are setItemWidget() widgets
   sized by sizeHint() -- adding padding there would desynchronise
   the row height from the widget it contains, and it draws no
   checkbox indicator at all.
   ========================================================== */

QListWidget#MemberList::item {{
    padding: 9px 8px;
}}

QListWidget#MemberList::indicator {{
    width: 18px;
    height: 18px;
    margin-right: 8px;
    border: 2px solid {COLOR_TEXT_MUTED};
    border-radius: 5px;
    background-color: {COLOR_PANEL_ALT};
}}

QListWidget#MemberList::indicator:hover {{
    border: 2px solid {COLOR_ACCENT};
}}

/* Filled accent block = selected. Styling ::indicator at all
   replaces Qt's native rendering, which takes the tick glyph with
   it, so the checked state is carried by fill and border rather
   than by a mark -- readable without shipping an image asset. */
QListWidget#MemberList::indicator:checked {{
    background-color: {COLOR_ACCENT};
    border: 2px solid {COLOR_ACCENT};
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