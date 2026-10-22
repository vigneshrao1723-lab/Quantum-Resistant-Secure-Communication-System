"""
Application Stylesheet

Contains the global stylesheet and colour palette for the
Quantum-Resistant Secure Communication System.
"""


# ==============================================================
# Theme and colour palette
# ==============================================================
#
# One palette per theme, taken from the Website's design tokens (web/client/style.css, ":root" and
# ":root[data-color-scheme=dark]") so both clients look like one product. The theme is chosen ONCE,
# when this module is first imported, because every widget builds its inline stylesheet from the
# constants below at construction time: it is "light", "dark", or "system" (follow Windows), saved by
# Settings -> Appearance and applied the next time the application starts. Tests (offscreen) always
# run light unless QRSCS_THEME says otherwise.

import json
import os
import sys
from pathlib import Path


def _theme_file():
    return Path(os.environ.get("QRSCS_THEME_FILE") or (Path.home() / ".qrscs" / "desktop_theme.json"))


def saved_theme_preference():
    """The person's saved choice: "light", "dark" or "system" (the default)."""

    override = os.environ.get("QRSCS_THEME")
    if override in ("light", "dark", "system"):
        return override
    # A headless (offscreen) run -- the automated tests -- never picks up the choice a person saved on
    # this computer, so its results do not depend on whoever last used the app. A test can still name a
    # file explicitly with QRSCS_THEME_FILE.
    if os.environ.get("QT_QPA_PLATFORM") == "offscreen" and not os.environ.get("QRSCS_THEME_FILE"):
        return "system"
    try:
        value = json.loads(_theme_file().read_text(encoding="utf-8")).get("theme")
    except (OSError, ValueError, AttributeError):
        return "system"
    return value if value in ("light", "dark", "system") else "system"


def save_theme_preference(preference):
    """Remember the choice for the next start. Returns True if it could be saved."""

    if preference not in ("light", "dark", "system"):
        return False
    try:
        target = _theme_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"theme": preference}), encoding="utf-8")
    except OSError:
        return False
    return True


def _system_prefers_dark():
    if sys.platform != "win32":
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        ) as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
    except OSError:
        return False


def _resolve_theme():
    preference = saved_theme_preference()
    if preference in ("light", "dark"):
        return preference
    # "system": a headless/offscreen run (the automated tests) is always light.
    if os.environ.get("QT_QPA_PLATFORM") == "offscreen":
        return "light"
    return "dark" if _system_prefers_dark() else "light"


THEME = _resolve_theme()

_LIGHT = {
    "BG": "#F3F3F6", "PANEL": "#FFFFFF", "PANEL_ALT": "#ECECF2", "BORDER": "#E6E6ED",
    "SIDEBAR": "#F7F7FA", "ACCENT_SOFT": "#EEEAFE",
    "TEXT": "#1D1D2E", "TEXT_SECONDARY": "#4D4C5E", "TEXT_MUTED": "#8E8E98",
    "ACCENT": "#765CF2", "ACCENT_HOVER": "#8B74F5", "ACCENT_PRESSED": "#5E44E0", "ACCENT_TEXT": "#5A3FD8",
    "ON_ACCENT": "#FFFFFF", "ON_DANGER": "#FFFFFF",
    "ONLINE": "#2DC8A4", "OFFLINE": "#B5B5BA", "DANGER": "#D95252",
    "OK_SOFT": "#E2F6EF", "OK_TEXT": "#12795A", "DANGER_SOFT": "#FCEBED", "DANGER_TEXT": "#B4283A",
    "WARNING_SOFT": "#FCF1DC", "WARNING_TEXT": "#8A5A06",
    "BUBBLE_SENT": "#765CF2", "BUBBLE_SENT_TEXT": "#FFFFFF",
    "BUBBLE_RECEIVED": "#D9D9E6", "BUBBLE_RECEIVED_TEXT": "#242333", "BUBBLE_RECEIVED_META": "#5D5C70",
    "BUBBLE_FAILED": "#FBE6EA", "READ_RECEIPT": "#59ADF7",
    "QUOTE_BG": "#F2F2F7", "QUOTE_BORDER": "#E3E3EB",
    "TONES": ("#4B4F80", "#2E6D72", "#7A4A6F", "#3D6291", "#646E3E", "#8A593B"),
}

_DARK = {
    "BG": "#0F1016", "PANEL": "#181922", "PANEL_ALT": "#22232F", "BORDER": "#2A2B38",
    "SIDEBAR": "#14151C", "ACCENT_SOFT": "#2D2948",
    "TEXT": "#ECEBF4", "TEXT_SECONDARY": "#B9B8CA", "TEXT_MUTED": "#908FA4",
    "ACCENT": "#8B74F6", "ACCENT_HOVER": "#9884F7", "ACCENT_PRESSED": "#7A62EE", "ACCENT_TEXT": "#B8A9FF",
    "ON_ACCENT": "#14121F", "ON_DANGER": "#17090C",
    "ONLINE": "#34D3AE", "OFFLINE": "#5D5D6C", "DANGER": "#E35A6B",
    "OK_SOFT": "#17302B", "OK_TEXT": "#5EE0BD", "DANGER_SOFT": "#3A1F26", "DANGER_TEXT": "#FF8E9C",
    "WARNING_SOFT": "#392F1C", "WARNING_TEXT": "#F0C063",
    "BUBBLE_SENT": "#6650E0", "BUBBLE_SENT_TEXT": "#FFFFFF",
    "BUBBLE_RECEIVED": "#1F2029", "BUBBLE_RECEIVED_TEXT": "#ECEBF4", "BUBBLE_RECEIVED_META": "#B9B8CA",
    "BUBBLE_FAILED": "#3A1F26", "READ_RECEIPT": "#8FE1FF",
    "QUOTE_BG": "#13141B", "QUOTE_BORDER": "#2A2B38",
    "TONES": ("#4D5291", "#2F7076", "#82507A", "#42679A", "#67713F", "#8E5D3E"),
}

_P = _DARK if THEME == "dark" else _LIGHT

COLOR_BG = _P["BG"]
COLOR_PANEL = _P["PANEL"]
COLOR_PANEL_ALT = _P["PANEL_ALT"]
COLOR_BORDER = _P["BORDER"]

# Chat-window surfaces (the Website's --sidebar-bg and --accent-soft): a navigation rail (PANEL_ALT),
# a slightly different conversation sidebar, and the conversation pane.
COLOR_SIDEBAR = _P["SIDEBAR"]
COLOR_ACCENT_SOFT = _P["ACCENT_SOFT"]

# Avatar tones: the Web client's --tone-0..5, indexed by the same name hash as its avatarTone()
# (hash = hash * 31 + codepoint, 32-bit), so a contact has the same colour on every client. A group
# with no tone falls back to the accent.
AVATAR_TONES = _P["TONES"]


def avatar_tone_color(name, group=False):
    if group and not name:
        return COLOR_ACCENT

    value = 0

    for character in str(name or ""):
        value = (value * 31 + ord(character)) & 0xFFFFFFFF

    return AVATAR_TONES[value % len(AVATAR_TONES)]

COLOR_TEXT = _P["TEXT"]
COLOR_TEXT_SECONDARY = _P["TEXT_SECONDARY"]
COLOR_TEXT_MUTED = _P["TEXT_MUTED"]

COLOR_ACCENT = _P["ACCENT"]
COLOR_ACCENT_HOVER = _P["ACCENT_HOVER"]
COLOR_ACCENT_PRESSED = _P["ACCENT_PRESSED"]
COLOR_ACCENT_TEXT = _P["ACCENT_TEXT"]
# Text and icons drawn ON an accent (or danger) surface: white on the light theme, dark on the dark
# theme, exactly as the Website does.
COLOR_ON_ACCENT = _P["ON_ACCENT"]
COLOR_ON_DANGER = _P["ON_DANGER"]

# PQC/Kyber vs. RSA/classical stay on two unrelated hues (cyan vs. amber) so the two remain
# distinguishable at a glance regardless of which accent color the rest of the UI uses.
COLOR_QUANTUM = "#1C9C96"
COLOR_CLASSICAL = "#C97A0A"

COLOR_ONLINE = _P["ONLINE"]
COLOR_OFFLINE = _P["OFFLINE"]

# Deliberately NOT COLOR_OFFLINE: the unread badge and the offline dot render on the same conversation
# row, and reusing red for both let one color mean two unrelated things.
COLOR_UNREAD = COLOR_ACCENT

COLOR_DANGER = _P["DANGER"]

# Status chips (verified / key changed / warning): a soft tint with readable text on it.
COLOR_OK_SOFT = _P["OK_SOFT"]
COLOR_OK_TEXT = _P["OK_TEXT"]
COLOR_DANGER_SOFT = _P["DANGER_SOFT"]
COLOR_DANGER_TEXT = _P["DANGER_TEXT"]
COLOR_WARNING_SOFT = _P["WARNING_SOFT"]
COLOR_WARNING_TEXT = _P["WARNING_TEXT"]

COLOR_BUBBLE_SENT = _P["BUBBLE_SENT"]
COLOR_BUBBLE_SENT_TEXT = _P["BUBBLE_SENT_TEXT"]
COLOR_BUBBLE_RECEIVED_TEXT = _P["BUBBLE_RECEIVED_TEXT"]
COLOR_BUBBLE_RECEIVED_META = _P["BUBBLE_RECEIVED_META"]

# The read-tick colour, readable against the sent bubble.
COLOR_READ_RECEIPT = _P["READ_RECEIPT"]

COLOR_BUBBLE_FAILED = _P["BUBBLE_FAILED"]
COLOR_SEND_FAILED = COLOR_DANGER
COLOR_BUBBLE_RECEIVED = _P["BUBBLE_RECEIVED"]
COLOR_BUBBLE_SYSTEM = COLOR_PANEL_ALT

# The quoted original inside a reply bubble.
COLOR_QUOTE_BG = _P["QUOTE_BG"]
COLOR_QUOTE_BORDER = _P["QUOTE_BORDER"]


def is_dark_theme():
    return THEME == "dark"

# ==============================================================
# Chat Wallpaper (Phase 19.24)
# ==============================================================
#
# Local-only per-conversation preference (storage/secure_key_store.py
# ::get/set_conversation_wallpaper()), never sent to or stored by the
# server. A small, deliberately bounded set of PRESET gradients rather
# than arbitrary custom images -- no new file-storage/upload handling
# per platform, and every preset is chosen soft/low-contrast enough
# that the existing solid, opaque bubble colors above stay fully
# readable on top of it. Mirrored by mobile/app.py's own WALLPAPER_PRESETS and
# web/client/style.css's .wallpaper-* classes -- same ids, same colors (the dark
# theme uses the Website's dark variants), so switching clients feels like the same
# app. "default" (id None) means no wallpaper -- the plain panel background every
# conversation already had.
_WALLPAPER_STOPS = {
    "light": {
        "lavender": ("Lavender", "#EDE9FE", "#DCD3FB"),
        "ocean": ("Ocean", "#E3F2FD", "#BBDEFB"),
        "sunset": ("Sunset", "#FFF3E0", "#FFE0B2"),
        "mint": ("Mint", "#E0F5EC", "#C8ECDE"),
        "midnight": ("Midnight", "#2A2A3D", "#1D1D2E"),
    },
    "dark": {
        "lavender": ("Lavender", "#221D3D", "#1A1630"),
        "ocean": ("Ocean", "#14243A", "#0F1B2D"),
        "sunset": ("Sunset", "#33231A", "#261A13"),
        "mint": ("Mint", "#12291F", "#0E2019"),
        "midnight": ("Midnight", "#171826", "#0F1019"),
    },
}

WALLPAPER_PRESETS = {
    wallpaper_id: (label, f"qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 {first}, stop:1 {second})")
    for wallpaper_id, (label, first, second) in _WALLPAPER_STOPS[THEME].items()
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
    color: {COLOR_ON_ACCENT};
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

/* Toolbar glyph buttons. The base QPushButton rule above sets white
   text, so an icon button must set its own colour -- and a symbol font,
   so the search/pin/gallery/wallpaper/attach code points render as
   monochrome glyphs in that colour instead of mixed-colour emoji. */
QPushButton#IconButton {{
    background-color: transparent;
    color: {COLOR_TEXT_MUTED};
    border-radius: 8px;
    padding: 6px;
    min-width: 20px;
    font-family: "Segoe UI Symbol", "Segoe UI", sans-serif;
    font-size: 13pt;
    font-weight: 400;
}}

QPushButton#IconButton:hover,
QPushButton#IconButton:focus {{
    background-color: {COLOR_PANEL_ALT};
    color: {COLOR_ACCENT};
}}

/* Destructive action (e.g. revoking a device): outlined in the danger
   colour, filling on hover, so it can never be mistaken for the
   accent-filled primary action beside it. */
QPushButton#DangerButton {{
    background-color: transparent;
    color: {COLOR_DANGER};
    border: 1.5px solid {COLOR_DANGER};
    border-radius: 21px;
    padding: 8px 18px;
}}

QPushButton#DangerButton:hover,
QPushButton#DangerButton:focus {{
    background-color: {COLOR_DANGER};
    color: {COLOR_ON_DANGER};
}}

QPushButton#IconButton:pressed {{
    background-color: {COLOR_BORDER};
    color: {COLOR_ACCENT_PRESSED};
}}

/* Conversation-header actions (verify, request approval, profile, group
   admin): secondary weight, so the open conversation's name -- not a
   row of accent-filled pills -- is what leads the header. */
QPushButton#HeaderActionButton,
QPushButton#HeaderDangerButton {{
    background-color: transparent;
    color: {COLOR_ACCENT};
    border: 1.5px solid {COLOR_BORDER};
    border-radius: 14px;
    padding: 4px 14px;
    min-height: 16px;
    font-size: 10pt;
    font-weight: 600;
}}

QPushButton#HeaderActionButton:hover,
QPushButton#HeaderActionButton:focus {{
    border-color: {COLOR_ACCENT};
    background-color: {COLOR_PANEL_ALT};
}}

QPushButton#HeaderDangerButton {{
    color: {COLOR_DANGER};
}}

QPushButton#HeaderDangerButton:hover,
QPushButton#HeaderDangerButton:focus {{
    border-color: {COLOR_DANGER};
    background-color: {COLOR_PANEL_ALT};
}}

QPushButton#SidebarToolButton {{
    background-color: {COLOR_PANEL_ALT};
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 10px;
    padding: 8px 10px;
    min-height: 18px;
}}

QPushButton#SidebarToolButton:hover {{
    background-color: {COLOR_PANEL};
    border-color: {COLOR_ACCENT};
}}

QPushButton#SidebarToolButton:checked {{
    background-color: {COLOR_ACCENT};
    color: {COLOR_ON_ACCENT};
}}

QPushButton#AuthPrimaryAction {{
    min-height: 24px;
    border-radius: 12px;
    font-size: 12pt;
    font-weight: 700;
}}

QPushButton#AuthModeToggle {{
    background-color: transparent;
    color: {COLOR_ACCENT};
    padding: 7px 12px;
    min-height: 16px;
}}

QPushButton#AuthModeToggle:hover {{
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
   CHAT WINDOW -- navigation rail, conversation sidebar, header,
   composer. Layout follows the three-region messenger pattern; every
   colour below is an existing palette token.
   ========================================================== */

QFrame#NavRail {{
    background-color: {COLOR_PANEL_ALT};
    border: none;
    border-right: 1px solid {COLOR_BORDER};
    border-radius: 0px;
}}

/* Sizes are stated here as well as in code: a QSS min/max size overrides
   QWidget.setFixedSize(), and an unstated one lets a bottom-aligned layout
   shrink the button to its size hint. */
QToolButton#RailButton {{
    background-color: transparent;
    border: none;
    border-radius: 12px;
    padding: 4px 0px 2px 0px;
    min-width: 64px;
    max-width: 64px;
    min-height: 56px;
    max-height: 56px;
    color: {COLOR_TEXT_MUTED};
    font-size: 8pt;
    font-weight: 600;
}}

QToolButton#RailButton:checked {{
    color: {COLOR_ACCENT_TEXT};
}}

QLabel#ConnectionPill {{
    background-color: {COLOR_OK_SOFT};
    color: {COLOR_OK_TEXT};
    border-radius: 11px;
    padding: 3px 10px;
    font-size: 8.5pt;
    font-weight: 700;
}}

QLabel#ConnectionPill[connected="false"] {{
    background-color: {COLOR_DANGER_SOFT};
    color: {COLOR_DANGER_TEXT};
}}

QPushButton#FilterChip {{
    background-color: transparent;
    color: {COLOR_TEXT_SECONDARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 14px;
    padding: 3px 12px;
    min-height: 0px;
    font-size: 9pt;
    font-weight: 600;
}}

QPushButton#FilterChip:hover {{
    background-color: {COLOR_PANEL_ALT};
}}

QPushButton#FilterChip:checked {{
    background-color: {COLOR_ACCENT_SOFT};
    color: {COLOR_ACCENT_TEXT};
    border: 1px solid {COLOR_ACCENT};
}}

QPushButton#ComposerButton {{
    background-color: transparent;
    border: none;
    border-radius: 20px;
    padding: 0px;
    min-width: 40px;
    max-width: 40px;
    min-height: 40px;
    max-height: 40px;
}}

QToolButton#RailButton:hover,
QPushButton#ComposerButton:hover {{
    background-color: {COLOR_BORDER};
}}

QToolButton#RailButton:checked {{
    background-color: {COLOR_ACCENT_SOFT};
}}

QToolButton#RailButton:focus,
QPushButton#ComposerButton:focus {{
    background-color: {COLOR_BORDER};
}}

QToolButton#RailButton:checked:focus {{
    background-color: {COLOR_ACCENT_SOFT};
}}

QLabel#RailBadge {{
    background-color: {COLOR_UNREAD};
    color: {COLOR_ON_ACCENT};
    border: 2px solid {COLOR_PANEL_ALT};
    border-radius: 9px;
    font-size: 8pt;
    font-weight: 700;
}}

QLabel#BrandMark {{
    background-color: {COLOR_ACCENT};
    color: {COLOR_ON_ACCENT};
    border-radius: 12px;
    font-size: 13pt;
    font-weight: 700;
}}

QFrame#Sidebar {{
    background-color: {COLOR_SIDEBAR};
    border: none;
    border-right: 1px solid {COLOR_BORDER};
    border-radius: 0px;
}}

QLabel#SidebarTitle {{
    background: transparent;
    font-size: 17pt;
    font-weight: 700;
    color: {COLOR_TEXT};
}}

QLineEdit#SidebarSearch {{
    background-color: {COLOR_PANEL_ALT};
    border: 1.5px solid transparent;
    border-radius: 12px;
    padding: 8px 12px;
    font-size: 10.5pt;
}}

QLineEdit#SidebarSearch:focus {{
    background-color: {COLOR_PANEL};
    border: 1.5px solid {COLOR_ACCENT};
}}

QListWidget#ConversationList {{
    background-color: transparent;
    border: none;
    border-radius: 0px;
    padding: 0px 6px;
}}

QListWidget#ConversationList::item {{
    border-radius: 12px;
    border: none;
    margin: {_LIST_ITEM_MARGIN_PX}px 0px;
}}

QListWidget#ConversationList::item:hover {{
    background-color: {COLOR_PANEL_ALT};
}}

QListWidget#ConversationList::item:selected {{
    background-color: {COLOR_BORDER};
    border: none;
}}

QFrame#MainPane {{
    background-color: {COLOR_PANEL};
    border: none;
    border-radius: 0px;
}}

QFrame#ChatHeader {{
    background-color: {COLOR_PANEL};
    border: none;
    border-bottom: 1px solid {COLOR_BORDER};
    border-radius: 0px;
}}

QWidget#ComposerContext {{
    background-color: {COLOR_ACCENT_SOFT};
    border-top: 1px solid {COLOR_BORDER};
}}

QWidget#ChatContent {{
    background-color: {COLOR_PANEL};
}}

QFrame#MessagesPane {{
    background-color: {COLOR_PANEL};
    border: none;
    border-radius: 0px;
}}

QFrame#Composer {{
    background-color: {COLOR_PANEL};
    border: none;
    border-top: 1px solid {COLOR_BORDER};
    border-radius: 0px;
}}

QFrame#ComposerField {{
    background-color: {COLOR_PANEL_ALT};
    border: 1.5px solid transparent;
    border-radius: 22px;
}}

QFrame#ComposerField[focused="true"] {{
    background-color: {COLOR_PANEL};
    border: 1.5px solid {COLOR_ACCENT};
}}

QPlainTextEdit#ComposerInput {{
    background-color: transparent;
    border: none;
    padding: 0px;
    font-size: 11pt;
    selection-background-color: {COLOR_ACCENT};
}}

QPushButton#SendButton {{
    background-color: {COLOR_ACCENT};
    border: none;
    border-radius: 20px;
    padding: 0px;
    min-width: 40px;
    max-width: 40px;
    min-height: 40px;
    max-height: 40px;
}}

QPushButton#SendButton:hover {{
    background-color: {COLOR_ACCENT_HOVER};
}}

QPushButton#SendButton:pressed {{
    background-color: {COLOR_ACCENT_PRESSED};
}}

QPushButton#SendButton:disabled {{
    background-color: {COLOR_BORDER};
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

QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 0px 4px;
}}

QScrollBar::handle:horizontal {{
    background: {COLOR_BORDER};
    border-radius: 5px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {COLOR_TEXT_MUTED};
}}

QScrollBar::add-line,
QScrollBar::sub-line {{
    height: 0px;
    width: 0px;
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


/* ==========================================================
   MENUS AND MESSAGE BOXES (follow the theme, light or dark)
   ========================================================== */

QMenu {{
    background-color: {COLOR_PANEL};
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 10px;
    padding: 6px;
}}

QMenu::item {{
    padding: 7px 18px 7px 12px;
    border-radius: 7px;
}}

QMenu::item:selected {{
    background-color: {COLOR_ACCENT_SOFT};
}}

QMenu::separator {{
    height: 1px;
    background: {COLOR_BORDER};
    margin: 6px 4px;
}}

QMessageBox,
QDialog {{
    background-color: {COLOR_PANEL};
}}

QRadioButton,
QCheckBox {{
    color: {COLOR_TEXT};
    spacing: 8px;
    padding: 4px 6px;
    background: transparent;
}}

QRadioButton::indicator,
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 2px solid {COLOR_BORDER};
    background: {COLOR_PANEL};
}}

QRadioButton::indicator {{
    border-radius: 9px;
}}

QCheckBox::indicator {{
    border-radius: 5px;
}}

QRadioButton::indicator:checked,
QCheckBox::indicator:checked {{
    background: {COLOR_ACCENT};
    border-color: {COLOR_ACCENT};
}}

QRadioButton::indicator:focus,
QCheckBox::indicator:focus {{
    border-color: {COLOR_ACCENT};
}}
"""


def apply_theme(app):
    """Apply the stylesheet and, on the dark theme, a matching base palette (so the parts the
    stylesheet does not reach -- scroll corners, disabled text, native chrome -- are not left light).
    Call once, right after the QApplication is created."""

    from PySide6.QtGui import QColor, QPalette

    if THEME == "dark":
        app.setStyle("Fusion")
        palette = QPalette()
        roles = {
            QPalette.Window: COLOR_BG, QPalette.WindowText: COLOR_TEXT, QPalette.Base: COLOR_PANEL,
            QPalette.AlternateBase: COLOR_PANEL_ALT, QPalette.Text: COLOR_TEXT, QPalette.Button: COLOR_PANEL_ALT,
            QPalette.ButtonText: COLOR_TEXT, QPalette.ToolTipBase: COLOR_PANEL_ALT, QPalette.ToolTipText: COLOR_TEXT,
            QPalette.Highlight: COLOR_ACCENT, QPalette.HighlightedText: COLOR_ON_ACCENT,
            QPalette.PlaceholderText: COLOR_TEXT_MUTED, QPalette.Link: COLOR_ACCENT_TEXT,
        }
        for role, color in roles.items():
            palette.setColor(role, QColor(color))
        for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
            palette.setColor(QPalette.Disabled, role, QColor(COLOR_TEXT_MUTED))
        app.setPalette(palette)

    app.setStyleSheet(APP_STYLE)