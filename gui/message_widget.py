"""
Message Widget

Displays the conversation between the current user and the
selected chat partner as chat bubbles (sent / received / system).
"""

import html
import mimetypes
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QBuffer, QByteArray, QEvent, QIODevice, QObject, QSize, QTimer, QUrl
from PySide6.QtGui import QImageReader, QPixmap
from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import (
    QApplication,
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
    QDialog,
    QFrame,
    QToolButton,
    QWidget,
    QLabel,
    QFileDialog,
    QHBoxLayout,
    QVBoxLayout,
    QMenu,
    QPushButton,
    QSizePolicy,
    QSlider,
)

from domain.payload_type import PayloadType

from gui.icons import toolbar_icon
from gui.message_parts import (
    MEDIA_REPLY_LABELS,
    MediaPlayerCard,
    ReactionStrip,
    ReplyQuote,
    format_clock,
    media_action_button,
)
from gui.styles import (
    COLOR_ACCENT,
    COLOR_BUBBLE_FAILED,
    COLOR_BUBBLE_SENT,
    COLOR_BUBBLE_SENT_TEXT,
    COLOR_BUBBLE_RECEIVED,
    COLOR_BUBBLE_RECEIVED_META,
    COLOR_BUBBLE_RECEIVED_TEXT,
    COLOR_BUBBLE_SYSTEM,
    COLOR_QUOTE_BG,
    COLOR_QUOTE_BORDER,
    COLOR_READ_RECEIPT,
    COLOR_SEND_FAILED,
    COLOR_TEXT_MUTED,
    LIST_ITEM_VERTICAL_MARGIN,
    is_dark_theme,
)


def _build_message_context_menu(bubble, parent):
    """
    Phase 19.24 (continued) -- Message Lifecycle Events UI. ONE shared
    builder for the right-click menu every message bubble kind (text/
    image/file) offers, since the available actions and their
    conditions are identical regardless of payload type.

    Reply/Copy/React/Forward: offered on any non-system, non-deleted
    bubble that has a real message_id (a live-sent bubble with no
    server id yet, "live-N", cannot yet be the TARGET of one of these
    -- see MessageWidget._add_bubble()'s own "live-N" placeholder
    comment; the menu simply omits message_id-addressed actions until
    a history reload/ack resolves the real id).

    Edit/Delete for everyone: sent bubbles only -- mirrors server/
    client_handler.py's own sender-only authorization for both; never
    offered here merely to look consistent, since offering a button
    that would always be server-rejected is worse than not offering it.

    Delete for me: any non-deleted bubble, sent or received.

    Returns the QMenu, or None if there is nothing to offer (a system
    bubble, or a bubble with no server-assigned message_id yet).
    """

    if bubble.kind == "system" or not bubble.message_id or bubble.message_id.startswith("live-"):
        return None

    if bubble.is_deleted:
        # A deleted message offers only Delete for me (hide the
        # tombstone from this user's own view) -- nothing else makes
        # sense once there is no content left.
        menu = QMenu(parent)
        menu.addAction("Delete for me").setData("delete_me")
        return menu

    menu = QMenu(parent)
    menu.addAction("Reply").setData("reply")
    menu.addAction("Copy").setData("copy")
    menu.addAction("Forward").setData("forward")
    menu.addAction("React …").setData("react")
    # Phase 19.24 -- Pinned Messages: any member may pin/unpin any
    # message, sent or received alike (server/client_handler.py::
    # handle_message_pin()'s own membership-only authorization) --
    # deliberately not restricted to bubble.kind == "sent" the way
    # Edit/Delete-for-everyone below are.
    menu.addAction("Unpin" if bubble.is_pinned else "Pin").setData(
        "unpin" if bubble.is_pinned else "pin"
    )

    if bubble.kind == "sent":
        menu.addSeparator()
        if bubble.supports_edit:
            menu.addAction("Edit").setData("edit")
        menu.addAction("Delete for me").setData("delete_me")
        menu.addAction("Delete for everyone").setData("delete_everyone")
    else:
        menu.addSeparator()
        menu.addAction("Delete for me").setData("delete_me")

    return menu


def _handle_message_context_menu_event(bubble, event, parent):
    """Shared contextMenuEvent body -- builds the menu, shows it, and
    dispatches the chosen action to bubble.on_context_action(action,
    bubble) if one was set and an action was actually chosen."""

    menu = _build_message_context_menu(bubble, parent)

    if menu is None:
        return

    chosen = menu.exec(event.globalPos())

    if chosen is None or bubble.on_context_action is None:
        return

    bubble.on_context_action(chosen.data(), bubble)


def _show_message_action_menu(bubble, button):
    menu = _build_message_context_menu(bubble, bubble)
    if menu is None:
        return
    action = menu.exec(button.mapToGlobal(button.rect().bottomLeft()))
    if action is not None and bubble.on_context_action is not None:
        bubble.on_context_action(action.data(), bubble)


def _create_message_actions_button(bubble):
    button = QPushButton("⋯")
    button.setAccessibleName("Message actions")
    button.setToolTip("Message actions")
    button.setFixedSize(28, 20)
    # Shown only once the server has assigned the message an id (see
    # refresh_actions_button()), which is after the list row was already
    # measured. Reserve its space while hidden so showing it later cannot
    # grow the footer into the message text above it.
    size_policy = button.sizePolicy()
    size_policy.setRetainSizeWhenHidden(True)
    button.setSizePolicy(size_policy)
    button.setCursor(Qt.PointingHandCursor)
    button.setStyleSheet(_actions_button_style(bubble._content_meta_color))
    button.setVisible(False)
    button.clicked.connect(lambda: _show_message_action_menu(bubble, button))

    # Quiet until needed: the glyph shows while the pointer is over the bubble
    # or the button has keyboard focus (its space is reserved either way).
    bubble._hover_reveal = _HoverReveal(button)
    bubble.installEventFilter(bubble._hover_reveal)
    return button


def _actions_button_style(color):
    return (
        "QPushButton { background: transparent; color: transparent; border: none; "
        "border-radius: 8px; padding: 0; font-size: 15pt; font-weight: 700; } "
        f'QPushButton[revealed="true"], QPushButton:hover, QPushButton:focus {{ color: {color}; }}'
    )


class _HoverReveal(QObject):
    """Event filter that flags a bubble's actions button as revealed while the
    pointer is over the bubble (see _actions_button_style())."""

    def __init__(self, button):
        super().__init__(button)
        self._button = button

    def eventFilter(self, watched, event):
        if event.type() in (QEvent.Enter, QEvent.Leave):
            self._button.setProperty("revealed", event.type() == QEvent.Enter)
            style = self._button.style()
            style.unpolish(self._button)
            style.polish(self._button)
        return False


def _message_footer(bubble, time_label, extra_widgets=()):
    footer = QWidget()
    # Without this the footer falls through to the application-wide
    # ``QWidget { background-color }`` rule and paints an opaque band over
    # the bubble -- the white-on-white timestamp/read tick on a sent
    # bubble, and the last text line cut off on a received one. Scoped by
    # object name so it never cascades onto the labels/button inside it.
    footer.setObjectName("MessageFooter")
    footer.setStyleSheet("#MessageFooter { background: transparent; }")
    layout = QHBoxLayout(footer)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    bubble.actions_button = _create_message_actions_button(bubble)
    layout.addWidget(bubble.actions_button)
    for widget in extra_widgets:
        layout.addWidget(widget)
    layout.addStretch()
    layout.addWidget(time_label)
    return footer


def _refresh_row(bubble):
    """Re-measure a bubble's list row after its content changed (a reply quote, reactions or a
    pin marker appeared, an edit or a deletion). A row keeps the height it was measured at when
    added, so without this the new content was clipped."""

    item = getattr(bubble, "_list_item", None)
    if item is not None:
        item.setSizeHint(_row_size_hint(bubble))


def _quote_colors(kind, read_status):
    if kind == "sent" and read_status != STATUS_FAILED:
        return "#FFFFFF", "rgba(255, 255, 255, 0.92)", "rgba(255, 255, 255, 0.16)"
    return COLOR_ACCENT, COLOR_BUBBLE_RECEIVED_META, "rgba(118, 92, 242, 0.08)"


def _pill_colors(kind, read_status):
    if kind == "sent" and read_status != STATUS_FAILED:
        return "#FFFFFF", "rgba(255, 255, 255, 0.18)", "rgba(255, 255, 255, 0.35)"
    return COLOR_BUBBLE_RECEIVED_TEXT, COLOR_QUOTE_BG, COLOR_QUOTE_BORDER


class _BubbleExtras:
    """
    The pieces every message bubble shares, whatever it carries: the "Pinned" marker, the quoted
    message a reply points at, and the reaction pills. Text, image and file/voice/video bubbles
    all render them the same way (previously only text bubbles did).
    """

    def _init_extras(self):
        self.on_reply_activated = None
        self._name_for = None
        self._own_username = None

    def _build_top_extras(self, bubble_layout):
        self._pinned_label = QLabel("")
        self._pinned_label.setTextFormat(Qt.PlainText)
        self._pinned_label.setVisible(False)
        bubble_layout.addWidget(self._pinned_label)

        self._reply_quote = ReplyQuote()
        self._reply_quote.activated.connect(self._on_reply_quote_activated)
        bubble_layout.addWidget(self._reply_quote)

    def _build_reactions(self, bubble_layout):
        self._reactions_strip = ReactionStrip()
        bubble_layout.addWidget(self._reactions_strip)

    def _style_extras(self):
        read_status = getattr(self, "_read_status", None)
        self._pinned_label.setStyleSheet(
            f"color: {self._content_meta_color}; font-size: 8.5pt; font-weight: 600; background: transparent;"
        )
        self._reply_quote.set_colors(*_quote_colors(self.kind, read_status))
        self._reactions_strip.set_colors(*_pill_colors(self.kind, read_status))

    def _on_reply_quote_activated(self):
        if self.on_reply_activated is not None:
            self.on_reply_activated(self)

    def set_reply_preview(self, preview_text, author=None, clickable=False, unavailable=False):
        """Show the quoted message this one replies to: who wrote it and a short excerpt, or a
        media label ("Voice message", "Photo"), already resolved by the caller from the
        original's stable message id. Never fetches or decrypts anything itself."""

        if self.kind == "system" or not preview_text or self.is_deleted:
            return

        self.reply_preview_text = preview_text
        self._reply_quote.set_quote(author, preview_text, clickable=clickable, unavailable=unavailable)
        _refresh_row(self)

    def update_reactions(self, reactions):
        """
        ``reactions``: already-decrypted, already-signature-verified {"user", "reaction"} dicts
        (ClientSession verifies each before this is called -- this widget never touches
        ciphertext). One pill per emoji with its count, like the Website.
        """

        if self.kind == "system":
            return

        self.reactions = list(reactions or [])
        self._reactions_strip.set_reactions(self.reactions, self._own_username, self._name_for)
        _refresh_row(self)

    def set_pinned(self, pinned, pinned_by=None):
        """Show/hide this bubble's "Pinned by X" marker (Phase 19.24)."""

        if self.kind == "system":
            return

        self.is_pinned = bool(pinned)
        self.pinned_by = pinned_by if self.is_pinned else None

        if self.is_pinned:
            if pinned_by and pinned_by == self._own_username:
                who = "you"
            elif pinned_by:
                who = (self._name_for or str)(pinned_by) or pinned_by
            else:
                who = None
            self._pinned_label.setText(f"\U0001F4CC Pinned by {who}" if who else "\U0001F4CC Pinned")
            self._pinned_label.setVisible(True)
        else:
            self._pinned_label.setText("")
            self._pinned_label.setVisible(False)

        _refresh_row(self)

    def _clear_extras_for_deletion(self):
        self._reply_quote.clear()
        self.reactions = []
        self._reactions_strip.set_reactions([])
        self.set_pinned(False)


def _row_size_hint(widget):
    """
    A QListWidgetItem's sizeHint for a row that embeds ``widget`` via
    setItemWidget().

    Not just ``widget.sizeHint()``: gui/styles.py's global
    ``QListWidget::item { margin: ...; }`` carves
    LIST_ITEM_VERTICAL_MARGIN out of the same rect the embedded widget
    is then given, on top of its own sizeHint(). Every row height
    computed this way must add that margin back, or the widget is
    silently granted less height than it asked for -- see
    LIST_ITEM_VERTICAL_MARGIN's docstring in gui/styles.py for the
    visible symptom this caused.
    """

    # A widget's stylesheet font (a bubble's 10.5pt message text, for
    # instance) only takes effect when the widget is polished, which Qt does
    # lazily at first show -- after this hint was already measured. Measured
    # unpolished, a wrapped label is sized with the 9pt default font, so the
    # row comes out a line-fraction too short and the last text line collides
    # with the timestamp footer beneath it. Polish first, then measure.
    widget.ensurePolished()
    for child in widget.findChildren(QWidget):
        child.ensurePolished()
    layout = widget.layout()
    if layout is not None:
        layout.invalidate()

    hint = widget.sizeHint()
    return QSize(hint.width(), hint.height() + LIST_ITEM_VERTICAL_MARGIN)


# Task 2 -- a fourth status alongside the C2 read-receipt tri-state.
#
# Deliberately a STRING, so it cannot collide with any value the
# server can produce: read_status arrives from the message-history
# packet and from read_receipt_notification as None / False / True
# only (see server/client_handler.py::_read_status_for_own_message()),
# and no bool ever compares equal to this.
STATUS_FAILED = "failed"

# Phase 19.23 -- Issue 3 (real DELIVERED signal): a fourth sentinel
# alongside STATUS_FAILED, for exactly the same reason -- a plain
# string that can never collide with the server's own True/False/None
# read_status vocabulary. Previously there was deliberately no such
# state (see _read_status_suffix()'s old docstring: the server tracked
# QUEUED -> DELIVERED but never told the sender). Phase 19.23 wires up
# server/client_handler.py's existing "message_delivered" live packet
# (Phase 19.14, already sent -- simply never consumed by this client)
# and the new additive "delivery_status" history field
# (server/client_handler.py::_delivery_status_for_own_message()) so
# this state is now real, server-derived, and survives reconnect.
STATUS_DELIVERED = "delivered"


def _read_status_suffix(read_status):
    """
    Delivery-status glyph appended to a sent bubble's timestamp label.

    Every state here is driven by a real event, never by a timer or an
    optimistic guess:

      None             no receipt data at all -- a legacy message
                       persisted before C2, or a conversation partner
                       who predates MessageRecipient rows for direct
                       messages. Renders nothing rather than claiming
                       something unknown.
      STATUS_FAILED    ClientSession.send_chat_message() raised, so
                       the ciphertext never reached the server. Set by
                       ChatWindow.send_message()'s except branch.
      False            the send call returned -- the server accepted
                       the message over TLS. "Sent", and nothing
                       stronger.
      STATUS_DELIVERED the live relay actually reached one of the
                       recipient's connected devices (message_
                       delivered packet), or history/reconnect
                       reported it (delivery_status == "delivered").
                       Grey ✓✓ -- deliberately the SAME colour as the
                       plain "Sent" ✓ (no inline <span> colour at all)
                       so it reads as "stronger than Sent, weaker than
                       Read" purely by tick count, exactly like Read
                       is distinguished purely by colour.
      True             every recipient's MessageRecipient row is READ.
                       Set by a read_receipt_notification packet, or
                       read back from history.

    Never called for a received/system bubble, which never shows a
    delivery indicator at all -- see each bubble class's
    set_read_status().
    """

    if read_status is None:
        return ""

    # Literal glyphs, never HTML entities: callers and tests read
    # these back out of QLabel.text().
    if read_status == STATUS_FAILED:
        return (
            f'  <span style="color: {COLOR_SEND_FAILED}; '
            'font-weight: 700;">⚠ Not sent</span>'
        )

    if read_status == STATUS_DELIVERED:
        # Phase 19.23 -- Issue 5: a single space, not two, and the two
        # glyphs themselves are already adjacent with no character
        # between them -- the "too much gap" defect was in a caller
        # padding this suffix further, not in this string itself.
        return " ✓✓"

    if read_status:
        return (
            f' <span style="color: {COLOR_READ_RECEIPT}; '
            'font-weight: 700;">✓✓</span>'
        )

    return " ✓"


# Characters a filename may never contain. Built with chr() rather
# than written as literals: several of these ARE invisible
# bidirectional-override codepoints, and pasting them into source
# would make this very line unreadable in an editor.
_UNSAFE_FILENAME_CHARS = frozenset(
    '<>:"/|?*'
    + chr(92)                                       # backslash
    + ''.join(chr(c) for c in range(0x00, 0x20))    # C0 controls
    + chr(0x7F)                                     # DEL
    + ''.join(chr(c) for c in range(0x80, 0xA0))    # C1 controls
    + ''.join(chr(c) for c in range(0x202A, 0x202F))  # bidi override
    + ''.join(chr(c) for c in range(0x2066, 0x206A))  # bidi isolates
    + chr(0x200E) + chr(0x200F)                     # LRM / RLM
)

# Windows refuses these names with or without an extension.
_RESERVED_FILENAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

_MAX_FILENAME_LENGTH = 120


def _safe_filename(raw, fallback):
    """
    Reduce a sender-supplied filename to something safe to show and to
    offer as a Save As default (D8 / P1).

    The filename arrives inside content_metadata, chosen entirely by
    the sender, and was previously used verbatim. Three separate
    problems came with that:

      * Path separators and "..", which steer the save dialog somewhere
        other than where the user is looking.
      * Bidirectional-override codepoints, the classic way to display
        an executable as "holiday.png" while it saves as .exe.
      * Control characters and unbounded length, which distort the
        transcript layout.

    Only the basename survives, on BOTH separator conventions -- a
    Windows client can be sent a POSIX path and vice versa, so
    os.path.basename alone is not enough.

    Deliberately NOT a security boundary on its own: the user still
    confirms the destination in a native save dialog, and this cannot
    make an untrusted file safe to open. It removes the deception, not
    the file.
    """

    name = raw if isinstance(raw, str) else ""

    # Basename under both conventions, then strip any leftover dots
    # so "..", "...", and ".." dressed up with separators all collapse.
    name = name.replace("\\", "/").rsplit("/", 1)[-1]

    name = "".join(
        "_" if character in _UNSAFE_FILENAME_CHARS else character
        for character in name
    ).strip().strip(".")

    if len(name) > _MAX_FILENAME_LENGTH:
        stem, dot, extension = name.rpartition(".")
        if dot and len(extension) <= 10:
            keep = _MAX_FILENAME_LENGTH - len(extension) - 1
            name = f"{stem[:keep]}.{extension}"
        else:
            name = name[:_MAX_FILENAME_LENGTH]

    if not name or name.split(".")[0].upper() in _RESERVED_FILENAMES:
        return fallback

    return name


def _time_label_html(timestamp_text, read_status):
    """
    Build the timestamp line for a bubble.

    This is the ONLY label in the application that is deliberately
    rendered as rich text, because _read_status_suffix() colours the
    read/failed glyph inline. That makes escaping mandatory rather
    than optional: the timestamp half is concatenated straight into
    markup, so it is html.escape()d here even though it is currently
    produced by strftime("%H:%M") and cannot contain markup today.
    The escape is what keeps that a local, checkable property of this
    function instead of a standing assumption about every caller.

    The status suffix is NOT escaped -- it is this module's own
    constant markup, never anything that arrived over the network.
    """

    return html.escape(timestamp_text or "") + _read_status_suffix(read_status)


def _apply_bubble_style(bubble, kind, read_status):
    """
    Paint one bubble's background for its kind and delivery status.

    A failed message is marked by restyling the whole bubble rather
    than by tinting a character, because red is not legible on the
    blue sent bubble at all -- see COLOR_BUBBLE_FAILED in
    gui/styles.py.

    Scoped through an object name (``#Bubble``) rather than a bare
    property list: an unscoped widget stylesheet also applies to that
    widget's children in Qt, so a bare ``border:`` would draw a box
    around every label inside the bubble too.
    """

    bubble.setObjectName("Bubble")

    # Android's own bubble corners (mobile/app.py Bubble: radius=
    # [16,16,4,16] sent / [16,16,16,4] received -- one sharp "tail"
    # corner per side, dp(16) everywhere else) reproduced exactly via
    # Qt's per-corner radius properties, rather than the uniform round
    # rect used before this pass.
    if kind == "sent" and read_status == STATUS_FAILED:
        bubble.setStyleSheet(
            f"#Bubble {{ background-color: {COLOR_BUBBLE_FAILED}; "
            f"border: 1px solid {COLOR_SEND_FAILED}; "
            "border-top-left-radius: 16px; border-top-right-radius: 16px; "
            "border-bottom-right-radius: 4px; border-bottom-left-radius: 16px; }"
        )
        return

    background = COLOR_BUBBLE_SENT if kind == "sent" else COLOR_BUBBLE_RECEIVED
    tail_corner = (
        "border-bottom-right-radius: 4px; border-bottom-left-radius: 16px;"
        if kind == "sent"
        else "border-bottom-right-radius: 16px; border-bottom-left-radius: 4px;"
    )

    bubble.setStyleSheet(
        f"#Bubble {{ background-color: {background}; "
        f"border-top-left-radius: 16px; border-top-right-radius: 16px; {tail_corner} }}"
    )


def _bubble_content_colors(kind, read_status):
    if kind == "sent" and read_status == STATUS_FAILED:
        return COLOR_BUBBLE_RECEIVED_TEXT, COLOR_BUBBLE_RECEIVED_META
    if kind == "sent":
        return COLOR_BUBBLE_SENT_TEXT, COLOR_BUBBLE_SENT_TEXT
    return COLOR_BUBBLE_RECEIVED_TEXT, COLOR_BUBBLE_RECEIVED_META


def to_local_time(utc_naive_timestamp):
    """
    Convert a naive-UTC timestamp -- this app's canonical storage/wire
    convention, see client/session.py::_parse_incoming_timestamp() and
    server/client_handler.py::_parse_message_timestamp(), both of
    which normalise every stored/relayed timestamp to naive UTC -- to
    this machine's local timezone, for DISPLAY only. Never affects
    what is stored or sent; a live message already displays local time
    because it is built straight from datetime.now() before any of
    this is involved (see MessageBubble.__init__'s ``timestamp or
    datetime.now()...`` fallback) -- this is what gives a message
    loaded from history / a sidebar preview the same local time
    instead of the raw UTC one.

    astimezone() with no argument asks the OS for its own configured
    local timezone and converts to it, so this is correct on whatever
    machine it runs on -- never a hardcoded offset. The naive value is
    tagged as UTC first (that is what it actually represents); calling
    astimezone() on a still-naive value would instead assume it's
    already local time and be a no-op, which is exactly the bug this
    fixes.
    """

    return utc_naive_timestamp.replace(tzinfo=timezone.utc).astimezone()


def _date_separator_text(separator_date):
    """
    UI Finalization Decision 4 -- render a message date as "Today",
    "Yesterday", or a full date, always relative to the ACTUAL current
    date at render time (datetime.now().date()), never a value
    captured once and reused -- a conversation left open across
    midnight must see "Today" become "Yesterday" on its own the next
    time a separator is (re-)evaluated, not stay wrong until reload.
    """

    today = datetime.now().date()

    if separator_date == today:
        return "Today"

    if separator_date == today - timedelta(days=1):
        return "Yesterday"

    return separator_date.strftime("%d %B %Y").lstrip("0")


class DateSeparatorBubble(QWidget):
    """
    A centered, muted date pill inserted into the message timeline
    (UI Finalization Decision 4) -- one per calendar date, never
    repeated per-message. Visually similar to a system-message bubble
    (MessageBubble kind="system"), but a distinct class rather than a
    fourth `kind` value: it carries no read/retry/sender concerns at
    all, and MessageWidget needs to tell "is this row a date marker"
    apart from "is this row a system notice" when deciding whether to
    insert a new one (see MessageWidget._maybe_insert_date_separator()).
    """

    def __init__(self, separator_date):
        super().__init__()

        self.separator_date = separator_date

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 6, 4, 6)

        label = QLabel(_date_separator_text(separator_date))
        # L-1: text is entirely app-generated (Today/Yesterday/a
        # strftime-formatted date) -- never markup, but PlainText kept
        # explicit for consistency with every other label in this
        # module.
        label.setTextFormat(Qt.PlainText)
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 8.5pt; font-weight: 600; "
            f"background-color: {COLOR_BUBBLE_SYSTEM}; "
            "padding: 3px 12px; border-radius: 10px;"
        )

        outer.addStretch()
        outer.addWidget(label)
        outer.addStretch()


def _accessible_summary(bubble):
    """
    Plain-text description of a message row for assistive technology.

    A list row is a ``setItemWidget()`` widget, which accessibility clients cannot
    see into, so without this a screen reader (or UI automation) finds an empty row.
    It repeats exactly what the bubble already shows -- no new information.
    """

    kind = getattr(bubble, "kind", "")
    if kind == "system":
        return getattr(bubble, "message_text", "") or ""
    who = "You" if kind == "sent" else (getattr(bubble, "_accessible_sender", None) or "")
    if getattr(bubble, "is_deleted", False):
        content = "Message deleted"
    elif isinstance(bubble, MessageBubble):
        content = bubble.message_text or ""
        if getattr(bubble, "edit_version", 0):
            content += " (edited)"
    elif isinstance(bubble, ImageMessageBubble):
        content = "Image " + (getattr(bubble, "_filename", "") or "")
    elif getattr(bubble, "payload_type", None) == PayloadType.VOICE:
        content = "Voice message"
    elif getattr(bubble, "payload_type", None) == PayloadType.VIDEO:
        content = "Video message"
    else:
        content = "File " + (getattr(bubble, "_filename", "") or "")
    if getattr(bubble, "reply_preview_text", None) and not getattr(bubble, "is_deleted", False):
        content = f"Reply to: {bubble.reply_preview_text}. {content}"
    when = getattr(bubble, "_timestamp_text", "") or ""
    return ", ".join(part for part in (who, content.strip(), when) if part)


def _sync_item_accessible_text(bubble):
    """Refresh the list row's accessible text after the bubble changed (edit / delete)."""

    item = getattr(bubble, "_list_item", None)
    if item is not None:
        item.setData(Qt.AccessibleTextRole, _accessible_summary(bubble))


class MessageBubble(_BubbleExtras, QWidget):
    """
    A single chat bubble.

    kind is one of "sent", "received", "system".
    """

    def __init__(
        self,
        text,
        kind,
        sender=None,
        timestamp=None,
        read_status=None,
        on_retry=None,
        on_context_action=None,
    ):
        super().__init__()

        self.kind = kind
        self._accessible_sender = sender
        self._list_item = None
        self._content_text_color, self._content_meta_color = _bubble_content_colors(kind, read_status)

        # Retained so a failed send can be retried without the
        # user retyping it (Task 2). It is the same plaintext
        # already held in this widget's label -- nothing new is
        # kept in memory, and nothing is written to disk.
        self.message_text = text

        # Phase 19.24 (continued) -- Message Lifecycle Events UI.
        # message_id/client_message_id are set by the caller AFTER
        # construction (gui/chat_window.py), exactly like the existing
        # client_message_id attribute Phase 19.24's retry-idempotency
        # work already added -- this widget is built before either id
        # is necessarily known. reply_to_message_id/is_deleted/
        # edit_version/reactions mirror the server's own per-message
        # fields (server/client_handler.py::handle_message_history_
        # request()), None/False/0/[] for an ordinary message.
        self.message_id = None
        self.client_message_id = None
        self.reply_to_message_id = None
        self.reply_preview_text = None
        self.is_deleted = False
        self.edit_version = 0
        self.reactions = []
        # Phase 19.24 -- Pinned Messages: mirrors is_deleted/edit_
        # version above -- server-derived state, applied by gui/
        # chat_window.py via set_pinned() (history load, and live
        # message_pinned/message_unpinned notifications).
        self.is_pinned = False
        self.pinned_by = None
        # TEXT bubbles support Edit; ImageMessageBubble/
        # FileMessageBubble override this to False in their own
        # __init__ (edit is scoped to PayloadType.TEXT only -- see
        # ClientSession.edit_message()'s own docstring).
        self.supports_edit = True
        self.on_context_action = on_context_action
        self._init_extras()

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(14, 8, 14, 8)
        bubble_layout.setSpacing(2)

        bubble.setMaximumWidth(600)
        bubble.setSizePolicy(
            QSizePolicy.Maximum,
            QSizePolicy.Minimum,
        )

        if kind == "system":

            label = QLabel(text)
            # L-1: system text can carry a username/group name that
            # originated off the wire, so it is never markup.
            label.setTextFormat(Qt.PlainText)
            label.setWordWrap(True)
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet(
                f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt; "
                "font-style: italic;"
            )

            bubble_layout.addWidget(label)

            bubble.setStyleSheet(
                f"background-color: {COLOR_BUBBLE_SYSTEM}; "
                "border-radius: 12px;"
            )

            outer.addStretch()
            outer.addWidget(bubble)
            outer.addStretch()

        else:

            if sender and kind == "received":

                name_label = QLabel(sender)
                # L-1: a username is chosen at registration and is
                # never format-validated, so it is display data, not
                # markup.
                name_label.setTextFormat(Qt.PlainText)
                name_label.setStyleSheet(
                    "font-size: 9pt; font-weight: 600; "
                    f"color: {COLOR_ACCENT};"
                )
                bubble_layout.addWidget(name_label)

            # Pinned marker and reply quote (hidden until set) -- shared with every bubble kind.
            self._build_top_extras(bubble_layout)

            text_label = QLabel(text)
            # L-1 -- the critical one. This label renders decrypted
            # message content written by another user. Left on Qt's
            # AutoText default it PARSED that content as HTML: an
            # <img src="file:///..."> in a message was resolved and
            # drawn from the recipient's own disk, and <b>/<a>/<span>
            # let a sender forge transcript chrome -- including fake
            # read-receipt glyphs. PlainText makes message text data
            # instead of markup.
            text_label.setTextFormat(Qt.PlainText)
            text_label.setWordWrap(True)
            text_label.setTextInteractionFlags(
                Qt.TextSelectableByMouse
            )
            text_label.setStyleSheet(
                f"color: {self._content_text_color}; font-size: 10.5pt; "
                "background: transparent;"
            )

            bubble_layout.addWidget(text_label)
            self._text_label = text_label

            # Reaction pills below the text (hidden until there is one).
            self._build_reactions(bubble_layout)

            self._timestamp_text = timestamp or datetime.now().strftime("%H:%M")

            self.time_label = QLabel(
                _time_label_html(
                    self._timestamp_text,
                    read_status if kind == "sent" else None,
                )
            )
            # Explicit, not inherited: this label is intentionally
            # rich text (see _time_label_html()), so it must never
            # fall back to AutoText -- and its content is
            # app-generated and escaped.
            self.time_label.setTextFormat(Qt.RichText)
            self.time_label.setObjectName("TimestampLabel")
            self.time_label.setStyleSheet(
                f"color: {self._content_meta_color}; "
                "font-size: 8pt; background: transparent;"
            )
            self.time_label.setAlignment(
                Qt.AlignRight if kind == "sent" else Qt.AlignLeft
            )

            bubble_layout.addWidget(_message_footer(self, self.time_label))

            self._bubble = bubble
            self._read_status = read_status
            self._on_retry = on_retry

            # Task 2 -- a failed message must be RECOVERABLE, not just
            # labelled. Without this the only options were retyping the
            # text or copying it back out of the bubble by hand.
            #
            # The button is created only for a bubble that is actually
            # in the failed state and was given a retry callback, so an
            # ordinary sent message carries no extra widget at all.
            self.retry_button = None

            if kind == "sent" and read_status == STATUS_FAILED and on_retry:
                self.retry_button = QPushButton("Retry")
                self.retry_button.setCursor(Qt.PointingHandCursor)
                self.retry_button.setStyleSheet(
                    f"background-color: transparent; color: {COLOR_SEND_FAILED}; "
                    f"border: 1px solid {COLOR_SEND_FAILED}; border-radius: 8px; "
                    "padding: 3px 10px; font-size: 8.5pt; font-weight: 600;"
                )
                self.retry_button.clicked.connect(self._handle_retry)
                bubble_layout.addWidget(self.retry_button, 0, Qt.AlignRight)

            _apply_bubble_style(bubble, kind, read_status)
            self._refresh_content_colors()

            if kind == "sent":

                outer.addStretch()
                outer.addWidget(bubble)

            else:

                outer.addWidget(bubble)
                outer.addStretch()

    def set_read_status(self, read_status):
        """
        Update this sent bubble's check-mark glyph in place (C2 --
        Read Receipts), without touching the timestamp it's appended
        to. A no-op for a received/system bubble -- neither ever shows
        one, by design (see _read_status_suffix()'s docstring).
        """

        if self.kind != "sent":
            return

        # A failed send is TERMINAL for this bubble. Without this
        # guard mark_all_sent_read() -- which sweeps every tracked
        # sent bubble in the conversation, by design -- would flip a
        # message that never reached the server to "✓✓ read", which is
        # precisely the state that must never be fabricated. There is
        # no real path from "the send call raised" to "the recipient
        # read it"; a retry produces a new message and a new bubble.
        if self._read_status == STATUS_FAILED and read_status != STATUS_FAILED:
            return

        # Phase 19.23 -- Issue 3: READ is likewise terminal with
        # respect to DELIVERED. A message_delivered packet racing a
        # read_receipt_notification (both are independent live
        # packets) must never downgrade an already-"✓✓ read" bubble
        # back to a grey "✓✓ delivered" one.
        if self._read_status is True and read_status != True:  # noqa: E712
            return

        self._read_status = read_status

        self.time_label.setText(
            _time_label_html(self._timestamp_text, read_status)
        )

        _apply_bubble_style(self._bubble, self.kind, read_status)
        self._refresh_content_colors()

    def _refresh_content_colors(self):
        self._content_text_color, self._content_meta_color = _bubble_content_colors(
            self.kind, self._read_status
        )
        text_style = (
            f"color: {self._content_text_color}; font-size: 10.5pt; "
            "background: transparent;"
        )
        if self.is_deleted:
            text_style += " font-style: italic;"
        self._text_label.setStyleSheet(text_style)
        self._style_extras()
        self.time_label.setStyleSheet(
            f"color: {self._content_meta_color}; font-size: 8pt; background: transparent;"
        )
        self.actions_button.setStyleSheet(_actions_button_style(self._content_meta_color))

    def refresh_actions_button(self):
        """Expose message actions only after the server assigns an addressable id."""
        if self.kind == "system":
            return
        message_id = self.message_id
        self.actions_button.setVisible(
            bool(message_id and not str(message_id).startswith("live-"))
        )

    def _show_action_menu(self):
        _show_message_action_menu(self, self.actions_button)

    # ------------------------------------------------------------------
    # Task 2 -- retry
    # ------------------------------------------------------------------

    def _handle_retry(self):
        """
        Ask the owner to send this message again.

        The bubble does not send anything itself and does not decide
        whether the retry worked -- it hands the text back to
        ChatWindow and waits to be told, exactly like the original
        send. The button is disabled for the duration so a second
        click cannot queue a duplicate.
        """

        if not self._on_retry:
            return

        if self.retry_button is not None:
            self.retry_button.setEnabled(False)
            self.retry_button.setText("Retrying...")

        try:
            self._on_retry(self)
        finally:
            if self.retry_button is not None and not self.retry_button.isHidden():
                self.retry_button.setEnabled(True)
                self.retry_button.setText("Retry")

    def mark_retry_succeeded(self):
        """
        Clear the failed state after a retry that actually reached the
        server, and drop the retry control.

        This is the ONE path allowed to leave STATUS_FAILED, and it
        deliberately bypasses set_read_status()'s terminal-failed
        guard. That guard exists to stop mark_all_sent_read() -- which
        sweeps every tracked sent bubble at once -- from promoting a
        message that never left the machine. This is the opposite
        situation: a specific, user-initiated resend that returned
        without raising, so the single tick is now a fact about this
        message rather than a guess about all of them.
        """

        if self.kind != "sent":
            return

        self._read_status = False

        self.time_label.setText(_time_label_html(self._timestamp_text, False))

        _apply_bubble_style(self._bubble, self.kind, False)
        self._refresh_content_colors()

        if self.retry_button is not None:
            self.retry_button.hide()
            self.retry_button.deleteLater()
            self.retry_button = None

    # ------------------------------------------------------------------
    # Phase 19.24 (continued) -- Message Lifecycle Events UI.
    # ------------------------------------------------------------------

    def contextMenuEvent(self, event):
        _handle_message_context_menu_event(self, event, self)

    def apply_edit(self, new_text, edit_version):
        """
        Update this bubble's own text in place after a successful edit
        (Phase 19.24) -- the SAME logical message, never a new bubble.
        Appends "(edited)" to the displayed text, mirroring the
        mandate's own example UI text exactly ("Hello everyone
        (edited)") -- a visible fact about the message, not hidden
        metadata.
        """

        if self.kind == "system":
            return

        self.message_text = new_text
        self.edit_version = edit_version
        self._text_label.setText(f"{new_text} (edited)")
        self._sync_accessible_text()
        _refresh_row(self)

    def mark_deleted(self):
        """
        Render this bubble as a deleted-message tombstone (Phase
        19.24) -- "Message deleted", no original content, no
        reactions, no reply preview. Called for BOTH delete-for-me
        (this user's own view only) and delete-for-everyone (every
        participant's view) -- the CALLER (gui/chat_window.py)
        decides which one actually happened server-side; this widget
        only ever renders "the content is gone", identically either
        way, since there is nothing left to show regardless of why.
        """

        if self.kind == "system":
            return

        self.is_deleted = True
        self.message_text = ""
        self._text_label.setText("Message deleted")
        self._refresh_content_colors()
        self._clear_extras_for_deletion()
        self._sync_accessible_text()
        _refresh_row(self)

    def _sync_accessible_text(self):
        _sync_item_accessible_text(self)


def _format_file_size(size_bytes):
    """Human-readable file size (Phase 8 -- File & Image Transfer)."""

    size = float(size_bytes)

    for unit in ("B", "KB", "MB", "GB"):

        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"

        size /= 1024

    return f"{size:.1f} TB"


# D8 / P1 -- bounds on decoding an untrusted image.
#
# Image bytes arrive from another user and are handed to Qt's image
# plugins, which are a large C++ parsing surface. Two limits, because
# they stop different things:
#
# ALLOWED_IMAGE_FORMATS is a content-sniffed allowlist. QImageReader
#   picks a plugin from the DATA, not the filename, so a file called
#   "cat.png" can still be routed to some other decoder. Restricting
#   the set restricts how much of that surface a sender can choose to
#   reach.
#
# MAX_IMAGE_PIXELS stops a decompression bomb. A few hundred KB of
#   PNG can declare 30000x30000, and decoding allocates roughly
#   width * height * 4 bytes -- 3.6 GB -- on the RECIPIENT's machine.
#   The frame and attachment limits do not help here at all: they
#   bound the compressed size, and the bomb is small.
ALLOWED_IMAGE_FORMATS = frozenset({"png", "jpeg", "jpg", "gif", "bmp", "webp"})

MAX_IMAGE_PIXELS = 40_000_000


def _decode_image(image_bytes):
    """
    Decode untrusted image bytes, or return None.

    Dimensions are read from the header via QImageReader.size() BEFORE
    the pixels are decoded, so an oversized declaration costs a header
    parse rather than a multi-gigabyte allocation.

    Returns None for every rejection -- unknown format, oversized,
    corrupt, or simply not an image -- because the caller has one
    "[Unable to display image]" fallback and a recipient does not
    benefit from knowing which of those it was.
    """

    if not image_bytes:
        return None

    # setData() on a QBuffer that owns its storage, NOT
    # QBuffer(QByteArray(...)). The constructor form takes the byte
    # array by reference without owning it, so the temporary is
    # collected while the reader is still using it -- which crashed
    # the interpreter outright (Windows access violation) rather than
    # failing cleanly.
    buffer = QBuffer()
    buffer.setData(QByteArray(image_bytes))

    if not buffer.open(QIODevice.ReadOnly):
        return None

    try:
        reader = QImageReader(buffer)
        reader.setAutoTransform(True)

        image_format = bytes(reader.format()).decode("ascii", "replace").lower()

        if image_format not in ALLOWED_IMAGE_FORMATS:
            return None

        size = reader.size()

        if size.isValid():

            declared_pixels = size.width() * size.height()

            if declared_pixels > MAX_IMAGE_PIXELS:
                return None

        image = reader.read()

        if image.isNull():
            return None

        return QPixmap.fromImage(image)

    finally:
        buffer.close()


class ImageMessageBubble(_BubbleExtras, QWidget):
    """
    A single image chat bubble -- an inline thumbnail rendered
    directly from already-decrypted bytes (Phase 8 -- File & Image
    Transfer).

    A sibling class to MessageBubble, not a modification of it: it
    duplicates MessageBubble's small amount of outer/bubble/alignment/
    timestamp scaffolding rather than generalizing MessageBubble
    itself, so the existing, tested text-bubble code path is provably
    untouched by this addition -- zero lines of MessageBubble changed.
    """

    MAX_THUMBNAIL_WIDTH = 320

    # A width-only bound left tall images unbounded: a 600x4000
    # screenshot came back 320x2133, which pushed every neighbouring
    # message off the visible transcript and made the scroll position
    # jump. Both dimensions are bounded, and the aspect ratio is
    # preserved, so a preview always fits in a predictable box.
    MAX_THUMBNAIL_HEIGHT = 360

    def __init__(
        self,
        image_bytes,
        kind,
        sender=None,
        timestamp=None,
        read_status=None,
        content_metadata=None,
        on_context_action=None,
    ):
        super().__init__()

        self.kind = kind
        self._accessible_sender = sender
        self._list_item = None
        self._content_text_color, self._content_meta_color = _bubble_content_colors(kind, read_status)

        # BUG 5 -- the decrypted bytes are RETAINED, not discarded once
        # a thumbnail has been built from them. Without them there was
        # nothing to open at full size and nothing to save, which is
        # exactly why a received image could not be viewed. Held in
        # memory only: like FileMessageBubble, nothing is written to
        # disk until the user explicitly saves.
        self.image_bytes = image_bytes
        self.content_metadata = content_metadata or {}

        # Phase 19.24 (continued) -- Message Lifecycle Events UI --
        # see MessageBubble.__init__'s identical attributes for the
        # full rationale. Edit is TEXT-only, so supports_edit is
        # always False here.
        self.message_id = None
        self.client_message_id = None
        self.reply_to_message_id = None
        self.reply_preview_text = None
        self.is_deleted = False
        self.edit_version = 0
        self.reactions = []
        self.is_pinned = False
        self.pinned_by = None
        self.supports_edit = False
        self.on_context_action = on_context_action
        self._init_extras()

        self._filename = _safe_filename(
            self.content_metadata.get("filename"), "image.png"
        )
        self._full_pixmap = None
        self._viewer = None

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(8, 8, 8, 8)
        bubble_layout.setSpacing(4)

        bubble.setMaximumWidth(self.MAX_THUMBNAIL_WIDTH + 16)
        bubble.setSizePolicy(
            QSizePolicy.Maximum,
            QSizePolicy.Minimum,
        )

        if sender and kind == "received":

            name_label = QLabel(sender)
            # L-1: see MessageBubble's identical guard.
            name_label.setTextFormat(Qt.PlainText)
            name_label.setStyleSheet(
                f"font-size: 9pt; font-weight: 600; color: {COLOR_ACCENT};"
            )
            bubble_layout.addWidget(name_label)

        self._build_top_extras(bubble_layout)

        self.image_label = QLabel()
        # L-1: normally shows a pixmap, but falls back to a text
        # message below; PlainText keeps that fallback from being
        # parsed.
        self.image_label.setTextFormat(Qt.PlainText)

        # D8 / P1 -- was QPixmap.loadFromData(image_bytes) with no
        # format allowlist and no dimension bound.
        pixmap = _decode_image(image_bytes)

        if pixmap is not None and not pixmap.isNull():

            self._full_pixmap = pixmap

            # Scale DOWN only, and only when the image actually
            # exceeds one of the bounds. Fitting every image to the box
            # upscaled small ones -- a 80px-wide screenshot was blown
            # up to 320px and looked wrong, which is part of what
            # "cannot be viewed properly" meant. KeepAspectRatio fits
            # the image INSIDE the box, so whichever dimension is
            # proportionally larger is the one that ends up on the
            # bound; the other stays under it, undistorted.
            if (
                pixmap.width() > self.MAX_THUMBNAIL_WIDTH
                or pixmap.height() > self.MAX_THUMBNAIL_HEIGHT
            ):
                shown = pixmap.scaled(
                    QSize(
                        self.MAX_THUMBNAIL_WIDTH,
                        self.MAX_THUMBNAIL_HEIGHT,
                    ),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
            else:
                shown = pixmap

            self.image_label.setPixmap(shown)
            self.image_label.setCursor(Qt.PointingHandCursor)
            self.image_label.setToolTip("Click to view full size")

        else:

            self.image_label.setText("[Unable to display image]")
            self.image_label.setStyleSheet(f"color: {self._content_text_color};")

        bubble_layout.addWidget(self.image_label)

        self._build_reactions(bubble_layout)

        # View / Save share the footer row with the time, as on the Website -- offered only when
        # there is really an image to act on (an attachment whose key this client never received
        # renders the placeholder above and must not offer to open or save bytes it does not have).
        actions = []
        if self._full_pixmap is not None:
            view_button = media_action_button("View", "expand", self._content_text_color, "View image")
            view_button.clicked.connect(self.open_viewer)
            save_button = media_action_button("Save", "download", self._content_text_color, "Save image")
            save_button.clicked.connect(self._handle_save_as)
            actions = [view_button, save_button]
        self._action_buttons = actions

        self._timestamp_text = timestamp or datetime.now().strftime("%H:%M")

        self.time_label = QLabel(
            _time_label_html(
                self._timestamp_text,
                read_status if kind == "sent" else None,
            )
        )
        # Explicit, not inherited: this label is intentionally rich
        # text (see _time_label_html()), so it must never fall back to
        # AutoText -- and its content is app-generated and escaped.
        self.time_label.setTextFormat(Qt.RichText)
        # Named so the structural guard in
        # tests/test_rich_text_injection.py can whitelist this one
        # label by identity rather than by position.
        self.time_label.setObjectName("TimestampLabel")
        self.time_label.setStyleSheet(
            f"color: {self._content_meta_color}; "
            "font-size: 8pt; background: transparent;"
        )
        self.time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(_message_footer(self, self.time_label, actions))

        self._bubble = bubble
        self._read_status = read_status

        _apply_bubble_style(bubble, kind, read_status)
        self._style_extras()

        if kind == "sent":
            outer.addStretch()
            outer.addWidget(bubble)
        else:
            outer.addWidget(bubble)
            outer.addStretch()

    def thumbnail_width(self):
        """Width of the thumbnail actually shown, or None when the
        image could not be decoded."""

        size = self.thumbnail_size()

        return size[0] if size else None

    def thumbnail_size(self):
        """(width, height) of the thumbnail actually shown, or None
        when the image could not be decoded."""

        pixmap = self.image_label.pixmap()

        if pixmap is None or pixmap.isNull():
            return None

        return (pixmap.width(), pixmap.height())

    def full_size(self):
        """(width, height) of the image at full resolution, or None."""

        if self._full_pixmap is None:
            return None

        return (self._full_pixmap.width(), self._full_pixmap.height())

    def open_viewer(self):
        """
        Show the image at full resolution in an in-app window (BUG 5).

        Deliberately an in-app viewer rather than handing the file to
        the operating system: the common case is simply looking at a
        picture, and doing that in-process means the decrypted image
        never has to touch disk at all. Writing a plaintext copy stays
        exactly where FileMessageBubble already put it -- behind an
        explicit "Save As...", chosen by the user.

        Returns the viewer window (or None if there is no decoded
        image), so the caller -- and the tests -- can address it. The
        reference is held on the bubble because a QDialog with no
        owning reference is garbage-collected straight back off the
        screen.
        """

        if self._full_pixmap is None:
            return None

        viewer = QDialog(self)
        viewer.setWindowTitle(self._filename)
        viewer.setModal(False)

        layout = QVBoxLayout(viewer)
        layout.setContentsMargins(0, 0, 0, 0)

        label = QLabel()
        label.setTextFormat(Qt.PlainText)
        label.setAlignment(Qt.AlignCenter)

        # Fit to the available screen if the image is larger than it,
        # so a big photo opens usable rather than off-screen. Never
        # upscales: a small image is shown at its true size.
        pixmap = self._full_pixmap
        screen = self.screen()

        if screen is not None:

            available = screen.availableGeometry()
            limit = available.size() * 0.9

            if (
                pixmap.width() > limit.width()
                or pixmap.height() > limit.height()
            ):
                pixmap = pixmap.scaled(
                    limit, Qt.KeepAspectRatio, Qt.SmoothTransformation
                )

        label.setPixmap(pixmap)
        layout.addWidget(label)

        viewer.resize(pixmap.width(), pixmap.height())

        self._viewer = viewer
        viewer.show()

        return viewer

    def _handle_save_as(self):
        """
        Write the already-decrypted image bytes this bubble holds to a
        user-chosen local path, defaulting to the filename the sender
        used. A no-op if the dialog is cancelled.

        Deliberately identical in shape to
        FileMessageBubble._handle_save_as() -- an image is a file, and
        saving one should not be a second, differently-behaved
        mechanism.
        """

        if not self.image_bytes:
            return

        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save Image",
            self._filename
        )

        if path:
            Path(path).write_bytes(self.image_bytes)

    def set_read_status(self, read_status):
        """
        Update this sent bubble's check-mark glyph in place (C2 --
        Read Receipts). A no-op for a received bubble -- see
        MessageBubble.set_read_status()'s identical docstring.
        """

        if self.kind != "sent":
            return

        # A failed send is TERMINAL for this bubble. Without this
        # guard mark_all_sent_read() -- which sweeps every tracked
        # sent bubble in the conversation, by design -- would flip a
        # message that never reached the server to "✓✓ read", which is
        # precisely the state that must never be fabricated. There is
        # no real path from "the send call raised" to "the recipient
        # read it"; a retry produces a new message and a new bubble.
        if self._read_status == STATUS_FAILED and read_status != STATUS_FAILED:
            return

        # Phase 19.23 -- Issue 3: READ is likewise terminal with
        # respect to DELIVERED. A message_delivered packet racing a
        # read_receipt_notification (both are independent live
        # packets) must never downgrade an already-"✓✓ read" bubble
        # back to a grey "✓✓ delivered" one.
        if self._read_status is True and read_status != True:  # noqa: E712
            return

        self._read_status = read_status

        self.time_label.setText(
            _time_label_html(self._timestamp_text, read_status)
        )

        _apply_bubble_style(self._bubble, self.kind, read_status)

    # ------------------------------------------------------------------
    # Phase 19.24 (continued) -- Message Lifecycle Events UI.
    # ------------------------------------------------------------------

    def refresh_actions_button(self):
        if self.kind != "system":
            message_id = self.message_id
            self.actions_button.setVisible(
                bool(message_id and not str(message_id).startswith("live-"))
            )

    def contextMenuEvent(self, event):
        _handle_message_context_menu_event(self, event, self)

    def mark_deleted(self):
        """Replace the image with a plain deleted-message notice --
        the decrypted bytes this bubble was holding are dropped, not
        merely hidden, mirroring the real server-side deletion this
        renders (server/client_handler.py::handle_message_delete_
        for_everyone())."""

        self.is_deleted = True
        self.image_bytes = None
        self._full_pixmap = None
        self.image_label.setPixmap(QPixmap())
        self.image_label.setText("Message deleted")
        self.image_label.setStyleSheet(
            f"color: {self._content_text_color}; font-style: italic;"
        )
        self.image_label.setToolTip("")
        self.image_label.setCursor(Qt.ArrowCursor)
        for button in getattr(self, "_action_buttons", []):
            button.setVisible(False)
        self._clear_extras_for_deletion()
        _sync_item_accessible_text(self)
        _refresh_row(self)



class FileMessageBubble(_BubbleExtras, QWidget):
    """
    A single file chat bubble -- filename, human-readable size, and a
    "Save" button that writes the already-decrypted bytes held in
    memory (Phase 8 -- File & Image Transfer). Voice and video messages
    are this same bubble with an inline player (MediaPlayerCard). No plaintext is ever
    written to disk until the user explicitly chooses to save it.

    A sibling class to MessageBubble, for the same reason
    ImageMessageBubble is -- see its docstring.
    """

    def __init__(
        self,
        file_bytes,
        content_metadata,
        kind,
        sender=None,
        timestamp=None,
        read_status=None,
        on_context_action=None,
        payload_type=None,
    ):
        super().__init__()

        self.kind = kind
        self._accessible_sender = sender
        self._list_item = None
        self._content_text_color, self._content_meta_color = _bubble_content_colors(kind, read_status)
        self._file_bytes = file_bytes
        # Phase 19.24 -- Voice/Video Messages: which specialised row
        # (play control vs. generic file row) to render below. None
        # (or PayloadType.FILE) is the pre-existing plain-file bubble,
        # unaffected by any of this -- see this module's own top-of-
        # file docstring for why voice/video are just FILE bubbles with
        # a different payload_type, not a new bubble class.
        self.payload_type = payload_type or PayloadType.FILE
        # Phase 19.24 (continued) -- Forward needs the original
        # content_metadata (filename/mime_type), not just the display
        # filename _safe_filename() derives below -- see
        # ImageMessageBubble's identical self.content_metadata.
        self.content_metadata = content_metadata or {}
        self._filename = _safe_filename(
            (content_metadata or {}).get("filename"), "file"
        )
        self._media_card = None
        self._video_dialog = None

        # Phase 19.24 (continued) -- Message Lifecycle Events UI --
        # see MessageBubble.__init__'s identical attributes.
        self.message_id = None
        self.client_message_id = None
        self.reply_to_message_id = None
        self.reply_preview_text = None
        self.is_deleted = False
        self.edit_version = 0
        self.reactions = []
        self.is_pinned = False
        self.pinned_by = None
        self.supports_edit = False
        self.on_context_action = on_context_action
        self._init_extras()
        self._read_status = read_status

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(14, 10, 14, 8)
        bubble_layout.setSpacing(6)

        bubble.setMaximumWidth(600)
        is_media = self.payload_type in (PayloadType.VOICE, PayloadType.VIDEO)
        if is_media:
            # Room for the play control, a usable progress bar and the time.
            bubble.setMinimumWidth(MediaPlayerCard.VIDEO_SIZE[0] + 28 if self.payload_type == PayloadType.VIDEO else 340)
        else:
            bubble.setMinimumWidth(300)  # room for the file tile, a readable name and the download button
        bubble.setSizePolicy(
            QSizePolicy.Maximum,
            QSizePolicy.Minimum,
        )

        if sender and kind == "received":

            sender_label = QLabel(sender)
            # L-1: see MessageBubble's identical guard.
            sender_label.setTextFormat(Qt.PlainText)
            sender_label.setStyleSheet(
                f"font-size: 9pt; font-weight: 600; color: {COLOR_ACCENT};"
            )
            bubble_layout.addWidget(sender_label)

        self._build_top_extras(bubble_layout)

        size_bytes = (content_metadata or {}).get("size_bytes", len(file_bytes or b""))

        # Laid out like the Website's cards. A voice or video message is titled "Voice message" /
        # "Video message" above its player. A file is a tile with its type, the name over the size,
        # and a round download button.
        title = {
            PayloadType.VOICE: "Voice message",
            PayloadType.VIDEO: "Video message",
        }.get(self.payload_type, self._filename)
        is_plain_file = not is_media
        # A soft inset on the bubble: lighter than a sent (purple) bubble, and darker than a received
        # one on the light theme but lighter than it on the dark theme.
        tint = (
            "rgba(255, 255, 255, 0.18)" if kind == "sent"
            else ("rgba(255, 255, 255, 0.08)" if is_dark_theme() else "rgba(0, 0, 0, 0.07)")
        )

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(10)

        icon_label = QLabel()
        icon_label.setTextFormat(Qt.PlainText)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("background: transparent;")
        if is_plain_file:
            # The file tile: the document glyph with its extension under it ("PDF").
            icon_label.setFixedSize(46, 52)
            icon_label.setStyleSheet(f"background: {tint}; border-radius: 10px;")
            icon_label.setPixmap(
                toolbar_icon("file", color=self._content_text_color, active_color=self._content_text_color)
                .pixmap(QSize(22, 22))
            )
            extension = Path(self._filename).suffix.lstrip(".").upper()[:4]
            self._extension_label = QLabel(extension, icon_label)
            self._extension_label.setTextFormat(Qt.PlainText)
            self._extension_label.setAlignment(Qt.AlignCenter)
            self._extension_label.setGeometry(0, 33, 46, 14)
            self._extension_label.setStyleSheet(
                f"color: {self._content_text_color}; font-size: 7pt; font-weight: 700; background: transparent;"
            )
            title_row.addWidget(icon_label)
        else:
            icon_label.setVisible(False)  # (kept so a deleted message can hide it, as before)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(2)
        # L-1: the filename arrives inside content_metadata from the sender. Sanitised at
        # ingress too (see _safe_filename()), but rendered as data regardless.
        name_label = QLabel(title)
        name_label.setTextFormat(Qt.PlainText)
        name_label.setWordWrap(True)
        name_label.setStyleSheet(
            f"color: {self._content_text_color}; font-size: 10pt; font-weight: 600; background: transparent;"
        )
        text_column.addWidget(name_label)
        size_label = QLabel(_format_file_size(size_bytes))
        size_label.setTextFormat(Qt.PlainText)
        size_label.setStyleSheet(
            f"color: {self._content_meta_color}; font-size: 8.5pt; background: transparent;"
        )
        size_label.setVisible(is_plain_file)  # a voice/video message shows its length in the player
        text_column.addWidget(size_label)
        title_row.addLayout(text_column, 1)
        self._icon_label, self._title_label, self._size_label = icon_label, name_label, size_label
        self._title_row = title_row
        bubble_layout.addLayout(title_row)

        # Phase 19.24 -- Voice/Video Messages: a real player, not merely a download link. Plays
        # DIRECTLY from the already-decrypted bytes held in memory (QBuffer), never writing
        # plaintext to disk merely to play it -- Save below remains the only path that touches
        # disk, and only on the user's explicit request.
        footer_actions = []
        if is_media:
            self._media_card = MediaPlayerCard(
                file_bytes,
                self.content_metadata.get("mime_type") or "",
                is_video=self.payload_type == PayloadType.VIDEO,
                text_color=self._content_text_color,
                meta_color=self._content_meta_color,
                accent_color=COLOR_ACCENT,
                duration_seconds=self.content_metadata.get("duration_seconds"),
            )
            if self.payload_type == PayloadType.VOICE:
                pill = QFrame()
                pill.setObjectName("MediaPill")
                pill.setStyleSheet(f"QFrame#MediaPill {{ background: {tint}; border-radius: 22px; }}")
                pill_layout = QHBoxLayout(pill)
                pill_layout.setContentsMargins(8, 6, 12, 6)
                pill_layout.addWidget(self._media_card)
                self._media_pill = pill
                bubble_layout.addWidget(pill)
            else:
                bubble_layout.addWidget(self._media_card)
            if self.payload_type == PayloadType.VOICE:
                # Kept under their established names (tests and callers use them).
                self._voice_play_button = self._media_card.play_button
                self._voice_duration_label = self._media_card.time_label
            else:
                expand_button = media_action_button(
                    "Full screen", "expand", self._content_text_color, "Play video full screen"
                )
                expand_button.clicked.connect(self._open_video_player)
                footer_actions.append(expand_button)

        if is_plain_file:
            # A round download button at the end of the file row, like the Website's.
            save_button = QToolButton()
            save_button.setObjectName("FileDownloadButton")
            save_button.setCursor(Qt.PointingHandCursor)
            save_button.setFixedSize(36, 36)
            save_button.setIcon(
                toolbar_icon("download", color=self._content_text_color, active_color=self._content_text_color)
            )
            save_button.setIconSize(QSize(18, 18))
            save_button.setAccessibleName(f"Save {title}")
            save_button.setToolTip("Save")
            save_button.setStyleSheet(
                f"QToolButton#FileDownloadButton {{ background: {tint}; border: none; border-radius: 18px; }}"
                f"QToolButton#FileDownloadButton:hover {{ background: rgba(127, 127, 127, 0.35); }}"
                f"QToolButton#FileDownloadButton:focus {{ border: 2px solid {self._content_text_color}; }}"
            )
            save_button.clicked.connect(self._handle_save_as)
            self._title_row.addWidget(save_button)
            self._save_button = save_button
            self._action_buttons = footer_actions + [save_button]
        else:
            save_button = media_action_button(
                "Save", "download", self._content_text_color, f"Save {title}"
            )
            save_button.clicked.connect(self._handle_save_as)
            footer_actions.insert(0, save_button)
            self._save_button = save_button
            self._action_buttons = footer_actions

        self._build_reactions(bubble_layout)

        self._timestamp_text = timestamp or datetime.now().strftime("%H:%M")

        self.time_label = QLabel(
            _time_label_html(
                self._timestamp_text,
                read_status if kind == "sent" else None,
            )
        )
        # Explicit, not inherited: this label is intentionally rich
        # text (see _time_label_html()), so it must never fall back to
        # AutoText -- and its content is app-generated and escaped.
        self.time_label.setTextFormat(Qt.RichText)
        # Named so the structural guard in
        # tests/test_rich_text_injection.py can whitelist this one
        # label by identity rather than by position.
        self.time_label.setObjectName("TimestampLabel")
        self.time_label.setStyleSheet(
            f"color: {self._content_meta_color}; "
            "font-size: 8pt; background: transparent;"
        )
        self.time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(_message_footer(self, self.time_label, footer_actions))

        self._bubble = bubble

        _apply_bubble_style(bubble, kind, read_status)
        self._style_extras()

        if kind == "sent":
            outer.addStretch()
            outer.addWidget(bubble)
        else:
            outer.addWidget(bubble)
            outer.addStretch()

    def _handle_save_as(self):
        """
        Write the already-decrypted bytes this bubble holds to a
        user-chosen local path. A no-op if the dialog is cancelled.
        """

        if not self._file_bytes:
            return

        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save File",
            self._filename
        )

        if path:
            Path(path).write_bytes(self._file_bytes)

    # ------------------------------------------------------------------
    # Phase 19.24 -- Voice/Video Messages playback.
    # ------------------------------------------------------------------

    def _media_source_url(self):
        """A hint URL (never resolved/fetched -- QMediaPlayer.
        setSourceDevice()'s second argument is used only to pick the
        right decoder by extension) carrying this attachment's real
        extension, derived from its own mime_type."""

        mime_type = (self.content_metadata.get("mime_type") or "").split(";")[0].strip()
        ext = mimetypes.guess_extension(mime_type) or ".bin"
        return QUrl(f"clip{ext}")

    def _format_duration(self, seconds=None):
        if seconds is None:
            seconds = self.content_metadata.get("duration_seconds")
        if not seconds:
            return ""
        return format_clock(seconds)

    def _toggle_voice_playback(self):
        if self._media_card is not None:
            self._media_card.toggle()

    @property
    def is_playing(self):
        return bool(self._media_card is not None and self._media_card.is_playing)

    def _open_video_player(self):
        """A larger player for a video message -- a real QVideoWidget/QMediaPlayer, playing
        directly from the already-decrypted bytes in memory. Stops and releases playback the
        moment the window closes. The inline card pauses while it is open."""

        if not self._file_bytes:
            return None

        if self._media_card is not None:
            self._media_card.pause()

        dialog = QDialog(self)
        dialog.setWindowTitle("Video message")
        dialog.resize(640, 400)

        layout = QVBoxLayout(dialog)
        video_widget = QVideoWidget(dialog)
        layout.addWidget(video_widget)

        player = QMediaPlayer(dialog)
        audio_output = QAudioOutput(dialog)
        player.setAudioOutput(audio_output)
        player.setVideoOutput(video_widget)

        buffer = QBuffer(dialog)
        buffer.setData(QByteArray(bytes(self._file_bytes)))
        buffer.open(QIODevice.ReadOnly)
        player.setSourceDevice(buffer, self._media_source_url())

        dialog.finished.connect(lambda *_: player.stop())
        self._video_dialog = dialog

        player.play()
        dialog.show()
        return dialog

    def set_read_status(self, read_status):
        """
        Update this sent bubble's check-mark glyph in place (C2 --
        Read Receipts). A no-op for a received bubble -- see
        MessageBubble.set_read_status()'s identical docstring.
        """

        if self.kind != "sent":
            return

        # A failed send is TERMINAL for this bubble. Without this
        # guard mark_all_sent_read() -- which sweeps every tracked
        # sent bubble in the conversation, by design -- would flip a
        # message that never reached the server to "✓✓ read", which is
        # precisely the state that must never be fabricated. There is
        # no real path from "the send call raised" to "the recipient
        # read it"; a retry produces a new message and a new bubble.
        if self._read_status == STATUS_FAILED and read_status != STATUS_FAILED:
            return

        # Phase 19.23 -- Issue 3: READ is likewise terminal with
        # respect to DELIVERED. A message_delivered packet racing a
        # read_receipt_notification (both are independent live
        # packets) must never downgrade an already-"✓✓ read" bubble
        # back to a grey "✓✓ delivered" one.
        if self._read_status is True and read_status != True:  # noqa: E712
            return

        self._read_status = read_status

        self.time_label.setText(
            _time_label_html(self._timestamp_text, read_status)
        )

        _apply_bubble_style(self._bubble, self.kind, read_status)

    def refresh_actions_button(self):
        if self.kind != "system":
            message_id = self.message_id
            self.actions_button.setVisible(
                bool(message_id and not str(message_id).startswith("live-"))
            )

    # ------------------------------------------------------------------
    # Phase 19.24 (continued) -- Message Lifecycle Events UI.
    # ------------------------------------------------------------------

    def contextMenuEvent(self, event):
        _handle_message_context_menu_event(self, event, self)

    def mark_deleted(self):
        """Mark this file bubble deleted -- the decrypted bytes this
        bubble was holding are dropped, not merely hidden."""

        self.is_deleted = True
        self._file_bytes = None
        self._icon_label.setVisible(False)
        self._size_label.setVisible(False)
        self._title_label.setText("Message deleted")
        self._title_label.setStyleSheet(
            f"color: {self._content_text_color}; font-size: 10pt; font-style: italic; background: transparent;"
        )
        if self._media_card is not None:
            self._media_card.release()
            self._media_card.setVisible(False)
        for button in getattr(self, "_action_buttons", []):
            button.setVisible(False)
        self._clear_extras_for_deletion()
        _sync_item_accessible_text(self)
        _refresh_row(self)



class MessageWidget(QListWidget):
    """
    Displays chat messages as bubbles.
    """

    def __init__(self):
        super().__init__()

        # handle -> name to show above a received group message; ChatWindow supplies the
        # session's display-name cache. Only for display: nothing here is keyed on it.
        self.name_for = None
        # This account's handle (reactions/pins by "you") and the open direct chat's display
        # name (the author of a quoted message when a bubble carries no sender label).
        self.own_username = None
        self.peer_display_name = None
        # original message_id -> [reply bubbles quoting it], so a quote updates when its
        # original arrives later, is edited or is deleted.
        self._replies_by_target = {}

        # C2 -- Read Receipts: this client's own sent bubbles in the
        # currently-open conversation, so a later
        # read_receipt_notification can flip them to "read" in place --
        # see mark_all_sent_read(). Cleared on every clear_messages()
        # call (i.e. every conversation open/switch), since bubbles are
        # always re-rendered fresh from history at that point anyway.
        #
        # Keyed by the database message_id where one is known (a
        # history-loaded row), and by a synthetic per-bubble key where
        # one is not (a message sent live this session, which has no
        # database id on this client -- the id is assigned server-side
        # by persist_message() and never sent back). BUG 2: a live
        # bubble used to be left out of this registry entirely, which
        # is precisely why a sender watching the conversation saw
        # nothing when the other party read it -- there was no
        # reference to flip -- and why the tick only appeared after a
        # logout/login, when history re-rendered the same message with
        # its real id. Every sent bubble is now reachable, whatever the
        # client happens to know about its id.
        #
        # Real ids are still used as keys wherever they exist, so a
        # future per-message (rather than conversation-level) receipt
        # can address exactly one bubble without changing this
        # structure.
        self._sent_bubbles_by_message_id = {}

        # Phase 19.24 -- Message Lifecycle Events: EVERY bubble (sent
        # OR received) that has a REAL, server-assigned message_id --
        # see _add_bubble()'s own docstring for why this is a second,
        # broader registry rather than reusing the one above. Cleared
        # on every clear_messages() call, same as the registry above.
        self._bubbles_by_message_id = {}

        # Phase 19.24 (continued) -- Message Lifecycle Events UI. ONE
        # callback (action: str, bubble) -> None, set ONCE by gui/
        # chat_window.py via set_context_action_handler() and applied
        # to every bubble _add_bubble() creates from then on, rather
        # than threading an on_context_action parameter through every
        # add_sent_*/add_received_* method's already-long signature.
        # None until set -- a bubble built before that (there is no
        # such caller in practice) simply offers no context menu.
        self._context_action_handler = None

        # Source of the synthetic keys above. A plain counter, never
        # persisted and never sent anywhere -- it exists only to keep
        # two live bubbles in the same conversation distinct.
        self._live_bubble_sequence = 0

        # UI Finalization Decision 4 -- the calendar date (a
        # datetime.date, never a datetime) the most recently added
        # separator/bubble belongs to, so _maybe_insert_date_separator()
        # can tell "same day as the last bubble" from "a new day
        # started" without re-scanning every row already in the list.
        # None until the first bubble is added, and reset by
        # clear_messages() exactly like the read-receipt registry
        # above, for the same reason: every clear is followed by a
        # fresh render from history, which must re-derive its own
        # separators rather than inherit stale state.
        self._last_separator_date = None

        # Phase 19.24 -- Message Search: the bubble (if any) currently
        # wearing the search-match highlight outline, so a later match
        # (or clear_highlight()) knows which one to restore. Never
        # persisted, never sent anywhere -- purely an in-memory pointer
        # into the already-rendered widget tree.
        self._highlighted_bubble = None

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):
        """
        Configure the message list.
        """

        self.setSelectionMode(
            QAbstractItemView.NoSelection
        )

        self.setFocusPolicy(
            Qt.NoFocus
        )

        self.setVerticalScrollMode(
            QAbstractItemView.ScrollPerPixel
        )

        self.setStyleSheet(
            "QListWidget { border: none; border-radius: 0px; background: transparent; "
            "padding: 8px 14px; outline: none; }"
        )

        self.setSpacing(2)

    # ==========================================================
    # Internal Helpers
    # ==========================================================

    def _maybe_insert_date_separator(self, message_date):
        """
        Insert a DateSeparatorBubble if ``message_date`` (a
        datetime.date) is not the same day as the last bubble added --
        never more than one separator per calendar date, and never out
        of order, since every caller appends chronologically (history
        loads in order; a live message is always "now").

        ``message_date=None`` (a system message, or any caller that
        genuinely has no date) is a deliberate no-op: it neither
        triggers nor updates the separator state, so a system notice
        sandwiched between two same-day messages cannot itself cause a
        spurious extra separator.
        """

        if message_date is None:
            return

        if message_date == self._last_separator_date:
            return

        self._last_separator_date = message_date

        separator_item = QListWidgetItem()
        separator_item.setFlags(Qt.NoItemFlags)

        separator_bubble = DateSeparatorBubble(message_date)

        separator_item.setSizeHint(_row_size_hint(separator_bubble))
        separator_item.setData(Qt.AccessibleTextRole, message_date.strftime("%d %B %Y"))

        self.addItem(separator_item)

        self.setItemWidget(separator_item, separator_bubble)

    def set_context_action_handler(self, handler):
        """Phase 19.24 (continued) -- see _context_action_handler's own
        __init__ comment. Called once by gui/chat_window.py."""

        self._context_action_handler = handler

    def _add_bubble(self, bubble, message_id=None, message_date=None):

        bubble.on_context_action = self._context_action_handler
        if bubble.kind != "system":
            bubble._name_for = self.name_for
            bubble._own_username = self.own_username
            bubble.on_reply_activated = self._on_reply_activated

        self._maybe_insert_date_separator(message_date)

        item = QListWidgetItem()

        item.setFlags(Qt.NoItemFlags)

        item.setSizeHint(
            _row_size_hint(bubble)
        )

        self.addItem(item)

        self.setItemWidget(item, bubble)

        bubble._list_item = item
        item.setData(Qt.AccessibleTextRole, _accessible_summary(bubble))

        self.scrollToBottom()

        # C2 -- Read Receipts: every SENT bubble is registered, with or
        # without a database id (BUG 2 -- see __init__'s note on this
        # registry for why the id cannot be a precondition). A received
        # bubble is still never registered here: it never shows a
        # receipt indicator (set_read_status() is a no-op for it
        # regardless), so tracking it in THIS registry would only
        # waste memory.
        assigned_id = message_id

        if bubble.kind == "sent":

            if assigned_id is None:
                self._live_bubble_sequence += 1
                assigned_id = f"live-{self._live_bubble_sequence}"

            self._sent_bubbles_by_message_id[assigned_id] = bubble

        # Phase 19.24 -- Message Lifecycle Events: bubble.message_id is
        # the SAME key used above for a sent bubble (including its
        # "live-N" placeholder, so the two registries always agree),
        # or the real history-supplied id, or None for a live-received
        # bubble the server has not yet told this client the id of
        # (_build_message_context_menu()'s own "not bubble.message_id"
        # check is exactly what keeps a menu from being offered on
        # such a bubble). EVERY bubble with a REAL id -- sent or
        # received -- is additionally registered in
        # _bubbles_by_message_id, since edit/delete/reaction
        # notifications must be able to find and update a RECEIVED
        # bubble too, unlike the sent-only receipt registry above.
        bubble.message_id = assigned_id
        if hasattr(bubble, "refresh_actions_button"):
            bubble.refresh_actions_button()

        if bubble.kind != "system" and assigned_id is not None and not str(assigned_id).startswith("live-"):
            self._bubbles_by_message_id[assigned_id] = bubble
            self._refresh_replies_to(assigned_id)

        # Phase 19.24 -- Message Lifecycle Events: lets a caller (e.g.
        # add_sent_message() -> gui/chat_window.py::send_message())
        # stash extra per-bubble state (client_message_id for retry
        # idempotency, the real message_id once history/an ack
        # supplies one, ...) on the exact bubble just created.
        return bubble

    # ==========================================================
    # Public Methods
    # ==========================================================

    def add_group_event(self, text, event_id=None, message_date=None):
        """A group membership event ("Alice added Bob") as a centred system line, in order with the
        messages. Like any system notice it never breaks a date separator -- except that its own
        calendar date (when known) is given one, so an event on a new day starts that day."""

        self._maybe_insert_date_separator(message_date)
        bubble = self.add_system_message(text)
        if bubble is not None:
            bubble.group_event_id = event_id
        return bubble

    def add_system_message(self, message):
        """
        Display a system message. Deliberately no ``message_date``: a
        system notice never anchors or breaks a date separator -- see
        _maybe_insert_date_separator()'s docstring.
        """

        return self._add_bubble(
            MessageBubble(message, kind="system")
        )

    def _shown_name(self, sender):
        if not sender or self.name_for is None:
            return sender
        try:
            return self.name_for(sender) or sender
        except Exception:  # noqa: BLE001 -- a name is cosmetic; never lose the message over it
            return sender

    def add_received_message(
        self,
        sender,
        message,
        timestamp=None,
        message_date=None,
        message_id=None,
    ):
        """
        Display a received message. ``message_date`` (UI Finalization
        Decision 4, a datetime.date) is optional and defaults to
        "today" at the ChatWindow call site for a live message -- see
        gui/chat_window.py::receive_message(). ``message_id`` (Phase
        19.24, continued) is the real, server-assigned id -- supplied
        directly by gui/chat_window.py::load_history() for a history
        row (already known), or attached shortly after a LIVE receive
        via register_received_bubble_id() (ClientSession.handle_chat()
        only learns/decrypts alongside the message itself, then
        signals it separately -- see message_id_received's own
        declaration). Returns the created bubble so the caller can
        attach reply-preview/edit/delete/reaction state.
        """

        return self._add_bubble(
            MessageBubble(
                message, kind="received", sender=self._shown_name(sender), timestamp=timestamp
            ),
            message_date=message_date,
            message_id=message_id,
        )

    def add_sent_message(
        self,
        message,
        timestamp=None,
        message_id=None,
        read_status=None,
        on_retry=None,
        message_date=None,
    ):
        """
        Display a sent message. ``message_id``/``read_status`` (C2 --
        Read Receipts) are optional -- omitted for a message sent live
        this session (no database id yet); supplied by
        gui/chat_window.py::load_history() for a history-loaded row,
        which always has both. ``message_date`` (UI Finalization
        Decision 4): see add_received_message()'s docstring.
        """

        return self._add_bubble(
            MessageBubble(
                message,
                kind="sent",
                timestamp=timestamp,
                read_status=read_status,
                on_retry=on_retry,
            ),
            message_id=message_id,
            message_date=message_date,
        )

    def add_received_image(
        self, sender, image_bytes, timestamp=None, content_metadata=None, message_date=None,
        message_id=None,
    ):
        """
        Display a received image (Phase 8 -- File & Image Transfer).

        ``content_metadata`` (BUG 5) carries the sender's original
        filename and MIME type through to the bubble, so "Save As..."
        can offer the real name instead of inventing one. Optional, so
        every existing caller keeps working unchanged. ``message_date``
        (UI Finalization Decision 4): see add_received_message()'s
        docstring. ``message_id`` (Phase 19.24, continued): see add_
        received_message()'s identical docstring note.
        """

        return self._add_bubble(
            ImageMessageBubble(
                image_bytes,
                kind="received",
                sender=self._shown_name(sender),
                timestamp=timestamp,
                content_metadata=content_metadata,
            ),
            message_date=message_date,
            message_id=message_id,
        )

    def add_sent_image(
        self,
        image_bytes,
        timestamp=None,
        message_id=None,
        read_status=None,
        content_metadata=None,
        message_date=None,
    ):
        """
        Display a sent image (Phase 8 -- File & Image Transfer). See
        add_sent_message() for ``message_id``/``read_status`` (C2 --
        Read Receipts) and ``message_date`` (UI Finalization Decision
        4), and add_received_image() for ``content_metadata`` (BUG 5).
        """

        return self._add_bubble(
            ImageMessageBubble(
                image_bytes,
                kind="sent",
                timestamp=timestamp,
                read_status=read_status,
                content_metadata=content_metadata,
            ),
            message_id=message_id,
            message_date=message_date,
        )

    def add_received_file(
        self, sender, file_bytes, content_metadata, timestamp=None, message_date=None,
        message_id=None, payload_type=None,
    ):
        """
        Display a received file (Phase 8 -- File & Image Transfer).
        ``message_date`` (UI Finalization Decision 4): see
        add_received_message()'s docstring. ``message_id`` (Phase
        19.24, continued): see add_received_message()'s identical
        docstring note. ``payload_type`` (Phase 19.24 -- Voice/Video
        Messages): PayloadType.VOICE/VIDEO render a play control
        instead of the plain file row -- see FileMessageBubble's own
        docstring for why this is not a separate bubble class.
        """

        return self._add_bubble(
            FileMessageBubble(
                file_bytes,
                content_metadata,
                kind="received",
                sender=self._shown_name(sender),
                timestamp=timestamp,
                payload_type=payload_type,
            ),
            message_date=message_date,
            message_id=message_id,
        )

    def add_sent_file(
        self,
        file_bytes,
        content_metadata,
        timestamp=None,
        message_id=None,
        read_status=None,
        message_date=None,
        payload_type=None,
    ):
        """
        Display a sent file (Phase 8 -- File & Image Transfer). See
        add_sent_message() for ``message_id``/``read_status`` (C2 --
        Read Receipts) and ``message_date`` (UI Finalization Decision
        4). ``payload_type``: see add_received_file()'s identical note.
        """

        return self._add_bubble(
            FileMessageBubble(
                file_bytes,
                content_metadata,
                kind="sent",
                timestamp=timestamp,
                read_status=read_status,
                payload_type=payload_type,
            ),
            message_id=message_id,
            message_date=message_date,
        )

    def mark_all_sent_read(self):
        """
        Flip every currently-tracked sent bubble in this conversation
        to the "read" check-mark state (C2 -- Read Receipts).

        Correct, not an approximation, given this app's conversation-
        level "read up to now" semantics (server/client_handler.py::
        handle_read_receipt() marks every one of the reader's unread
        MessageRecipient rows in the conversation at once, not a
        single message) -- when a read_receipt_notification arrives
        for a direct conversation, the one other party has, by
        definition, just read every message they could see; for a
        group, the caller (gui/chat_window.py) only calls this once
        every currently-active recipient has been accounted for.
        Covers every sent bubble in the conversation, including one
        sent live this session that has no database id on this client
        (BUG 2 -- such bubbles used to be skipped, so a sender watching
        the conversation saw nothing until a logout/login re-rendered
        them from history).
        """

        for bubble in self._sent_bubbles_by_message_id.values():
            bubble.set_read_status(True)

    def mark_oldest_undelivered_sent(self):
        """
        Phase 19.23 -- Issue 3: flip the oldest still-"✓ sent" bubble
        in this conversation to "✓✓ delivered", in response to a live
        message_delivered packet.

        Resolves by POSITION, not by message_id, deliberately: a
        live-sent bubble is tracked here under a "live-N" placeholder
        id (_add_bubble()'s own scheme, above) until this client's
        next history reload learns its real server-assigned id, so a
        message_delivered packet's own real id can never be matched
        directly against a bubble that was only just sent in this same
        session. The oldest bubble still in the plain "Sent" (False)
        state is, by construction, the one this ack is for: the server
        relays and acknowledges messages to a given recipient in the
        order they were sent, and this dict preserves insertion order.
        Mirrors mobile/app.py's own identical "oldest unresolved
        bubble" resolution, done for the exact same reason (its
        bubbles are equally unaware of their real server id yet).

        A no-op once nothing is left in the plain "Sent" state --
        every already-delivered/read/failed bubble is skipped, so a
        late or duplicate ack changes nothing.
        """

        for bubble in self._sent_bubbles_by_message_id.values():

            if bubble._read_status is False:

                bubble.set_read_status(STATUS_DELIVERED)

                return

    # ------------------------------------------------------------------
    # Phase 19.24 (continued) -- Message Lifecycle Events UI. Thin
    # message_id -> bubble dispatch, reused by gui/chat_window.py's
    # signal handlers for both a live notification and a history-
    # reload row -- neither needs to know which bubble class it
    # actually is, only that it exposes these same three methods
    # (every MessageBubble/ImageMessageBubble/FileMessageBubble does).
    # A message_id this widget has no bubble for (scrolled out,
    # different conversation, or arriving before its own bubble was
    # ever rendered) is silently ignored -- there is nothing on screen
    # to update, not an error.
    # ------------------------------------------------------------------

    def resolve_oldest_live_bubble_id(self, real_message_id):
        """
        Phase 19.24 (continued) -- re-key the oldest still-"live-N"-
        keyed sent bubble to its real, server-assigned message_id, in
        response to ClientSession.own_message_id_resolved (fired from
        message_delivered/message_queued -- the first packets that
        ever tell a sender what a just-sent message's real id is).
        Mirrors mark_oldest_undelivered_sent()'s identical "oldest
        unresolved, by insertion order" resolution, for the identical
        reason: there is no way to address a specific live-sent bubble
        by real id before this arrives, since it never had one.

        This is what makes Reply/Edit/Delete/React usable on a
        message THIS SESSION just sent, without waiting for a history
        reload -- before this, a live-sent bubble's context menu had
        nothing to address (see _build_message_context_menu()'s own
        "not bubble.message_id" gate) until the next reconnect re-
        rendered it from history with a real id already attached.

        A no-op once nothing is left under a live-N key (every
        already-resolved bubble is skipped), so a late/duplicate
        resolution changes nothing.
        """

        for key, bubble in list(self._sent_bubbles_by_message_id.items()):

            if not str(key).startswith("live-"):
                continue

            del self._sent_bubbles_by_message_id[key]
            self._sent_bubbles_by_message_id[real_message_id] = bubble
            bubble.message_id = real_message_id
            self._bubbles_by_message_id[real_message_id] = bubble
            if hasattr(bubble, "refresh_actions_button"):
                bubble.refresh_actions_button()
            self._refresh_replies_to(real_message_id)

            return

    def apply_edit_to_message(self, message_id, new_text, edit_version):
        bubble = self._bubbles_by_message_id.get(message_id)
        if bubble is not None and bubble.supports_edit:
            bubble.apply_edit(new_text, edit_version)
            self._refresh_replies_to(message_id)

    def mark_message_deleted(self, message_id):
        bubble = self._bubbles_by_message_id.get(message_id)
        if bubble is not None:
            bubble.mark_deleted()
            self._refresh_replies_to(message_id)

    # ==========================================================
    # Replies -- resolved by the original's stable message id, never by text
    # ==========================================================

    def reply_excerpt_for(self, original):
        """What a reply quotes for ``original``: its text, a media label (never the media
        itself), or "Message deleted"."""

        if getattr(original, "is_deleted", False):
            return "Message deleted"
        if isinstance(original, MessageBubble):
            return original.message_text or "Message"
        if isinstance(original, ImageMessageBubble):
            return MEDIA_REPLY_LABELS["image"]
        payload_type = getattr(original, "payload_type", None)
        if payload_type == PayloadType.VOICE:
            return MEDIA_REPLY_LABELS["voice"]
        if payload_type == PayloadType.VIDEO:
            return MEDIA_REPLY_LABELS["video"]
        return f"\U0001F4C4 {getattr(original, '_filename', '') or 'File'}"

    def _author_of(self, original):
        if original.kind == "sent":
            return "You"
        return getattr(original, "_accessible_sender", None) or self.peer_display_name or "Them"

    def set_reply_reference(self, bubble, reply_to_message_id):
        """
        Show on ``bubble`` the message it replies to. The original is looked up by its stable,
        server-assigned id among THIS transcript's bubbles only (one conversation is rendered at
        a time, and the server only keeps a reply reference that points into the same
        conversation), so nothing from another conversation can be quoted. An original that is
        not loaded -- older than what is shown, hidden for this account, or not visible to it --
        is shown as unavailable rather than guessed at.
        """

        if bubble is None or not reply_to_message_id or bubble.kind == "system":
            return

        bubble.reply_to_message_id = reply_to_message_id
        waiting = self._replies_by_target.setdefault(reply_to_message_id, [])
        if bubble not in waiting:
            waiting.append(bubble)

        if getattr(bubble, "is_deleted", False):
            return

        original = self._bubbles_by_message_id.get(reply_to_message_id)

        if original is None:
            bubble.set_reply_preview(
                "Original message unavailable", author="Reply", clickable=False, unavailable=True
            )
        else:
            bubble.set_reply_preview(
                self.reply_excerpt_for(original),
                author=self._author_of(original),
                clickable=not getattr(original, "is_deleted", False),
            )

        _sync_item_accessible_text(bubble)

    def _refresh_replies_to(self, message_id):
        for reply in list(self._replies_by_target.get(message_id, ())):
            self.set_reply_reference(reply, message_id)

    def _on_reply_activated(self, bubble):
        original = self._bubbles_by_message_id.get(getattr(bubble, "reply_to_message_id", None))
        if original is not None and self.scroll_to_bubble(original):
            # A brief highlight, like the Website's jump-to-original.
            QTimer.singleShot(2200, self.clear_highlight)

    def update_message_reactions(self, message_id, reactions):
        bubble = self._bubbles_by_message_id.get(message_id)
        if bubble is not None:
            bubble.update_reactions(reactions)

    def register_received_bubble_id(self, bubble, message_id):
        """
        Phase 19.24 (continued) -- attach a real, server-assigned
        message_id to a RECEIVED bubble that was rendered without one
        yet (a live message -- see ClientSession's message_id_received
        signal declaration for why this arrives one signal after the
        message itself), retroactively making its own context-menu
        actions (Reply/React/Delete-for-me/Forward) available. A no-op
        if the bubble already has an id (a duplicate/late signal) or if
        message_id is falsy.
        """

        if bubble is None or not message_id or bubble.message_id:
            return

        bubble.message_id = message_id
        if hasattr(bubble, "refresh_actions_button"):
            bubble.refresh_actions_button()

        if bubble.kind != "system":
            self._bubbles_by_message_id[message_id] = bubble
            self._refresh_replies_to(message_id)

    def get_bubble(self, message_id):
        """Read-only lookup -- used by gui/chat_window.py to resolve a
        reply target's own preview text (its already-decrypted
        message_text) and to check supports_edit/is_deleted/reactions
        before offering an action."""

        return self._bubbles_by_message_id.get(message_id)

    def set_wallpaper(self, wallpaper_id):
        """Phase 19.24 -- Chat Wallpaper: applies (or, for None,
        clears) a preset gradient background behind this conversation's
        bubbles. Purely a per-instance QSS override -- the shared
        QListWidget rule in gui/styles.py is untouched, so every OTHER
        list in the app (conversation sidebar, dialogs) is unaffected.
        The existing solid, opaque bubble colors (COLOR_BUBBLE_SENT/
        RECEIVED) always render on top, so readability is never at
        risk regardless of which preset is chosen -- see gui/styles.py
        ::WALLPAPER_PRESETS's own docstring for why these are
        deliberately low-contrast."""

        from gui.styles import COLOR_BORDER, COLOR_PANEL, WALLPAPER_PRESETS

        preset = WALLPAPER_PRESETS.get(wallpaper_id)
        background = preset[1] if preset else COLOR_PANEL

        self.setStyleSheet(
            f"QListWidget {{ background: {background}; "
            "border: none; border-radius: 0px; "
            "padding: 8px 14px; outline: none; }"
        )

    # ==========================================================
    # Phase 19.24 -- Message Search
    # ==========================================================
    #
    # Operates ONLY on bubbles already rendered in this widget --
    # i.e. the SAME already-decrypted plaintext load_history() and
    # add_sent_message()/add_received_message() already put on
    # screen. There is no second query, no server round trip, and
    # the search text itself is never transmitted: this satisfies
    # the "do not send decrypted message text to the server merely
    # to implement search" requirement by construction, and "works
    # after history recovery" for the same reason -- whatever
    # load_history() loaded IS the searchable set.

    def find_matches(self, query):
        """
        Return the row indices (into this QListWidget) of every
        rendered, non-deleted message bubble whose own message_text
        contains ``query`` (case-insensitive substring match), in
        on-screen (chronological) order. Date separators and system
        bubbles have no message_text and are skipped automatically
        via getattr's default rather than an isinstance check, so a
        future bubble kind needs no change here.
        """

        query = (query or "").strip().lower()
        if not query:
            return []

        matches = []
        for row in range(self.count()):
            bubble = self.itemWidget(self.item(row))
            text = getattr(bubble, "message_text", None)
            if not text or getattr(bubble, "is_deleted", False):
                continue
            if query in text.lower():
                matches.append(row)
        return matches

    def highlight_row(self, row):
        """
        Scroll row ``row`` into view and outline its bubble so the
        user can see which match is current. Clears any previous
        highlight first, so only ever one bubble is outlined at a
        time.
        """

        self.clear_highlight()

        item = self.item(row)
        if item is None:
            return

        self.scrollToItem(item, QAbstractItemView.PositionAtCenter)

        bubble = self.itemWidget(item)
        frame = getattr(bubble, "_bubble", None)
        if frame is None:
            return

        frame.setStyleSheet(
            frame.styleSheet() + f"border: 2px solid {COLOR_ACCENT};"
        )
        self._highlighted_bubble = bubble

    def clear_highlight(self):
        """
        Remove the search-match outline from whichever bubble
        currently wears one, restoring its normal per-kind style via
        the same _apply_bubble_style() every other state change
        (read receipt, retry, delete) already uses -- never a
        hand-rolled "undo" of the outline string.
        """

        bubble = self._highlighted_bubble
        self._highlighted_bubble = None
        if bubble is None:
            return

        frame = getattr(bubble, "_bubble", None)
        if frame is not None:
            _apply_bubble_style(
                frame, bubble.kind, getattr(bubble, "_read_status", None)
            )

    # ==========================================================
    # Phase 19.24 -- Pinned Messages
    # ==========================================================

    def apply_pin_to_message(self, message_id, pinned, pinned_by=None):
        """Apply pin/unpin state to whichever rendered bubble has this
        REAL server-assigned message_id -- a no-op if that bubble is
        not currently rendered (e.g. the notification is for a
        conversation that is not the one currently open)."""

        bubble = self._bubbles_by_message_id.get(message_id)

        if bubble is not None and hasattr(bubble, "set_pinned"):
            bubble.set_pinned(pinned, pinned_by)

    def get_pinned_bubbles(self):
        """Every currently-pinned bubble in this conversation, in on-
        screen (chronological) order -- the source list for gui/
        chat_window.py's Pinned Messages panel."""

        return [
            self.itemWidget(self.item(row))
            for row in range(self.count())
            if getattr(self.itemWidget(self.item(row)), "is_pinned", False)
        ]

    def get_media_bubbles(self):
        """Every currently-rendered image/video/voice/file attachment
        bubble in this conversation, in on-screen (chronological)
        order -- the source list for gui/chat_window.py's Media
        Gallery panel. Purely a scan over bubbles already decrypted
        and rendered (mirrors get_pinned_bubbles()'s/Message Search's
        own identical "no server round trip" contract) -- a deleted
        attachment's content is already gone (mark_deleted() drops the
        bytes), so it is skipped here rather than shown as a broken
        tile.
        """

        result = []
        for row in range(self.count()):
            bubble = self.itemWidget(self.item(row))
            if isinstance(bubble, (ImageMessageBubble, FileMessageBubble)) and not getattr(
                bubble, "is_deleted", False
            ):
                result.append(bubble)
        return result

    def scroll_to_bubble(self, bubble):
        """Scroll ``bubble`` into view and briefly outline it -- reuses
        the exact same highlight_row()/clear_highlight() machinery
        Message Search already built, so "navigate to message" from
        the Pinned Messages panel and a search-match jump look and
        behave identically. Returns True if the bubble was found (still
        actually rendered in this conversation), False otherwise."""

        for row in range(self.count()):
            if self.itemWidget(self.item(row)) is bubble:
                self.highlight_row(row)
                return True
        return False

    def clear_messages(self):
        """
        Remove every message.
        """

        self.clear()

        self._sent_bubbles_by_message_id = {}
        self._bubbles_by_message_id = {}
        self._replies_by_target = {}

        self._live_bubble_sequence = 0

        self._last_separator_date = None

        self._highlighted_bubble = None