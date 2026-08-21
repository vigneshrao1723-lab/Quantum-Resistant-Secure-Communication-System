"""
Message Widget

Displays the conversation between the current user and the
selected chat partner as chat bubbles (sent / received / system).
"""

import html
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QBuffer, QByteArray, QIODevice, QSize
from PySide6.QtGui import QImageReader, QPixmap
from PySide6.QtWidgets import (
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
    QDialog,
    QWidget,
    QLabel,
    QFileDialog,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QSizePolicy,
)

from gui.styles import (
    COLOR_BUBBLE_FAILED,
    COLOR_BUBBLE_SENT,
    COLOR_BUBBLE_RECEIVED,
    COLOR_BUBBLE_SYSTEM,
    COLOR_READ_RECEIPT,
    COLOR_SEND_FAILED,
    COLOR_TEXT_MUTED,
)


# Task 2 -- a fourth status alongside the C2 read-receipt tri-state.
#
# Deliberately a STRING, so it cannot collide with any value the
# server can produce: read_status arrives from the message-history
# packet and from read_receipt_notification as None / False / True
# only (see server/client_handler.py::_read_status_for_own_message()),
# and no bool ever compares equal to this.
STATUS_FAILED = "failed"


def _read_status_suffix(read_status):
    """
    Delivery-status glyph appended to a sent bubble's timestamp label.

    Every state here is driven by a real event, never by a timer or an
    optimistic guess:

      None           no receipt data at all -- a legacy message
                     persisted before C2, or a conversation partner
                     who predates MessageRecipient rows for direct
                     messages. Renders nothing rather than claiming
                     something unknown.
      STATUS_FAILED  ClientSession.send_chat_message() raised, so the
                     ciphertext never reached the server. Set by
                     ChatWindow.send_message()'s except branch.
      False          the send call returned -- the server accepted the
                     message over TLS. "Sent", and nothing stronger.
      True           every recipient's MessageRecipient row is READ.
                     Set by a read_receipt_notification packet, or
                     read back from history.

    There is deliberately no DELIVERED (grey ✓✓) state. The server
    does record it -- _record_direct_recipient() promotes QUEUED ->
    DELIVERED on live relay -- but it never tells the SENDER: the
    relay path sends the sender no packet at all, and the history
    packet's read_status flattens QUEUED and DELIVERED into the same
    False. Rendering ✓✓ without that signal would be exactly the
    fabricated state this must not invent.

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

    if read_status:
        return (
            f'  <span style="color: {COLOR_READ_RECEIPT}; '
            'font-weight: 700;">✓✓</span>'
        )

    return "  ✓"


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

    if kind == "sent" and read_status == STATUS_FAILED:
        bubble.setStyleSheet(
            f"#Bubble {{ background-color: {COLOR_BUBBLE_FAILED}; "
            f"border: 1px solid {COLOR_SEND_FAILED}; "
            "border-radius: 14px; }"
        )
        return

    background = COLOR_BUBBLE_SENT if kind == "sent" else COLOR_BUBBLE_RECEIVED

    bubble.setStyleSheet(
        f"#Bubble {{ background-color: {background}; "
        "border-radius: 14px; }"
    )


class MessageBubble(QWidget):
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
    ):
        super().__init__()

        self.kind = kind

        # Retained so a failed send can be retried without the
        # user retyping it (Task 2). It is the same plaintext
        # already held in this widget's label -- nothing new is
        # kept in memory, and nothing is written to disk.
        self.message_text = text

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(14, 8, 14, 8)
        bubble_layout.setSpacing(2)

        bubble.setMaximumWidth(480)
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
                    "color: #9EB4FF;"
                )
                bubble_layout.addWidget(name_label)

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
                "color: white; font-size: 10.5pt; "
                "background: transparent;"
            )

            bubble_layout.addWidget(text_label)

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
                "color: rgba(255, 255, 255, 0.55); "
                "font-size: 8pt; background: transparent;"
            )
            self.time_label.setAlignment(
                Qt.AlignRight if kind == "sent" else Qt.AlignLeft
            )

            bubble_layout.addWidget(self.time_label)

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

        self._read_status = read_status

        self.time_label.setText(
            _time_label_html(self._timestamp_text, read_status)
        )

        _apply_bubble_style(self._bubble, self.kind, read_status)

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

        if self.retry_button is not None:
            self.retry_button.hide()
            self.retry_button.deleteLater()
            self.retry_button = None


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


class ImageMessageBubble(QWidget):
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
    ):
        super().__init__()

        self.kind = kind

        # BUG 5 -- the decrypted bytes are RETAINED, not discarded once
        # a thumbnail has been built from them. Without them there was
        # nothing to open at full size and nothing to save, which is
        # exactly why a received image could not be viewed. Held in
        # memory only: like FileMessageBubble, nothing is written to
        # disk until the user explicitly saves.
        self.image_bytes = image_bytes
        self.content_metadata = content_metadata or {}

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
                "font-size: 9pt; font-weight: 600; color: #9EB4FF;"
            )
            bubble_layout.addWidget(name_label)

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
            self.image_label.setStyleSheet("color: white;")

        bubble_layout.addWidget(self.image_label)

        # Actions, offered only when there is really an image to act
        # on. An attachment whose key this client never received
        # renders the placeholder above and must not offer to open or
        # save bytes it does not have.
        if self._full_pixmap is not None:

            actions = QHBoxLayout()
            actions.setContentsMargins(0, 0, 0, 0)
            actions.setSpacing(6)

            view_button = QPushButton("View")
            view_button.setObjectName("SecondaryButton")
            view_button.setCursor(Qt.PointingHandCursor)
            view_button.clicked.connect(self.open_viewer)
            actions.addWidget(view_button)

            save_button = QPushButton("Save As...")
            save_button.setObjectName("SecondaryButton")
            save_button.setCursor(Qt.PointingHandCursor)
            save_button.clicked.connect(self._handle_save_as)
            actions.addWidget(save_button)

            actions.addStretch()

            bubble_layout.addLayout(actions)

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
            "color: rgba(255, 255, 255, 0.55); "
            "font-size: 8pt; background: transparent;"
        )
        self.time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(self.time_label)

        self._bubble = bubble
        self._read_status = read_status

        _apply_bubble_style(bubble, kind, read_status)

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

        self._read_status = read_status

        self.time_label.setText(
            _time_label_html(self._timestamp_text, read_status)
        )

        _apply_bubble_style(self._bubble, self.kind, read_status)


class FileMessageBubble(QWidget):
    """
    A single file chat bubble -- filename, human-readable size, and a
    "Save As..." button that writes the already-decrypted bytes held
    in memory (Phase 8 -- File & Image Transfer). No plaintext is ever
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
    ):
        super().__init__()

        self.kind = kind
        self._file_bytes = file_bytes
        self._filename = _safe_filename(
            (content_metadata or {}).get("filename"), "file"
        )

        outer = QHBoxLayout(self)
        outer.setContentsMargins(4, 2, 4, 2)

        bubble = QWidget()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(14, 10, 14, 10)
        bubble_layout.setSpacing(4)

        bubble.setMaximumWidth(480)
        bubble.setSizePolicy(
            QSizePolicy.Maximum,
            QSizePolicy.Minimum,
        )

        if sender and kind == "received":

            sender_label = QLabel(sender)
            # L-1: see MessageBubble's identical guard.
            sender_label.setTextFormat(Qt.PlainText)
            sender_label.setStyleSheet(
                "font-size: 9pt; font-weight: 600; color: #9EB4FF;"
            )
            bubble_layout.addWidget(sender_label)

        name_label = QLabel(f"\U0001F4C4 {self._filename}")
        # L-1: the filename arrives inside content_metadata from
        # the sender. Sanitised at ingress too (see _safe_filename()),
        # but rendered as data regardless.
        name_label.setTextFormat(Qt.PlainText)
        name_label.setWordWrap(True)
        name_label.setStyleSheet(
            "color: white; font-size: 10.5pt; background: transparent;"
        )
        bubble_layout.addWidget(name_label)

        size_bytes = (content_metadata or {}).get("size_bytes", len(file_bytes))
        size_label = QLabel(_format_file_size(size_bytes))
        size_label.setTextFormat(Qt.PlainText)
        size_label.setStyleSheet(
            "color: rgba(255, 255, 255, 0.6); "
            "font-size: 8.5pt; background: transparent;"
        )
        bubble_layout.addWidget(size_label)

        save_button = QPushButton("Save As...")
        save_button.setObjectName("SecondaryButton")
        save_button.setCursor(Qt.PointingHandCursor)
        save_button.clicked.connect(self._handle_save_as)
        bubble_layout.addWidget(save_button)

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
            "color: rgba(255, 255, 255, 0.55); "
            "font-size: 8pt; background: transparent;"
        )
        self.time_label.setAlignment(
            Qt.AlignRight if kind == "sent" else Qt.AlignLeft
        )
        bubble_layout.addWidget(self.time_label)

        self._bubble = bubble
        self._read_status = read_status

        _apply_bubble_style(bubble, kind, read_status)

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

        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save File",
            self._filename
        )

        if path:
            Path(path).write_bytes(self._file_bytes)

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

        self._read_status = read_status

        self.time_label.setText(
            _time_label_html(self._timestamp_text, read_status)
        )

        _apply_bubble_style(self._bubble, self.kind, read_status)


class MessageWidget(QListWidget):
    """
    Displays chat messages as bubbles.
    """

    def __init__(self):
        super().__init__()

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

        # Source of the synthetic keys above. A plain counter, never
        # persisted and never sent anywhere -- it exists only to keep
        # two live bubbles in the same conversation distinct.
        self._live_bubble_sequence = 0

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
            "QListWidget { border: none; background: transparent; }"
        )

        self.setSpacing(2)

    # ==========================================================
    # Internal Helpers
    # ==========================================================

    def _add_bubble(self, bubble, message_id=None):

        item = QListWidgetItem()

        item.setFlags(Qt.NoItemFlags)

        item.setSizeHint(
            bubble.sizeHint()
        )

        self.addItem(item)

        self.setItemWidget(item, bubble)

        self.scrollToBottom()

        # C2 -- Read Receipts: every SENT bubble is registered, with or
        # without a database id (BUG 2 -- see __init__'s note on this
        # registry for why the id cannot be a precondition). A received
        # bubble is still never registered: it never shows a receipt
        # indicator (set_read_status() is a no-op for it regardless),
        # so tracking it would only waste memory.
        if bubble.kind == "sent":

            if message_id is None:
                self._live_bubble_sequence += 1
                message_id = f"live-{self._live_bubble_sequence}"

            self._sent_bubbles_by_message_id[message_id] = bubble

    # ==========================================================
    # Public Methods
    # ==========================================================

    def add_system_message(self, message):
        """
        Display a system message.
        """

        self._add_bubble(
            MessageBubble(message, kind="system")
        )

    def add_received_message(
        self,
        sender,
        message,
        timestamp=None,
    ):
        """
        Display a received message.
        """

        self._add_bubble(
            MessageBubble(
                message, kind="received", sender=sender, timestamp=timestamp
            )
        )

    def add_sent_message(
        self,
        message,
        timestamp=None,
        message_id=None,
        read_status=None,
        on_retry=None,
    ):
        """
        Display a sent message. ``message_id``/``read_status`` (C2 --
        Read Receipts) are optional -- omitted for a message sent live
        this session (no database id yet); supplied by
        gui/chat_window.py::load_history() for a history-loaded row,
        which always has both.
        """

        self._add_bubble(
            MessageBubble(
                message,
                kind="sent",
                timestamp=timestamp,
                read_status=read_status,
                on_retry=on_retry,
            ),
            message_id=message_id,
        )

    def add_received_image(
        self, sender, image_bytes, timestamp=None, content_metadata=None
    ):
        """
        Display a received image (Phase 8 -- File & Image Transfer).

        ``content_metadata`` (BUG 5) carries the sender's original
        filename and MIME type through to the bubble, so "Save As..."
        can offer the real name instead of inventing one. Optional, so
        every existing caller keeps working unchanged.
        """

        self._add_bubble(
            ImageMessageBubble(
                image_bytes,
                kind="received",
                sender=sender,
                timestamp=timestamp,
                content_metadata=content_metadata,
            )
        )

    def add_sent_image(
        self,
        image_bytes,
        timestamp=None,
        message_id=None,
        read_status=None,
        content_metadata=None,
    ):
        """
        Display a sent image (Phase 8 -- File & Image Transfer). See
        add_sent_message() for ``message_id``/``read_status`` (C2 --
        Read Receipts) and add_received_image() for
        ``content_metadata`` (BUG 5).
        """

        self._add_bubble(
            ImageMessageBubble(
                image_bytes,
                kind="sent",
                timestamp=timestamp,
                read_status=read_status,
                content_metadata=content_metadata,
            ),
            message_id=message_id,
        )

    def add_received_file(self, sender, file_bytes, content_metadata, timestamp=None):
        """
        Display a received file (Phase 8 -- File & Image Transfer).
        """

        self._add_bubble(
            FileMessageBubble(
                file_bytes,
                content_metadata,
                kind="received",
                sender=sender,
                timestamp=timestamp,
            )
        )

    def add_sent_file(
        self, file_bytes, content_metadata, timestamp=None, message_id=None, read_status=None
    ):
        """
        Display a sent file (Phase 8 -- File & Image Transfer). See
        add_sent_message() for ``message_id``/``read_status`` (C2 --
        Read Receipts).
        """

        self._add_bubble(
            FileMessageBubble(
                file_bytes,
                content_metadata,
                kind="sent",
                timestamp=timestamp,
                read_status=read_status,
            ),
            message_id=message_id,
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

    def clear_messages(self):
        """
        Remove every message.
        """

        self.clear()

        self._sent_bubbles_by_message_id = {}

        self._live_bubble_sequence = 0