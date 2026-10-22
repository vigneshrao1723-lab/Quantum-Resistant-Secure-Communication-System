"""
Pieces shared by every message bubble: the quoted message a reply points at, the reaction pills,
the flat Save/View actions, and the voice/video player card.

Media always plays from the already-decrypted bytes held in memory (QBuffer); nothing here writes
plaintext to disk. Saving stays an explicit user action handled by the bubble.
"""

import mimetypes
import weakref

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer, QVideoSink
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSlider,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from gui.icons import toolbar_icon
from gui.styles import (
    COLOR_ACCENT_TEXT,
    COLOR_BUBBLE_RECEIVED,
    COLOR_QUOTE_BG,
    COLOR_QUOTE_BORDER,
    COLOR_TEXT,
    COLOR_TEXT_SECONDARY,
)


def _is_light_hex(color):
    """True for a light "#RRGGBB" colour (used to pick a glyph colour that contrasts with it)."""

    try:
        red, green, blue = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    except (ValueError, IndexError, TypeError):
        return False
    return (0.299 * red + 0.587 * green + 0.114 * blue) / 255 > 0.6

REPLY_EXCERPT_LIMIT = 80

MEDIA_REPLY_LABELS = {
    "image": "\U0001F4F7 Photo",
    "voice": "\U0001F3A4 Voice message",
    "video": "\U0001F3AC Video message",
}


def format_clock(seconds):
    """0:07, 1:15 ... for a media position or duration (None/0 -> "0:00")."""

    seconds = int(round(seconds or 0))
    return f"{seconds // 60}:{seconds % 60:02d}"


def _excerpt(text):
    text = " ".join((text or "").split())
    return text if len(text) <= REPLY_EXCERPT_LIMIT else text[: REPLY_EXCERPT_LIMIT - 3] + "…"


class ReplyQuote(QFrame):
    """
    The quoted message above a reply: who wrote the original and a short excerpt (or a media
    label). When the original is on screen, clicking it -- or Enter/Space when focused -- asks
    the transcript to scroll to it. Hidden until set.
    """

    activated = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ReplyQuote")
        self.setVisible(False)
        self._clickable = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(0)

        self.author_label = QLabel("")
        self.author_label.setTextFormat(Qt.PlainText)
        self.text_label = QLabel("")
        self.text_label.setTextFormat(Qt.PlainText)
        self.text_label.setWordWrap(True)
        layout.addWidget(self.author_label)
        layout.addWidget(self.text_label)

        self.set_colors(COLOR_ACCENT_TEXT, COLOR_TEXT_SECONDARY, "rgba(118, 92, 242, .10)")

    @property
    def text(self):
        return self.text_label.text()

    def set_colors(self, accent, text, background):
        self._colors = (accent, text, background)
        self.setStyleSheet(
            f"#ReplyQuote {{ background: {background}; border-left: 3px solid {accent}; "
            "border-radius: 6px; }"
            f"#ReplyQuote:focus {{ border: 1px solid {accent}; border-left: 3px solid {accent}; }}"
        )
        self.author_label.setStyleSheet(
            f"color: {accent}; font-size: 8.5pt; font-weight: 600; background: transparent;"
        )
        self.text_label.setStyleSheet(
            f"color: {text}; font-size: 9pt; background: transparent;"
        )

    def set_quote(self, author, excerpt, clickable=False, unavailable=False):
        self.author_label.setText(author or "Reply")
        self.text_label.setText(_excerpt(excerpt))
        font = self.text_label.font()
        font.setItalic(bool(unavailable))
        self.text_label.setFont(font)
        self._clickable = bool(clickable)
        self.setCursor(Qt.PointingHandCursor if clickable else Qt.ArrowCursor)
        self.setFocusPolicy(Qt.StrongFocus if clickable else Qt.NoFocus)
        self.setToolTip("Show the original message" if clickable else "")
        self.setAccessibleName(f"Reply to {author or 'a message'}: {_excerpt(excerpt)}")
        self.setVisible(True)

    def clear(self):
        self.author_label.setText("")
        self.text_label.setText("")
        self._clickable = False
        self.setVisible(False)

    def mousePressEvent(self, event):
        if self._clickable and event.button() == Qt.LeftButton:
            self.activated.emit()
            event.accept()
            return
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        if self._clickable and event.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
            self.activated.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class ReactionStrip(QWidget):
    """One pill per distinct emoji with its count ("👍 2"), the same summary the Website shows.
    Names of who reacted are in the tooltip. Hidden while there are none."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ReactionStrip")
        self.setStyleSheet("#ReactionStrip { background: transparent; }")
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 2, 0, 0)
        self._layout.setSpacing(4)
        self._layout.addStretch()
        self._colors = (COLOR_TEXT, COLOR_QUOTE_BG, COLOR_QUOTE_BORDER)
        self.pills = []
        self.setVisible(False)

    @property
    def text(self):
        return "  ".join(pill.text() for pill in self.pills)

    def set_colors(self, text, background, border):
        self._colors = (text, background, border)
        for pill in self.pills:
            self._style_pill(pill)

    def _style_pill(self, pill):
        text, background, border = self._colors
        pill.setStyleSheet(
            f"color: {text}; background: {background}; border: 1px solid {border}; "
            "border-radius: 10px; padding: 1px 8px; font-size: 9.5pt;"
        )

    def set_reactions(self, reactions, own_username=None, name_for=None):
        for pill in self.pills:
            self._layout.removeWidget(pill)
            pill.deleteLater()
        self.pills = []

        groups = {}
        for entry in reactions or []:
            emoji = entry.get("reaction")
            user = entry.get("user")
            # One person counts once per emoji, however many times the same reaction is replayed.
            if emoji and user not in groups.setdefault(emoji, []):
                groups[emoji].append(user)

        for emoji, users in groups.items():
            pill = QLabel(f"{emoji} {len(users)}")
            pill.setTextFormat(Qt.PlainText)
            names = [
                "You" if user and user == own_username else ((name_for or str)(user) if user else "")
                for user in users
            ]
            pill.setToolTip(", ".join(name for name in names if name))
            pill.setAccessibleName(
                f"{emoji} {len(users)} {'reaction' if len(users) == 1 else 'reactions'}"
            )
            self._style_pill(pill)
            self._layout.insertWidget(self._layout.count() - 1, pill)
            self.pills.append(pill)

        self.setVisible(bool(self.pills))


def media_action_button(text, icon_name, color, accessible_name=None):
    """A flat text button (with an icon) drawn in the bubble's own content colour, so it is
    legible on both the violet sent bubble and the white received one."""

    button = QPushButton(text)
    button.setObjectName("MediaActionButton")
    button.setCursor(Qt.PointingHandCursor)
    button.setFlat(True)
    if icon_name:
        button.setIcon(toolbar_icon(icon_name, color=color, active_color=color))
        button.setIconSize(QSize(16, 16))
    button.setAccessibleName(accessible_name or text)
    button.setStyleSheet(
        f"QPushButton#MediaActionButton {{ background: transparent; border: none; color: {color}; "
        "font-size: 9pt; font-weight: 600; padding: 2px 4px; }"
        "QPushButton#MediaActionButton:hover { text-decoration: underline; }"
        f"QPushButton#MediaActionButton:focus {{ border: 1px solid {color}; border-radius: 6px; }}"
    )
    return button


class _VideoScreen(QLabel):
    """Where an inline video draws its frames; a click plays or pauses."""

    clicked = Signal()

    def __init__(self, width, height):
        super().__init__()
        self.setTextFormat(Qt.PlainText)
        self.setFixedSize(width, height)
        self.setAlignment(Qt.AlignCenter)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet("background: #12101F; border-radius: 10px; color: #FFFFFF; font-size: 22pt;")
        self.setText("▶")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
            event.accept()
            return
        super().mousePressEvent(event)


class MediaPlayerCard(QWidget):
    """
    A voice or video message player: play/pause, a seekable progress bar and the time
    ("0:03 / 0:12"); a video also shows its frames inline. One card plays at a time. Media that
    cannot be decoded (corrupt, or a format this machine cannot play) is reported in the card and
    the play control is disabled -- nothing raises.
    """

    VIDEO_SIZE = (288, 162)

    _playing = None  # weakref to the card currently playing

    def __init__(self, media_bytes, mime_type, is_video, text_color, meta_color, accent_color,
                 duration_seconds=None, parent=None):
        super().__init__(parent)
        self.setObjectName("MediaPlayerCard")
        self.setStyleSheet("#MediaPlayerCard { background: transparent; }")
        self._media_bytes = media_bytes
        self._mime_type = mime_type or ""
        self.is_video = bool(is_video)
        self._colors = (text_color, meta_color, accent_color)
        self._duration_ms = int((duration_seconds or 0) * 1000)
        self._player = None
        self._audio_output = None
        self._buffer = None
        self._sink = None
        self._probed = False
        self.failed = False
        self._dragging = False
        self._what = "video message" if self.is_video else "voice message"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.screen = None
        if self.is_video:
            self.screen = _VideoScreen(*self.VIDEO_SIZE)
            self.screen.clicked.connect(self.toggle)
            layout.addWidget(self.screen)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(8)

        self.play_button = QToolButton()
        self.play_button.setObjectName("MediaPlayButton")
        self.play_button.setCursor(Qt.PointingHandCursor)
        self.play_button.setFixedSize(34, 34)
        self.play_button.setIconSize(QSize(16, 16))
        self.play_button.clicked.connect(self.toggle)
        controls.addWidget(self.play_button)

        # Same order as the Website's player: play, time, progress, volume.
        self.time_label = QLabel(format_clock(self._duration_ms / 1000) if self._duration_ms else "")
        self.time_label.setTextFormat(Qt.PlainText)
        self.time_label.setMinimumWidth(34)
        controls.addWidget(self.time_label)

        self.slider = QSlider(Qt.Horizontal)
        self.slider.setObjectName("MediaProgress")
        self.slider.setRange(0, max(self._duration_ms, 0))
        self.slider.setEnabled(False)
        self.slider.setMinimumWidth(120)
        self.slider.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.slider.setAccessibleName("Playback position")
        self.slider.sliderPressed.connect(self._on_slider_pressed)
        self.slider.sliderReleased.connect(self._on_slider_released)
        controls.addWidget(self.slider, 1)

        # Volume: a mute button and a short level slider, applied to this player's own output.
        self._volume = 1.0
        self._muted = False
        self.volume_button = QToolButton()
        self.volume_button.setObjectName("MediaVolumeButton")
        self.volume_button.setCursor(Qt.PointingHandCursor)
        self.volume_button.setFixedSize(26, 26)
        self.volume_button.setIconSize(QSize(16, 16))
        self.volume_button.clicked.connect(self.toggle_mute)
        controls.addWidget(self.volume_button)

        self.volume_slider = QSlider(Qt.Horizontal)
        self.volume_slider.setObjectName("MediaVolume")
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(100)
        self.volume_slider.setFixedWidth(56)
        self.volume_slider.setAccessibleName("Volume")
        self.volume_slider.valueChanged.connect(self._on_volume_changed)
        controls.addWidget(self.volume_slider)

        layout.addLayout(controls)

        self.status_label = QLabel("")
        self.status_label.setTextFormat(Qt.PlainText)
        self.status_label.setWordWrap(True)
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)

        self.set_colors(*self._colors)
        self._show_state(playing=False)

    # ------------------------------------------------------------- appearance

    def set_colors(self, text_color, meta_color, accent_color):
        self._colors = (text_color, meta_color, accent_color)
        self.play_button.setStyleSheet(
            f"QToolButton#MediaPlayButton {{ background: {text_color}; border: none; border-radius: 17px; }}"
            f"QToolButton#MediaPlayButton:focus {{ border: 2px solid {meta_color}; }}"
            "QToolButton#MediaPlayButton:disabled { background: rgba(127, 127, 127, .35); }"
        )
        self.slider.setStyleSheet(
            f"QSlider#MediaProgress::groove:horizontal {{ height: 4px; border-radius: 2px; background: {meta_color}; }}"
            f"QSlider#MediaProgress::sub-page:horizontal {{ background: {text_color}; border-radius: 2px; }}"
            f"QSlider#MediaProgress::handle:horizontal {{ background: {text_color}; width: 12px; height: 12px; "
            "margin: -4px 0; border-radius: 6px; }"
            "QSlider#MediaProgress { background: transparent; }"
        )
        self.time_label.setStyleSheet(f"color: {meta_color}; font-size: 8.5pt; background: transparent;")
        self.volume_button.setStyleSheet(
            f"QToolButton#MediaVolumeButton {{ background: transparent; border: none; border-radius: 13px; }}"
            f"QToolButton#MediaVolumeButton:focus {{ border: 2px solid {meta_color}; }}"
        )
        self.volume_slider.setStyleSheet(
            f"QSlider#MediaVolume::groove:horizontal {{ height: 3px; border-radius: 1px; background: {meta_color}; }}"
            f"QSlider#MediaVolume::sub-page:horizontal {{ background: {text_color}; border-radius: 1px; }}"
            f"QSlider#MediaVolume::handle:horizontal {{ background: {text_color}; width: 10px; height: 10px; "
            "margin: -4px 0; border-radius: 5px; }"
            "QSlider#MediaVolume { background: transparent; }"
        )
        self._show_volume_state()
        self.status_label.setStyleSheet(f"color: {text_color}; font-size: 8.5pt; background: transparent;")
        self._show_state(self.is_playing)

    def _show_volume_state(self):
        silent = self._muted or self._volume <= 0.0
        self.volume_button.setIcon(
            toolbar_icon("volume-off" if silent else "volume", color=self._colors[0], active_color=self._colors[0])
        )
        label = "Unmute" if silent else "Mute"
        self.volume_button.setAccessibleName(label)
        self.volume_button.setToolTip(label)

    def toggle_mute(self):
        self._muted = not self._muted
        if self._muted is False and self._volume <= 0.0:
            self._volume = 0.5
            self.volume_slider.setValue(50)
        self._apply_volume()

    def _on_volume_changed(self, value):
        self._volume = value / 100.0
        if self._volume > 0.0:
            self._muted = False
        self._apply_volume()

    def _apply_volume(self):
        if self._audio_output is not None:
            self._audio_output.setMuted(self._muted)
            self._audio_output.setVolume(self._volume)
        self._show_volume_state()

    def _show_state(self, playing):
        # The glyph is drawn in the bubble's background colour on a round "ink" button.
        # (white on the purple sent bubble -> purple glyph; a light text colour on a dark received
        # bubble -> that dark colour; otherwise a white glyph on the dark button)
        text_color = self._colors[0].upper()
        if text_color == "#FFFFFF":
            glyph_color = "#6F55EE"
        elif _is_light_hex(text_color):
            glyph_color = COLOR_BUBBLE_RECEIVED
        else:
            glyph_color = "#FFFFFF"
        self.play_button.setIcon(
            toolbar_icon("pause" if playing else "play", color=glyph_color, active_color=glyph_color)
        )
        self.play_button.setAccessibleName(f"{'Pause' if playing else 'Play'} {self._what}")
        self.play_button.setToolTip(f"{'Pause' if playing else 'Play'} {self._what}")
        if self.screen is not None:
            self.screen.setVisible(True)
            if not playing and (self._player is None or self._player.position() == 0):
                self.screen.setText("▶")

    # ------------------------------------------------------------- state

    @property
    def is_playing(self):
        return bool(
            self._player is not None
            and self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState
        )

    @property
    def duration_ms(self):
        return self._duration_ms

    def showEvent(self, event):
        super().showEvent(event)
        # Learn the real duration as soon as the card is on screen (cheap: nothing plays).
        if not self._probed and not self._duration_ms:
            QTimer.singleShot(0, self._ensure_player)

    def _source_hint(self):
        ext = mimetypes.guess_extension(self._mime_type.split(";")[0].strip()) or ".bin"
        return QUrl(f"clip{ext}")

    def _ensure_player(self):
        if self._player is not None or self.failed or not self._media_bytes:
            return self._player
        self._probed = True
        player = QMediaPlayer(self)
        self._audio_output = QAudioOutput(self)
        self._audio_output.setVolume(self._volume)
        self._audio_output.setMuted(self._muted)
        player.setAudioOutput(self._audio_output)
        if self.is_video:
            self._sink = QVideoSink(self)
            self._sink.videoFrameChanged.connect(self._on_frame)
            player.setVideoOutput(self._sink)
        player.durationChanged.connect(self._on_duration)
        player.positionChanged.connect(self._on_position)
        player.playbackStateChanged.connect(lambda _state: self._show_state(self.is_playing))
        player.mediaStatusChanged.connect(self._on_status)
        player.errorOccurred.connect(self._on_error)
        # The buffer must outlive playback, so it is held on the card.
        self._buffer = QBuffer(self)
        self._buffer.setData(QByteArray(bytes(self._media_bytes)))
        self._buffer.open(QIODevice.ReadOnly)
        player.setSourceDevice(self._buffer, self._source_hint())
        self._player = player
        return player

    def toggle(self):
        player = self._ensure_player()
        if player is None or self.failed:
            return
        if self.is_playing:
            player.pause()
            return
        other = MediaPlayerCard._playing() if MediaPlayerCard._playing else None
        if other is not None and other is not self:
            other.pause()
        MediaPlayerCard._playing = weakref.ref(self)
        player.play()
        self._show_state(True)

    def pause(self):
        if self._player is not None and self.is_playing:
            self._player.pause()

    def stop(self):
        if self._player is not None:
            self._player.stop()

    def release(self):
        """Drop the decoded media (the message was deleted)."""

        self.stop()
        self._media_bytes = None
        if self._player is not None:
            self._player.setSource(QUrl())
        if self._buffer is not None:
            self._buffer.close()
        self.play_button.setEnabled(False)

    # ------------------------------------------------------------- player signals

    def _on_duration(self, duration_ms):
        if duration_ms > 0:
            self._duration_ms = duration_ms
            self.slider.setRange(0, duration_ms)
            self.slider.setEnabled(True)
            self._update_time(self._player.position() if self._player else 0)

    def _on_position(self, position_ms):
        if not self._dragging:
            self.slider.setValue(position_ms)
        self._update_time(position_ms)

    def _update_time(self, position_ms):
        total = format_clock(self._duration_ms / 1000) if self._duration_ms else ""
        if position_ms > 0 or self.is_playing:
            self.time_label.setText(f"{format_clock(position_ms / 1000)} / {total}" if total else format_clock(position_ms / 1000))
        else:
            self.time_label.setText(total)

    def _on_status(self, status):
        if status == QMediaPlayer.MediaStatus.EndOfMedia:
            self._player.setPosition(0)
            self._player.pause()
            self.slider.setValue(0)
            self._update_time(0)
            self._show_state(False)
        elif status == QMediaPlayer.MediaStatus.InvalidMedia:
            self._fail()

    def _on_error(self, error, _message=""):
        if error != QMediaPlayer.Error.NoError:
            self._fail()

    def _fail(self):
        if self.failed:
            return
        self.failed = True
        if self._player is not None:
            self._player.stop()
        self.play_button.setEnabled(False)
        self.slider.setEnabled(False)
        self.status_label.setText(f"This {self._what} can't be played on this device. You can still save it.")
        self.status_label.setVisible(True)
        self.play_button.setAccessibleName(f"{self._what.capitalize()} cannot be played")
        if self.screen is not None:
            self.screen.setText("")

    def _on_frame(self, frame):
        if self.screen is None or not frame.isValid():
            return
        image = frame.toImage()
        if image.isNull():
            return
        self.screen.setPixmap(
            QPixmap.fromImage(image).scaled(self.screen.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        )

    def _on_slider_pressed(self):
        self._dragging = True

    def _on_slider_released(self):
        self._dragging = False
        if self._player is not None:
            self._player.setPosition(self.slider.value())
