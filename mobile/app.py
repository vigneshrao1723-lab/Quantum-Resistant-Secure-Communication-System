"""
Phase 19 (final) -- Mobile Client UI (Kivy), redesigned against the
three user-supplied reference screenshots (Get Started / chat-list /
in-chat) as the visual source of truth, over the unchanged
mobile/session.py::MobileClientSession as the functional source of
truth (same terminology, same workflow, same security states as
desktop's gui/ package).

This is a visual/interaction rebuild, not a protocol or architecture
change: every session method call already present before this pass
is preserved; only how it is presented changed (styling, real image
rendering, real presence, real search-by-phone, saving a received
attachment to device storage).

Threading model (unchanged): MobileClientSession's receiver thread
calls this class's connected signal handlers SYNCHRONOUSLY on that
background thread (mobile/session.py::_Signal.emit()). Every handler
below that touches a widget is therefore wrapped in
kivy.clock.Clock.schedule_once(..., 0), Kivy's documented thread-safe
way to marshal a call onto the main thread.

Run with (desktop-mode, for development/testing):
    python -m mobile.app
"""

import io
import mimetypes
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone

from kivy.app import App
from kivy.clock import Clock
from kivy.core.audio import SoundLoader
from kivy.core.clipboard import Clipboard
from kivy.core.image import Image as CoreImage
from kivy.core.window import Window
from kivy.logger import Logger
from kivy.metrics import dp
from kivy.graphics import Color, Ellipse, Rectangle, RoundedRectangle
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.image import Image as KivyImage
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scatter import Scatter
from kivy.uix.scrollview import ScrollView
from kivy.uix.stencilview import StencilView
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from kivy.utils import platform

from domain.payload_type import PayloadType, classify_attachment
from mobile.session import MobileClientSession, PeerNotVerifiedError

# ==================================================================
# Design tokens -- reproduces the reference screenshots' design
# LANGUAGE (color roles, rounded/pill components, card-based lists,
# purple-accented active states) rather than their exact pixel
# layout, per this phase's own instruction that the real device's
# resolution differs from the reference images. Flat colors, not
# gradients: Kivy has no simple cross-platform gradient primitive,
# and a flat purple already reproduces the same visual language.
# ==================================================================
PURPLE = (0.463, 0.361, 0.949, 1)
PURPLE_DARK = (0.369, 0.267, 0.878, 1)
PURPLE_SOFT = (0.463, 0.361, 0.949, 0.12)
NAVY = (0.118, 0.106, 0.267, 1)
BG = (0.953, 0.953, 0.965, 1)
SURFACE = (1, 1, 1, 1)
TEXT_DARK = (0.114, 0.114, 0.180, 1)
TEXT_GRAY = (0.557, 0.557, 0.596, 1)
TEXT_ON_PURPLE = (1, 1, 1, 1)
ONLINE_GREEN = (0.176, 0.784, 0.643, 1)
OFFLINE_GRAY = (0.71, 0.71, 0.73, 1)
DANGER = (0.85, 0.32, 0.32, 1)
BORDER = (0.90, 0.90, 0.93, 1)
# Phase 19.24 -- Message Search: the temporary outline color a matched
# bubble's canvas is repainted to (see Bubble.__init__'s own
# self._bg_color/self._normal_bg) -- amber, distinct from every other
# bubble/status color already in this palette so a match is
# unambiguous regardless of which wallpaper preset is active behind it.
SEARCH_HIGHLIGHT = (0.98, 0.75, 0.18, 1)

_AVATAR_PALETTE = [
    (0.463, 0.361, 0.949, 1), (0.118, 0.106, 0.267, 1), (0.20, 0.60, 0.86, 1),
    (0.86, 0.47, 0.20, 1), (0.20, 0.70, 0.55, 1), (0.80, 0.30, 0.55, 1),
]

# Phase 19.24 -- Chat Wallpaper: same preset ids and approximate colors
# as gui/styles.py::WALLPAPER_PRESETS (a flat midpoint color here,
# since Kivy's plain Color+Rectangle -- unlike Qt's qlineargradient --
# has no built-in two-stop gradient without a custom shader) and web/
# client/style.css's .wallpaper-* classes -- same ids, so switching
# clients feels like the same app. Local-only (mobile/session.py's
# get/set_conversation_wallpaper()) -- never sent to or stored by the
# server.
WALLPAPER_PRESETS = {
    "lavender": ("Lavender", (0.933, 0.914, 0.996, 1)),
    "ocean": ("Ocean", (0.890, 0.949, 0.992, 1)),
    "sunset": ("Sunset", (1.0, 0.953, 0.878, 1)),
    "mint": ("Mint", (0.878, 0.961, 0.925, 1)),
    "midnight": ("Midnight", (0.165, 0.165, 0.239, 1)),
}

# Real Android voice/video recording (android.media.MediaRecorder) --
# same duration caps as gui/media_recorder_dialog.py's own
# MAX_VOICE_SECONDS/MAX_VIDEO_SECONDS, so a recording started on one
# platform is never longer than this project's other clients allow.
MAX_VOICE_SECONDS = 120
MAX_VIDEO_SECONDS = 60


def _avatar_color(seed_text):
    if not seed_text:
        return PURPLE
    return _AVATAR_PALETTE[sum(ord(c) for c in seed_text) % len(_AVATAR_PALETTE)]


def _bind_rounded_bg(widget, color_rgba, radius):
    """Draws a rounded-rect background on widget.canvas.before, kept in
    sync with widget.pos/size. ``radius`` may be a plain number or a
    zero-arg callable evaluated on every sync (e.g. a pill button's
    ``height / 2``, which only becomes known once layout has run).
    Returns the Color instruction so a caller can retint later (e.g. a
    button's pressed state).

    Used for every styled Button/BoxLayout-derived widget in this file
    (PillButton, GhostButton, RowCard, the header/sheet panels, ...).
    Deliberately NOT used for RoundedField (TextInput) -- see that
    class's own docstring: appending here corrupted its text
    rendering, and even inserting at canvas.before's front (tried and
    reverted) produced a different, still-wrong duplicated-text
    artifact bleeding onto sibling widgets. TextInput styles itself
    via background_color instead, with no custom canvas at all."""

    initial_radius = radius() if callable(radius) else radius
    with widget.canvas.before:
        color_instr = Color(*color_rgba)
        rect = RoundedRectangle(pos=widget.pos, size=widget.size, radius=[initial_radius])

    def _sync(*_):
        rect.pos = widget.pos
        rect.size = widget.size
        if callable(radius):
            rect.radius = [radius()]

    widget.bind(pos=_sync, size=_sync)
    return color_instr, rect


def friendly_error(error):
    """Maps internal exceptions to a human-readable message for the
    UI, per this phase's own explicit instruction that users must
    never see raw Python exceptions/paths/errno text. The technical
    detail is always ALSO logged (Logger.warning), never discarded --
    only kept out of the widget tree."""

    Logger.warning(f"QRSCS: {type(error).__name__}: {error}")
    if isinstance(error, PeerNotVerifiedError):
        return "You need to verify this contact's identity before sending."
    if isinstance(error, PermissionError):
        return "The app doesn't have permission to access that file."
    if isinstance(error, FileNotFoundError):
        return "That file could not be found."
    if isinstance(error, ConnectionError):
        return "Lost connection to the server. Please try again."
    text = str(error)
    if "SSLEOFError" in type(error).__name__ or "ssl" in text.lower():
        return "Connection was interrupted. Please try again."
    if "exceeds the" in text and "byte limit" in text:
        return "That file is too large to send."
    if "No session key established" in text or "No group key established" in text:
        return "Still setting up a secure channel for this conversation -- please try again in a moment."
    if "Invalid phone number or password" in text:
        return text
    if "already exists" in text.lower() or "already registered" in text.lower():
        return "That phone number or username is already registered."
    return "Something went wrong. Please try again."


def _mobile_storage_dir(app):
    """Platform-appropriate app-private directory for the encrypted
    local key store (mirrors storage/secure_key_store.py's own
    KEY_STORE_DIR default, just resolved per-platform)."""

    return os.path.join(app.user_data_dir, "keystore")


def _friendly_time(iso_or_hhmm):
    return iso_or_hhmm


def _format_last_seen(dt):
    """Phase 19.24 -- Presence/Last Seen: mirrors gui/chat_window.py::
    _refresh_presence_label()'s today/yesterday/date phrasing, so the
    same peer's offline state reads similarly on Desktop and Mobile.
    ``dt`` is naive UTC (this app's canonical wire convention) and is
    NOT converted to local time here -- unlike gui/message_widget.py::
    to_local_time(), this mobile client has no local-timezone
    conversion helper at all yet (every other timestamp in this file,
    e.g. _friendly_time(), is also rendered as received) -- so the
    "today"/"yesterday" boundary can be off by up to a day for a user
    far from UTC. Acceptable for a coarse presence hint; a real fix
    needs a mobile-wide timezone-conversion pass, not a one-label
    special case here."""

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    today = now.date()

    if dt.date() == today:
        return f"Last seen today at {dt.strftime('%H:%M')}"
    if (today - dt.date()).days == 1:
        return f"Last seen yesterday at {dt.strftime('%H:%M')}"
    return f"Last seen {dt.strftime('%d %b %Y, %H:%M')}"


class _FriendlyPopup(Popup):
    def __init__(self, title, message, **kwargs):
        super().__init__(title=title, size_hint=(0.85, 0.4), background_color=SURFACE, **kwargs)
        content = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(12))
        content.add_widget(Label(text=message, color=TEXT_DARK))
        close_btn = PillButton(text="OK", size_hint_y=None, height=dp(42))
        close_btn.bind(on_release=lambda *_: self.dismiss())
        content.add_widget(close_btn)
        self.content = content


# ==================================================================
# Reusable styled widgets
# ==================================================================

class PillButton(Button):
    """Fully-rounded, purple, primary-action button (Get Started,
    Login, Send, Create, Add...)."""

    def __init__(self, **kwargs):
        kwargs.setdefault("background_normal", "")
        kwargs.setdefault("background_down", "")
        kwargs.setdefault("background_color", (0, 0, 0, 0))
        kwargs.setdefault("color", TEXT_ON_PURPLE)
        kwargs.setdefault("bold", True)
        kwargs.setdefault("font_size", dp(15))
        super().__init__(**kwargs)
        self._color_instr, self._rect = _bind_rounded_bg(self, PURPLE, lambda: self.height / 2)
        self.bind(state=self._on_state, disabled=self._on_state)

    def _on_state(self, *_):
        if self.disabled:
            self._color_instr.rgba = (PURPLE[0], PURPLE[1], PURPLE[2], 0.45)
        else:
            self._color_instr.rgba = PURPLE_DARK if self.state == "down" else PURPLE


class GhostButton(Button):
    """Secondary action: transparent/white background, purple text --
    used for Cancel/toggle/nav-style actions."""

    def __init__(self, **kwargs):
        kwargs.setdefault("background_normal", "")
        kwargs.setdefault("background_down", "")
        kwargs.setdefault("background_color", (0, 0, 0, 0))
        kwargs.setdefault("color", PURPLE)
        kwargs.setdefault("font_size", dp(13))
        super().__init__(**kwargs)


class RoundedField(TextInput):
    """A rounded, white/light-surfaced text field matching the
    reference screenshots' input styling."""

    def __init__(self, **kwargs):
        kwargs.setdefault("multiline", False)
        # Deliberately NO custom canvas drawing anywhere on this class
        # (unlike every other styled widget in this file) and
        # background_normal/background_active are left at their Kivy
        # defaults -- two different custom-canvas approaches were each
        # tried and, on-device, each corrupted this widget's own text
        # rendering in a different way (one left it fully blank; the
        # other left duplicated, oversized ghost text bleeding across
        # sibling fields). TextInput's OWN default background image is
        # used instead, just tinted via background_color -- the corners
        # are Kivy's stock TextInput shape rather than this project's
        # own rounded-rectangle style, a deliberate, smaller visual
        # trade-off for guaranteed-correct text rendering.
        kwargs.setdefault("background_color", SURFACE)
        kwargs.setdefault("foreground_color", TEXT_DARK)
        kwargs.setdefault("hint_text_color", TEXT_GRAY)
        kwargs.setdefault("cursor_color", PURPLE)
        kwargs.setdefault("padding", (dp(14), dp(12), dp(14), dp(12)))
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(46))
        kwargs.setdefault("font_size", dp(14))
        super().__init__(**kwargs)


class CircleAvatar(FloatLayout):
    """A circular avatar: solid color + initial letter (no real photo
    asset is available for a generated identity), with an optional
    online/offline status dot -- the same visual role the reference
    screenshots' photo avatars + status dot play."""

    def __init__(self, label_text, *, diameter=44, online=None, **kwargs):
        super().__init__(size_hint=(None, None), size=(dp(diameter), dp(diameter)), **kwargs)
        with self.canvas.before:
            Color(*_avatar_color(label_text))
            self._circle = Ellipse(pos=self.pos, size=self.size)
        self.bind(pos=self._sync_circle, size=self._sync_circle)
        initial = (label_text or "?").strip()[:1].upper() or "?"
        self.add_widget(Label(text=initial, bold=True, color=(1, 1, 1, 1), font_size=dp(diameter * 0.42)))

        self._dot = Widget(size_hint=(None, None), size=(dp(diameter * 0.34), dp(diameter * 0.34)),
                            pos_hint={"right": 1, "y": 0})
        self._dot_ring_color = None
        self._dot_fill_color = None
        self._dot_ring = None
        self._dot_fill = None
        self._dot.bind(pos=self._sync_dot, size=self._sync_dot)
        if online is not None:
            self.set_online(online)

    def _sync_circle(self, *_):
        self._circle.pos = self.pos
        self._circle.size = self.size

    def _sync_dot(self, *_):
        if self._dot_ring is not None:
            self._dot_ring.pos = self._dot.pos
            self._dot_ring.size = self._dot.size
            pad = self._dot.width * 0.16
            self._dot_fill.pos = (self._dot.x + pad, self._dot.y + pad)
            self._dot_fill.size = (self._dot.width - pad * 2, self._dot.height - pad * 2)

    def set_online(self, online):
        if self._dot not in self.children:
            self.add_widget(self._dot)
        if self._dot_ring is None:
            with self._dot.canvas:
                self._dot_ring_color = Color(1, 1, 1, 1)
                self._dot_ring = Ellipse(pos=self._dot.pos, size=self._dot.size)
                self._dot_fill_color = Color(*(ONLINE_GREEN if online else OFFLINE_GRAY))
                self._dot_fill = Ellipse(pos=self._dot.pos, size=self._dot.size)
            self._sync_dot()
        else:
            self._dot_fill_color.rgba = ONLINE_GREEN if online else OFFLINE_GRAY


class TappableCircleAvatar(ButtonBehavior, CircleAvatar):
    """Phase 19.14 -- profile picture viewer (item 12): CircleAvatar
    itself is a plain FloatLayout with no tap event, so rather than
    add tap-handling (and its opacity/state-color side effects) to
    every existing avatar everywhere in the app, this mixes in
    ButtonBehavior only where a tap target is actually needed."""


class RowCard(ButtonBehavior, BoxLayout):
    """A tappable, rounded white row/card -- the base shape used for
    every list row (conversations, groups, devices, search results)."""

    def __init__(self, **kwargs):
        kwargs.setdefault("orientation", "horizontal")
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(72))
        kwargs.setdefault("padding", (dp(12), dp(8)))
        kwargs.setdefault("spacing", dp(10))
        super().__init__(**kwargs)
        self._bg_color, _ = _bind_rounded_bg(self, SURFACE, lambda: dp(16))
        self.bind(state=self._on_state)

    def _on_state(self, *_):
        self._bg_color.rgba = (0.94, 0.94, 0.97, 1) if self.state == "down" else SURFACE


class SectionHeader(BoxLayout):
    """Top bar used by every top-level screen: a bold title and an
    optional right-side action button."""

    def __init__(self, title, action_text=None, on_action=None, **kwargs):
        super().__init__(orientation="horizontal", size_hint_y=None, height=dp(52),
                          padding=(dp(16), dp(4)), spacing=dp(8), **kwargs)
        self.add_widget(Label(text=title, font_size=dp(19), bold=True, color=TEXT_DARK, halign="left"))
        if action_text:
            btn = PillButton(text=action_text, size_hint=(None, None), size=(dp(108), dp(36)), font_size=dp(12))
            btn.bind(on_release=lambda *_: on_action())
            self.add_widget(btn)


# ==================================================================
# Image handling -- real decode/display/tap-to-view, aspect-ratio
# preserved, safe fallback on anything that isn't a real, supported
# image. Mirrors gui/message_widget.py's own security posture
# (format allowlist + safe "[Unable to display image]" fallback,
# never a raw crash on attacker-controlled bytes) using Kivy/SDL2's
# own image decoder (already bundled -- the sdl2_image recipe) rather
# than adding a new dependency (Pillow is not in buildozer.spec).
# ==================================================================
_MAX_IMAGE_BYTES = 25 * 1024 * 1024


def _sniff_image_ext(data):
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:2] == b"BM":
        return "bmp"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _decode_image_texture(data_bytes):
    if not data_bytes or len(data_bytes) > _MAX_IMAGE_BYTES:
        return None
    ext = _sniff_image_ext(data_bytes)
    if ext is None:
        return None
    try:
        return CoreImage(io.BytesIO(data_bytes), ext=ext).texture
    except Exception as error:  # noqa: BLE001
        Logger.warning(f"QRSCS: image decode failed: {error}")
        return None


class TappableImage(ButtonBehavior, KivyImage):
    pass


class ImageViewerPopup(Popup):
    """Full-screen-ish image viewer -- tap a thumbnail to open, tap
    Close to return. Reuses the already-decoded texture (no re-read
    of the underlying bytes, no internal file path ever shown)."""

    def __init__(self, texture, **kwargs):
        # No custom canvas drawing anywhere in this popup (unlike an
        # earlier version of this class) -- Popup's own
        # background_color is used to tint its stock background
        # instead. A real, physically-confirmed bug was found here:
        # a custom RoundedRectangle drawn on a child inside a Popup's
        # content left the Popup's own dim/background overlay
        # permanently stuck covering the whole screen after
        # dismiss() -- every widget underneath kept working
        # (confirmed by navigating and opening another chat), only
        # the visual overlay never cleared. Removing the custom
        # canvas draw and using background_color instead resolved it.
        super().__init__(
            title="", separator_height=0, size_hint=(0.96, 0.9),
            background_color=(0.05, 0.05, 0.07, 1), **kwargs,
        )
        outer = BoxLayout(orientation="vertical")
        img = KivyImage(texture=texture, allow_stretch=True, keep_ratio=True)
        outer.add_widget(img)
        close_btn = PillButton(text="Close", size_hint_y=None, height=dp(46))
        close_btn.bind(on_release=lambda *_: self.dismiss())
        bar = BoxLayout(size_hint_y=None, height=dp(58), padding=dp(8))
        bar.add_widget(close_btn)
        outer.add_widget(bar)
        self.content = outer


class ImageCropPopup(Popup):
    """
    Phase 19.22 -- Part E: a real, interactive square-crop UI for
    Android, mirroring gui/image_crop_dialog.py's Desktop counterpart
    (same reason: a picked file's raw bytes used to be uploaded
    completely unmodified, non-square and all, with each VIEWER left
    to independently auto-center-crop it purely for display -- unable
    to reproduce what the user actually meant to keep in frame, and
    liable to disagree between call sites).

    Reuses Kivy's own Scatter widget for pan/pinch-zoom (do_rotation
    disabled) instead of hand-rolled touch handling -- Scatter already
    does exactly this natively. Its fixed-size StencilView parent
    clips rendering to a real square via the GL stencil buffer, so
    whatever is visible there IS the crop; Save exports exactly that
    region (StencilView.export_to_png(), at a higher fixed scale than
    the on-screen viewport) and hands the PNG bytes to ``on_done``.
    Cancel calls ``on_done(None)``.
    """

    _VIEWPORT_DP = 280
    _EXPORT_SCALE = 2

    def __init__(self, texture, on_done, **kwargs):
        super().__init__(
            title="Crop Profile Picture", separator_height=0, size_hint=(0.94, 0.82),
            background_color=SURFACE, **kwargs,
        )
        self.on_done = on_done

        outer = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))

        hint = Label(
            text="Drag to reposition. Pinch to zoom.", color=TEXT_GRAY,
            font_size=dp(11), size_hint_y=None, height=dp(20),
        )
        outer.add_widget(hint)

        viewport_wrap = AnchorLayout(size_hint_y=None, height=dp(self._VIEWPORT_DP))
        self.stencil = StencilView(
            size_hint=(None, None), size=(dp(self._VIEWPORT_DP), dp(self._VIEWPORT_DP)),
        )
        with self.stencil.canvas.before:
            Color(*PURPLE_SOFT)
            self._stencil_bg = RoundedRectangle(pos=self.stencil.pos, size=self.stencil.size)
        self.stencil.bind(pos=self._sync_stencil_bg, size=self._sync_stencil_bg)

        img_w, img_h = texture.size
        fit_scale = dp(self._VIEWPORT_DP) / min(img_w, img_h)

        self.scatter = Scatter(
            size_hint=(None, None), size=(img_w, img_h),
            do_rotation=False, do_translation=True, do_scale=True,
            scale=fit_scale, scale_min=fit_scale, scale_max=fit_scale * 4,
        )
        image_widget = KivyImage(texture=texture, size=(img_w, img_h), size_hint=(None, None))
        self.scatter.add_widget(image_widget)
        self.stencil.add_widget(self.scatter)
        viewport_wrap.add_widget(self.stencil)
        outer.add_widget(viewport_wrap)

        # Scatter transforms around whatever point the user touches
        # (natural pinch-to-zoom) once interaction starts; this one
        # deferred call only establishes the INITIAL centered-and-
        # fitted starting state, once real widget geometry exists
        # after the first layout pass.
        Clock.schedule_once(self._center_scatter, 0)

        button_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        cancel_btn.bind(on_release=lambda *_: self._finish(None))
        save_btn = PillButton(text="Save")
        save_btn.bind(on_release=lambda *_: self._handle_save())
        button_row.add_widget(cancel_btn)
        button_row.add_widget(save_btn)
        outer.add_widget(button_row)

        self.content = outer

    def _sync_stencil_bg(self, *_):
        self._stencil_bg.pos = self.stencil.pos
        self._stencil_bg.size = self.stencil.size

    def _center_scatter(self, *_):
        self.scatter.center = self.stencil.center

    def _handle_save(self):
        export_path = os.path.join(tempfile.gettempdir(), f"qrscs_crop_{id(self)}.png")

        self.stencil.export_to_png(export_path, scale=self._EXPORT_SCALE)

        def _read_and_finish(dt):
            try:
                with open(export_path, "rb") as file:
                    png_bytes = file.read()
            except OSError as error:  # noqa: BLE001
                Logger.warning(f"QRSCS: crop export read failed: {error}")
                png_bytes = None
            finally:
                try:
                    os.remove(export_path)
                except OSError:
                    pass
            self._finish(png_bytes)

        # export_to_png() renders on the NEXT frame, not synchronously
        # -- one scheduled frame of slack before reading the file back.
        Clock.schedule_once(_read_and_finish, 0.15)

    def _finish(self, png_bytes):
        self.dismiss()
        self.on_done(png_bytes)


def _payload_type_from_mime(mime_type):
    """Phase 19.24 -- Voice/Video Messages: this file's own equivalent
    of domain/payload_type.py::classify_attachment() -- mime-type
    prefix only (mirrors web/client/app.js's identical classify
    Attachment() addition), since a received attachment here already
    carries its real mime_type from content_metadata."""

    if not mime_type:
        return None
    if mime_type.startswith("audio/"):
        return "voice"
    if mime_type.startswith("video/"):
        return "video"
    return None


def _build_attachment_bubble_content(filename, data_bytes, *, kind, mime_type=None, on_save=None):
    """Builds the inner content widget for a file/image/voice/video
    attachment bubble -- a real decoded, aspect-ratio-preserved, tap-
    to-view image when the bytes are a real supported image, a real
    Play/Pause control (kivy.core.audio.SoundLoader, the confirmed-
    working audio_sdl2 backend on this build) for a voice message, a
    real Play control for a video message (native android.widget.
    VideoView/MediaController via pyjnius on a real Android build --
    this Kivy build's OWN video-decode backend is null on this dev
    machine, see this project's own memory note, so the fallback on a
    non-Android/desktop-preview build stays an honest Save-only row,
    never a fake player), otherwise a filename/size row. ``on_save``
    (received attachments only) adds a Save action that writes the
    real decrypted bytes to device storage via the Android SAF
    picker."""

    payload_type_hint = _payload_type_from_mime(mime_type)
    box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(4))
    kb = len(data_bytes) / 1024

    if payload_type_hint == "voice":
        icon_row = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        play_btn = GhostButton(
            text="▶", size_hint_x=None, width=dp(40), font_size=dp(16),
            color=PURPLE if kind != "sent" else (1, 1, 1, 1),
        )
        icon_row.add_widget(play_btn)
        icon_row.add_widget(Label(
            text="Voice message", font_size=dp(13), bold=True,
            color=(1, 1, 1, 1) if kind == "sent" else TEXT_DARK,
            halign="left", size_hint_x=1,
        ))
        box.add_widget(icon_row)
        box.height = dp(40)
        caption_color = (0.9, 0.9, 1, 1) if kind == "sent" else TEXT_GRAY

        # A real file is required -- SoundLoader/SDL2 have no in-
        # memory-buffer playback API (mirrors gui/message_widget.py's
        # own QBuffer-based in-memory approach being Qt-specific, not
        # available here) -- written once, eagerly, to this app's own
        # private temp directory, never anywhere the user chose or any
        # externally-visible storage location.
        ext = mimetypes.guess_extension(mime_type or "") or ".wav"
        fd, tmp_path = tempfile.mkstemp(prefix="qrscs_voice_", suffix=ext)
        with os.fdopen(fd, "wb") as f:
            f.write(data_bytes)

        state = {"sound": None}

        def _toggle_play(*_args, _state=state, _btn=play_btn, _path=tmp_path):
            sound = _state["sound"]
            if sound is None:
                sound = SoundLoader.load(_path)
                if sound is None:
                    _btn.text = "⚠"
                    return
                _state["sound"] = sound
                sound.bind(on_stop=lambda *_a: setattr(_btn, "text", "▶"))
            if sound.state == "play":
                sound.stop()
                _btn.text = "▶"
            else:
                sound.play()
                _btn.text = "⏸"

        play_btn.bind(on_release=_toggle_play)
    elif payload_type_hint == "video":
        icon_row = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        if platform == "android":
            play_btn = GhostButton(
                text="▶", size_hint_x=None, width=dp(40), font_size=dp(16),
                color=PURPLE if kind != "sent" else (1, 1, 1, 1),
            )
            play_btn.bind(on_release=lambda *_: _play_video_android(data_bytes, mime_type))
            icon_row.add_widget(play_btn)
        icon_row.add_widget(Label(
            text="\U0001F3AC Video message", font_size=dp(13), bold=True,
            color=(1, 1, 1, 1) if kind == "sent" else TEXT_DARK,
            halign="left", size_hint_x=1,
        ))
        box.add_widget(icon_row)
        box.height = dp(40)
        caption_color = (0.9, 0.9, 1, 1) if kind == "sent" else TEXT_GRAY
    else:
        texture = _decode_image_texture(data_bytes) if payload_type_hint is None else None
        return _build_image_or_file_content(box, texture, filename, kb, kind, data_bytes, mime_type, on_save)

    size_label = Label(text=f"{kb:.1f} KB", size_hint_y=None, height=dp(16),
                        font_size=dp(10), color=caption_color, halign="left")
    box.add_widget(size_label)
    box.height += dp(16) + dp(4)

    if on_save is not None:
        save_btn = GhostButton(text="Save", size_hint_y=None, height=dp(40), font_size=dp(11),
                                color=PURPLE if kind != "sent" else (1, 1, 1, 1))
        save_btn.bind(on_release=lambda *_: on_save(filename, mime_type, data_bytes))
        box.add_widget(save_btn)
        box.height += dp(40)

    return box


def _build_image_or_file_content(box, texture, filename, kb, kind, data_bytes, mime_type, on_save):
    """The pre-existing plain-image/plain-file rendering, unchanged --
    extracted verbatim from _build_attachment_bubble_content() so that
    function's own voice/video branches (above) could be added without
    touching this logic at all."""

    if texture is not None:
        max_w = min(dp(220), Window.width * 0.62)
        max_h = dp(260)
        tw, th = texture.size
        scale = min(max_w / tw, max_h / th) if tw and th else 1
        disp_w, disp_h = max(dp(60), tw * scale), max(dp(60), th * scale)
        img = TappableImage(texture=texture, size_hint=(None, None), size=(disp_w, disp_h))
        img.bind(on_release=lambda *_: ImageViewerPopup(texture).open())
        row = BoxLayout(size_hint_y=None, height=disp_h)
        row.add_widget(img)
        box.add_widget(row)
        box.height = disp_h
        caption_color = (1, 1, 1, 1) if kind == "sent" else TEXT_DARK
    else:
        icon_row = BoxLayout(size_hint_y=None, height=dp(22), spacing=dp(6))
        icon_row.add_widget(Label(
            text=f"[File] {filename}", font_size=dp(13), bold=True,
            color=(1, 1, 1, 1) if kind == "sent" else TEXT_DARK,
            halign="left", size_hint_x=1,
        ))
        box.add_widget(icon_row)
        box.height = dp(22)
        caption_color = (0.9, 0.9, 1, 1) if kind == "sent" else TEXT_GRAY

    size_label = Label(text=f"{kb:.1f} KB", size_hint_y=None, height=dp(16),
                        font_size=dp(10), color=caption_color, halign="left")
    box.add_widget(size_label)
    box.height += dp(16) + dp(4)

    if on_save is not None:
        # Phase 19.23 -- Issue 4: there is no hover state on Android to
        # begin with (this button was always visible), but dp(26) is
        # below the ~48dp touch target Android's own guidelines call
        # "adequate" -- bumped to dp(40), the one change this issue
        # actually calls for here. Nothing else about save_btn (its
        # callback, its always-visible placement) changes.
        save_btn = GhostButton(text="Save", size_hint_y=None, height=dp(40), font_size=dp(11),
                                color=PURPLE if kind != "sent" else (1, 1, 1, 1))
        save_btn.bind(on_release=lambda *_: on_save(filename, mime_type, data_bytes))
        box.add_widget(save_btn)
        box.height += dp(40)

    return box


def _play_video_android(data_bytes, mime_type):
    """Real, native video PLAYBACK for a received video message --
    android.widget.VideoView (which internally wraps MediaPlayer +
    its own SurfaceView) plus android.widget.MediaController for the
    play/pause/seek touch UI, both via pyjnius, mirroring this file's
    established _open_media_recorder_popup() pattern for adding a
    native Android View alongside Kivy's own GL surface.

    Security contract identical to the voice player above: the server
    never sees plaintext -- ``data_bytes`` here is already the fully
    decrypted, ML-DSA-verified plaintext this bubble was built from
    (same call path as the Save button), written ONCE to a private
    temp file (VideoView, like MediaPlayer, has no in-memory-buffer
    playback API) that is deleted the moment playback ends for any
    reason -- completion, error, or the user closing the player --
    never left behind as a permanent decrypted copy.

    Only reachable when platform == "android" (see the call site in
    _build_attachment_bubble_content()); a non-Android/desktop-preview
    build never calls this, consistent with this project's own "do not
    fake a capability this build cannot actually provide" rule."""

    from jnius import autoclass

    ext = mimetypes.guess_extension(mime_type or "") or ".mp4"
    fd, tmp_path = tempfile.mkstemp(prefix="qrscs_video_play_", suffix=ext)
    with os.fdopen(fd, "wb") as f:
        f.write(data_bytes)

    PythonActivity = autoclass("org.kivy.android.PythonActivity")
    VideoView = autoclass("android.widget.VideoView")
    MediaController = autoclass("android.widget.MediaController")
    LayoutParams = autoclass("android.view.ViewGroup$LayoutParams")
    Uri = autoclass("android.net.Uri")
    JFile = autoclass("java.io.File")

    activity = PythonActivity.mActivity
    video_view = VideoView(activity)
    state = {"closed": False}

    def _cleanup(*_args):
        if state["closed"]:
            return
        state["closed"] = True
        try:
            video_view.stopPlayback()
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: VideoView stopPlayback failed: {error}")

        def _remove_and_delete(_dt):
            try:
                parent = video_view.getParent()
                if parent is not None:
                    parent.removeView(video_view)
            except Exception as error:  # noqa: BLE001
                Logger.warning(f"QRSCS: failed to remove native VideoView: {error}")
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        Clock.schedule_once(_remove_and_delete, 0)

    try:
        controller = MediaController(activity)
        video_view.setMediaController(controller)
        controller.setAnchorView(video_view)
        video_view.setVideoURI(Uri.fromFile(JFile(tmp_path)))
        video_view.setOnCompletionListener(lambda *_: Clock.schedule_once(_cleanup, 0))
        video_view.setOnErrorListener(lambda *_a: (Clock.schedule_once(_cleanup, 0), True)[1])
        activity.addContentView(
            video_view, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT)
        )
        video_view.requestFocus()
        video_view.start()
    except Exception as error:  # noqa: BLE001
        Logger.warning(f"QRSCS: native video playback failed to start: {error}")
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return

    box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
    box.add_widget(Label(text="Playing…", font_size=dp(14), color=TEXT_DARK, size_hint_y=None, height=dp(30)))
    close_btn = PillButton(text="Close")
    box.add_widget(close_btn)
    popup = Popup(
        title="Video Message", content=box, size_hint=(0.7, None),
        height=dp(140), background_color=SURFACE, auto_dismiss=False,
    )
    close_btn.bind(on_release=lambda *_: (popup.dismiss(), _cleanup()))
    popup.bind(on_dismiss=_cleanup)
    popup.open()


# Phase 19.23 -- Issue 3/5: SENT/DELIVERED/READ now render as the
# same compact tick glyphs gui/message_widget.py already uses on
# Desktop (single ✓ for Sent/Queued, double ✓✓ for Delivered/Read),
# in place of the plain ASCII words this file used before (Phase
# 19.9's own documented, physically-confirmed reason: arbitrary
# Unicode glyphs were found to render as tofu boxes on the real test
# device's font at the time). This is a deliberate, narrow reversal of
# that finding for exactly ONE glyph -- U+2713 CHECK MARK, doubled --
# re-verified on-device for this phase (see the phase report); it is
# not a return to arbitrary glyph usage in general. FAILED is left
# exactly as it was, the plain word "Failed" -- this phase's own scope
# ("FAILED=existing failed indicator") never asked for a glyph there,
# and there is no previously-tested failed glyph to revert to.
_TICK_GLYPH = {"Sent": "✓", "Queued": "✓", "Delivered": "✓✓", "Read": "✓✓"}


def _tick_footer_text(status):
    return _TICK_GLYPH.get(status, status)


# ==================================================================
# Message bubbles
# ==================================================================

class Bubble(BoxLayout):
    """A single chat message bubble -- sent (right-aligned, purple) or
    received (left-aligned, white), mirroring gui/message_widget.py's
    MessageBubble in spirit: sender label (group chats only), body,
    timestamp + delivery state."""

    def __init__(self, text=None, *, sender_label=None, timestamp="", status="",
                 kind="received", attachment=None, on_context_action=None, **kwargs):
        pad, spacing = dp(10), dp(3)
        # Wrap width is fixed once at construction, from Window.width (a
        # stable reference independent of this widget's own layout) --
        # NOT re-derived reactively from self.parent.width or self.width.
        # See the historical note this project keeps on this exact
        # class: re-deriving it from a live layout dimension created an
        # unbounded relayout loop on the physical device.
        max_width = max(dp(120), Window.width * 0.78)

        super().__init__(orientation="vertical", size_hint_y=None, size_hint_x=None,
                          width=max_width, padding=pad, spacing=spacing, **kwargs)
        self.kind = kind
        self._pad_total = pad * 2
        self._spacing_unit = spacing

        # Phase 19.24 (continued) -- Message Lifecycle Events UI,
        # mirroring gui/message_widget.py::MessageBubble's identical
        # attributes exactly. message_id/client_message_id are set by
        # the caller (ChatScreen) once known -- this widget is built
        # before either id necessarily is (see ChatScreen._append_
        # bubble()'s own "_bubbles_awaiting_message_id" FIFO comment).
        self.message_id = None
        self.client_message_id = None
        self.reply_to_message_id = None
        self.is_deleted = False
        self.edit_version = 0
        self.reactions = []
        # Phase 19.24 -- Pinned Messages: mirrors is_deleted/edit_
        # version above -- server-derived state, applied via set_
        # pinned() (history load, and live message_pinned/message_
        # unpinned notifications -- see ChatScreen._on_message_pinned_
        # received()/_on_message_unpinned_received()).
        self.is_pinned = False
        self.pinned_by = None
        # Edit is TEXT-only (ClientSession.edit_message()'s own
        # docstring, unchanged on mobile) -- an attachment bubble never
        # supports it.
        self.supports_edit = attachment is None
        self.on_context_action = on_context_action
        self.message_text = text if attachment is None else None

        # Phase 19.24 (continued) -- Forward: retains the already-
        # decrypted attachment bytes/metadata on the bubble itself, the
        # same way gui/message_widget.py's ImageMessageBubble/
        # FileMessageBubble already do on Desktop, so _forward_bubble_
        # to() below can forward an image/file/voice/video bubble for
        # real instead of the previous TEXT-only restriction (this
        # class used to discard these bytes after building the inner
        # content widget above).
        if attachment is not None:
            self._attachment_filename, self._attachment_bytes, self._attachment_mime_type = attachment[0], attachment[1], attachment[2]
            hint = _payload_type_from_mime(self._attachment_mime_type)
            if hint == "voice":
                self.payload_type = PayloadType.VOICE
            elif hint == "video":
                self.payload_type = PayloadType.VIDEO
            else:
                self.payload_type = classify_attachment(self._attachment_filename or "")
        else:
            self._attachment_filename = None
            self._attachment_bytes = None
            self._attachment_mime_type = None
            self.payload_type = PayloadType.TEXT

        # Long-press gesture state (Kivy has no built-in long-press
        # event) -- armed on touch_down, cancelled on touch_up/move
        # past a small threshold, and fires the context menu only if
        # still held after _LONG_PRESS_SECONDS.
        self._press_event = None
        self._press_pos = None

        if kind == "sent":
            bg, radius = PURPLE, [dp(16), dp(16), dp(4), dp(16)]
        elif kind == "system":
            bg, radius = (0.85, 0.85, 0.90, 1), [dp(12)]
        else:
            bg, radius = SURFACE, [dp(16), dp(16), dp(16), dp(4)]

        # Phase 19.24 -- Message Search: the RESTING background color
        # (never overwritten in place), and the actual Color
        # instruction driving this bubble's canvas -- so a search
        # match can temporarily repaint _bg_color.rgba and later
        # restore it EXACTLY, the same "store the instruction, don't
        # rebuild the canvas" approach ChatScreen._apply_wallpaper()
        # already uses for the scroll background.
        self._normal_bg = bg
        with self.canvas.before:
            self._bg_color = Color(*bg)
            self._rect = RoundedRectangle(radius=radius, pos=self.pos, size=self.size)
        self.bind(pos=self._sync_rect, size=self._sync_rect)

        if sender_label:
            self.add_widget(Label(
                text=sender_label, size_hint_y=None, height=dp(16),
                font_size=dp(11), bold=True, color=PURPLE if kind != "sent" else (0.9, 0.9, 1, 1),
                halign="left", text_size=(None, None),
            ))

        # Phase 19.24 (continued) -- Reply preview: a small quoted
        # snippet above the message body, hidden (zero height) until
        # set_reply_preview() supplies one (ChatScreen resolves the
        # referenced message's own already-decrypted text locally --
        # never a second network round trip) -- always constructed, at
        # a fixed position in the layout, rather than inserted later:
        # Kivy's BoxLayout.children list is in REVERSE add-order, which
        # makes a correct later insertion error-prone; an always-
        # present-but-empty label (mirroring gui/message_widget.py::
        # MessageBubble's identical "hidden by default" reply label)
        # sidesteps that entirely.
        self._max_width = max_width

        # Phase 19.24 -- Pinned Messages: a small "Pinned by X" marker,
        # hidden by default (zero-height-until-relevant, same pattern
        # as the reply-preview label below) -- shown only once set_
        # pinned(True, ...) is called.
        self._pinned_label = Label(
            text="", size_hint_y=None, height=0, halign="left", valign="top",
            color=(0.75, 0.75, 0.85, 1) if kind == "sent" else PURPLE,
            font_size=dp(11), bold=True,
            text_size=(max_width - pad * 2, None),
        )
        self.add_widget(self._pinned_label)

        self._reply_preview_label = Label(
            text="", size_hint_y=None, height=0, halign="left", valign="top",
            color=(0.75, 0.75, 0.85, 1) if kind == "sent" else TEXT_GRAY,
            font_size=dp(11), italic=True,
            text_size=(max_width - pad * 2, None),
        )
        self.add_widget(self._reply_preview_label)

        if attachment is not None:
            filename, data_bytes, mime_type, on_save = attachment
            content = _build_attachment_bubble_content(filename, data_bytes, kind=kind, mime_type=mime_type, on_save=on_save)
            self.add_widget(content)
            self._body = None
        else:
            text_color = TEXT_ON_PURPLE if kind == "sent" else (
                (0.35, 0.35, 0.38, 1) if kind == "system" else TEXT_DARK
            )
            body = Label(
                text=text or "", size_hint_y=None, halign="left", valign="top",
                color=text_color, font_size=dp(11) if kind == "system" else dp(14),
                text_size=(max_width - pad * 2, None),
            )
            body.bind(texture_size=self._on_body_texture_size)
            self.add_widget(body)
            self._body = body

        self._timestamp = timestamp
        self._footer_label = None
        # Phase 19.23 -- Issue 5: one space, not two, between the
        # timestamp and the tick glyph/word -- mirrors gui/message_
        # widget.py's identical spacing reduction on Desktop.
        footer = f"{timestamp} {_tick_footer_text(status)}".strip()
        if footer:
            self._footer_label = Label(
                text=footer, size_hint_y=None, height=dp(14),
                font_size=dp(10),
                color=(0.9, 0.9, 1, 0.85) if kind == "sent" else (TEXT_GRAY if kind != "system" else (0.5, 0.5, 0.5, 1)),
                halign="right",
            )
            self.add_widget(self._footer_label)

        # Phase 19.24 (continued) -- Reactions: a compact "emoji×count"
        # row, hidden (zero height) until update_reactions() supplies
        # at least one -- same always-present-but-empty pattern as the
        # reply-preview label above.
        self._reactions_label = Label(
            text="", size_hint_y=None, height=0, halign="left", valign="top",
            font_size=dp(12), text_size=(max_width - pad * 2, None),
        )
        self.add_widget(self._reactions_label)

        self._resize()

    _READ_TICK_COLOR = (0.35, 0.68, 0.97, 1)  # distinct "read" accent (Phase 19.15, item 7)

    def set_status(self, status):
        """Phase 19.14 -- message status ticks (item 7): updates just
        the status indicator in the footer, keeping the original send
        timestamp.

        Phase 19.23 -- Issue 3: renders as a tick glyph (see
        _TICK_GLYPH/_tick_footer_text() above) for every state except
        Failed, which stays the plain word it always was. "Read" is
        still ALSO visually distinguished by colour, not just by tick
        count -- the same distinct footer colour this already had
        (Phase 19.15's own "coloured" requirement), now on top of the
        glyph change rather than instead of it."""

        if self._footer_label is None:
            return
        self._footer_label.text = f"{self._timestamp} {_tick_footer_text(status)}".strip()
        if status == "Read":
            self._footer_label.color = self._READ_TICK_COLOR
        elif self.kind == "sent":
            self._footer_label.color = (0.9, 0.9, 1, 0.85)

    def _on_body_texture_size(self, instance, size):
        instance.height = size[1]
        self._resize()

    def _resize(self, *_):
        # Phase 19.24 (continued): a hidden reply-preview/reactions
        # label (height=0, hasn't been given content yet) must not add
        # its own spacing gap on top of contributing zero height -- see
        # its own construction comment. Every child that predates this
        # phase always had height > 0, so this is unchanged behavior
        # for them.
        visible = [c for c in self.children if c.height > 0]
        self.height = (
            sum(c.height for c in self.children)
            + self._spacing_unit * max(0, len(visible) - 1)
            + self._pad_total
        )

    def _sync_rect(self, *_):
        self._rect.pos = self.pos
        self._rect.size = self.size

    # ------------------------------------------------------------------
    # Phase 19.24 (continued) -- Message Lifecycle Events UI.
    # ------------------------------------------------------------------

    _LONG_PRESS_SECONDS = 0.45
    _MOVE_CANCEL_THRESHOLD = dp(12)

    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos):
            self._press_pos = tuple(touch.pos)
            self._press_event = Clock.schedule_once(
                lambda dt: self._fire_long_press(touch), self._LONG_PRESS_SECONDS
            )
        return super().on_touch_down(touch)

    def on_touch_move(self, touch):
        if self._press_event is not None and self._press_pos is not None:
            dx = touch.pos[0] - self._press_pos[0]
            dy = touch.pos[1] - self._press_pos[1]
            if (dx * dx + dy * dy) ** 0.5 > self._MOVE_CANCEL_THRESHOLD:
                self._press_event.cancel()
                self._press_event = None
        return super().on_touch_move(touch)

    def on_touch_up(self, touch):
        if self._press_event is not None:
            self._press_event.cancel()
            self._press_event = None
        return super().on_touch_up(touch)

    def _fire_long_press(self, touch):
        self._press_event = None
        if not self.collide_point(*touch.pos):
            return
        _open_bubble_context_menu(self)

    def set_reply_preview(self, preview_text):
        """Show a quoted snippet of the message this one replies to --
        mirrors gui/message_widget.py::MessageBubble.set_reply_
        preview() exactly (same 80-character truncation)."""

        if self.kind == "system" or not preview_text:
            return

        shown = preview_text if len(preview_text) <= 80 else preview_text[:77] + "…"

        self._reply_preview_label.text = shown
        self._reply_preview_label.texture_update()
        self._reply_preview_label.height = max(dp(16), self._reply_preview_label.texture_size[1])
        self._resize()

    def set_pinned(self, pinned, pinned_by=None):
        """Show/hide this bubble's "📌 Pinned by X" marker -- mirrors
        gui/message_widget.py::MessageBubble.set_pinned() exactly."""

        if self.kind == "system":
            return

        self.is_pinned = bool(pinned)
        self.pinned_by = pinned_by if self.is_pinned else None

        if self.is_pinned:
            self._pinned_label.text = (
                f"\U0001F4CC Pinned by {pinned_by}" if pinned_by else "\U0001F4CC Pinned"
            )
            self._pinned_label.texture_update()
            self._pinned_label.height = max(dp(14), self._pinned_label.texture_size[1])
        else:
            self._pinned_label.text = ""
            self._pinned_label.height = 0
        self._resize()

    def update_reactions(self, reactions):
        """``reactions``: a list of already-decrypted, already-
        signature-verified {"user", "reaction"} dicts -- mirrors gui/
        message_widget.py::MessageBubble.update_reactions() exactly."""

        if self.kind == "system":
            return

        self.reactions = list(reactions or [])

        if not self.reactions:
            self._reactions_label.text = ""
            self._reactions_label.height = 0
            self._resize()
            return

        counts = {}
        for entry in self.reactions:
            emoji = entry.get("reaction", "")
            if emoji:
                counts[emoji] = counts.get(emoji, 0) + 1

        self._reactions_label.text = "  ".join(f"{emoji}×{count}" for emoji, count in counts.items())
        self._reactions_label.height = dp(18)
        self._resize()

    def apply_edit(self, new_text, edit_version):
        """Mirrors gui/message_widget.py::MessageBubble.apply_edit()
        exactly -- appends "(edited)" to the displayed text."""

        if self.kind == "system" or self._body is None:
            return

        self.message_text = new_text
        self.edit_version = edit_version
        self._body.text = f"{new_text} (edited)"

    def mark_deleted(self):
        """Mirrors gui/message_widget.py::MessageBubble.mark_deleted()
        exactly -- renders as a tombstone, for BOTH delete-for-me and
        delete-for-everyone alike (the caller, ChatScreen, decides
        which one actually happened server-side)."""

        if self.kind == "system":
            return

        self.is_deleted = True
        self.message_text = ""
        if self._body is not None:
            self._body.text = "Message deleted"
            self._body.italic = True
        self._reply_preview_label.text = ""
        self._reply_preview_label.height = 0
        self.update_reactions([])
        self.set_pinned(False)
        self._resize()


def _bubble_context_actions(bubble):
    """Mirrors gui/message_widget.py::_build_message_context_menu()'s
    exact action set and conditions, adapted to return plain (action,
    label) pairs instead of building a QMenu -- see that function's own
    docstring for the full per-case rationale (Edit/Delete-for-
    everyone are sender-only; a deleted bubble offers only Delete for
    me; a bubble with no real, non-live message_id offers nothing)."""

    if bubble.kind == "system":
        return []

    # Phase 19.24 -- Message Retry: a failed send never reached the
    # server, so it never has a real message_id (checked below) --
    # special-cased FIRST so a failed bubble is still addressable at
    # all, offering only what actually makes sense for text that never
    # left this device.
    if bubble.kind == "sent" and getattr(bubble, "_tick_status", None) == "Failed":
        return [("retry", "Retry"), ("delete_me", "Delete for me")]

    if not bubble.message_id:
        return []

    if bubble.is_deleted:
        return [("delete_me", "Delete for me")]

    actions = [("reply", "Reply"), ("copy", "Copy"), ("forward", "Forward"), ("react", "React …")]
    # Phase 19.24 -- Pinned Messages: any member may pin/unpin any
    # message, sent or received alike -- see gui/message_widget.py::
    # _build_message_context_menu()'s identical note.
    actions.append(("unpin", "Unpin") if bubble.is_pinned else ("pin", "Pin"))

    if bubble.kind == "sent":
        if bubble.supports_edit:
            actions.append(("edit", "Edit"))
        actions.append(("delete_me", "Delete for me"))
        actions.append(("delete_everyone", "Delete for everyone"))
    else:
        actions.append(("delete_me", "Delete for me"))

    return actions


def _open_bubble_context_menu(bubble):
    """Phase 19.24 (continued) -- the long-press equivalent of gui/
    message_widget.py's right-click context menu. Dispatches the
    chosen action to bubble.on_context_action(action, bubble), exactly
    like Desktop's _handle_message_context_menu_event()."""

    actions = _bubble_context_actions(bubble)

    if not actions:
        return

    box = BoxLayout(orientation="vertical", spacing=dp(4), padding=dp(8), size_hint_y=None)
    box.bind(minimum_height=box.setter("height"))
    popup = Popup(
        title="Message", content=box, size_hint=(0.82, None),
        height=dp(56) * len(actions) + dp(60), background_color=SURFACE,
    )

    for action, label in actions:
        btn = GhostButton(text=label, size_hint_y=None, height=dp(48), font_size=dp(14))

        def _choose(*_, action=action):
            popup.dismiss()
            if bubble.on_context_action is not None:
                bubble.on_context_action(action, bubble)

        btn.bind(on_release=_choose)
        box.add_widget(btn)

    popup.open()


# Phase 19.24 (continued) -- a small, touch-friendly, fixed emoji set
# (mirrors gui/chat_window.py::_handle_react_bubble()'s identical
# desktop set exactly) rather than a full emoji keyboard -- the
# server/encryption layer accepts ANY short string, this is purely a
# UI convenience.
REACTION_CHOICES = ("\U0001F44D", "❤️", "\U0001F602", "\U0001F62E", "\U0001F622", "\U0001F64F")


def _open_reaction_picker(on_choose):
    box = BoxLayout(orientation="horizontal", spacing=dp(8), padding=dp(12), size_hint_y=None, height=dp(64))
    popup = Popup(title="React", content=box, size_hint=(0.9, None), height=dp(140), background_color=SURFACE)

    for emoji in REACTION_CHOICES:
        btn = GhostButton(text=emoji, font_size=dp(22))

        def _choose(*_, emoji=emoji):
            popup.dismiss()
            on_choose(emoji)

        btn.bind(on_release=_choose)
        box.add_widget(btn)

    popup.open()


class VerifiedBadge(BoxLayout):
    """Small header badge mirroring gui/chat_window.py's
    _update_verification_status(): "Verified"/"Not verified"/
    "Identity changed" states, with a contextual action button."""

    def __init__(self, on_verify, on_request=None, **kwargs):
        super().__init__(orientation="horizontal", size_hint_y=None, height=dp(26), spacing=dp(6), **kwargs)
        self.on_verify = on_verify
        self.on_request = on_request
        self.status_label = Label(text="", font_size=dp(11), size_hint_x=0.4, halign="left", color=TEXT_GRAY)
        self.status_label.bind(size=lambda *_: setattr(self.status_label, "text_size", self.status_label.size))
        self.action_btn = GhostButton(text="", size_hint_x=0.3, font_size=dp(10))
        self.action_btn.bind(on_release=lambda *_: self.on_verify())
        # Phase 19.15 -- the direct "Verify Identity" action above uses
        # the KEY THIS CLIENT ALREADY OBSERVED, with no server round
        # trip: real, pre-existing, working, and left unchanged. It is
        # NOT the async inbox-mediated flow (request_verification() +
        # the peer's own Inbox approval, see server/client_handler.py
        # ::handle_verification_request()/respond_to_inbox()) -- that
        # backend has existed since Phase 19.13 and was automated-
        # tested, but had no UI entry point at all until now. This
        # button is that missing entry point, added alongside the
        # existing one rather than replacing it.
        self.request_btn = GhostButton(text="Request Approval", size_hint_x=0.3, font_size=dp(10))
        self.request_btn.bind(on_release=lambda *_: self.on_request and self.on_request())
        self.add_widget(self.status_label)
        self.add_widget(self.action_btn)
        self.add_widget(self.request_btn)

    def set_state(self, state):
        # Plain ASCII text only, deliberately -- a real physical-device
        # check (Phase 19.9) found the Unicode checkmark/warning glyphs
        # this badge previously used (tick/warning symbols) render as
        # tofu boxes on this device's actual font (Kivy/SDL2's font
        # fallback on Android, not a Kivy bug this project controls).
        # Color coding carries the same information; wording alone is
        # unambiguous without a glyph.
        # request_btn only makes sense while this peer is NOT already
        # verified -- asking someone to approve an identity you've
        # already verified (or haven't observed at all yet) is either
        # redundant or premature.
        show_request = state in ("unverified", "changed")
        self.request_btn.opacity = 1 if show_request else 0
        self.request_btn.disabled = not show_request

        if state == "verified":
            self.status_label.text = "[color=1cc98a]Verified[/color]"
            self.status_label.markup = True
            self.action_btn.text = "Re-verify"
            self.action_btn.opacity = 1
            self.action_btn.disabled = False
        elif state == "changed":
            self.status_label.text = "[color=e08a2b]Identity changed[/color]"
            self.status_label.markup = True
            self.action_btn.text = "Verify New Identity"
            self.action_btn.opacity = 1
            self.action_btn.disabled = False
        elif state == "unverified":
            self.status_label.text = "[color=e08a2b]Not verified[/color]"
            self.status_label.markup = True
            self.action_btn.text = "Verify Identity"
            self.action_btn.opacity = 1
            self.action_btn.disabled = False
        else:  # no identity observed yet
            self.status_label.text = "Waiting for identity..."
            self.status_label.markup = False
            self.action_btn.text = ""
            self.action_btn.opacity = 0
            self.action_btn.disabled = True


# ==================================================================
# Screens
# ==================================================================

class GetStartedScreen(BoxLayout):
    """Pre-login onboarding screen -- reference screenshot #1: a light
    hero area, a rounded white bottom sheet with a heading, subtext,
    and a large pill "Get Started" button leading into LoginScreen."""

    def __init__(self, on_get_started, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        with self.canvas.before:
            Color(*BG)
            self._bg = RoundedRectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._sync, size=self._sync)

        # AnchorLayout + an explicit-dp-sized grid, deliberately NOT a
        # FloatLayout child sized via a fractional size_hint: a real,
        # reproducible Kivy timing quirk was found here (isolated and
        # confirmed with a standalone repro) where a FloatLayout child
        # given size_hint=(0.72, 0.82) resolves that fraction against
        # the FloatLayout's size at the moment do_layout() FIRST runs
        # (which can still be Kivy's pre-window-resize placeholder
        # size) and never re-resolves it once the real window size
        # lands a moment later -- rendering this project's own avatar
        # circles as stretched ellipses. An explicit, fixed dp size has
        # nothing to re-resolve, so it cannot go stale the same way.
        hero = AnchorLayout(anchor_x="center", anchor_y="center", size_hint_y=0.52)
        grid = BoxLayout(orientation="vertical", size_hint=(None, None), size=(dp(206), dp(206)), spacing=dp(14))
        top_row = BoxLayout(spacing=dp(14))
        bottom_row = BoxLayout(spacing=dp(14))
        for row, seeds in ((top_row, ("A", "B")), (bottom_row, ("C", "D"))):
            for seed in seeds:
                row.add_widget(CircleAvatar(seed, diameter=96))
        grid.add_widget(top_row)
        grid.add_widget(bottom_row)
        hero.add_widget(grid)
        self.add_widget(hero)

        sheet = BoxLayout(orientation="vertical", size_hint_y=0.48, padding=(dp(28), dp(30)), spacing=dp(10))
        with sheet.canvas.before:
            Color(*SURFACE)
            self._sheet_rect = RoundedRectangle(pos=sheet.pos, size=sheet.size, radius=[dp(28), dp(28), 0, 0])
        sheet.bind(pos=self._sync_sheet, size=self._sync_sheet)
        self._sheet = sheet

        heading = Label(
            text="Enjoy the new experience of\nchatting with quantum-safe friends",
            font_size=dp(20), bold=True, color=TEXT_DARK, halign="center", valign="middle",
            size_hint_y=None, height=dp(80),
        )
        subtext = Label(
            text="Post-quantum end-to-end encrypted messaging, for free",
            font_size=dp(13), color=TEXT_GRAY, halign="center", size_hint_y=None, height=dp(32),
        )
        sheet.add_widget(heading)
        sheet.add_widget(subtext)

        # text_size tracks width continuously via a bind on `width`
        # specifically (never the full `size` tuple -- see below), and
        # is re-applied on EVERY change, self-correcting regardless of
        # how many intermediate/stale widths this widget's own layout
        # and the window's real dimensions pass through before
        # settling (proven necessary on-device: neither reading
        # Window.width immediately at construction, nor a one-shot
        # Clock.schedule_once() a fixed delay later, converged in time
        # on both a desktop test run AND this device -- each showed
        # a DIFFERENT wrong intermediate width, confirming there is no
        # single safe moment to freeze this value once). Binding to
        # `size` instead of `width` was this project's own earlier,
        # already-documented anti-pattern (see Bubble's docstring) for
        # a related reason; binding to `width` specifically is the
        # standard, idiomatic Kivy pattern for a label that must wrap
        # to its container's width.
        def _track_width(instance, width):
            instance.text_size = (width, instance.height)
        heading.bind(width=_track_width)
        subtext.bind(width=_track_width)

        sheet.add_widget(Widget())

        get_started_btn = PillButton(text="Get Started", size_hint_y=None, height=dp(54), font_size=dp(16))
        get_started_btn.bind(on_release=lambda *_: on_get_started())
        sheet.add_widget(get_started_btn)

        footer = Label(text="Powered by QRSCS post-quantum cryptography", font_size=dp(10),
                        color=TEXT_GRAY, size_hint_y=None, height=dp(24))
        sheet.add_widget(footer)

        self.add_widget(sheet)

    def _sync(self, *_):
        self._bg.pos = self.pos
        self._bg.size = self.size

    def _sync_sheet(self, *_):
        self._sheet_rect.pos = self._sheet.pos
        self._sheet_rect.size = self._sheet.size


class LoginScreen(BoxLayout):
    """2. Authentication -- mirrors gui/login_window.py's own
    Login/Register mode toggle: USERNAME is registration-only (the
    authenticated username always comes from the server's own
    response, never re-typed at login), PHONE NUMBER is the sole
    login identifier in both modes, and full_name/email are derived
    from the username exactly as MainWindow.handle_registration()
    does -- never asked of the user."""

    def __init__(self, on_success, storage_dir, **kwargs):
        super().__init__(orientation="vertical", spacing=dp(10), padding=dp(24), **kwargs)
        with self.canvas.before:
            Color(*BG)
            self._bg = RoundedRectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._sync, size=self._sync)

        self.on_success = on_success
        self.storage_dir = storage_dir
        self.mode = "login"

        self.add_widget(Widget(size_hint_y=None, height=dp(12)))
        # Phase 19.14 -- Login branding: the bare "QRSCS" initialism
        # alone under-identified the app; pairing it with the full
        # project name (README.md's own title) matches how a real
        # messaging app's login screen names itself. halign="left" is
        # bound to text_size the same way as every other left-aligned
        # label fixed this phase -- without that binding it is a no-op
        # and the text renders centered regardless of the flag.
        brand_title = Label(text="QRSCS", font_size=dp(30), bold=True, color=TEXT_DARK,
                             halign="left", valign="bottom", size_hint_y=None, height=dp(38))
        brand_title.bind(width=lambda inst, w: setattr(inst, "text_size", (w, inst.height)))
        self.add_widget(brand_title)
        brand_full_name = Label(text="Quantum-Resistant Secure Communication System",
                                 font_size=dp(11), bold=True, color=TEXT_GRAY,
                                 halign="left", valign="top", size_hint_y=None, height=dp(16))
        brand_full_name.bind(width=lambda inst, w: setattr(inst, "text_size", (w, inst.height)))
        self.add_widget(brand_full_name)
        subtitle = Label(
            text="End-to-end chat secured with post-quantum cryptography",
            font_size=dp(12), color=TEXT_GRAY, halign="left", valign="top", size_hint_y=None, height=dp(36),
        )
        subtitle.bind(width=lambda inst, w: setattr(inst, "text_size", (w, inst.height)))
        self.add_widget(subtitle)

        self.username_input = RoundedField(hint_text="Enter your username")
        self.phone_input = RoundedField(hint_text="+91 98765 43210")
        self.password_input = RoundedField(hint_text="Enter your password", password=True)
        self.confirm_password_input = RoundedField(hint_text="Confirm your password", password=True)

        self.field_box = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(46), spacing=dp(10))
        self.add_widget(self.field_box)

        self.submit_btn = PillButton(text="Login", size_hint_y=None, height=dp(50))
        self.submit_btn.bind(on_release=lambda *_: self._submit())
        self.add_widget(self.submit_btn)

        self.toggle_btn = GhostButton(text="Create an account", size_hint_y=None, height=dp(40))
        self.toggle_btn.bind(on_release=lambda *_: self._toggle_mode())
        self.add_widget(self.toggle_btn)

        self.status_label = Label(text="", size_hint_y=None, height=dp(50), color=TEXT_GRAY, font_size=dp(12))
        self.add_widget(self.status_label)
        self.add_widget(Widget())

        self._set_mode("login")

    def _sync(self, *_):
        self._bg.pos = self.pos
        self._bg.size = self.size

    def _set_mode(self, mode):
        self.mode = mode
        self.field_box.clear_widgets()
        if mode == "register":
            self.field_box.add_widget(self.username_input)
        self.field_box.add_widget(self.phone_input)
        self.field_box.add_widget(self.password_input)
        if mode == "register":
            self.field_box.add_widget(self.confirm_password_input)
        self.field_box.height = dp(46) * len(self.field_box.children) + dp(10) * max(0, len(self.field_box.children) - 1)
        self.submit_btn.text = "Register" if mode == "register" else "Login"
        self.toggle_btn.text = "Already have an account? Login" if mode == "register" else "Create an account"

    def _toggle_mode(self):
        self._set_mode("register" if self.mode == "login" else "login")

    def _submit(self):
        if self.mode == "register":
            self._register()
        else:
            self._login()

    def _login(self):
        phone = self.phone_input.text.strip()
        password = self.password_input.text
        self.status_label.text = "Connecting..."

        def _worker():
            # Phase 19.22 -- Part I: "the phone is taking more time to
            # login" -- measure before guessing. Each stage timed
            # independently and logged (visible via logcat), rather
            # than one end-to-end number, since the six stages below
            # span genuinely different cost categories (password
            # hashing, network/TLS, post-quantum key generation, two
            # more network round trips) and only per-stage numbers can
            # actually say WHICH one is slow on real hardware -- a
            # single total cannot distinguish "slow phone CPU doing
            # ML-DSA keygen" from "slow/high-latency network".
            stage_start = time.monotonic()

            def _mark(stage_name):
                nonlocal stage_start
                now = time.monotonic()
                Logger.info(f"QRSCS: login timing -- {stage_name}: {now - stage_start:.3f}s")
                stage_start = now

            session = MobileClientSession(storage_dir=self.storage_dir)
            try:
                result = session.authenticate_credentials(phone, password)
                _mark("authenticate_credentials (network + server-side password hash verify)")
                if not result.success:
                    message = result.message
                    Clock.schedule_once(lambda dt, message=message: setattr(self.status_label, "text", message), 0)
                    return
                session.user_id = result.user_id
                session.username = result.username
                session.access_token = result.token_pair.access_token
                session.connect()
                _mark("connect (TCP + TLS handshake)")
                session.login(result.username)
                _mark("login (protocol handshake)")
                session.send_public_key()
                _mark("send_public_key (ML-KEM + ML-DSA keygen and signing)")
                session.start_receiver()
                _mark("start_receiver (thread start)")
                # Real device identity for THIS install: auto-enroll and
                # bind on first successful login, mirroring how a real
                # app treats device registration as invisible plumbing,
                # not a user-facing button (Phase 19.9's own requirement).
                try:
                    session.enroll_device(device_name=platform.capitalize() if platform else "Mobile", platform=platform or "unknown")
                    session.bind_device_session()
                except Exception as device_error:  # noqa: BLE001
                    Logger.warning(f"QRSCS: device enrollment/bind failed: {device_error}")
                _mark("enroll_device + bind_device_session (ML-DSA signing + 2 network round trips)")
                # BUG -- Mobile Conversation Persistence: without this,
                # a fresh login's direct_conversation_ids/groups dicts
                # start empty and the chat list looks wiped, even for
                # an account with real history -- see session.
                # load_conversations()'s own docstring. Best-effort:
                # a failure here must not block login itself, same as
                # device enrollment above.
                try:
                    session._restored_conversations = session.load_conversations()
                except Exception as restore_error:  # noqa: BLE001
                    Logger.warning(f"QRSCS: conversation restore failed: {restore_error}")
                    session._restored_conversations = []
                _mark("load_conversations (network round trip)")
            except Exception as error:  # noqa: BLE001
                message = friendly_error(error)
                Clock.schedule_once(lambda dt, message=message: setattr(self.status_label, "text", message), 0)
                return

            Clock.schedule_once(lambda dt: self.on_success(session), 0)

        threading.Thread(target=_worker, daemon=True).start()

    def _register(self):
        username = self.username_input.text.strip()
        phone = self.phone_input.text.strip()
        password = self.password_input.text
        confirm = self.confirm_password_input.text
        self.status_label.text = "Creating your account..."

        def _worker():
            session = MobileClientSession(storage_dir=self.storage_dir)
            try:
                result = session.register(
                    full_name=username,
                    username=username,
                    email=f"{username}@users.invalid",
                    phone_number=phone,
                    password=password,
                    confirm_password=confirm,
                )
            except Exception as error:  # noqa: BLE001
                message = friendly_error(error)
                Clock.schedule_once(lambda dt, message=message: setattr(self.status_label, "text", message), 0)
                return

            if result.success:
                Clock.schedule_once(lambda dt: self._set_mode("login"), 0)
                Clock.schedule_once(lambda dt: setattr(self.status_label, "text", "Account created. Please log in."), 0)
            else:
                message = result.message
                Clock.schedule_once(lambda dt, message=message: setattr(self.status_label, "text", message), 0)

        threading.Thread(target=_worker, daemon=True).start()


class BottomNav(FloatLayout):
    """Floating rounded white navigation bar with a purple active
    state, plus a floating circular purple "+" action that overlaps
    its top edge -- reference screenshot #2's bottom navigation.
    Uses plain text labels (not an icon font) for the nav items: a
    real physical-device check in an earlier phase found that
    arbitrary Unicode glyphs can render as tofu on this device's
    font, and this project's own standing rule since then is to never
    introduce one without on-device proof it renders."""

    def __init__(self, items, on_select, on_fab, **kwargs):
        super().__init__(size_hint_y=None, height=dp(78), **kwargs)
        self._buttons = {}
        self.active = items[0][0]

        bar = BoxLayout(orientation="horizontal", size_hint=(1, None), height=dp(58),
                         pos_hint={"center_x": 0.5, "y": 0}, padding=(dp(10), dp(6)))
        with bar.canvas.before:
            Color(*SURFACE)
            self._bar_rect = RoundedRectangle(pos=bar.pos, size=bar.size, radius=[dp(24)])
        bar.bind(pos=self._sync_bar, size=self._sync_bar)
        self._bar = bar

        for key, label in items:
            btn = GhostButton(text=label, font_size=dp(12), bold=(key == self.active),
                               color=PURPLE if key == self.active else TEXT_GRAY)
            btn.bind(on_release=lambda *_, k=key: (self._set_active(k), on_select(k)))
            self._buttons[key] = btn
            bar.add_widget(btn)
        self.add_widget(bar)

        fab = PillButton(text="+", font_size=dp(26), size_hint=(None, None), size=(dp(56), dp(56)),
                          pos_hint={"center_x": 0.5, "top": 1.12})
        fab.bind(on_release=lambda *_: on_fab())
        self.add_widget(fab)
        self.fab = fab

    def _sync_bar(self, *_):
        self._bar_rect.pos = self._bar.pos
        self._bar_rect.size = self._bar.size

    def _set_active(self, key):
        self.active = key
        for k, btn in self._buttons.items():
            btn.color = PURPLE if k == key else TEXT_GRAY
            btn.bold = k == key


class ChatScreen(BoxLayout):
    """Top-level container: bottom-navigated Chats / Groups / Devices
    sections, each swapping between a list view and (for Chats/
    Groups) a detail/chat view -- mirrors desktop's sidebar-plus-
    detail-pane layout, adapted to a single portrait screen."""

    def __init__(self, session, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        with self.canvas.before:
            Color(*BG)
            self._bg = RoundedRectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._sync, size=self._sync)

        self.session = session

        # identity_key -> {"name", "is_group", "last_message", "time", "unread"}
        self.conversations = {}
        self.active_conversation = None  # identity_key of the open chat, or None
        self.active_is_group = False
        self._active_real_conversation_id = None  # real conversation UUID of the open chat (direct chats only differ from active_conversation)
        self._inbox_open = False  # True only while show_inbox()'s screen is the visible one
        self._bubble_rows = {}  # identity_key -> BoxLayout (message list)
        self._active_section = "chats"
        self._presence_labels = {}  # peer username -> Label, refreshed on users_updated
        # Phase 19.14 -- message status ticks (item 7): mobile/session.
        # py's _send_payload() is fire-and-forget and never learns its
        # own message's server-assigned message_id, so a delivered/
        # queued/failed packet cannot be correlated to a bubble by id.
        # Messages to one receiver are sent and acknowledged in the
        # same TCP-ordered stream, so a plain FIFO queue per receiver
        # username is a real send-order correlation, not a guess.
        self._pending_send_status = {}  # receiver_username -> [Bubble, ...] oldest-first

        # Phase 19.24 (continued) -- Message Lifecycle Events UI.
        # _bubbles_by_message_id: EVERY currently-rendered bubble that
        # has learned its real message_id, regardless of sent/
        # received -- addressable by Reply/Edit/Delete/React/Forward.
        # _bubbles_awaiting_message_id: identity_key -> [Bubble, ...]
        # FIFO, oldest-first, for a bubble already on screen that has
        # NOT yet learned its id -- resolved in strict send/receive
        # order by _on_own_message_id_resolved() (this account's own
        # live send, via message_delivered/message_queued) or _on_
        # message_id_received() (a received live message, or ANY
        # historical row, own or received alike -- see mobile/
        # session.py's message_id_received/message_lifecycle_state_
        # received declarations for the full rationale). Both reset
        # whenever open_chat() rebuilds the message list (a bubble from
        # a discarded widget tree can never be resolved into again).
        self._bubbles_by_message_id = {}
        self._bubbles_awaiting_message_id = {}
        # Set/cleared by _handle_bubble_context_action()'s "reply"/
        # "edit" cases and _clear_composer_context() -- the message_id
        # this screen's NEXT send should attach reply_to_message_id
        # for, or the message being edited instead of sent fresh.
        self._pending_reply_message_id = None
        self._editing_message_id = None
        self._editing_expected_version = 0
        self._composer_context_label = None  # set per open_chat() -- see its own composer section
        self._active_message_input = None  # the currently-open chat's composer TextInput, or None

        # Phase 19.24 -- Drafts: identity_key -> unsent composer text.
        # In-memory only, this screen's lifetime -- never persisted or
        # sent anywhere. Mirrors gui/chat_window.py's identical
        # self._drafts exactly, including the same "not while a reply/
        # edit is in progress" exclusion.
        self._drafts = {}

        # Phase 19.24 -- Archive: one flag shared by show_chats_list()/
        # show_groups_list() -- flipped only by each screen's own
        # Archived toggle button, mirrors gui/chat_window.py's
        # self._show_archived exactly.
        self._show_archived = False

        self.content_area = BoxLayout(orientation="vertical")
        self.add_widget(self.content_area)

        self.nav_bar = BottomNav(
            items=[("chats", "Chats"), ("groups", "Groups"), ("devices", "Devices"), ("settings", "Settings")],
            on_select=self._on_nav_select, on_fab=self._on_fab,
        )
        self.add_widget(self.nav_bar)

        self.session.message_received.connect(self._on_message_received)
        self.session.payload_message_received.connect(self._on_payload_received)
        self.session.security_rejection.connect(self._on_security_rejection)
        self.session.read_receipt_updated.connect(self._on_read_receipt)
        self.session.group_created.connect(self._on_group_created)
        self.session.users_updated.connect(self._on_users_updated)
        self.session.message_status_updated.connect(self._on_message_status_updated)
        # Phase 19.17C -- was never connected at all (the one signal
        # session.py already emits, for both a brand-new pushed
        # notification and the resolution of one of THIS user's own
        # earlier requests, that this file never listened for): the
        # Inbox screen only ever refreshed on a manual pull (opening
        # it, or its own "Refresh" header action), never live.
        self.session.inbox_updated.connect(self._on_inbox_updated)

        # Phase 19.24 (continued) -- Message Lifecycle Events UI.
        self.session.own_message_id_resolved.connect(self._on_own_message_id_resolved)
        self.session.message_id_received.connect(self._on_message_id_received)
        self.session.message_lifecycle_state_received.connect(self._on_message_lifecycle_state_received)
        self.session.message_edited_received.connect(self._on_message_edited_received)
        self.session.message_deleted_received.connect(self._on_message_deleted_received)
        self.session.reaction_updated_received.connect(self._on_reaction_updated_received)
        self.session.message_pinned_received.connect(self._on_message_pinned_received)
        self.session.message_unpinned_received.connect(self._on_message_unpinned_received)
        self.session.typing_indicator_received.connect(self._on_typing_indicator_received)

        # Phase 19.24 -- Typing Indicator. _typing_active/_typing_stop_
        # event: this account's own outstanding is_typing=True and the
        # Kivy Clock event that will end it after 3s idle (Kivy's
        # QTimer-equivalent -- Clock.schedule_once(), re-armed via
        # Clock.unschedule()+reschedule on every keystroke, exactly
        # mirroring gui/chat_window.py's identical QTimer contract).
        # _typing_senders: conversation_id -> {username: Clock event},
        # this account's own view of who else is typing, each entry
        # self-expiring after 5s of silence (mirrors Desktop's
        # identical per-sender auto-expiry -- see its own docstring for
        # why: a dropped connection mid-type never sends the matching
        # is_typing=False).
        self._typing_active = False
        self._typing_stop_event = None
        self._typing_senders = {}
        self._typing_status_label = None  # set per open_chat() -- see its own composer section

        # Phase 19.24 -- a disconnect (explicit logout, or a mid-
        # session drop) must never leave a typing-related Clock event
        # armed -- mirrors gui/chat_window.py's identical connection_
        # changed-triggered cleanup exactly (see its own docstring for
        # the full rationale: send_typing_indicator() is already safe
        # to call on a dead session, but there is no reason to let a
        # stale event fire at all once disconnected).
        self.session.connection_changed.connect(self._on_connection_changed_stop_typing_events)

        self._seed_restored_conversations()

        self.show_chats_list()

    def _seed_restored_conversations(self):
        """Populate self.conversations from session._restored_
        conversations -- the list session.load_conversations() built
        during login (BUG -- Mobile Conversation Persistence). session.
        direct_conversation_ids/groups are already populated by that
        same call; this only seeds THIS screen's own preview/unread
        presentation state, which the session object has no reason to
        know about."""

        for entry in getattr(self.session, "_restored_conversations", None) or []:
            time_text = ""
            if entry.get("timestamp"):
                try:
                    time_text = datetime.fromisoformat(entry["timestamp"]).strftime("%H:%M")
                except (TypeError, ValueError):
                    time_text = ""
            self.conversations[entry["identity_key"]] = {
                "name": entry["name"],
                "is_group": entry["is_group"],
                "last_message": entry.get("last_message") or "",
                "time": time_text,
                "unread": entry.get("unread_count") or 0,
            }

        # Phase 19.23 -- Issue 1: a direct conversation with zero
        # messages is deliberately excluded from the server's own
        # conversation list (database/repositories/conversation_
        # repository.py::get_conversation_previews_for_user()'s own
        # documented reason -- merely opening a chat with someone
        # never messaged must not add sidebar noise), so a peer who is
        # VERIFIED but has never actually been messaged never appears
        # in ``entry`` above no matter how many times the server list
        # is re-fetched. A verified peer is different: verification
        # itself is a real, deliberate, mutual, on-device-persisted
        # fact this device already knows about (self.session.peers,
        # rehydrated at login from SecureKeyStore -- see
        # MobileClientSession._rehydrate_peers_from_key_store()), not
        # merely "a chat screen was opened", so it is added here using
        # THAT existing persistence instead of asking the server to
        # special-case it. Never overwrites an entry the server's own
        # list already provided above (a verified peer who HAS
        # messages keeps their real preview/unread/time, untouched);
        # only ever fills in the neutral, zero-message shape
        # _conversation_preview() already produces for a brand new
        # chat -- the same "No messages yet" state a freshly-started,
        # never-sent conversation already renders as, never a
        # fabricated message of any kind.
        for peer, peer_state in self.session.peers.items():
            if peer_state.get("state") != "VERIFIED":
                continue
            if peer in self.conversations:
                continue
            self._conversation_preview(peer, name=peer, is_group=False)

    def _sync(self, *_):
        self._bg.pos = self.pos
        self._bg.size = self.size

    # ---------------------------------------------------------------
    # Navigation helpers
    # ---------------------------------------------------------------

    def _on_nav_select(self, key):
        self._active_section = key
        if key == "chats":
            self.show_chats_list()
        elif key == "groups":
            self.show_groups_list()
        elif key == "devices":
            self.show_devices_list()
        elif key == "settings":
            self.show_settings()

    def _on_fab(self):
        if self.active_conversation is not None:
            return  # inside a chat -- FAB has no action there
        if self._active_section == "groups":
            self._open_create_group_dialog()
        elif self._active_section == "devices":
            self.show_devices_list()
        elif self._active_section == "settings":
            return  # Settings is a plain action list -- "+" has no action there
        else:
            self._open_new_chat_dialog()

    def _set_content(self, widget):
        # Phase 19.17C -- the single chokepoint every screen switch
        # already goes through, so it's also the correct place to
        # track "did the user just navigate away from Inbox" -- reset
        # here, then show_inbox() re-asserts it right after calling
        # this, exactly the same order every other _set_content
        # caller already runs in.
        self._inbox_open = False
        self.content_area.clear_widgets()
        self.content_area.add_widget(widget)

    def _conversation_preview(self, identity_key, name=None, is_group=False):
        entry = self.conversations.get(identity_key)
        if entry is None:
            entry = {
                "name": name or identity_key,
                "is_group": is_group,
                "last_message": "",
                "time": "",
                "unread": 0,
            }
            self.conversations[identity_key] = entry
        elif name:
            entry["name"] = name
        return entry

    def _resolve_identity_key(self, identity_key):
        """mobile/session.py's load_history() (mirroring web/client/
        app.js::loadHistory() exactly) emits historical DIRECT messages
        keyed by the real conversation UUID, while LIVE direct messages
        (and both live and historical GROUP messages) are keyed by
        username/group-conversation_id respectively -- see
        _handle_chat()'s ``identity_key = conversation_id or sender``
        vs load_history()'s ``self.message_received.emit(conversation_id,
        ...)``. Translate a historical direct UUID back to the peer's
        username so this screen has one consistent key per conversation."""

        if identity_key in self.session.groups:
            return identity_key
        for peer, conversation_id in self.session.direct_conversation_ids.items():
            if conversation_id == identity_key:
                return peer
        return identity_key

    def _touch_preview(self, identity_key, text, *, incoming, name=None, is_group=False):
        entry = self._conversation_preview(identity_key, name=name, is_group=is_group)
        entry["last_message"] = text
        entry["time"] = datetime.now().strftime("%H:%M")
        if incoming and self.active_conversation != identity_key:
            entry["unread"] = entry.get("unread", 0) + 1

    # ---------------------------------------------------------------
    # Chats list
    # ---------------------------------------------------------------

    def show_chats_list(self):
        self.active_conversation = None
        # Root/bottom-nav screen -- no in-app back control of its own,
        # so hardware back should fall through to Android's normal
        # exit-the-app behavior, not a stale action left over from
        # whichever drill-down screen (open_chat(), user search) was
        # open before this. See build()'s own comment for why this
        # matters.
        App.get_running_app().back_action = None
        layout = BoxLayout(orientation="vertical")

        layout.add_widget(SectionHeader("Archived Chats" if self._show_archived else "Chats"))

        search_row = BoxLayout(size_hint_y=None, height=dp(46), padding=(dp(16), 0), spacing=dp(8))
        search_field = RoundedField(hint_text="Search by phone number to start a chat...")
        search_field.bind(on_text_validate=lambda *_: self._quick_search(search_field.text))
        search_row.add_widget(search_field)
        # Phase 19.24 -- Archive: mirrors gui/chat_window.py's Archived
        # toggle button -- flips self._show_archived and rebuilds this
        # same screen.
        archived_btn = PillButton(
            text="Back to Chats" if self._show_archived else "Archived",
            size_hint_x=None, width=dp(110) if self._show_archived else dp(84),
            font_size=dp(12), height=dp(40),
        )
        archived_btn.bind(on_release=lambda *_: self._toggle_archived_chats())
        search_row.add_widget(archived_btn)
        inbox_btn = PillButton(
            text="Inbox", size_hint_x=None, width=dp(78), font_size=dp(12), height=dp(40),
        )
        inbox_btn.bind(on_release=lambda *_: self.show_inbox())
        search_row.add_widget(inbox_btn)
        layout.add_widget(search_row)

        scroll = ScrollView()
        rows = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(8), padding=(dp(16), dp(8)))
        rows.bind(minimum_height=rows.setter("height"))

        direct_entries = [
            (peer, self._conversation_preview(peer, name=peer, is_group=False))
            for peer in self.session.direct_conversation_ids
        ]
        if not direct_entries and not any(not e.get("is_group") for e in self.conversations.values()):
            rows.add_widget(Label(
                text="No conversations yet.\nSearch a phone number or tap + to start one.",
                size_hint_y=None, height=dp(80), color=TEXT_GRAY, font_size=dp(13),
            ))
        # Phase 19.24 -- Archive: this screen shows either the main
        # (non-archived) list or the archived one, never both -- never
        # deletes/hides anything server-side, purely local filtering,
        # mirrors gui/chat_window.py::render_conversations()'s
        # identical filter.
        for identity_key, entry in list(self.conversations.items()):
            if entry.get("is_group"):
                continue
            if self.session.is_conversation_archived(identity_key) != self._show_archived:
                continue
            self._add_chat_row(rows, identity_key, entry)

        layout.add_widget(scroll)
        scroll.add_widget(rows)
        self._set_content(layout)

    def _toggle_archived_chats(self):
        self._show_archived = not self._show_archived
        self.show_chats_list()

    def _quick_search(self, phone_text):
        phone_text = phone_text.strip()
        if not phone_text:
            return

        # Backgrounded -- find_user_by_phone_number() is a blocking
        # send_request() call; running it directly on Kivy's main
        # thread (as this did before) blocks the whole app for the
        # round-trip, exactly the class of bug already found and
        # fixed for the Settings dialogs (see _open_change_username_
        # dialog's own comment). Observed on-device to leave the next
        # screen (open_chat()'s own widget construction, which runs
        # once this resolves) rendering as a stuck, uniform dim wash
        # that swallowed all further input until the app was
        # restarted -- consistent with Kivy's window/touch handling
        # getting confused by a screen transition built while the
        # main/event thread had been blocked.
        def _worker():
            try:
                result = self.session.find_user_by_phone_number(phone_text)
            except Exception as error:  # noqa: BLE001
                message = friendly_error(error)
                Clock.schedule_once(lambda dt: _FriendlyPopup("Search", message).open(), 0)
                return
            Clock.schedule_once(lambda dt: self._on_quick_search_result(result), 0)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_quick_search_result(self, result):
        if not result:
            _FriendlyPopup("Search", "No matching user found.").open()
            return
        username = result["username"]
        if username == self.session.username:
            _FriendlyPopup("Search", "That's you.").open()
            return
        self._conversation_preview(username, name=result["display_name"] or username, is_group=False)
        self.open_chat(username)

    def _add_chat_row(self, rows, identity_key, entry):
        peer_state = self.session.peers.get(identity_key)
        online = identity_key in self.session.online_users
        row = RowCard()
        avatar = CircleAvatar(entry["name"], diameter=48, online=online)
        row.add_widget(avatar)
        self._presence_labels.setdefault(identity_key, []).append(avatar)

        info = BoxLayout(orientation="vertical")
        name_row = BoxLayout(size_hint_y=None, height=dp(20))
        name_row.add_widget(Label(text=entry["name"], bold=True, color=TEXT_DARK, halign="left", font_size=dp(15)))
        if entry.get("time"):
            name_row.add_widget(Label(text=entry["time"], color=TEXT_GRAY, halign="right", font_size=dp(10), size_hint_x=None, width=dp(56)))
        info.add_widget(name_row)

        preview_row = BoxLayout(size_hint_y=None, height=dp(18))
        preview_text = entry.get("last_message") or "No messages yet"
        if peer_state and peer_state.get("state") != "VERIFIED":
            preview_text = "Not verified -- " + preview_text
        # Manual acceptance defect fix, round 2 (real vivo V2036 device
        # screenshot -- round 1's halign/text_size binding alone was
        # NOT sufficient, confirmed by physical rendering, not just
        # code inspection). Root cause: name_row (the sibling row
        # directly above this one) reserves a fixed dp(56) on its
        # right for the timestamp Label when one is present, so the
        # USERNAME's own available width is name_row's full width
        # MINUS 56dp -- but preview_row had no matching reservation,
        # so preview_label was centering across preview_row's FULL
        # width, a WIDER span than name_row's username column sits
        # in directly above it. Two labels centered within two
        # DIFFERENT available widths can never visually line up,
        # regardless of each one's own halign/text_size correctness in
        # isolation -- this was a container-geometry mismatch between
        # the two rows, not a per-label alignment property, which is
        # exactly why round 1's fix (correct in isolation, confirmed
        # by re-reading it here, still unchanged below) did not
        # resolve what the physical screenshot showed. The username
        # Label itself is deliberately NOT touched -- its position
        # must remain exactly as it already is.
        preview_label = Label(
            text=preview_text, color=TEXT_GRAY, font_size=dp(12), shorten=True,
            halign="center", valign="middle",
        )
        preview_label.bind(size=lambda inst, s: setattr(inst, "text_size", s))
        preview_row.add_widget(preview_label)
        unread = entry.get("unread", 0)
        # name_row reserves dp(56) for the timestamp whenever one is
        # shown (see the "if entry.get('time')" guard above) -- that
        # is the exact width preview_row must also reserve so its own
        # Label centers within the SAME available width as the
        # username above it. The unread badge below already claims
        # dp(22) of that reservation when present (a real, incoming
        # message commonly carries both a timestamp and an unread
        # increment together -- see _touch_preview()), so only the
        # remainder is added as an invisible spacer; nothing extra is
        # reserved when there is no timestamp, matching name_row
        # exactly in every combination of time/unread.
        timestamp_reserved = dp(56) if entry.get("time") else 0
        # Phase 19.24 -- Mute: the real count is untouched (entry
        # ["unread"] stays exactly as ClientSession-equivalent live
        # arrival tracking left it), only the VISUAL badge is
        # suppressed while muted -- affects notifications, never
        # delivery/read-state, mirrors gui/conversation_list_widget.py
        # ::ConversationRow._refresh_badge()'s identical suppression.
        if unread and not self.session.is_conversation_muted(identity_key):
            badge = FloatLayout(size_hint=(None, None), size=(dp(22), dp(22)))
            with badge.canvas.before:
                Color(*PURPLE)
                circle = Ellipse(pos=badge.pos, size=badge.size)
            badge.bind(pos=lambda *_: setattr(circle, "pos", badge.pos), size=lambda *_: setattr(circle, "size", badge.size))
            badge.add_widget(Label(text=str(unread), font_size=dp(11), bold=True, color=(1, 1, 1, 1)))
            preview_row.add_widget(badge)
            timestamp_reserved = max(0, timestamp_reserved - dp(22))
        if timestamp_reserved:
            preview_row.add_widget(Widget(size_hint_x=None, width=timestamp_reserved))
        info.add_widget(preview_row)
        row.add_widget(info)

        row.bind(on_release=lambda *_: self.open_chat(identity_key))
        row.add_widget(self._build_mute_button(identity_key, self.show_chats_list))
        rows.add_widget(row)

    def _build_mute_button(self, key, refresh, is_group=False):
        """Phase 19.24 -- Mute: a small, always-present bell icon on
        every chat/group row -- Kivy has no equivalent of a native
        right-click context menu (see gui/conversation_list_widget.py::
        ConversationRow.contextMenuEvent() for Desktop's own, real
        right-click version of this same feature), so this is the
        touch-UI entry point instead. Nested inside a RowCard (itself
        a ButtonBehavior) without double-firing the row's own on_release
        -- a child ButtonBehavior widget that consumes touch_down
        (this button does, being within its own bounds) is standard
        Kivy behaviour, not a special case here. ``is_group`` gates
        whether Block/Unblock is also offered in the same popup -- see
        _open_mute_popup()'s own comment."""

        muted = self.session.is_conversation_muted(key)
        btn = GhostButton(
            text="\U0001F515" if muted else "\U0001F514",  # 🔕 / 🔔
            size_hint=(None, None), size=(dp(32), dp(32)), font_size=dp(15),
        )
        btn.bind(on_release=lambda *_: self._open_mute_popup(key, refresh, is_group))
        return btn

    def _open_mute_popup(self, key, refresh, is_group=False):
        """Phase 19.24 -- Mute: mirrors gui/conversation_list_widget.py
        ::ConversationRow.contextMenuEvent()'s exact action set (Mute
        for 1h/8h/1w/forever, or Unmute if already muted) and the same
        underlying ClientSession.mute_conversation()/unmute_
        conversation() call every platform shares -- affects
        notifications (this list's own unread badge/preview), never
        delivery. ``refresh`` rebuilds whichever list screen (Chats or
        Groups) this row belongs to, mirroring every other state change
        in this file's own established "just rebuild the list" pattern."""

        muted = self.session.is_conversation_muted(key)
        archived = self.session.is_conversation_archived(key)

        if muted:
            options = [("unmute", "Unmute")]
        else:
            options = [
                ("mute_1h", "Mute for 1 hour"),
                ("mute_8h", "Mute for 8 hours"),
                ("mute_1w", "Mute for 1 week"),
                ("mute_forever", "Mute until I turn it back on"),
            ]
        # Phase 19.24 -- Archive: retains history, purely a "don't show
        # in the main list" local preference, offered in the same
        # popup as Mute (mirrors gui/conversation_list_widget.py's
        # ConversationRow.contextMenuEvent() adding it to the same
        # right-click menu).
        options.append(("unarchive", "Unarchive") if archived else ("archive", "Archive"))

        # Phase 19.24 -- Block User: only meaningful for a direct
        # conversation -- ``key`` there is a username (what
        # ClientSession.block_user() needs); for a group it is a
        # conversation_id, and blocking a "conversation" rather than a
        # person has no meaning (mirrors gui/conversation_list_
        # widget.py's identical is_group guard).
        if not is_group:
            blocked = self.session.is_user_blocked(key)
            options.append(("unblock", "Unblock") if blocked else ("block", "Block"))

        box = BoxLayout(orientation="vertical", spacing=dp(4), padding=dp(8), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        popup = Popup(
            title="Unmute" if muted else "Mute", content=box, size_hint=(0.82, None),
            height=dp(56) * len(options) + dp(60), background_color=SURFACE,
        )

        for action, label in options:
            btn = GhostButton(text=label, size_hint_y=None, height=dp(48), font_size=dp(14))

            def _choose(*_, action=action):
                popup.dismiss()
                if action == "block":
                    self._confirm_and_block_user(key)
                else:
                    self._apply_mute_action(key, action)
                refresh()

            btn.bind(on_release=_choose)
            box.add_widget(btn)

        popup.open()

    def _confirm_and_block_user(self, username):
        """Real Yes/No confirmation before Block User is sent -- mirrors
        gui/chat_window.py::_confirm_block_user() on Desktop. _do_block_
        user() is the actual action, factored out so tests can call it
        directly and bypass only this popup."""

        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        box.add_widget(Label(
            text=f"Block {username}? They will no longer be able to "
                 f"message you, see your presence, or verify your "
                 f"identity. You can unblock them later.",
            halign="left", valign="top", color=TEXT_DARK, font_size=dp(13),
        ))
        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        block_btn = PillButton(text="Block")
        btn_row.add_widget(cancel_btn)
        btn_row.add_widget(block_btn)
        box.add_widget(btn_row)
        popup = Popup(
            title="Block User?", content=box, size_hint=(0.88, None),
            height=dp(200), background_color=SURFACE,
        )
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())

        def _confirm(*_):
            popup.dismiss()
            self._do_block_user(username)

        block_btn.bind(on_release=_confirm)
        popup.open()

    def _do_block_user(self, username):
        """The actual Block User request, extracted so tests can call
        it directly without driving the confirmation popup."""

        self.session.block_user(username)

    def _apply_mute_action(self, key, action):
        """The actual state change a real Mute/Unmute/Archive/Unarchive
        popup selection applies -- factored out of _open_mute_popup()
        so the exact same call a real tap makes is directly reachable,
        mirroring gui/chat_window.py::_handle_mute_action() on
        Desktop. "block" is handled by _confirm_and_block_user() above
        instead (it needs a confirmation step block/mute/archive
        don't), so it is deliberately not one of this method's
        branches."""

        if action == "unmute":
            self.session.unmute_conversation(key)
        elif action == "archive":
            self.session.archive_conversation(key)
        elif action == "unarchive":
            self.session.unarchive_conversation(key)
        elif action == "unblock":
            self.session.unblock_user(key)
        else:
            self.session.mute_conversation(key, action[len("mute_"):])

    def _apply_wallpaper(self, identity_key):
        """Phase 19.24 -- Chat Wallpaper: repaints self._wallpaper_
        color to whichever preset (or the plain default BG) this
        conversation currently has -- called once when its screen is
        built, and again immediately after a real picker selection."""

        wallpaper_id = self.session.get_conversation_wallpaper(identity_key)
        preset = WALLPAPER_PRESETS.get(wallpaper_id)
        self._wallpaper_color.rgba = preset[1] if preset else BG

    def _open_wallpaper_picker(self, identity_key):
        """Phase 19.24 -- Chat Wallpaper: a small preset picker for
        this conversation. Local-only (mobile/session.py's own get/
        set_conversation_wallpaper()) -- never sent to or stored by
        the server. Mirrors gui/chat_window.py::handle_open_wallpaper_
        picker()'s exact preset set."""

        current = self.session.get_conversation_wallpaper(identity_key)

        box = BoxLayout(orientation="vertical", spacing=dp(4), padding=dp(8), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        options = [(None, "Default")] + [
            (wallpaper_id, label) for wallpaper_id, (label, _rgba) in WALLPAPER_PRESETS.items()
        ]
        popup = Popup(
            title="Wallpaper", content=box, size_hint=(0.82, None),
            height=dp(56) * len(options) + dp(60), background_color=SURFACE,
        )

        for wallpaper_id, label in options:
            text = f"✓ {label}" if wallpaper_id == current else label
            btn = GhostButton(text=text, size_hint_y=None, height=dp(48), font_size=dp(14))

            def _choose(*_, wallpaper_id=wallpaper_id):
                popup.dismiss()
                self.session.set_conversation_wallpaper(identity_key, wallpaper_id)
                if identity_key == self.active_conversation:
                    self._apply_wallpaper(identity_key)

            btn.bind(on_release=_choose)
            box.add_widget(btn)

        popup.open()

    # ==========================================================
    # Phase 19.24 -- Pinned Messages
    # ==========================================================

    def _pinned_bubbles(self, identity_key):
        """Every currently-pinned bubble in this conversation, in on-
        screen (chronological) order -- mirrors gui/message_widget.py
        ::MessageWidget.get_pinned_bubbles()'s exact contract, reusing
        the same anchor-unwrap logic _search_matching_bubbles() above
        already established."""

        box = self._bubble_rows.get(identity_key)
        if box is None:
            return []
        bubbles = []
        for anchor in reversed(box.children):
            for child in anchor.children:
                if hasattr(child, "message_text"):
                    bubbles.append(child)
        return [b for b in bubbles if getattr(b, "is_pinned", False)]

    def _media_bubbles(self, identity_key):
        """Every attachment bubble (image/file/voice/video) currently
        rendered in this conversation, in on-screen (chronological)
        order -- mirrors gui/message_widget.py::MessageWidget.get_
        media_bubbles()'s exact contract, reusing the same anchor-
        unwrap logic _search_matching_bubbles()/_pinned_bubbles() above
        already established. Never touches the server or triggers a
        second history fetch -- exactly like those two."""

        box = self._bubble_rows.get(identity_key)
        if box is None:
            return []
        bubbles = []
        for anchor in reversed(box.children):
            for child in anchor.children:
                if hasattr(child, "message_text"):
                    bubbles.append(child)
        return [b for b in bubbles if getattr(b, "_attachment_bytes", None) is not None and not b.is_deleted]

    def _open_media_gallery(self, identity_key):
        """A real per-conversation gallery (this closure pass, closing
        the previous Desktop-only gap) -- mirrors gui/chat_window.py::
        handle_open_media_gallery()'s exact contract and grouping
        (Photos & Videos grid above, Voice Messages & Files list
        below). Operates entirely over _media_bubbles() above --
        already-decrypted, already-rendered bubbles -- so this never
        touches the server, triggers a second history fetch, or
        indexes plaintext media anywhere outside this device. Each
        tile/row REUSES the real, already-tested playback/view/save
        widget _build_attachment_bubble_content() already builds for
        the inline chat bubble (a fresh instance, not a shared one --
        this project's SoundLoader-based voice playback has no
        multi-instance-safety concerns since each Sound object is
        independent), never a second, gallery-specific implementation
        of the same behavior."""

        media = self._media_bubbles(identity_key)

        box = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(8), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(box)
        popup = Popup(
            title="Media Gallery", content=scroll, size_hint=(0.94, 0.85), background_color=SURFACE,
        )

        if not media:
            box.add_widget(Label(
                text="No media in this conversation yet.", size_hint_y=None, height=dp(48),
                color=TEXT_GRAY, font_size=dp(13),
            ))
            popup.open()
            return

        images_and_videos = [b for b in media if b.payload_type in (PayloadType.IMAGE, PayloadType.VIDEO)]
        other_files = [b for b in media if b not in images_and_videos]

        if images_and_videos:
            box.add_widget(Label(
                text="Photos & Videos", size_hint_y=None, height=dp(28), font_size=dp(13),
                bold=True, color=TEXT_DARK, halign="left",
            ))
            grid = GridLayout(cols=3, spacing=dp(4), size_hint_y=None)
            grid.bind(minimum_height=grid.setter("height"))
            for bubble in images_and_videos:
                grid.add_widget(self._build_gallery_tile(bubble))
            box.add_widget(grid)

        if other_files:
            box.add_widget(Label(
                text="Voice Messages & Files", size_hint_y=None, height=dp(28), font_size=dp(13),
                bold=True, color=TEXT_DARK, halign="left",
            ))
            for bubble in other_files:
                row = _build_attachment_bubble_content(
                    bubble._attachment_filename or "attachment", bubble._attachment_bytes,
                    kind="received", mime_type=bubble._attachment_mime_type,
                    on_save=lambda *_a, b=bubble: self._save_attachment_android(
                        b._attachment_filename or "attachment", b._attachment_mime_type, b._attachment_bytes
                    ) if platform == "android" else None,
                )
                box.add_widget(row)

        popup.open()

    def _build_gallery_tile(self, bubble):
        """One tappable tile in the Media Gallery's Photos & Videos
        grid. An image decodes and shows a real thumbnail (tap opens
        the SAME real ImageViewerPopup the inline bubble uses); a video
        shows a labeled placeholder tile (tap Saves it, mirroring the
        inline video bubble's own honest Save-only behavior on this
        Kivy build -- see _build_attachment_bubble_content()'s own
        docstring for why in-app video playback is not available)."""

        tile = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(90))

        if bubble.payload_type == PayloadType.IMAGE:
            texture = _decode_image_texture(bubble._attachment_bytes)
            if texture is not None:
                img_btn = ButtonBehavior(KivyImage(texture=texture, allow_stretch=True, keep_ratio=True))
                img_btn.bind(on_release=lambda *_: ImageViewerPopup(texture).open())
                tile.add_widget(img_btn)
                return tile
            tile.add_widget(Label(text="[Image]", font_size=dp(11), color=TEXT_GRAY))
            return tile

        video_btn = GhostButton(text="\U0001F3AC Video", font_size=dp(11))
        video_btn.bind(on_release=lambda *_: self._save_attachment_android(
            bubble._attachment_filename or "video-message.mp4", bubble._attachment_mime_type, bubble._attachment_bytes
        ) if platform == "android" else None)
        tile.add_widget(video_btn)
        return tile

    def _open_pinned_messages_panel(self, identity_key):
        """Phase 19.24 -- Pinned Messages: a real, server-synchronized
        panel (NOT a fake local-only button -- pin/unpin is a real
        message_pin/message_unpin protocol round trip with a server-
        side row that synchronizes to every conversation member and
        every one of this account's own other authorized devices via
        ordinary history reload, mirrors gui/chat_window.py::handle_
        open_pinned_messages_panel()'s identical contract) listing
        every currently-pinned message, with tap-to-navigate."""

        pinned = self._pinned_bubbles(identity_key)

        box = BoxLayout(orientation="vertical", spacing=dp(4), padding=dp(8), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        popup = Popup(
            title="Pinned Messages", content=box, size_hint=(0.9, None),
            height=dp(56) * max(len(pinned), 1) + dp(60), background_color=SURFACE,
        )

        if not pinned:
            box.add_widget(Label(
                text="No pinned messages", size_hint_y=None, height=dp(48),
                color=TEXT_GRAY, font_size=dp(13),
            ))
        else:
            for bubble in reversed(pinned):
                preview = bubble.message_text or "[Attachment]"
                shown = preview if len(preview) <= 60 else preview[:57] + "…"
                by = f" — pinned by {bubble.pinned_by}" if bubble.pinned_by else ""
                btn = GhostButton(
                    text=f"{shown}{by}", size_hint_y=None, height=dp(48), font_size=dp(13),
                    halign="left",
                )

                def _navigate(*_, bubble=bubble):
                    popup.dismiss()
                    self._highlight_search_match(bubble)

                btn.bind(on_release=_navigate)
                box.add_widget(btn)

        popup.open()

    # ==========================================================
    # Phase 19.24 -- Message Search
    # ==========================================================
    #
    # Searches only the already-decrypted bubbles currently rendered
    # for this conversation (mirrors gui/message_widget.py::
    # MessageWidget.find_matches()'s exact contract) -- no network
    # call, no second history fetch, the query text never leaves this
    # device.

    def _search_matching_bubbles(self, identity_key, query):
        query = (query or "").strip().lower()
        box = self._bubble_rows.get(identity_key)
        if not query or box is None:
            return []
        # Each row in box.children is an "anchor" BoxLayout wrapping
        # the actual Bubble alongside alignment spacer Widget()s (see
        # _append_bubble()'s own "anchor.add_widget(bubble)" -- the
        # Bubble is never box's direct child). box.children is also in
        # REVERSE add-order -- flip it back to chronological order.
        bubbles = []
        for anchor in reversed(box.children):
            for child in anchor.children:
                if hasattr(child, "message_text"):
                    bubbles.append(child)
        return [
            b for b in bubbles
            if b.message_text and not b.is_deleted and query in b.message_text.lower()
        ]

    def _highlight_search_match(self, bubble):
        self._clear_search_highlight()
        if bubble is None:
            return
        bubble._bg_color.rgba = SEARCH_HIGHLIGHT
        self._search_highlighted_bubble = bubble
        if self._messages_scroll is not None:
            self._messages_scroll.scroll_to(bubble)

    def _clear_search_highlight(self):
        bubble = self._search_highlighted_bubble
        self._search_highlighted_bubble = None
        if bubble is not None:
            bubble._bg_color.rgba = bubble._normal_bg

    def _toggle_search_bar(self, identity_key):
        if self._search_bar.height:
            self._close_search_bar()
            return
        self._search_bar.height = dp(48)
        self._search_input.focus = True

    def _close_search_bar(self):
        self._search_bar.height = 0
        self._search_input.text = ""
        self._search_matches = []
        self._search_match_index = -1
        self._search_result_label.text = ""
        self._clear_search_highlight()

    def _handle_search_query_changed(self, identity_key, text):
        self._search_matches = self._search_matching_bubbles(identity_key, text)
        if not self._search_matches:
            self._search_match_index = -1
            self._clear_search_highlight()
            self._search_result_label.text = "No matches" if text.strip() else ""
            return
        self._search_match_index = 0
        self._show_current_search_match()

    def _show_current_search_match(self):
        bubble = self._search_matches[self._search_match_index]
        self._highlight_search_match(bubble)
        self._search_result_label.text = f"{self._search_match_index + 1} of {len(self._search_matches)}"

    def _search_next(self):
        if not self._search_matches:
            return
        self._search_match_index = (self._search_match_index + 1) % len(self._search_matches)
        self._show_current_search_match()

    def _search_previous(self):
        if not self._search_matches:
            return
        self._search_match_index = (self._search_match_index - 1) % len(self._search_matches)
        self._show_current_search_match()

    def _open_new_chat_dialog(self):
        self._open_user_search_screen(
            "New Conversation", multi=False,
            on_done=self._on_new_chat_selected, on_cancel=self.show_chats_list,
        )

    def _on_new_chat_selected(self, usernames):
        if not usernames:
            return
        peer = usernames[0]
        self._conversation_preview(peer, name=peer, is_group=False)
        self.open_chat(peer)

    def _open_user_search_screen(self, title, *, multi, on_done, on_cancel=None, exclude_usernames=None):
        """Phase 19.16 -- Blocker 1: UserPickerPopup's phone-number
        TextInput never became the real Android-IME-focused widget on
        this physical device, in any of several independently tried
        Popup/TextInput structures (removing popup nesting, changing
        the TextInput's sibling layout, passing content= straight into
        Popup.__init__()). The one thing every OTHER working TextInput
        in this file has in common -- the login fields, the Chats
        list's own inline search field, this screen's own composer --
        is that none of them live inside a Popup/ModalView at all;
        they're all placed directly into a normal screen's content
        area via ChatScreen._set_content(), the exact same mechanism
        show_chats_list()/show_groups_list()/open_chat() already use.
        Moving user search onto a real, full-content screen sidesteps
        the broken Popup/TextInput interaction entirely instead of
        continuing to fight it. Behaviour is otherwise a direct port of
        the old UserPickerPopup: search by phone number -> matched user
        card -> Select/Add; ``multi`` builds a running selection (Create
        Group / Add Members) instead of resolving on the first pick
        (New Chat)."""

        exclude_usernames = set(exclude_usernames or ())
        selected = {}  # username -> display_name

        layout = BoxLayout(orientation="vertical")

        header = BoxLayout(size_hint_y=None, height=dp(52), padding=(dp(16), dp(6)), spacing=dp(8))
        back_btn = GhostButton(text="< Back", size_hint_x=None, width=dp(72))
        header.add_widget(back_btn)
        title_lbl = Label(text=title, font_size=dp(17), bold=True, color=TEXT_DARK, halign="left", valign="middle")
        title_lbl.bind(size=lambda inst, s: setattr(inst, "text_size", s))
        header.add_widget(title_lbl)
        layout.add_widget(header)

        body = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))

        phone_field = RoundedField(hint_text="Search by phone number...")
        body.add_widget(phone_field)

        search_btn = PillButton(text="Search", size_hint_y=None, height=dp(46))
        body.add_widget(search_btn)

        result_box = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(76), spacing=dp(6))
        body.add_widget(result_box)

        selected_box = None
        if multi:
            body.add_widget(Label(text="Selected", size_hint_y=None, height=dp(20), halign="left", color=TEXT_GRAY, font_size=dp(11)))
            scroll = ScrollView(size_hint_y=1)
            selected_box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(6))
            selected_box.bind(minimum_height=selected_box.setter("height"))
            scroll.add_widget(selected_box)
            body.add_widget(scroll)
        else:
            body.add_widget(Widget())

        layout.add_widget(body)

        def _finish():
            if on_done:
                on_done(list(selected.keys()))

        if multi:
            bottom = BoxLayout(size_hint_y=None, height=dp(64), padding=(dp(16), dp(8)))
            done_btn = PillButton(text="Done")
            done_btn.bind(on_release=lambda *_: _finish())
            bottom.add_widget(done_btn)
            layout.add_widget(bottom)

        def _choose(username, display_name):
            if not multi:
                if on_done:
                    on_done([username])
                return
            if username in selected:
                return
            selected[username] = display_name
            chip = RowCard(height=dp(46))
            chip.add_widget(CircleAvatar(display_name or username, diameter=30))
            chip_lbl = Label(text=display_name or username, color=TEXT_DARK, halign="left", font_size=dp(13))
            chip_lbl.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None)))
            chip.add_widget(chip_lbl)
            remove_btn = GhostButton(text="Remove", size_hint=(None, None), size=(dp(80), dp(30)), font_size=dp(10), color=DANGER)

            def _remove(*_):
                selected.pop(username, None)
                selected_box.remove_widget(chip)

            remove_btn.bind(on_release=_remove)
            chip.add_widget(remove_btn)
            selected_box.add_widget(chip)

        def _on_search_result(result):
            result_box.clear_widgets()
            if not result:
                result_box.add_widget(Label(text="No matching user found.", color=TEXT_GRAY, font_size=dp(12)))
                return
            username = result["username"]
            if username == self.session.username or username in exclude_usernames:
                result_box.add_widget(Label(text="That user is already in this conversation.", color=TEXT_GRAY, font_size=dp(12)))
                return

            row = RowCard(height=dp(64))
            row.add_widget(CircleAvatar(result["display_name"] or username, diameter=40))
            info = BoxLayout(orientation="vertical")
            name_lbl = Label(text=result["display_name"] or username, bold=True, color=TEXT_DARK, halign="left", font_size=dp(14))
            name_lbl.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None)))
            info.add_widget(name_lbl)
            handle_lbl = Label(text=f"@{username}", color=TEXT_GRAY, halign="left", font_size=dp(11))
            handle_lbl.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None)))
            info.add_widget(handle_lbl)
            row.add_widget(info)
            select_btn = PillButton(text="Add" if multi else "Select", size_hint=(None, None), size=(dp(80), dp(34)), font_size=dp(11))
            select_btn.bind(on_release=lambda *_: _choose(username, result["display_name"]))
            row.add_widget(select_btn)
            result_box.add_widget(row)

        def _search(*_):
            result_box.clear_widgets()
            phone = phone_field.text.strip()
            if not phone:
                return

            # Backgrounded -- see ChatScreen._quick_search()'s own
            # comment: find_user_by_phone_number() blocks on a
            # send_request() round trip, and running it on Kivy's main
            # thread risks the same stuck-render class of bug found
            # there.
            def _worker():
                try:
                    result = self.session.find_user_by_phone_number(phone)
                except Exception as error:  # noqa: BLE001
                    message = friendly_error(error)
                    Clock.schedule_once(lambda dt: result_box.add_widget(Label(text=message, color=DANGER, font_size=dp(12))), 0)
                    return
                Clock.schedule_once(lambda dt: _on_search_result(result), 0)

            threading.Thread(target=_worker, daemon=True).start()

        phone_field.bind(on_text_validate=_search)
        search_btn.bind(on_release=_search)
        _go_back = lambda *_: (on_cancel() if on_cancel else None)
        back_btn.bind(on_release=_go_back)
        # Android hardware/gesture back button -- see build()'s own
        # comment for the full root-cause.
        App.get_running_app().back_action = _go_back

        self._set_content(layout)

    # ---------------------------------------------------------------
    # Chat view (direct or group)
    # ---------------------------------------------------------------

    def open_chat(self, identity_key):
        entry = self.conversations.get(identity_key)
        is_group = bool(identity_key in self.session.groups or (entry and entry.get("is_group")))
        # Phase 19.15 -- the conversation-preview cache (self.conversations,
        # populated by _conversation_preview()) never stores a "members"
        # key at all (only name/is_group/last_message/time/unread), so
        # this header's member/online count was always reading a
        # nonexistent field and silently showing 0/0 for every group,
        # regardless of the real membership -- a real Test 4 acceptance
        # blocker ("count must be real, not static text"). Sourcing
        # both the title and the count from self.session.groups (the
        # session's own authoritative, live-updated group state) instead
        # of the UI-only preview cache fixes both.
        group_info = self.session.groups.get(identity_key, {}) if is_group else {}

        # Phase 19.24 -- Typing Indicator: an outstanding is_typing=True
        # belongs to whichever conversation was open BEFORE this call,
        # not the one about to open -- stopped here, before self.
        # _active_real_conversation_id moves further down, so the
        # "stopped" packet still addresses the right one. Per-sender
        # state (what OTHER people are typing) is simply reset below --
        # it is scoped per-conversation and becomes irrelevant here
        # rather than needing an explicit "stopped" of its own, mirrors
        # gui/chat_window.py::open_conversation()'s identical two-part
        # cleanup exactly.
        self._stop_typing_immediately()
        for senders in self._typing_senders.values():
            for event in senders.values():
                event.cancel()
        self._typing_senders = {}
        self._typing_status_label = None

        # Phase 19.24 -- Drafts: save whatever unsent text sits in the
        # composer for whichever conversation was open BEFORE this call
        # -- self.active_conversation is still the OLD identity_key
        # here, not yet reassigned below. Skipped while a reply/edit is
        # in progress: that text belongs to the pending action, not a
        # draft of a fresh message (mirrors gui/chat_window.py::open_
        # conversation()'s identical exclusion).
        old_key = self.active_conversation
        if (
            old_key is not None
            and self._pending_reply_message_id is None
            and self._editing_message_id is None
        ):
            draft_text = self._active_message_input.text if self._active_message_input else ""
            if draft_text:
                self._drafts[old_key] = draft_text
            else:
                self._drafts.pop(old_key, None)

        self.active_conversation = identity_key
        self.active_is_group = is_group
        if entry:
            entry["unread"] = 0

        # Phase 19.24 (continued) -- a bubble from whichever conversation
        # was open before belongs to a widget tree about to be
        # discarded (self._set_content() below) -- reset before it, so
        # nothing here can ever resolve into or address a bubble that
        # no longer exists on screen.
        self._bubbles_by_message_id = {}
        self._bubbles_awaiting_message_id = {}
        self._pending_reply_message_id = None
        self._editing_message_id = None
        self._editing_expected_version = 0
        self._composer_context_label = None
        self._active_message_input = None

        layout = BoxLayout(orientation="vertical")

        header = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(84), padding=(dp(8), dp(6)))
        with header.canvas.before:
            Color(*SURFACE)
            header_rect = RoundedRectangle(pos=header.pos, size=header.size, radius=[0, 0, dp(18), dp(18)])
        header.bind(pos=lambda *_: (setattr(header_rect, "pos", header.pos)), size=lambda *_: (setattr(header_rect, "size", header.size)))

        top_row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
        back_btn = GhostButton(text="< Back", size_hint_x=None, width=dp(72))
        _go_back = lambda *_: (self.show_groups_list() if is_group else self.show_chats_list())
        back_btn.bind(on_release=_go_back)
        # Android hardware/gesture back button -- see build()'s own
        # comment for the full root-cause: without this, the exact
        # same "< Back" action above only ran for a tap on this text
        # button, never for the system back control most Android users
        # reach for instead, which otherwise exited the app.
        App.get_running_app().back_action = _go_back
        top_row.add_widget(back_btn)

        title = (group_info.get("name") or identity_key) if is_group else (entry["name"] if entry else identity_key)
        # label_text is passed as a keyword here deliberately: Kivy's
        # ButtonBehavior.__init__(self, **kwargs) has no positional
        # parameter slot, so a positional label_text would never reach
        # CircleAvatar.__init__ through the super() chain and would
        # raise a TypeError at construction (see TappableImage's own
        # call sites in this file, which follow the same rule).
        header_avatar = TappableCircleAvatar(label_text=title, diameter=36, online=(not is_group and identity_key in self.session.online_users))
        if not is_group:
            header_avatar.bind(on_release=lambda *_: self._open_profile_picture_viewer(identity_key, title))
        top_row.add_widget(header_avatar)
        title_box = BoxLayout(orientation="vertical", padding=(dp(8), 0))
        # Phase 19.14 -- Chat header alignment: halign="left" alone
        # does nothing in Kivy unless text_size[0] is also set -- with
        # no text_size, the Label's texture is exactly as wide as the
        # text itself and there is no extra space left to align
        # *within*, so the text renders centered inside whatever width
        # the BoxLayout actually gave the widget (the reported bug).
        # Reactively binding text_size to width (not the fixed value
        # read once at construction, which can still be Kivy's stale
        # pre-resize placeholder -- see this file's own established
        # lesson from the Phase 19 redesign) is what makes halign
        # finally have an effect.
        name_label = Label(
            text=title, font_size=dp(15), bold=True, color=TEXT_DARK,
            halign="left", valign="bottom", size_hint_y=None, height=dp(22),
        )
        name_label.bind(width=lambda inst, w: setattr(inst, "text_size", (w, inst.height)))
        title_box.add_widget(name_label)
        presence_label = Label(text="", font_size=dp(11), halign="left", valign="top", size_hint_y=None, height=dp(16))
        presence_label.bind(width=lambda inst, w: setattr(inst, "text_size", (w, inst.height)))
        if is_group:
            members = group_info.get("members", [])
            # Phase 19.16 -- Blocker 2: self.session.online_users is a
            # presence broadcast of OTHER connected users (confirmed via
            # this project's own daemon captures -- a session's own
            # username never appears in its own online_users list, the
            # ordinary "you obviously know you're online" convention),
            # so the viewer's own membership must be counted separately
            # -- they are definitionally online while looking at this
            # screen.
            online_count = sum(1 for m in members if m in self.session.online_users or m == self.session.username)
            presence_label.text = f"{len(members)} members • {online_count} online"
            presence_label.color = TEXT_GRAY
        else:
            # Phase 19.24 -- Presence/Last Seen: tracked so _on_users_
            # updated() can refresh THIS exact label live, the same
            # server-pushed event this method's presence dots already
            # use -- reset on every open_chat() call (a direct or group
            # chat leaving means there is no longer a "the open direct
            # chat's own presence line" to refresh).
            self._active_presence_label = presence_label
            self._set_presence_label(presence_label, identity_key)
            title_box.add_widget(presence_label)
        if is_group:
            self._active_presence_label = None
        top_row.add_widget(title_box)

        if is_group:
            members_btn = GhostButton(text="Members", size_hint_x=None, width=dp(76), font_size=dp(11), height=dp(34))
            members_btn.bind(on_release=lambda *_: self._open_group_members_dialog(identity_key))
            top_row.add_widget(members_btn)
            add_members_btn = PillButton(text="+ Add", size_hint_x=None, width=dp(72), font_size=dp(11), height=dp(34))
            add_members_btn.bind(on_release=lambda *_: self._open_add_members_dialog(identity_key))
            top_row.add_widget(add_members_btn)
        # Phase 19.24 -- Message Search: always present, direct or
        # group alike -- toggles self._search_bar (built below, a
        # zero-height-until-relevant row like composer_context).
        search_btn = GhostButton(text="\U0001F50D", size_hint_x=None, width=dp(40), font_size=dp(16), height=dp(34))
        search_btn.bind(on_release=lambda *_: self._toggle_search_bar(identity_key))
        top_row.add_widget(search_btn)
        # Phase 19.24 -- Pinned Messages: always present, direct or
        # group alike -- see _open_pinned_messages_panel()'s own
        # docstring.
        pinned_btn = GhostButton(text="\U0001F4CC", size_hint_x=None, width=dp(40), font_size=dp(16), height=dp(34))
        pinned_btn.bind(on_release=lambda *_: self._open_pinned_messages_panel(identity_key))
        top_row.add_widget(pinned_btn)
        # Media Gallery (this closure pass): always present -- see
        # _open_media_gallery()'s own docstring.
        gallery_btn = GhostButton(text="\U0001F5C2", size_hint_x=None, width=dp(40), font_size=dp(16), height=dp(34))
        gallery_btn.bind(on_release=lambda *_: self._open_media_gallery(identity_key))
        top_row.add_widget(gallery_btn)
        # Phase 19.24 -- Chat Wallpaper: always present, direct or
        # group alike -- see _open_wallpaper_picker()'s own docstring.
        wallpaper_btn = GhostButton(text="\U0001F5BC", size_hint_x=None, width=dp(40), font_size=dp(16), height=dp(34))
        wallpaper_btn.bind(on_release=lambda *_: self._open_wallpaper_picker(identity_key))
        top_row.add_widget(wallpaper_btn)
        header.add_widget(top_row)

        if is_group:
            # Phase 19.16 -- Blocker 2 (final root cause): title_box
            # sits in top_row alongside a fixed-width Back button,
            # avatar, Members button and +Add button, leaving it only
            # ~70-90dp wide on this device -- nowhere near enough for
            # "N members * M online" at any reasonable font size (a
            # dp(10)->dp(9) font shrink, tried first, still truncated
            # it on-device: real screens confirmed the width itself was
            # the constraint, not the font). Group headers don't use
            # the direct-chat verified-badge row that already occupies
            # the header's remaining height below top_row, so giving
            # the presence line that same full-width row instead of
            # squeezing it into title_box fits any realistic member
            # count without truncation, without touching top_row's own
            # already-accepted spacing/alignment at all.
            # Left padding lines the text up under name_label: back_btn
            # (72) + spacing (8) + avatar (36) + spacing (8) +
            # title_box's own left padding (8) = 132, all matching
            # top_row's real widths/spacing above, unchanged by this.
            presence_row = BoxLayout(size_hint_y=None, height=dp(18), padding=(dp(132), 0, dp(8), 0))
            presence_row.add_widget(presence_label)
            header.add_widget(presence_row)

        if not is_group:
            self.verified_badge = VerifiedBadge(
                on_verify=lambda: self._verify_peer(identity_key),
                on_request=lambda: self._request_verification(identity_key),
            )
            header.add_widget(self.verified_badge)
            self._refresh_verified_badge(identity_key)
        layout.add_widget(header)

        # Phase 19.24 -- Message Search: zero-height until search_btn
        # (above) toggles it -- same "hidden by default" pattern as
        # composer_context/typing_status_label below. Operates only on
        # THIS conversation's already-rendered, already-decrypted
        # bubbles (see _search_matching_bubbles()'s own docstring) --
        # the query text itself is never sent anywhere.
        self._search_matches = []
        self._search_match_index = -1
        self._search_highlighted_bubble = None

        search_bar = BoxLayout(orientation="horizontal", size_hint_y=None, height=0, padding=(dp(10), dp(4)), spacing=dp(6))
        search_input = RoundedField(hint_text="Search in this conversation", multiline=False, height=dp(40))
        search_input.bind(text=lambda inst, text: self._handle_search_query_changed(identity_key, text))
        search_bar.add_widget(search_input)
        search_result_label = Label(text="", size_hint_x=None, width=dp(56), font_size=dp(11), color=TEXT_GRAY)
        search_bar.add_widget(search_result_label)
        search_prev_btn = GhostButton(text="▲", size_hint_x=None, width=dp(36), font_size=dp(14))
        search_prev_btn.bind(on_release=lambda *_: self._search_previous())
        search_bar.add_widget(search_prev_btn)
        search_next_btn = GhostButton(text="▼", size_hint_x=None, width=dp(36), font_size=dp(14))
        search_next_btn.bind(on_release=lambda *_: self._search_next())
        search_bar.add_widget(search_next_btn)
        search_close_btn = GhostButton(text="x", size_hint_x=None, width=dp(32), font_size=dp(14))
        search_close_btn.bind(on_release=lambda *_: self._close_search_bar())
        search_bar.add_widget(search_close_btn)
        layout.add_widget(search_bar)
        self._search_bar = search_bar
        self._search_input = search_input
        self._search_result_label = search_result_label

        scroll = ScrollView()
        # Phase 19.24 -- Chat Wallpaper: a plain Color+Rectangle behind
        # the message list, applied fresh for whichever conversation
        # is now open -- see _apply_wallpaper()'s own docstring.
        with scroll.canvas.before:
            self._wallpaper_color = Color(*BG)
            self._wallpaper_rect = Rectangle(pos=scroll.pos, size=scroll.size)
        scroll.bind(
            pos=lambda inst, val: setattr(self._wallpaper_rect, "pos", val),
            size=lambda inst, val: setattr(self._wallpaper_rect, "size", val),
        )
        self._apply_wallpaper(identity_key)
        messages_box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(8), padding=dp(12))
        messages_box.bind(minimum_height=messages_box.setter("height"))
        scroll.add_widget(messages_box)
        layout.add_widget(scroll)
        self._bubble_rows[identity_key] = messages_box
        self._messages_scroll = scroll

        # A search result opened via _quick_search() has no real
        # conversation yet -- open_direct_conversation() only ever
        # runs later, the first time a message actually sends (see
        # _send_text() below). Without this, the chat screen looked
        # visually identical to an established conversation with no
        # messages, which read as "a chat already exists with
        # nothing in it" rather than "nobody has said anything yet
        # because this is brand new" (Phase 19.13, item 9).
        if not is_group and identity_key not in self.session.direct_conversation_ids:
            messages_box.add_widget(Label(
                text=f"New conversation with {title}.\nSay hello to get started.",
                size_hint_y=None, height=dp(60), color=TEXT_GRAY, font_size=dp(13), halign="center",
            ))

        # Phase 19.17C -- the composer row and its text field both grow
        # with content (minimum_height, capped) instead of a fixed
        # dp(58)/dp(46): RoundedField previously defaulted to
        # multiline=False, so a longer message was entered blind,
        # scrolling sideways inside a single fixed-height line instead
        # of wrapping visibly. multiline=True also changes what Enter
        # does -- Kivy only fires on_text_validate (bound to _send()
        # below) for a single-line TextInput, so Enter now inserts a
        # newline like every other mobile messenger; Send stays the
        # only way to actually send.
        # Phase 19.24 (continued) -- the composer's Reply/Edit context
        # bar -- shown only while self._pending_reply_message_id or
        # self._editing_message_id is set (see _handle_bubble_context_
        # action()'s "reply"/"edit" cases and _clear_composer_
        # context()). Same "zero height until relevant" pattern as
        # Bubble's own reply-preview/reactions labels.
        composer_context = BoxLayout(orientation="horizontal", size_hint_y=None, height=0, padding=(dp(10), 0), spacing=dp(8))
        composer_context_label = Label(
            text="", size_hint_x=1, halign="left", valign="middle", font_size=dp(11),
            color=PURPLE, text_size=(Window.width - dp(90), None),
        )
        composer_context.add_widget(composer_context_label)
        composer_context_cancel = GhostButton(text="x", size_hint_x=None, width=dp(32), font_size=dp(14))
        composer_context_cancel.bind(on_release=lambda *_: self._clear_composer_context())
        composer_context.add_widget(composer_context_cancel)
        layout.add_widget(composer_context)
        self._composer_context_label = composer_context_label

        # Phase 19.24 -- Typing Indicator: "X is typing..." (or "X and
        # Y are typing..." for a group), shown just above the composer
        # -- empty/hidden whenever nobody in the currently open
        # conversation is typing, same "zero height until relevant"
        # pattern as composer_context above.
        typing_status_label = Label(
            text="", size_hint_y=None, height=0, halign="left", valign="middle",
            font_size=dp(11), italic=True, color=TEXT_GRAY,
        )
        typing_status_label.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None)))
        layout.add_widget(typing_status_label)
        self._typing_status_label = typing_status_label

        composer = BoxLayout(orientation="horizontal", size_hint_y=None, padding=(dp(10), dp(6)), spacing=dp(8))
        composer.bind(minimum_height=composer.setter("height"))
        attach_btn = PillButton(text="+", size_hint_x=None, width=dp(44), font_size=dp(20))
        attach_btn.bind(on_release=lambda *_: self._start_attachment_pick(identity_key, is_group))
        message_input = RoundedField(hint_text="Type here...", multiline=True, height=dp(46))
        message_input.bind(minimum_height=lambda inst, h: setattr(inst, "height", min(max(h, dp(46)), dp(120))))
        self._active_message_input = message_input

        # Phase 19.24 -- Drafts: restore whatever unsent text this
        # conversation had, or leave it empty if it never had one --
        # set BEFORE the typing-indicator text= bind below, so simply
        # reopening a chat with a stale draft is never itself treated
        # as "the user started typing".
        message_input.text = self._drafts.get(identity_key, "")
        send_btn = PillButton(text="Send", size_hint_x=None, width=dp(76))

        # Phase 19.24 -- Typing Indicator: every composer keystroke
        # (Kivy TextInput has no separate "user typed" event -- this
        # fires for ANY text change, edit-mode pre-fill included, same
        # as gui/chat_window.py's plain Qt textChanged) re-arms the
        # idle timer -- see _on_composer_text_changed()'s own
        # docstring for the full debounce contract.
        message_input.bind(text=lambda inst, text: self._on_composer_text_changed(text))

        def _send(*_):
            text = message_input.text
            if not text.strip():
                return

            # Phase 19.24 -- Typing Indicator: an actual send (ordinary
            # or edit) always ends any outstanding is_typing=True
            # immediately -- mirrors gui/chat_window.py::send_message()'s
            # identical call.
            self._stop_typing_immediately()

            if self._editing_message_id is not None:
                message_id = self._editing_message_id
                expected_version = self._editing_expected_version
                conversation_id = self._active_real_conversation_id
                self._clear_composer_context()
                if conversation_id is None:
                    return
                try:
                    self.session.edit_message(conversation_id, message_id, text, expected_version)
                except Exception as error:  # noqa: BLE001
                    self._append_bubble(identity_key, friendly_error(error), kind="system")
                return

            reply_to_message_id = self._pending_reply_message_id
            self._pending_reply_message_id = None
            if self._composer_context_label is not None:
                self._composer_context_label.text = ""
                self._composer_context_label.height = 0

            self._send_text(identity_key, is_group, text, reply_to_message_id=reply_to_message_id)
            message_input.text = ""

        send_btn.bind(on_release=_send)
        message_input.bind(on_text_validate=lambda *_: _send())
        composer.add_widget(attach_btn)
        composer.add_widget(message_input)
        composer.add_widget(send_btn)
        layout.add_widget(composer)

        self._set_content(layout)

        if is_group:
            history_conversation_id = identity_key
        else:
            # identity_key is the PEER'S USERNAME for a direct chat, not the
            # real conversation UUID load_history() needs. direct_conversation_ids
            # is populated as a side effect of local key establishment or of
            # receiving a key-install packet, but neither of those necessarily
            # happened yet in *this* process lifetime (e.g. after an app
            # restart, when the conversation and its key already existed from
            # a prior session) -- so fall back to the same server round-trip
            # open_direct_conversation()/establish_session_key() already use,
            # which finds-or-creates the conversation and is safe/idempotent
            # to call even if a key hasn't been established yet.
            history_conversation_id = self.session.direct_conversation_ids.get(identity_key)
            if not history_conversation_id:
                try:
                    history_conversation_id = self.session.open_direct_conversation(identity_key)
                except Exception as error:  # noqa: BLE001
                    Logger.warning(f"QRSCS: could not resolve conversation id for {identity_key}: {error}")

        self._active_real_conversation_id = history_conversation_id

        if history_conversation_id:
            try:
                # Phase 19.17C -- messages-disappear-on-reopen fix: the
                # messages_box built above is BRAND NEW every time this
                # method runs, including a reopen of a conversation
                # already visited this session -- without this,
                # load_history()'s dedup would silently skip messages
                # it already emitted once into that now-discarded
                # widget, leaving the new one empty.
                self.session.forget_rendered_history(history_conversation_id)
                self.session.load_history(history_conversation_id, is_group=is_group)
            except Exception as error:  # noqa: BLE001
                self._append_bubble(identity_key, friendly_error(error), kind="system")
            self._mark_active_read()

    def _set_presence_label(self, label, peer_username):
        """Phase 19.24 -- Presence/Last Seen: "Online" is unchanged;
        "Offline" now upgrades to a real "Last seen ..." line once
        fetch_last_seen() returns (a blocking round trip, same as
        every other synchronous session call already made from this
        method's own call site, open_chat()) -- server/client_
        handler.py::handle_last_seen_request()'s own privacy rule
        (hidden in either direction a block exists) means this simply
        stays "Offline" for a blocked/blocking peer, with no separate
        client-side check needed here."""

        label.markup = True

        if peer_username in self.session.online_users:
            label.text = "[color=1cc98a]Online[/color]"
            return

        label.text = "[color=8e8e98]Offline[/color]"

        try:
            last_seen = self.session.fetch_last_seen(peer_username)
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: fetch_last_seen failed: {error}")
            return

        # The round trip is blocking but the user may have already
        # navigated to a different conversation (or this label's own
        # widget may since have been torn down) by the time it returns.
        if self.active_conversation != peer_username or last_seen is None:
            return

        try:
            label.text = f"[color=8e8e98]{_format_last_seen(last_seen)}[/color]"
        except ReferenceError:
            pass

    def _on_users_updated(self, users):
        def _update(dt):
            for identity_key, avatars in list(self._presence_labels.items()):
                online = identity_key in self.session.online_users
                for avatar in avatars:
                    try:
                        avatar.set_online(online)
                    except ReferenceError:
                        pass
            # Phase 19.24 -- Presence/Last Seen: the open direct chat's
            # own header presence line, kept live by the SAME server-
            # pushed event every OTHER presence indicator in this
            # method already uses -- no polling added.
            if (
                self.active_conversation and not self.active_is_group
                and getattr(self, "_active_presence_label", None) is not None
            ):
                try:
                    self._set_presence_label(self._active_presence_label, self.active_conversation)
                except ReferenceError:
                    pass
        Clock.schedule_once(_update, 0)

    def show_settings(self):
        """Items 13/14 -- a real Settings screen (Change Username,
        Change Password, Change Profile Picture, Logout), replacing
        the bottom nav's previous standalone "Logout" destination.
        All three account-mutation rows call the smallest real
        server endpoints added for this phase (server/client_handler.
        py's handle_change_username_request/handle_change_password_
        request/handle_profile_picture_upload_request) -- nothing here
        edits account state locally without a round-trip."""

        self.active_conversation = None
        # Root/bottom-nav screen -- see show_chats_list()'s identical
        # comment.
        App.get_running_app().back_action = None
        layout = BoxLayout(orientation="vertical")
        layout.add_widget(SectionHeader("Settings"))

        scroll = ScrollView()
        rows = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(8), padding=(dp(16), dp(8)))
        rows.bind(minimum_height=rows.setter("height"))

        account_row = RowCard(height=dp(72))
        account_row.add_widget(TappableCircleAvatar(label_text=self.session.username, diameter=44, online=True))
        account_info = BoxLayout(orientation="vertical")
        username_lbl = Label(text=self.session.username, bold=True, color=TEXT_DARK, halign="left", font_size=dp(15))
        username_lbl.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None)))
        account_info.add_widget(username_lbl)
        account_hint = Label(text="Tap to view your profile picture", color=TEXT_GRAY, halign="left", font_size=dp(11))
        account_hint.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None)))
        account_info.add_widget(account_hint)
        account_row.add_widget(account_info)
        account_row.bind(on_release=lambda *_: self._open_profile_picture_viewer(self.session.username, self.session.username))
        rows.add_widget(account_row)

        for label_text, handler in (
            ("Change Username", self._open_change_username_dialog),
            ("Change Password", self._open_change_password_dialog),
            ("Change Profile Picture", self._open_change_profile_picture_dialog),
            ("Bio", self._open_change_bio_dialog),
            ("Logout", self._logout),
        ):
            row = RowCard(height=dp(56))
            row_lbl = Label(text=label_text, color=DANGER if label_text == "Logout" else TEXT_DARK,
                             halign="left", bold=(label_text == "Logout"), font_size=dp(14))
            row_lbl.bind(width=lambda inst, w: setattr(inst, "text_size", (w, None)))
            row.add_widget(row_lbl)
            row.bind(on_release=lambda *_, h=handler: h())
            rows.add_widget(row)

        layout.add_widget(scroll)
        scroll.add_widget(rows)
        self._set_content(layout)

    def _open_change_username_dialog(self):
        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        box.add_widget(Label(text="New username", size_hint_y=None, height=dp(22), halign="left", color=TEXT_GRAY, font_size=dp(11)))
        field = RoundedField(hint_text=self.session.username)
        box.add_widget(field)
        status_label = Label(text="", size_hint_y=None, height=dp(30), color=DANGER, font_size=dp(11))
        box.add_widget(status_label)
        box.add_widget(Widget())

        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        save_btn = PillButton(text="Save")
        btn_row.add_widget(cancel_btn)
        btn_row.add_widget(save_btn)
        box.add_widget(btn_row)
        popup = Popup(title="Change Username", content=box, size_hint=(0.92, 0.5), background_color=SURFACE)
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())

        def _save(*_):
            new_username = field.text.strip()
            if not new_username:
                status_label.text = "Enter a new username."
                return

            # Phase 19.14 -- change_username()/change_password() below
            # are send_request() calls that BLOCK the calling thread
            # until the server responds (or REQUEST_TIMEOUT_SECONDS
            # elapses). Calling them directly from this on_release
            # handler, on Kivy's own main/UI thread, was a real,
            # physically-reproduced bug: it froze the entire app for
            # up to 10s on any slow/stalled connection, during which
            # SDL/Kivy cannot process new input at all -- any taps that
            # arrived during the freeze were queued and each later
            # fired their own on_release, each blocking for another
            # full timeout in turn, compounding into a much longer
            # apparent "stuck dialog" than a single request ever
            # should be. Backgrounding the request and marshaling the
            # UI update back via Clock.schedule_once (0) is this file's
            # own established pattern for exactly this, already used
            # by LoginScreen._login()/._register().
            save_btn.disabled = True
            status_label.text = "Saving..."

            def _worker():
                try:
                    response = self.session.change_username(new_username)
                except Exception as error:  # noqa: BLE001
                    message = friendly_error(error)
                    Clock.schedule_once(lambda dt: (setattr(save_btn, "disabled", False), setattr(status_label, "text", message)), 0)
                    return
                if not response.get("success"):
                    message = response.get("error") or "Could not change username."
                    Clock.schedule_once(lambda dt: (setattr(save_btn, "disabled", False), setattr(status_label, "text", message)), 0)
                    return

                def _done(dt):
                    popup.dismiss()
                    self.show_settings()
                Clock.schedule_once(_done, 0)

            threading.Thread(target=_worker, daemon=True).start()

        save_btn.bind(on_release=_save)
        popup.open()

    def _open_change_password_dialog(self):
        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        current_field = RoundedField(hint_text="Current password", password=True)
        new_field = RoundedField(hint_text="New password", password=True)
        confirm_field = RoundedField(hint_text="Confirm new password", password=True)
        for f in (current_field, new_field, confirm_field):
            box.add_widget(f)
        status_label = Label(text="", size_hint_y=None, height=dp(30), color=DANGER, font_size=dp(11))
        box.add_widget(status_label)
        box.add_widget(Widget())

        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        save_btn = PillButton(text="Save")
        btn_row.add_widget(cancel_btn)
        btn_row.add_widget(save_btn)
        box.add_widget(btn_row)
        popup = Popup(title="Change Password", content=box, size_hint=(0.92, 0.62), background_color=SURFACE)
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())

        def _save(*_):
            current = current_field.text
            new = new_field.text
            confirm = confirm_field.text
            if not current or not new or not confirm:
                status_label.text = "Fill in all three fields."
                return

            # Backgrounded -- see _open_change_username_dialog's own
            # comment for why a blocking send_request() must never run
            # directly on Kivy's main thread.
            save_btn.disabled = True
            status_label.text = "Saving..."

            def _worker():
                try:
                    response = self.session.change_password(current, new, confirm)
                except Exception as error:  # noqa: BLE001
                    message = friendly_error(error)
                    Clock.schedule_once(lambda dt: (setattr(save_btn, "disabled", False), setattr(status_label, "text", message)), 0)
                    return
                if not response.get("success"):
                    message = response.get("error") or "Could not change password."
                    Clock.schedule_once(lambda dt: (setattr(save_btn, "disabled", False), setattr(status_label, "text", message)), 0)
                    return

                def _done(dt):
                    popup.dismiss()
                    _FriendlyPopup("Password Changed", "Your password has been updated.").open()
                Clock.schedule_once(_done, 0)

            threading.Thread(target=_worker, daemon=True).start()

        save_btn.bind(on_release=_save)
        popup.open()

    def _open_change_bio_dialog(self):
        """Phase 19.22 -- Part F: mirrors _open_change_username_dialog()
        exactly. ClientSession.fetch_bio()/change_bio() are the same
        methods client/session.py's own Settings uses -- no separate
        implementation."""

        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        box.add_widget(Label(text="Bio", size_hint_y=None, height=dp(22), halign="left", color=TEXT_GRAY, font_size=dp(11)))
        field = RoundedField(hint_text="Tell people a little about yourself...", multiline=True, height=dp(90))
        box.add_widget(field)
        status_label = Label(text="", size_hint_y=None, height=dp(30), color=DANGER, font_size=dp(11))
        box.add_widget(status_label)
        box.add_widget(Widget())

        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        save_btn = PillButton(text="Save")
        btn_row.add_widget(cancel_btn)
        btn_row.add_widget(save_btn)
        box.add_widget(btn_row)
        popup = Popup(title="Bio", content=box, size_hint=(0.92, 0.6), background_color=SURFACE)
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())

        def _load_worker():
            try:
                bio = self.session.fetch_bio(self.session.username)
            except Exception as error:  # noqa: BLE001
                Logger.warning(f"QRSCS: fetch_bio failed: {error}")
                bio = ""
            Clock.schedule_once(lambda dt: setattr(field, "text", bio), 0)
        threading.Thread(target=_load_worker, daemon=True).start()

        def _save(*_):
            new_bio = field.text.strip()

            save_btn.disabled = True
            status_label.text = "Saving..."

            def _worker():
                try:
                    response = self.session.change_bio(new_bio)
                except Exception as error:  # noqa: BLE001
                    message = friendly_error(error)
                    Clock.schedule_once(lambda dt: (setattr(save_btn, "disabled", False), setattr(status_label, "text", message)), 0)
                    return
                if not response.get("success"):
                    message = response.get("error") or "Could not save bio."
                    Clock.schedule_once(lambda dt: (setattr(save_btn, "disabled", False), setattr(status_label, "text", message)), 0)
                    return
                Clock.schedule_once(lambda dt: popup.dismiss(), 0)

            threading.Thread(target=_worker, daemon=True).start()

        save_btn.bind(on_release=_save)
        popup.open()

    def _open_change_profile_picture_dialog(self):
        if platform != "android":
            _FriendlyPopup("Change Profile Picture", "Picking an image requires the Android app (no picker in desktop-mode preview).").open()
            return
        self._pick_file_android(self._on_profile_picture_picked)

    def _on_profile_picture_picked(self, filename, data_bytes):
        texture = _decode_image_texture(data_bytes)
        if texture is None:
            _FriendlyPopup("Change Profile Picture", "That file isn't a supported image (PNG/JPG/GIF/BMP/WEBP).").open()
            return

        # Phase 19.22 -- Part E: crop ONCE, here, before upload -- see
        # ImageCropPopup's own docstring for why this replaces the
        # previous "upload the raw picked file unmodified" behavior.
        def _on_cropped(png_bytes):
            if png_bytes is None:
                return
            self._upload_profile_picture_bytes(png_bytes, "image/png")

        ImageCropPopup(texture, _on_cropped).open()

    def _upload_profile_picture_bytes(self, data_bytes, content_type):
        # Backgrounded -- see _open_change_username_dialog's own
        # comment: this can be called from a main-thread callback
        # (ImageCropPopup's Save button), so the same blocking-
        # send_request-on-the-UI-thread risk applies here too.
        def _worker():
            try:
                response = self.session.upload_profile_picture(data_bytes, content_type)
            except Exception as error:  # noqa: BLE001
                message = friendly_error(error)
                Clock.schedule_once(lambda dt: _FriendlyPopup("Change Profile Picture", message).open(), 0)
                return
            if not response.get("success"):
                message = response.get("error") or "Could not update profile picture."
                Clock.schedule_once(lambda dt: _FriendlyPopup("Change Profile Picture", message).open(), 0)
                return
            Clock.schedule_once(lambda dt: _FriendlyPopup("Change Profile Picture", "Your profile picture has been updated.").open(), 0)

        threading.Thread(target=_worker, daemon=True).start()

    def _logout(self):
        try:
            self.session.logout()
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: logout request failed: {error}")
        try:
            self.session.disconnect()
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: disconnect after logout failed: {error}")
        App.get_running_app().return_to_login()

    def _mark_active_read(self):
        if self._active_real_conversation_id:
            try:
                self.session.mark_read(self._active_real_conversation_id)
            except Exception as error:  # noqa: BLE001
                Logger.warning(f"QRSCS: mark_read failed: {error}")

    def _refresh_verified_badge(self, peer):
        raw_state = self.session.get_peer_verification_state(peer)
        mapped = {
            "VERIFIED": "verified", "UNVERIFIED": "unverified", "KEY_CHANGED": "changed",
        }.get(raw_state, "none")
        self.verified_badge.set_state(mapped)

    def _verify_peer(self, peer):
        peer_state = self.session.peers.get(peer)
        if not peer_state:
            self._append_bubble(peer, "This contact hasn't shared their identity with the server yet.", kind="system")
            return
        try:
            self.session.confirm_peer_verified(peer, peer_state["fingerprint"])
            # Phase 19.23 -- Issue 2: verification success is no longer
            # rendered into the chat transcript at all (it used to
            # expose the fingerprint inline as chat content). The
            # VerifiedBadge refresh below is the ONLY user-visible
            # effect now -- exactly mirroring gui/verify_identity_
            # dialog.py on Desktop, which has never rendered anything
            # into chat history either, only into its own dialog and
            # the persistent header badge. The fingerprint comparison
            # itself still happens (confirm_peer_verified() above,
            # unchanged) and the security/audit data behind it is
            # untouched -- only this chat-visible announcement of it
            # is removed.
        except ValueError as error:
            self._append_bubble(peer, friendly_error(error), kind="system")
        else:
            # Phase 19.23 -- Issue 1: this device just directly
            # verified ``peer`` -- add them to the Chats list
            # immediately (same zero-message-safe preview shape as
            # everywhere else in this phase), not just at this
            # device's next login.
            self._conversation_preview(peer, name=peer, is_group=False)
        self._refresh_verified_badge(peer)

    def _request_verification(self, peer):
        """Phase 19.15 -- the missing UI entry point for the async,
        inbox-mediated verification flow (server/client_handler.py::
        handle_verification_request(), backend since Phase 19.13):
        fire-and-forget send_message(), same as request_verification()
        itself, so no threading needed here (unlike the send_request()
        round trips elsewhere in this file). ``peer``'s own Inbox
        screen is what shows and resolves this -- nothing here decides
        approval."""

        try:
            self.session.request_verification(peer)
        except Exception as error:  # noqa: BLE001
            self._append_bubble(peer, friendly_error(error), kind="system")
            return
        self._append_bubble(peer, f"Verification request sent to {peer}.", kind="system")

    def _send_text(self, identity_key, is_group, text, reply_to_message_id=None, client_message_id=None):
        # Phase 19.24 -- Message Retry: generated BEFORE the risky send
        # call (unless this IS a retry re-using an earlier one -- see
        # _retry_failed_bubble()), not read back from a return value, so
        # it is still available to attach to the FAILED bubble even when
        # send_message()/send_group_message() raises before ever
        # returning anything -- mirrors gui/chat_window.py::
        # send_message()'s identical client_message_id timing exactly.
        if client_message_id is None:
            client_message_id = str(uuid.uuid4())
        try:
            if is_group:
                self.session.send_group_message(
                    identity_key, text, reply_to_message_id=reply_to_message_id,
                    client_message_id=client_message_id,
                )
            else:
                self.session.establish_session_key(identity_key)
                self.session.send_message(
                    identity_key, text, reply_to_message_id=reply_to_message_id,
                    client_message_id=client_message_id,
                )
        except Exception as error:  # noqa: BLE001
            # The bubble is added for a FAILED send too, not just
            # dropped behind a system message -- previously the message
            # text simply vanished from the transcript. STATUS_FAILED
            # here is a fact, not a guess: the send call raised, so the
            # ciphertext never reached the server -- mirrors gui/chat_
            # window.py::send_message()'s identical Task 2 reasoning.
            # _resolved=True/_tick_status="Failed" set immediately
            # (synchronously, before any other send can race in)
            # prevents a LATER, genuinely different message's delivery/
            # queued ack from being misapplied to this one via _on_
            # message_status_updated()'s "first unresolved" FIFO scan.
            bubble = self._append_bubble(identity_key, text, kind="sent", is_group=is_group)
            bubble.client_message_id = client_message_id
            bubble.reply_to_message_id = reply_to_message_id
            bubble._resolved = True
            bubble._tick_status = "Failed"
            bubble.set_status("Failed")
            # A failed bubble will NEVER receive a real server-assigned
            # message_id -- it must not occupy a slot in this FIFO, or
            # a SUBSEQUENT, genuinely different message's real id would
            # be misapplied to it instead (see _bubbles_awaiting_
            # message_id's own __init__ comment for the FIFO contract
            # this would otherwise violate).
            awaiting = self._bubbles_awaiting_message_id.get(identity_key)
            if awaiting and bubble in awaiting:
                awaiting.remove(bubble)
            return
        if not is_group and identity_key == self.active_conversation and not self._active_real_conversation_id:
            self._active_real_conversation_id = self.session.direct_conversation_ids.get(identity_key)
        bubble = self._append_bubble(identity_key, text, kind="sent", is_group=is_group)
        # Phase 19.24 -- Message Retry: carried even on a successful
        # send (not just the failed path above) so a later retry of a
        # bubble that DID fail can be told apart from an ordinary new
        # send by more than just its tick status, and so this send's
        # own client_message_id is genuinely traceable end to end.
        if bubble is not None:
            bubble.client_message_id = client_message_id
            bubble.reply_to_message_id = reply_to_message_id
        self._touch_preview(identity_key, text, incoming=False)

    def _retry_failed_bubble(self, bubble):
        """Phase 19.24 -- Message Retry: re-send a failed bubble's
        original text, reusing its SAME client_message_id (Desktop's
        identical idempotency reasoning -- see _send_text()'s own
        comment). The failed bubble is removed only once the retry
        itself does not raise -- a retry can never leave the transcript
        claiming more than actually happened, mirrors gui/chat_
        window.py::_retry_failed_message()'s identical contract."""

        identity_key = self.active_conversation
        if identity_key is None:
            self._append_bubble(
                self.active_conversation, "Open the conversation again before retrying.", kind="system"
            )
            return
        is_group = identity_key in self.session.groups

        # A failed bubble's own row (anchor) is its direct parent, and
        # the message list box is the anchor's parent -- see _append_
        # bubble()'s own construction for this exact shape.
        if bubble.parent is not None and bubble.parent.parent is not None:
            bubble.parent.parent.remove_widget(bubble.parent)
        pending = self._pending_send_status.get(identity_key)
        if pending and bubble in pending:
            pending.remove(bubble)

        self._send_text(
            identity_key, is_group, bubble.message_text,
            reply_to_message_id=bubble.reply_to_message_id,
            client_message_id=bubble.client_message_id,
        )

    def _append_bubble(self, identity_key, text, *, kind="received", sender_label=None, attachment=None, is_group=False):
        box = self._bubble_rows.get(identity_key)
        if box is None:
            return
        timestamp = datetime.now().strftime("%H:%M")
        status = "Sent" if kind == "sent" else ""
        bubble = Bubble(text, sender_label=sender_label, timestamp=timestamp if kind != "system" else "",
                         status=status, kind=kind, attachment=attachment,
                         on_context_action=self._handle_bubble_context_action)

        # Phase 19.24 (continued) -- see _bubbles_awaiting_message_id's
        # own __init__ comment. A system bubble is never message_id-
        # addressable (mirrors _bubble_context_actions()'s own "kind ==
        # system" gate), so it is never tracked here at all.
        if kind != "system":
            self._bubbles_awaiting_message_id.setdefault(identity_key, []).append(bubble)
        anchor = BoxLayout(size_hint_y=None, height=bubble.height)
        bubble.bind(height=lambda instance, value: setattr(anchor, "height", value))
        if kind == "sent":
            anchor.add_widget(Widget())
            anchor.add_widget(bubble)
            # Item 7 -- only direct-chat sends get delivered/queued/
            # failed acks from the server (see server/client_handler.
            # py's handle_chat relay branch); group sends have no such
            # per-recipient ack, so they are deliberately left out of
            # this queue and simply keep showing "Sent".
            if not is_group:
                # _resolved tracks whether a delivered/queued/failed ack
                # has already updated this bubble's tick -- the list
                # itself is never pruned (unlike before), because a
                # read-receipt watermark (see _on_read_receipt) must be
                # able to reach EVERY one of this peer's sent bubbles,
                # not just the single oldest still-pending one.
                bubble._resolved = False
                bubble._tick_status = "Sent"
                self._pending_send_status.setdefault(identity_key, []).append(bubble)
        elif kind == "system":
            anchor.add_widget(Widget())
            anchor.add_widget(bubble)
            anchor.add_widget(Widget())
        else:
            anchor.add_widget(bubble)
            anchor.add_widget(Widget())
        box.add_widget(anchor)
        Clock.schedule_once(lambda dt: setattr(self._messages_scroll, "scroll_y", 0), 0.05)

        # Phase 19.23 -- Issue 3: lets a caller (specifically a
        # historical own message restoring its real tick state --
        # see _on_message_received()/_on_payload_received()) act on
        # the exact bubble just created, instead of only being able to
        # reach it later via _pending_send_status's FIFO.
        return bubble

    def _on_message_status_updated(self, receiver_username, status):
        def _update(dt):
            pending = self._pending_send_status.get(receiver_username)
            if not pending:
                return
            # Find-in-place, not pop(0): the list is kept for the whole
            # conversation's lifetime now (see _append_bubble's own
            # comment) so a later read-receipt can still reach bubbles
            # this already resolved.
            bubble = next((b for b in pending if not b._resolved), None)
            if bubble is None:
                return
            bubble._resolved = True
            label = {"delivered": "Delivered", "queued": "Queued", "failed": "Failed"}.get(status, status.capitalize())
            bubble._tick_status = label
            bubble.set_status(label)
        Clock.schedule_once(_update, 0)

    # ---------------------------------------------------------------
    # Phase 19.24 (continued) -- Message Lifecycle Events UI.
    # ---------------------------------------------------------------

    def _resolve_next_awaiting_message_id(self, identity_key, message_id):
        """Shared by _on_own_message_id_resolved() (this account's own
        live send -- message_delivered/message_queued) and _on_message_
        id_received() (a received live message, or ANY historical row)
        -- see _bubbles_awaiting_message_id's own __init__ comment for
        why exactly one of those two signals resolves any given bubble,
        never both."""

        pending = self._bubbles_awaiting_message_id.get(identity_key)
        if not pending:
            return
        bubble = pending.pop(0)
        bubble.message_id = message_id
        self._bubbles_by_message_id[message_id] = bubble

    def _on_own_message_id_resolved(self, receiver_username, message_id):
        def _update(dt):
            self._resolve_next_awaiting_message_id(receiver_username, message_id)
        Clock.schedule_once(_update, 0)

    def _on_message_id_received(self, identity_key, message_id):
        def _update(dt):
            # Phase 19.24 (continued) -- a HISTORICAL direct row's
            # identity_key is the real conversation UUID (mobile/
            # session.py::load_history()'s own identity, matching
            # message_received's identical key for that same row), but
            # _append_bubble() registered the bubble under the
            # RESOLVED key (the peer's username -- see _on_message_
            # received()'s own "key = self._resolve_identity_key(...)"
            # step it runs before ever calling _append_bubble()). Must
            # be resolved identically here or the FIFO lookup below
            # would silently find nothing. A no-op for a group (already
            # keyed by conversation_id on both sides) or a LIVE direct
            # message (identity_key is already the sender's username --
            # see mobile/session.py::_handle_chat()'s own identity_key
            # computation).
            key = self._resolve_identity_key(identity_key)
            self._resolve_next_awaiting_message_id(key, message_id)
        Clock.schedule_once(_update, 0)

    def _on_message_lifecycle_state_received(
        self, identity_key, message_id, reply_to_message_id, is_deleted, edit_version, reactions,
        is_pinned=False, pinned_by=None,
    ):
        def _update(dt):
            bubble = self._bubbles_by_message_id.get(message_id)
            if bubble is None:
                return
            if is_deleted:
                bubble.mark_deleted()
                return
            if edit_version and bubble.supports_edit:
                bubble.apply_edit(bubble.message_text or "", edit_version)
            if reply_to_message_id:
                referenced = self._bubbles_by_message_id.get(reply_to_message_id)
                if referenced is not None and referenced.message_text:
                    bubble.set_reply_preview(referenced.message_text)
            if reactions:
                bubble.update_reactions(reactions)
            if is_pinned:
                bubble.set_pinned(True, pinned_by)
        Clock.schedule_once(_update, 0)

    def _on_message_pinned_received(self, conversation_id, message_id, pinned_by, pinned_at):
        def _update(dt):
            bubble = self._bubbles_by_message_id.get(message_id)
            if bubble is not None:
                bubble.set_pinned(True, pinned_by)
        Clock.schedule_once(_update, 0)

    def _on_message_unpinned_received(self, conversation_id, message_id, unpinned_by):
        def _update(dt):
            bubble = self._bubbles_by_message_id.get(message_id)
            if bubble is not None:
                bubble.set_pinned(False)
        Clock.schedule_once(_update, 0)

    def _on_message_edited_received(self, conversation_id, message_id, new_text, editor, edited_at, edit_version):
        def _update(dt):
            bubble = self._bubbles_by_message_id.get(message_id)
            if bubble is not None and bubble.supports_edit:
                bubble.apply_edit(new_text, edit_version)
        Clock.schedule_once(_update, 0)

    def _on_message_deleted_received(self, conversation_id, message_id, deleted_by, deleted_at):
        def _update(dt):
            bubble = self._bubbles_by_message_id.get(message_id)
            if bubble is not None:
                bubble.mark_deleted()
        Clock.schedule_once(_update, 0)

    def _on_reaction_updated_received(self, conversation_id, message_id, actor, action, reaction):
        def _update(dt):
            bubble = self._bubbles_by_message_id.get(message_id)
            if bubble is None:
                return
            reactions = [r for r in bubble.reactions if r.get("user") != actor]
            if action == "add":
                reactions.append({"user": actor, "reaction": reaction})
            bubble.update_reactions(reactions)
        Clock.schedule_once(_update, 0)

    def _handle_bubble_context_action(self, action, bubble):
        """Mirrors gui/chat_window.py::_handle_bubble_context_action()
        exactly -- dispatches a chosen long-press menu action (see
        _bubble_context_actions() above) to the matching ClientSession
        call or composer state change."""

        if action == "reply":
            self._editing_message_id = None
            self._pending_reply_message_id = bubble.message_id
            preview = bubble.message_text or "[Attachment]"
            shown = preview if len(preview) <= 80 else preview[:77] + "…"
            self._set_composer_context(f"Replying to: {shown}")
            return

        if action == "copy":
            if bubble.message_text:
                Clipboard.copy(bubble.message_text)
            return

        if action == "forward":
            self._handle_forward_bubble(bubble)
            return

        if action == "react":
            _open_reaction_picker(lambda emoji: self._send_reaction(bubble, emoji))
            return

        if action == "pin":
            try:
                self.session.pin_message(bubble.message_id)
            except Exception as error:  # noqa: BLE001
                self._append_bubble(self.active_conversation, friendly_error(error), kind="system")
                return
            # Optimistic local update, mirrors gui/chat_window.py's
            # identical immediate-feedback comment -- the eventual
            # message_pinned notification simply re-applies the same
            # state, a harmless no-op repeat.
            bubble.set_pinned(True)
            return

        if action == "unpin":
            try:
                self.session.unpin_message(bubble.message_id)
            except Exception as error:  # noqa: BLE001
                self._append_bubble(self.active_conversation, friendly_error(error), kind="system")
                return
            bubble.set_pinned(False)
            return

        if action == "edit":
            if not bubble.supports_edit or bubble.kind != "sent":
                return
            self._pending_reply_message_id = None
            self._editing_message_id = bubble.message_id
            self._editing_expected_version = bubble.edit_version
            self._set_composer_context("Editing message")
            if self._active_message_input is not None:
                self._active_message_input.text = bubble.message_text or ""
            return

        if action == "retry":
            self._retry_failed_bubble(bubble)
            return

        if action == "delete_me":
            # Phase 19.24 -- Message Retry: a failed bubble never
            # reached the server at all (no real message_id to even
            # address it by) -- "delete for me" here just removes the
            # local, never-sent row, never a server call.
            if bubble.kind == "sent" and getattr(bubble, "_tick_status", None) == "Failed":
                if bubble.parent is not None and bubble.parent.parent is not None:
                    bubble.parent.parent.remove_widget(bubble.parent)
                pending = self._pending_send_status.get(self.active_conversation)
                if pending and bubble in pending:
                    pending.remove(bubble)
                return
            try:
                self.session.delete_message_for_me(bubble.message_id)
            except Exception as error:  # noqa: BLE001
                self._append_bubble(self.active_conversation, friendly_error(error), kind="system")
                return
            # No server broadcast for delete-for-me (mobile/session.py::
            # handle_message_delete_for_me()'s docstring, unchanged from
            # Desktop) -- this is the one action this client must apply
            # to the bubble itself rather than wait for a notification.
            bubble.mark_deleted()
            return

        if action == "delete_everyone":
            if bubble.kind != "sent":
                return
            self._confirm_and_delete_everyone(bubble)
            return

    def _confirm_and_delete_everyone(self, bubble):
        """Real Yes/No confirmation before an irreversible Delete-for-
        everyone request is sent -- mirrors gui/chat_window.py::
        _confirm_delete_for_everyone() on Desktop. _do_delete_for_
        everyone() is the actual action, factored out so tests can call
        it directly and bypass only this popup, same convention as
        _apply_mute_action() vs. _open_mute_popup() above."""

        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        box.add_widget(Label(
            text="This message will be permanently deleted for everyone "
                 "in this conversation. This cannot be undone.",
            halign="left", valign="top", color=TEXT_DARK, font_size=dp(13),
        ))
        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        delete_btn = PillButton(text="Delete")
        btn_row.add_widget(cancel_btn)
        btn_row.add_widget(delete_btn)
        box.add_widget(btn_row)
        popup = Popup(
            title="Delete for Everyone?", content=box, size_hint=(0.88, None),
            height=dp(190), background_color=SURFACE,
        )
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())

        def _confirm(*_):
            popup.dismiss()
            self._do_delete_for_everyone(bubble)

        delete_btn.bind(on_release=_confirm)
        popup.open()

    def _do_delete_for_everyone(self, bubble):
        """The actual Delete-for-everyone request, extracted so tests
        can call it directly without driving the confirmation popup."""

        try:
            self.session.delete_message_for_everyone(bubble.message_id)
        except Exception as error:  # noqa: BLE001
            self._append_bubble(self.active_conversation, friendly_error(error), kind="system")

    def _handle_forward_bubble(self, bubble):
        """Shows a picker of this account's existing conversations
        (direct + group) and forwards ``bubble``'s content to whichever
        one is chosen -- mirrors gui/forward_dialog.py + gui/chat_
        window.py::_forward_bubble_to() exactly, adapted to a Kivy
        popup list."""

        targets = []
        for peer in self.session.direct_conversation_ids:
            targets.append((peer, None, self.conversations.get(peer, {}).get("name", peer)))
        for conversation_id, group in self.session.groups.items():
            targets.append((None, conversation_id, group.get("name") or "Group"))

        if not targets:
            return

        box = BoxLayout(orientation="vertical", spacing=dp(4), padding=dp(8), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        popup = Popup(
            title="Forward to", content=box, size_hint=(0.86, None),
            height=min(dp(56) * len(targets) + dp(60), dp(420)), background_color=SURFACE,
        )

        scroll = ScrollView(size_hint_y=None, height=popup.height - dp(60))
        inner = BoxLayout(orientation="vertical", spacing=dp(4), size_hint_y=None)
        inner.bind(minimum_height=inner.setter("height"))
        for peer_username, conversation_id, label in targets:
            btn = GhostButton(text=label, size_hint_y=None, height=dp(48), font_size=dp(14))

            def _choose(*_, peer_username=peer_username, conversation_id=conversation_id):
                popup.dismiss()
                self._forward_bubble_to(bubble, peer_username, conversation_id)

            btn.bind(on_release=_choose)
            inner.add_widget(btn)
        scroll.add_widget(inner)
        box.add_widget(scroll)

        popup.open()

    def _forward_bubble_to(self, bubble, peer_username, conversation_id):
        """Reuses ClientSession.forward_message() end to end -- see its
        own docstring for why this always produces a genuinely new,
        independently encrypted message rather than reusing ``bubble``'s
        ciphertext. Handles text and attachment (image/file/voice/
        video) bubbles alike -- Bubble.__init__ now retains an
        attachment bubble's decrypted bytes/mime_type/payload_type
        (previously discarded after building the inner content widget,
        which made attachment forwarding impossible here even though
        the underlying protocol/session method was always fully
        payload-type-generic).

        Unlike Desktop's ClientSession.forward_message() (which
        auto-establishes a session key for a direct target as part of
        its own send pipeline), MobileClientSession.forward_message()
        requires the caller to already have one -- mirrors _send_
        attachment()'s own explicit establish_session_key() call for
        this exact reason (a real user forwarding to someone they have
        never messaged before must not hit a silent, unhandled
        RuntimeError)."""

        try:
            if peer_username is not None:
                self.session.establish_session_key(peer_username)
            if bubble._attachment_bytes is not None:
                self.session.forward_message(
                    peer_username, conversation_id, bubble.payload_type,
                    bubble._attachment_bytes,
                    content_metadata={
                        "filename": bubble._attachment_filename,
                        "mime_type": bubble._attachment_mime_type,
                    },
                )
            elif bubble.message_text:
                self.session.forward_message(
                    peer_username, conversation_id, PayloadType.TEXT, bubble.message_text,
                )
        except Exception as error:  # noqa: BLE001
            self._append_bubble(self.active_conversation, friendly_error(error), kind="system")

    def _send_reaction(self, bubble, emoji):
        if self._active_real_conversation_id is None:
            return
        try:
            self.session.add_reaction(self._active_real_conversation_id, bubble.message_id, emoji)
        except Exception as error:  # noqa: BLE001
            self._append_bubble(self.active_conversation, friendly_error(error), kind="system")

    def _set_composer_context(self, text):
        if self._composer_context_label is not None:
            self._composer_context_label.text = text
            self._composer_context_label.height = dp(24)

    def _clear_composer_context(self):
        self._pending_reply_message_id = None
        self._editing_message_id = None
        self._editing_expected_version = 0
        if self._composer_context_label is not None:
            self._composer_context_label.text = ""
            self._composer_context_label.height = 0
        if self._active_message_input is not None:
            self._active_message_input.text = ""

    # ---------------------------------------------------------------
    # Phase 19.24 -- Typing Indicator.
    # ---------------------------------------------------------------

    def _on_composer_text_changed(self, text):
        """
        Debounced typing-indicator sender -- mirrors gui/chat_window.py
        ::_on_composer_text_changed() exactly (same "arm once, re-arm
        on every keystroke, empty composer stops immediately" debounce
        contract), adapted to Kivy's Clock.schedule_once() in place of
        a QTimer. A no-op with no conversation open.
        """

        conversation_id = self._active_real_conversation_id

        if conversation_id is None:
            return

        if not text:
            self._stop_typing_immediately()
            return

        if not self._typing_active:
            self._typing_active = True
            self.session.send_typing_indicator(conversation_id, True)

        if self._typing_stop_event is not None:
            self._typing_stop_event.cancel()

        self._typing_stop_event = Clock.schedule_once(self._send_typing_stopped, 3.0)

    def _send_typing_stopped(self, *_args):
        """Idle-timeout fire (3s) -- see _on_composer_text_changed()'s
        own docstring for the full debounce contract this is one half
        of. Kivy's Clock hands the scheduled callback its own dt as a
        positional arg -- absorbed by *_args, unused."""

        self._stop_typing_immediately()

    def _stop_typing_immediately(self):
        """Shared by the idle timeout, an actual send, and clearing the
        composer back to empty -- mirrors gui/chat_window.py's
        identical method exactly."""

        if self._typing_stop_event is not None:
            self._typing_stop_event.cancel()
            self._typing_stop_event = None

        if not self._typing_active:
            return

        self._typing_active = False

        conversation_id = self._active_real_conversation_id

        if conversation_id is not None:
            self.session.send_typing_indicator(conversation_id, False)

    def _on_typing_indicator_received(self, conversation_id, username, is_typing):
        """
        A live typing hint arrived -- mirrors gui/chat_window.py::
        handle_typing_indicator_received() exactly, including the
        per-sender 5-second auto-expiry (self._typing_senders
        [conversation_id][username], a Kivy Clock event restarted on
        every is_typing=True for that exact sender) and the "only
        acted on when it is the conversation currently open" gate.
        """

        if conversation_id != self._active_real_conversation_id:
            return

        senders = self._typing_senders.setdefault(conversation_id, {})

        existing_event = senders.get(username)

        if is_typing:

            if existing_event is not None:
                existing_event.cancel()

            senders[username] = Clock.schedule_once(
                lambda dt: self._expire_typing_sender(conversation_id, username), 5.0
            )

        else:

            if existing_event is not None:
                existing_event.cancel()

            senders.pop(username, None)

        self._render_typing_status(conversation_id)

    def _expire_typing_sender(self, conversation_id, username):
        """A typing sender's own 5-second auto-expiry fired -- see
        _on_typing_indicator_received()'s own docstring for why this
        exists (a dropped connection mid-type never sends the matching
        is_typing=False)."""

        senders = self._typing_senders.get(conversation_id)

        if senders is not None:
            senders.pop(username, None)

        self._render_typing_status(conversation_id)

    def _render_typing_status(self, conversation_id):
        """Renders self._typing_status_label from self._typing_senders'
        current state -- a no-op if that conversation is not the one
        currently open, or if this window has no such label right now
        (e.g. the chat view was already torn down)."""

        if conversation_id != self._active_real_conversation_id:
            return

        if self._typing_status_label is None:
            return

        senders = self._typing_senders.get(conversation_id) or {}
        names = sorted(senders.keys())

        if not names:
            text = ""
        elif len(names) == 1:
            text = f"{names[0]} is typing…"
        elif len(names) == 2:
            text = f"{names[0]} and {names[1]} are typing…"
        else:
            text = f"{len(names)} people are typing…"

        self._typing_status_label.text = text
        self._typing_status_label.height = dp(16) if text else 0

    def _on_connection_changed_stop_typing_events(self, connected):
        """A disconnect must stop EVERY typing-related Clock event this
        screen owns -- mirrors gui/chat_window.py::_on_connection_
        changed_stop_typing_timers() exactly. A no-op on connected=True."""

        if connected:
            return

        if self._typing_stop_event is not None:
            self._typing_stop_event.cancel()
            self._typing_stop_event = None

        for senders in self._typing_senders.values():
            for event in senders.values():
                event.cancel()

        self._typing_senders = {}

    # ---------------------------------------------------------------
    # Attachments (real Android SAF pickers; desktop-mode fallback)
    # ---------------------------------------------------------------

    def _start_attachment_pick(self, identity_key, is_group):
        """
        Phase 19.24 -- Attachment Menu: a small, consistent menu
        exposing every attachment kind (Photo/File, Voice Message,
        Video Message) -- mirrors gui/input_bar.py's/web/client's own
        identical three choices, so the feature looks and behaves like
        the same app across all three clients.

        Voice/Video recording (this closure pass): real
        android.media.MediaRecorder via pyjnius, replacing the earlier
        honest "not yet available" placeholder (plyer's own Windows
        audio backend crashed outright in THIS dev environment -- a
        Windows-only failure, irrelevant to the actual Android target,
        so a native Android API was the correct fix all along, not a
        different cross-platform library). Written against Android's
        documented MediaRecorder API and this project's own established
        pyjnius/activity-callback conventions (see _pick_file_android()
        below) -- this development environment has no physical Android
        device or emulator to run it on, so it is implemented and wired
        into the real UI/encryption pipeline but NOT physically
        verified; see docs/architecture/mobile_client.md for the exact,
        honest status. On a non-Android build (desktop-mode preview),
        both still show the same honest placeholder the file picker
        already uses, since there is no Android MediaRecorder to call.
        """

        box = BoxLayout(orientation="vertical", spacing=dp(4), padding=dp(8), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        options = [
            ("file", "\U0001F5BC️ Photo / File"),
            ("voice", "\U0001F3A4 Voice Message"),
            ("video", "\U0001F3AC Video Message"),
        ]
        popup = Popup(
            title="Attach", content=box, size_hint=(0.8, None),
            height=dp(56) * len(options) + dp(60), background_color=SURFACE,
        )

        def _choose(choice):
            popup.dismiss()
            if choice == "file":
                if platform == "android":
                    self._pick_file_android(
                        lambda name, data: self._send_attachment(identity_key, is_group, name, data)
                    )
                else:
                    self._append_bubble(
                        identity_key,
                        "File attachments require the Android app (no picker in desktop-mode preview).",
                        kind="system",
                    )
            elif choice == "voice":
                if platform == "android":
                    self._record_voice_android(identity_key, is_group)
                else:
                    self._append_bubble(
                        identity_key,
                        "Voice recording requires the Android app (no microphone access in "
                        "desktop-mode preview) -- received voice messages can still be played back.",
                        kind="system",
                    )
            else:
                if platform == "android":
                    self._record_video_android(identity_key, is_group)
                else:
                    self._append_bubble(
                        identity_key,
                        "Video recording requires the Android app (no camera access in "
                        "desktop-mode preview) -- received video messages can still be saved.",
                        kind="system",
                    )

        for choice, label in options:
            btn = GhostButton(text=label, size_hint_y=None, height=dp(48), font_size=dp(14))
            btn.bind(on_release=lambda *_, choice=choice: _choose(choice))
            box.add_widget(btn)

        popup.open()

    def _request_android_permission(self, permission_name, on_result):
        """Real Android runtime permission request (RECORD_AUDIO/CAMERA
        are both "dangerous" permissions requiring this even though
        buildozer.spec's own android.permissions already declares them
        in the manifest -- a manifest declaration alone does not grant
        a dangerous permission on API 23+). ``on_result(granted: bool)``
        is always called back on the main/Kivy thread via Clock,
        exactly like _pick_file_android()'s own activity-result
        marshaling below, since android.permissions' own callback runs
        off the Kivy thread."""

        try:
            from android.permissions import Permission, check_permission, request_permissions
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: Android permissions API unavailable: {error}")
            Clock.schedule_once(lambda dt: on_result(False), 0)
            return

        permission = getattr(Permission, permission_name)
        if check_permission(permission):
            Clock.schedule_once(lambda dt: on_result(True), 0)
            return

        def _callback(permissions, grants):
            granted = bool(grants) and all(grants)
            Clock.schedule_once(lambda dt: on_result(granted), 0)

        request_permissions([permission], _callback)

    def _record_voice_android(self, identity_key, is_group):
        """Requests RECORD_AUDIO, then opens the real recorder popup on
        grant. Denial is reported honestly, never silently ignored."""

        def _on_permission(granted):
            if not granted:
                self._append_bubble(
                    identity_key,
                    "Microphone permission was denied -- voice recording needs it.",
                    kind="system",
                )
                return
            self._open_media_recorder_popup(identity_key, is_group, mode="voice")

        self._request_android_permission("RECORD_AUDIO", _on_permission)

    def _record_video_android(self, identity_key, is_group):
        """Requests CAMERA (and RECORD_AUDIO, for the video's own audio
        track), then opens the real recorder popup on grant."""

        def _on_audio_result(audio_granted):
            def _on_camera_result(camera_granted):
                if not audio_granted or not camera_granted:
                    self._append_bubble(
                        identity_key,
                        "Camera/microphone permission was denied -- video recording needs both.",
                        kind="system",
                    )
                    return
                self._open_media_recorder_popup(identity_key, is_group, mode="video")

            self._request_android_permission("CAMERA", _on_camera_result)

        self._request_android_permission("RECORD_AUDIO", _on_audio_result)

    def _open_media_recorder_popup(self, identity_key, is_group, mode):
        """Real android.media.MediaRecorder recording -- voice (audio-
        only) or video (camera + audio). Mirrors gui/media_recorder_
        dialog.py's own record/Stop-and-Send/Cancel/duration-cap
        contract exactly (MAX_VOICE_SECONDS=120/MAX_VIDEO_SECONDS=60),
        and hands the recorded file to the EXACT SAME _send_attachment()
        encrypt/send pipeline every other attachment already uses --
        this needed no new encryption code, only a real source of
        bytes. Video recording additionally needs a real camera preview
        surface: a native android.view.SurfaceView is added directly to
        PythonActivity's own Android view hierarchy (layered behind
        Kivy's own GL surface, which is itself transparent-background
        by default) for the camera to render into, released the moment
        recording stops -- Kivy's own widget tree has no camera-preview
        primitive of its own to reuse."""

        from jnius import autoclass

        MediaRecorder = autoclass("android.media.MediaRecorder")
        AudioSource = autoclass("android.media.MediaRecorder$AudioSource")
        VideoSource = autoclass("android.media.MediaRecorder$VideoSource")
        OutputFormat = autoclass("android.media.MediaRecorder$OutputFormat")
        AudioEncoder = autoclass("android.media.MediaRecorder$AudioEncoder")
        VideoEncoder = autoclass("android.media.MediaRecorder$VideoEncoder")

        is_video = mode == "video"
        max_seconds = MAX_VIDEO_SECONDS if is_video else MAX_VOICE_SECONDS
        suffix = ".mp4" if is_video else ".m4a"
        fd, tmp_path = tempfile.mkstemp(prefix=f"qrscs_rec_{mode}_", suffix=suffix)
        os.close(fd)

        recorder = MediaRecorder()
        surface_view = None
        try:
            if is_video:
                # VideoSource.CAMERA (the legacy, pre-Camera2 recording
                # path MediaRecorder itself still fully supports through
                # this API level) needs a real preview Surface to be
                # attached BEFORE prepare() -- a native SurfaceView,
                # since Kivy's own window is a single GL surface with no
                # per-widget Surface Android's camera stack can target.
                PythonActivity = autoclass("org.kivy.android.PythonActivity")
                SurfaceView = autoclass("android.view.SurfaceView")
                LayoutParams = autoclass("android.view.ViewGroup$LayoutParams")
                activity = PythonActivity.mActivity
                surface_view = SurfaceView(activity)
                activity.addContentView(
                    surface_view, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT)
                )
                holder = surface_view.getHolder()
                recorder.setAudioSource(AudioSource.MIC)
                recorder.setVideoSource(VideoSource.CAMERA)
                recorder.setOutputFormat(OutputFormat.MPEG_4)
                recorder.setAudioEncoder(AudioEncoder.AAC)
                recorder.setVideoEncoder(VideoEncoder.H264)
                recorder.setVideoSize(640, 480)
                recorder.setPreviewDisplay(holder.getSurface())
            else:
                recorder.setAudioSource(AudioSource.MIC)
                recorder.setOutputFormat(OutputFormat.MPEG_4)
                recorder.setAudioEncoder(AudioEncoder.AAC)
            recorder.setOutputFile(tmp_path)
            recorder.prepare()
            recorder.start()
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: MediaRecorder failed to start ({mode}): {error}")
            try:
                recorder.release()
            except Exception:  # noqa: BLE001
                pass
            if surface_view is not None:
                self._remove_android_view(surface_view)
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            self._append_bubble(
                identity_key,
                f"Could not start {'video' if is_video else 'voice'} recording on this device.",
                kind="system",
            )
            return

        state = {"elapsed": 0, "stopped": False}
        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        timer_label = Label(text="00:00", font_size=dp(28), bold=True, color=TEXT_DARK, size_hint_y=None, height=dp(50))
        box.add_widget(timer_label)
        status_label = Label(
            text="Recording…", font_size=dp(12), color=TEXT_GRAY, size_hint_y=None, height=dp(20),
        )
        box.add_widget(status_label)
        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        stop_btn = PillButton(text="Stop && Send")
        btn_row.add_widget(cancel_btn)
        btn_row.add_widget(stop_btn)
        box.add_widget(btn_row)
        popup = Popup(
            title="Video Message" if is_video else "Voice Message", content=box,
            size_hint=(0.85, None), height=dp(220), background_color=SURFACE, auto_dismiss=False,
        )

        def _tick(dt):
            if state["stopped"]:
                return False
            state["elapsed"] += 1
            minutes, seconds = divmod(state["elapsed"], 60)
            timer_label.text = f"{minutes:02d}:{seconds:02d}"
            if state["elapsed"] >= max_seconds:
                _finish(send=True)
            return not state["stopped"]

        tick_event = Clock.schedule_interval(_tick, 1)

        def _finish(send):
            if state["stopped"]:
                return
            state["stopped"] = True
            tick_event.cancel()
            popup.dismiss()
            try:
                recorder.stop()
            except Exception as error:  # noqa: BLE001
                Logger.warning(f"QRSCS: MediaRecorder stop failed ({mode}): {error}")
                send = False
            finally:
                try:
                    recorder.release()
                except Exception:  # noqa: BLE001
                    pass
                if surface_view is not None:
                    self._remove_android_view(surface_view)

            if not send or state["elapsed"] < 1:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                return

            # File-existence/readability validation: recorder.stop()
            # raising is already handled above (send=False), but a
            # stop() that returns successfully is not itself proof the
            # output file exists and is non-empty -- an interrupted
            # recording (e.g. the OS reclaimed the mic mid-write) can
            # leave a missing or zero-byte file. Caught explicitly
            # rather than letting an uncaught OSError/ValueError
            # propagate out of this Kivy button callback.
            try:
                if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
                    raise OSError(f"recording output file missing or empty: {tmp_path}")
                with open(tmp_path, "rb") as f:
                    data_bytes = f.read()
            except OSError as error:
                Logger.warning(f"QRSCS: recorded {mode} file unreadable: {error}")
                self._append_bubble(
                    identity_key,
                    f"The {'video' if is_video else 'voice'} recording could not be saved.",
                    kind="system",
                )
                return
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

            filename = "video-message.mp4" if is_video else "voice-message.m4a"
            self._send_attachment(identity_key, is_group, filename, data_bytes)

        cancel_btn.bind(on_release=lambda *_: _finish(send=False))
        stop_btn.bind(on_release=lambda *_: _finish(send=True))

        popup.open()

    def _remove_android_view(self, view):
        """Detaches a native Android View this app added directly to
        the activity's own view hierarchy (the camera preview
        SurfaceView above) -- best-effort, mirrors every other
        pyjnius cleanup call in this file in never letting a teardown
        failure propagate as a crash."""

        try:
            parent = view.getParent()
            if parent is not None:
                parent.removeView(view)
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: failed to remove native view: {error}")

    def _pick_file_android(self, on_picked):
        try:
            from jnius import autoclass
            from android import activity
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: Android file picker unavailable: {error}")
            return

        Intent = autoclass("android.content.Intent")
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        intent = Intent(Intent.ACTION_GET_CONTENT)
        intent.setType("*/*")
        intent.addCategory(Intent.CATEGORY_OPENABLE)

        self._pending_pick_callback = on_picked

        def _on_activity_result(request_code, result_code, data):
            if request_code != 9001:
                return
            Activity = autoclass("android.app.Activity")
            callback = self._pending_pick_callback
            self._pending_pick_callback = None
            if result_code != Activity.RESULT_OK or data is None or callback is None:
                return
            try:
                uri = data.getData()
                name, content = self._read_android_uri(uri)
            except Exception as error:  # noqa: BLE001
                Logger.warning(f"QRSCS: reading picked file failed: {error}")
                return
            Clock.schedule_once(lambda dt: callback(name, content), 0)

        activity.bind(on_activity_result=_on_activity_result)
        PythonActivity.mActivity.startActivityForResult(intent, 9001)

    def _read_android_uri(self, uri):
        from jnius import autoclass

        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        resolver = PythonActivity.mActivity.getContentResolver()

        name = None
        cursor = resolver.query(uri, None, None, None, None)
        if cursor is not None:
            try:
                if cursor.moveToFirst():
                    idx = cursor.getColumnIndex("_display_name")
                    if idx != -1:
                        name = cursor.getString(idx)
            finally:
                cursor.close()
        if not name:
            name = "attachment"

        input_stream = resolver.openInputStream(uri)
        chunk = bytearray(65536)
        output = bytearray()
        n = input_stream.read(chunk)
        while n != -1:
            output.extend(chunk[:n])
            n = input_stream.read(chunk)
        input_stream.close()
        return name, bytes(output)

    def _send_attachment(self, identity_key, is_group, filename, data_bytes):
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        try:
            if is_group:
                self.session.send_attachment(None, identity_key, data_bytes, filename, mime_type)
            else:
                self.session.establish_session_key(identity_key)
                self.session.send_attachment(identity_key, None, data_bytes, filename, mime_type)
        except Exception as error:  # noqa: BLE001
            self._append_bubble(identity_key, friendly_error(error), kind="system")
            return
        if not is_group and identity_key == self.active_conversation and not self._active_real_conversation_id:
            self._active_real_conversation_id = self.session.direct_conversation_ids.get(identity_key)
        self._append_bubble(identity_key, None, kind="sent", attachment=(filename, data_bytes, mime_type, None), is_group=is_group)
        preview = "[Image]" if classify_attachment(filename) == PayloadType.IMAGE else f"[File] {filename}"
        self._touch_preview(identity_key, preview, incoming=False)

    # ---------------------------------------------------------------
    # Saving a RECEIVED attachment to real device storage (Part 16):
    # a small, additive Android SAF "create document" flow, parallel
    # to the existing pick-a-file flow above -- writes the SAME
    # decrypted bytes handed to the bubble at receive time, so a
    # SHA-256 of the saved file is a genuine end-to-end proof, not a
    # re-fetch/re-decrypt.
    # ---------------------------------------------------------------

    def _save_attachment_android(self, filename, mime_type, data_bytes):
        if platform != "android":
            _FriendlyPopup("Save", "Saving files requires the Android app (no storage picker in desktop-mode preview).").open()
            return
        try:
            from jnius import autoclass
            from android import activity
        except Exception as error:  # noqa: BLE001
            Logger.warning(f"QRSCS: Android save picker unavailable: {error}")
            _FriendlyPopup("Save", "Saving isn't available on this device.").open()
            return

        Intent = autoclass("android.content.Intent")
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.setType(mime_type or "application/octet-stream")
        intent.putExtra(Intent.EXTRA_TITLE, filename)

        self._pending_save_payload = data_bytes

        def _on_activity_result(request_code, result_code, data):
            if request_code != 9002:
                return
            Activity = autoclass("android.app.Activity")
            payload = self._pending_save_payload
            self._pending_save_payload = None
            if result_code != Activity.RESULT_OK or data is None or payload is None:
                return
            try:
                uri = data.getData()
                resolver = PythonActivity.mActivity.getContentResolver()
                output_stream = resolver.openOutputStream(uri)
                output_stream.write(payload)
                output_stream.close()
            except Exception as error:  # noqa: BLE001
                Logger.warning(f"QRSCS: saving attachment failed: {error}")
                Clock.schedule_once(lambda dt: _FriendlyPopup("Save", friendly_error(error)).open(), 0)
                return
            Clock.schedule_once(lambda dt: _FriendlyPopup("Saved", f"{filename} was saved.").open(), 0)

        activity.bind(on_activity_result=_on_activity_result)
        PythonActivity.mActivity.startActivityForResult(intent, 9002)

    # ---------------------------------------------------------------
    # Groups
    # ---------------------------------------------------------------

    def show_groups_list(self):
        self.active_conversation = None
        # Root/bottom-nav screen -- see show_chats_list()'s identical
        # comment.
        App.get_running_app().back_action = None
        layout = BoxLayout(orientation="vertical")
        layout.add_widget(SectionHeader("Archived Groups" if self._show_archived else "Groups"))

        # Phase 19.24 -- Archive: mirrors show_chats_list()'s identical
        # toggle.
        toggle_row = BoxLayout(size_hint_y=None, height=dp(40), padding=(dp(16), 0))
        toggle_row.add_widget(Widget())
        archived_btn = PillButton(
            text="Back to Groups" if self._show_archived else "Archived",
            size_hint_x=None, width=dp(120) if self._show_archived else dp(84),
            font_size=dp(12), height=dp(36),
        )
        archived_btn.bind(on_release=lambda *_: self._toggle_archived_groups())
        toggle_row.add_widget(archived_btn)
        layout.add_widget(toggle_row)

        scroll = ScrollView()
        rows = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(8), padding=(dp(16), dp(8)))
        rows.bind(minimum_height=rows.setter("height"))

        # Phase 19.24 -- Archive: same local-only filter as show_chats_
        # list()'s identical comment.
        visible_groups = [
            (conversation_id, group) for conversation_id, group in self.session.groups.items()
            if self.session.is_conversation_archived(conversation_id) == self._show_archived
        ]

        if not visible_groups:
            rows.add_widget(Label(
                text="No groups yet.\nTap + to start one." if not self._show_archived else "No archived groups.",
                size_hint_y=None, height=dp(80), color=TEXT_GRAY, font_size=dp(13),
            ))
        for conversation_id, group in visible_groups:
            entry = self._conversation_preview(conversation_id, name=group["name"], is_group=True)
            members = group.get("members", [])
            preview = entry.get("last_message") or f"{len(members)} member(s)"
            row = RowCard()
            row.add_widget(CircleAvatar(entry["name"], diameter=48))
            info = BoxLayout(orientation="vertical")
            info.add_widget(Label(text=entry["name"], bold=True, color=TEXT_DARK, halign="left", font_size=dp(15)))
            info.add_widget(Label(text=preview, color=TEXT_GRAY, halign="left", font_size=dp(12), shorten=True))
            row.add_widget(info)
            row.bind(on_release=lambda *_, cid=conversation_id: self.open_chat(cid))
            row.add_widget(self._build_mute_button(conversation_id, self.show_groups_list, is_group=True))
            rows.add_widget(row)

        layout.add_widget(scroll)
        scroll.add_widget(rows)
        self._set_content(layout)

    def _toggle_archived_groups(self):
        self._show_archived = not self._show_archived
        self.show_groups_list()

    def _open_profile_picture_viewer(self, username, display_name):
        """Item 12 -- tap a peer's avatar in the chat header to view
        their profile picture full-size. View-only by design: reuses
        ImageViewerPopup as-is, which offers Close only -- no save/
        download/share/export/filesystem-path exposure, unlike the
        received-attachment bubble viewer which deliberately does
        offer Save (that flow is for content the user was actually
        sent, not another person's account profile picture)."""

        # Backgrounded -- see _open_change_username_dialog's own
        # comment for why a blocking send_request() must never run
        # directly on Kivy's main thread (this is a tap handler,
        # called on that thread, same as every dialog opener here).
        def _on_result(image_bytes):
            # Texture creation touches Kivy/GL state, so it must run
            # here (inside the Clock.schedule_once callback -- the
            # main thread), never inside _worker() below.
            if not image_bytes:
                _FriendlyPopup("Profile Picture", f"{display_name} has not set a profile picture yet.").open()
                return
            texture = _decode_image_texture(image_bytes)
            if texture is None:
                _FriendlyPopup("Profile Picture", "Unable to display this profile picture.").open()
                return
            ImageViewerPopup(texture).open()

        def _worker():
            try:
                image_bytes = self.session.fetch_profile_picture(username)
            except Exception as error:  # noqa: BLE001
                message = friendly_error(error)
                Clock.schedule_once(lambda dt: _FriendlyPopup("Profile Picture", message).open(), 0)
                return
            Clock.schedule_once(lambda dt: _on_result(image_bytes), 0)

        threading.Thread(target=_worker, daemon=True).start()

    def _open_create_group_dialog(self, initial_name="", initial_members=None):
        initial_members = list(initial_members or [])
        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        box.add_widget(Label(text="Group name", size_hint_y=None, height=dp(22), halign="left", color=TEXT_GRAY, font_size=dp(11)))
        name_field = RoundedField(hint_text="Enter a group name", text=initial_name)
        box.add_widget(name_field)
        status_label = Label(text="", size_hint_y=None, height=dp(22), color=DANGER, font_size=dp(11))
        box.add_widget(status_label)

        picked = {"members": initial_members}
        pick_row = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        pick_summary = Label(
            text=f"{len(initial_members)} member(s) selected" if initial_members else "No members selected",
            color=TEXT_GRAY, halign="left", font_size=dp(12),
        )
        pick_btn = GhostButton(text="Search members", size_hint_x=None, width=dp(130))
        pick_row.add_widget(pick_summary)
        pick_row.add_widget(pick_btn)
        box.add_widget(pick_row)

        popup = Popup(title="Create Group", content=box, size_hint=(0.92, 0.62), background_color=SURFACE)

        def _open_member_picker(*_):
            # Phase 19.16 -- see _open_user_search_screen()'s own
            # docstring for why this is a full screen, not a Popup.
            # Create Group itself stays a Popup (its own TextInput
            # works fine); this still closes it first and reopens it
            # afterwards (pre-filled), now purely so the search screen
            # underneath isn't hidden behind a stale, still-open Create
            # Group popup while the user is picking members.
            name_now = name_field.text
            current_members = list(picked["members"])
            popup.dismiss()

            def _reopen(members):
                self.show_groups_list()
                self._open_create_group_dialog(initial_name=name_now, initial_members=members)

            self._open_user_search_screen(
                "Add Group Members", multi=True,
                on_done=_reopen, on_cancel=lambda: _reopen(current_members),
            )

        pick_btn.bind(on_release=_open_member_picker)

        btn_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        cancel_btn = GhostButton(text="Cancel")
        create_btn = PillButton(text="Create")
        btn_row.add_widget(cancel_btn)
        btn_row.add_widget(create_btn)
        box.add_widget(btn_row)
        cancel_btn.bind(on_release=lambda *_: popup.dismiss())

        def _create(*_):
            name = name_field.text.strip()
            members = picked["members"]
            if not name or not members:
                status_label.text = "Enter a group name and select at least one member."
                return
            try:
                self.session.create_group(name, members)
            except Exception as error:  # noqa: BLE001
                status_label.text = friendly_error(error)
                return
            popup.dismiss()

        create_btn.bind(on_release=_create)
        popup.open()

    def _open_group_members_dialog(self, conversation_id):
        """Member list + admin-only Remove (Phase 19.13 -- Group
        Admin). Hiding Remove for a non-admin here is a convenience
        only -- server/client_handler.py::handle_group_remove_member()
        re-derives the admin from the database on every call and
        rejects anyone else, so this dialog cannot itself grant
        anything a non-admin client could not already have been
        refused by the server."""

        group = self.session.groups.get(conversation_id, {})
        members = group.get("members", [])
        is_admin = group.get("admin") == self.session.username

        box = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(16))
        scroll = ScrollView(size_hint_y=1)
        rows = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(6))
        rows.bind(minimum_height=rows.setter("height"))
        scroll.add_widget(rows)
        box.add_widget(scroll)

        popup = Popup(title=f"Members ({group.get('name', 'Group')})", content=box, size_hint=(0.9, 0.7), background_color=SURFACE)

        def _render():
            rows.clear_widgets()
            for username in members:
                row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
                label = f"{username} (admin)" if username == group.get("admin") else username
                row.add_widget(Label(text=label, color=TEXT_DARK, font_size=dp(13), halign="left"))
                if is_admin and username != self.session.username and username != group.get("admin"):
                    remove_btn = GhostButton(text="Remove", size_hint_x=None, width=dp(76), font_size=dp(11))
                    remove_btn.color = DANGER

                    def _remove(*_, target=username):
                        try:
                            result = self.session.remove_group_member(conversation_id, target)
                        except Exception as error:  # noqa: BLE001
                            _FriendlyPopup("Remove Member", friendly_error(error)).open()
                            return
                        if not result.get("success"):
                            _FriendlyPopup("Remove Member", result.get("error") or "Could not remove that member.").open()
                            return
                        if target in members:
                            members.remove(target)
                        _render()

                    remove_btn.bind(on_release=_remove)
                    row.add_widget(remove_btn)
                rows.add_widget(row)

        _render()
        popup.open()

    def _open_add_members_dialog(self, conversation_id):
        group = self.session.groups.get(conversation_id, {})
        existing = set(group.get("members", []))

        def _on_members_picked(usernames):
            self.open_chat(conversation_id)
            if not usernames:
                return
            try:
                self.session.add_group_members(conversation_id, usernames)
            except Exception as error:  # noqa: BLE001
                _FriendlyPopup("Add Members", friendly_error(error)).open()
                return
            # Phase 19.13 -- Group Admin: a non-admin's request does
            # not add anyone immediately, it goes to the admin's Inbox
            # (server/client_handler.py::handle_group_add_members()).
            # The admin's own direct add still completes right away
            # (group_members_added arrives the normal way) -- this is
            # purely telling a non-admin requester what just happened,
            # not a different action.
            is_admin = group.get("admin") == self.session.username
            if not is_admin:
                _FriendlyPopup(
                    "Add Members",
                    "Request sent to the group admin for approval.",
                ).open()

        self._open_user_search_screen(
            f"Add Members ({group.get('name', 'Group')})", multi=True,
            on_done=_on_members_picked, on_cancel=lambda: self.open_chat(conversation_id),
            exclude_usernames=existing,
        )

    def _on_group_created(self, conversation_id, name, members):
        def _update(dt):
            self._conversation_preview(conversation_id, name=name, is_group=True)
            if self.active_conversation is None:
                self.show_groups_list()
        Clock.schedule_once(_update, 0)

    # ---------------------------------------------------------------
    # Inbox (Phase 19.13) -- verification requests + group member-add
    # approval. Reuses the exact synchronous send_request()-then-
    # render pattern show_devices_list() below already established
    # for this file (no separate background-thread plumbing).
    # ---------------------------------------------------------------

    def show_inbox(self):
        self.active_conversation = None
        # Root/bottom-nav screen -- see show_chats_list()'s identical
        # comment.
        App.get_running_app().back_action = None
        layout = BoxLayout(orientation="vertical")
        layout.add_widget(SectionHeader("Inbox", "Refresh", lambda: self.show_inbox()))

        scroll = ScrollView()
        rows = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(8), padding=(dp(16), dp(8)))
        rows.bind(minimum_height=rows.setter("height"))
        status_label = Label(text="Loading...", size_hint_y=None, height=dp(40), color=TEXT_GRAY)
        rows.add_widget(status_label)
        layout.add_widget(scroll)
        scroll.add_widget(rows)
        self._set_content(layout)
        self._inbox_open = True

        try:
            notifications = self.session.load_inbox()
        except Exception as error:  # noqa: BLE001
            status_label.text = friendly_error(error)
            return
        rows.clear_widgets()

        my_username = self.session.username
        # A notification's own dict never names the recipient
        # explicitly (see server/client_handler.py's _serialize_*_
        # notification() docstrings) -- if this account is not the
        # requester, it can only be the recipient, since load_inbox()
        # itself is already scoped to "I am one of the two parties".
        actionable = [n for n in notifications if n.get("status") == "pending" and n.get("requester_username") != my_username]
        sent = [n for n in notifications if n.get("requester_username") == my_username]

        if not actionable and not sent:
            rows.add_widget(Label(text="Nothing here yet.", size_hint_y=None, height=dp(60), color=TEXT_GRAY))

        for notification in actionable:
            rows.add_widget(self._build_inbox_card(notification, status_label))

        for notification in sent:
            if notification.get("status") == "pending":
                continue  # already covered by "actionable" if it were ours to act on; a sent-and-still-pending one has nothing to show yet
            rows.add_widget(self._build_inbox_history_row(notification))

    def _inbox_card_text(self, notification):
        requester = notification.get("requester_username", "Someone")
        if notification.get("type") == "verification_request":
            return f"{requester} wants to verify your identity."
        candidate = notification.get("candidate_username", "someone")
        group_name = notification.get("group_name") or "your group"
        return f"{requester} wants to add {candidate} to \"{group_name}\"."

    def _build_inbox_card(self, notification, status_label):
        card = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(96), padding=dp(12), spacing=dp(6))
        with card.canvas.before:
            Color(*SURFACE)
            rect = RoundedRectangle(pos=card.pos, size=card.size, radius=[dp(12)])
        card.bind(pos=lambda *_: setattr(rect, "pos", card.pos), size=lambda *_: setattr(rect, "size", card.size))

        title = "Verification Request" if notification.get("type") == "verification_request" else "Group Member Request"
        card.add_widget(Label(text=title, bold=True, color=TEXT_DARK, font_size=dp(13), size_hint_y=None, height=dp(20), halign="left"))
        card.add_widget(Label(text=self._inbox_card_text(notification), color=TEXT_GRAY, font_size=dp(12), size_hint_y=None, height=dp(32), halign="left"))

        btn_row = BoxLayout(size_hint_y=None, height=dp(34), spacing=dp(8))
        approve_btn = PillButton(text="Approve", font_size=dp(12))
        deny_btn = GhostButton(text="Deny", font_size=dp(12))

        def _respond(approve):
            try:
                self.session.respond_to_inbox(notification, approve)
            except Exception as error:  # noqa: BLE001
                status_label.text = friendly_error(error)
                return
            # Phase 19.23 -- Issue 1: approving a verification_request
            # marks the REQUESTER VERIFIED on this (the approver's) own
            # device (respond_to_inbox()'s own docstring above), via
            # the SAME existing, zero-message-safe preview shape
            # _seed_restored_conversations() uses for the general case
            # -- immediate for THIS session, since this device won't
            # re-run that seeding again until its next login.
            if approve and notification.get("type") == "verification_request":
                requester = notification.get("requester_username")
                if requester:
                    self._conversation_preview(requester, name=requester, is_group=False)
            self.show_inbox()

        approve_btn.bind(on_release=lambda *_: _respond(True))
        deny_btn.bind(on_release=lambda *_: _respond(False))
        btn_row.add_widget(approve_btn)
        btn_row.add_widget(deny_btn)
        card.add_widget(btn_row)
        return card

    def _build_inbox_history_row(self, notification):
        outcome = "Approved" if notification.get("status") == "approved" else "Denied"
        color = ONLINE_GREEN if notification.get("status") == "approved" else DANGER
        row = BoxLayout(size_hint_y=None, height=dp(40), padding=(dp(4), 0), spacing=dp(6))
        row.add_widget(Label(text=self._inbox_card_text(notification), color=TEXT_GRAY, font_size=dp(11), halign="left"))
        row.add_widget(Label(text=outcome, color=color, bold=True, font_size=dp(11), size_hint_x=None, width=dp(70)))
        return row

    # ---------------------------------------------------------------
    # Devices ("My Devices" -- friendly presentation over the device
    # management backend; mirrors nothing in desktop since desktop's
    # gui/ package has no device-management UI at all -- confirmed by
    # inspection in Phase 19.8 -- so mobile's own existing coverage is
    # kept and simply re-presented in user terms here.)
    # ---------------------------------------------------------------

    def show_devices_list(self):
        self.active_conversation = None
        # Root/bottom-nav screen -- see show_chats_list()'s identical
        # comment.
        App.get_running_app().back_action = None
        layout = BoxLayout(orientation="vertical")
        layout.add_widget(SectionHeader("My Devices", "Refresh", lambda: self.show_devices_list()))

        scroll = ScrollView()
        rows = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(8), padding=(dp(16), dp(8)))
        rows.bind(minimum_height=rows.setter("height"))
        status_label = Label(text="Loading...", size_hint_y=None, height=dp(40), color=TEXT_GRAY)
        rows.add_widget(status_label)
        layout.add_widget(scroll)
        scroll.add_widget(rows)
        self._set_content(layout)

        try:
            devices = self.session.list_devices()
        except Exception as error:  # noqa: BLE001
            status_label.text = friendly_error(error)
            return
        rows.clear_widgets()

        if not devices:
            rows.add_widget(Label(text="No devices found yet.", size_hint_y=None, height=dp(60), color=TEXT_GRAY))

        for device in devices:
            device_id = device["device_id"]
            is_this_device = device_id == self.session.device_id
            state = device.get("state", "UNKNOWN")
            label = device.get("device_name") or device.get("platform") or "Device"
            suffix = " (This device)" if is_this_device else ""
            state_text = {
                "AUTHORIZED": "Authorized", "PENDING": "Pending authorization", "REVOKED": "Revoked",
            }.get(state, state)
            state_color = {"AUTHORIZED": ONLINE_GREEN, "PENDING": (0.88, 0.6, 0.15, 1), "REVOKED": DANGER}.get(state, TEXT_GRAY)

            row = RowCard()
            row.add_widget(CircleAvatar(label, diameter=44))
            info = BoxLayout(orientation="vertical")
            info.add_widget(Label(text=f"{label}{suffix}", bold=True, color=TEXT_DARK, halign="left", font_size=dp(14)))
            state_lbl = Label(text=state_text, halign="left", font_size=dp(11), color=state_color)
            info.add_widget(state_lbl)
            row.add_widget(info)
            row.bind(on_release=lambda *_, d=device, self_=is_this_device: self._open_device_detail(d, self_))
            rows.add_widget(row)

    def _open_device_detail(self, device, is_this_device):
        device_id = device["device_id"]
        try:
            peer = self.session.observe_device_peer_identity(device_id, device["kem_public_key"], device["ml_dsa_public_key"])
            fingerprint = peer["fingerprint"]
            verify_state = peer["state"]
        except Exception as error:  # noqa: BLE001
            fingerprint = "(unavailable)"
            verify_state = "unknown"

        # Phase 19.17C -- friendly text instead of raw protocol state
        # strings ("AUTHORIZED", "identity UNVERIFIED"), matching
        # show_devices_list()'s own state_text mapping above -- an
        # ordinary user reads this, not a protocol log.
        def _friendly_status(device_state, identity_state):
            device_text = {
                "AUTHORIZED": "Authorized", "PENDING": "Pending authorization", "REVOKED": "Revoked",
            }.get(device_state, device_state)
            identity_text = {
                "VERIFIED": "verified", "UNVERIFIED": "not yet verified", "unknown": "unknown",
            }.get(identity_state, str(identity_state).lower())
            return f"{device_text} · Identity {identity_text}"

        box = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(16))
        box.add_widget(Label(text=f"Fingerprint:\n{fingerprint}", size_hint_y=None, height=dp(70), font_size=dp(11), color=TEXT_DARK))
        status_label = Label(text=_friendly_status(device.get("state"), verify_state), size_hint_y=None, height=dp(24), color=TEXT_GRAY, font_size=dp(12))
        box.add_widget(status_label)

        btn_row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(6))
        popup = Popup(title=device.get("device_name") or "Device", content=box, size_hint=(0.92, 0.58), background_color=SURFACE)

        # An authorized device's key-sync packets are only trusted once
        # THIS device has independently verified the sender's identity
        # (mobile/session.py::_handle_device_key_sync() requires
        # _peer_key_is_verified(source_device_id) -- confirmed by a real
        # sync attempt that was silently rejected as "unverified_sender"
        # until this verification step existed). The Authorize flow
        # above already confirms verification for a device THIS one is
        # authorizing; this covers the reverse direction, verifying an
        # already-authorized device before trusting keys synced from it.
        if not is_this_device and verify_state != "VERIFIED":
            verify_btn = GhostButton(text="Verify")

            def _verify(*_):
                try:
                    self.session.confirm_device_peer_verified(device_id, fingerprint)
                    status_label.text = _friendly_status(device.get("state"), "VERIFIED")
                except Exception as error:  # noqa: BLE001
                    status_label.text = friendly_error(error)

            verify_btn.bind(on_release=_verify)
            btn_row.add_widget(verify_btn)

        if not is_this_device and device.get("state") == "PENDING":
            authorize_btn = PillButton(text="Authorize")

            def _authorize(*_):
                try:
                    self.session.confirm_device_peer_verified(device_id, fingerprint)
                    self.session.authorize_device(device_id, fingerprint)
                    status_label.text = "Authorized."
                except Exception as error:  # noqa: BLE001
                    status_label.text = friendly_error(error)

            authorize_btn.bind(on_release=_authorize)
            btn_row.add_widget(authorize_btn)

        if not is_this_device and device.get("state") == "AUTHORIZED":
            sync_btn = GhostButton(text="Sync keys")

            def _sync(*_):
                synced, failed = 0, 0
                for conversation_id in list(self.session.direct_conversation_ids.values()) + list(self.session.groups.keys()):
                    try:
                        package_type = "group" if conversation_id in self.session.groups else "direct"
                        self.session.sync_conversation_key_to_device(device_id, conversation_id, package_type=package_type)
                        synced += 1
                    except Exception:  # noqa: BLE001
                        failed += 1
                status_label.text = f"Synced {synced} conversation key(s)." + (f" ({failed} skipped)" if failed else "")

            sync_btn.bind(on_release=_sync)
            btn_row.add_widget(sync_btn)

            revoke_btn = GhostButton(text="Revoke access", color=DANGER)

            def _revoke(*_):
                try:
                    self.session.revoke_device(device_id)
                    status_label.text = "Revoked."
                except Exception as error:  # noqa: BLE001
                    status_label.text = friendly_error(error)

            revoke_btn.bind(on_release=_revoke)
            btn_row.add_widget(revoke_btn)

        close_btn = GhostButton(text="Close")
        close_btn.bind(on_release=lambda *_: popup.dismiss())
        btn_row.add_widget(close_btn)
        box.add_widget(btn_row)
        popup.open()

    # ---------------------------------------------------------------
    # Session signal handlers
    # ---------------------------------------------------------------

    def _on_message_received(self, identity_key, sender, text, historical, status=None):
        def _update(dt):
            key = self._resolve_identity_key(identity_key)
            is_group = key in self.session.groups
            name = self.session.groups[key]["name"] if is_group else key
            self._conversation_preview(key, name=name, is_group=is_group)
            # Phase 19.23 -- Issue 3: a HISTORICAL entry for a message
            # THIS user sent must render as a "sent" bubble (with its
            # real tick state restored below), not "received" -- see
            # mobile/session.py::load_history()'s own is_own/status
            # computation. Previously unconditional "received" here
            # meant a direct conversation's own history reload showed
            # every one of the user's own past messages as if they had
            # come from the other person (left-aligned, no tick), and
            # (via _touch_preview's incoming=True below) could even
            # inflate the unread badge with the user's own sent
            # messages.
            is_own = sender == self.session.username
            sender_label = sender if (is_group and not is_own) else None
            if key == self.active_conversation:
                if not is_group and not self._active_real_conversation_id:
                    self._active_real_conversation_id = self.session.direct_conversation_ids.get(key)
                if is_own:
                    bubble = self._append_bubble(key, text, kind="sent", is_group=is_group)
                    if historical and status and bubble is not None:
                        bubble._tick_status = status
                        bubble._resolved = status != "Sent"
                        bubble.set_status(status)
                else:
                    self._append_bubble(key, text, kind="received", sender_label=sender_label)
                    self._mark_active_read()
            self._touch_preview(key, text, incoming=not is_own, name=name, is_group=is_group)
        Clock.schedule_once(_update, 0)

    def _on_payload_received(self, identity_key, sender, payload_type, content, content_metadata, historical, status=None):
        filename = content_metadata.get("filename", "attachment")
        mime_type = content_metadata.get("mime_type")
        preview = "[Image]" if payload_type == PayloadType.IMAGE else f"[File] {filename}"

        def _update(dt):
            key = self._resolve_identity_key(identity_key)
            is_group = key in self.session.groups
            name = self.session.groups[key]["name"] if is_group else key
            self._conversation_preview(key, name=name, is_group=is_group)
            # Phase 19.23 -- Issue 3: identical is_own handling to
            # _on_message_received() above, for the exact same reason.
            is_own = sender == self.session.username
            sender_label = sender if (is_group and not is_own) else None
            if key == self.active_conversation:
                if not is_group and not self._active_real_conversation_id:
                    self._active_real_conversation_id = self.session.direct_conversation_ids.get(key)
                if is_own:
                    # Phase 19.23: no on_save for the user's own sent
                    # attachment -- mirrors the live-send path's own
                    # identical attachment=(filename, data, mime, None)
                    # a few lines above _send_attachment() (there is no
                    # existing sent-attachment case in this file that
                    # ever offers Save; only a received one does).
                    bubble = self._append_bubble(
                        key, None, kind="sent", is_group=is_group,
                        attachment=(filename, content, mime_type, None),
                    )
                    if historical and status and bubble is not None:
                        bubble._tick_status = status
                        bubble._resolved = status != "Sent"
                        bubble.set_status(status)
                else:
                    self._append_bubble(
                        key, None, kind="received", sender_label=sender_label,
                        attachment=(filename, content, mime_type, self._save_attachment_android),
                    )
                    self._mark_active_read()
            self._touch_preview(key, preview, incoming=not is_own, name=name, is_group=is_group)
        Clock.schedule_once(_update, 0)

    def _on_security_rejection(self, reason, sender, conversation_id):
        readable = {
            "unverified_sender": "A message from an unverified contact was blocked.",
            "invalid_signature": "A message failed a security check and was blocked.",
            "decryption_failure": "A message could not be decrypted and was blocked.",
            "malformed_packet": "A malformed message was blocked.",
        }.get(reason, "A message was blocked for security reasons.")
        Logger.warning(f"QRSCS: security rejection reason={reason} sender={sender} conversation_id={conversation_id}")

        def _update(dt):
            target = conversation_id or sender
            if not target:
                return
            key = self._resolve_identity_key(target)
            if key == self.active_conversation:
                self._append_bubble(key, readable, kind="system")
            else:
                # Phase 19.17C -- previously invisible unless this
                # exact conversation happened to already be open at
                # the moment of rejection: no preview update, no
                # unread badge, nothing to find later (unlike a
                # successfully-decrypted message, which always calls
                # _touch_preview()). The security decision itself is
                # unchanged -- this only makes an already-correct
                # rejection visible instead of silent.
                is_group = key in self.session.groups
                name = self.session.groups[key]["name"] if is_group else key
                self._touch_preview(key, readable, incoming=True, name=name, is_group=is_group)
        Clock.schedule_once(_update, 0)

    def _on_read_receipt(self, conversation_id, reader):
        def _update(dt):
            # Phase 19.23 -- Issue 3: no longer rendered into the chat
            # transcript as text at all -- the tick-glyph update below
            # (unchanged) is now the ONLY user-visible effect, exactly
            # matching Desktop's handle_read_receipt_updated(), which
            # has never rendered anything but a tick either.

            # Phase 19.15 -- item 7's Read tick: this is a "read up to
            # here" watermark (server/client_handler.py's own C2 Read
            # Receipts design), not a per-message id, so it marks every
            # one of OUR bubbles sent to `reader` (a direct conversation
            # keys _pending_send_status by the peer's own username,
            # which for a message *I* sent *to* them is exactly who
            # just read it) that isn't already Failed. A failed send
            # never reached them, so it must never flip to Read.
            for bubble in self._pending_send_status.get(reader, []):
                if bubble._tick_status == "Failed":
                    continue
                bubble._resolved = True
                bubble._tick_status = "Read"
                bubble.set_status("Read")
        Clock.schedule_once(_update, 0)

    def _on_inbox_updated(self, notification):
        # Phase 19.17C -- fires on this receiver thread for a
        # brand-new pushed notification OR the resolution of one of
        # this user's own earlier requests (session.py's own
        # inbox_updated docstring). Only re-renders if Inbox is the
        # screen actually on screen right now (_inbox_open, kept
        # accurate by _set_content()/show_inbox() together) -- calling
        # show_inbox() while the user is elsewhere would yank them
        # away from whatever they're doing.
        def _update(dt):
            # Phase 19.23 -- Issue 1: this is the ORIGINAL REQUESTER's
            # own notification that their earlier verification_request
            # was just approved -- MobileClientSession.
            # _complete_requester_side_verification() (session-layer,
            # already runs before this signal fires) has just marked
            # the approver VERIFIED on this device. Mirrors the
            # approver's own identical _respond()-side handling above;
            # unlike that side, this one is UI-independent of whether
            # Inbox happens to be open right now.
            if (
                notification.get("type") == "verification_request"
                and notification.get("status") == "approved"
                and notification.get("requester_username") == self.session.username
            ):
                approver = notification.get("recipient_username")
                if approver:
                    self._conversation_preview(approver, name=approver, is_group=False)
            if self._inbox_open:
                self.show_inbox()
        Clock.schedule_once(_update, 0)


class MobileClientApp(App):
    """Top-level Kivy application."""

    def build(self):
        self.title = "QRSCS"
        Window.clearcolor = BG
        # Phase 19.14 -- Composer keyboard fix: Kivy's default
        # softinput_mode ('') never resizes/pans the window for the
        # on-screen keyboard at all -- the keyboard just overlays on
        # top of whatever was already there, covering the composer
        # entirely (the reported bug). 'below_target' shifts the
        # window so the currently-focused widget (whichever TextInput
        # the user just tapped) stays fully above the keyboard --
        # Kivy's own built-in, real mechanism for this, not a manual
        # height-tracking workaround.
        Window.softinput_mode = "below_target"
        # PHYSICAL ACCEPTANCE BLOCKER -- Test 2B, Issue 2 (root cause):
        # this app never intercepted Android's hardware/gesture back
        # button (Kivy maps it to keycode 27, the same as desktop
        # Escape). With nothing consuming it, Kivy's own default
        # unhandled-Escape behaviour runs instead, which backgrounds/
        # exits the Activity -- confirmed on the real device: pressing
        # back from inside a chat dropped window focus straight to the
        # launcher, not to this app's own Chats list. A conversation
        # opened by tapping a search result (deliberately NOT written
        # to the database yet -- see open_chat()'s own "no real
        # conversation yet" comment, mirroring gui/chat_window.py::
        # handle_find_user()'s identical conversation_id=None pattern
        # on Desktop) lives only in this ChatScreen instance's
        # in-memory self.conversations until a first message is sent;
        # if Android reclaims the backgrounded process before that
        # happens -- routine on real hardware, unlike this same-process
        # round trip -- that in-memory entry is gone on relaunch,
        # exactly matching the reported "conversation doesn't appear in
        # Chats" symptom. The fix is narrowly the missing back-button
        # handling, not the deferred-persistence design itself (that
        # part is shared, intentional Desktop/Android architecture and
        # is left unchanged, per "search alone must not create a
        # conversation").
        #
        # back_action is set by whichever screen currently has its own
        # in-app "< Back"/Cancel control (open_chat(),
        # _open_user_search_screen()) to that exact same callable, and
        # cleared back to None by every root/bottom-nav screen
        # (show_chats_list(), show_groups_list(), show_devices_list(),
        # show_settings(), show_inbox()) that has no such control of
        # its own -- so hardware back does precisely what the visible
        # in-app back control would already do, and only truly exits
        # the app from a root screen, exactly like before this fix.
        self.back_action = None
        Window.bind(on_keyboard=self._on_keyboard)
        self.root_container = BoxLayout()
        self._show_get_started()
        return self.root_container

    def _on_keyboard(self, window, key, *args):
        if key != 27 or self.back_action is None:
            return False
        # A Popup (_FriendlyPopup, ImageViewerPopup, ...) is a
        # ModalView, which attaches itself directly as a Window child
        # while open and binds its own on_keyboard handler to dismiss
        # itself on this exact key -- deferring to that here (instead
        # of unconditionally consuming the key for this screen's own
        # back_action) is what stops a back-press from both closing a
        # popup AND navigating the screen behind it in the same tap.
        if any(isinstance(child, Popup) for child in window.children):
            return False
        self.back_action()
        return True

    def _show_get_started(self):
        self.root_container.clear_widgets()
        self.root_container.add_widget(GetStartedScreen(self._show_login))

    def _show_login(self):
        self.root_container.clear_widgets()
        storage_dir = _mobile_storage_dir(self)
        self.root_container.add_widget(LoginScreen(self._on_logged_in, storage_dir))

    def _on_logged_in(self, session):
        self.root_container.clear_widgets()
        self.root_container.add_widget(ChatScreen(session))

    def return_to_login(self):
        # Drops any back_action left over from the ChatScreen instance
        # that's being discarded -- otherwise hardware back, pressed
        # before the next login's own screens set a fresh one, would
        # still run a closure bound to that now-detached instance. See
        # build()'s own comment.
        self.back_action = None
        self._show_login()


def main():
    MobileClientApp().run()


if __name__ == "__main__":
    main()
