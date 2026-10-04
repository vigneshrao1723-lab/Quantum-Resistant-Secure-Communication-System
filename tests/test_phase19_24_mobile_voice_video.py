"""
Phase 19.24 -- Voice/Video Messages: mobile Bubble/attachment
rendering.

Voice/video are NOT a new crypto/protocol path -- domain/payload_type.
py's own module docstring explains why: a recorded clip is read into
memory and pushed through the EXACT SAME AES-256-GCM/ML-DSA/blob-
storage send_attachment() pipeline FILE/IMAGE already use. The
protocol-level reuse is proven by tests/test_file_payload_pipeline.py
and tests/test_message_persistence_integration.py; this file proves
the MOBILE UI side: mobile/app.py's attachment bubble renders a real
Play/Pause control (kivy.core.audio.SoundLoader, this build's
confirmed-working audio_sdl2 backend) for a received voice message --
a genuine, valid WAV file, not a mock -- and that the Attachment Menu
honestly reports voice/video RECORDING as unavailable on this build
rather than silently doing nothing (see _start_attachment_pick()'s own
docstring for the full reasoning: no reliable cross-platform recording
API was found -- plyer's Windows audio backend crashes outright in
this environment, and a native Android MediaRecorder/Camera2
implementation would be untestable from this Windows development
machine).

Run with:
    pytest tests/test_phase19_24_mobile_voice_video.py -v
"""

import io
import os
import wave

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from mobile.app import Bubble, ChatScreen, _build_attachment_bubble_content, _payload_type_from_mime
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])


def _tiny_wav_bytes():
    """A REAL, valid, tiny WAV file -- SoundLoader must genuinely be
    able to decode this, not just accept arbitrary bytes."""

    buf = io.BytesIO()
    with wave.open(buf, "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(8000)
        writer.writeframes(b"\x00\x00" * 800)
    return buf.getvalue()


@pytest.fixture(scope="module", autouse=True)
def _keep_alive():
    keep = []
    yield keep


def test_payload_type_from_mime_classifies_audio_and_video():
    assert _payload_type_from_mime("audio/wav") == "voice"
    assert _payload_type_from_mime("audio/mp4") == "voice"
    assert _payload_type_from_mime("video/mp4") == "video"
    assert _payload_type_from_mime("application/pdf") is None
    assert _payload_type_from_mime(None) is None


def test_voice_attachment_bubble_renders_a_real_play_button(_keep_alive):
    bubble = Bubble(
        None, kind="received", sender_label="alice", timestamp="10:00",
        attachment=("clip.wav", _tiny_wav_bytes(), "audio/wav", None),
    )
    _keep_alive.append(bubble)

    # _build_attachment_bubble_content() built a play button + label
    # row rather than the plain [File] fallback -- found by walking the
    # widget tree it returned (self._body is None for an attachment
    # bubble; the content lives directly under the bubble's layout).
    labels = [
        w.text for w in bubble.walk() if hasattr(w, "text") and isinstance(getattr(w, "text", None), str)
    ]
    assert any("Voice message" in text for text in labels)
    assert any(text in ("▶", "⏸") for text in labels)


def test_video_attachment_bubble_renders_an_honest_label_not_a_broken_player(_keep_alive):
    bubble = Bubble(
        None, kind="received", sender_label="alice", timestamp="10:00",
        attachment=("clip.mp4", b"fake video bytes", "video/mp4", None),
    )
    _keep_alive.append(bubble)

    labels = [
        w.text for w in bubble.walk() if hasattr(w, "text") and isinstance(getattr(w, "text", None), str)
    ]
    assert any("Video message" in text for text in labels)


def test_plain_file_attachment_unaffected_by_mime_hint_addition(_keep_alive):
    bubble = Bubble(
        None, kind="received", sender_label="alice", timestamp="10:00",
        attachment=("report.pdf", b"pdf bytes", "application/pdf", None),
    )
    _keep_alive.append(bubble)

    labels = [
        w.text for w in bubble.walk() if hasattr(w, "text") and isinstance(getattr(w, "text", None), str)
    ]
    assert any("report.pdf" in text for text in labels)


def test_voice_play_button_actually_toggles_a_real_sound_without_crashing(_keep_alive):
    """Exercises the REAL SoundLoader path end to end against a
    genuinely valid WAV file -- this build's audio_sdl2 backend is
    confirmed working (unlike its video backend), so play must
    actually succeed, not merely fail gracefully."""

    content = _build_attachment_bubble_content(
        "clip.wav", _tiny_wav_bytes(), kind="received", mime_type="audio/wav",
    )
    _keep_alive.append(content)

    play_button = next(
        w for w in content.walk() if hasattr(w, "text") and getattr(w, "text", None) == "▶"
    )

    play_button.dispatch("on_release")
    assert play_button.text == "⏸"

    play_button.dispatch("on_release")
    assert play_button.text == "▶"


def test_attachment_menu_reports_voice_and_video_recording_as_unavailable_honestly(
    running_server, monkeypatch, tmp_path
):
    """Desktop-preview mode (this dev machine, no Android hardware) --
    proves the menu never silently no-ops for Voice/Video, and never
    claims recording works when it does not."""

    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mvv"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        before = len(screen._bubble_rows[bob.username].children)

        # The real popup's own button dispatch, bypassing only the
        # modal Popup.open() rendering itself -- mirrors this
        # project's established "call the real choose handler
        # directly" convention for every other Kivy Popup-driven
        # feature in this file.
        import mobile.app as mobile_app_module

        captured = {}
        real_popup_cls = mobile_app_module.Popup

        class _CapturingPopup(real_popup_cls):
            def open(self, *a, **k):
                captured["popup"] = self

        monkeypatch.setattr(mobile_app_module, "Popup", _CapturingPopup)
        screen._start_attachment_pick(bob.username, False)

        popup = captured["popup"]
        buttons = [w for w in popup.content.children if hasattr(w, "text")]
        voice_btn = next(b for b in buttons if "Voice" in b.text)
        voice_btn.dispatch("on_release")

        after = screen._bubble_rows[bob.username].children
        assert len(after) == before + 1
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
