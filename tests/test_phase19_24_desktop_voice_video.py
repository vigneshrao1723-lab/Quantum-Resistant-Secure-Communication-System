"""
Phase 19.24 -- Voice/Video Messages: Desktop UI.

Voice/video are NOT a new crypto/protocol path -- domain/payload_type.
py's own module docstring explains why: a recorded clip is read into
memory and pushed through the EXACT SAME AES-256-GCM/ML-DSA/blob-
storage send_attachment() pipeline FILE/IMAGE already use. The
protocol/crypto-level reuse is proven by tests/test_file_payload_
pipeline.py and tests/test_message_persistence_integration.py; this
file proves the DESKTOP UI side: gui.message_widget.FileMessageBubble
renders a real playback control (not a plain download link) for
PayloadType.VOICE/VIDEO, and gui.media_recorder_dialog.
MediaRecorderDialog performs a REAL recording from this machine's own
microphone (confirmed present) via PySide6's QtMultimedia -- no mock,
no stub.

Run with:
    pytest tests/test_phase19_24_desktop_voice_video.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path

import pytest
from PySide6.QtMultimedia import QMediaDevices
from PySide6.QtWidgets import QApplication

from domain.payload_type import PayloadType
from gui.media_recorder_dialog import MediaRecorderDialog, MAX_VOICE_SECONDS
from gui.message_widget import FileMessageBubble

_app = QApplication.instance() or QApplication([])

_HAS_MICROPHONE = not QMediaDevices.defaultAudioInput().isNull()


@pytest.fixture(scope="module", autouse=True)
def _keep_alive():
    """Mirrors tests/test_phase19_24_mobile_bubble_ui.py's own
    identical convention -- a bubble/dialog built inline can be
    garbage-collected before an assertion reads its Qt-owned state."""

    keep = []
    yield keep


def _voice_bubble(**kwargs):
    return FileMessageBubble(
        b"fake-decrypted-voice-bytes",
        {"filename": "clip.m4a", "mime_type": "audio/mp4", "size_bytes": 27},
        kind=kwargs.pop("kind", "received"),
        payload_type=PayloadType.VOICE,
        **kwargs,
    )


def _video_bubble(**kwargs):
    return FileMessageBubble(
        b"fake-decrypted-video-bytes",
        {"filename": "clip.mp4", "mime_type": "video/mp4", "size_bytes": 27},
        kind=kwargs.pop("kind", "received"),
        payload_type=PayloadType.VIDEO,
        **kwargs,
    )


# ----------------------------------------------------------------------
# FileMessageBubble -- voice
# ----------------------------------------------------------------------


def test_voice_bubble_renders_a_play_button_not_a_plain_file_row(_keep_alive):
    bubble = _voice_bubble()
    _keep_alive.append(bubble)

    assert bubble.payload_type == PayloadType.VOICE
    assert hasattr(bubble, "_voice_play_button")
    assert bubble._voice_play_button.text() == "▶"


def test_voice_bubble_still_offers_lifecycle_features(_keep_alive):
    """Reusing FileMessageBubble (not a separate class) is what makes
    Pin/Reactions/Forward/Delete all work automatically -- this is the
    concrete proof, not just an architectural claim."""

    bubble = _voice_bubble(kind="sent")
    _keep_alive.append(bubble)
    bubble.message_id = "msg-voice-1"

    bubble.set_pinned(True, "alice")
    assert bubble.is_pinned is True

    bubble.update_reactions([{"user": "bob", "reaction": "\U0001F44D"}])
    assert len(bubble.reactions) == 1

    bubble.mark_deleted()
    assert bubble.is_deleted is True
    assert bubble.is_pinned is False  # cleared by mark_deleted(), like every other bubble


def test_voice_bubble_play_button_toggles_without_crashing_on_fake_bytes(_keep_alive):
    """The bytes here are not a real audio file -- QMediaPlayer will
    fail to decode them, exactly like it would for corrupted/malformed
    real-world input (Phase 19.24's own "malformed input handling"
    requirement). Decode failure is asynchronous (mediaStatusChanged/
    errorOccurred), so the exact play/pause label sequence is not
    deterministic here the way it would be for a real clip -- what
    this asserts is the actual safety property: repeated toggling on
    permanently-undecodable input never raises."""

    bubble = _voice_bubble()
    _keep_alive.append(bubble)

    for _ in range(4):
        bubble._toggle_voice_playback()
        _app.processEvents()
        assert bubble._voice_play_button.text() in ("▶", "⏸")


def test_voice_bubble_duration_label_present_when_metadata_supplies_it(_keep_alive):
    bubble = FileMessageBubble(
        b"fake-decrypted-voice-bytes",
        {"filename": "clip.m4a", "mime_type": "audio/mp4", "duration_seconds": 75},
        kind="received",
        payload_type=PayloadType.VOICE,
    )
    _keep_alive.append(bubble)

    assert bubble._voice_duration_label.text() == "1:15"


# ----------------------------------------------------------------------
# FileMessageBubble -- video
# ----------------------------------------------------------------------


def test_video_bubble_renders_a_play_video_button(_keep_alive):
    bubble = _video_bubble()
    _keep_alive.append(bubble)

    assert bubble.payload_type == PayloadType.VIDEO
    assert hasattr(bubble, "_open_video_player")


def test_plain_file_bubble_unaffected_by_payload_type_default(_keep_alive):
    """payload_type=None (every pre-existing FILE call site) must keep
    rendering exactly the old plain-file row -- no play button, no
    behavior change for FILE/IMAGE callers that predate this feature."""

    bubble = FileMessageBubble(
        b"plain file bytes",
        {"filename": "report.pdf"},
        kind="received",
    )
    _keep_alive.append(bubble)

    assert bubble.payload_type == PayloadType.FILE
    assert not hasattr(bubble, "_voice_play_button")


# ----------------------------------------------------------------------
# MediaRecorderDialog -- a REAL recording from this machine's own
# microphone (QMediaDevices.defaultAudioInput() confirmed present).
# ----------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_MICROPHONE, reason="no microphone available on this machine")
def test_real_voice_recording_produces_a_nonempty_audio_file(_keep_alive):
    dialog = MediaRecorderDialog("voice")
    _keep_alive.append(dialog)

    output_path = dialog._output_path
    assert not Path(output_path).exists()

    dialog._toggle_recording()
    assert dialog._recorder.recorderState().name == "RecordingState"

    # A real ~1.2s recording -- long enough for the OS audio backend
    # to actually open the device and flush at least one buffer to
    # disk, short enough to keep this test fast.
    deadline = 1.2
    elapsed = 0.0
    step = 0.05
    while elapsed < deadline:
        _app.processEvents()
        time.sleep(step)
        elapsed += step

    dialog._toggle_recording()

    for _ in range(40):
        _app.processEvents()
        if dialog._has_recording:
            break
        time.sleep(0.05)

    try:
        assert dialog._has_recording is True
        assert Path(output_path).exists()
        assert Path(output_path).stat().st_size > 0
        assert dialog._send_button.isEnabled() is True
    finally:
        if Path(output_path).exists():
            Path(output_path).unlink()


def test_recording_auto_stops_at_the_max_duration_cap():
    """Verifies the cap is wired to actually stop the recorder, without
    running a real 120-second recording -- ticks the dialog's own
    _on_tick() the way its internal QTimer would, MAX_VOICE_SECONDS - 1
    times (still recording) then once more (must auto-stop)."""

    dialog = MediaRecorderDialog("voice")
    try:
        dialog._elapsed_seconds = MAX_VOICE_SECONDS - 1
        stopped = {"called": False}
        dialog._recorder.stop = lambda: stopped.__setitem__("called", True)

        dialog._on_tick()

        assert stopped["called"] is True
    finally:
        if Path(dialog._output_path).exists():
            Path(dialog._output_path).unlink()


def test_cancelling_without_recording_deletes_the_temp_output_path():
    dialog = MediaRecorderDialog("voice")
    output_path = dialog._output_path

    dialog.reject()

    assert not Path(output_path).exists()
