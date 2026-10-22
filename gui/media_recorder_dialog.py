"""
Voice/Video Message recorder dialog (Phase 19.24).

Records a REAL clip from the local microphone (voice) or camera+
microphone (video) via PySide6's QtMultimedia -- no new dependency, no
new cryptographic primitive. The recorded file is handed back to the
caller (gui/chat_window.py::handle_attachment_selected(), completely
unmodified) as a plain local file path, which pushes it through the
EXACT SAME AES-256-GCM/ML-DSA/blob-storage send_attachment() pipeline
every other attachment already uses (see domain/payload_type.py's own
module docstring for the full trust-model rationale) -- this dialog
invents no new crypto and adds no new wire protocol.

QMediaRecorder has no in-memory recording mode -- it always writes to
a real output file -- so this is the one place a voice/video message's
plaintext briefly touches local disk before encryption, exactly like
any OS-level recording API. The temp file is the CALLER's
responsibility to delete once its bytes have been read into memory and
encrypted (see handle_attachment_selected()'s own cleanup); this
dialog itself deletes it only if the user cancels without sending.

The container and codecs are set explicitly -- AAC in MPEG-4 audio
(.m4a) for voice, H.264 + AAC in MPEG-4 (.mp4) for video -- rather than
left to the platform default, so every client (the Website's browser
included) can play what Desktop records.

The flow matches the Website's recorder: Record, Stop, listen to (or
watch) the recording, then Record again, Cancel or Send. Duration is
capped (MAX_VOICE_SECONDS / MAX_VIDEO_SECONDS below) -- recording
auto-stops rather than producing an unbounded clip.
"""

import os
import tempfile
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtMultimedia import (
    QAudioInput,
    QCamera,
    QMediaCaptureSession,
    QMediaDevices,
    QMediaFormat,
    QMediaRecorder,
)
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from gui.message_parts import MediaPlayerCard, format_clock
from gui.styles import COLOR_ACCENT, COLOR_DANGER, COLOR_TEXT, COLOR_TEXT_MUTED

MAX_VOICE_SECONDS = 120
MAX_VIDEO_SECONDS = 60


def recording_format(mode):
    """The explicit container/codecs for a recording (see the module docstring)."""

    if mode == "voice":
        media_format = QMediaFormat(QMediaFormat.FileFormat.Mpeg4Audio)
        media_format.setAudioCodec(QMediaFormat.AudioCodec.AAC)
        return media_format, ".m4a", "audio/mp4"

    media_format = QMediaFormat(QMediaFormat.FileFormat.MPEG4)
    media_format.setVideoCodec(QMediaFormat.VideoCodec.H264)
    media_format.setAudioCodec(QMediaFormat.AudioCodec.AAC)
    return media_format, ".mp4", "video/mp4"


class MediaRecorderDialog(QDialog):
    """
    Records a voice or video message. exec() returns QDialog.Accepted
    only when the user chose Send with a completed, non-empty
    recording -- self.recorded_file_path is then the local path to
    send (the caller owns deleting it after reading it).
    """

    def __init__(self, mode, parent=None):
        super().__init__(parent)

        if mode not in ("voice", "video"):
            raise ValueError(f"Unknown recorder mode: {mode!r}")

        self.mode = mode
        self.recorded_file_path = None
        self._elapsed_seconds = 0
        self._has_recording = False
        self._camera = None
        self._preview = None
        self._what = "voice message" if mode == "voice" else "video message"

        self.setWindowTitle(
            "Record Voice Message" if mode == "voice" else "Record Video Message"
        )
        self.setMinimumWidth(380)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)

        title = QLabel("Voice message" if mode == "voice" else "Video message")
        title.setTextFormat(Qt.PlainText)
        title.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 13pt; font-weight: 700;")
        layout.addWidget(title)

        microphone = QMediaDevices.defaultAudioInput()
        camera_device = QMediaDevices.defaultVideoInput() if mode == "video" else None
        self._device_problem = None
        if microphone.isNull():
            self._device_problem = "No microphone was found. Connect one and try again."
        elif mode == "video" and camera_device.isNull():
            self._device_problem = "No camera was found. Connect one and try again."

        self._session = QMediaCaptureSession()
        self._audio_input = QAudioInput(microphone)
        self._session.setAudioInput(self._audio_input)

        if mode == "video":
            self._camera = QCamera(camera_device)
            self._camera.errorOccurred.connect(self._on_camera_error)
            self._session.setCamera(self._camera)
            self._video_widget = QVideoWidget()
            self._video_widget.setMinimumHeight(240)
            self._session.setVideoOutput(self._video_widget)
            layout.addWidget(self._video_widget)
            if self._device_problem is None:
                self._camera.start()

        self._recorder = QMediaRecorder()
        self._session.setRecorder(self._recorder)

        media_format, suffix, self.mime_type = recording_format(mode)
        self._recorder.setMediaFormat(media_format)
        self._recorder.setQuality(QMediaRecorder.Quality.HighQuality)

        # QMediaRecorder refuses to record to a path that already
        # exists as an empty file on some backends -- mkstemp() creates
        # the file, so it is removed immediately and the recorder
        # creates its own at the same path.
        fd, path = tempfile.mkstemp(prefix="qrscs_recording_", suffix=suffix)
        os.close(fd)
        os.remove(path)
        self._output_path = path
        self._recorder.setOutputLocation(QUrl.fromLocalFile(path))

        self._timer_label = QLabel("0:00")
        self._timer_label.setTextFormat(Qt.PlainText)
        self._timer_label.setAlignment(Qt.AlignCenter)
        self._timer_label.setAccessibleName("Recording time")
        self._timer_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 24pt; font-weight: 600;")
        layout.addWidget(self._timer_label)

        self._status_label = QLabel(
            self._device_problem or f"Up to {format_clock(self._max_seconds())}. Press Record to start."
        )
        self._status_label.setTextFormat(Qt.PlainText)
        self._status_label.setWordWrap(True)
        self._status_label.setAlignment(Qt.AlignCenter)
        self._status_label.setAccessibleName("Recorder status")
        self._set_status_style(error=self._device_problem is not None)
        layout.addWidget(self._status_label)

        # The recording, playable before it is sent (filled in once recording stops).
        self._preview_slot = QVBoxLayout()
        layout.addLayout(self._preview_slot)

        self._record_button = QPushButton("Record")
        self._record_button.setCursor(Qt.PointingHandCursor)
        self._record_button.setAccessibleName(f"Record a {self._what}")
        self._record_button.setEnabled(self._device_problem is None)
        self._record_button.clicked.connect(self._toggle_recording)
        layout.addWidget(self._record_button)

        action_row = QHBoxLayout()
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self.reject)
        self._send_button = QPushButton("Send")
        self._send_button.setCursor(Qt.PointingHandCursor)
        self._send_button.setEnabled(False)
        self._send_button.setAccessibleName(f"Send the {self._what}")
        self._send_button.clicked.connect(self._handle_send)
        action_row.addWidget(cancel_button)
        action_row.addStretch()
        action_row.addWidget(self._send_button)
        layout.addLayout(action_row)

        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._on_tick)

        self._recorder.recorderStateChanged.connect(self._on_recorder_state_changed)
        self._recorder.errorOccurred.connect(self._on_recorder_error)

    def _max_seconds(self):
        return MAX_VOICE_SECONDS if self.mode == "voice" else MAX_VIDEO_SECONDS

    def _set_status_style(self, error=False):
        self._status_label.setStyleSheet(
            f"color: {COLOR_DANGER if error else COLOR_TEXT_MUTED}; font-size: 9.5pt;"
        )

    def _clear_preview(self):
        if self._preview is not None:
            self._preview.release()
            self._preview_slot.removeWidget(self._preview)
            self._preview.deleteLater()
            self._preview = None

    def _toggle_recording(self):
        if self._recorder.recorderState() == QMediaRecorder.RecorderState.RecordingState:
            self._recorder.stop()
            return

        # Record again: the previous take is discarded.
        self._clear_preview()
        self._has_recording = False
        self._send_button.setEnabled(False)
        if Path(self._output_path).exists():
            try:
                Path(self._output_path).unlink()
            except OSError:
                pass

        self._elapsed_seconds = 0
        self._timer_label.setText("0:00")
        self._set_status_style(error=False)
        self._recorder.record()

    def _on_recorder_state_changed(self, state):
        if state == QMediaRecorder.RecorderState.RecordingState:
            self._record_button.setText("Stop")
            self._record_button.setAccessibleName("Stop recording")
            self._status_label.setText("Recording…")
            self._send_button.setEnabled(False)
            self._tick_timer.start()
        elif state == QMediaRecorder.RecorderState.StoppedState:
            self._tick_timer.stop()
            self._record_button.setText("Record again")
            self._record_button.setAccessibleName(f"Record the {self._what} again")
            path = Path(self._output_path)
            if self._elapsed_seconds > 0 and path.exists() and path.stat().st_size > 0:
                self._has_recording = True
                self._status_label.setText("Listen to your recording, then send it." if self.mode == "voice"
                                           else "Watch your recording, then send it.")
                self._send_button.setEnabled(True)
                self._show_preview(path)

    def _show_preview(self, path):
        try:
            data = path.read_bytes()
        except OSError:
            return
        self._clear_preview()
        self._preview = MediaPlayerCard(
            data,
            self.mime_type,
            is_video=self.mode == "video",
            text_color=COLOR_ACCENT,
            meta_color=COLOR_TEXT_MUTED,
            accent_color=COLOR_ACCENT,
        )
        self._preview_slot.addWidget(self._preview)

    def _on_recorder_error(self, _error, message):
        self._tick_timer.stop()
        self._has_recording = False
        self._send_button.setEnabled(False)
        self._record_button.setText("Record")
        self._status_label.setText(f"Recording failed: {message or 'the recorder reported an error.'}")
        self._set_status_style(error=True)

    def _on_camera_error(self, _error, message):
        self._status_label.setText(f"The camera is unavailable: {message or 'unknown error'}")
        self._set_status_style(error=True)
        self._record_button.setEnabled(False)

    def _on_tick(self):
        self._elapsed_seconds += 1
        self._timer_label.setText(format_clock(self._elapsed_seconds))
        if self._elapsed_seconds >= self._max_seconds():
            self._recorder.stop()

    def _handle_send(self):
        if not self._has_recording or not Path(self._output_path).exists():
            return

        self.recorded_file_path = self._output_path
        self.accept()

    def reject(self):
        self._cleanup()

        if not self.recorded_file_path and Path(self._output_path).exists():
            try:
                Path(self._output_path).unlink()
            except OSError:
                pass

        super().reject()

    def accept(self):
        self._cleanup()
        super().accept()

    def _cleanup(self):
        if self._recorder.recorderState() == QMediaRecorder.RecorderState.RecordingState:
            self._recorder.stop()
        self._clear_preview()
        if self._camera is not None:
            self._camera.stop()

    # Kept for callers that used the previous name.
    _cleanup_camera = _cleanup
