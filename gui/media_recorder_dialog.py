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

Duration is capped (MAX_VOICE_SECONDS / MAX_VIDEO_SECONDS below) --
recording auto-stops rather than producing an unbounded clip.
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

MAX_VOICE_SECONDS = 120
MAX_VIDEO_SECONDS = 60


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

        self.setWindowTitle(
            "Record Voice Message" if mode == "voice" else "Record Video Message"
        )
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)

        self._session = QMediaCaptureSession()
        self._audio_input = QAudioInput(QMediaDevices.defaultAudioInput())
        self._session.setAudioInput(self._audio_input)

        if mode == "video":
            self._camera = QCamera(QMediaDevices.defaultVideoInput())
            self._session.setCamera(self._camera)
            self._video_widget = QVideoWidget()
            self._video_widget.setMinimumHeight(240)
            self._session.setVideoOutput(self._video_widget)
            layout.addWidget(self._video_widget)
            self._camera.start()

        self._recorder = QMediaRecorder()
        self._session.setRecorder(self._recorder)

        # QMediaRecorder refuses to record to a path that already
        # exists as an empty file on some backends -- mkstemp() creates
        # the file, so it is removed immediately and the recorder
        # creates its own at the same path.
        suffix = ".m4a" if mode == "voice" else ".mp4"
        fd, path = tempfile.mkstemp(prefix="qrscs_recording_", suffix=suffix)
        os.close(fd)
        os.remove(path)
        self._output_path = path
        self._recorder.setOutputLocation(QUrl.fromLocalFile(path))

        self._status_label = QLabel("Ready to record.")
        self._status_label.setTextFormat(Qt.PlainText)
        layout.addWidget(self._status_label)

        self._timer_label = QLabel("00:00")
        self._timer_label.setTextFormat(Qt.PlainText)
        self._timer_label.setAlignment(Qt.AlignCenter)
        self._timer_label.setStyleSheet("font-size: 22pt; font-weight: 600;")
        layout.addWidget(self._timer_label)

        self._record_button = QPushButton("⏺ Record")
        self._record_button.setCursor(Qt.PointingHandCursor)
        self._record_button.clicked.connect(self._toggle_recording)
        layout.addWidget(self._record_button)

        action_row = QHBoxLayout()
        cancel_button = QPushButton("Cancel")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self.reject)
        self._send_button = QPushButton("Send")
        self._send_button.setCursor(Qt.PointingHandCursor)
        self._send_button.setEnabled(False)
        self._send_button.clicked.connect(self._handle_send)
        action_row.addWidget(cancel_button)
        action_row.addStretch()
        action_row.addWidget(self._send_button)
        layout.addLayout(action_row)

        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._on_tick)

        self._recorder.recorderStateChanged.connect(self._on_recorder_state_changed)

    def _max_seconds(self):
        return MAX_VOICE_SECONDS if self.mode == "voice" else MAX_VIDEO_SECONDS

    def _toggle_recording(self):
        if self._recorder.recorderState() == QMediaRecorder.RecorderState.RecordingState:
            self._recorder.stop()
            return

        self._elapsed_seconds = 0
        self._timer_label.setText("00:00")
        self._recorder.record()

    def _on_recorder_state_changed(self, state):
        if state == QMediaRecorder.RecorderState.RecordingState:
            self._record_button.setText("⏹ Stop")
            self._status_label.setText("Recording…")
            self._send_button.setEnabled(False)
            self._tick_timer.start()
        elif state == QMediaRecorder.RecorderState.StoppedState:
            self._tick_timer.stop()
            self._record_button.setText("⏺ Record Again")
            if self._elapsed_seconds > 0:
                self._has_recording = True
                self._status_label.setText("Recording ready to send.")
                self._send_button.setEnabled(True)

    def _on_tick(self):
        self._elapsed_seconds += 1
        self._timer_label.setText(
            f"{self._elapsed_seconds // 60:02d}:{self._elapsed_seconds % 60:02d}"
        )
        if self._elapsed_seconds >= self._max_seconds():
            self._recorder.stop()

    def _handle_send(self):
        if not self._has_recording or not Path(self._output_path).exists():
            return

        self.recorded_file_path = self._output_path
        self.accept()

    def reject(self):
        self._cleanup_camera()

        if not self.recorded_file_path and Path(self._output_path).exists():
            try:
                Path(self._output_path).unlink()
            except OSError:
                pass

        super().reject()

    def accept(self):
        self._cleanup_camera()
        super().accept()

    def _cleanup_camera(self):
        if self._camera is not None:
            self._camera.stop()
