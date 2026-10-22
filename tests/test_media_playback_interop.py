"""
Voice and video messages play on Desktop and on the Website, in both directions.

What is proved here, with real media rather than placeholder bytes:

* a clip recorded by Chrome (its WebM/Opus voice, WebM video) is decoded by the Desktop player to
  real, non-silent audio with a real duration, and a video clip yields real frames;
* the clip the Desktop recorder produces (AAC in MPEG-4 audio, H.264/AAC in MPEG-4 video, built
  from a synthetic tone / test pattern -- the owner's microphone is never opened) is decoded by
  Chrome to real, non-silent audio, and the video loads, has a size and advances;
* the same holds across the real server: Web -> Desktop through the recorder modal, and
  Desktop -> Web through the encrypted attachment pipeline, where the receiving side decodes what
  it decrypted;
* media that cannot be decoded is reported on the card and never raises.

The encryption pipeline is unchanged and is exercised end to end by the cross-client tests; none
of this weakens it.
"""

import base64
import math
import os
import struct
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from playwright.sync_api import sync_playwright
from PySide6.QtCore import QBuffer, QByteArray, QEventLoop, QIODevice, QTimer, QUrl
from PySide6.QtGui import QColor, QImage
from PySide6.QtMultimedia import (
    QAudioBuffer,
    QAudioBufferInput,
    QAudioDecoder,
    QAudioFormat,
    QMediaCaptureSession,
    QMediaDevices,
    QMediaRecorder,
    QVideoFrame,
    QVideoFrameInput,
)
from PySide6.QtWidgets import QApplication

from domain.payload_type import PayloadType
from gui.media_recorder_dialog import recording_format
from gui.message_parts import MediaPlayerCard
from gui.message_widget import FileMessageBubble
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _connect_browser,
    _delete,
    _register,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_feature_completion_e2e import (
    _verify_browser_observes_desktop,
    _verify_desktop_observes_browser,
)
from tests.test_web_phase19_24_lifecycle_ui import (
    _establish_key_in_browser,
    _open_direct_chat_in_browser,
    _record_and_send,
)

_app = QApplication.instance() or QApplication([])

CHROME_ARGS = ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"]
MIN_RMS = 0.02          # a real tone/speech signal; digital silence is 0.0
SECONDS = 2.0


# --------------------------------------------------------------------------- Qt helpers


def pump(condition, timeout=15.0, interval=0.02):
    """Run the Qt event loop until ``condition()`` is true (or the timeout passes)."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _app.processEvents()
        if condition():
            return True
        time.sleep(interval)
    return bool(condition())


def decode_pcm(raw):
    """Decode ``raw`` with Qt's audio decoder -> (sample_count, rms, error_text)."""

    decoder = QAudioDecoder()
    buffer = QBuffer()
    buffer.setData(QByteArray(bytes(raw)))
    buffer.open(QIODevice.ReadOnly)
    decoder.setSourceDevice(buffer)
    samples = []
    errors = []
    loop = QEventLoop()

    def read_ready():
        while decoder.bufferAvailable():
            chunk = decoder.read()
            data = bytes(chunk.constData())
            sample_format = chunk.format().sampleFormat()
            if sample_format == QAudioFormat.SampleFormat.Int16:
                samples.extend(v / 32768 for v in struct.unpack(f"<{len(data) // 2}h", data[: len(data) // 2 * 2]))
            elif sample_format == QAudioFormat.SampleFormat.Float:
                samples.extend(struct.unpack(f"<{len(data) // 4}f", data[: len(data) // 4 * 4]))

    decoder.bufferReady.connect(read_ready)
    decoder.finished.connect(loop.quit)
    decoder.error.connect(lambda _e: (errors.append(decoder.errorString()), loop.quit()))
    QTimer.singleShot(20000, loop.quit)
    decoder.start()
    loop.exec()
    rms = math.sqrt(sum(s * s for s in samples) / len(samples)) if samples else 0.0
    return len(samples), rms, "; ".join(errors)


def _record_synthetic(path, mode):
    """Record a tone (and, for video, a moving test pattern) through the Desktop recorder's own
    format. Nothing from the real microphone or camera is involved."""

    audio_format = QAudioFormat()
    audio_format.setSampleRate(48000)
    audio_format.setChannelCount(1)
    audio_format.setSampleFormat(QAudioFormat.SampleFormat.Int16)

    session = QMediaCaptureSession()
    audio_input = QAudioBufferInput(audio_format)
    session.setAudioBufferInput(audio_input)
    video_input = None
    if mode == "video":
        video_input = QVideoFrameInput()
        session.setVideoFrameInput(video_input)

    recorder = QMediaRecorder()
    session.setRecorder(recorder)
    media_format, _suffix, _mime = recording_format(mode)
    recorder.setMediaFormat(media_format)
    recorder.setAutoStop(True)
    if os.path.exists(path):
        os.remove(path)
    recorder.setOutputLocation(QUrl.fromLocalFile(str(path)))

    fps = 25
    state = {"frame": 0, "sample": 0}
    total_samples = int(48000 * SECONDS)
    total_frames = int(fps * SECONDS)

    def feed_audio():
        while state["sample"] < total_samples:
            n = min(4800, total_samples - state["sample"])
            pcm = b"".join(
                struct.pack("<h", int(12000 * math.sin(2 * math.pi * 440 * (state["sample"] + i) / 48000)))
                for i in range(n)
            )
            if not audio_input.sendAudioBuffer(QAudioBuffer(QByteArray(pcm), audio_format)):
                return
            state["sample"] += n
        audio_input.sendAudioBuffer(QAudioBuffer())

    def feed_video():
        while state["frame"] < total_frames:
            image = QImage(320, 240, QImage.Format_RGB32)
            image.fill(QColor.fromHsv((state["frame"] * 9) % 360, 220, 230))
            frame = QVideoFrame(image)
            frame.setStartTime(int(state["frame"] * 1_000_000 / fps))
            frame.setEndTime(int((state["frame"] + 1) * 1_000_000 / fps))
            if not video_input.sendVideoFrame(frame):
                return
            state["frame"] += 1
        video_input.sendVideoFrame(QVideoFrame())

    audio_input.readyToSendAudioBuffer.connect(feed_audio)
    if video_input is not None:
        video_input.readyToSendVideoFrame.connect(feed_video)

    errors = []
    recorder.errorOccurred.connect(lambda _e, text: errors.append(text))
    loop = QEventLoop()
    recorder.recorderStateChanged.connect(
        lambda s: loop.quit() if s == QMediaRecorder.RecorderState.StoppedState else None
    )
    recorder.record()
    QTimer.singleShot(40000, loop.quit)
    loop.exec()
    assert not errors, errors
    assert os.path.exists(path) and os.path.getsize(path) > 1000
    return path


@pytest.fixture(scope="module")
def desktop_voice_clip(tmp_path_factory):
    path = tmp_path_factory.mktemp("clips") / "voice.m4a"
    _record_synthetic(path, "voice")
    return path.read_bytes()


@pytest.fixture(scope="module")
def desktop_video_clip(tmp_path_factory):
    path = tmp_path_factory.mktemp("clips") / "video.mp4"
    _record_synthetic(path, "video")
    return path.read_bytes()


# --------------------------------------------------------------------------- Chrome helpers

RECORD_JS = """async (mode) => {
  const stream = await navigator.mediaDevices.getUserMedia(
    mode === 'video' ? {audio: true, video: true} : {audio: true});
  const rec = new MediaRecorder(stream); const chunks = [];
  rec.ondataavailable = e => chunks.push(e.data);
  const done = new Promise(r => rec.onstop = r);
  rec.start(); await new Promise(r => setTimeout(r, 2500)); rec.stop(); await done;
  stream.getTracks().forEach(t => t.stop());
  const blob = new Blob(chunks, {type: rec.mimeType});
  const buf = new Uint8Array(await blob.arrayBuffer()); let s = '';
  for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return [rec.mimeType, btoa(s)];
}"""

DECODE_AUDIO_JS = """async (b64) => {
  const bin = atob(b64); const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const ctx = new AudioContext();
  const audio = await ctx.decodeAudioData(bytes.buffer);
  const data = audio.getChannelData(0); let sum = 0;
  for (let i = 0; i < data.length; i++) sum += data[i] * data[i];
  return {duration: audio.duration, rms: Math.sqrt(sum / data.length)};
}"""

PLAY_VIDEO_JS = """async ([b64, mime]) => {
  const bin = atob(b64); const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const video = document.createElement('video'); video.muted = true;
  video.src = URL.createObjectURL(new Blob([bytes], {type: mime}));
  document.body.appendChild(video);
  await new Promise((res, rej) => { video.onloadeddata = res; video.onerror = () => rej(new Error('video error ' + (video.error && video.error.code))); });
  await video.play(); await new Promise(r => setTimeout(r, 700));
  return {width: video.videoWidth, height: video.videoHeight, duration: video.duration, time: video.currentTime};
}"""


@pytest.fixture(scope="module")
def chrome_clips():
    """A voice and a video clip recorded by Chrome's MediaRecorder from its fake devices."""

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<!doctype html><title>recorder</title>")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)  # localhost is a secure context
    threading.Thread(target=server.serve_forever, daemon=True).start()
    clips = {}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome", headless=True, args=CHROME_ARGS)
            context = browser.new_context()
            context.grant_permissions(["microphone", "camera"])
            page = context.new_page()
            page.goto(f"http://127.0.0.1:{server.server_address[1]}/")
            for mode in ("voice", "video"):
                mime, data = page.evaluate(RECORD_JS, mode)
                clips[mode] = (mime, base64.b64decode(data))
            browser.close()
    finally:
        server.shutdown()
    return clips


def chrome_decode_audio(raw):
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page()
        result = page.evaluate(DECODE_AUDIO_JS, base64.b64encode(raw).decode())
        browser.close()
    return result


def chrome_play_video(raw, mime):
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page()
        result = page.evaluate(PLAY_VIDEO_JS, [base64.b64encode(raw).decode(), mime])
        browser.close()
    return result


# --------------------------------------------------------------------------- Desktop plays Chrome's clips


def test_desktop_decodes_a_chrome_recorded_voice_clip_to_real_audio(chrome_clips):
    mime, raw = chrome_clips["voice"]
    assert mime.startswith("audio/webm") and len(raw) > 1000

    sample_count, rms, error = decode_pcm(raw)

    assert not error, error
    assert sample_count > 48000, "the clip decoded to (almost) nothing"
    assert rms > MIN_RMS, f"the decoded voice clip is silent (rms={rms:.4f})"


def test_desktop_player_card_loads_a_chrome_voice_clip_and_reports_its_duration(chrome_clips):
    mime, raw = chrome_clips["voice"]
    card = MediaPlayerCard(raw, mime, is_video=False, text_color="#FFFFFF", meta_color="#DDDDDD",
                           accent_color="#765CF2")
    card.show()
    try:
        assert pump(lambda: card.duration_ms > 1000), "the player never learned the clip's duration"
        assert card.time_label.text()  # e.g. "0:02"
        assert not card.failed
        assert card.play_button.isEnabled()
        assert card.slider.isEnabled()
    finally:
        card.release()
        card.close()


@pytest.mark.skipif(QMediaDevices.defaultAudioOutput().isNull(), reason="no audio output device")
def test_desktop_player_card_actually_plays_and_advances_then_resets(chrome_clips):
    mime, raw = chrome_clips["voice"]
    card = MediaPlayerCard(raw, mime, is_video=False, text_color="#FFFFFF", meta_color="#DDDDDD",
                           accent_color="#765CF2")
    card.show()
    try:
        assert pump(lambda: card.duration_ms > 0)
        card.toggle()
        assert pump(lambda: card.is_playing)
        assert card.play_button.accessibleName() == "Pause voice message"
        assert pump(lambda: card._player.position() > 300), "playback never advanced"
        assert card.slider.value() > 0

        card.toggle()  # pause
        assert pump(lambda: not card.is_playing)
        assert card.play_button.accessibleName() == "Play voice message"
    finally:
        card.release()
        card.close()


def test_desktop_player_card_shows_frames_of_a_chrome_video_clip(chrome_clips):
    mime, raw = chrome_clips["video"]
    assert mime.startswith("video/webm")
    card = MediaPlayerCard(raw, mime, is_video=True, text_color="#FFFFFF", meta_color="#DDDDDD",
                           accent_color="#765CF2")
    card.show()
    try:
        assert pump(lambda: card.duration_ms > 0)
        card.toggle()
        assert pump(lambda: card.screen.pixmap() is not None and not card.screen.pixmap().isNull(), timeout=20), \
            "no video frame was ever drawn"
        assert not card.failed
    finally:
        card.release()
        card.close()


# --------------------------------------------------------------------------- Chrome plays Desktop's clips


def test_the_desktop_voice_recording_format_is_aac_in_mpeg4_audio(desktop_voice_clip):
    # ISO base media: "ftyp" box at offset 4 with an audio brand.
    assert desktop_voice_clip[4:8] == b"ftyp"
    assert desktop_voice_clip[8:12] in (b"M4A ", b"mp42", b"isom")


def test_desktop_voice_recording_decodes_in_chrome_to_real_audio(desktop_voice_clip):
    result = chrome_decode_audio(desktop_voice_clip)

    assert result["duration"] > 1.5, result
    assert result["rms"] > MIN_RMS, f"Chrome decoded the Desktop recording as silence: {result}"


def test_desktop_voice_recording_decodes_on_desktop_too(desktop_voice_clip):
    sample_count, rms, error = decode_pcm(desktop_voice_clip)

    assert not error, error
    assert sample_count > 48000
    assert rms > MIN_RMS


def test_desktop_video_recording_loads_and_plays_in_chrome(desktop_video_clip):
    assert desktop_video_clip[4:8] == b"ftyp"

    result = chrome_play_video(desktop_video_clip, "video/mp4")

    assert result["width"] == 320 and result["height"] == 240, result
    assert result["duration"] > 1.5, result
    assert result["time"] > 0.2, f"the video did not advance: {result}"


def test_desktop_player_card_plays_the_desktop_recorded_video(desktop_video_clip):
    card = MediaPlayerCard(desktop_video_clip, "video/mp4", is_video=True, text_color="#FFFFFF",
                           meta_color="#DDDDDD", accent_color="#765CF2")
    card.show()
    try:
        assert pump(lambda: card.duration_ms > 1000)
        card.toggle()
        assert pump(lambda: card.screen.pixmap() is not None and not card.screen.pixmap().isNull(), timeout=20)
    finally:
        card.release()
        card.close()


# --------------------------------------------------------------------------- invalid media


@pytest.mark.parametrize("payload_type, mime", [
    (PayloadType.VOICE, "audio/mp4"),
    (PayloadType.VIDEO, "video/mp4"),
])
def test_undecodable_media_is_reported_on_the_card_and_never_raises(payload_type, mime):
    bubble = FileMessageBubble(
        b"this is not audio or video, just some bytes" * 50,
        {"filename": "broken", "mime_type": mime, "size_bytes": 2150},
        kind="received",
        payload_type=payload_type,
    )
    bubble.show()
    try:
        card = bubble._media_card
        for _ in range(3):
            card.toggle()
            _app.processEvents()
        assert pump(lambda: card.failed, timeout=10), "an undecodable clip was never reported"
        assert not card.play_button.isEnabled()
        assert "can't be played" in card.status_label.text()
        assert not card.status_label.isHidden()
        card.toggle()  # pressing play after failure is a no-op, not an error
    finally:
        bubble._media_card.release()
        bubble.close()


def test_an_empty_clip_cannot_be_played_and_does_not_raise():
    card = MediaPlayerCard(b"", "audio/mp4", is_video=False, text_color="#FFFFFF", meta_color="#DDDDDD",
                           accent_color="#765CF2")
    card.show()
    try:
        card.toggle()
        _app.processEvents()
        assert not card.is_playing
    finally:
        card.close()


def test_a_deleted_voice_message_drops_its_audio_and_its_player():
    bubble = FileMessageBubble(
        b"x" * 100, {"filename": "v.m4a", "mime_type": "audio/mp4"}, kind="sent",
        payload_type=PayloadType.VOICE,
    )
    bubble.show()
    bubble.mark_deleted()

    assert bubble._file_bytes is None
    assert bubble._media_card.isHidden()
    assert bubble._title_label.text() == "Message deleted"


# --------------------------------------------------------------------------- across the real server


def test_web_recorded_voice_reaches_desktop_as_playable_audio(running_server, gateway_url, browser_page, desktop_app):
    """Web -> Desktop: record in the Website's modal (Chrome's fake microphone), send it through
    the encrypted pipeline, and decode what the Desktop client decrypted."""

    alice_payload = desktop_app["register"]("mvoice_a_")
    alice = desktop_app["launch"](alice_payload)
    bob_payload = _register("mvoice_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_payload["username"])
        _open_direct_chat_in_browser(page, alice.username)
        _establish_key_in_browser(page, alice.username)

        received = []
        alice.payload_message_received.connect(
            lambda key, sender, payload_type, data, metadata: received.append((payload_type, bytes(data), metadata))
        )

        _record_and_send(page, "voice")
        assert _wait_for(lambda: len(received) == 1, attempts=200, interval=0.1)

        payload_type, data, metadata = received[0]
        assert payload_type == "voice"
        sample_count, rms, error = decode_pcm(data)
        assert not error, error
        assert sample_count > 24000 and rms > MIN_RMS, f"the received voice message is silent: rms={rms:.4f}"

        bubble = FileMessageBubble(data, metadata, kind="received", sender="bob", payload_type=PayloadType.VOICE)
        bubble.show()
        try:
            assert pump(lambda: bubble._media_card.duration_ms > 500)
            assert not bubble._media_card.failed
        finally:
            bubble._media_card.release()
            bubble.close()
    finally:
        _delete(bob_payload["username"])


def test_desktop_recorded_voice_reaches_web_as_playable_audio(
    running_server, gateway_url, browser_page, desktop_app, desktop_voice_clip, tmp_path
):
    """Desktop -> Web: send the Desktop recorder's AAC clip through the encrypted attachment
    pipeline and check the Website's own <audio> element can play what it decrypted."""

    alice_payload = desktop_app["register"]("dvoice_a_")
    alice = desktop_app["launch"](alice_payload)
    bob_payload = _register("dvoice_b_")
    try:
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: alice.key_manager.get_public_key(bob_username) is not None)
        _verify_browser_observes_desktop(alice, page)
        _verify_desktop_observes_browser(alice, page, bob_username)
        _open_direct_chat_in_browser(page, alice.username)

        from domain.conversation_summary import ConversationSummary
        alice.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob_username, is_online=True, latest_message=None)
        )
        alice.establish_session_key()
        assert _wait_for(lambda: alice.key_manager.has_key(alice.current_conversation_id))

        clip = tmp_path / "voice-message.m4a"
        clip.write_bytes(desktop_voice_clip)
        payload_type, _data, _metadata = alice.send_attachment(str(clip))
        assert payload_type == PayloadType.VOICE

        assert _wait_for(lambda: page.evaluate("!!document.querySelector('#messages audio.bubble-media')"),
                         attempts=200, interval=0.1)

        info = page.evaluate("""async () => {
          const audio = document.querySelector('#messages audio.bubble-media');
          if (audio.readyState < 1) await new Promise((res, rej) => {
            audio.onloadedmetadata = res; audio.onerror = () => rej(new Error('audio error ' + (audio.error && audio.error.code)));
          });
          const bytes = new Uint8Array(await (await fetch(audio.src)).arrayBuffer());
          const ctx = new AudioContext();
          const decoded = await ctx.decodeAudioData(bytes.buffer.slice(0));
          const data = decoded.getChannelData(0); let sum = 0;
          for (let i = 0; i < data.length; i++) sum += data[i] * data[i];
          return {duration: audio.duration, rms: Math.sqrt(sum / data.length), size: bytes.length};
        }""")
        assert info["duration"] > 1.5, info
        assert info["rms"] > MIN_RMS, f"the received voice message is silent: {info}"
        assert info["size"] == len(desktop_voice_clip), "the decrypted clip differs from the one sent"
    finally:
        _delete(bob_payload["username"])
