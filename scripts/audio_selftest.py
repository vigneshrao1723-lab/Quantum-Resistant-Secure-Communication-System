"""
Check this computer's microphone, speakers and the Desktop app's recording and playback path.

Run it yourself, in a terminal, with the project's Python 3.12 environment:

    & "C:\\Users\\Vignesh T\\venvs\\qrscs312\\Scripts\\python.exe" scripts\\audio_selftest.py

It plays a short tone (so you can check you hear it), then records three seconds from each
microphone (so speak, or clap, when told to) with the same recorder settings the Desktop app uses,
measures how loud the recording is, and plays it back through the app's own playback path.

Nothing is sent anywhere and nothing is kept: the recordings are temporary files that are deleted
when the check ends. It does not touch the database, the server or any account.

    --list    only list the audio and camera devices, and play/record nothing
"""

import argparse
import math
import os
import struct
import sys
import tempfile
import wave
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.pop("QT_QPA_PLATFORM", None)  # a real window system: this checks real devices

from PySide6.QtCore import QBuffer, QByteArray, QEventLoop, QIODevice, QTimer, QUrl  # noqa: E402
from PySide6.QtMultimedia import (  # noqa: E402
    QAudioDecoder,
    QAudioFormat,
    QAudioInput,
    QAudioOutput,
    QMediaCaptureSession,
    QMediaDevices,
    QMediaPlayer,
    QMediaRecorder,
)
from PySide6.QtWidgets import QApplication  # noqa: E402

from gui.media_recorder_dialog import recording_format  # noqa: E402

SILENT_BELOW = 0.002  # RMS of a recording that is essentially digital silence
RECORD_SECONDS = 3


def _pump(milliseconds):
    loop = QEventLoop()
    QTimer.singleShot(milliseconds, loop.quit)
    loop.exec()


def _tone_wav(seconds=2.0):
    path = Path(tempfile.gettempdir()) / "qrscs_selftest_tone.wav"
    rate = 16000
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        frames = []
        for i in range(int(rate * seconds)):
            frequency = 523.25 if i < rate * seconds / 2 else 659.25
            frames.append(struct.pack("<h", int(9000 * math.sin(2 * math.pi * frequency * i / rate))))
        wav.writeframes(b"".join(frames))
    return path


def play_like_the_app(data, extension, label, device=None):
    """Play bytes exactly as a message card does (an in-memory buffer through QMediaPlayer)."""

    player = QMediaPlayer()
    output = QAudioOutput(device) if device is not None else QAudioOutput()
    output.setVolume(1.0)
    player.setAudioOutput(output)
    buffer = QBuffer()
    buffer.setData(QByteArray(bytes(data)))
    buffer.open(QIODevice.ReadOnly)
    errors = []
    player.errorOccurred.connect(lambda _e, message="": errors.append(player.errorString()))
    player.setSourceDevice(buffer, QUrl(f"clip{extension}"))
    player.play()
    positions = []
    for _ in range(40):
        _pump(100)
        positions.append(player.position())
        if player.mediaStatus() == QMediaPlayer.MediaStatus.EndOfMedia:
            break
    moved = positions[-1] > 0
    status = "the player ran to the end" if player.mediaStatus() == QMediaPlayer.MediaStatus.EndOfMedia else (
        "the player moved forward" if moved else "the player did NOT move"
    )
    if errors:
        status += f" (error: {errors[0]})"
    print(f"    {label}: {status}; output device: {output.device().description()}; "
          f"volume {output.volume():.0%}, muted: {output.isMuted()}")
    player.stop()
    player.setSource(QUrl())
    return not errors and moved


def measure(path):
    """(seconds_of_audio, rms, peak) of a recording, decoded the way the app's tests do."""

    decoder = QAudioDecoder()
    buffer = QBuffer()
    buffer.setData(QByteArray(Path(path).read_bytes()))
    buffer.open(QIODevice.ReadOnly)
    decoder.setSourceDevice(buffer)
    samples, errors, rate = [], [], [16000]
    loop = QEventLoop()

    def ready():
        while decoder.bufferAvailable():
            chunk = decoder.read()
            raw = bytes(chunk.constData())
            fmt = chunk.format()
            rate[0] = fmt.sampleRate() or rate[0]
            if fmt.sampleFormat() == QAudioFormat.SampleFormat.Int16:
                samples.extend(v / 32768 for v in struct.unpack(f"<{len(raw) // 2}h", raw[: len(raw) // 2 * 2]))
            elif fmt.sampleFormat() == QAudioFormat.SampleFormat.Float:
                samples.extend(struct.unpack(f"<{len(raw) // 4}f", raw[: len(raw) // 4 * 4]))

    decoder.bufferReady.connect(ready)
    decoder.finished.connect(loop.quit)
    decoder.error.connect(lambda _e: (errors.append(decoder.errorString()), loop.quit()))
    QTimer.singleShot(20000, loop.quit)
    decoder.start()
    loop.exec()
    if errors and not samples:
        return 0.0, 0.0, 0.0, errors[0]
    rms = math.sqrt(sum(s * s for s in samples) / len(samples)) if samples else 0.0
    peak = max((abs(s) for s in samples), default=0.0)
    return len(samples) / rate[0], rms, peak, ""


def record(microphone):
    """Record RECORD_SECONDS from ``microphone`` with the Desktop app's settings; returns the path."""

    media_format, suffix, _mime = recording_format("voice")
    session = QMediaCaptureSession()
    audio_input = QAudioInput(microphone)
    audio_input.setVolume(1.0)
    session.setAudioInput(audio_input)
    recorder = QMediaRecorder()
    session.setRecorder(recorder)
    recorder.setMediaFormat(media_format)
    recorder.setQuality(QMediaRecorder.Quality.HighQuality)
    handle, path = tempfile.mkstemp(prefix="qrscs_selftest_", suffix=suffix)
    os.close(handle)
    os.remove(path)
    recorder.setOutputLocation(QUrl.fromLocalFile(path))
    errors = []
    recorder.errorOccurred.connect(lambda _e, message="": errors.append(recorder.errorString()))
    recorder.record()
    _pump(RECORD_SECONDS * 1000)
    recorder.stop()
    _pump(800)
    return path, errors


def ask(question):
    try:
        return input(question + " [y/n] ").strip().lower().startswith("y")
    except EOFError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1], formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--list", action="store_true", help="only list devices")
    args = parser.parse_args()

    app = QApplication([])  # noqa: F841 -- must exist for the multimedia backend

    outputs, inputs, cameras = QMediaDevices.audioOutputs(), QMediaDevices.audioInputs(), QMediaDevices.videoInputs()
    print("Audio outputs (speakers/headphones):")
    for device in outputs:
        print(f"  {'*' if device.isDefault() else ' '} {device.description()}")
    print("Audio inputs (microphones):")
    for device in inputs:
        print(f"  {'*' if device.isDefault() else ' '} {device.description()}")
    print("Cameras:")
    for device in cameras:
        print(f"  {'*' if device.isDefault() else ' '} {device.description()}")
    print("(* = the one Windows has set as the default, which is what the app uses)")
    if args.list:
        return 0

    print("\n1. PLAYBACK -- you should hear two beeps (a lower, then a higher one).")
    input("   Put on your headphones / check the volume, then press Enter... ")
    tone = _tone_wav()
    try:
        plays = play_like_the_app(tone.read_bytes(), ".wav", "tone")
    finally:
        tone.unlink(missing_ok=True)
    heard = ask("   Did you hear the two beeps?")
    print("   -> speakers/headphones and the app's playback path work." if heard and plays else
          "   -> NOT heard (or the player did not move). Check the default output device and its volume in Windows "
          "Sound settings; this is why recordings can seem silent." if not heard else
          "   -> heard, but the player reported a problem (see above).")

    print(f"\n2. MICROPHONES -- {RECORD_SECONDS} seconds from each microphone, in turn.")
    results = []
    for microphone in inputs:
        input(f"\n   Microphone: {microphone.description()}\n   Press Enter, then SPEAK or clap for {RECORD_SECONDS} seconds... ")
        path, errors = record(microphone)
        try:
            if errors or not Path(path).exists() or Path(path).stat().st_size == 0:
                print(f"   -> no recording was made ({errors[0] if errors else 'empty file'}).")
                results.append((microphone.description(), "no recording"))
                continue
            seconds, rms, peak, problem = measure(path)
            verdict = ("SILENT -- this microphone captured nothing (muted, switched off, or the wrong device)"
                       if rms < SILENT_BELOW else "OK -- it captured sound")
            print(f"   -> {seconds:.1f} s, loudness {rms:.4f} (peak {peak:.2f}): {verdict}" + (f" [{problem}]" if problem else ""))
            results.append((microphone.description(), verdict.split(" --")[0]))
            if rms >= SILENT_BELOW and ask("   Play this recording back now?"):
                data = Path(path).read_bytes()
                play_like_the_app(data, Path(path).suffix, "recording")
                heard_back = ask("   Did you hear your own voice?")
                results[-1] = (results[-1][0], results[-1][1] + (", heard on playback" if heard_back else ", NOT heard on playback"))
        finally:
            Path(path).unlink(missing_ok=True)

    print("\nSummary")
    for name, outcome in results:
        print(f"  {name}: {outcome}")
    print("\nIf a microphone says SILENT, switch to the one that says OK in Windows Settings > System > Sound > Input,")
    print("or check the headset's own mute switch. Then record again in the app.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
