"""
Tests for domain/payload_type.py::classify_attachment() (Phase 8 --
File & Image Transfer; Phase 19.24 -- Voice/Video Messages).

Pure unit tests -- no database, no socket, no GUI. Classification is
by MIME type via the standard library's extension table, never a
user prompt: every filename below must resolve to exactly one of
PayloadType.IMAGE / VOICE / VIDEO / FILE with no fifth outcome.

Run with:
    pytest tests/test_attachment_classification.py -v
"""

import pytest

from domain.payload_type import PayloadType, classify_attachment


@pytest.mark.parametrize(
    "filename",
    [
        "photo.jpg",
        "photo.jpeg",
        "photo.png",
        "photo.gif",
        "photo.bmp",
        "PHOTO.PNG",
        "a/path/to/photo.jpg",
    ],
)
def test_image_extensions_classify_as_image(filename):
    assert classify_attachment(filename) == PayloadType.IMAGE


@pytest.mark.parametrize("filename", ["audio.mp3", "clip.m4a", "clip.wav", "clip.ogg"])
def test_audio_extensions_classify_as_voice(filename):
    assert classify_attachment(filename) == PayloadType.VOICE


@pytest.mark.parametrize("filename", ["video.mp4", "clip.webm", "movie.mov"])
def test_video_extensions_classify_as_video(filename):
    assert classify_attachment(filename) == PayloadType.VIDEO


@pytest.mark.parametrize(
    "filename",
    [
        "document.pdf",
        "notes.txt",
        "archive.zip",
        "spreadsheet.xlsx",
        "no_extension_at_all",
        "",
    ],
)
def test_non_media_files_classify_as_file(filename):
    assert classify_attachment(filename) == PayloadType.FILE


def test_classification_never_returns_a_fifth_payload_type():
    """The user is never asked to choose -- classify_attachment() must
    always resolve to exactly one of IMAGE/VOICE/VIDEO/FILE, never TEXT
    or anything else."""
    for filename in ("photo.png", "document.pdf", "mystery.xyz", "clip.m4a", "clip.mp4"):
        result = classify_attachment(filename)
        assert result in (PayloadType.IMAGE, PayloadType.VOICE, PayloadType.VIDEO, PayloadType.FILE)
