"""
Tests for domain/payload_type.py::classify_attachment() (Phase 8 --
File & Image Transfer).

Pure unit tests -- no database, no socket, no GUI. Classification is
by MIME type via the standard library's extension table, never a
user prompt: every filename below must resolve to exactly one of
PayloadType.IMAGE / PayloadType.FILE with no third outcome.

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


@pytest.mark.parametrize(
    "filename",
    [
        "document.pdf",
        "notes.txt",
        "archive.zip",
        "spreadsheet.xlsx",
        "video.mp4",
        "audio.mp3",
        "no_extension_at_all",
        "",
    ],
)
def test_non_image_files_classify_as_file(filename):
    assert classify_attachment(filename) == PayloadType.FILE


def test_classification_never_returns_a_third_payload_type():
    """The user is never asked to choose -- classify_attachment() must
    always resolve to exactly IMAGE or FILE, never TEXT or anything
    else."""
    for filename in ("photo.png", "document.pdf", "mystery.xyz"):
        result = classify_attachment(filename)
        assert result in (PayloadType.IMAGE, PayloadType.FILE)
