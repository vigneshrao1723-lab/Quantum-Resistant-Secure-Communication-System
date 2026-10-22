"""
Profile pictures are checked before they are stored: the format must be a supported image, the
header must parse, and the dimensions must be sane. The picture is then visible to the contacts who
look the account up.

* the header parser against real encoded images (PNG, JPEG, GIF and WebP made by Qt and by hand);
* the real server over TLS: a valid picture is stored and fetchable by another account; a non-image,
  a renamed document, a truncated file, an absurd size and an oversized file are all refused and
  leave the previous picture alone.
"""

import os
import struct
import uuid
import zlib

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QBuffer, QIODevice
from PySide6.QtGui import QColor, QGuiApplication, QImage

from security.image_validation import (
    MAX_SIDE,
    InvalidImageError,
    inspect_image,
)
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401 -- fixtures reused
    accounts,
    connect,
    running_server,
)

_gui = QGuiApplication.instance() or QGuiApplication([])


# A valid 1x1 GIF (Qt cannot write GIFs); the logical-screen size is rewritten to the size wanted.
_GIF_1X1 = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)


def _gif(width, height):
    return _GIF_1X1[:6] + struct.pack("<HH", width, height) + _GIF_1X1[10:]


def _encode(width, height, fmt):
    if fmt == "GIF":
        return _gif(width, height)
    image = QImage(width, height, QImage.Format_RGB32)
    image.fill(QColor("#3D6291"))
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    assert image.save(buffer, fmt), f"Qt could not encode {fmt}"
    return bytes(buffer.data())


def _png_header(width, height):
    """A PNG signature + IHDR declaring ``width`` x ``height`` (no pixel data: header-only)."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr
        + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    )


# ------------------------------------------------------------------ the header parser


@pytest.mark.parametrize("fmt, expected", [("PNG", "png"), ("JPEG", "jpeg"), ("GIF", "gif")])
def test_real_encoded_images_report_their_format_and_size(fmt, expected):
    data = _encode(200, 120, fmt)

    assert inspect_image(data) == (expected, 200, 120)


def test_a_real_webp_reports_its_size():
    data = _encode(96, 64, "WEBP")

    assert inspect_image(data) == ("webp", 96, 64)


@pytest.mark.parametrize("data", [
    b"",
    b"hello world, this is not an image",
    b"<script>alert(1)</script>" * 4,
    b"%PDF-1.7 " + b"x" * 64,
    b"MZ" + b"\x00" * 64,                    # an executable
    b"\x89PNG\r\n\x1a\n" + b"\x00" * 4,      # a PNG signature and nothing else
    b"\xff\xd8\xff" + b"\x00" * 6,           # a JPEG marker and nothing else
])
def test_things_that_are_not_images_are_refused(data):
    with pytest.raises(InvalidImageError):
        inspect_image(data)


def test_a_random_png_signature_with_garbage_is_refused_or_out_of_range():
    garbage = b"\x89PNG\r\n\x1a\n" + os.urandom(256)

    with pytest.raises(InvalidImageError):
        inspect_image(garbage)


@pytest.mark.parametrize("width, height", [(MAX_SIDE + 1, 10), (10, MAX_SIDE + 1), (0, 10), (10, 0)])
def test_absurd_dimensions_are_refused_from_the_header_alone(width, height):
    with pytest.raises(InvalidImageError):
        inspect_image(_png_header(width, height))


def test_too_many_pixels_is_refused_even_when_each_side_is_allowed():
    with pytest.raises(InvalidImageError):
        inspect_image(_png_header(MAX_SIDE, MAX_SIDE))      # 67 megapixels


def test_a_large_but_reasonable_photo_is_accepted():
    assert inspect_image(_png_header(4032, 3024))[1:] == (4032, 3024)


# ------------------------------------------------------------------ against the real server


def _upload(session, data):
    return session.upload_profile_picture(data, content_type="image/png")


def test_a_valid_picture_is_stored_and_visible_to_a_contact(tmp_path, connect, accounts):
    alice_payload, bob_payload = accounts("alice_"), accounts("bob_")
    alice, bob = connect(alice_payload), connect(bob_payload)
    picture = _encode(256, 256, "PNG")

    assert _upload(alice, picture)["success"] is True

    assert bob.fetch_profile_picture(alice_payload["username"]) == picture


@pytest.mark.parametrize("label, data", [
    ("plain text", b"this is just text, not a picture" * 4),
    ("a document", b"%PDF-1.7\n" + b"x" * 200),
    ("garbage with a PNG signature", b"\x89PNG\r\n\x1a\n" + os.urandom(128)),
    ("an absurd size", _png_header(60000, 60000)),
])
def test_non_images_and_absurd_images_are_refused_and_the_old_picture_stays(tmp_path, connect, accounts, label, data):
    payload = accounts("alice_")
    alice = connect(payload)
    first = _encode(128, 128, "PNG")
    assert _upload(alice, first)["success"]

    result = _upload(alice, data)

    assert result["success"] is False, label
    assert result["error"], label
    assert alice.fetch_profile_picture(payload["username"]) == first


def test_an_oversized_file_is_refused_by_size(tmp_path, connect, accounts):
    payload = accounts("alice_")
    alice = connect(payload)
    too_big = _encode(64, 64, "PNG") + b"\x00" * (2 * 1024 * 1024)

    result = _upload(alice, too_big)

    assert result["success"] is False
    assert "MB" in result["error"]
    assert alice.fetch_profile_picture(payload["username"]) is None


def test_every_supported_format_is_accepted(tmp_path, connect, accounts):
    payload = accounts("alice_")
    alice = connect(payload)

    for fmt in ("PNG", "JPEG", "GIF", "WEBP"):
        assert _upload(alice, _encode(80, 80, fmt))["success"] is True, fmt
