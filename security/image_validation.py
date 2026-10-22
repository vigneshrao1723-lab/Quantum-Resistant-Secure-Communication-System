"""
Cheap, dependency-free validation of an image's FORMAT and DIMENSIONS from its header.

A profile picture is stored as given and served to every other user who looks the account up, so
the server checks what it is about to store: the bytes must start as one of the supported formats
(PNG, JPEG, WebP, GIF), the header must parse, and the declared dimensions must be sane. Reading
only the header means a malicious "image" cannot make the server decode a decompression bomb --
and rejects non-images (a script or document renamed ``.png``) outright.

This is a gate, not a decoder: it does not prove the file decodes everywhere, only that it is
what it says and is a reasonable size. Clients crop and re-encode what they upload.
"""

import struct

MIN_SIDE = 1
MAX_SIDE = 8192
MAX_PIXELS = 40_000_000

SUPPORTED_FORMATS = ("png", "jpeg", "webp", "gif")


class InvalidImageError(ValueError):
    """The bytes are not a supported image, or its declared size is out of range."""


def inspect_image(data):
    """Return ``(format, width, height)`` for PNG/JPEG/WebP/GIF ``data``; raise InvalidImageError."""

    if not isinstance(data, (bytes, bytearray)) or len(data) < 16:
        raise InvalidImageError("That file is not a supported image (PNG, JPEG, WebP or GIF).")

    data = bytes(data)

    if data[:8] == b"\x89PNG\r\n\x1a\n":
        image_format, width, height = "png", *_png_size(data)
    elif data[:3] == b"\xff\xd8\xff":
        image_format, width, height = "jpeg", *_jpeg_size(data)
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        image_format = "gif"
        width, height = struct.unpack("<HH", data[6:10])
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        image_format, width, height = "webp", *_webp_size(data)
    else:
        raise InvalidImageError("That file is not a supported image (PNG, JPEG, WebP or GIF).")

    if not (MIN_SIDE <= width <= MAX_SIDE and MIN_SIDE <= height <= MAX_SIDE) or width * height > MAX_PIXELS:
        raise InvalidImageError(
            f"Image dimensions must be between {MIN_SIDE} and {MAX_SIDE} pixels on each side."
        )

    return image_format, width, height


def _png_size(data):
    # signature, then the IHDR chunk: length (4) "IHDR" width (4) height (4)
    if data[12:16] != b"IHDR" or len(data) < 24:
        raise InvalidImageError("That file is not a supported image (PNG, JPEG, WebP or GIF).")
    return struct.unpack(">II", data[16:24])


def _jpeg_size(data):
    index = 2
    length = len(data)
    while index + 4 <= length:
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        index += 2
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue  # markers with no length
        if marker == 0xFF:
            index -= 1
            continue
        if index + 2 > length:
            break
        segment = struct.unpack(">H", data[index:index + 2])[0]
        # Start-of-frame markers carry the size (not DHT 0xC4, JPG 0xC8, DAC 0xCC).
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if index + 7 > length:
                break
            height, width = struct.unpack(">HH", data[index + 3:index + 7])
            return width, height
        index += segment
    raise InvalidImageError("That file is not a supported image (PNG, JPEG, WebP or GIF).")


def _webp_size(data):
    chunk = data[12:16]
    try:
        if chunk == b"VP8 ":
            # frame tag (3) + start code 9d 01 2a (3), then 14-bit width and height
            if data[23:26] != b"\x9d\x01\x2a":
                raise InvalidImageError("That file is not a supported image (PNG, JPEG, WebP or GIF).")
            width, height = struct.unpack("<HH", data[26:30])
            return width & 0x3FFF, height & 0x3FFF
        if chunk == b"VP8L":
            if data[20] != 0x2F:
                raise InvalidImageError("That file is not a supported image (PNG, JPEG, WebP or GIF).")
            bits = struct.unpack("<I", data[21:25])[0]
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        if chunk == b"VP8X":
            width = int.from_bytes(data[24:27], "little") + 1
            height = int.from_bytes(data[27:30], "little") + 1
            return width, height
    except struct.error:
        pass
    raise InvalidImageError("That file is not a supported image (PNG, JPEG, WebP or GIF).")
