"""Small, valid images for tests, built without an imaging library."""

import struct
import zlib


def _chunk(kind, payload):
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))


def solid_png(width, height, rgb=(0x76, 0x5C, 0xF2)):
    """A valid ``width`` x ``height`` PNG of one colour."""

    row = b"\x00" + bytes(rgb) * width
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(row * height))
        + _chunk(b"IEND", b"")
    )
