"""
D8 / P1 -- file and data hardening.

Four separate weaknesses, four sections:

  * The attachment size limit existed only in client/session.py, so it
    bound only clients that chose to be bound. FILE_STORAGE_ROOT has
    no quota, no retention policy and no cleanup.
  * storage/encrypted_blob_store.py built its path as
    ``FILE_STORAGE_ROOT / reference`` with no validation. Not reachable
    from a client today, but the containment was an argument about
    callers rather than a property of the module.
  * The Save As filename came straight from the sender.
  * Image bytes went to QPixmap.loadFromData() with no format
    allowlist and no dimension bound.
"""

import os
import struct
import uuid
import zlib

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QBuffer, QByteArray, QIODevice
from PySide6.QtGui import QColor, QImage
from PySide6.QtWidgets import QApplication

from config import MAX_ATTACHMENT_CIPHERTEXT_BYTES, MAX_ATTACHMENT_SIZE_BYTES
from domain.payload_type import PayloadType
from server import client_handler
from storage import encrypted_blob_store
from storage.encrypted_blob_store import (
    InvalidBlobReference,
    _path_for,
    delete_blob,
    load_blob,
    store_blob,
)

_app = QApplication.instance() or QApplication([])


# ----------------------------------------------------------------------
# Blob reference containment
# ----------------------------------------------------------------------

TRAVERSAL_REFERENCES = [
    "../../etc/passwd",
    "..\\..\\Windows\\System32\\config\\SAM",
    "../" * 12 + "etc/shadow",
    "..",
    ".",
    "",
    "subdir/file",
    "a/../../../b",
]

ABSOLUTE_REFERENCES = [
    "C:/Windows/win.ini",
    "C:\\Windows\\win.ini",
    "/etc/passwd",
    "//host/share/secret",
    "\\\\host\\share\\secret",
]

MALFORMED_REFERENCES = [
    None,
    12345,
    b"a" * 32,
    "A" * 32,          # uppercase hex is not what uuid4().hex emits
    "g" * 32,          # not hex at all
    "a" * 31,          # too short
    "a" * 33,          # too long
    "a" * 16 + "-" + "a" * 15,
]


@pytest.mark.parametrize("reference", TRAVERSAL_REFERENCES)
def test_traversal_references_are_rejected(reference):
    with pytest.raises(InvalidBlobReference):
        _path_for(reference)


@pytest.mark.parametrize("reference", ABSOLUTE_REFERENCES)
def test_absolute_and_unc_references_are_rejected(reference):
    """pathlib DISCARDS the left operand when the right is absolute or
    UNC, so ``FILE_STORAGE_ROOT / "C:/Windows/win.ini"`` was simply
    ``C:/Windows/win.ini`` -- the escape needed no "..'' at all."""

    with pytest.raises(InvalidBlobReference):
        _path_for(reference)


@pytest.mark.parametrize("reference", MALFORMED_REFERENCES)
def test_malformed_references_are_rejected(reference):
    with pytest.raises(InvalidBlobReference):
        _path_for(reference)


def test_a_generated_reference_is_accepted_and_stays_inside_the_root():
    reference = uuid.uuid4().hex

    resolved = _path_for(reference)

    assert resolved.name == reference
    assert resolved.is_relative_to(encrypted_blob_store.FILE_STORAGE_ROOT.resolve())


def test_store_and_load_still_round_trip():
    """The containment check must not break the legitimate path."""

    reference = store_blob(b"opaque ciphertext")

    try:
        assert load_blob(reference) == b"opaque ciphertext"
    finally:
        delete_blob(reference)


def test_load_of_a_hostile_reference_never_reads_a_file(tmp_path):
    """End-to-end: even handed a reference pointing at a real file
    outside the root, load_blob() refuses rather than returning its
    contents."""

    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"TOP SECRET")

    hostile = str(outside)

    with pytest.raises(InvalidBlobReference):
        load_blob(hostile)


# ----------------------------------------------------------------------
# Server-side attachment size limit
# ----------------------------------------------------------------------


def _attachment_packet(ciphertext):
    return {
        "payload_type": PayloadType.FILE,
        "message": ciphertext,
        "content_metadata": {"filename": "x.bin", "size": len(ciphertext)},
        "timestamp": None,
        "epoch": 1,
    }


def test_oversized_attachment_is_rejected_before_it_reaches_disk(monkeypatch):
    """The L-2 frame cap bounds memory during the read; this bounds
    disk at rest. A modified client that skips the client-side check
    must still be refused."""

    monkeypatch.setattr(client_handler, "MAX_ATTACHMENT_CIPHERTEXT_BYTES", 1000)

    written = []
    monkeypatch.setattr(
        client_handler.encrypted_blob_store,
        "store_blob",
        lambda data: written.append(data) or "deadbeef" * 4,
    )

    with pytest.raises(ValueError, match="Attachment ciphertext"):
        client_handler.persist_message(
            sender_id=uuid.uuid4(),
            receiver_id=uuid.uuid4(),
            algorithm="KYBER",
            packet=_attachment_packet("x" * 1001),
            conversation_id=uuid.uuid4(),
        )

    assert written == [], "an oversized attachment reached the blob store"


def test_attachment_exactly_at_the_limit_is_not_rejected(monkeypatch):
    """Boundary: the limit is inclusive, so a maximum-size attachment
    must still be accepted. Stops short of the database write -- what
    is under test is the guard, not persistence."""

    monkeypatch.setattr(client_handler, "MAX_ATTACHMENT_CIPHERTEXT_BYTES", 1000)

    written = []
    monkeypatch.setattr(
        client_handler.encrypted_blob_store,
        "store_blob",
        lambda data: written.append(data) or "d" * 32,
    )

    class _Stop(Exception):
        pass

    def _explode(*args, **kwargs):
        raise _Stop

    monkeypatch.setattr(client_handler.MessageRepository, "save_message", _explode)

    with pytest.raises(_Stop):
        client_handler.persist_message(
            sender_id=uuid.uuid4(),
            receiver_id=uuid.uuid4(),
            algorithm="KYBER",
            packet=_attachment_packet("x" * 1000),
            conversation_id=uuid.uuid4(),
        )

    assert len(written) == 1, "a legitimate maximum-size attachment was rejected"


def test_the_server_limit_matches_a_real_maximum_attachment():
    """The bound is the EXACT ciphertext a maximum-size attachment
    produces -- derived from the pipeline, not rounded."""

    assert MAX_ATTACHMENT_CIPHERTEXT_BYTES == 46_603_420
    assert MAX_ATTACHMENT_CIPHERTEXT_BYTES > MAX_ATTACHMENT_SIZE_BYTES


def test_text_messages_are_unaffected_by_the_attachment_limit(monkeypatch):
    """TEXT payloads are stored inline, never as blobs, and must not
    be measured against an attachment limit."""

    monkeypatch.setattr(client_handler, "MAX_ATTACHMENT_CIPHERTEXT_BYTES", 10)

    class _Stop(Exception):
        pass

    def _explode(*args, **kwargs):
        raise _Stop

    monkeypatch.setattr(client_handler.MessageRepository, "save_message", _explode)

    # Reaching save_message() proves the size guard did not fire.
    with pytest.raises(_Stop):
        client_handler.persist_message(
            sender_id=uuid.uuid4(),
            receiver_id=uuid.uuid4(),
            algorithm="KYBER",
            packet={
                "payload_type": PayloadType.TEXT,
                "message": "y" * 5000,
                "content_metadata": {},
                "timestamp": None,
                "epoch": 1,
            },
            conversation_id=uuid.uuid4(),
        )


# ----------------------------------------------------------------------
# Filename sanitisation
# ----------------------------------------------------------------------


def test_filename_sanitisation():
    from gui.message_widget import _safe_filename

    cases = {
        "holiday.png": "holiday.png",
        "../../../etc/passwd": "passwd",
        "..\\..\\Windows\\System32\\evil.exe": "evil.exe",
        "C:/Windows/win.ini": "win.ini",
        "//host/share/x.txt": "x.txt",
        "..": "FALLBACK",
        ".....": "FALLBACK",
        "": "FALLBACK",
        "CON": "FALLBACK",
        "con.txt": "FALLBACK",
        "LPT1.dat": "FALLBACK",
    }

    for raw, expected in cases.items():
        assert _safe_filename(raw, "FALLBACK") == expected, raw


def test_filename_sanitisation_handles_non_strings():
    from gui.message_widget import _safe_filename

    for raw in (None, 123, b"bytes.txt", ["x"]):
        assert _safe_filename(raw, "FALLBACK") == "FALLBACK"


def test_bidirectional_override_is_stripped():
    """U+202E is the classic trick: "photo<RLO>gnp.exe" DISPLAYS as
    "photoexe.png" while remaining an .exe."""

    from gui.message_widget import _safe_filename

    deceptive = "photo" + chr(0x202E) + "gnp.exe"

    cleaned = _safe_filename(deceptive, "FALLBACK")

    assert chr(0x202E) not in cleaned
    assert cleaned.endswith(".exe"), "the real extension must stay visible"


def test_control_characters_are_stripped():
    from gui.message_widget import _safe_filename

    cleaned = _safe_filename("bad\x00na\tme\r\n.txt", "FALLBACK")

    assert all(ord(character) >= 0x20 for character in cleaned)


def test_absurdly_long_filenames_are_truncated_keeping_the_extension():
    from gui.message_widget import _safe_filename

    cleaned = _safe_filename("a" * 4000 + ".png", "FALLBACK")

    assert len(cleaned) <= 120
    assert cleaned.endswith(".png")


def test_bubbles_sanitise_the_filename_at_ingress():
    from gui.message_widget import FileMessageBubble, ImageMessageBubble

    file_bubble = FileMessageBubble(
        b"data",
        {"filename": "../../../etc/passwd", "size": 4},
        kind="received",
        sender="mallory",
    )
    assert file_bubble._filename == "passwd"

    image_bubble = ImageMessageBubble(
        b"data",
        kind="received",
        sender="mallory",
        content_metadata={"filename": "..\\..\\evil.exe"},
    )
    assert image_bubble._filename == "evil.exe"


# ----------------------------------------------------------------------
# Image decoding
# ----------------------------------------------------------------------


def _png(width, height, payload_bytes=16):
    """A structurally valid PNG header declaring width x height, with
    almost no pixel data -- a decompression bomb in miniature."""

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00" * payload_bytes))
        + chunk(b"IEND", b"")
    )


def _real_png(width, height):
    image = QImage(width, height, QImage.Format_RGB32)
    image.fill(QColor(10, 20, 30))

    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    data = bytes(buffer.data())
    buffer.close()

    return data


def test_a_legitimate_image_still_decodes():
    from gui.message_widget import _decode_image

    pixmap = _decode_image(_real_png(64, 48))

    assert pixmap is not None
    assert (pixmap.width(), pixmap.height()) == (64, 48)


def test_decompression_bomb_is_rejected():
    """68 bytes of PNG declaring 30000x30000 -- decoding would try to
    allocate roughly 3.6 GB on the RECIPIENT's machine. The frame and
    attachment limits are no help: the file is tiny."""

    from gui.message_widget import MAX_IMAGE_PIXELS, _decode_image

    bomb = _png(30000, 30000)

    assert len(bomb) < 1000, "the bomb should be tiny -- that is the point"
    assert 30000 * 30000 > MAX_IMAGE_PIXELS
    assert _decode_image(bomb) is None


def test_dimensions_are_checked_from_the_header_before_decoding():
    """Proves the limit is applied to the DECLARED size: QImageReader
    reports it without decoding pixels."""

    from PySide6.QtGui import QImageReader

    buffer = QBuffer()
    buffer.setData(QByteArray(_png(30000, 30000)))
    buffer.open(QIODevice.ReadOnly)

    try:
        reader = QImageReader(buffer)
        size = reader.size()

        assert size.isValid()
        assert (size.width(), size.height()) == (30000, 30000)
    finally:
        buffer.close()


def test_formats_outside_the_allowlist_are_rejected():
    from gui.message_widget import _decode_image

    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>'

    assert _decode_image(svg) is None


def test_invalid_image_data_is_rejected_without_raising():
    from gui.message_widget import _decode_image

    for data in (b"", None, b"not an image", b"\x89PNG\r\n\x1a\n" + b"\x00" * 40):
        assert _decode_image(data) is None


def test_the_bubble_falls_back_cleanly_for_undecodable_data():
    from gui.message_widget import ImageMessageBubble

    bubble = ImageMessageBubble(b"not an image", kind="received", sender="mallory")

    assert bubble.thumbnail_size() is None
    assert bubble.full_size() is None
    assert "[Unable to display image]" in bubble.image_label.text()


def test_the_bubble_falls_back_cleanly_for_a_decompression_bomb():
    from gui.message_widget import ImageMessageBubble

    bubble = ImageMessageBubble(_png(30000, 30000), kind="received", sender="mallory")

    assert bubble.full_size() is None
    assert "[Unable to display image]" in bubble.image_label.text()
