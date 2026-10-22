"""Images and files between users: delivered intact, shown to the recipient, oversize refused."""

import hashlib
import struct
import uuid
import zlib

from tests.acceptance import evidence
from tests.acceptance.parties import converse, verify_pair
from tests.acceptance.web_driver import wait_until

MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024


def _png(width=48, height=32, shade=90):
    """A real, valid PNG (solid colour) built from scratch."""
    raw = b"".join(b"\x00" + bytes([shade, 120, 200]) * width for _ in range(height))

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def _displayed_image_sha256(page):
    return page.evaluate(
        """async () => {
            const img = document.querySelector('#messages img.msg-image');
            const bytes = await (await fetch(img.src)).arrayBuffer();
            const digest = await crypto.subtle.digest('SHA-256', bytes);
            return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
        }"""
    )


def _send_file(user, path, record=True):
    if record:
        evidence.record_file(path.read_bytes())
    user.page.set_input_files("#attachmentInput", str(path))
    user.page.click("#sendAttachmentBtn")


def test_image_arrives_byte_for_byte_and_appears_in_the_gallery(party, tmp_path):
    a, b = party("web", "att_a"), party("web", "att_b")
    verify_pair(a, b)
    a.start_secure_session()

    picture = _png()
    path = tmp_path / "picture.png"
    path.write_bytes(picture)
    _send_file(a.user, path)

    wait_until(lambda: b.user.page.locator("#messages img.msg-image").count() >= 1, 30, what="the image on B")
    assert _displayed_image_sha256(b.user.page) == hashlib.sha256(picture).hexdigest(), "the image was altered in transit"

    b.user.chat_tool("galleryBtn")
    wait_until(lambda: b.user.page.evaluate("!!document.querySelector('.gallery-thumb')"), 20,
               what="the image in the media gallery")
    assert not a.errors() and not b.errors(), (a.errors(), b.errors())


def test_file_reaches_a_desktop_recipient_by_name(party, tmp_path):
    a, d = party("web", "att_web"), party("desktop", "att_desk")
    verify_pair(a, d)
    converse(a, d, "warm-up")

    name = f"report-{uuid.uuid4().hex[:6]}.txt"
    path = tmp_path / name
    path.write_text("quarterly figures")
    _send_file(a.user, path)

    d.wait_for_text(name, timeout=40)
    assert not a.errors() and not d.errors(), (a.errors(), d.errors())


def test_an_oversized_file_is_refused_and_never_delivered(party, tmp_path):
    a, b = party("web", "big_a"), party("web", "big_b")
    verify_pair(a, b)
    a.start_secure_session()

    path = tmp_path / "too-big.bin"
    path.write_bytes(b"\x00" * (MAX_ATTACHMENT_BYTES + 1))
    _send_file(a.user, path, record=False)  # 25 MiB of zeros: not worth scanning for

    wait_until(lambda: "maximum attachment size" in a.user.page.inner_text("body"), 30,
               what="the size-limit message on the sender")
    assert b.user.page.locator("#messages .bubble").count() == 0, "an oversized file reached the recipient"
