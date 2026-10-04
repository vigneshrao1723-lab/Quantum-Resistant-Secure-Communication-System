"""
Phase 19.24 (closure pass) -- Media Gallery: mobile ChatScreen UI
wiring, closing the previous Desktop-only gap.

Mirrors tests/test_phase19_24_desktop_media_gallery.py's own contract
exactly: operates entirely over already-decrypted, already-rendered
bubbles (ChatScreen._media_bubbles()) -- no second history fetch, no
server-side plaintext indexing. Drives the REAL _media_bubbles()/
_open_media_gallery()/_build_gallery_tile() code a real header button
tap actually runs, against a REAL running server and REAL
MobileClientSession instances.

Run with:
    pytest tests/test_phase19_24_mobile_media_gallery.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from kivy.clock import Clock

from domain.payload_type import PayloadType
from mobile.app import ChatScreen
from tests.test_phase19_24_mobile_drafts import _three_mobile_sessions  # noqa: F401
from tests.test_device_key_sync import _delete, _wait_for, running_server  # noqa: F401

_app = QApplication.instance() or QApplication([])

_VALID_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000a49444154789c6360000002000100"
    "0dae7f870000000049454e44ae426082"
)


def _ticking(predicate):
    def _poll():
        Clock.tick()
        return predicate()
    return _poll


def test_gallery_is_empty_before_any_attachment_is_sent(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mgalempty"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)
        assert screen._media_bubbles(bob.username) == []
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_gallery_lists_a_sent_image_and_a_sent_file(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mgalsend"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        screen._send_attachment(bob.username, False, "photo.png", _VALID_PNG_BYTES)
        screen._send_attachment(bob.username, False, "report.txt", b"plain document content")

        media = screen._media_bubbles(bob.username)
        assert len(media) == 2
        assert media[0].payload_type == PayloadType.IMAGE
        assert media[1].payload_type == PayloadType.FILE
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_gallery_reaches_the_real_recipient_too(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mgalrecv"
    )
    try:
        alice_screen = ChatScreen(alice)
        alice_screen.open_chat(bob.username)
        bob_screen = ChatScreen(bob)
        bob_screen.open_chat(alice.username)

        alice_screen._send_attachment(bob.username, False, "photo.png", _VALID_PNG_BYTES)

        assert _wait_for(_ticking(lambda: len(bob_screen._media_bubbles(alice.username)) == 1))
        assert bob_screen._media_bubbles(alice.username)[0].payload_type == PayloadType.IMAGE
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_gallery_dialog_does_not_crash_when_empty(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mgalcrash"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)
        screen._open_media_gallery(bob.username)  # must not raise
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_gallery_dialog_builds_a_real_tile_for_an_image(running_server, monkeypatch, tmp_path):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mgaltile"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)
        screen._send_attachment(bob.username, False, "photo.png", _VALID_PNG_BYTES)

        bubble = screen._media_bubbles(bob.username)[0]
        tile = screen._build_gallery_tile(bubble)  # must not raise
        assert tile is not None

        screen._open_media_gallery(bob.username)  # full dialog build must not raise
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
