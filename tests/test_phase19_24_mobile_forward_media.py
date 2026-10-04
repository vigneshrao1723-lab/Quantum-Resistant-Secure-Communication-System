"""
Phase 19.24 (continued) -- Forward: mobile media forwarding.

Before this phase, mobile/app.py::Bubble discarded an attachment
bubble's decrypted bytes/mime_type after building the inner content
widget, so ChatScreen._forward_bubble_to() could only ever forward a
TEXT bubble's message_text (a known, explicitly documented gap -- see
that method's own prior docstring). Bubble now retains this content
(mirroring gui/message_widget.py's ImageMessageBubble/FileMessageBubble
on Desktop, which always did), so this file proves the real thing the
mandate calls out: forwarding an image and a voice message on Mobile
produces a genuinely new, independently encrypted message for the
target, with the CORRECT payload type preserved (not silently
downgraded to a generic file) -- driving the REAL ChatScreen._send_
attachment()/_forward_bubble_to() code against a REAL running server
and REAL MobileClientSession instances.

Run with:
    pytest tests/test_phase19_24_mobile_forward_media.py -v
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


def _ticking(predicate):
    def _poll():
        Clock.tick()
        return predicate()
    return _poll


def test_forwarding_an_image_reaches_a_third_party_with_correct_payload_type(
    running_server, monkeypatch, tmp_path
):
    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mfwdimg"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        image_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0"
            b"\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        screen._send_attachment(bob.username, False, "photo.png", image_bytes)

        assert screen._pending_send_status.get(bob.username)
        alice_bubble = list(screen._pending_send_status[bob.username])[-1]

        assert alice_bubble._attachment_bytes == image_bytes
        assert alice_bubble.payload_type == PayloadType.IMAGE

        received = []
        carol.payload_message_received.connect(
            lambda identity_key, sender, payload_type, data, content_metadata, historical, status:
                received.append((payload_type, data, content_metadata))
        )

        screen._forward_bubble_to(alice_bubble, carol.username, None)

        assert _wait_for(_ticking(lambda: len(received) > 0))
        payload_type, data, content_metadata = received[0]
        assert payload_type == PayloadType.IMAGE
        assert data == image_bytes
        assert content_metadata.get("forwarded") is True
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])


def test_forwarding_a_voice_message_preserves_its_payload_type(
    running_server, monkeypatch, tmp_path
):
    """Regression test for the same bug class fixed on Desktop
    (test_phase19_24_desktop_ui_wiring.py::test_forwarding_a_voice_
    message_preserves_its_payload_type): a naive forward implementation
    that hardcodes PayloadType.FILE (or, here, was previously simply
    unable to forward attachments at all) would silently downgrade a
    forwarded voice message, losing its playback UI on the target
    conversation."""

    alice, alice_payload, bob, bob_payload, carol, carol_payload = _three_mobile_sessions(
        running_server, monkeypatch, tmp_path, "mfwdvoice"
    )
    try:
        screen = ChatScreen(alice)
        screen.open_chat(bob.username)

        voice_bytes = b"fake recorded audio bytes, never a real codec frame"
        screen._send_attachment(bob.username, False, "clip.m4a", voice_bytes)

        alice_bubble = list(screen._pending_send_status[bob.username])[-1]
        assert alice_bubble.payload_type == PayloadType.VOICE

        received = []
        carol.payload_message_received.connect(
            lambda identity_key, sender, payload_type, data, content_metadata, historical, status:
                received.append(payload_type)
        )

        screen._forward_bubble_to(alice_bubble, carol.username, None)

        assert _wait_for(_ticking(lambda: len(received) > 0))
        assert received[0] == PayloadType.VOICE, (
            "forwarded voice message was reclassified instead of preserving PayloadType.VOICE"
        )
    finally:
        alice.disconnect()
        bob.disconnect()
        carol.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(carol_payload["username"])
