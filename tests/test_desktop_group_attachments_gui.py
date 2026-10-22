"""
Desktop: attachments in a group conversation, through the real windows.

A file, a voice message and a video message sent from one member's window appear as the right kind
of bubble in the sender's group transcript and in every other member's, with the sender named; the
voice and video bubbles carry the inline player, and Save writes the exact decrypted bytes.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog

from gui.message_widget import FileMessageBubble
from tests.test_desktop_chat_settings import _group_windows  # noqa: F401 -- helper reused
from tests.test_phase19_24_desktop_ui_wiring import (  # noqa: F401 -- fixtures reused
    _two_windows,
    _wait_for,
    accounts,
    connect,
    running_server,
)

_app = QApplication.instance() or QApplication([])


@pytest.fixture()
def group(connect, accounts, tmp_path):
    pair = _two_windows(connect, accounts, tmp_path)
    return _group_windows(pair)


def _bubbles(window):
    return [
        widget for widget in (window.messages.itemWidget(window.messages.item(i)) for i in range(window.messages.count()))
        if isinstance(widget, FileMessageBubble)
    ]


@pytest.mark.parametrize("name, kind", [
    ("report.pdf", "file"),
    ("voice-message.m4a", "voice"),
    ("clip.mp4", "video"),
])
def test_an_attachment_sent_to_a_group_appears_for_every_member_as_the_right_bubble(group, tmp_path, name, kind):
    alice_window, bob_window, alice_payload, bob_payload = group
    path = tmp_path / name
    path.write_bytes(b"\x00\x01\x02 attachment bytes " * 80)

    alice_window.handle_attachment_selected(str(path))

    assert _wait_for(lambda: len(_bubbles(alice_window)) == 1)         # the sender's own transcript
    assert _wait_for(lambda: len(_bubbles(bob_window)) == 1)           # the other member's
    mine, theirs = _bubbles(alice_window)[0], _bubbles(bob_window)[0]
    assert mine.kind == "sent" and theirs.kind == "received"
    assert theirs._accessible_sender == bob_window.name_for(alice_payload["username"])   # named by display name

    expected_type = {"file": "file", "voice": "voice", "video": "video"}[kind]
    assert theirs.payload_type == expected_type
    assert (theirs._media_card is not None) == (kind in ("voice", "video"))      # an inline player for media

    # Save writes exactly what the sender attached.
    target = tmp_path / "saved.bin"
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (str(target), ""))
    theirs._handle_save_as()
    assert target.read_bytes() == path.read_bytes()


def test_an_attachment_is_shown_in_the_open_group_only(group, tmp_path):
    alice_window, bob_window, _ap, _bp = group
    path = tmp_path / "only-here.bin"
    path.write_bytes(b"x" * 300)

    alice_window.handle_attachment_selected(str(path))

    assert _wait_for(lambda: len(_bubbles(bob_window)) == 1)
    assert len(_bubbles(bob_window)) == 1                               # exactly one bubble, not a duplicate
