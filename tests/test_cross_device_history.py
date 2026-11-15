"""
Cross-device history: a conversation held on one device of an account
(the Website) must become readable on another device of the same
account (the Desktop) once -- and only once -- a person has authorized
and verified that device and sent it the keys.

Two things used to make this impossible, both covered here:

* the keys never left the first device (the Desktop could receive a
  device key sync but nothing ever asked a device to send one, and
  only one epoch of one conversation could be sent at a time); and
* history signed by the account's OTHER device was always rejected,
  because "own" messages were checked against this device's key only.

Run with:
    pytest tests/test_cross_device_history.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

from client.session import PeerNotVerifiedError
from domain.conversation_summary import ConversationSummary
from gui.device_management_dialog import DeviceManagementDialog
from storage.secure_key_store import PEER_STATE_VERIFIED
from tests.test_device_key_sync import (  # noqa: F401 -- reused, not re-implemented
    _delete,
    _mutually_verify_devices,
    _new_device_session,
    _register,
    _verify_peers,
    _wait_for,
    account,
    running_server,
)

_app = QApplication.instance() or QApplication([])


def _chat_with(session, username, conversation_id=None):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=conversation_id, username=username, is_online=True, latest_message=None
        )
    )


def _authorize_and_connect_device(first, new_device, name):
    """Enroll ``new_device`` (PENDING), have ``first`` authorize it, bind it."""

    new_device.enroll_device(device_name=name, platform="test")
    pending = next(d for d in first.list_devices() if d["device_id"] == new_device.device_id)
    assert pending["state"] == "PENDING"
    assert first.authorize_device(new_device.device_id, pending["fingerprint"])["success"]
    assert new_device.bind_device_session()["success"]


def _texts(history):
    return [(entry["text"], entry["is_own"]) for entry in history]


@pytest.fixture()
def conversation_on_the_website(running_server, monkeypatch, account, tmp_path):
    """The account's first device ("website") holds a verified,
    key-established conversation with Bob that already has one message
    each way. Yields (website, bob, conversation_id, helpers)."""

    website = _new_device_session(running_server, monkeypatch, account, tmp_path / "website")
    bob_payload = _register("bob_")
    bob = _new_device_session(running_server, monkeypatch, bob_payload, tmp_path / "bob")
    sessions = [website, bob]
    try:
        website.enroll_device(device_name="Website", platform="web")  # first device -> AUTHORIZED
        website.bind_device_session()

        assert _wait_for(lambda: website.key_manager.get_public_key(bob.username) is not None)
        assert _wait_for(lambda: bob.key_manager.get_public_key(website.username) is not None)
        _verify_peers(website, bob, bob.username)
        _verify_peers(bob, website, website.username)

        _chat_with(website, bob.username)
        website.establish_session_key()
        conversation_id = website.current_conversation_id
        assert _wait_for(lambda: bob.key_manager.has_key(conversation_id))

        website.send_chat_message("from the website")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "from the website"
            for s in bob.conversation_store.get_all()
        ))

        _chat_with(bob, website.username)
        bob.send_chat_message("from bob")
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "from bob"
            for s in website.conversation_store.get_all()
        ))

        yield website, bob, conversation_id, sessions
    finally:
        for session in sessions:
            session.disconnect()
        _delete(bob_payload["username"])


def test_website_conversation_is_readable_on_the_desktop_after_authorization(
    conversation_on_the_website, running_server, monkeypatch, account, tmp_path
):
    website, bob, conversation_id, sessions = conversation_on_the_website

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    sessions.append(desktop)

    # Before anything is authorized the Desktop has no keys: the history
    # exists on the server but is unavailable here (the reported bug).
    assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
    _chat_with(desktop, bob.username, conversation_id)
    before = desktop.load_conversation_history(bob.username)
    placeholder = "Message unavailable"
    assert [entry["text"].startswith(placeholder) for entry in before] == [True, True]

    # Authorize, mutually verify, and send the keys -- the same steps
    # the Devices dialogs perform.
    _authorize_and_connect_device(website, desktop, "Desktop")
    _mutually_verify_devices(website, desktop)

    sent, failures = website.sync_all_conversation_keys_to_device(desktop.device_id)
    assert sent >= 1 and failures == []
    assert _wait_for(lambda: desktop.key_manager.has_key(conversation_id))
    assert desktop.key_manager.get_key(conversation_id) == website.key_manager.get_key(conversation_id)

    # Web -> Desktop: both directions of the existing conversation read.
    history = desktop.load_conversation_history(bob.username)
    assert _texts(history) == [("from the website", True), ("from bob", False)]

    # Desktop -> Web: a message sent from the Desktop reads on the Website.
    # Sending (unlike reading) needs this device to have verified Bob itself.
    _verify_peers(desktop, bob, bob.username)
    desktop.send_chat_message("from the desktop")
    assert _wait_for(lambda: ("from the desktop", True) in _texts(
        website.load_conversation_history(bob.username)
    ))
    assert ("from the website", True) in _texts(website.load_conversation_history(bob.username))

    # And the restored key survives a restart of the Desktop.
    assert _wait_for(lambda: desktop.key_store is not None)
    restarted = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    sessions.append(restarted)
    assert restarted.key_manager.has_key(conversation_id)


def test_a_device_this_one_has_not_verified_cannot_authenticate_own_history(
    conversation_on_the_website, running_server, monkeypatch, account, tmp_path
):
    """A message "from you" signed by an account device the reading
    device never verified stays unavailable: being on the same account
    is not enough."""

    website, bob, conversation_id, sessions = conversation_on_the_website

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    third = _new_device_session(running_server, monkeypatch, account, tmp_path / "third")
    sessions.extend([desktop, third])

    _authorize_and_connect_device(website, desktop, "Desktop")
    _authorize_and_connect_device(website, third, "Third")

    # The Website trusts both; the Desktop verifies only the Website.
    _mutually_verify_devices(website, desktop)
    _mutually_verify_devices(website, third)
    website.sync_all_conversation_keys_to_device(desktop.device_id)
    website.sync_all_conversation_keys_to_device(third.device_id)
    assert _wait_for(lambda: desktop.key_manager.has_key(conversation_id))
    assert _wait_for(lambda: third.key_manager.has_key(conversation_id))

    _verify_peers(third, bob, bob.username)
    _chat_with(third, bob.username, conversation_id)
    third.send_chat_message("from the third device")
    assert _wait_for(lambda: any(
        entry["text"] == "from the third device"
        for entry in website.load_conversation_history(bob.username)
    ))  # the Website verified it, so it can read it

    assert _wait_for(lambda: desktop.key_manager.get_public_key(bob.username) is not None)
    _chat_with(desktop, bob.username, conversation_id)
    history = desktop.load_conversation_history(bob.username)

    assert ("from the website", True) in _texts(history)
    assert all(entry["text"] != "from the third device" for entry in history)
    assert desktop.get_peer_verification_state(third.device_id) != PEER_STATE_VERIFIED


def test_a_pending_device_cannot_obtain_conversation_keys(
    conversation_on_the_website, running_server, monkeypatch, account, tmp_path
):
    website, _bob, conversation_id, sessions = conversation_on_the_website

    pending = _new_device_session(running_server, monkeypatch, account, tmp_path / "pending")
    sessions.append(pending)

    pending.enroll_device(device_name="Unapproved", platform="test")
    pending.bind_device_session()

    # Never verified by the Website: refused before anything is wrapped.
    with pytest.raises(PeerNotVerifiedError):
        website.sync_all_conversation_keys_to_device(pending.device_id)

    # Even verified locally, the server still refuses a device that no
    # authorized device has approved, and nothing is installed.
    pending_row = next(d for d in website.list_devices() if d["device_id"] == pending.device_id)
    assert pending_row["state"] == "PENDING"
    _mutually_verify_devices(website, pending)
    sent, failures = website.sync_all_conversation_keys_to_device(pending.device_id)

    assert sent == 0 and failures
    assert not pending.key_manager.has_key(conversation_id)


def test_devices_dialog_verifies_a_device_and_sends_keys(
    conversation_on_the_website, running_server, monkeypatch, account, tmp_path
):
    website, bob, conversation_id, sessions = conversation_on_the_website

    other = _new_device_session(running_server, monkeypatch, account, tmp_path / "other")
    sessions.append(other)
    _authorize_and_connect_device(website, other, "Other")

    dialog = DeviceManagementDialog(website)
    other_row = next(d for d in website.list_devices() if d["device_id"] == other.device_id)

    # Refusing the comparison verifies nothing.
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.No))
    dialog._handle_verify(other_row)
    assert website.get_peer_verification_state(other.device_id) != PEER_STATE_VERIFIED

    # Confirming the comparison does; the device then shows the fingerprint it computed itself.
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    dialog._handle_verify(other_row)
    assert website.get_peer_verification_state(other.device_id) == PEER_STATE_VERIFIED

    # The receiving device must trust the sender too before it accepts keys.
    other.observe_own_device(next(d for d in other.list_devices() if d["device_id"] == website.device_id))
    other.confirm_device_peer_verification(
        website.device_id, other.get_peer_fingerprint_for_verification(website.device_id)
    )

    dialog._handle_send_keys(other_row)
    assert _wait_for(lambda: other.key_manager.has_key(conversation_id))
    assert other.key_manager.get_key(conversation_id) == website.key_manager.get_key(conversation_id)
    assert "Sent" in dialog._status_label.text()
