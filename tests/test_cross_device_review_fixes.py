"""
Regression tests for the security review of cross-device key sync
(findings F1-F3, F6, F7) on the Desktop / ClientSession side.

The "malicious server" cases (a lying device list, a fake device row, a
misaddressed or malformed package) are simulated by calling the receiving
functions directly with what a hostile relay could hand them -- they prove
the client defends itself, not that a hostile server was run end to end.

Run with:
    pytest tests/test_cross_device_review_fixes.py -v
"""

import ast
import base64
import logging
import os
import uuid
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

import client.session as client_session_module
from crypto.device_protocol import canonical_device_key_sync_payload, sign_device_payload
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from crypto.message_protocol import sign_message_payload
from domain.security_rejection_reason import SecurityRejectionReason
from gui.device_management_dialog import DeviceManagementDialog
from storage.secure_key_store import PEER_STATE_VERIFIED
from tests.test_cross_device_history import (  # noqa: F401 -- reused fixtures, not re-implemented
    _authorize_and_connect_device,
    _chat_with,
    conversation_on_the_website,
)
from tests.test_device_key_sync import (  # noqa: F401
    _mutually_verify_devices,
    _new_device_session,
    _wait_for,
    account,
    running_server,
)

_app = QApplication.instance() or QApplication([])

REPO_ROOT = Path(__file__).resolve().parent.parent


def _captured_package(source, target, conversation_id, epoch, key=None):
    """The exact package sync_conversation_key_to_device() would send,
    captured instead of sent (so the test can hand it to a receiver)."""

    source.key_manager.store_key(conversation_id, key or os.urandom(32), epoch=epoch)
    captured = []
    original = source.send_request
    source.send_request = lambda packet: captured.append(packet) or {"success": True}
    try:
        source.sync_conversation_key_to_device(target.device_id, conversation_id, epoch=epoch)
    finally:
        source.send_request = original

    packet = dict(captured[0])
    packet["source_device_id"] = source.device_id
    packet["sender"] = source.username
    return packet


@pytest.fixture()
def three_devices(running_server, monkeypatch, account, tmp_path):
    """One account, three enrolled devices: ``a`` and ``b`` (and ``a`` and
    ``c``) have verified each other; ``b`` and ``c`` have not."""

    a = _new_device_session(running_server, monkeypatch, account, tmp_path / "a")
    b = _new_device_session(running_server, monkeypatch, account, tmp_path / "b")
    c = _new_device_session(running_server, monkeypatch, account, tmp_path / "c")
    try:
        for session, name in ((a, "A"), (b, "B"), (c, "C")):
            session.enroll_device(device_name=name, platform="test")
        _mutually_verify_devices(a, b)
        _mutually_verify_devices(a, c)
        yield a, b, c
    finally:
        for session in (a, b, c):
            session.disconnect()


def _verified_contact(session, name="verified_contact"):
    contact = KeyManager()
    kem, signing = contact.public_key, contact.ml_dsa.export_public_key()
    session.observe_peer_identity(name, kem, signing)
    session.confirm_combined_peer_verification(name, fingerprint_combined_identity(kem, signing))
    assert session.get_peer_verification_state(name) == PEER_STATE_VERIFIED
    return contact


def _signed_history_entry(signer, sender, conversation_id, is_own, epoch=1, receiver="someone"):
    ciphertext = "opaque-ciphertext"
    signature = sign_message_payload(
        signer, sender, receiver, conversation_id, "text", ciphertext, None, epoch
    )
    entry = {
        "sender": sender, "receiver": receiver, "conversation_id": conversation_id,
        "payload_type": "text", "content_metadata": None, "epoch": epoch, "is_own": is_own,
        "message_signature": base64.b64encode(signature).decode(),
    }
    return entry, ciphertext


# ----------------------------------------------------------------------
# F1 -- device ids are UUIDs; a device entry can never name a contact
# ----------------------------------------------------------------------


def test_lying_device_list_cannot_make_a_contacts_message_count_as_mine(three_devices):
    _a, b, _c = three_devices
    contact = _verified_contact(b)
    entry, ciphertext = _signed_history_entry(contact.ml_dsa, "verified_contact", str(uuid.uuid4()), True)

    # The server lists a "device" whose id is the contact's username.
    b.list_devices = lambda: [{"device_id": "verified_contact", "state": "AUTHORIZED"}]
    b._history_own_device_keys = None

    assert b._verify_history_message_signature(entry, ciphertext) is False
    assert b._verified_own_device_signing_keys() == []


def test_lying_device_list_cannot_nominate_a_uuid_this_device_never_verified(three_devices):
    a, b, _c = three_devices
    stranger = KeyManager()
    conversation_id = str(uuid.uuid4())
    entry, ciphertext = _signed_history_entry(stranger.ml_dsa, b.username, conversation_id, True)

    b.list_devices = lambda: [{"device_id": str(uuid.uuid4()), "state": "AUTHORIZED"}]
    b._history_own_device_keys = None

    assert b._verify_history_message_signature(entry, ciphertext) is False


def test_a_genuinely_verified_own_device_still_authenticates_own_history(three_devices):
    a, b, _c = three_devices
    entry, ciphertext = _signed_history_entry(a.key_manager.ml_dsa, b.username, str(uuid.uuid4()), True)

    b._history_own_device_keys = None

    assert b._verify_history_message_signature(entry, ciphertext) is True


def test_a_row_flagged_as_mine_must_name_this_account_as_sender(three_devices):
    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())

    # Validly signed by a device b trusts -- only the sender claim is wrong.
    wrong_sender, ciphertext = _signed_history_entry(a.key_manager.ml_dsa, "somebody_else", conversation_id, True)
    own_sender, own_ciphertext = _signed_history_entry(a.key_manager.ml_dsa, b.username, conversation_id, True)

    b._history_own_device_keys = None
    assert b._verify_history_message_signature(wrong_sender, ciphertext) is False
    assert b._verify_history_message_signature(own_sender, own_ciphertext) is True


@pytest.mark.parametrize("bad_id", ["verified_contact", "not-a-uuid", "", None, 42, "{" + str(uuid.uuid4()) + "}", str(uuid.uuid4()).replace("-", "")])
def test_non_uuid_device_ids_are_refused_before_any_state_changes(three_devices, bad_id):
    _a, b, _c = three_devices
    _verified_contact(b)
    kem_before = b.key_manager.get_public_key("verified_contact")

    rogue = KeyManager()
    row = {
        "device_id": bad_id, "state": "AUTHORIZED", "kem_public_key": rogue.public_key.decode(),
        "ml_dsa_public_key": base64.b64encode(rogue.ml_dsa.export_public_key()).decode(),
    }
    with pytest.raises(ValueError):
        b.observe_own_device(row)
    with pytest.raises(ValueError):
        b.observe_device_peer_identity(bad_id, rogue.public_key.decode(), rogue.ml_dsa.export_public_key())
    with pytest.raises(ValueError):
        b.sync_conversation_key_to_device(bad_id, str(uuid.uuid4()))

    # The contact is untouched: still VERIFIED, same encryption key.
    assert b.get_peer_verification_state("verified_contact") == PEER_STATE_VERIFIED
    assert b.key_manager.get_public_key("verified_contact") == kem_before


def test_fake_row_for_an_already_verified_device_cannot_replace_its_verified_key(three_devices):
    a, b, _c = three_devices
    kem_before = b.key_manager.get_public_key(a.device_id)
    assert b.get_peer_verification_state(a.device_id) == PEER_STATE_VERIFIED

    rogue = KeyManager()
    fake_row = {
        "device_id": a.device_id, "state": "AUTHORIZED", "kem_public_key": rogue.public_key.decode(),
        "ml_dsa_public_key": base64.b64encode(rogue.ml_dsa.export_public_key()).decode(),
    }
    b.observe_own_device(fake_row)

    assert b.get_peer_verification_state(a.device_id) != PEER_STATE_VERIFIED   # flagged, not trusted
    assert b.key_manager.get_public_key(a.device_id) == kem_before            # key not replaced
    with pytest.raises(client_session_module.PeerNotVerifiedError):
        b.sync_conversation_key_to_device(a.device_id, str(uuid.uuid4()))


# ----------------------------------------------------------------------
# F2 -- the receiver checks the package is addressed to THIS device
# ----------------------------------------------------------------------


@pytest.fixture()
def signature_must_not_be_reached(monkeypatch):
    def _fail(*args, **kwargs):
        raise AssertionError("signature verification was reached")
    monkeypatch.setattr(client_session_module, "verify_device_payload", _fail)


def test_genuine_package_is_still_installed(three_devices):
    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())
    key = os.urandom(32)

    assert b.handle_device_key_sync(_captured_package(a, b, conversation_id, 2, key)) is None
    assert b.key_manager.get_key(conversation_id, epoch=2) == key


def test_package_addressed_to_another_device_is_rejected_explicitly(three_devices, signature_must_not_be_reached):
    a, b, c = three_devices
    conversation_id = str(uuid.uuid4())
    package_for_b = _captured_package(a, b, conversation_id, 2)

    result = c.handle_device_key_sync(package_for_b)   # c trusts a, but this is not c's package

    assert result == SecurityRejectionReason.WRONG_RECEIVER
    assert not c.key_manager.has_key(conversation_id)


def test_package_with_wrong_target_fingerprint_is_rejected(three_devices, signature_must_not_be_reached):
    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())
    package = _captured_package(a, b, conversation_id, 2)

    # A package that a's own key really did sign, naming b's device id but a different fingerprint.
    payload = canonical_device_key_sync_payload(
        a.username, a.device_id, b.device_id, "0" * 40, conversation_id, 2, "direct",
        package["encapsulation"], package["wrapped_key"],
    )
    package["target_fingerprint"] = "0" * 40
    package["sync_signature"] = base64.b64encode(sign_device_payload(a.key_manager.ml_dsa, payload)).decode()

    assert b.handle_device_key_sync(package) == SecurityRejectionReason.WRONG_RECEIVER
    assert not b.key_manager.has_key(conversation_id)


def test_a_device_that_never_enrolled_accepts_no_package(three_devices, running_server, monkeypatch, account, tmp_path, signature_must_not_be_reached):
    a, b, _c = three_devices
    unenrolled = _new_device_session(running_server, monkeypatch, account, tmp_path / "unenrolled")
    try:
        conversation_id = str(uuid.uuid4())
        package = _captured_package(a, b, conversation_id, 2)

        assert unenrolled.device_id is None
        assert unenrolled.handle_device_key_sync(package) == SecurityRejectionReason.WRONG_RECEIVER
        assert not unenrolled.key_manager.has_key(conversation_id)
    finally:
        unenrolled.disconnect()


# ----------------------------------------------------------------------
# F3 -- epoch must be a positive int, checked before signature / key store
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_epoch",
    ["2", 2.0, 2.5, True, False, 0, -1, -(2**32), None, [2], {"n": 2}, 2**32, 2**32 + 2, 2**64],
)
def test_malformed_epochs_are_rejected_before_signature_or_key_store(three_devices, signature_must_not_be_reached, bad_epoch):
    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())
    package = _captured_package(a, b, conversation_id, 2)
    package["epoch"] = bad_epoch

    assert b.handle_device_key_sync(package) == SecurityRejectionReason.INVALID_EPOCH

    assert b.key_manager.export_conversation_keys() == {}      # nothing stored, not even a stray entry
    assert not b.key_manager.has_key(conversation_id)


MAX_EPOCH = 4_294_967_295


def test_the_largest_representable_epoch_is_accepted_when_genuinely_signed(three_devices):
    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())
    key = os.urandom(32)

    assert b.handle_device_key_sync(_captured_package(a, b, conversation_id, MAX_EPOCH, key)) is None
    assert b.key_manager.get_key(conversation_id, epoch=MAX_EPOCH) == key


def test_an_in_range_epoch_rewritten_by_a_relay_is_still_caught_by_the_signature(three_devices):
    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())
    package = _captured_package(a, b, conversation_id, 2, os.urandom(32))

    assert b.handle_device_key_sync(dict(package, epoch=MAX_EPOCH)) == SecurityRejectionReason.INVALID_SIGNATURE
    assert not b.key_manager.has_key(conversation_id)


@pytest.mark.parametrize("hostile_epoch", [MAX_EPOCH + 1, MAX_EPOCH + 3])   # 4,294,967,296 and 4,294,967,298
def test_an_oversized_epoch_cannot_stall_or_change_the_current_epoch(three_devices, hostile_epoch):
    """The Website's encoder would wrap 2**32 + 2 to 2, so a relay rewriting epoch 2 to it still
    verified there. Here it is refused first, so rotation to epoch 3 is unaffected."""

    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())
    package_2 = _captured_package(a, b, conversation_id, 2, os.urandom(32))
    package_3 = _captured_package(a, b, conversation_id, 3, os.urandom(32))

    # Hostile copy first, on a conversation the receiver holds nothing for.
    assert b.handle_device_key_sync(dict(package_2, epoch=hostile_epoch)) == SecurityRejectionReason.INVALID_EPOCH
    assert b.key_manager.current_epoch(conversation_id) is None
    assert b.key_manager.export_conversation_keys() == {}

    # The genuine epoch 2 installs; a hostile copy then changes nothing.
    assert b.handle_device_key_sync(package_2) is None
    assert b.handle_device_key_sync(dict(package_2, epoch=hostile_epoch)) == SecurityRejectionReason.INVALID_EPOCH
    assert b.key_manager.current_epoch(conversation_id) == 2
    assert sorted(b.key_manager.export_conversation_keys()[conversation_id]) == [2]

    # A legitimate epoch 3 still becomes current.
    assert b.handle_device_key_sync(package_3) is None
    assert b.key_manager.current_epoch(conversation_id) == 3
    assert sorted(b.key_manager.export_conversation_keys()[conversation_id]) == [2, 3]


def test_a_valid_epoch_is_still_accepted_after_malformed_ones(three_devices):
    a, b, _c = three_devices
    conversation_id = str(uuid.uuid4())
    package = _captured_package(a, b, conversation_id, 2)

    bad = dict(package, epoch="2")
    assert b.handle_device_key_sync(bad) == SecurityRejectionReason.INVALID_EPOCH
    assert b.handle_device_key_sync(package) is None
    assert b.key_manager.has_key(conversation_id, epoch=2)


# ----------------------------------------------------------------------
# F6 -- no message text (or key material) reaches the Desktop log
# ----------------------------------------------------------------------


def test_received_and_sent_text_never_reaches_the_log(conversation_on_the_website, caplog):
    website, bob, conversation_id, _sessions = conversation_on_the_website
    canary = f"CANARY-{uuid.uuid4().hex}"
    reply_canary = f"REPLY-{uuid.uuid4().hex}"

    with caplog.at_level(logging.DEBUG):
        _chat_with(website, bob.username, conversation_id)
        website.send_chat_message(canary)
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == canary for s in bob.conversation_store.get_all()
        ))
        _chat_with(bob, website.username, conversation_id)
        bob.send_chat_message(reply_canary)
        assert _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == reply_canary for s in website.conversation_store.get_all()
        ))

    rendered = "\n".join(
        record.getMessage() + (logging.Formatter().formatException(record.exc_info) if record.exc_info else "")
        for record in caplog.records
    )
    assert canary not in rendered and reply_canary not in rendered
    assert "RECEIVED: text message from" in rendered          # the metadata line is still there
    for session in (website, bob):                             # no key material either
        key = session.key_manager.get_key(conversation_id)
        assert key.hex() not in rendered and base64.b64encode(key).decode() not in rendered


def test_a_failure_after_decryption_does_not_log_the_text(conversation_on_the_website, caplog, monkeypatch):
    website, bob, conversation_id, _sessions = conversation_on_the_website
    canary = f"CANARY-{uuid.uuid4().hex}"

    def _boom(*args, **kwargs):
        raise RuntimeError("storing failed")
    monkeypatch.setattr(bob.conversation_store, "record_message", _boom)

    with caplog.at_level(logging.DEBUG):
        _chat_with(website, bob.username, conversation_id)
        website.send_chat_message(canary)
        assert _wait_for(lambda: any("Skipping malformed or unhandled packet" in r.getMessage() for r in caplog.records))

    rendered = "\n".join(
        record.getMessage() + (logging.Formatter().formatException(record.exc_info) if record.exc_info else "")
        for record in caplog.records
    )
    assert canary not in rendered


def test_no_log_call_in_the_client_interpolates_plaintext_or_key_variables():
    """Static guard: a logging call in the client may not interpolate a variable that holds
    decrypted content or key material."""

    forbidden = {
        "decrypted_content", "plaintext", "message_text", "session_key", "group_key", "key_bytes",
        "wrapping_secret", "shared_secret", "aes_key", "wrapped_key",
    }
    log_methods = {"debug", "info", "warning", "error", "exception", "critical"}
    offenders = []

    for relative in ("client/session.py", "client/receiver.py", "client/sender.py", "client/conversation_store.py"):
        tree = ast.parse((REPO_ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in log_methods
                and "log" in ast.unparse(node.func.value).lower()
            ):
                # A length (``len(x)``) is safe metadata; anything else naming the variable is not.
                measured = {
                    id(inner)
                    for call in ast.walk(node)
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "len"
                    for inner in ast.walk(call)
                }
                names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and id(n) not in measured}
                names |= {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute) and id(n) not in measured}
                hit = names & forbidden
                if hit:
                    offenders.append(f"{relative}:{node.lineno} {sorted(hit)}")

    assert offenders == []


# ----------------------------------------------------------------------
# F7 -- safety-number prompts: right instructions, "No" by default,
#       explicit confirmation before trusting or authorizing a device
# ----------------------------------------------------------------------


def _record_prompt(monkeypatch, answer):
    seen = {}

    def _question(parent, title, text, buttons=None, default=None):
        seen.update(title=title, text=text, buttons=buttons, default=default)
        return answer

    monkeypatch.setattr(QMessageBox, "question", staticmethod(_question))
    return seen


def test_verify_prompt_defaults_to_no_and_points_to_where_the_number_is_shown(conversation_on_the_website, running_server, monkeypatch, account, tmp_path):
    website, _bob, _conversation_id, sessions = conversation_on_the_website
    other = _new_device_session(running_server, monkeypatch, account, tmp_path / "other")
    sessions.append(other)
    _authorize_and_connect_device(website, other, "Other")
    row = next(d for d in website.list_devices() if d["device_id"] == other.device_id)

    dialog = DeviceManagementDialog(website)
    seen = _record_prompt(monkeypatch, QMessageBox.No)

    dialog._handle_verify(row)

    assert seen["default"] == QMessageBox.No
    assert seen["buttons"] == QMessageBox.Yes | QMessageBox.No
    assert "Show my safety number" in seen["text"] and "Your safety number" in seen["text"]
    assert "Open Devices on" not in seen["text"]
    # The number shown is computed locally from the device's keys, not the server's field.
    assert fingerprint_combined_identity(
        other.key_manager.public_key, other.key_manager.ml_dsa.export_public_key()
    ) in seen["text"]
    assert website.get_peer_verification_state(other.device_id) != PEER_STATE_VERIFIED


def test_devices_window_shows_this_devices_own_safety_number(conversation_on_the_website):
    website, _bob, _conversation_id, _sessions = conversation_on_the_website

    dialog = DeviceManagementDialog(website)

    assert website.get_own_fingerprint() in dialog._own_number_label.text()


def test_authorize_needs_explicit_confirmation_and_uses_the_locally_computed_number(conversation_on_the_website, running_server, monkeypatch, account, tmp_path):
    website, _bob, _conversation_id, sessions = conversation_on_the_website
    pending = _new_device_session(running_server, monkeypatch, account, tmp_path / "pending")
    sessions.append(pending)
    pending.enroll_device(device_name="Pending", platform="test")

    dialog = DeviceManagementDialog(website)
    row = next(d for d in website.list_devices() if d["device_id"] == pending.device_id)
    row = dict(row, fingerprint="server-supplied-and-wrong")     # must not be what gets signed

    # Declined: nothing is trusted or authorized.
    seen = _record_prompt(monkeypatch, QMessageBox.No)
    dialog._handle_authorize(row)
    assert seen["default"] == QMessageBox.No
    assert next(d for d in website.list_devices() if d["device_id"] == pending.device_id)["state"] == "PENDING"
    assert website.get_peer_verification_state(pending.device_id) != PEER_STATE_VERIFIED

    # Confirmed: authorized using the number computed from the keys.
    signed = []
    original = website.authorize_device
    website.authorize_device = lambda device_id, fingerprint: signed.append(fingerprint) or original(device_id, fingerprint)
    _record_prompt(monkeypatch, QMessageBox.Yes)
    dialog._handle_authorize(row)

    expected = fingerprint_combined_identity(
        pending.key_manager.public_key, pending.key_manager.ml_dsa.export_public_key()
    )
    assert signed == [expected]
    assert next(d for d in website.list_devices() if d["device_id"] == pending.device_id)["state"] == "AUTHORIZED"
    assert website.get_peer_verification_state(pending.device_id) == PEER_STATE_VERIFIED
