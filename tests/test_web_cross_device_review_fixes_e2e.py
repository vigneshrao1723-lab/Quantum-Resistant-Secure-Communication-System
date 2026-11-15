"""
Regression tests for the security review of cross-device key sync (findings
F1-F4) on the Website side, run in real Chrome against the real Website code
and a real Desktop session on the same account.

Hostile-relay inputs (a wrongly addressed package, malformed epochs, a lying
device list, a conflicting key delivery) are handed straight to the Website's
handlers -- they prove the client defends itself, not that a hostile server
was run end to end.

Run with:
    pytest tests/test_web_cross_device_review_fixes_e2e.py -v
"""

import base64
import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from crypto.aes import AESCipher
from crypto.device_protocol import canonical_device_key_sync_payload, sign_device_payload
from crypto.key_manager import fingerprint_combined_identity
from crypto.message_protocol import sign_message_payload
from tests.test_web_browser_e2e import (  # noqa: F401 -- reused fixtures/helpers, not re-implemented
    _connect_browser,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)


def _captured_package(source, target_device_id, conversation_id, epoch, key):
    source.key_manager.store_key(conversation_id, key, epoch=epoch)
    captured = []
    original = source.send_request
    source.send_request = lambda packet: captured.append(packet) or {"success": True}
    try:
        source.sync_conversation_key_to_device(target_device_id, conversation_id, epoch=epoch)
    finally:
        source.send_request = original
    packet = dict(captured[0])
    packet["source_device_id"] = source.device_id
    packet["sender"] = source.username
    return packet


@pytest.fixture()
def website_and_desktop(running_server, gateway_url, browser_page, desktop_app):
    """The account's Website (first device, authorized, bound) and a Desktop
    (authorized by the Website), each having verified the other."""

    account = desktop_app["register"]("acct_")
    page = browser_page["page"]
    _connect_browser(browser_page, gateway_url, account)

    page.evaluate("(async () => window.__session.enrollDevice('Website', 'web'))()")
    page.evaluate("(async () => window.__session.bindDeviceSession())()")
    web_device_id = page.evaluate("window.__session.deviceId")

    desktop = desktop_app["launch"](account)
    desktop.enroll_device(device_name="Desktop", platform="Desktop")
    page.evaluate(
        """(async (id) => {
            const s = window.__session;
            const target = (await s.listDevices()).find((d) => d.device_id === id);
            const peer = await s.observeDevicePeerIdentity(id, target.kem_public_key, target.ml_dsa_public_key);
            s.confirmDevicePeerVerified(id, peer.fingerprint);
            await s.authorizeDevice(id, peer.fingerprint);
        })""",
        desktop.device_id,
    )
    assert desktop.bind_device_session()["success"]
    web_row = next(d for d in desktop.list_devices() if d["device_id"] == web_device_id)
    desktop.confirm_device_peer_verification(web_device_id, desktop.observe_own_device(web_row))

    return page, desktop, web_device_id, account


def _delivered(page, packet):
    """Hand one package to the Website's device-key-sync handler."""
    page.evaluate("(p) => window.__session._handleDeviceKeySync(p)", packet)


def _web_key(page, conversation_id, epoch=None):
    """The Website's key for a conversation (current, or a specific epoch) as hex, or None."""
    return page.evaluate(
        """([id, epoch]) => {
            const key = window.__session._keyForEpoch(id, epoch === null ? undefined : epoch);
            return key ? Array.from(key).map((b) => b.toString(16).padStart(2, '0')).join('') : null;
        }""",
        [conversation_id, epoch],
    )


def test_website_rejects_wrongly_addressed_and_malformed_packages(website_and_desktop):
    page, desktop, web_device_id, account = website_and_desktop
    conversation_id = str(uuid.uuid4())
    key = os.urandom(32)
    package = _captured_package(desktop, web_device_id, conversation_id, 2, key)

    # F2: addressed to some other device.
    _delivered(page, dict(package, target_device_id=str(uuid.uuid4())))
    assert _web_key(page, conversation_id) is None

    # F2: the right device id but a fingerprint that is not this device's -- validly signed by the Desktop.
    payload = canonical_device_key_sync_payload(
        account["username"], desktop.device_id, web_device_id, "0" * 40, conversation_id, 2, "direct",
        package["encapsulation"], package["wrapped_key"],
    )
    wrong_fingerprint = dict(
        package, target_fingerprint="0" * 40,
        sync_signature=base64.b64encode(sign_device_payload(desktop.key_manager.ml_dsa, payload)).decode(),
    )
    _delivered(page, wrong_fingerprint)
    assert _web_key(page, conversation_id) is None

    # F3: epochs that are not positive integers -- including ones the signed payload would coerce.
    for bad_epoch in ("2", True, False, 0, -1, 2.5, None, [2]):
        _delivered(page, dict(package, epoch=bad_epoch))
        assert _web_key(page, conversation_id) is None, bad_epoch

    # F1: a source "device" that is not a UUID.
    _delivered(page, dict(package, source_device_id="verified_contact"))
    assert _web_key(page, conversation_id) is None

    # The genuine package is still installed.
    _delivered(page, package)
    assert _web_key(page, conversation_id) == key.hex()


MAX_EPOCH = 4_294_967_295


def _web_current_epoch(page, conversation_id):
    return page.evaluate(
        "(id) => { const k = window.__session.sessionKeys.get(id); return k ? k.epoch : null; }", conversation_id
    )


def test_website_accepts_the_largest_epoch_only_when_genuinely_signed(website_and_desktop):
    page, desktop, web_device_id, _account = website_and_desktop
    conversation_id = str(uuid.uuid4())
    key = os.urandom(32)

    genuine = _captured_package(desktop, web_device_id, conversation_id, MAX_EPOCH, key)
    _delivered(page, genuine)
    assert _web_key(page, conversation_id, MAX_EPOCH) == key.hex()

    other = str(uuid.uuid4())
    package_2 = _captured_package(desktop, web_device_id, other, 2, os.urandom(32))
    _delivered(page, dict(package_2, epoch=MAX_EPOCH))      # in range, but not what was signed
    assert _web_key(page, other) is None


@pytest.mark.parametrize("hostile_epoch", [MAX_EPOCH + 1, MAX_EPOCH + 3, 2**53])  # 4,294,967,296 / ...298 / unsafe
def test_website_oversized_epoch_cannot_install_or_stall_rotation(website_and_desktop, hostile_epoch):
    """Its encoder wraps 2**32 + 2 to 2, so a relay rewriting epoch 2 to it still verified: the key was
    installed under epoch 4294967298 and a real epoch 3 could never become current again."""

    page, desktop, web_device_id, _account = website_and_desktop
    conversation_id = str(uuid.uuid4())
    package_2 = _captured_package(desktop, web_device_id, conversation_id, 2, os.urandom(32))
    package_3 = _captured_package(desktop, web_device_id, conversation_id, 3, os.urandom(32))
    key_3 = desktop.key_manager.get_key(conversation_id, epoch=3)

    # Hostile copy first: nothing is installed.
    _delivered(page, dict(package_2, epoch=hostile_epoch))
    assert _web_current_epoch(page, conversation_id) is None
    assert _web_key(page, conversation_id) is None

    # Genuine epoch 2, then a hostile copy: the current epoch and its key are untouched.
    _delivered(page, package_2)
    key_2 = _web_key(page, conversation_id)
    assert _web_current_epoch(page, conversation_id) == 2 and key_2
    _delivered(page, dict(package_2, epoch=hostile_epoch))
    assert _web_current_epoch(page, conversation_id) == 2
    assert _web_key(page, conversation_id) == key_2
    assert _web_key(page, conversation_id, hostile_epoch) is None

    # A legitimate epoch 3 still becomes current.
    _delivered(page, package_3)
    assert _web_current_epoch(page, conversation_id) == 3
    assert _web_key(page, conversation_id) == key_3.hex()


def test_website_never_replaces_a_key_it_holds_for_an_epoch(website_and_desktop):
    page, _desktop, _web_device_id, _account = website_and_desktop
    conversation_id = str(uuid.uuid4())
    first, rival, newer, older = (os.urandom(32).hex() for _ in range(4))

    def install(key_hex, epoch):
        page.evaluate(
            "([id, hex, epoch]) => window.__session._installSessionKey(id, "
            "Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16))), epoch)",
            [conversation_id, key_hex, epoch],
        )

    install(first, 2)
    install(rival, 2)                                   # same epoch, different key
    assert _web_key(page, conversation_id, 2) == first
    assert _web_key(page, conversation_id) == first

    install(newer, 3)                                   # a new epoch still installs and becomes current
    assert _web_key(page, conversation_id) == newer
    assert _web_key(page, conversation_id, 2) == first

    install(older, 1)                                   # an older epoch fills history, never the current key
    assert _web_key(page, conversation_id, 1) == older
    assert _web_key(page, conversation_id) == newer

    install(rival, 3)                                   # the current epoch cannot be replaced either
    assert _web_key(page, conversation_id) == newer


def test_website_ignores_a_lying_device_list_and_fake_device_rows(website_and_desktop):
    page, desktop, web_device_id, account = website_and_desktop

    # A verified CONTACT, as the Website would hold one.
    page.evaluate(
        """() => {
            const s = window.__session;
            s.peers.set('verified_contact', {
                kemWire: s.peers.values().next().value.kemWire, signingKey: new Uint8Array(1952),
                state: 'VERIFIED', fingerprint: 'contact-fingerprint',
            });
        }"""
    )
    before = page.evaluate("JSON.stringify(window.__session.peers.get('verified_contact').fingerprint)")

    # A fake device row naming the contact is refused and touches nothing.
    refused = page.evaluate(
        """async () => {
            try {
                await window.__session.observeDevicePeerIdentity('verified_contact', 'a2V5', 'a2V5');
                return false;
            } catch (error) { return error.message; }
        }"""
    )
    assert "UUID" in refused
    assert page.evaluate("JSON.stringify(window.__session.peers.get('verified_contact').fingerprint)") == before
    assert page.evaluate("window.__session.peers.get('verified_contact').state") == "VERIFIED"

    refused_sync = page.evaluate(
        """async () => {
            try { await window.__session.syncConversationKeyToDevice('verified_contact', 'c', 'direct'); return false; }
            catch (error) { return error.message; }
        }"""
    )
    assert "UUID" in refused_sync

    # A lying list that names the contact, an unverified UUID, and the genuinely verified Desktop.
    keys = page.evaluate(
        """async ([desktopId]) => {
            const s = window.__session;
            s.listDevices = async () => [
                { device_id: 'verified_contact', state: 'AUTHORIZED' },
                { device_id: '00000000-0000-4000-8000-000000000000', state: 'AUTHORIZED' },
                { device_id: desktopId, state: 'AUTHORIZED' },
            ];
            s._historyOwnDeviceKeys = null;
            return (await s._verifiedOwnDeviceSigningKeys()).length;
        }""",
        [desktop.device_id],
    )
    assert keys == 1     # only the verified Desktop


def test_website_history_row_flagged_mine_must_name_this_account(website_and_desktop):
    page, desktop, web_device_id, account = website_and_desktop
    conversation_id = str(uuid.uuid4())
    key = os.urandom(32)
    _delivered(page, _captured_package(desktop, web_device_id, conversation_id, 1, key))
    assert _web_key(page, conversation_id) == key.hex()

    def entry(sender, message_id):
        ciphertext = AESCipher(key).encrypt(f"text from {sender}")
        signature = sign_message_payload(
            desktop.key_manager.ml_dsa, sender, "somebody", conversation_id, "text", ciphertext, None, 1
        )
        return {
            "message_id": message_id, "sender": sender, "receiver": "somebody",
            "conversation_id": conversation_id, "payload_type": "text", "content_metadata": None,
            "epoch": 1, "is_own": True, "ciphertext": ciphertext,
            "message_signature": base64.b64encode(signature).decode(),
            "timestamp": "2026-10-29T10:00:00",
        }

    own = entry(account["username"], str(uuid.uuid4()))
    other = entry("somebody_else", str(uuid.uuid4()))

    rendered = page.evaluate(
        """async ([conversationId, entries]) => {
            const s = window.__session;
            const original = s._sendRequest.bind(s);
            s._sendRequest = async (packet) =>
              packet.type === 'message_history_request' ? { messages: entries } : original(packet);
            s.listDevices = async () => (await original({ type: 'device_list_request' })).devices || [];
            s.forgetRenderedHistory(conversationId);
            await s.loadHistory(conversationId, false);
            s._sendRequest = original;
            return Array.from(s._renderedMessageIds.get(conversationId) || []);
        }""",
        [conversation_id, [own, other]],
    )

    assert own["message_id"] in rendered        # signed by the verified Desktop, sender is this account
    assert other["message_id"] not in rendered  # same signature quality, but not "from me"
