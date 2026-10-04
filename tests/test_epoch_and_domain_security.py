"""
Phase 16E -- Steps 6/7: server-side epoch authority for device_key_sync,
and explicit proof that domain separation already defeats cross-
operation signature reuse.

Step 6 -- epoch authority: the RECEIVER's own monotonic KeyManager.
store_key() protection (max()-based, never rolls back -- proven in
tests/test_device_key_sync_hardening.py) is necessary but not
sufficient: it is a last-resort CLIENT-side defense against a
malicious relay, not a substitute for the server validating what it
can authoritatively validate before ever relaying anything at all.
server/device_handler.py::handle_device_key_sync() (Phase 16E) now
also rejects a malformed/negative epoch and any epoch exceeding
Conversation.current_key_epoch -- the exact same server-side authority
and bound server/client_handler.py::handle_group_key_distribution()
already enforces for ordinary group-key delivery, reused here rather
than invented fresh.

Step 7 -- package/domain separation: crypto/device_protocol.py already
domain-separates every device-management operation by ML-DSA signing
purpose (qrscs-device-v1 + a per-operation suffix for enroll/
authorize/revoke/session_bind; qrscs-device-key-sync-v1, a wholly
separate top-level purpose, for key sync). A signature produced over
one operation's canonical payload cryptographically cannot verify
against a different operation's canonical payload -- ML-DSA signs
exact bytes, and the purpose prefix is baked into those bytes. This
file proves that already-existing property directly, rather than
merely asserting it: a genuine ENROLLMENT signature is captured and
resubmitted as a device_key_sync's sync_signature, and vice versa.

Run with:
    pytest tests/test_epoch_and_domain_security.py -v
"""

import base64
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from crypto.device_protocol import (
    canonical_device_enrollment_payload,
    canonical_device_key_sync_payload,
    sign_device_payload,
)
from domain.conversation_summary import ConversationSummary
from utils.protocol import create_device_key_sync_packet
from tests.test_device_key_sync import (
    _delete,
    _mutually_verify_devices,
    _new_device_session,
    _register,
    _verify_peers,
    _wait_for,
    account,
    running_server,
)


def _enroll_and_authorize_pair(desktop, browser):
    desktop.enroll_device(device_name="Desktop", platform="linux")
    desktop.bind_device_session()
    browser.enroll_device(device_name="Browser", platform="web")
    browser_pending = next(d for d in desktop.list_devices() if d["device_id"] == browser.device_id)
    desktop.authorize_device(browser.device_id, browser_pending["fingerprint"])
    browser.bind_device_session()
    _mutually_verify_devices(desktop, browser)
    return browser_pending


def _real_conversation_id(desktop, running_server, monkeypatch, tmp_path, hint="peer_"):
    peer_payload = _register(hint)
    peer = _new_device_session(running_server, monkeypatch, peer_payload, tmp_path / hint.strip("_"))

    assert _wait_for(lambda: desktop.key_manager.get_public_key(peer.username) is not None)
    assert _wait_for(lambda: peer.key_manager.get_public_key(desktop.username) is not None)
    _verify_peers(desktop, peer, peer.username)
    _verify_peers(peer, desktop, desktop.username)

    desktop.set_current_chat(
        ConversationSummary(conversation_id=None, username=peer.username, is_online=True, latest_message=None)
    )
    desktop.establish_session_key()

    return peer, desktop.current_conversation_id, peer_payload


# ========================================================================
# Step 6: server-side epoch authority.
# ========================================================================


def test_negative_epoch_rejected(running_server, monkeypatch, account, tmp_path):
    """
    A negative epoch cannot even be legitimately SIGNED -- crypto/
    device_protocol.py::canonical_device_key_sync_payload() packs epoch
    as an unsigned 4-byte integer (struct.pack(">I", ...)), which
    raises for any negative value -- so no genuine client, however
    malicious, can produce a validly-signed negative-epoch package at
    all. The only way one reaches the wire is a raw, unsigned/
    arbitrarily-"signed" packet an attacker assembles directly
    (bypassing the real signing path entirely), so that is what is
    sent here -- the server's Step 6 type check must reject it before
    signature verification is ever attempted, exactly like the non-
    integer-epoch case below.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = peer_payload = None
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "negepoch_"
        )
        genuine_epoch = desktop.key_manager.current_epoch(conversation_id)
        key_bytes = desktop.key_manager.get_key(conversation_id, epoch=genuine_epoch)

        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_bytes)

        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch=-1, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(os.urandom(64)).decode("ascii"),
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


def test_non_integer_epoch_rejected(running_server, monkeypatch, account, tmp_path):
    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = peer_payload = None
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "typeepoch_"
        )
        genuine_epoch = desktop.key_manager.current_epoch(conversation_id)
        key_bytes = desktop.key_manager.get_key(conversation_id, epoch=genuine_epoch)

        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_bytes)

        # The malformed value is injected at the WIRE level (the raw
        # packet dict), not through the signed canonical payload
        # builder (which would reject/coerce it before signing) --
        # exactly what an attacker tampering with an in-flight,
        # already-signed packet's epoch field would have to do; the
        # signature therefore also fails to verify, in addition to the
        # type check.
        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch="not-an-integer", package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(os.urandom(64)).decode("ascii"),
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


def test_epoch_exceeding_server_reserved_epoch_rejected(running_server, monkeypatch, account, tmp_path):
    """
    An absurdly large epoch the server has never reserved
    (Conversation.current_key_epoch) is rejected BEFORE relay, even
    with an otherwise perfectly valid signature over that (fabricated)
    epoch value -- the source device is trusted to report ITS OWN
    epoch honestly for values it could legitimately hold, but the
    server independently bounds it against its own authoritative
    record rather than trusting the claim outright.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = peer_payload = None
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "ceilepoch_"
        )
        genuine_epoch = desktop.key_manager.current_epoch(conversation_id)
        key_bytes = desktop.key_manager.get_key(conversation_id, epoch=genuine_epoch)

        absurd_epoch = genuine_epoch + 999999

        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_bytes)
        payload = canonical_device_key_sync_payload(
            desktop.username, desktop.device_id, browser.device_id, browser_pending["fingerprint"],
            conversation_id, absurd_epoch, "direct", encapsulation, wrapped_key,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)

        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch=absurd_epoch, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


def test_epoch_at_server_reserved_ceiling_accepted(running_server, monkeypatch, account, tmp_path):
    """Sanity counterpart: the conversation's real, currently-reserved
    epoch is accepted -- the ceiling check does not over-reject
    legitimate traffic."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = peer_payload = None
    try:
        _enroll_and_authorize_pair(desktop, browser)
        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "okepoch_"
        )

        result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)

        assert result["success"] is True
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


# ========================================================================
# Step 7: cross-operation domain-separation proof.
# ========================================================================


def test_enrollment_signature_cannot_be_reused_as_key_sync_signature(
    running_server, monkeypatch, account, tmp_path
):
    """
    A genuine, validly-produced device ENROLLMENT signature (purpose
    qrscs-device-v1 + op=enroll) cannot be resubmitted as a
    device_key_sync package's sync_signature (purpose qrscs-device-
    key-sync-v1) -- proves the pre-existing domain-separation design
    (crypto/device_protocol.py) already defeats cross-operation replay,
    exactly as Step 7 requires, without adding a second, incompatible
    mechanism.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = peer_payload = None
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "domain_"
        )
        genuine_epoch = desktop.key_manager.current_epoch(conversation_id)
        key_bytes = desktop.key_manager.get_key(conversation_id, epoch=genuine_epoch)
        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_bytes)

        # A genuine ENROLLMENT signature -- produced by the SAME
        # device's SAME ML-DSA key that would otherwise legitimately
        # sign a key-sync package.
        kem_public_key_wire = desktop.key_manager.public_key.decode("utf-8")
        ml_dsa_public_key = desktop.key_manager.ml_dsa.export_public_key()
        enrollment_payload = canonical_device_enrollment_payload(
            desktop.username, desktop.device_id, kem_public_key_wire,
            ml_dsa_public_key, "Desktop", "linux",
        )
        enrollment_signature = sign_device_payload(desktop.key_manager.ml_dsa, enrollment_payload)

        cross_domain_packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch=genuine_epoch, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(enrollment_signature).decode("ascii"),
        )
        result = desktop.send_request(cross_domain_packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


def test_key_sync_signature_cannot_be_reused_as_enrollment_signature(
    running_server, monkeypatch, account, tmp_path
):
    """The reverse direction: a genuine device_key_sync signature
    cannot be used to forge a NEW device's enrollment request."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = peer_payload = None
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "domain2_"
        )
        genuine_epoch = desktop.key_manager.current_epoch(conversation_id)
        key_bytes = desktop.key_manager.get_key(conversation_id, epoch=genuine_epoch)
        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_bytes)

        sync_payload = canonical_device_key_sync_payload(
            desktop.username, desktop.device_id, browser.device_id, browser_pending["fingerprint"],
            conversation_id, genuine_epoch, "direct", encapsulation, wrapped_key,
        )
        sync_signature = sign_device_payload(desktop.key_manager.ml_dsa, sync_payload)

        # Attempt: enroll a brand-new "device" using the key-sync
        # signature as the enrollment_signature.
        import base64 as b64
        import uuid as uuid_mod
        from utils.protocol import create_device_enroll_request_packet

        forged_device_id = str(uuid_mod.uuid4())
        forged_kem_public_key = desktop.key_manager.public_key.decode("utf-8")
        forged_ml_dsa_public_key = desktop.key_manager.ml_dsa.export_public_key()

        forged_packet = create_device_enroll_request_packet(
            device_id=forged_device_id,
            device_name="Forged",
            platform="linux",
            kem_public_key=forged_kem_public_key,
            ml_dsa_public_key=b64.b64encode(forged_ml_dsa_public_key).decode("ascii"),
            enrollment_signature=b64.b64encode(sync_signature).decode("ascii"),
        )
        result = desktop.send_request(forged_packet)

        assert result["success"] is False
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])
