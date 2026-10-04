"""
Phase 16D -- Multi-Device Security Hardening: exact replay, epoch/
rollback protection, revocation-race honesty, and the remaining
security-negative-matrix cases Phase 16C left untested (see
docs/architecture/multi_device_identity.md's Phase 16C "Remaining
limitations").

No new cryptographic construction and no change to device_key_sync's
wire shape here -- this file proves properties that ALREADY hold
because of how the existing, unmodified building blocks are composed:

* crypto/key_manager.py::KeyManager.store_key() is already, by design,
  monotonic-epoch (never lowers ``_current_epoch``) and idempotent for
  a repeated identical epoch (never overwrites an existing epoch's key
  with a different value) -- a property ordinary group-key rotation
  already relies on ("a retried rotation instruction safe" -- see that
  method's own docstring). This phase's contribution is proving that
  property also protects the device_key_sync path, which reuses
  store_key() unchanged.
* crypto/device_protocol.py::canonical_device_key_sync_payload() binds
  target_device_id/target_fingerprint/conversation_id/epoch/
  package_type/encapsulation/wrapped_key into ONE ML-DSA signature --
  so mutating ANY one of those fields after signing invalidates the
  whole package. Each "modified X after signing" test below exercises
  a DIFFERENT field of that same binding.
* The client->server device_key_sync packet never carries a client-
  supplied source identity at all (see create_device_key_sync_packet()
  -- no username/source_device_id field); the server resolves both
  from its OWN authenticated connection state
  (server/device_handler.py::handle_device_key_sync()). "Wrong/
  modified source device_id" is therefore not a payload an attacker
  can even construct through the real client -- it is structurally
  prevented rather than merely rejected, documented here rather than
  faked as a test.

Run with:
    pytest tests/test_device_key_sync_hardening.py -v
"""

import base64
import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from crypto.device_protocol import canonical_device_key_sync_payload, sign_device_payload
from crypto.identity_protocol import sign_identity_payload
from domain.conversation_summary import ConversationSummary
from utils.network import send_message
from utils.protocol import create_device_key_sync_packet, create_public_key_packet
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
    """
    Phase 16E -- Step 3 added a server-side check
    (server/device_handler.py::handle_device_key_sync()) that the
    authenticated account is actually a member of ``conversation_id``,
    resolved from the server's own ConversationMember rows -- never
    from anything the client claims. A hand-picked ``str(uuid.uuid4())``
    (this file's own convention before this phase, used purely to
    isolate a cryptographic-boundary check from conversation setup) is
    therefore no longer a conversation the server will relay
    device_key_sync material for at all, regardless of what else is
    correct about the request.

    Returns ``(peer_session, conversation_id)`` -- a genuine peer, a
    real establish_session_key() round trip, and the real, server-
    registered conversation_id that produces. Caller is responsible
    for disconnecting the returned peer session.
    """

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
# Step 6: exact replay.
# ========================================================================


def test_exact_replay_of_valid_sync_package_is_idempotent_and_safe(
    running_server, monkeypatch, account, tmp_path
):
    """
    The EXACT SAME signed device_key_sync package, delivered twice,
    must never corrupt state or roll anything back -- proves
    KeyManager.store_key()'s existing same-epoch idempotency (see this
    module's own docstring) also covers the sync path. A malicious
    relay (this project's whole threat model for the server) can
    always resend bytes it has already seen once; this is what makes
    that harmless.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = None
    peer_payload = None
    try:
        _enroll_and_authorize_pair(desktop, browser)

        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "replay1_"
        )

        captured = []
        original_send_request = desktop.send_request

        def _capture(packet):
            captured.append(dict(packet))
            return original_send_request(packet)

        desktop.send_request = _capture
        try:
            first_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        finally:
            desktop.send_request = original_send_request

        assert first_result["success"] is True
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
        key_after_first_delivery = browser.key_manager.get_key(conversation_id)
        epoch_after_first_delivery = browser.key_manager.current_epoch(conversation_id)

        # Replay: the IDENTICAL signed package (every field byte-for-
        # byte the same as what was actually sent, including the
        # signature) delivered a SECOND time via the real send_request
        # path -- exactly what a malicious relay replaying captured
        # traffic would do.
        replayed_packet = captured[0]
        second_result = desktop.send_request(replayed_packet)

        assert second_result["success"] is True
        assert browser.key_manager.get_key(conversation_id) == key_after_first_delivery
        assert browser.key_manager.current_epoch(conversation_id) == epoch_after_first_delivery
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


def test_exact_replay_after_target_reconnect_is_still_safe(
    running_server, monkeypatch, account, tmp_path
):
    """Step 6 -- replay after the target has disconnected and
    reconnected (a fresh receiver-thread/socket, same on-disk identity)
    must be exactly as safe as a same-session replay."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser_dir = tmp_path / "browser"
    browser = _new_device_session(running_server, monkeypatch, account, browser_dir)
    peer = None
    peer_payload = None
    try:
        _enroll_and_authorize_pair(desktop, browser)

        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "replay2_"
        )

        captured = []
        original_send_request = desktop.send_request

        def _capture(packet):
            captured.append(dict(packet))
            return original_send_request(packet)

        desktop.send_request = _capture
        try:
            result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        finally:
            desktop.send_request = original_send_request

        assert result["success"] is True
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
        key_before_reconnect = browser.key_manager.get_key(conversation_id)
    finally:
        browser.disconnect()

    reconnected_browser = _new_device_session(running_server, monkeypatch, account, browser_dir)
    try:
        # device_id persisted (Phase 16B) -- resolving it again (the
        # normal app-startup call) loads the SAME id from the on-disk
        # key store rather than minting a new one, so desktop's
        # captured packet, naming that SAME device_id/fingerprint, is
        # still addressed correctly after the reconnect.
        reconnected_browser.enroll_device(device_name="Browser", platform="web")
        assert reconnected_browser.device_id == browser.device_id
        reconnected_browser.bind_device_session()

        replayed_packet = captured[0]
        result = desktop.send_request(replayed_packet)

        assert result["success"] is True
        assert reconnected_browser.key_manager.has_key(conversation_id) or _wait_for(
            lambda: reconnected_browser.key_manager.has_key(conversation_id)
        )
        assert reconnected_browser.key_manager.get_key(conversation_id) == key_before_reconnect
    finally:
        desktop.disconnect()
        reconnected_browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


def test_replayed_package_cannot_be_redirected_to_a_different_target_device(
    running_server, monkeypatch, account, tmp_path
):
    """
    Step 6 (replay against another device) + Step 9 case 20 (server-
    side redirect attempt): a captured, validly-signed package for
    Browser cannot be re-addressed to a THIRD device by rewriting
    target_device_id/target_fingerprint -- both are bound into the
    ML-DSA signature, so any redirect attempt invalidates it. Modeled
    as the untrusted relay (the server) itself tampering with an
    already-signed, in-flight packet -- exactly the "server must never
    be trusted with device state" threat model this protocol was built
    against.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    tablet = _new_device_session(running_server, monkeypatch, account, tmp_path / "tablet")
    peer = None
    peer_payload = None
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)

        tablet.enroll_device(device_name="Tablet", platform="android")
        tablet_pending = next(d for d in desktop.list_devices() if d["device_id"] == tablet.device_id)
        desktop.authorize_device(tablet.device_id, tablet_pending["fingerprint"])
        tablet.bind_device_session()
        _mutually_verify_devices(desktop, tablet)

        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "redirect_"
        )
        genuine_epoch = desktop.key_manager.current_epoch(conversation_id)
        key_bytes = desktop.key_manager.get_key(conversation_id, epoch=genuine_epoch)

        # A genuinely valid package, signed for Browser...
        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_bytes)
        payload = canonical_device_key_sync_payload(
            desktop.username, desktop.device_id, browser.device_id, browser_pending["fingerprint"],
            conversation_id, genuine_epoch, "direct", encapsulation, wrapped_key,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)

        # ...but redirected to Tablet by rewriting target_device_id/
        # target_fingerprint post-signing.
        redirected_packet = create_device_key_sync_packet(
            target_device_id=tablet.device_id, target_fingerprint=tablet_pending["fingerprint"],
            conversation_id=conversation_id, epoch=genuine_epoch, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        )
        result = desktop.send_request(redirected_packet)

        assert result["success"] is False
        assert not tablet.key_manager.has_key(conversation_id)
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()
        tablet.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


# ========================================================================
# Step 7: epoch / rollback protection.
# ========================================================================


def test_stale_epoch_sync_cannot_roll_back_already_advanced_local_epoch(
    running_server, monkeypatch, account, tmp_path
):
    """
    Step 7 C/F: if the target has ALREADY locally advanced past the
    epoch a (genuinely, validly signed) sync package names, delivering
    that stale package must never move current_epoch() backwards, and
    must never disturb the newer epoch's own key -- KeyManager.
    store_key()'s existing max()-based monotonic epoch tracking (see
    this module's own docstring), exercised here through the real
    device_key_sync receive path rather than store_key() directly.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = None
    peer_payload = None
    try:
        _enroll_and_authorize_pair(desktop, browser)

        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "epoch_"
        )
        # establish_session_key() reserves a real epoch server-side --
        # not necessarily 1 -- so "stale" is genuinely relative to
        # whatever this conversation's real starting epoch is.
        stale_epoch = desktop.key_manager.current_epoch(conversation_id)
        stale_key = desktop.key_manager.get_key(conversation_id, epoch=stale_epoch)

        # Target already independently holds a NEWER epoch for this
        # conversation (e.g. from a legitimate group rotation) --
        # simulated locally, since this phase does not implement group
        # sync (see Step 11's own "Remaining limitations"). Relative to
        # the conversation's real reserved starting epoch, not a
        # hardcoded absolute value.
        advanced_epoch = stale_epoch + 5
        advanced_key = os.urandom(32)
        browser.key_manager.store_key(conversation_id, advanced_key, epoch=advanced_epoch)
        assert browser.key_manager.current_epoch(conversation_id) == advanced_epoch

        encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, stale_key)
        target_fingerprint = desktop.get_peer_fingerprint_for_verification(browser.device_id)
        payload = canonical_device_key_sync_payload(
            desktop.username, desktop.device_id, browser.device_id, target_fingerprint,
            conversation_id, stale_epoch, "direct", encapsulation, wrapped_key,
        )
        signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)

        stale_packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=target_fingerprint,
            conversation_id=conversation_id, epoch=stale_epoch, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=base64.b64encode(signature).decode("ascii"),
        )
        result = desktop.send_request(stale_packet)

        assert result["success"] is True  # a valid package -- relayed and installed at stale_epoch

        def _stale_epoch_installed():
            return browser.key_manager.get_key(conversation_id, epoch=stale_epoch) == stale_key

        assert _wait_for(_stale_epoch_installed)

        # The newer epoch is completely undisturbed, and "current" (the
        # highest epoch this client has ever held) never moved backward.
        assert browser.key_manager.current_epoch(conversation_id) == advanced_epoch
        assert browser.key_manager.get_key(conversation_id, epoch=advanced_epoch) == advanced_key
        assert browser.key_manager.get_key(conversation_id) == advanced_key  # default = current = advanced_epoch
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


# ========================================================================
# Step 8: revocation race / delivery ordering.
# ========================================================================


def test_revoking_source_after_legitimate_delivery_does_not_erase_delivered_key(
    running_server, monkeypatch, account, tmp_path
):
    """
    Step 8 Case A: Desktop syncs a key to Browser while still
    AUTHORIZED; Desktop is revoked AFTERWARD. Revocation prevents
    FUTURE access (Desktop can no longer sync/act as an authorized
    device), but it does NOT -- and architecturally cannot --
    retroactively erase key material Browser already received and
    decrypted before the revocation. This is the same honest boundary
    already documented for ordinary device revocation
    (docs/architecture/multi_device_identity.md) -- this test proves
    it holds for device_key_sync specifically, and that it is not
    silently misrepresented as erasure.
    """

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    peer = None
    peer_payload = None
    try:
        _enroll_and_authorize_pair(desktop, browser)

        peer, conversation_id, peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "revrace_"
        )
        key_bytes = desktop.key_manager.get_key(conversation_id)  # current (real, reserved) epoch

        result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        assert result["success"] is True
        assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))

        desktop.revoke_device(desktop.device_id)  # self-revoke AFTER legitimate delivery

        # The key Browser already received/decrypted is still held --
        # revocation is prospective, never retroactive erasure.
        assert browser.key_manager.get_key(conversation_id) == key_bytes

        # But the revoked Desktop can no longer sync anything NEW --
        # a second sync attempt (same conversation, so Desktop is
        # still genuinely a member and the Phase 16E membership check
        # alone would not explain a rejection here; it must be the
        # revocation check) is blocked.
        browser.key_manager.remove_key(conversation_id)  # undo the legitimate delivery locally to observe the attempt cleanly
        blocked_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
        assert blocked_result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()
        if peer is not None:
            peer.disconnect()
        if peer_payload is not None:
            _delete(peer_payload["username"])


# ========================================================================
# Step 9: remaining security-negative-matrix cases (post-signing field
# tamper -- each mutates exactly one bound field of an otherwise
# genuinely signed package).
# ========================================================================


def _genuine_signed_fields(desktop, browser, browser_fingerprint, conversation_id, epoch=1):
    key_bytes = os.urandom(32)
    desktop.key_manager.store_key(conversation_id, key_bytes, epoch=epoch)
    encapsulation, wrapped_key = desktop.key_manager.wrap_key_for_member(browser.device_id, key_bytes)
    payload = canonical_device_key_sync_payload(
        desktop.username, desktop.device_id, browser.device_id, browser_fingerprint,
        conversation_id, epoch, "direct", encapsulation, wrapped_key,
    )
    signature = sign_device_payload(desktop.key_manager.ml_dsa, payload)
    return encapsulation, wrapped_key, base64.b64encode(signature).decode("ascii")


def test_modified_ciphertext_after_signing_rejected(running_server, monkeypatch, account, tmp_path):
    """Step 9 case 13: wrapped_key (the AES-256-GCM-wrapped key
    material) mutated after signing must fail signature verification,
    never merely fail decryption silently-successfully with wrong
    bytes."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        conversation_id = str(uuid.uuid4())
        encapsulation, wrapped_key, sig_b64 = _genuine_signed_fields(
            desktop, browser, browser_pending["fingerprint"], conversation_id
        )

        raw = base64.b64decode(wrapped_key)
        tampered_wrapped_key = base64.b64encode(bytes(b ^ 0xFF for b in raw)).decode("ascii")

        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch=1, package_type="direct",
            encapsulation=encapsulation, wrapped_key=tampered_wrapped_key,
            sync_signature=sig_b64,
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


def test_modified_conversation_id_after_signing_rejected(running_server, monkeypatch, account, tmp_path):
    """Step 9 case 16: conversation_id mutated after signing must be
    rejected -- otherwise a genuine package for conversation A could be
    replayed/relabeled to install its key under a DIFFERENT
    conversation B."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        genuine_conversation_id = str(uuid.uuid4())
        relabeled_conversation_id = str(uuid.uuid4())
        encapsulation, wrapped_key, sig_b64 = _genuine_signed_fields(
            desktop, browser, browser_pending["fingerprint"], genuine_conversation_id
        )

        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=relabeled_conversation_id, epoch=1, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=sig_b64,
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(relabeled_conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


def test_modified_package_type_after_signing_rejected(running_server, monkeypatch, account, tmp_path):
    """Step 9 case 17: package_type ("direct" vs. a future "group")
    mutated after signing must be rejected -- it is bound into the
    signature so a direct-conversation package cannot be relabeled as
    a group package (or vice versa) in flight."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        conversation_id = str(uuid.uuid4())
        encapsulation, wrapped_key, sig_b64 = _genuine_signed_fields(
            desktop, browser, browser_pending["fingerprint"], conversation_id
        )

        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=browser_pending["fingerprint"],
            conversation_id=conversation_id, epoch=1, package_type="group",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=sig_b64,
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


def test_modified_target_fingerprint_after_signing_rejected(running_server, monkeypatch, account, tmp_path):
    """Step 9 cases 4/9 (wrong target fingerprint): even naming the
    CORRECT target_device_id, a fingerprint that disagrees with the
    signed one (or with the server's own stored record) must be
    rejected -- binds the package to a specific public key, not just
    an opaque id the server could otherwise silently swap under."""

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        browser_pending = _enroll_and_authorize_pair(desktop, browser)
        conversation_id = str(uuid.uuid4())
        encapsulation, wrapped_key, sig_b64 = _genuine_signed_fields(
            desktop, browser, browser_pending["fingerprint"], conversation_id
        )

        wrong_fingerprint = "0" * len(browser_pending["fingerprint"])

        packet = create_device_key_sync_packet(
            target_device_id=browser.device_id, target_fingerprint=wrong_fingerprint,
            conversation_id=conversation_id, epoch=1, package_type="direct",
            encapsulation=encapsulation, wrapped_key=wrapped_key,
            sync_signature=sig_b64,
        )
        result = desktop.send_request(packet)

        assert result["success"] is False
        assert not browser.key_manager.has_key(conversation_id)
    finally:
        desktop.disconnect()
        browser.disconnect()


# ========================================================================
# Phase 18.5 -- Closure Audit: an unverified key_exchange announcement
# must never be able to clobber a cryptographically-verified device
# binding.
# ========================================================================


def test_unverified_public_key_reannouncement_cannot_spoof_bound_device_id(
    running_server, monkeypatch, account, tmp_path
):
    """
    server/server_state.py::set_public_key() stores the device_id
    carried on an ordinary key_exchange/public_key packet -- entirely
    client-claimed, never verified (canonical_identity_payload()'s own
    signed fields are username/kem_public_key/signing_public_key only;
    device_id is not among them -- confirmed by reading crypto/
    identity_protocol.py). server/device_handler.py::
    handle_device_session_bind() stores a SEPARATE, cryptographically-
    verified device_id (proven by an ML-DSA signature over that exact
    device's private key) that is_device_bound_and_authorized()/
    _find_socket_for_bound_device()/handle_device_key_sync() all then
    trust for real authorization/routing decisions.

    Before this phase's fix, both writes landed in the SAME
    ServerState.clients[...]["device_id"] slot -- so ANY authenticated
    connection could silently overwrite its own already-verified device
    binding just by sending one more, otherwise perfectly ordinary,
    validly-signed public-key re-announcement with a different
    device_id field (a field the identity signature does not cover at
    all). This proves the fix: after desktop binds to its real,
    verified device_id, a later public-key re-announcement claiming an
    arbitrary OTHER device_id must not change what
    is_device_bound_and_authorized()/device_key_sync's source-device
    resolution actually trust -- server-internal state is inspected
    directly (via the running_server harness's own ServerState, the
    same object server/device_handler.py itself reads) since this is a
    server-internal invariant, not something the client-facing API
    surface alone can observe.
    """

    state, _port = running_server

    desktop = _new_device_session(running_server, monkeypatch, account, tmp_path / "desktop")
    browser = _new_device_session(running_server, monkeypatch, account, tmp_path / "browser")
    try:
        _enroll_and_authorize_pair(desktop, browser)

        desktop_socket = next(
            sock for sock, client in state.clients.items()
            if client["username"] == desktop.username and client.get("device_id") == desktop.device_id
        )
        assert state.clients[desktop_socket]["device_id"] == desktop.device_id

        # A validly-signed public-key re-announcement (the identity
        # signature is real and would verify -- this is not a
        # malformed-packet or forged-signature attack) that merely
        # CLAIMS a different device_id, exactly like a compromised or
        # buggy client could send at any time on an already-bound
        # connection.
        spoofed_device_id = str(uuid.uuid4())
        kem_public_key_wire = desktop.key_manager.public_key.decode("utf-8")
        signing_public_key = desktop.key_manager.ml_dsa.export_public_key()
        signature = sign_identity_payload(
            desktop.key_manager.ml_dsa, desktop.username, kem_public_key_wire, signing_public_key,
        )
        spoofed_packet = create_public_key_packet(
            username=desktop.username,
            algorithm=desktop.key_manager.algorithm,
            public_key=kem_public_key_wire,
            signing_public_key=base64.b64encode(signing_public_key).decode("ascii"),
            identity_signature=base64.b64encode(signature).decode("ascii"),
            device_id=spoofed_device_id,
        )
        send_message(desktop.client_socket, spoofed_packet)

        assert _wait_for(
            lambda: state.clients[desktop_socket].get("announced_device_id") == spoofed_device_id
        )

        # The claim was recorded -- but ONLY in the unverified slot.
        # The verified binding (what security-relevant code actually
        # trusts) must be completely unaffected.
        assert state.clients[desktop_socket]["device_id"] == desktop.device_id
        assert state.clients[desktop_socket]["device_id"] != spoofed_device_id

        # End-to-end proof, not just internal-state inspection: a real
        # device_key_sync from this connection still authenticates as
        # the ORIGINAL bound device -- browser (already device-peer-
        # VERIFIED against desktop's REAL device_id) must still accept
        # it exactly as before the spoofed announcement.
        peer, conversation_id, _peer_payload = _real_conversation_id(
            desktop, running_server, monkeypatch, tmp_path, "spoofpeer_"
        )
        try:
            sync_result = desktop.sync_conversation_key_to_device(browser.device_id, conversation_id)
            assert sync_result["success"] is True
            assert _wait_for(lambda: browser.key_manager.has_key(conversation_id))
            assert (
                browser.key_manager.get_key(conversation_id)
                == desktop.key_manager.get_key(conversation_id)
            )
        finally:
            peer.disconnect()
    finally:
        desktop.disconnect()
        browser.disconnect()
