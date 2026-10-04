"""
Phase 19 -- Mobile Client: interoperability proof.

Every scenario drives the REAL mobile/session.py::MobileClientSession
against the REAL server (no gateway -- Python has raw socket access,
so this connects over the same TLS+TCP protocol client/session.py
itself uses), interoperating with a REAL desktop client.session.py::
ClientSession and, for one scenario, a REAL browser running the REAL
web client through the REAL gateway -- consistent with this whole
project's "never mock the protocol/crypto" testing philosophy. No
byte-exact interop proof is needed for crypto (unlike the web client,
which ported ML-KEM/ML-DSA/AES-GCM to JS): mobile imports and runs the
EXACT SAME crypto.* modules desktop does, so interoperability here is
inherent, not merely proven -- these tests exercise it end to end
regardless.

Run with:
    pytest tests/test_mobile_client_session.py -v
"""

import base64
import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

import client.session as client_session_module
import mobile.session as mobile_session_module
from client.session import ClientSession
from crypto.aes import AESCipher
from crypto.key_manager import fingerprint_combined_identity
from crypto.message_protocol import sign_message_payload
from domain.conversation_summary import ConversationSummary
from domain.payload_envelope import PayloadEnvelope
from mobile.session import MobileClientSession
from tests.test_device_key_sync import (
    PASSWORD,
    _delete,
    _register,
    _wait_for,
    running_server,
)
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _connect_browser,
    browser_page,
    gateway_url,
    static_url,
)
from utils.network import send_message as raw_send_message
from utils.protocol import create_payload_packet

_app = QApplication.instance() or QApplication([])


def _new_mobile_session(running_server, monkeypatch, payload, storage_dir):
    _state, port = running_server
    monkeypatch.setattr(mobile_session_module, "SERVER_PORT", port)

    session = MobileClientSession(storage_dir=str(storage_dir))
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _new_desktop_session(running_server, monkeypatch, payload, key_store_dir):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr("storage.secure_key_store.KEY_STORE_DIR", key_store_dir)

    session = ClientSession()
    result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
    assert result.success, result.message
    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _confirm(session, key, fingerprint):
    """ClientSession (desktop) and MobileClientSession name their
    "mark this observed identity as VERIFIED" method differently
    (confirm_combined_peer_verification vs confirm_peer_verified) --
    this dispatches to whichever the object actually has."""

    if hasattr(session, "confirm_combined_peer_verification"):
        session.confirm_combined_peer_verification(key, fingerprint)
    else:
        session.confirm_peer_verified(key, fingerprint)


def _write_temp_file(tmp_path, filename, data):
    """ClientSession.send_attachment() (desktop) takes a file PATH, not
    bytes directly (unlike MobileClientSession.send_attachment(), which
    takes bytes -- a mobile-appropriate shape, matching how a real
    Android file/image picker hands the app bytes, not a filesystem
    path it necessarily controls)."""

    path = tmp_path / filename
    path.write_bytes(data)
    return str(path)


def _mutual_verify(a, b):
    """a observes+verifies b (addressed as b.username), and vice versa
    -- ordinary peer verification, both directions."""

    a.observe_peer_identity(b.username, b.key_manager.public_key.decode("utf-8"), b.key_manager.ml_dsa.export_public_key())
    fp_b = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    _confirm(a, b.username, fp_b)

    b.observe_peer_identity(a.username, a.key_manager.public_key.decode("utf-8"), a.key_manager.ml_dsa.export_public_key())
    fp_a = fingerprint_combined_identity(a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key())
    _confirm(b, a.username, fp_a)


# ========================================================================
# Auth + connect.
# ========================================================================


def test_mobile_authenticates_connects_and_sends_public_key(running_server, monkeypatch, tmp_path):
    payload = _register("mobauth_")
    try:
        mobile = _new_mobile_session(running_server, monkeypatch, payload, tmp_path / "mobile")
        assert mobile.connected is True
        assert mobile.username == payload["username"]
        assert mobile.key_manager.algorithm == "KYBER"
        assert mobile.key_manager.public_key is not None
    finally:
        mobile.disconnect()
        _delete(payload["username"])


def test_mobile_rejects_login_with_wrong_password(running_server, monkeypatch, tmp_path):
    payload = _register("mobauthbad_")
    try:
        _state, port = running_server
        monkeypatch.setattr(mobile_session_module, "SERVER_PORT", port)
        mobile = MobileClientSession(storage_dir=str(tmp_path / "mobile"))
        result = mobile.authenticate_credentials(payload["phone_number"], "WrongPassword!123")
        assert result.success is False
    finally:
        _delete(payload["username"])


# ========================================================================
# Direct messaging, both directions.
# ========================================================================


def test_mobile_desktop_direct_messaging_bidirectional(running_server, monkeypatch, tmp_path):
    alice_payload = _register("mobalice_")
    bob_payload = _register("mobbob_")
    try:
        alice = _new_desktop_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_ks")
        mobile = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        assert _wait_for(lambda: alice.key_manager.get_public_key(mobile.username) is not None)
        assert _wait_for(lambda: mobile.key_manager.get_public_key(alice.username) is not None)

        _mutual_verify(alice, mobile)

        alice.set_current_chat(ConversationSummary(conversation_id=None, username=mobile.username, is_online=True, latest_message=None))
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: mobile.key_manager.has_key(conversation_id))

        received_by_mobile = {}
        mobile.message_received.connect(lambda identity_key, sender, text, historical, status=None: received_by_mobile.update(sender=sender, text=text))
        alice.send_chat_message("hello mobile, from desktop")
        assert _wait_for(lambda: received_by_mobile.get("text") == "hello mobile, from desktop")

        received_by_alice = {}
        alice.message_received.connect(lambda identity_key, sender, text: received_by_alice.update(sender=sender, text=text))
        mobile.send_message(alice.username, "hello desktop, from mobile")
        assert _wait_for(lambda: received_by_alice.get("text") == "hello desktop, from mobile")
        assert received_by_alice.get("sender") == mobile.username
    finally:
        alice.disconnect()
        mobile.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_mobile_rejects_tampered_message_signature(running_server, monkeypatch, tmp_path):
    """Security-negative: a chat packet with a message_signature that
    does not match its (tampered) ciphertext must be rejected -- never
    decrypted, never delivered to message_received."""

    alice_payload = _register("mobtamper_")
    bob_payload = _register("mobtamperb_")
    try:
        alice = _new_desktop_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_ks")
        mobile = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        assert _wait_for(lambda: alice.key_manager.get_public_key(mobile.username) is not None)
        assert _wait_for(lambda: mobile.key_manager.get_public_key(alice.username) is not None)
        _mutual_verify(alice, mobile)

        alice.set_current_chat(ConversationSummary(conversation_id=None, username=mobile.username, is_online=True, latest_message=None))
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: mobile.key_manager.has_key(conversation_id))

        rejected = {}
        mobile.security_rejection.connect(lambda reason, sender, cid: rejected.update(reason=reason, sender=sender))

        # Send a raw, hand-tampered packet directly on the wire --
        # desktop's own send_chat_message() always produces a valid
        # signature, so the tamper has to be injected below it.
        session_key = alice.key_manager.get_key(conversation_id)
        aes = AESCipher(session_key)
        ciphertext = aes.encrypt("genuine text")
        epoch = alice.key_manager.current_epoch(conversation_id) or 1
        signature = sign_message_payload(
            alice.key_manager.ml_dsa, alice.username, mobile.username, None, "text", ciphertext, None, epoch,
        )
        envelope = PayloadEnvelope(payload_type="text", ciphertext=ciphertext, content_metadata={})
        packet = create_payload_packet(
            sender=alice.username, envelope=envelope, receiver=mobile.username, epoch=epoch,
            message_signature=base64.b64encode(signature).decode("ascii"),
        )
        # Tamper: swap in a DIFFERENT (still validly base64, still
        # validly AES-GCM-encrypted, just for different plaintext)
        # ciphertext AFTER the signature was already computed over the
        # original one -- the signature no longer matches.
        packet["message"] = aes.encrypt("tampered text")

        raw_send_message(alice.client_socket, packet)

        assert _wait_for(lambda: rejected.get("reason") == "invalid_signature")
    finally:
        alice.disconnect()
        mobile.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


# ========================================================================
# Offline recovery + history dedup.
# ========================================================================


def test_mobile_offline_message_recovery_no_duplicates(running_server, monkeypatch, tmp_path):
    alice_payload = _register("mobhist_")
    bob_payload = _register("mobhistb_")
    mobile2 = None
    try:
        alice = _new_desktop_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_ks")
        mobile = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        assert _wait_for(lambda: alice.key_manager.get_public_key(mobile.username) is not None)
        assert _wait_for(lambda: mobile.key_manager.get_public_key(alice.username) is not None)
        _mutual_verify(alice, mobile)

        alice.set_current_chat(ConversationSummary(conversation_id=None, username=mobile.username, is_online=True, latest_message=None))
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: mobile.key_manager.has_key(conversation_id))

        alice.send_chat_message("message before mobile goes offline")
        # Phase 19.17C -- _rendered_message_ids is keyed by conversation_id
        # (dict[conversation_id, set[message_id]]), not a flat cross-
        # conversation set (see MobileClientSession.forget_rendered_
        # history()'s own docstring for why: open_chat() must be able to
        # forget just ONE conversation's dedup memory on reopen without
        # losing every other open conversation's).
        assert _wait_for(lambda: len(mobile._rendered_message_ids.get(conversation_id, ())) >= 1)

        mobile.disconnect()
        time.sleep(0.2)

        alice.send_chat_message("missed message one")
        alice.send_chat_message("missed message two")
        time.sleep(0.3)

        mobile2 = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        received = []
        mobile2.message_received.connect(lambda identity_key, sender, text, historical, status=None: received.append(text))

        # mobile2 is a genuinely fresh MobileClientSession -- peer trust
        # is session-local by this class's own deliberate design (see
        # mobile/session.py's own module docstring), so it must observe
        # alice's identity again before it can verify her historical
        # messages' signatures, exactly like it would for a live one.
        # The server re-broadcasts alice's already-known public key to
        # this newly-connecting account automatically
        # (distribute_public_keys(), unchanged) -- this just waits for
        # that async delivery to land on the receiver thread.
        assert _wait_for(lambda: mobile2.peers.get(alice.username) is not None)

        cid = mobile2.open_direct_conversation(alice.username)
        n = mobile2.load_history(cid, is_group=False)
        assert n >= 3  # the pre-offline message + the two missed ones

        assert "missed message one" in received
        assert "missed message two" in received
        assert received.index("missed message one") < received.index("missed message two")

        # Loading again must not add new entries to the rendered set
        # (Step 6 dedup semantics, reused unchanged from Phase 18.5).
        before = len(mobile2._rendered_message_ids.get(cid, ()))
        mobile2.load_history(cid, is_group=False)
        assert len(mobile2._rendered_message_ids.get(cid, ())) == before
    finally:
        alice.disconnect()
        mobile.disconnect()
        if mobile2 is not None:
            mobile2.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


# ========================================================================
# Group messaging.
# ========================================================================


def test_mobile_group_messaging_with_desktop(running_server, monkeypatch, tmp_path):
    alice_payload = _register("mobgroupa_")
    bob_payload = _register("mobgroupb_")
    try:
        alice = _new_desktop_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_ks")
        mobile = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        assert _wait_for(lambda: alice.key_manager.get_public_key(mobile.username) is not None)
        assert _wait_for(lambda: mobile.key_manager.get_public_key(alice.username) is not None)
        _mutual_verify(alice, mobile)

        alice.create_group_conversation("mobile-interop-group", [mobile.username])

        conversation_id = None

        def _group_ready_on_desktop():
            nonlocal conversation_id
            for summary in alice.conversation_store.get_all():
                if summary.is_group and summary.group_name == "mobile-interop-group":
                    conversation_id = summary.conversation_id
                    return True
            return False

        assert _wait_for(_group_ready_on_desktop)
        assert _wait_for(lambda: conversation_id in mobile.groups)
        assert _wait_for(lambda: mobile.key_manager.has_key(conversation_id))

        assert mobile.key_manager.get_key(conversation_id) == alice.key_manager.get_key(conversation_id)

        alice.set_current_chat(ConversationSummary(
            conversation_id=conversation_id, username=None, is_online=True, latest_message=None,
            is_group=True, group_name="mobile-interop-group",
        ))
        received_by_mobile = {}
        mobile.message_received.connect(lambda identity_key, sender, text, historical, status=None: received_by_mobile.update(sender=sender, text=text))
        alice.send_chat_message("hello group, from desktop")
        assert _wait_for(lambda: received_by_mobile.get("text") == "hello group, from desktop")

        received_by_alice = {}
        alice.message_received.connect(lambda identity_key, sender, text: received_by_alice.update(sender=sender, text=text))
        mobile.send_group_message(conversation_id, "hello group, from mobile")
        assert _wait_for(lambda: received_by_alice.get("text") == "hello group, from mobile")
        assert received_by_alice.get("sender") == mobile.username
    finally:
        alice.disconnect()
        mobile.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


# ========================================================================
# File transfer, byte-exact.
# ========================================================================


def test_mobile_file_transfer_byte_exact(running_server, monkeypatch, tmp_path):
    alice_payload = _register("mobfilea_")
    bob_payload = _register("mobfileb_")
    try:
        alice = _new_desktop_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_ks")
        mobile = _new_mobile_session(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        assert _wait_for(lambda: alice.key_manager.get_public_key(mobile.username) is not None)
        assert _wait_for(lambda: mobile.key_manager.get_public_key(alice.username) is not None)
        _mutual_verify(alice, mobile)

        alice.set_current_chat(ConversationSummary(conversation_id=None, username=mobile.username, is_online=True, latest_message=None))
        alice.establish_session_key()
        conversation_id = alice.current_conversation_id
        assert _wait_for(lambda: mobile.key_manager.has_key(conversation_id))

        # --- Desktop (alice) -> mobile: a genuinely binary file. ---
        file_bytes = bytes(range(256)) * 4  # 1024 bytes, every byte value present
        received_by_mobile = {}
        mobile.payload_message_received.connect(
            lambda identity_key, sender, payload_type, content, content_metadata, historical, status=None: received_by_mobile.update(
                sender=sender, payload_type=payload_type, content=content, content_metadata=content_metadata,
            )
        )
        alice.send_attachment(_write_temp_file(tmp_path, "desktop_test.bin", file_bytes))
        assert _wait_for(lambda: received_by_mobile.get("content") == file_bytes)
        assert received_by_mobile.get("payload_type") == "file"

        # --- mobile -> Desktop (alice): a genuinely binary image. ---
        received_by_alice = {}
        alice.payload_message_received.connect(
            lambda identity_key, sender, payload_type, content, content_metadata: received_by_alice.update(
                sender=sender, payload_type=payload_type, content=content,
            )
        )
        image_bytes = os.urandom(2048)
        mobile.send_attachment(alice.username, None, image_bytes, "mobile_test.png", "image/png")
        assert _wait_for(lambda: received_by_alice.get("content") == image_bytes)
        assert received_by_alice.get("payload_type") == "image"
    finally:
        alice.disconnect()
        mobile.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


# ========================================================================
# Multi-device identity: mobile as a second device of a desktop account.
# ========================================================================


def test_mobile_device_enrollment_authorization_and_key_sync(running_server, monkeypatch, tmp_path):
    carol_payload = _register("mobdev_")
    dave_payload = _register("mobdevd_")
    dave = None
    try:
        desktop = _new_desktop_session(running_server, monkeypatch, carol_payload, tmp_path / "carol_ks")
        desktop.enroll_device(device_name="Desktop", platform="linux")  # bootstrap -> AUTHORIZED
        desktop.bind_device_session()

        mobile = _new_mobile_session(running_server, monkeypatch, carol_payload, tmp_path / "carol_mobile")
        enroll_result = mobile.enroll_device(device_name="Mobile", platform="android")
        assert enroll_result["state"] == "PENDING", enroll_result
        mobile_device_id = mobile.device_id
        assert mobile_device_id

        pending = next(d for d in desktop.list_devices() if d["device_id"] == mobile_device_id)
        pending_ml_dsa_key = base64.b64decode(pending["ml_dsa_public_key"])
        desktop.observe_device_peer_identity(mobile_device_id, pending["kem_public_key"], pending_ml_dsa_key)
        fp = fingerprint_combined_identity(pending["kem_public_key"], pending_ml_dsa_key)
        desktop.confirm_device_peer_verification(mobile_device_id, fp)
        desktop.authorize_device(mobile_device_id, fp)

        bind_result = mobile.bind_device_session()
        assert bind_result["success"] is True

        # Mutual device trust -- mobile must also verify the desktop
        # device before accepting a device_key_sync FROM it.
        desktop_device_id = desktop.device_id
        mobile_devices = mobile.list_devices()
        desktop_row = next(d for d in mobile_devices if d["device_id"] == desktop_device_id)
        mobile.observe_device_peer_identity(desktop_device_id, desktop_row["kem_public_key"], desktop_row["ml_dsa_public_key"])
        desktop_fp = fingerprint_combined_identity(desktop_row["kem_public_key"], base64.b64decode(desktop_row["ml_dsa_public_key"]))
        mobile.confirm_device_peer_verified(desktop_device_id, desktop_fp)

        # An ordinary conversation Desktop already holds a key for.
        dave = _new_desktop_session(running_server, monkeypatch, dave_payload, tmp_path / "dave_ks")
        assert _wait_for(lambda: desktop.key_manager.get_public_key(dave.username) is not None)
        assert _wait_for(lambda: dave.key_manager.get_public_key(desktop.username) is not None)
        _mutual_verify(desktop, dave)

        desktop.set_current_chat(ConversationSummary(conversation_id=None, username=dave.username, is_online=True, latest_message=None))
        desktop.establish_session_key()
        conversation_id = desktop.current_conversation_id
        assert _wait_for(lambda: dave.key_manager.has_key(conversation_id))

        sync_result = desktop.sync_conversation_key_to_device(mobile_device_id, conversation_id)
        assert sync_result["success"] is True
        assert _wait_for(lambda: mobile.key_manager.has_key(conversation_id))
        assert mobile.key_manager.get_key(conversation_id) == desktop.key_manager.get_key(conversation_id)

        # Revoke: mobile can no longer bind afterward.
        desktop.revoke_device(mobile_device_id)
        revoked_bind = mobile.bind_device_session()
        assert revoked_bind["success"] is False
    finally:
        desktop.disconnect()
        mobile.disconnect()
        if dave is not None:
            dave.disconnect()
        _delete(carol_payload["username"])
        _delete(dave_payload["username"])


# ========================================================================
# Web <-> Mobile interoperability (real browser, real gateway, real
# mobile session, real server -- three genuinely different client
# implementations of the SAME protocol).
# ========================================================================


def test_mobile_web_direct_messaging_bidirectional(running_server, gateway_url, browser_page, monkeypatch, tmp_path):
    alice_payload = _register("mobweb_")
    bob_payload = _register("mobwebb_")
    try:
        mobile = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice_mobile")
        _connect_browser(browser_page, gateway_url, bob_payload)
        page = browser_page["page"]
        bob_username = bob_payload["username"]

        assert _wait_for(lambda: mobile.key_manager.get_public_key(bob_username) is not None)

        # Mobile observes+verifies the browser.
        kem_wire = page.evaluate(
            "(() => { const b=window.__session.kemKeypair.publicKey; "
            "let s=''; for (let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); return btoa(s); })()"
        )
        signing_key_hex = page.evaluate(
            "(() => { const b=window.__session.signingKeypair.publicKey; "
            "let s=''; for (let i=0;i<b.length;i++) s+= b[i].toString(16).padStart(2,'0'); return s; })()"
        )
        signing_key = bytes.fromhex(signing_key_hex)
        mobile.observe_peer_identity(bob_username, kem_wire, signing_key)
        fp = fingerprint_combined_identity(kem_wire, signing_key)
        mobile.confirm_peer_verified(bob_username, fp)

        # The browser observes+verifies mobile, through the real UI.
        page.fill("#peerUsername", mobile.username)
        assert _wait_for(lambda: mobile.username in page.inner_text("#fingerprintDisplay"))
        page.click("#confirmVerifiedBtn")
        assert _wait_for(lambda: "marked VERIFIED" in page.inner_text("#log"))

        # --- Mobile -> Web ---
        mobile.establish_session_key(bob_username)
        conversation_id = mobile.open_direct_conversation(bob_username)
        assert _wait_for(lambda: page.evaluate(f"window.__session.sessionKeys.has({conversation_id!r})"))

        mobile.send_message(bob_username, "hello web, from mobile")
        assert _wait_for(
            lambda: "hello web, from mobile" in page.inner_text("#messages"),
            attempts=200, interval=0.1,
        )

        # --- Web -> Mobile ---
        received_by_mobile = {}
        mobile.message_received.connect(lambda identity_key, sender, text, historical, status=None: received_by_mobile.update(sender=sender, text=text))
        page.fill("#messageText", "hello mobile, from web")
        page.click("#sendBtn")
        assert _wait_for(lambda: received_by_mobile.get("text") == "hello mobile, from web")
        assert received_by_mobile.get("sender") == bob_username
    finally:
        mobile.disconnect()
        _delete(alice_payload["username"])


def test_sidebar_preview_never_shows_the_undecryptable_placeholder_text(running_server, monkeypatch, tmp_path):
    """Manual-acceptance defect fix (real physical vivo V2036 device
    test): _UNDECRYPTABLE_PLACEHOLDER ("Message unavailable (encrypted
    in a previous session)") was leaking into the chats-list sidebar
    preview when this device has no cached session key for a stored
    message, visually overlapping the unread indicator. load_history()
    (an OPENED conversation's real message list) is unaffected by this
    fix -- it already skips an undecryptable message outright, never
    showing any placeholder text for it (see load_history()'s own
    "continue" on decryption failure, unchanged by this fix)."""
    from database.repositories.conversation_repository import ConversationRepository
    from database.repositories.message_repository import MessageRepository
    from database.connection import SessionLocal
    from datetime import datetime, timezone
    from domain.payload_type import PayloadType

    alice_payload = _register("nokeyprev_a_")
    bob_payload = _register("nokeyprev_b_")

    db = SessionLocal()
    try:
        conversation_repo = ConversationRepository(db)
        conversation = conversation_repo.get_or_create_direct_conversation(
            uuid.UUID(alice_payload["user_id"]), uuid.UUID(bob_payload["user_id"])
        )
        conversation_repo.commit()
        conversation_id = conversation.id

        MessageRepository(db).save_message(
            sender_id=uuid.UUID(bob_payload["user_id"]),
            receiver_id=uuid.UUID(alice_payload["user_id"]),
            conversation_id=conversation_id,
            ciphertext="opaque-ciphertext-no-real-key",
            blob_ref=None,
            payload_type=PayloadType.TEXT,
            content_metadata=None,
            algorithm="KYBER",
            timestamp=datetime.now(timezone.utc),
            epoch=1,
            message_signature=None,
        )
        conversation_repo.commit()
    finally:
        db.close()

    # This session never established a session key with bob -- exactly
    # like a fresh install, or a message left over from a previous
    # device/session.
    alice = _new_mobile_session(running_server, monkeypatch, alice_payload, tmp_path / "alice")
    try:
        conversations = alice.load_conversations()
        assert len(conversations) == 1

        preview = conversations[0]["last_message"]
        assert preview is not None
        assert "Message unavailable" not in preview
        assert "previous session" not in preview
        assert preview == ""
    finally:
        alice.disconnect()
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])
        _delete(bob_payload["username"])
