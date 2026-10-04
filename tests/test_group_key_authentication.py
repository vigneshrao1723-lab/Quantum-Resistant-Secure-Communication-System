"""
Phase 13 -- Group-Key-Distribution ML-DSA Origin Authentication:
session-level fail-closed tests (Part 3) and a real end-to-end
ClientSession/server integration test (Part 4).

Before this phase, ClientSession.handle_group_key_distribution()'s own
docstring said outright "Uses only this client's own private key
material; nothing from the sender is needed beyond the packet's opaque
fields" -- ML-KEM-then-DEM (crypto/key_manager.py::
wrap_key_for_member()) gives CONFIDENTIALITY only: ANYONE holding a
recipient's PUBLIC ML-KEM key (broadcast to every connected client by
design) could independently encapsulate a fresh secret and wrap an
arbitrary key of their own choosing, and the recipient would install
it with zero origin verification. This file proves that gap is closed.

Mirrors tests/test_phase12a_downgrade_audit.py's and tests/
test_message_authentication.py's established patterns: bare, real
(no-mock) ClientSession + SecureKeyStore for hand-crafted-packet fail-
closed tests, and a real TLS test server + real ClientSession pairs
for the end-to-end production-path proof.

Run with:
    pytest tests/test_group_key_authentication.py -v
"""

import base64
import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession, PEER_KEY_STATE_CHANGED
from crypto.group_key_protocol import sign_group_key_payload
from crypto.identity_protocol import sign_identity_payload
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from crypto.kyber import KyberKEM
from crypto.message_protocol import sign_message_payload
from crypto.ml_dsa import MLDSASigner
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_UNVERIFIED, PEER_STATE_VERIFIED, SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


# ========================================================================
# Session-level helpers (no server, no socket) -- mirrors
# tests/test_phase12a_downgrade_audit.py's established pattern.
# ========================================================================


def _bare_session_with_store(username, tmp_path):
    session = ClientSession()
    session.username = username

    store = SecureKeyStore(f"{username}-user-id", storage_dir=tmp_path / username)
    store.unlock(PASSWORD)
    session.key_store = store

    return session


def _verify_peer(local_session, peer_session, peer_username):
    """Fully observe + explicitly VERIFY peer_session's identity from
    local_session's point of view -- required both for local_session
    to receive a group-key delivery FROM that sender (this phase's new
    rule) and, symmetrically, established via the exact same
    combined-identity machinery Phase 11 already built."""

    kem_wire = peer_session.key_manager.public_key
    signing_public_key = peer_session.key_manager.ml_dsa.export_public_key()

    local_session.observe_peer_identity(peer_username, kem_wire, signing_public_key)
    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    local_session.confirm_combined_peer_verification(peer_username, fingerprint)


def _signed_delivery_packet(
    sender_username, sender_ml_dsa, sender_km, recipient_session, recipient_username,
    conversation_id, group_key, epoch=1, signer=None,
):
    """
    Builds a REAL, genuinely-wrapped (crypto/key_manager.py::
    wrap_key_for_member()) and genuinely-signed (crypto/
    group_key_protocol.py::sign_group_key_payload()) group_key_
    distribution packet from ``sender_km`` (a standalone KeyManager
    acting as the sender's identity) to ``recipient_session`` (a real
    ClientSession whose own real KEM public key is used for wrapping).
    ``signer`` overrides the ML-DSA signer used (default: sender_km.ml_dsa)
    -- used by attack tests that sign with a DIFFERENT key than the one
    that did the wrapping.
    """

    sender_km.add_public_key(recipient_username, recipient_session.key_manager.public_key)

    encapsulation, wrapped_key = sender_km.wrap_key_for_member(recipient_username, group_key)

    actual_signer = signer if signer is not None else sender_ml_dsa

    signature = sign_group_key_payload(
        actual_signer, sender_username, conversation_id, recipient_username,
        encapsulation, wrapped_key, epoch,
    )

    return {
        "type": "group_key_distribution",
        "sender": sender_username,
        "conversation_id": conversation_id,
        "recipient": recipient_username,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": epoch,
        "group_key_signature": base64.b64encode(signature).decode("ascii"),
    }


def _fresh_sender():
    """A standalone, real (KeyManager, MLDSASigner-is-km.ml_dsa) sender
    identity -- KeyManager.__init__() already generates a real Kyber
    keypair and a real persistent-shaped ml_dsa signer unconditionally,
    matching exactly what a real ClientSession's own key_manager looks
    like."""

    km = KeyManager()
    return km, km.ml_dsa


# ========================================================================
# Part 3 -- fail-closed tests (session level)
# ========================================================================


def test_1_valid_group_key_packet_succeeds(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    group_key = os.urandom(32)

    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, group_key,
    )
    bob.username = "bob"
    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) == group_key


class _StubIdentity:
    """Adapts a standalone KeyManager (used as a "sender" in these
    tests, never a real ClientSession) to the (key_manager) shape
    _verify_peer() needs to read a peer's public identity from."""

    def __init__(self, key_manager):
        self.key_manager = key_manager


def test_2_modified_encrypted_group_key_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["wrapped_key"] = packet["wrapped_key"][:-1] + ("X" if packet["wrapped_key"][-1] != "X" else "Y")

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_3_modified_sender_identity_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["sender"] = "mallory"

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_4_modified_group_identity_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    other_conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["conversation_id"] = other_conversation_id

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    assert bob.key_manager.get_key(other_conversation_id, epoch=1) is None


def test_5_modified_recipient_identity_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["recipient"] = "charlie"

    # Not addressed to bob at all -- handle_group_key_distribution()'s
    # very first line ignores it (routing, not authentication), so
    # nothing is installed under any conversation_id bob might guess.
    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_6_modified_epoch_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32), epoch=1,
    )
    packet["epoch"] = 2

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    assert bob.key_manager.get_key(conversation_id, epoch=2) is None


def test_7_random_signature_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_8_truncated_signature_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    raw = base64.b64decode(packet["group_key_signature"])
    packet["group_key_signature"] = base64.b64encode(raw[:-4]).decode("ascii")

    bob.handle_group_key_distribution(packet)  # must not raise/crash

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_9_extra_signature_bytes_fail(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    raw = base64.b64decode(packet["group_key_signature"])
    packet["group_key_signature"] = base64.b64encode(raw + b"\x00" * 16).decode("ascii")

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_10_signature_from_another_peer_fails(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    charlie_km, charlie_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    # Signed with CHARLIE's key but claiming to be from alice.
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
        signer=charlie_signer,
    )

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_11_attacker_own_key_and_signature_fails(tmp_path):
    """The core CRITICAL TRUST RULE proof: an attacker with their own
    valid ML-DSA keypair signs their own forged delivery consistently
    -- but bob never resolves a verification key from the packet, only
    from his own trusted state for whoever "alice" already is."""

    alice_km, alice_signer = _fresh_sender()
    attacker_km, attacker_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    # Attacker wraps with THEIR OWN KeyManager (still targeting bob's
    # real public key) and signs with their own key, claiming sender="alice".
    packet = _signed_delivery_packet(
        "alice", attacker_signer, attacker_km, bob, "bob", conversation_id, os.urandom(32),
    )

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_12_valid_message_signature_cannot_authenticate_a_group_key_packet(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    alice_km.add_public_key("bob", bob.key_manager.public_key)
    encapsulation, wrapped_key = alice_km.wrap_key_for_member("bob", os.urandom(32))

    message_signature = sign_message_payload(
        alice_signer, "alice", "bob", None, "text", wrapped_key, None, 1
    )

    packet = {
        "type": "group_key_distribution",
        "sender": "alice",
        "conversation_id": conversation_id,
        "recipient": "bob",
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": 1,
        "group_key_signature": base64.b64encode(message_signature).decode("ascii"),
    }

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_13_valid_identity_signature_cannot_authenticate_a_group_key_packet(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    alice_km.add_public_key("bob", bob.key_manager.public_key)
    encapsulation, wrapped_key = alice_km.wrap_key_for_member("bob", os.urandom(32))

    identity_signature = sign_identity_payload(
        alice_signer, "alice", alice_km.public_key, alice_signer.export_public_key()
    )

    packet = {
        "type": "group_key_distribution",
        "sender": "alice",
        "conversation_id": conversation_id,
        "recipient": "bob",
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": 1,
        "group_key_signature": base64.b64encode(identity_signature).decode("ascii"),
    }

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_14_invalid_signature_does_not_install_the_group_key(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")

    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.has_key(conversation_id) is False


def test_15_invalid_signature_does_not_alter_current_active_group_key(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    real_key = os.urandom(32)
    good_packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, real_key,
    )
    bob.handle_group_key_distribution(good_packet)
    assert bob.key_manager.get_key(conversation_id, epoch=1) == real_key

    forged_packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32), epoch=2,
    )
    forged_packet["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
    bob.handle_group_key_distribution(forged_packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) == real_key
    assert bob.key_manager.current_epoch(conversation_id) == 1


def test_16_invalid_signature_does_not_change_group_epoch(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    good_packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32), epoch=1,
    )
    bob.handle_group_key_distribution(good_packet)
    assert bob.key_manager.current_epoch(conversation_id) == 1

    forged_packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32), epoch=5,
    )
    forged_packet["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
    bob.handle_group_key_distribution(forged_packet)

    assert bob.key_manager.current_epoch(conversation_id) == 1


def test_17_invalid_signature_does_not_crash_receiver(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    del packet["group_key_signature"]

    bob.handle_group_key_distribution(packet)  # must not raise

    packet2 = dict(packet)
    packet2["encapsulation"] = "not valid base64 kyber ciphertext!!"
    packet2["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
    bob.handle_group_key_distribution(packet2)  # must not raise


def test_18_invalid_signature_does_not_corrupt_group_membership_state(tmp_path):
    """No group-membership bookkeeping (conversation_store) is touched
    by handle_group_key_distribution() at all, valid or forged --
    proven directly: this handler only ever installs/refuses key
    material, never mutates conversation_store."""

    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    before = list(bob.conversation_store.get_all())

    forged_packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    forged_packet["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
    bob.handle_group_key_distribution(forged_packet)

    after = list(bob.conversation_store.get_all())
    assert before == after


def test_19_verified_peer_same_identity_remains_valid(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")
    assert bob.get_peer_verification_state("alice") == PEER_STATE_VERIFIED

    conversation_id = str(uuid.uuid4())
    real_key = os.urandom(32)
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, real_key,
    )
    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) == real_key
    assert bob.get_peer_verification_state("alice") == PEER_STATE_VERIFIED


def test_20_verified_peer_changed_signing_identity_causes_key_changed(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    # Alice's signing identity changes (e.g. reinstall / key loss).
    new_alice_km, new_alice_signer = _fresh_sender()
    new_alice_km.kyber = alice_km.kyber  # same KEM key, only signing changed
    new_alice_km.public_key = alice_km.public_key

    conversation_id = str(uuid.uuid4())
    bob.observe_peer_identity(
        "alice", new_alice_km.public_key, new_alice_signer.export_public_key()
    )
    assert bob.get_peer_verification_state("alice") == PEER_KEY_STATE_CHANGED

    # A group-key delivery genuinely, validly signed by the NEW
    # (disputed, KEY_CHANGED) identity must still be rejected -- it is
    # not silently accepted as though it came from the old, VERIFIED
    # identity, because it is not VERIFIED at all right now.
    packet = _signed_delivery_packet(
        "alice", new_alice_signer, new_alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    assert bob.get_peer_verification_state("alice") == PEER_KEY_STATE_CHANGED


def test_21_replay_of_identical_valid_packet_is_harmless(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    real_key = os.urandom(32)
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, real_key,
    )

    for _ in range(5):
        bob.handle_group_key_distribution(dict(packet))

    assert bob.key_manager.get_key(conversation_id, epoch=1) == real_key
    assert bob.key_manager.current_epoch(conversation_id) == 1


def test_22_old_epoch_cannot_overwrite_a_newer_active_epoch(tmp_path):
    """KeyManager.store_key()'s existing, pre-Phase-13 no-overwrite +
    max()-tracked current-epoch behavior already provides this
    monotonicity -- proven directly against a VALIDLY signed OLD-epoch
    delivery (not a forged one): even a genuine, correctly-authenticated
    epoch-1 redelivery arriving AFTER epoch 2 is already active must not
    roll the conversation's current epoch backward."""

    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    epoch_2_key = os.urandom(32)
    packet_epoch_2 = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, epoch_2_key, epoch=2,
    )
    bob.handle_group_key_distribution(packet_epoch_2)
    assert bob.key_manager.current_epoch(conversation_id) == 2

    old_epoch_1_key = os.urandom(32)
    packet_epoch_1 = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, old_epoch_1_key, epoch=1,
    )
    bob.handle_group_key_distribution(packet_epoch_1)

    assert bob.key_manager.current_epoch(conversation_id) == 2
    assert bob.key_manager.get_key(conversation_id, epoch=1) == old_epoch_1_key
    assert bob.key_manager.get_key(conversation_id, epoch=2) == epoch_2_key


def test_23_new_valid_epoch_works(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    epoch_1_key = os.urandom(32)
    bob.handle_group_key_distribution(
        _signed_delivery_packet(
            "alice", alice_signer, alice_km, bob, "bob", conversation_id, epoch_1_key, epoch=1,
        )
    )

    epoch_2_key = os.urandom(32)
    bob.handle_group_key_distribution(
        _signed_delivery_packet(
            "alice", alice_signer, alice_km, bob, "bob", conversation_id, epoch_2_key, epoch=2,
        )
    )

    assert bob.key_manager.get_key(conversation_id, epoch=1) == epoch_1_key
    assert bob.key_manager.get_key(conversation_id, epoch=2) == epoch_2_key
    assert bob.key_manager.current_epoch(conversation_id) == 2


# ========================================================================
# UNVERIFIED sender: group-key packets must be REJECTED, not merely
# left un-promoted (stricter than message-level authentication -- see
# handle_group_key_distribution()'s own docstring for why).
# ========================================================================


def test_unverified_sender_group_key_packet_is_rejected_even_with_valid_signature(tmp_path):
    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)

    # Bob OBSERVES alice's identity (so a signing key is resolvable)
    # but never explicitly VERIFIES her.
    bob.observe_peer_identity(
        "alice", alice_km.public_key, alice_signer.export_public_key()
    )
    assert bob.get_peer_verification_state("alice") == PEER_STATE_UNVERIFIED

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_unknown_sender_group_key_packet_is_rejected(tmp_path):
    """No observation of any kind -- the sender is a total stranger to
    this receiver."""

    alice_km, alice_signer = _fresh_sender()
    bob = _bare_session_with_store("bob", tmp_path)

    conversation_id = str(uuid.uuid4())
    packet = _signed_delivery_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    bob.handle_group_key_distribution(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


# ========================================================================
# Part 4 -- real end-to-end ClientSession/server integration
# ========================================================================


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Group Key Authentication Test",
            "username": f"gkauth_{hint}{suffix}",
            "email": f"gkauth_{hint}{suffix}@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": "+91%012d" % (uuid.uuid4().int % 10**12),
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete(username):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(username)
        if user is not None:
            for session in SessionRepository(db).get_active_sessions_for_user(user.id):
                db.delete(session)
            db.delete(user)
            db.commit()
    finally:
        db.close()


def _wait_for(predicate, attempts=300, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


@pytest.fixture()
def app(running_server, monkeypatch, tmp_path):
    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr(
        "storage.secure_key_store.KEY_STORE_DIR", tmp_path / "keystore"
    )

    opened = []
    created = []

    def _launch(payload):
        session = ClientSession()
        opened.append(session)

        result = session.authenticate_credentials(payload["phone_number"], PASSWORD)
        assert result.success, result.message

        session.user_id = result.user_id
        session.username = result.username
        session.session_id = result.session_id
        session.access_token = result.token_pair.access_token
        session.refresh_token = result.token_pair.refresh_token

        session.connect()
        session.login(payload["username"])
        session.send_public_key()
        session.start_receiver()
        return session

    def _register_user(hint):
        payload = _register(hint)
        created.append(payload)
        return payload

    yield {"launch": _launch, "register": _register_user}

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001
            pass

    for payload in created:
        _delete(payload["username"])


def _mutual_verify_real(a, b):
    """Waits for BOTH the KEM key AND the ML-DSA signing-key
    observation to be in place on each side before verifying --
    _handle_signed_public_key() installs the former slightly before it
    records the latter (a deliberate Phase-11 ordering fix), so waiting
    on the KEM key alone leaves a real, sub-millisecond race where
    confirm_combined_peer_verification() (which needs BOTH) can still
    raise PeerVerificationMismatchError -- see tests/
    test_message_authentication.py::_mutual_public_keys()'s identical
    fix/docstring for the original diagnosis."""

    assert _wait_for(lambda: a.key_manager.get_public_key(b.username) is not None)
    assert _wait_for(lambda: b.key_manager.get_public_key(a.username) is not None)
    assert _wait_for(lambda: a._observed_peer_signing_public_keys.get(b.username) is not None)
    assert _wait_for(lambda: b._observed_peer_signing_public_keys.get(a.username) is not None)

    a_fp = fingerprint_combined_identity(
        b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key()
    )
    a.confirm_combined_peer_verification(b.username, a_fp)
    b_fp = fingerprint_combined_identity(
        a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key()
    )
    b.confirm_combined_peer_verification(a.username, b_fp)


def test_real_end_to_end_group_key_distribution_and_messaging(app):
    """
    Alice -> real group-key generation -> real authenticated group-key
    distribution -> real server relay -> Bob/Carol -> ML-DSA
    verification -> group-key installation -> encrypted group message
    -> Bob/Carol receiver -> message authentication -> decryption.
    """

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")
    carol_payload = app["register"]("carol_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    carol = app["launch"](carol_payload)

    for a, b in ((alice, bob), (alice, carol), (bob, carol)):
        assert _wait_for(lambda a=a, b=b: a.key_manager.get_public_key(b.username) is not None)
        assert _wait_for(lambda a=a, b=b: b.key_manager.get_public_key(a.username) is not None)
        _mutual_verify_real(a, b)

    alice.create_group_conversation(
        "Real E2E Group", [bob_payload["username"], carol_payload["username"]]
    )

    assert _wait_for(
        lambda: any(
            s.is_group and s.group_name == "Real E2E Group"
            for s in alice.conversation_store.get_all()
        )
    )
    group_summary = next(
        s for s in alice.conversation_store.get_all()
        if s.is_group and s.group_name == "Real E2E Group"
    )
    conversation_id = group_summary.conversation_id

    assert _wait_for(
        lambda: bob.key_manager.has_key(conversation_id)
        and carol.key_manager.has_key(conversation_id)
    )

    # Both received the SAME real key alice generated -- proving
    # genuine ML-KEM-then-DEM unwrap succeeded for both, authenticated.
    assert bob.key_manager.get_key(conversation_id) == alice.key_manager.get_key(conversation_id)
    assert carol.key_manager.get_key(conversation_id) == alice.key_manager.get_key(conversation_id)

    alice.set_current_chat(group_summary)
    alice.send_chat_message("hello group, authenticated key and message")

    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "hello group, authenticated key and message"
            for summary in bob.conversation_store.get_all()
        )
    )
    assert _wait_for(
        lambda: any(
            summary.latest_message
            and summary.latest_message.text == "hello group, authenticated key and message"
            for summary in carol.conversation_store.get_all()
        )
    )


# ========================================================================
# Part 5 (group-key portion, K-O) -- malicious-server-in-the-middle
# tampering against the REAL production relay.
# ========================================================================


def test_attack_K_replace_encrypted_group_key_in_transit(app, monkeypatch):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None)
    _mutual_verify_real(alice, bob)

    attacker_km = KeyManager()
    attacker_km.add_public_key(bob_payload["username"], bob.key_manager.public_key)

    real_send_message = client_session_module.send_message

    def tampering_send_message(sock, packet):
        if packet.get("type") == "group_key_distribution":
            tampered = dict(packet)
            _, attacker_wrapped = attacker_km.wrap_key_for_member(
                bob_payload["username"], os.urandom(32)
            )
            tampered["wrapped_key"] = attacker_wrapped
            return real_send_message(sock, tampered)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", tampering_send_message)

    alice.create_group_conversation("Attack K Group", [bob_payload["username"]])

    time.sleep(1.0)
    _app.processEvents()

    conversation_ids_with_key = [
        cid for cid, epochs in bob.key_manager.keys.items() if epochs
    ]
    assert conversation_ids_with_key == [], (
        "the attacker-substituted group key must never be installed"
    )


def test_attack_L_modify_group_identity_in_transit(app, monkeypatch):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None)
    _mutual_verify_real(alice, bob)

    real_send_message = client_session_module.send_message
    captured = {}

    def tampering_send_message(sock, packet):
        if packet.get("type") == "group_key_distribution":
            captured["real_conversation_id"] = packet["conversation_id"]
            tampered = dict(packet)
            tampered["conversation_id"] = str(uuid.uuid4())
            return real_send_message(sock, tampered)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", tampering_send_message)

    alice.create_group_conversation("Attack L Group", [bob_payload["username"]])

    time.sleep(1.0)
    _app.processEvents()

    monkeypatch.setattr(client_session_module, "send_message", real_send_message)

    assert "real_conversation_id" in captured
    assert not bob.key_manager.has_key(captured["real_conversation_id"])


def test_attack_M_modify_epoch_in_transit(app, monkeypatch):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None)
    _mutual_verify_real(alice, bob)

    real_send_message = client_session_module.send_message
    captured = {}

    def tampering_send_message(sock, packet):
        if packet.get("type") == "group_key_distribution":
            captured["conversation_id"] = packet["conversation_id"]
            tampered = dict(packet)
            tampered["epoch"] = 999
            return real_send_message(sock, tampered)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", tampering_send_message)

    alice.create_group_conversation("Attack M Group", [bob_payload["username"]])

    time.sleep(1.0)
    _app.processEvents()

    monkeypatch.setattr(client_session_module, "send_message", real_send_message)

    assert "conversation_id" in captured
    assert bob.key_manager.get_key(captured["conversation_id"], epoch=999) is None
    assert bob.key_manager.current_epoch(captured["conversation_id"]) is None


def test_attack_N_replace_signature_in_transit(app, monkeypatch):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None)
    _mutual_verify_real(alice, bob)

    real_send_message = client_session_module.send_message
    captured = {}

    def tampering_send_message(sock, packet):
        if packet.get("type") == "group_key_distribution":
            captured["conversation_id"] = packet["conversation_id"]
            tampered = dict(packet)
            tampered["group_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
            return real_send_message(sock, tampered)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", tampering_send_message)

    alice.create_group_conversation("Attack N Group", [bob_payload["username"]])

    time.sleep(1.0)
    _app.processEvents()

    monkeypatch.setattr(client_session_module, "send_message", real_send_message)

    assert "conversation_id" in captured
    assert not bob.key_manager.has_key(captured["conversation_id"])


def test_attack_O_strip_signature_in_transit(app, monkeypatch):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None)
    _mutual_verify_real(alice, bob)

    real_send_message = client_session_module.send_message
    captured = {}

    def stripping_send_message(sock, packet):
        if packet.get("type") == "group_key_distribution":
            captured["conversation_id"] = packet["conversation_id"]
            stripped = dict(packet)
            stripped.pop("group_key_signature", None)
            return real_send_message(sock, stripped)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", stripping_send_message)

    alice.create_group_conversation("Attack O Group", [bob_payload["username"]])

    time.sleep(1.0)
    _app.processEvents()

    monkeypatch.setattr(client_session_module, "send_message", real_send_message)

    assert "conversation_id" in captured
    assert not bob.key_manager.has_key(captured["conversation_id"])

    # Receiver thread must still be alive and functional after every
    # attack above.
    assert bob.receiver_thread is not None
    assert bob.receiver_thread.is_alive()
