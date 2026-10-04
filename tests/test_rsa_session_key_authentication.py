"""
Phase 13.6 -- RSA Direct-Session-Key ML-DSA Origin Authentication:
session-level fail-closed tests (Part 7), a real end-to-end
ClientSession/server integration test, a genuine malicious-relay test
(Part 8), the Phase 13.5 audit's forgery PoC turned into a permanent
regression (Part 9), and cross-protocol domain-separation proofs
(Part 10).

Phase 13.5's independent audit proved empirically that
ClientSession.handle_session_key()'s RSA (non-KYBER) branch installed
ANY session key an attacker chose, addressed under ANY claimed sender
username, using nothing but the victim's PUBLIC RSA key (broadcast to
every connected client by design, exactly like the ML-KEM public key
Phase 13 already protected) -- RSA-OAEP is true public-key encryption,
so it gives confidentiality only, never authenticity. This file proves
that gap is closed the same way Phase 13 closed it for KYBER: an
ML-DSA-65 signature over a canonical envelope, verified against the
receiver's own already-established (and VERIFIED) peer-identity state,
BEFORE the RSA private-key decryption ever runs.

Mirrors tests/test_group_key_authentication.py's established pattern
(bare, real -- no-mock -- ClientSession + SecureKeyStore for hand-
crafted-packet fail-closed tests; a real TLS test server + real
ClientSession pairs for the end-to-end and malicious-relay proofs) and
tests/test_rsa_key_exchange_integration.py's established RSA-mode
fixture conventions (KEY_EXCHANGE_ALGORITHM patched before any
ClientSession/KeyManager is constructed).

Run with:
    pytest tests/test_rsa_session_key_authentication.py -v
"""

import base64
import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
import crypto.key_manager as key_manager_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.group_key_protocol import sign_group_key_payload
from crypto.identity_protocol import sign_identity_payload
from crypto.key_manager import KeyManager, fingerprint_public_key
from crypto.message_protocol import sign_message_payload
from crypto.ml_dsa import MLDSASigner
from crypto.session_key_protocol import (
    RSA_SESSION_KEY_PAYLOAD_PURPOSE,
    canonical_rsa_session_key_payload,
    sign_rsa_session_key_payload,
    verify_rsa_session_key_payload,
)
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


def _wait_for(predicate, attempts=150, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ========================================================================
# Session-level helpers (no server, no socket) -- mirrors
# tests/test_group_key_authentication.py's established pattern.
# ========================================================================


def _bare_rsa_session_with_store(username, tmp_path, monkeypatch):
    """A real, unconnected, RSA-mode ClientSession with a real,
    unlocked, isolated SecureKeyStore attached. KEY_EXCHANGE_ALGORITHM
    must be patched BEFORE construction -- KeyManager.__init__() reads
    it immediately (see tests/test_rsa_key_exchange_integration.py's
    own module docstring)."""

    monkeypatch.setattr(key_manager_module, "KEY_EXCHANGE_ALGORITHM", "RSA")

    session = ClientSession()
    session.username = username
    assert session.key_manager.algorithm == "RSA"

    store = SecureKeyStore(f"{username}-user-id", storage_dir=tmp_path / username)
    store.unlock(PASSWORD)
    session.key_store = store

    return session


def _verify_peer(local_session, peer_session, peer_username):
    """Fully observe + explicitly VERIFY peer_session's identity from
    local_session's point of view (Phase 13's established pattern,
    algorithm-agnostic: send_public_key() always attaches an ML-DSA
    signing key/signature regardless of KEY_EXCHANGE_ALGORITHM -- see
    client/session.py::send_public_key()'s own docstring)."""

    kem_wire = peer_session.key_manager.public_key
    signing_public_key = peer_session.key_manager.ml_dsa.export_public_key()

    local_session.observe_peer_identity(peer_username, kem_wire, signing_public_key)
    from crypto.key_manager import fingerprint_combined_identity

    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    local_session.confirm_combined_peer_verification(peer_username, fingerprint)


class _StubIdentity:
    """Adapts a bare KeyManager to the `.key_manager`-attribute shape
    _verify_peer() expects -- mirrors tests/test_group_key_
    authentication.py's own _StubIdentity exactly."""

    def __init__(self, key_manager):
        self.key_manager = key_manager


def _fresh_rsa_sender():
    """A standalone, real (KeyManager, MLDSASigner-is-km.ml_dsa) sender
    identity, forced to RSA mode post-construction (KeyManager.__init__
    already builds a real self.rsa unconditionally regardless of the
    active algorithm -- see crypto/key_manager.py)."""

    km = KeyManager()
    km.algorithm = "RSA"
    return km, km.ml_dsa


def _signed_rsa_packet(
    sender_username, sender_ml_dsa, sender_km, recipient_session, recipient_username,
    conversation_id, session_key, epoch=1, signer=None, algorithm="RSA",
):
    """
    Builds a REAL, genuinely-encrypted (crypto/key_manager.py::
    KeyManager.encrypt_session_key(), true RSA-OAEP public-key
    encryption) and genuinely-signed (crypto/session_key_protocol.py::
    sign_rsa_session_key_payload()) session_key packet from
    ``sender_km`` (a standalone KeyManager acting as the sender's
    identity) to ``recipient_session`` (a real ClientSession whose own
    real RSA public key is used for encryption). ``signer`` overrides
    the ML-DSA signer used (default: sender_ml_dsa) -- used by attack
    tests that sign with a DIFFERENT key than the one that did the
    encryption.
    """

    sender_km.add_public_key(recipient_username, recipient_session.key_manager.public_key)

    encrypted_key = sender_km.encrypt_session_key(recipient_username, session_key)
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")

    actual_signer = signer if signer is not None else sender_ml_dsa

    signature = sign_rsa_session_key_payload(
        actual_signer, sender_username, recipient_username, conversation_id,
        algorithm, encrypted_key_b64, epoch,
    )

    return {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": sender_username,
        "receiver": recipient_username,
        "algorithm": algorithm,
        "encrypted_key": encrypted_key_b64,
        "conversation_id": conversation_id,
        "epoch": epoch,
        "session_key_signature": base64.b64encode(signature).decode("ascii"),
    }


# ========================================================================
# Part 7 -- attack-resistance tests (session level, real handle_session_key())
# ========================================================================


def test_A_missing_signature_is_rejected(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    del packet["session_key_signature"]

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_B_invalid_signature_is_rejected(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["session_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_C_signature_generated_by_attacker_is_rejected(tmp_path, monkeypatch):
    """The attack Phase 13.5 demonstrated: the attacker has nothing
    belonging to the real alice -- only bob's already-public RSA key.
    Signing with the ATTACKER's own ML-DSA key (never alice's) must
    not authorize anything, because bob resolves the verification key
    from HIS OWN trust state for the CLAIMED sender ("alice"), never
    from the packet."""

    attacker_km, attacker_signer = _fresh_rsa_sender()
    alice_km, _alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", attacker_signer, attacker_km, bob, "bob", conversation_id,
        os.urandom(32), signer=attacker_signer,
    )

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_D_sender_substitution_is_rejected(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    carol_km, _carol_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")
    _verify_peer(bob, _StubIdentity(carol_km), "carol")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    # Relabel the sender after genuine signing -- the signed payload
    # still says "alice", so reconstructing it under the claimed
    # "carol" identity must not verify.
    packet["sender"] = "carol"

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_E_receiver_substitution_is_rejected(tmp_path, monkeypatch):
    """A packet genuinely signed for Bob must not verify if relabeled
    toward a different receiver -- proven directly against
    verify_rsa_session_key_payload() with the mismatched receiver,
    exactly as a receiver whose own username differs from what was
    signed would experience."""

    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    signature = base64.b64decode(packet["session_key_signature"])

    verified = verify_rsa_session_key_payload(
        "alice", "someone-else", conversation_id, "RSA",
        packet["encrypted_key"], 1, signature,
        alice_km.ml_dsa.export_public_key(),
    )

    assert verified is False


def test_F_conversation_substitution_is_rejected(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    other_conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["conversation_id"] = other_conversation_id

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    assert bob.key_manager.get_key(other_conversation_id, epoch=1) is None


def test_G_algorithm_substitution_is_rejected(tmp_path, monkeypatch):
    """Changing the signed ``algorithm`` field after the fact must
    invalidate the signature -- proven directly, since bob's own
    pre-existing (Phase-13.6-unrelated) algorithm-label-mismatch guard
    would otherwise short-circuit this before signature verification
    even runs for a genuinely KYBER-declared packet."""

    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    signature = base64.b64decode(packet["session_key_signature"])

    verified = verify_rsa_session_key_payload(
        "alice", "bob", conversation_id, "KYBER",
        packet["encrypted_key"], 1, signature,
        alice_km.ml_dsa.export_public_key(),
    )

    assert verified is False


def test_H_epoch_substitution_is_rejected(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
        epoch=1,
    )
    packet["epoch"] = 999

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=999) is None
    assert bob.key_manager.current_epoch(conversation_id) is None


def test_I_encrypted_key_substitution_is_rejected(tmp_path, monkeypatch):
    """The exact Phase 13.5 attack shape: the attacker replaces
    encrypted_key with their own RSA-OAEP encryption of an arbitrary
    key, using nothing but bob's already-public RSA key -- keeping
    alice's genuine signature and sender field untouched."""

    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )

    attacker_km, _ = _fresh_rsa_sender()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    forged_key = os.urandom(32)
    forged_encrypted = attacker_km.encrypt_session_key("bob", forged_key)
    packet["encrypted_key"] = base64.b64encode(forged_encrypted).decode("utf-8")

    bob.handle_session_key(packet)

    installed = bob.key_manager.get_key(conversation_id, epoch=1)
    assert installed is None
    assert installed != forged_key


def test_J_kyber_group_key_signature_does_not_authenticate_rsa_session_key(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    session_key = os.urandom(32)
    alice_km.add_public_key("bob", bob.key_manager.public_key)
    encrypted_key = alice_km.encrypt_session_key("bob", session_key)
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")

    # A genuinely-produced GROUP-KEY signature over superficially
    # similar-looking fields -- must not authenticate an RSA
    # session-key packet.
    group_signature = sign_group_key_payload(
        alice_signer, "alice", conversation_id, "bob",
        None, encrypted_key_b64, 1,
    )

    packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "RSA",
        "encrypted_key": encrypted_key_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
        "session_key_signature": base64.b64encode(group_signature).decode("ascii"),
    }

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_K_message_signature_does_not_authenticate_rsa_session_key(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    session_key = os.urandom(32)
    alice_km.add_public_key("bob", bob.key_manager.public_key)
    encrypted_key = alice_km.encrypt_session_key("bob", session_key)
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")

    message_signature = sign_message_payload(
        alice_signer, "alice", "bob", conversation_id, "TEXT",
        encrypted_key_b64, None, 1,
    )

    packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "RSA",
        "encrypted_key": encrypted_key_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
        "session_key_signature": base64.b64encode(message_signature).decode("ascii"),
    }

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_L_identity_signature_does_not_authenticate_rsa_session_key(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    session_key = os.urandom(32)
    alice_km.add_public_key("bob", bob.key_manager.public_key)
    encrypted_key = alice_km.encrypt_session_key("bob", session_key)
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")

    identity_signature = sign_identity_payload(
        alice_signer, "alice", alice_km.public_key,
        alice_signer.export_public_key(),
    )

    packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "RSA",
        "encrypted_key": encrypted_key_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
        "session_key_signature": base64.b64encode(identity_signature).decode("ascii"),
    }

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_M_unverified_sender_is_rejected_even_with_valid_signature(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)

    # Bob has OBSERVED alice's real identity (so a signing key IS
    # resolvable) but never explicitly VERIFIED her.
    bob.observe_peer_identity(
        "alice", alice_km.public_key, alice_signer.export_public_key()
    )

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    assert bob.get_peer_verification_state("alice") != "VERIFIED"


def test_N_unknown_sender_is_rejected(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)

    assert bob.key_manager.get_public_key("alice") is None
    assert bob.get_peer_verification_state("alice") is None

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )

    bob.handle_session_key(packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_O_malformed_signature_does_not_crash_receiver(tmp_path, monkeypatch):
    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, os.urandom(32),
    )
    packet["session_key_signature"] = "not valid base64 at all !!"

    bob.handle_session_key(packet)  # must not raise

    del packet["session_key_signature"]
    bob.handle_session_key(packet)  # must not raise

    packet["session_key_signature"] = None
    bob.handle_session_key(packet)  # must not raise

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_P_replay_of_old_valid_packet_obeys_epoch_rules(tmp_path, monkeypatch):
    """A genuine, still-current-epoch replay is a harmless no-op
    (KeyManager.store_key()'s pre-existing idempotent behavior, reused
    unmodified)."""

    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    session_key = os.urandom(32)
    packet = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, session_key,
    )

    bob.handle_session_key(packet)
    first = bob.key_manager.get_key(conversation_id, epoch=1)
    assert first == session_key

    # Replay the identical, already-processed packet again.
    bob.handle_session_key(packet)
    assert bob.key_manager.get_key(conversation_id, epoch=1) == session_key


def test_Q_duplicate_valid_packet_does_not_corrupt_installed_key(tmp_path, monkeypatch):
    """A SECOND, independently and genuinely signed packet for the
    SAME epoch (a different key value) must not replace the already-
    installed one -- KeyManager.store_key()'s no-overwrite rule,
    reused unmodified, applies regardless of how genuinely the second
    delivery is signed."""

    alice_km, alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    first_key = os.urandom(32)
    packet1 = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, first_key,
    )
    bob.handle_session_key(packet1)
    assert bob.key_manager.get_key(conversation_id, epoch=1) == first_key

    second_key = os.urandom(32)
    packet2 = _signed_rsa_packet(
        "alice", alice_signer, alice_km, bob, "bob", conversation_id, second_key,
    )
    bob.handle_session_key(packet2)

    assert bob.key_manager.get_key(conversation_id, epoch=1) == first_key
    assert bob.key_manager.get_key(conversation_id, epoch=1) != second_key


# ========================================================================
# Part 9 -- RSA forgery PoC turned into a permanent regression
# ========================================================================


def test_phase_13_5_audit_forgery_poc_no_longer_installs_attacker_key(tmp_path, monkeypatch):
    """
    Preserves the EXACT Phase 13.5 audit scenario:

        attacker has Bob's public RSA key (broadcast by design)
        attacker claims to be Alice
        attacker chooses an arbitrary session key
        attacker encrypts it to Bob (true RSA-OAEP public-key encryption)
        attacker sends a fake session_key packet

    Before Phase 13.6: bob installed the attacker's key (proven
    empirically during the Phase 13.5 audit). After Phase 13.6: bob
    must not -- there is no session_key_signature the attacker can
    produce without alice's ML-DSA private key, and bob only resolves
    the verification key from his OWN already-established (VERIFIED)
    trust state for "alice", never from the packet.

    This test is written to FAIL against the pre-Phase-13.6
    implementation (handle_session_key() with no signature/VERIFIED
    check at all would have unconditionally accepted this packet) and
    PASS against the fixed one.
    """

    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)

    # The attacker has ONLY bob's PUBLIC RSA key -- nothing belonging
    # to the real alice, no private key of bob's, no password for
    # either account, no ML-DSA key of alice's at all.
    attacker_km = KeyManager()
    attacker_km.algorithm = "RSA"
    attacker_km.add_public_key("bob", bob.key_manager.public_key)

    forged_session_key = os.urandom(32)
    encrypted_key = attacker_km.encrypt_session_key("bob", forged_session_key)

    conversation_id = str(uuid.uuid4())

    forged_packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",  # claimed -- attacker controls nothing belonging to the real alice
        "receiver": "bob",
        "algorithm": "RSA",
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "conversation_id": conversation_id,
        "epoch": 1,
        # Deliberately no session_key_signature -- the attacker has no
        # legitimate private key to produce one with.
    }

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None

    bob.handle_session_key(forged_packet)

    installed_key = bob.key_manager.get_key(conversation_id, epoch=1)

    # THE FIX PROVEN: no key was installed -- no cryptographic material
    # from the real Alice exists in this packet, bob never had "alice"
    # VERIFIED (indeed never even observed her), and there is no valid
    # signature.
    assert installed_key is None
    assert installed_key != forged_session_key


# ========================================================================
# Part 10 -- cross-protocol domain separation (unit-level, direct
# canonical-payload/verify calls -- no receiver involved)
# ========================================================================


def test_purpose_constant_is_distinct_from_other_three_protocols():
    from crypto.group_key_protocol import GROUP_KEY_PAYLOAD_PURPOSE
    from crypto.identity_protocol import IDENTITY_PAYLOAD_PURPOSE
    from crypto.message_protocol import MESSAGE_PAYLOAD_PURPOSE

    purposes = {
        RSA_SESSION_KEY_PAYLOAD_PURPOSE,
        GROUP_KEY_PAYLOAD_PURPOSE,
        IDENTITY_PAYLOAD_PURPOSE,
        MESSAGE_PAYLOAD_PURPOSE,
    }
    assert len(purposes) == 4, "all four domain-separation purposes must be distinct"

    # No purpose is a byte-for-byte prefix of another -- ruling out any
    # accidental boundary collision in the unframed leading prefix.
    values = list(purposes)
    for i, a in enumerate(values):
        for b in values[i + 1:]:
            shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
            assert longer[: len(shorter)] != shorter


def test_rsa_session_key_signature_does_not_verify_as_group_key_signature():
    km = KeyManager()
    km.algorithm = "RSA"

    conversation_id = str(uuid.uuid4())
    signature = sign_rsa_session_key_payload(
        km.ml_dsa, "alice", "bob", conversation_id, "RSA", "ZW5jcnlwdGVk", 1,
    )

    from crypto.group_key_protocol import verify_group_key_payload

    verified = verify_group_key_payload(
        "alice", conversation_id, "bob", None, "ZW5jcnlwdGVk", 1,
        signature, km.ml_dsa.export_public_key(),
    )
    assert verified is False


def test_rsa_session_key_signature_does_not_verify_as_message_signature():
    km = KeyManager()
    km.algorithm = "RSA"

    conversation_id = str(uuid.uuid4())
    signature = sign_rsa_session_key_payload(
        km.ml_dsa, "alice", "bob", conversation_id, "RSA", "ZW5jcnlwdGVk", 1,
    )

    from crypto.message_protocol import verify_message_payload

    verified = verify_message_payload(
        "alice", "bob", conversation_id, "TEXT", "ZW5jcnlwdGVk", None, 1,
        signature, km.ml_dsa.export_public_key(),
    )
    assert verified is False


def test_rsa_session_key_signature_does_not_verify_as_identity_signature():
    km = KeyManager()
    km.algorithm = "RSA"

    conversation_id = str(uuid.uuid4())
    signature = sign_rsa_session_key_payload(
        km.ml_dsa, "alice", "bob", conversation_id, "RSA", "ZW5jcnlwdGVk", 1,
    )

    from crypto.identity_protocol import verify_identity_payload

    verified = verify_identity_payload(
        "alice", km.public_key, km.ml_dsa.export_public_key(), signature,
    )
    assert verified is False


def test_group_key_signature_does_not_verify_as_rsa_session_key_signature():
    """The reverse direction: a genuinely-produced group-key signature
    must not authenticate an RSA session-key payload either."""

    km = KeyManager()
    conversation_id = str(uuid.uuid4())
    signature = sign_group_key_payload(
        km.ml_dsa, "alice", conversation_id, "bob", None, "ZW5jcnlwdGVk", 1,
    )

    verified = verify_rsa_session_key_payload(
        "alice", "bob", conversation_id, "RSA", "ZW5jcnlwdGVk", 1,
        signature, km.ml_dsa.export_public_key(),
    )
    assert verified is False


# ========================================================================
# Part 12 -- backward compatibility: unsigned legacy packets rejected
# ========================================================================


def test_unsigned_legacy_rsa_session_key_packet_is_rejected(tmp_path, monkeypatch):
    """A packet built exactly the way the PRE-Phase-13.6 protocol
    version constructed it -- no session_key_signature field at all --
    must not be silently accepted. Security takes priority over
    silently accepting legacy unauthenticated packets, per this
    phase's own explicit instruction."""

    alice_km, _alice_signer = _fresh_rsa_sender()
    bob = _bare_rsa_session_with_store("bob", tmp_path, monkeypatch)
    _verify_peer(bob, _StubIdentity(alice_km), "alice")

    conversation_id = str(uuid.uuid4())
    session_key = os.urandom(32)
    alice_km.add_public_key("bob", bob.key_manager.public_key)
    encrypted_key = alice_km.encrypt_session_key("bob", session_key)

    legacy_packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "algorithm": "RSA",
        "sender": "alice",
        "receiver": "bob",
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "epoch": 1,
        "conversation_id": conversation_id,
        # No session_key_signature -- the exact pre-Phase-13.6 wire shape.
    }

    bob.handle_session_key(legacy_packet)

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


# ========================================================================
# Part 8 -- real end-to-end + genuine malicious-relay tests. Real TLS
# test server, real ClientSession pair, real RSA encryption, real
# ML-DSA signing -- never handle_session_key() called directly.
# ========================================================================


def _register_rsa_user(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "RSA Session Key Auth Test",
            "username": f"rsask_{hint}{suffix}",
            "email": f"rsask_{hint}{suffix}@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete_rsa_user(username):
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


def _login_token(payload):
    db = SessionLocal()
    try:
        result = AuthenticationService(db).authenticate_user(
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _open_direct(session, partner_username):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=partner_username,
            is_online=True,
            latest_message=None,
        )
    )


@pytest.fixture()
def running_server():
    harness = start_test_server()
    yield harness
    harness.shutdown()


@pytest.fixture()
def rsa_app(running_server, monkeypatch, tmp_path):
    """Two real, fully connected, RSA-mode ClientSessions with real,
    unlocked, isolated SecureKeyStores, mutually VERIFIED -- mirrors
    tests/test_rsa_key_exchange_integration.py's own rsa_alice_and_bob
    fixture's conventions (KEY_EXCHANGE_ALGORITHM patched before any
    ClientSession/KeyManager is constructed) plus tests/
    test_group_key_authentication.py's real-server `app` fixture shape
    (real, on-disk key stores, so both directions' Phase-13/13.6
    VERIFIED requirement is actually satisfiable)."""

    _state, port = running_server

    monkeypatch.setattr(key_manager_module, "KEY_EXCHANGE_ALGORITHM", "RSA")
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    opened = []
    created = []

    def _launch(payload):
        session = ClientSession()
        assert session.key_manager.algorithm == "RSA"
        opened.append(session)

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

    def _register(hint):
        payload = _register_rsa_user(hint)
        created.append(payload)
        return payload

    yield {"launch": _launch, "register": _register}

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001 -- teardown must not mask a failure
            pass

    for payload in created:
        _delete_rsa_user(payload["username"])


def _mutual_verify_real(a, b):
    """Mutual VERIFIED, from real, live-observed identities (Phase
    13.6's symmetric requirement, matching Phase 13's own KYBER-mode
    rule)."""

    assert _wait_for(lambda: a._observed_peer_signing_public_keys.get(b.username) is not None)
    assert _wait_for(lambda: b._observed_peer_signing_public_keys.get(a.username) is not None)

    from crypto.key_manager import fingerprint_combined_identity

    a_fp = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    b_fp = fingerprint_combined_identity(a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key())

    a.confirm_combined_peer_verification(b.username, a_fp)
    b.confirm_combined_peer_verification(a.username, b_fp)


def test_real_end_to_end_rsa_session_key_and_message(rsa_app):
    """The production path, proved for real: Alice and Bob mutually
    verify, Alice's real establish_session_key() RSA branch signs and
    sends a real session_key packet over a real TLS socket, the real
    server relays it, Bob's real handle_session_key() verifies and
    installs it, and a subsequent real encrypted chat message actually
    decrypts on Bob's side."""

    alice_payload = rsa_app["register"]("alice_")
    bob_payload = rsa_app["register"]("bob_")

    alice = rsa_app["launch"](alice_payload)
    bob = rsa_app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    _mutual_verify_real(alice, bob)

    _open_direct(alice, bob.username)
    _open_direct(bob, alice.username)

    alice.send_chat_message("real rsa session key, real message")

    assert _wait_for(
        lambda: any(
            s.latest_message and s.latest_message.text == "real rsa session key, real message"
            for s in bob.conversation_store.get_all()
        )
    )

    conversation_id = alice.current_conversation_id
    assert bob.key_manager.has_key(conversation_id)


def _tampering_relay(monkeypatch, tamper_fn, captured=None):
    """Monkeypatches client_session_module.send_message to tamper with
    a genuinely-signed session_key packet AFTER signing but BEFORE it
    hits the wire -- simulating a malicious server intercepting and
    modifying a real packet in transit. The server never sees, and
    cannot forge, alice's ML-DSA private key."""

    real_send_message = client_session_module.send_message

    def recording(sock, packet):
        if packet.get("type") == "key_exchange" and packet.get("operation") == "session_key":
            if captured is not None:
                captured["packet"] = dict(packet)
            packet = tamper_fn(dict(packet))
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", recording)


def test_attack_relay_sender_substitution(rsa_app, monkeypatch):
    """Like conversation_id above, the ``sender`` field on a
    session_key packet is server-HARDENED (D3.1, pre-existing,
    unrelated to Phase 13.6: server/client_handler.py overwrites it
    with the authenticated socket's own username before relay), so a
    CLIENT-side tamper of this field is silently undone by the honest
    test server before bob ever sees it -- proving nothing about a
    malicious server, which controls that overwrite itself. Simulated
    correctly here by intercepting the server's own relay send and
    substituting a different (real, connected) user's identity for
    alice's, exactly as a malicious server relaying alice's genuinely-
    encrypted, genuinely-signed packet could attempt while claiming it
    came from carol instead."""

    import server.client_handler as server_client_handler_module

    alice_payload = rsa_app["register"]("alice_")
    bob_payload = rsa_app["register"]("bob_")
    carol_payload = rsa_app["register"]("carol_")

    alice = rsa_app["launch"](alice_payload)
    bob = rsa_app["launch"](bob_payload)
    carol = rsa_app["launch"](carol_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(carol.username) is not None)
    _mutual_verify_real(alice, bob)
    _mutual_verify_real(bob, carol)

    real_send_to_client = server_client_handler_module.send_to_client

    def tampering_send_to_client(sock, packet):
        if (
            packet.get("type") == "key_exchange"
            and packet.get("operation") == "session_key"
            and packet.get("sender") == alice.username
        ):
            packet = dict(packet)
            packet["sender"] = carol.username
        return real_send_to_client(sock, packet)

    monkeypatch.setattr(
        server_client_handler_module, "send_to_client", tampering_send_to_client
    )

    _open_direct(alice, bob.username)
    alice.send_chat_message("attack: sender substitution")
    time.sleep(1.0)
    _app.processEvents()

    conversation_id = alice.current_conversation_id
    assert not bob.key_manager.has_key(conversation_id)


def test_attack_relay_encrypted_key_substitution(rsa_app, monkeypatch):
    alice_payload = rsa_app["register"]("alice_")
    bob_payload = rsa_app["register"]("bob_")

    alice = rsa_app["launch"](alice_payload)
    bob = rsa_app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    _mutual_verify_real(alice, bob)

    attacker_km = KeyManager()
    attacker_km.algorithm = "RSA"
    attacker_km.add_public_key(bob.username, bob.key_manager.public_key)

    def _tamper(packet):
        forged = attacker_km.encrypt_session_key(bob.username, os.urandom(32))
        packet["encrypted_key"] = base64.b64encode(forged).decode("utf-8")
        return packet

    _tampering_relay(monkeypatch, _tamper)

    _open_direct(alice, bob.username)
    alice.send_chat_message("attack: encrypted_key substitution")
    time.sleep(1.0)
    _app.processEvents()

    conversation_id = alice.current_conversation_id
    assert not bob.key_manager.has_key(conversation_id)


def test_attack_relay_conversation_id_substitution(rsa_app, monkeypatch):
    """Like ``sender`` above, ``conversation_id`` on a session_key
    packet is server-RESOLVED (D3.1 hardening, server/client_handler.py
    ::_resolve_direct_conversation_id(), pre-existing and unrelated to
    Phase 13.6) -- a CLIENT-side tamper of this field would simply be
    overwritten right back to the correct value by the honest test
    server's own resolution, proving nothing about a malicious server.
    Simulated correctly here by intercepting the server's own relay
    send and corrupting conversation_id AFTER the server has already
    (honestly) resolved it -- exactly what a malicious server's own
    relay logic controls. Alice's signature is still computed over her
    own correctly-resolved local conversation_id, so the mismatch is
    caught regardless of which layer introduced it."""

    import server.client_handler as server_client_handler_module

    alice_payload = rsa_app["register"]("alice_")
    bob_payload = rsa_app["register"]("bob_")

    alice = rsa_app["launch"](alice_payload)
    bob = rsa_app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    _mutual_verify_real(alice, bob)

    real_send_to_client = server_client_handler_module.send_to_client
    captured = {}

    def tampering_send_to_client(sock, packet):
        if (
            packet.get("type") == "key_exchange"
            and packet.get("operation") == "session_key"
            and packet.get("sender") == alice.username
        ):
            captured["real_conversation_id"] = packet.get("conversation_id")
            packet = dict(packet)
            packet["conversation_id"] = str(uuid.uuid4())
        return real_send_to_client(sock, packet)

    monkeypatch.setattr(
        server_client_handler_module, "send_to_client", tampering_send_to_client
    )

    _open_direct(alice, bob.username)
    alice.send_chat_message("attack: conversation_id substitution")
    time.sleep(1.0)
    _app.processEvents()

    assert "real_conversation_id" in captured
    assert not bob.key_manager.has_key(captured["real_conversation_id"])


def test_attack_relay_epoch_substitution(rsa_app, monkeypatch):
    alice_payload = rsa_app["register"]("alice_")
    bob_payload = rsa_app["register"]("bob_")

    alice = rsa_app["launch"](alice_payload)
    bob = rsa_app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    _mutual_verify_real(alice, bob)

    captured = {}

    def _tamper(packet):
        captured["conversation_id"] = packet["conversation_id"]
        packet["epoch"] = 999
        return packet

    _tampering_relay(monkeypatch, _tamper, captured)

    _open_direct(alice, bob.username)
    alice.send_chat_message("attack: epoch substitution")
    time.sleep(1.0)
    _app.processEvents()

    assert "conversation_id" in captured
    assert bob.key_manager.get_key(captured["conversation_id"], epoch=999) is None
    assert bob.key_manager.current_epoch(captured["conversation_id"]) is None


def test_attack_relay_signature_replacement(rsa_app, monkeypatch):
    alice_payload = rsa_app["register"]("alice_")
    bob_payload = rsa_app["register"]("bob_")

    alice = rsa_app["launch"](alice_payload)
    bob = rsa_app["launch"](bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    _mutual_verify_real(alice, bob)

    captured = {}

    def _tamper(packet):
        captured["conversation_id"] = packet["conversation_id"]
        packet["session_key_signature"] = base64.b64encode(b"\x00" * 3309).decode("ascii")
        return packet

    _tampering_relay(monkeypatch, _tamper, captured)

    _open_direct(alice, bob.username)
    alice.send_chat_message("attack: signature replacement")
    time.sleep(1.0)
    _app.processEvents()

    assert "conversation_id" in captured
    assert not bob.key_manager.has_key(captured["conversation_id"])
