"""
Phase 13.8A -- KYBER Session-Key Forgery Remediation.

Phase 13.8's independent audit proved empirically that
ClientSession.handle_session_key()'s "KYBER branch" -- previously
believed dead/legacy code, since no production CLIENT ever constructs
a "session_key" packet with algorithm="KYBER" (KYBER-mode direct
session-key establishment uses group_key_distribution instead,
authenticated since Phase 13) -- was in fact directly reachable by
packet injection: this project's entire threat model is a MALICIOUS
SERVER/RELAY, which needs no legitimate client's cooperation to forge
a packet shape nothing legitimate produces. The branch decapsulated
and installed ANY session key an attacker chose, addressed under ANY
claimed sender, using nothing but the victim's already-public ML-KEM
key -- no signature was ever checked. This file proves that gap is
closed: the branch now rejects unconditionally, before any
decapsulation is attempted, since exhaustive tracing (this phase's own
Part 1/2) found zero legitimate production or test dependency on it
ever succeeding.

Mirrors tests/test_rsa_session_key_authentication.py's and tests/
test_group_key_authentication.py's established patterns (bare, real --
no-mock -- ClientSession for hand-crafted-packet tests).

Run with:
    pytest tests/test_kyber_session_key_forgery_remediation.py -v
"""

import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from client.session import ClientSession
from crypto.key_manager import KeyManager
from domain.security_rejection_reason import SecurityRejectionReason


def _bare_kyber_session(username):
    """A real, unconnected, default (KYBER-mode) ClientSession -- no
    server, no socket."""

    session = ClientSession()
    session.username = username
    assert session.key_manager.algorithm == "KYBER"
    return session


def _signals(session):
    events = []
    session.security_rejection.connect(
        lambda reason, sender, conversation_id: events.append((reason, sender, conversation_id))
    )
    return events


# ========================================================================
# Part 6 -- the exact previously-successful attack, as a permanent
# regression: attacker knows only the victim's public KYBER key.
# ========================================================================


def test_phase_13_8_kyber_forgery_poc_no_longer_installs_attacker_key():
    """
    Preserves the EXACT Phase 13.8 audit scenario:

        attacker has bob's public KYBER key (broadcast by design)
        attacker claims to be alice
        attacker encapsulates their OWN fresh secret against it (true
            ML-KEM public-key operation -- the attacker therefore
            knows the resulting shared secret exactly)
        attacker sends a fake session_key packet, algorithm=KYBER,
            no signature at all

    Before this fix: bob installed the attacker's key (proven
    empirically during the Phase 13.8 audit). After this fix: bob must
    not -- the branch is rejected unconditionally, before any
    decapsulation is attempted.

    This test is written to FAIL against the pre-Phase-13.8A
    implementation and PASS against the fixed one.
    """

    bob = _bare_kyber_session("bob")
    events = _signals(bob)

    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    ciphertext_b64, attacker_known_secret = attacker_km.encapsulate_session_key("bob")

    conversation_id = str(uuid.uuid4())

    forged_packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",  # claimed -- attacker controls nothing belonging to the real alice
        "receiver": "bob",
        "algorithm": "KYBER",
        "encrypted_key": ciphertext_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
        # Deliberately no signature field of any kind -- this branch
        # never checked for one, and still doesn't need to: it now
        # rejects before ever looking at the ciphertext.
    }

    assert bob.key_manager.get_key(conversation_id, epoch=1) is None

    result = bob.handle_session_key(forged_packet)

    assert result == SecurityRejectionReason.OTHER_SECURITY_REJECTION
    assert events == [(SecurityRejectionReason.OTHER_SECURITY_REJECTION.value, "alice", conversation_id)]

    installed_key = bob.key_manager.get_key(conversation_id, epoch=1)

    # THE FIX PROVEN: no key was installed at all, let alone the
    # attacker's specific known secret.
    assert installed_key is None
    assert installed_key != attacker_known_secret


# ========================================================================
# Part 7 -- negative / state-integrity coverage (A-H)
# ========================================================================


def test_A_forged_kyber_session_key_is_rejected():
    bob = _bare_kyber_session("bob")
    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    ciphertext_b64, _secret = attacker_km.encapsulate_session_key("bob")
    conversation_id = str(uuid.uuid4())

    result = bob.handle_session_key({
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "KYBER",
        "encrypted_key": ciphertext_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
    })

    assert result == SecurityRejectionReason.OTHER_SECURITY_REJECTION
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_B_attacker_knowing_the_shared_secret_does_not_help_them():
    """Even though the attacker fully knows the resulting shared
    secret (they generated it themselves via a real ML-KEM
    encapsulation), it is still never installed -- confidentiality of
    the KEM output was never the defense here; origin authentication
    (now: outright rejection of this unsupported path) is."""

    bob = _bare_kyber_session("bob")
    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    ciphertext_b64, attacker_known_secret = attacker_km.encapsulate_session_key("bob")
    conversation_id = str(uuid.uuid4())

    bob.handle_session_key({
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "KYBER",
        "encrypted_key": ciphertext_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
    })

    assert bob.key_manager.get_key(conversation_id, epoch=1) != attacker_known_secret
    assert bob.key_manager.has_key(conversation_id, epoch=1) is False


def test_C_no_signature_is_rejected():
    """The branch never checked for a signature before, and does not
    need to now -- confirming a completely bare packet (no signature
    field present at all, not even an empty one) is rejected."""

    bob = _bare_kyber_session("bob")
    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    ciphertext_b64, _secret = attacker_km.encapsulate_session_key("bob")
    conversation_id = str(uuid.uuid4())

    packet = {
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "KYBER",
        "encrypted_key": ciphertext_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
    }
    assert "session_key_signature" not in packet
    assert "group_key_signature" not in packet

    result = bob.handle_session_key(packet)

    assert result == SecurityRejectionReason.OTHER_SECURITY_REJECTION


def test_D_forged_sender_is_rejected():
    bob = _bare_kyber_session("bob")
    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    ciphertext_b64, _secret = attacker_km.encapsulate_session_key("bob")
    conversation_id = str(uuid.uuid4())

    result = bob.handle_session_key({
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "definitely-not-a-real-verified-peer",
        "receiver": "bob",
        "algorithm": "KYBER",
        "encrypted_key": ciphertext_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
    })

    assert result == SecurityRejectionReason.OTHER_SECURITY_REJECTION
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_E_forged_receiver_is_rejected():
    """A packet addressed to someone other than this client is still
    rejected outright (the algorithm/operation combination itself is
    unsupported, independent of the claimed receiver field -- this
    handler never actually branches on ``receiver`` at all)."""

    bob = _bare_kyber_session("bob")
    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    ciphertext_b64, _secret = attacker_km.encapsulate_session_key("bob")
    conversation_id = str(uuid.uuid4())

    result = bob.handle_session_key({
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "someone-else-entirely",
        "algorithm": "KYBER",
        "encrypted_key": ciphertext_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
    })

    assert result == SecurityRejectionReason.OTHER_SECURITY_REJECTION
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_F_malformed_kyber_ciphertext_is_rejected_safely():
    """A garbage, non-KEM-shaped ``encrypted_key`` must not crash the
    receiver -- proven trivially now, since the branch rejects before
    ever reading/parsing that field at all."""

    bob = _bare_kyber_session("bob")
    conversation_id = str(uuid.uuid4())

    result = bob.handle_session_key({
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "KYBER",
        "encrypted_key": "not a valid kyber ciphertext at all !!",
        "conversation_id": conversation_id,
        "epoch": 1,
    })  # must not raise

    assert result == SecurityRejectionReason.OTHER_SECURITY_REJECTION
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None


def test_G_existing_valid_key_survives_a_forged_packet():
    """A legitimately-installed key for this conversation/epoch
    (installed here directly, standing in for whatever authenticated
    path actually produced it -- group_key_distribution in real
    production) must survive an attempted forged KYBER session_key
    delivery for the SAME conversation/epoch untouched."""

    bob = _bare_kyber_session("bob")
    conversation_id = str(uuid.uuid4())
    real_key = os.urandom(32)
    bob.key_manager.store_key(conversation_id, real_key, epoch=1)

    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)
    ciphertext_b64, attacker_known_secret = attacker_km.encapsulate_session_key("bob")

    result = bob.handle_session_key({
        "type": "key_exchange",
        "operation": "session_key",
        "sender": "alice",
        "receiver": "bob",
        "algorithm": "KYBER",
        "encrypted_key": ciphertext_b64,
        "conversation_id": conversation_id,
        "epoch": 1,
    })

    assert result == SecurityRejectionReason.OTHER_SECURITY_REJECTION
    assert bob.key_manager.get_key(conversation_id, epoch=1) == real_key
    assert bob.key_manager.get_key(conversation_id, epoch=1) != attacker_known_secret


def test_H_receiver_remains_operational_after_repeated_forgery_attempts():
    bob = _bare_kyber_session("bob")
    attacker_km = KeyManager()
    attacker_km.add_public_key("bob", bob.key_manager.public_key)

    for _ in range(5):
        ciphertext_b64, _secret = attacker_km.encapsulate_session_key("bob")
        bob.handle_session_key({
            "type": "key_exchange",
            "operation": "session_key",
            "sender": "alice",
            "receiver": "bob",
            "algorithm": "KYBER",
            "encrypted_key": ciphertext_b64,
            "conversation_id": str(uuid.uuid4()),
            "epoch": 1,
        })  # must not raise, any iteration

    # bob's session object is still fully usable afterward.
    conversation_id = str(uuid.uuid4())
    real_key = os.urandom(32)
    bob.key_manager.store_key(conversation_id, real_key, epoch=1)
    assert bob.key_manager.get_key(conversation_id, epoch=1) == real_key
