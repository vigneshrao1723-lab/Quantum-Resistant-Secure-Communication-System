"""
Trust-Boundary Audit: origin authentication of key-distribution packets.

HISTORY: this file was originally an AUDIT-DEMONSTRATION file proving
that ClientSession.handle_group_key_distribution() -- the single
receiver-side handler for both direct-first-contact and group key
material -- performed NO check of any kind on a packet's claimed
sender before unwrapping and installing key material via
KeyManager.store_key(). Every test below originally PASSED, and that
was itself the finding: a malicious server, possessing nothing but a
victim's already-publicly-broadcast ML-KEM public key, could fabricate
a group_key_distribution packet from whole cloth and have it installed
and later relied upon as if it had genuinely come from the claimed
sender.

Phase 13 (Group-Key-Distribution ML-DSA Origin Authentication) closed
this gap -- see client/session.py::handle_group_key_distribution()'s
own docstring for the full fix (an ML-DSA signature over crypto/
group_key_protocol.py's canonical envelope, verified against the
receiver's own already-VERIFIED peer-identity state, BEFORE the key is
ever unwrapped or installed). This file now proves the OPPOSITE of its
original finding: the exact same attacks, unchanged, are rejected.

Every test below still constructs its "malicious server" packet BY
HAND, never through any real ClientSession acting as sender, and never
using any private key belonging to the claimed sender -- the same
threat model as before: an attacker who controls the server's
application-level behavior (can fabricate/relay any packet to any
connected client) but does NOT possess any legitimate endpoint's
private ML-KEM or ML-DSA identity key, does NOT possess any account
password, and does NOT have access to any real plaintext or session
key.

Run with:
    pytest tests/test_key_distribution_origin_authentication.py -v
"""

import base64
import os
import uuid

import pytest

from client.session import ClientSession
from crypto.group_key_protocol import sign_group_key_payload
from crypto.key_manager import KeyManager, fingerprint_combined_identity
from storage.secure_key_store import SecureKeyStore

PASSWORD = "Str0ng!Passw0rd"


def _bare_session(username):
    """A real, unconnected ClientSession -- no server, no socket --
    with a fixed username, matching the pattern already established
    in tests/test_rsa_key_exchange_integration.py's handle_session_key
    hardening tests for exercising a receiver-side handler directly."""

    session = ClientSession()
    session.username = username
    return session


def _bare_session_with_store(username, tmp_path):
    """A real, unconnected ClientSession with a real, unlocked,
    isolated SecureKeyStore attached -- required now that accepting a
    group_key_distribution packet requires this receiver to have an
    explicitly VERIFIED sender identity on file (Phase 13), which
    needs a real key store to persist into."""

    session = _bare_session(username)

    store = SecureKeyStore(f"{username}-user-id", storage_dir=tmp_path / username)
    store.unlock(PASSWORD)
    session.key_store = store

    return session


def test_attack_a_forged_packet_does_not_install_a_first_ever_key_with_no_sender_material(
    tmp_path,
):
    """ATTACK A: a completely new conversation_id that Bob has never
    seen before. The "attacker" possesses only Bob's real (publicly
    broadcast) Kyber public key -- nothing belonging to Alice, nothing
    belonging to Bob beyond that public key, and no password for
    either account. A group_key_distribution packet is fabricated
    entirely by hand, exactly as a malicious server could construct
    one directly (bypassing every one of its own authorization checks,
    since those checks are server-side code a malicious server
    operator is not obligated to run).

    Bob has never observed "alice" at all -- no ML-DSA identity to
    verify a signature against even if one were present, and this
    forged packet carries no group_key_signature at all (the attacker
    has no legitimate private key to produce one with). Rejected on
    two independent grounds: no VERIFIED sender, and no valid
    signature."""

    bob = _bare_session_with_store("bob", tmp_path)

    # Bob's real Kyber keypair (would be his real, persisted identity
    # in production) -- the attacker knows only its PUBLIC half,
    # exactly as broadcast to every connected client by design.
    bobs_public_key = bob.key_manager.public_key

    # The "attacker" has no keypair belonging to Alice or Bob at all.
    # A throwaway KeyManager is the only cryptographic material the
    # attacker uses to build a plausible-looking wire packet.
    attacker_key_manager = KeyManager()
    attacker_key_manager.add_public_key("bob", bobs_public_key)

    forged_group_key = os.urandom(32)  # the attacker's own choice
    encapsulation, wrapped_key = attacker_key_manager.wrap_key_for_member(
        "bob", forged_group_key
    )

    never_before_seen_conversation_id = str(uuid.uuid4())

    forged_packet = {
        "type": "group_key_distribution",
        "sender": "alice",  # claimed -- never actually alice
        "recipient": "bob",
        "conversation_id": never_before_seen_conversation_id,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": 1,
        # Deliberately no "group_key_signature" -- the attacker has no
        # legitimate private key to produce one with.
    }

    assert bob.key_manager.get_key(never_before_seen_conversation_id) is None

    bob.handle_group_key_distribution(forged_packet)

    installed_key = bob.key_manager.get_key(
        never_before_seen_conversation_id, epoch=1
    )

    # THE FIX PROVEN: no key was installed -- no cryptographic material
    # from Alice (or any legitimate party) exists in this packet, Bob
    # never had "alice" VERIFIED, and there is no valid signature.
    assert installed_key is None


def test_attack_d_forged_packet_no_longer_wins_the_race_against_the_real_key(tmp_path):
    """ATTACK D: originally, if a forged packet arrived BEFORE the
    real Alice's own first-contact key-establishment packet for the
    identical conversation_id/epoch, KeyManager.store_key()'s no-
    overwrite guarantee protected the ATTACKER's key, not the real
    one -- a pure availability/integrity attack using only the
    victim's already-public public key.

    Now: the forged packet (unsigned, and even if Bob had never
    verified anyone, un-verifiable) is rejected outright and never
    reaches store_key() at all -- there is no attacker key for the
    real one to lose a race against. Proven by delivering the real key
    SECOND, exactly as before, and confirming it is the one that ends
    up installed.
    """

    bob = _bare_session_with_store("bob", tmp_path)
    alice = _bare_session("alice")

    conversation_id = str(uuid.uuid4())

    # --- The forged packet arrives first (the attacker controls
    # relay timing, per the stated threat model). ---
    attacker_key_manager = KeyManager()
    attacker_key_manager.add_public_key("bob", bob.key_manager.public_key)

    forged_group_key = os.urandom(32)
    encapsulation, wrapped_key = attacker_key_manager.wrap_key_for_member(
        "bob", forged_group_key
    )

    bob.handle_group_key_distribution({
        "type": "group_key_distribution",
        "sender": "alice",
        "recipient": "bob",
        "conversation_id": conversation_id,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": 1,
    })

    # THE FIX PROVEN, part 1: the forged packet, arriving first, was
    # rejected outright -- nothing was installed for it to "win" with.
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None

    # --- The REAL Alice's genuine first-contact key arrives second,
    # exactly as establish_session_key() would really send it: a
    # real, independently generated session key, really wrapped
    # against Bob's real public key, using Alice's real KeyManager,
    # and now genuinely signed -- with Bob having explicitly VERIFIED
    # Alice's real combined identity first, exactly as the real
    # production flow requires (establish_session_key()'s own
    # pre-existing gate already requires the SENDER to have verified
    # the recipient; Phase 13 adds the symmetric requirement here). ---
    alice.key_manager.add_public_key("bob", bob.key_manager.public_key)

    bob.observe_peer_identity(
        "alice", alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
    )
    alice_fingerprint = fingerprint_combined_identity(
        alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
    )
    bob.confirm_combined_peer_verification("alice", alice_fingerprint)

    real_session_key = os.urandom(32)
    real_encapsulation, real_wrapped_key = alice.key_manager.wrap_key_for_member(
        "bob", real_session_key
    )

    real_signature = sign_group_key_payload(
        alice.key_manager.ml_dsa, "alice", conversation_id, "bob",
        real_encapsulation, real_wrapped_key, 1,
    )

    bob.handle_group_key_distribution({
        "type": "group_key_distribution",
        "sender": "alice",
        "recipient": "bob",
        "conversation_id": conversation_id,
        "encapsulation": real_encapsulation,
        "wrapped_key": real_wrapped_key,
        "epoch": 1,
        "group_key_signature": base64.b64encode(real_signature).decode("ascii"),
    })

    # THE FIX PROVEN, part 2: Bob now holds Alice's REAL key -- the
    # forged one never occupied that slot to begin with.
    assert bob.key_manager.get_key(conversation_id, epoch=1) == real_session_key
    assert bob.key_manager.get_key(conversation_id, epoch=1) != forged_group_key


def test_receiver_now_performs_a_sender_verification_check(tmp_path):
    """Root-cause check, directly against the ORIGINAL docstring's own
    claim (now false): handle_group_key_distribution() now calls
    _peer_key_is_verified() on the packet's sender BEFORE anything
    else, and requires Bob to have both explicitly observed AND
    VERIFIED a public identity for "alice" before any key material is
    ever unwrapped or installed."""

    bob = _bare_session_with_store("bob", tmp_path)

    # Bob has never heard of "alice" in any capacity -- no public key
    # ever observed, no verification state of any kind.
    assert bob.key_manager.get_public_key("alice") is None
    assert bob.get_peer_verification_state("alice") is None

    attacker_key_manager = KeyManager()
    attacker_key_manager.add_public_key("bob", bob.key_manager.public_key)

    forged_group_key = os.urandom(32)
    encapsulation, wrapped_key = attacker_key_manager.wrap_key_for_member(
        "bob", forged_group_key
    )

    conversation_id = str(uuid.uuid4())

    bob.handle_group_key_distribution({
        "type": "group_key_distribution",
        "sender": "alice",
        "recipient": "bob",
        "conversation_id": conversation_id,
        "encapsulation": encapsulation,
        "wrapped_key": wrapped_key,
        "epoch": 1,
    })

    # THE FIX PROVEN: rejected -- "alice" being completely unverified
    # (indeed, entirely unknown) is now exactly why this fails.
    assert bob.key_manager.get_key(conversation_id, epoch=1) is None
    assert bob.get_peer_verification_state("alice") is None
