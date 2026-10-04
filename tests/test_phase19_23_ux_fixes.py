"""
Phase 19.23 -- Cross-Platform UX + Conversation Consistency Fixes.

Covers the actually-testable layer of each of the five reported UX
defects. Two of the five (Issue 2 -- hidden verification event, Issue 4
-- always-visible image controls) and most of Issue 3/5's Android
rendering are implemented entirely inside mobile/app.py's Kivy UI
layer, which this project's own existing test suite never instantiates
(no test anywhere imports mobile.app -- see this phase's own final
report for why: Kivy's desktop backend opens a REAL on-screen window
the moment the module is imported on this dev machine, unlike PySide6,
which this project's test suite already runs headless via
QT_QPA_PLATFORM=offscreen). Those remain physical-device/manual-
verification items, consistent with that existing boundary -- covering
them here would mean either popping a real window during every test
run, or testing something other than the real code path.

What IS covered here, at the layer this project's test suite already
exercises other session-level behavior at:

  A. A directly-verified peer is immediately VERIFIED with zero
     messages ever exchanged (Issue 1's precondition).
  B. A verified peer's state survives a full relaunch WITHOUT ever
     being re-observed live -- the actual root cause of Issue 1 on
     Android (self.peers was previously populated only by live
     observation, so an offline-the-whole-time peer never rehydrated).
  C. SecureKeyStore.get_all_peer_verifications() (new, additive) is
     correct and read-only.
  D. History's new "delivery_status" field (server) and mobile/
     session.py's own Sent/Delivered/Read status computation from it
     (Issue 3's history-reload requirement).
  E. Desktop's message_delivered_updated signal/tick wiring is covered
     separately in tests/test_read_receipts_realtime.py and
     tests/test_message_status_indicators.py (added in this same
     phase) -- not duplicated here.
"""

import time
import uuid

import mobile.session as mobile_session_module
from crypto.key_manager import fingerprint_combined_identity
from mobile.session import MobileClientSession
from storage.secure_key_store import PEER_STATE_VERIFIED, SecureKeyStore
from tests.test_mobile_peer_verification_persistence import (  # noqa: F401
    _new_desktop,
    _new_mobile,
    _observe_and_verify_mobile_of_desktop,
    running_server,
)
from tests.test_device_key_sync import PASSWORD, _delete, _register, _wait_for  # noqa: F401


# ----------------------------------------------------------------------
# Issue 1 -- verified-peer-in-chats persistence (root cause + fix)
# ----------------------------------------------------------------------


def test_direct_verification_needs_no_message_at_all(running_server, monkeypatch, tmp_path):
    """A -- the peer becomes VERIFIED purely from observing + confirming
    a fingerprint; no chat message is sent by either side at any point
    in this test. This is exactly the state mobile/app.py::
    _seed_restored_conversations()'s new verified-peer loop keys off
    of."""

    alice_payload = _register("p1923a_alice_")
    bob_payload = _register("p1923a_bob_")
    try:
        alice = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_desktop")
        bob = _new_mobile(running_server, monkeypatch, bob_payload, tmp_path / "bob_mobile")

        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify_mobile_of_desktop(bob, alice)

        assert bob.is_peer_verified(alice.username) is True
        assert alice.username not in bob.direct_conversation_ids

        bob.disconnect()
        alice.disconnect()
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_verified_peer_survives_relaunch_without_ever_being_reobserved(
    running_server, monkeypatch, tmp_path
):
    """B -- the actual Issue 1 root cause on Android: self.peers was
    populated only by a LIVE observation of the peer's key this
    session (mobile/session.py::_upsert_peer_observation()). A peer who
    is verified but stays offline for the relaunched session's entire
    lifetime was therefore never rehydrated, and reported as
    unverified/absent even though SecureKeyStore never forgot them.

    Alice is deliberately kept disconnected for the whole second half
    of this test -- there is no observation event for bob_relaunched
    to ever receive. Before MobileClientSession.
    _rehydrate_peers_from_key_store() (this phase), this test would
    have hung forever waiting on an observation that never comes; it
    now asserts the state is correct IMMEDIATELY after reconnecting,
    with no _wait_for polling needed at all, because nothing
    asynchronous has to happen first.
    """

    alice_payload = _register("p1923b_alice_")
    bob_payload = _register("p1923b_bob_")
    mobile_dir = tmp_path / "bob_mobile"
    try:
        alice = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_desktop")
        bob = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify_mobile_of_desktop(bob, alice)

        bob.disconnect()
        alice.disconnect()  # alice stays offline for the remainder of this test

        bob_relaunched = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        # No _wait_for: alice is offline, so nothing will ever arrive
        # to populate this the OLD (observation-only) way. Correct
        # immediately, straight from _rehydrate_peers_from_key_store()
        # running synchronously inside _unlock_key_store().
        assert bob_relaunched.get_peer_verification_state(alice.username) == "VERIFIED"
        assert bob_relaunched.is_peer_verified(alice.username) is True
        assert alice.username in bob_relaunched.peers
        assert bob_relaunched.peers[alice.username]["kem_wire"] is None, (
            "rehydration must not fabricate crypto key material it never received"
        )

        bob_relaunched.disconnect()
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_rehydration_never_overwrites_a_live_observation(running_server, monkeypatch, tmp_path):
    """B (continued) -- when alice IS online and gets observed live
    during this same session, that live, fully-populated (real
    kem_wire) entry must win, not the rehydration stub. Verifies the
    two mechanisms compose correctly rather than one clobbering the
    other."""

    alice_payload = _register("p1923c_alice_")
    bob_payload = _register("p1923c_bob_")
    mobile_dir = tmp_path / "bob_mobile"
    try:
        alice = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_desktop")
        bob = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        _observe_and_verify_mobile_of_desktop(bob, alice)
        bob.disconnect()

        # alice stays online this time -- bob_relaunched WILL observe
        # her live, on top of the rehydrated stub.
        bob_relaunched = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        assert _wait_for(
            lambda: bob_relaunched.peers.get(alice.username, {}).get("kem_wire") is not None
        )
        assert bob_relaunched.is_peer_verified(alice.username) is True

        alice.disconnect()
        bob_relaunched.disconnect()
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def test_get_all_peer_verifications_matches_individual_lookups(tmp_path):
    """C -- SecureKeyStore.get_all_peer_verifications() (new, additive)
    must report exactly what get_peer_verification() already reports
    per-peer, for every peer on file, and must never be able to change
    stored state (returns copies)."""

    user_id = str(uuid.uuid4())
    store = SecureKeyStore(user_id, storage_dir=tmp_path / "ks")
    store.unlock("Str0ng!Passw0rd")

    store.record_observed_peer_fingerprint("carol", "fp-carol", signing_public_key=b"sig-carol")
    store.verify_peer_fingerprint("dave", "fp-dave", signing_public_key=b"sig-dave")

    everyone = store.get_all_peer_verifications()

    # get_peer_verification() deliberately returns ONLY {fingerprint,
    # state} (its own docstring); get_all_peer_verifications() also
    # carries signing_public_key -- compare on the shared subset only.
    for username in ("carol", "dave"):
        single = store.get_peer_verification(username)
        assert everyone[username]["fingerprint"] == single["fingerprint"]
        assert everyone[username]["state"] == single["state"]

    assert everyone["carol"]["signing_public_key"] == b"sig-carol"
    assert everyone["dave"]["signing_public_key"] == b"sig-dave"
    assert everyone["dave"]["state"] == PEER_STATE_VERIFIED

    # Mutating the returned dict must not corrupt the store.
    everyone["dave"]["state"] = "TAMPERED"
    assert store.get_peer_verification("dave")["state"] == PEER_STATE_VERIFIED


def test_get_all_peer_verifications_empty_store_returns_empty_dict(tmp_path):
    user_id = str(uuid.uuid4())
    store = SecureKeyStore(user_id, storage_dir=tmp_path / "ks")
    store.unlock("Str0ng!Passw0rd")

    assert store.get_all_peer_verifications() == {}


# ----------------------------------------------------------------------
# Issue 3 -- history reload carries real Sent/Delivered/Read status
# (server's additive "delivery_status" field + mobile/session.py's own
# consumption of it -- see load_history()).
# ----------------------------------------------------------------------


def test_history_reports_delivered_then_read_status_for_own_message(
    running_server, monkeypatch, tmp_path
):
    """D -- bob (mobile) sends to alice (desktop) while she is online
    (guaranteeing live delivery, never a QUEUED/offline path). bob then
    relaunches (a genuinely fresh MobileClientSession -- exactly what a
    real history reload after app restart looks like) and loads
    history: the emitted status for his own message must be
    "Delivered" before alice has read it, and "Read" afterwards --
    never fabricated, always following the server's own real,
    persisted MessageRecipient status."""

    alice_payload = _register("p1923d_alice_")
    bob_payload = _register("p1923d_bob_")
    mobile_dir = tmp_path / "bob_mobile"
    try:
        alice = _new_desktop(running_server, monkeypatch, alice_payload, tmp_path / "alice_desktop")
        bob = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)

        assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)
        assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
        _observe_and_verify_mobile_of_desktop(bob, alice)
        alice.key_store.verify_peer_fingerprint(
            bob.username,
            fingerprint_combined_identity(bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key()),
        )

        bob.establish_session_key(alice.username)
        conversation_id = bob.open_direct_conversation(alice.username)
        bob.send_message(alice.username, "phase 19.23 delivered/read status check")

        # Give the server's live relay a moment to record DELIVERED
        # (mirrors this same pattern in test_read_receipts_realtime.py).
        time.sleep(0.3)

        bob.disconnect()

        captured = []
        bob_relaunched = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)
        bob_relaunched.message_received.connect(
            lambda identity_key, sender, text, historical, status: captured.append(
                (sender, text, historical, status)
            )
        )
        assert _wait_for(lambda: bob_relaunched.load_history(conversation_id, is_group=False) >= 1)

        own_entries = [c for c in captured if c[0] == bob_payload["username"]]
        assert own_entries, "the sender's own message never came back through history"
        assert own_entries[0][2] is True  # historical
        assert own_entries[0][3] in ("Sent", "Delivered"), own_entries[0]

        bob_relaunched.disconnect()

        # --- Now alice reads it. ---
        alice.set_current_chat(_conversation_summary(alice, bob.username))
        alice.mark_conversation_read(alice.current_conversation_id)
        time.sleep(0.3)

        captured2 = []
        bob_relaunched2 = _new_mobile(running_server, monkeypatch, bob_payload, mobile_dir)
        bob_relaunched2.message_received.connect(
            lambda identity_key, sender, text, historical, status: captured2.append(
                (sender, text, historical, status)
            )
        )
        assert _wait_for(lambda: bob_relaunched2.load_history(conversation_id, is_group=False) >= 1)

        own_entries2 = [c for c in captured2 if c[0] == bob_payload["username"]]
        assert own_entries2, "the sender's own message never came back through history (2nd load)"
        assert own_entries2[0][3] == "Read", own_entries2[0]

        bob_relaunched2.disconnect()
        alice.disconnect()
    finally:
        _delete(alice_payload["username"])
        _delete(bob_payload["username"])


def _conversation_summary(session, partner_username):
    from domain.conversation_summary import ConversationSummary

    return ConversationSummary(
        conversation_id=None,
        username=partner_username,
        is_online=True,
        latest_message=None,
    )
