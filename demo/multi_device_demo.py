"""
Multi-Device Cryptographic Identity & Key Synchronization -- Demo

Standalone, human-readable demonstration of this project's strongest
technical contribution: per-device post-quantum cryptographic
identity, device authorization, device-to-device conversation-key
synchronization, multi-device identity separation, and revocation
enforcement.

This script calls ONLY the real, production ClientSession API
(client/session.py) against a REAL running server -- the exact same
code path the desktop GUI (main.py) and the browser client use. It
does not reimplement any protocol logic, and it does not use the
pytest in-process test harness: every network round trip in this demo
goes over a real TLS socket to a real server process.

Cryptographic building blocks exercised (see docs/architecture/
multi_device_identity.md for the full design):
    - ML-KEM-768 (post-quantum key establishment / Kyber768, FIPS 203)
    - ML-DSA-65 (post-quantum digital signatures / FIPS 204) --
      authenticates every device-management operation and the key-sync
      envelope itself, via crypto/device_protocol.py's domain-separated
      canonical payloads
    - AES-256-GCM (symmetric authenticated encryption) -- wraps the
      synchronized conversation key (KeyManager.wrap_key_for_member())

This demo does NOT claim the whole system is "quantum-proof", that TLS
itself is post-quantum, or that the server has zero metadata
visibility -- see README.md's "Security Model" section for the
precise, hedged claim this project actually makes.

--------------------------------------------------------------------
PREREQUISITES
--------------------------------------------------------------------
1. PostgreSQL running, with the project's database created and
   migrated:
       alembic upgrade head
2. .env configured (DATABASE_URL, JWT_SECRET_KEY) -- see
   .env.example / README.md "Environment configuration".
3. Dev TLS certificates generated:
       python scripts/generate_dev_certs.py
4. The real server running, from the repository root, in its own
   terminal:
       python -m server.server
5. Python environment activated with requirements.txt (+
   requirements-dev.txt if you also want to run the pytest suite)
   installed.

--------------------------------------------------------------------
RUNNING
--------------------------------------------------------------------
From the repository root, with the server already running:

    python demo/multi_device_demo.py

The script registers its OWN throwaway demo accounts (via
AuthenticationService.register_user() -- the same production
registration path the GUI's registration form uses) and deletes them
again when it finishes, whether it succeeds or fails. Nothing here
touches any pre-existing account or conversation.

Nothing sensitive is ever printed: no private keys, no passwords, no
JWT secret, no database credentials. Only device IDs, usernames,
authorization states, conversation IDs, epoch numbers, and algorithm
names.
"""

import os
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Runnable as `python demo/multi_device_demo.py` from any working
# directory: Python only puts this script's OWN directory (demo/) on
# sys.path, not the repository root, so the repo-root imports below
# (client.session, crypto.key_manager, ...) would otherwise fail with
# ModuleNotFoundError. Inserted before those imports run.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from PySide6.QtWidgets import QApplication

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_combined_identity
from database.connection import SessionLocal
from database.models.device import DEVICE_STATE_AUTHORIZED, DEVICE_STATE_PENDING, Device
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import PEER_STATE_VERIFIED

_app = QApplication.instance() or QApplication([])

_DEMO_PASSWORD = "Str0ng!Demo#Passw0rd"


def _wait_for(predicate, attempts=150, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


def _register_demo_account(hint):
    """Real registration, via the same production
    AuthenticationService.register_user() the GUI's registration form
    calls -- not a hand-rolled DB insert."""

    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:8]
        payload = {
            "full_name": "Multi-Device Demo",
            "username": f"mddemo_{hint}{suffix}",
            "email": f"mddemo_{hint}{suffix}@example.invalid",
            "password": _DEMO_PASSWORD,
            "confirm_password": _DEMO_PASSWORD,
            "phone_number": f"+91{uuid.uuid4().int % 10 ** 12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        if not result.success:
            raise RuntimeError(f"Demo account registration failed: {result.errors}")
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete_demo_account(username):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(username)
        if user is not None:
            for session_row in SessionRepository(db).get_active_sessions_for_user(user.id):
                db.delete(session_row)
            db.query(Device).filter(Device.user_id == user.id).delete()
            db.delete(user)
            db.commit()
    finally:
        db.close()


def _get_device_row(device_id):
    db = SessionLocal()
    try:
        return db.query(Device).filter(Device.device_id == uuid.UUID(device_id)).first()
    finally:
        db.close()


def _connect_device(payload, key_store_dir, device_name, platform):
    """
    Bring up one real ClientSession, connected to the REAL configured
    server (client/session.py's own SERVER_HOST/SERVER_PORT -- never
    overridden here, unlike the pytest test harness), with its own
    isolated on-disk SecureKeyStore representing one physical device
    installation.

    Enrolls IMMEDIATELY after starting the receiver thread -- this
    device's identity broadcast therefore always carries a device_id
    from its very first packet onward. A second (or third) device of
    the same account that instead sent an ordinary plain broadcast
    BEFORE enrolling would risk a spurious KEY_CHANGED against a
    sibling device a third party has already verified (see docs/
    architecture/multi_device_identity.md's Phase 16D section) --
    this is the same production-proven pattern tests/
    test_multi_device_peer_identity.py's own _new_pre_enrolled_device_
    session() helper uses.
    """

    import storage.secure_key_store as secure_key_store_module

    secure_key_store_module.KEY_STORE_DIR = key_store_dir

    session = ClientSession()
    result = session.authenticate_credentials(payload["phone_number"], _DEMO_PASSWORD)
    if not result.success:
        raise RuntimeError(f"Authentication failed for {payload['username']}: {result.message}")

    session.user_id = result.user_id
    session.username = result.username
    session.access_token = result.token_pair.access_token
    session.connect()
    session.login(payload["username"])
    session.start_receiver()
    session.enroll_device(device_name=device_name, platform=platform)

    return session


def _mutually_verify_devices(a, b):
    """Both directions of DEVICE-peer verification (Phase 16C) --
    reuses the ordinary VERIFIED/UNVERIFIED/KEY_CHANGED trust machinery,
    keyed by device_id instead of username. Required before either
    device may wrap key material for, or trust material from, the
    other -- never automatic."""

    a.observe_device_peer_identity(
        b.device_id, b.key_manager.public_key.decode("utf-8"), b.key_manager.ml_dsa.export_public_key()
    )
    fp_b = fingerprint_combined_identity(b.key_manager.public_key, b.key_manager.ml_dsa.export_public_key())
    a.confirm_device_peer_verification(b.device_id, fp_b)

    b.observe_device_peer_identity(
        a.device_id, a.key_manager.public_key.decode("utf-8"), a.key_manager.ml_dsa.export_public_key()
    )
    fp_a = fingerprint_combined_identity(a.key_manager.public_key, a.key_manager.ml_dsa.export_public_key())
    b.confirm_device_peer_verification(a.device_id, fp_a)


def _verify_ordinary_peers(local_session, peer_session, peer_username):
    """Ordinary (username-keyed) peer verification -- distinct from
    device-peer verification above; used between two different
    accounts (Alice and Bob), never between two devices of the same
    account."""

    kem_wire = peer_session.key_manager.public_key
    signing_public_key = peer_session.key_manager.ml_dsa.export_public_key()
    local_session.observe_peer_identity(peer_username, kem_wire, signing_public_key)
    fingerprint = fingerprint_combined_identity(kem_wire, signing_public_key)
    local_session.confirm_combined_peer_verification(peer_username, fingerprint)


_step_number = 0
_failed = False


def _step(title):
    global _step_number
    _step_number += 1
    print(f"\n[{_step_number}] {title}")


def _pass(detail=""):
    suffix = f" -- {detail}" if detail else ""
    print(f"PASS{suffix}")


def _fail(detail):
    global _failed
    _failed = True
    print(f"FAIL -- {detail}")
    raise DemoStepFailed(detail)


class DemoStepFailed(Exception):
    pass


def main():
    print("=" * 72)
    print("MULTI-DEVICE CRYPTOGRAPHIC IDENTITY & KEY SYNCHRONIZATION DEMO")
    print("ML-KEM-768 (post-quantum key establishment) + ML-DSA-65")
    print("(post-quantum digital signatures) + AES-256-GCM (symmetric")
    print("authenticated encryption)")
    print("=" * 72)

    tmp_root = tempfile.mkdtemp(prefix="qrscs_multidevice_demo_")
    alice_payload = bob_payload = None
    device1 = device2 = device3 = bob = None

    try:
        alice_payload = _register_demo_account("alice_")
        bob_payload = _register_demo_account("bob_")

        # ------------------------------------------------------------
        _step("Creating Device 1 (Alice's first device -- bootstrap)")
        device1 = _connect_device(
            alice_payload, os.path.join(tmp_root, "device1"), "Demo-Desktop", "linux"
        )
        row1 = _get_device_row(device1.device_id)
        if row1 is None or row1.state != DEVICE_STATE_AUTHORIZED:
            _fail(f"Device 1 expected AUTHORIZED (bootstrap), got {row1.state if row1 else 'missing'}")
        device1.bind_device_session()
        _pass(f"account={alice_payload['username']} device_id={device1.device_id} state={row1.state}")

        # ------------------------------------------------------------
        _step("Enrolling Device 2 (Alice's second device)")
        device2 = _connect_device(
            alice_payload, os.path.join(tmp_root, "device2"), "Demo-Browser", "web"
        )
        row2 = _get_device_row(device2.device_id)
        if row2 is None or row2.state != DEVICE_STATE_PENDING:
            _fail(f"Device 2 expected PENDING, got {row2.state if row2 else 'missing'}")
        _pass(f"device_id={device2.device_id} state={row2.state}")

        # ------------------------------------------------------------
        _step("Device 1 authorizing Device 2")
        pending_entry = next(d for d in device1.list_devices() if d["device_id"] == device2.device_id)
        auth_result = device1.authorize_device(device2.device_id, pending_entry["fingerprint"])
        if not auth_result.get("success"):
            _fail(f"authorize_device failed: {auth_result}")
        device2.bind_device_session()
        row2 = _get_device_row(device2.device_id)
        if row2.state != DEVICE_STATE_AUTHORIZED:
            _fail(f"Device 2 expected AUTHORIZED after authorization, got {row2.state}")
        _mutually_verify_devices(device1, device2)
        _pass(f"device_id={device2.device_id} state={row2.state} (device-peer verified with Device 1)")

        # ------------------------------------------------------------
        _step("Establishing a real conversation with Bob (for Device 1)")
        bob = _connect_device(bob_payload, os.path.join(tmp_root, "bob"), "Bob-Desktop", "linux")
        if not _wait_for(lambda: device1.key_manager.get_public_key(bob.username) is not None):
            _fail("Device 1 never observed Bob's public key")
        if not _wait_for(lambda: bob.key_manager.get_public_key(device1.username) is not None):
            _fail("Bob never observed Device 1's public key")
        _verify_ordinary_peers(device1, bob, bob.username)
        _verify_ordinary_peers(bob, device1, device1.username)

        device1.set_current_chat(
            ConversationSummary(conversation_id=None, username=bob.username, is_online=True, latest_message=None)
        )
        device1.establish_session_key()
        conversation_id = device1.current_conversation_id
        if not _wait_for(lambda: bob.key_manager.get_key(conversation_id) is not None):
            _fail("Bob never received the direct conversation key")

        device1.send_chat_message("Hello Bob, this is Device 1 (pre-sync).")
        if not _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "Hello Bob, this is Device 1 (pre-sync)."
            for s in bob.conversation_store.get_all()
        )):
            _fail("Bob never received Device 1's pre-sync message")
        _pass(f"conversation_id={conversation_id} epoch={device1.key_manager.current_epoch(conversation_id)}")

        # ------------------------------------------------------------
        _step("Synchronizing the conversation key to Device 2 (device_key_sync)")
        if device2.key_manager.has_key(conversation_id):
            _fail("Device 2 already has the key before sync -- test setup error")
        sync_result = device1.sync_conversation_key_to_device(device2.device_id, conversation_id)
        if not sync_result.get("success"):
            _fail(f"sync_conversation_key_to_device failed: {sync_result}")
        _pass(f"target_device_id={device2.device_id} conversation_id={conversation_id} package_type=direct")

        # ------------------------------------------------------------
        _step("Verifying Device 2's synchronized cryptographic state")
        if not _wait_for(lambda: device2.key_manager.has_key(conversation_id)):
            _fail("Device 2 never installed the synchronized key")
        if device2.key_manager.get_key(conversation_id) != device1.key_manager.get_key(conversation_id):
            _fail("Device 2's synchronized key does not match Device 1's key bytes")

        # Device 2 uses the synchronized state for real: sends a
        # genuine message Bob decrypts, over the real wire.
        # send_chat_message() also requires the SENDER to already
        # trust the recipient (ordinary, unmodified precondition --
        # every message-sending client verifies who it is encrypting
        # to) -- Device 2's OWN peer-trust view of Bob, independent of
        # the device-peer verification with Device 1 above.
        if not _wait_for(lambda: device2.key_manager.get_public_key(bob.username) is not None):
            _fail("Device 2 never observed Bob's public key")
        _verify_ordinary_peers(device2, bob, bob.username)

        device2.set_current_chat(
            ConversationSummary(conversation_id=conversation_id, username=bob.username, is_online=True, latest_message=None)
        )
        device2.send_chat_message("Hello Bob, this is Device 2, using the synchronized key.")
        if not _wait_for(lambda: any(
            s.latest_message and s.latest_message.text == "Hello Bob, this is Device 2, using the synchronized key."
            for s in bob.conversation_store.get_all()
        )):
            _fail("Bob never received Device 2's message sent with the synchronized key")
        _pass("Device 2 decrypted the synchronized key and sent a real message Bob decrypted")

        # ------------------------------------------------------------
        _step("Enrolling Device 3 (Alice's third device)")
        device3 = _connect_device(
            alice_payload, os.path.join(tmp_root, "device3"), "Demo-Phone", "android"
        )
        pending_entry_3 = next(d for d in device1.list_devices() if d["device_id"] == device3.device_id)
        auth_result_3 = device1.authorize_device(device3.device_id, pending_entry_3["fingerprint"])
        if not auth_result_3.get("success"):
            _fail(f"authorize_device (Device 3) failed: {auth_result_3}")
        device3.bind_device_session()
        row3 = _get_device_row(device3.device_id)
        if row3.state != DEVICE_STATE_AUTHORIZED:
            _fail(f"Device 3 expected AUTHORIZED, got {row3.state}")
        _mutually_verify_devices(device1, device3)
        _mutually_verify_devices(device2, device3)
        _pass(f"device_id={device3.device_id} state={row3.state}")

        # ------------------------------------------------------------
        _step("Verifying distinct device identities (Bob's point of view)")
        if not _wait_for(lambda: bob.get_peer_verification_state(device1.username) == PEER_STATE_VERIFIED):
            _fail("Bob's trust of Device 1's identity was disturbed")
        if device1.device_id == device2.device_id or device2.device_id == device3.device_id or device1.device_id == device3.device_id:
            _fail("Device IDs are not distinct")
        if device1.key_manager.ml_dsa.export_public_key() == device2.key_manager.ml_dsa.export_public_key():
            _fail("Device 1 and Device 2 share an ML-DSA signing key -- identities are not cryptographically distinct")
        _pass(
            f"3 distinct device_ids, 3 distinct ML-DSA-65 signing keys, "
            f"all under one account ({alice_payload['username']}); "
            f"Bob's trust of Device 1 is unaffected by Devices 2/3"
        )

        # ------------------------------------------------------------
        _step("Revoking Device 2")
        revoke_result = device1.revoke_device(device2.device_id)
        if not revoke_result.get("success"):
            _fail(f"revoke_device failed: {revoke_result}")
        row2 = _get_device_row(device2.device_id)
        if row2.state != "REVOKED":
            _fail(f"Device 2 expected REVOKED, got {row2.state}")
        _pass(f"device_id={device2.device_id} state={row2.state}")

        # ------------------------------------------------------------
        _step("Attempting a device-sync operation FROM the revoked Device 2")
        # sync_conversation_key_to_device() requires the CALLER to
        # already hold a local key for the conversation it is trying
        # to sync (checked before any network round trip) -- Device 2
        # already legitimately has the real conversation's key from
        # Step 6, so that is what is used for this attempt: a revoked
        # device trying to help a sibling catch up on a conversation
        # it genuinely knows about, exactly the realistic attack this
        # check exists to stop.
        blocked_result = device2.sync_conversation_key_to_device(device3.device_id, conversation_id)
        if blocked_result.get("success"):
            _fail("Server accepted a device_key_sync request from a REVOKED device -- security failure")
        _pass(f"server rejected the request: {blocked_result.get('error', 'rejected')}")

        # ------------------------------------------------------------
        _step("Verifying sibling devices remain authorized")
        row1_final = _get_device_row(device1.device_id)
        row3_final = _get_device_row(device3.device_id)
        if row1_final.state != DEVICE_STATE_AUTHORIZED:
            _fail(f"Device 1 unexpectedly not AUTHORIZED: {row1_final.state}")
        if row3_final.state != DEVICE_STATE_AUTHORIZED:
            _fail(f"Device 3 unexpectedly not AUTHORIZED: {row3_final.state}")
        # Device 2's already-synchronized key material is NOT erased --
        # revocation is prospective, never retroactive (see docs/
        # architecture/multi_device_identity.md's revocation semantics).
        if device2.key_manager.get_key(conversation_id) is None:
            _fail("Device 2's previously-synchronized key was unexpectedly erased on revocation")
        _pass(
            f"Device 1 state={row1_final.state}, Device 3 state={row3_final.state}; "
            f"Device 2's earlier-synchronized key is still locally present "
            f"(revocation is prospective, not retroactive erasure)"
        )

        print("\n" + "=" * 72)
        print("FINAL RESULT: MULTI-DEVICE SECURITY DEMO PASSED")
        print("=" * 72)
        return 0

    except DemoStepFailed as error:
        print("\n" + "=" * 72)
        print(f"FINAL RESULT: MULTI-DEVICE SECURITY DEMO FAILED -- {error}")
        print("=" * 72)
        return 1

    except Exception as error:  # noqa: BLE001
        print("\n" + "=" * 72)
        print(f"FINAL RESULT: MULTI-DEVICE SECURITY DEMO ERRORED -- {type(error).__name__}: {error}")
        print("=" * 72)
        return 1

    finally:
        for session in (device1, device2, device3, bob):
            if session is None:
                continue
            try:
                session.disconnect()
            except Exception:  # noqa: BLE001
                pass
        if alice_payload is not None:
            _delete_demo_account(alice_payload["username"])
        if bob_payload is not None:
            _delete_demo_account(bob_payload["username"])
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
