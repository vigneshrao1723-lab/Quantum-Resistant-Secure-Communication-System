"""
Server-Untrusted Identity Verification, Stage 2.5 -- persistent local
ML-KEM-768 keypair.

Stage 1/2 made a peer's fingerprint stability across logins into a
real security property: a VERIFIED fingerprint is only meaningful if
the underlying key it was verified against stays the same. But
KeyManager.__init__() generates a brand-new Kyber keypair every single
time it is constructed -- every login, every application restart --
so without this stage, a peer's *legitimate* relogin and a *malicious*
server substitution of a different key are the same event from the
other side's point of view: both are "this VERIFIED peer's key just
changed." That would make Stage 2's already-proven KEY_CHANGED
detection either constantly noisy (unusable) or, worse, something
users learn to click through (ignored) -- neither is a security
property.

This stage does not change what gets verified, how, or by whom (that
remains Stage 3's job, entirely out of scope here). It only makes this
LOCAL user's own Kyber keypair -- both halves -- persist across logins
in the existing encrypted, password-derived SecureKeyStore, exactly
the same file and mechanism already protecting conversation keys
(BUG 1) and peer verification state (Stage 1). Every method under test
here reuses that infrastructure; nothing introduces a new encryption
primitive, a new storage location, a new wire packet, or a new
protocol field.

What this stage explicitly does NOT solve: first-contact trust. A
peer's key received before any explicit verification remains
UNVERIFIED and is not protected by any of this -- see the project's
Stage-3 design report.

Run with:
    pytest tests/test_own_kyber_keypair_persistence.py -v
"""

import base64
import json
import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
import crypto.key_manager as key_manager_module
import crypto.kyber as kyber_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from crypto.kyber import (
    ML_KEM_768_PRIVATE_KEY_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
)
from crypto.key_manager import KeyManager, fingerprint_public_key
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from kyber_py.ml_kem import ML_KEM_768
from storage.secure_key_store import KeyStoreError, KeyStoreLocked, SecureKeyStore
from tests.tls_test_support import start_test_server
from utils.protocol import create_public_key_packet

_app = QApplication.instance() or QApplication([])

PASSWORD = "Str0ng!Passw0rd"


# ----------------------------------------------------------------------
# Unit-level: KeyManager + SecureKeyStore directly, no server needed.
# ----------------------------------------------------------------------


@pytest.fixture()
def store_dir(tmp_path):
    return tmp_path / "keystore"


def _store(store_dir, user_id="user-1"):
    return SecureKeyStore(user_id, storage_dir=store_dir)


def test_first_creation_generates_and_persists_a_keypair(store_dir):
    """TEST A: no persisted own keypair -> initialize KeyManager and
    load -> a keypair is generated and persisted."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    assert store.get_own_kyber_keypair() is None

    manager = KeyManager()
    manager.load_or_create_kyber_keypair(store)

    persisted = store.get_own_kyber_keypair()

    assert persisted is not None
    assert persisted == (
        manager.kyber.encapsulation_key,
        manager.kyber.decapsulation_key,
    )

    # Also durable across a fresh unlock of the same file, not just
    # visible on the same in-memory store object.
    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)
    assert reopened.get_own_kyber_keypair() == persisted


def test_reload_yields_an_identical_keypair(store_dir):
    """TEST B: persist K1 -> create a new KeyManager -> load K1.
    Public key identical, private key identical, byte-for-byte."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    first = KeyManager()
    first.load_or_create_kyber_keypair(store)

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    second = KeyManager()
    second.load_or_create_kyber_keypair(reopened)

    assert second.kyber.encapsulation_key == first.kyber.encapsulation_key
    assert second.kyber.decapsulation_key == first.kyber.decapsulation_key
    assert second.public_key == first.public_key


def test_fingerprint_is_identical_before_and_after_a_simulated_restart(store_dir):
    """TEST C: fingerprint(K1_before) == fingerprint(K1_after_restart).
    The actual property Stage 2's VERIFIED state depends on."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    before = KeyManager()
    before.load_or_create_kyber_keypair(store)
    fingerprint_before = fingerprint_public_key(before.public_key)

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    after = KeyManager()
    after.load_or_create_kyber_keypair(reopened)
    fingerprint_after = fingerprint_public_key(after.public_key)

    assert fingerprint_after == fingerprint_before


def test_load_does_not_regenerate_when_a_keypair_is_already_persisted(
    store_dir, monkeypatch
):
    """TEST D: persist K1 -> initialize KeyManager again -> keygen()
    is NOT called again.

    Scoped precisely to the LOAD step itself, not to KeyManager.
    __init__() as a whole: __init__() necessarily always calls
    KyberKEM.generate_keys() once, unconditionally, because it has no
    way to know whether a persisted keypair exists (ClientSession
    constructs KeyManager before login, before any password-derived
    SecureKeyStore can be unlocked -- see load_or_create_kyber_keypair()'s
    docstring). What load_or_create_kyber_keypair() guarantees, and
    what this test proves, is that its OWN call to that method -- the
    one deciding whether to keep, discard, or persist a keypair -- never
    triggers a second generation once persisted material already
    exists. The spy is attached only around that call, after the
    unavoidable __init__()-time generation has already happened, so it
    cannot be satisfied by accident.
    """

    store = _store(store_dir)
    store.unlock(PASSWORD)

    first = KeyManager()
    first.load_or_create_kyber_keypair(store)  # persists K1

    second = KeyManager()  # __init__ always generates once -- see docstring above

    calls = []
    original_generate_keys = kyber_module.KyberKEM.generate_keys

    def counting_generate_keys(self):
        calls.append(1)
        return original_generate_keys(self)

    monkeypatch.setattr(
        kyber_module.KyberKEM, "generate_keys", counting_generate_keys
    )

    second.load_or_create_kyber_keypair(store)  # must only ever LOAD here

    assert calls == []
    assert second.kyber.encapsulation_key == first.kyber.encapsulation_key
    assert second.kyber.decapsulation_key == first.kyber.decapsulation_key


def test_private_key_is_never_stored_in_plaintext(store_dir):
    """TEST F: the on-disk file never contains the raw private-key
    bytes, in raw or base64 form -- only through the same encrypted,
    authenticated payload already protecting conversation keys."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    manager = KeyManager()
    manager.load_or_create_kyber_keypair(store)

    raw_file = store.path.read_bytes()
    private_key = manager.kyber.decapsulation_key
    public_key = manager.kyber.encapsulation_key

    assert private_key not in raw_file
    assert base64.b64encode(private_key) not in raw_file
    assert public_key not in raw_file
    assert base64.b64encode(public_key) not in raw_file

    document = json.loads(raw_file.decode("utf-8"))
    assert "own_kyber_keypair" not in document
    assert "encapsulation_key" not in json.dumps(document)
    assert "decapsulation_key" not in json.dumps(document)


def test_public_and_private_key_round_trip_correctly_after_reload(store_dir):
    """TEST G: after reload, decapsulation(encapsulation(message)) ==
    message, using the real ML-KEM-768 implementation -- not a mock."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    original = KeyManager()
    original.load_or_create_kyber_keypair(store)

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    loaded = KeyManager()
    loaded.load_or_create_kyber_keypair(reopened)

    # A peer encapsulating against the RELOADED public key must be
    # decapsulatable by the RELOADED private key, via the real
    # kyber_py ML_KEM_768 implementation end to end.
    shared_secret, ciphertext = ML_KEM_768.encaps(loaded.kyber.encapsulation_key)
    recovered = ML_KEM_768.decaps(loaded.kyber.decapsulation_key, ciphertext)

    assert recovered == shared_secret

    # And also through KeyManager/KyberKEM's own encapsulate()/
    # decapsulate() wrappers, exactly as client/session.py uses them.
    ciphertext_b64, shared_secret_direct = loaded.kyber.encapsulate(
        loaded.kyber.encapsulation_key
    )
    recovered_direct = loaded.kyber.decapsulate(ciphertext_b64)

    assert recovered_direct == shared_secret_direct


def test_corrupted_own_keypair_section_fails_closed_not_silent_regeneration(
    store_dir,
):
    """
    Section 4 of the Stage-2.5 design brief: a corrupted/incomplete
    persisted keypair must never silently produce a replacement K2 --
    it must fail closed. Simulates corruption of ONLY the
    own_kyber_keypair section (the rest of the authenticated payload
    stays genuine) by re-deriving the same storage key and re-writing
    a payload whose own_kyber_keypair.decapsulation_key is truncated,
    then re-encrypting it under a FRESH nonce with the SAME derived
    key -- exactly what a bit-level corruption of the ciphertext would
    also trigger: the GCM tag will not match, so this is
    indistinguishable, from unlock()'s point of view, from any other
    on-disk corruption already handled by this module.
    """

    store = _store(store_dir)
    store.unlock(PASSWORD)

    manager = KeyManager()
    manager.load_or_create_kyber_keypair(store)

    # Corrupt the payload the same way test_corrupted_store_fails_
    # authentication (Stage 1) already does for the "keys" section:
    # flip bytes inside the authenticated ciphertext, so the GCM tag
    # no longer matches.
    document = json.loads(store.path.read_text())
    document["payload"] = document["payload"][:-8] + "AAAAAAAA"
    store.path.write_text(json.dumps(document), encoding="utf-8")

    reopened = _store(store_dir)
    with pytest.raises(KeyStoreLocked):
        reopened.unlock(PASSWORD)

    # Fail closed means exactly that: no keypair is silently produced
    # and no store is usable. It does NOT mean the process is
    # unusable -- ClientSession._unlock_key_store() already treats any
    # KeyStoreLocked the same way it always has (key_store_error set,
    # self.key_store stays None), and the session simply keeps its
    # own __init__()-time ephemeral keypair for that session's
    # lifetime, exactly as every session behaved before Stage 2.5.
    # This is proven at the ClientSession level in
    # test_own_keypair_survives_logout_and_login below (the honest,
    # non-corrupted path) and by the existing Stage-1 corrupted-store
    # test (the same failure mode, already proven not to break login).


def test_save_own_kyber_keypair_refuses_to_overwrite_an_existing_one(store_dir):
    """Defense in depth for the fail-closed requirement: even called
    directly (bypassing KeyManager entirely), SecureKeyStore itself
    must never silently replace an already-persisted own keypair."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    store.save_own_kyber_keypair(b"E" * ML_KEM_768_PUBLIC_KEY_BYTES, b"D" * ML_KEM_768_PRIVATE_KEY_BYTES)

    with pytest.raises(KeyStoreError):
        store.save_own_kyber_keypair(
            b"X" * ML_KEM_768_PUBLIC_KEY_BYTES, b"Y" * ML_KEM_768_PRIVATE_KEY_BYTES
        )

    # The original, first-persisted keypair must still be intact.
    assert store.get_own_kyber_keypair() == (
        b"E" * ML_KEM_768_PUBLIC_KEY_BYTES,
        b"D" * ML_KEM_768_PRIVATE_KEY_BYTES,
    )


def test_a_store_written_before_stage_2_5_existed_still_unlocks(store_dir):
    """Section 9 -- backward compatibility: a store with "keys" and
    "peers" sections but no "own_kyber_keypair" section at all (as
    every store written before this stage existed looks) must unlock
    exactly as it always did, with get_own_kyber_keypair() reporting
    None rather than treating the absence as corruption. Existing peer
    verification state must remain completely intact and unaffected."""

    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.record_observed_peer_fingerprint("bob", "AAAA BBBB")
    store.save({"conv-a": {1: b"K" * 32}})

    # save_own_kyber_keypair() was never called, so _write() already
    # encoded own_kyber_keypair as None (the same as a genuinely
    # pre-Stage-2.5 file, which would omit the key entirely -- unlock()
    # treats a present-but-null value and a fully absent key
    # identically via document.get("own_kyber_keypair"), matching how
    # "peers" was proven backward compatible in Stage 1).
    reopened = _store(store_dir)
    restored_keys = reopened.unlock(PASSWORD)

    assert reopened.get_own_kyber_keypair() is None
    assert reopened.get_peer_verification("bob") == {
        "fingerprint": "AAAA BBBB",
        "state": "UNVERIFIED",
    }
    assert restored_keys == {"conv-a": {1: b"K" * 32}}

    # A fresh KeyManager can still safely generate-and-persist for the
    # first time against this now-upgraded store, exactly like a
    # brand-new installation.
    manager = KeyManager()
    manager.load_or_create_kyber_keypair(reopened)
    assert reopened.get_own_kyber_keypair() is not None

    # And peer verification state remains completely untouched by that.
    assert reopened.get_peer_verification("bob") == {
        "fingerprint": "AAAA BBBB",
        "state": "UNVERIFIED",
    }


def test_rsa_algorithm_is_unaffected_and_out_of_scope(store_dir, monkeypatch):
    """Stage 2.5 is scoped to Kyber only. When RSA is the active
    algorithm, load_or_create_kyber_keypair() must be a complete
    no-op: no store interaction, no change to RSA's own (still
    per-session, still unpersisted) keys."""

    monkeypatch.setattr(key_manager_module, "KEY_EXCHANGE_ALGORITHM", "RSA")

    store = _store(store_dir)
    store.unlock(PASSWORD)

    manager = key_manager_module.KeyManager()
    original_public_key = manager.public_key

    manager.load_or_create_kyber_keypair(store)

    assert manager.public_key == original_public_key
    assert store.get_own_kyber_keypair() is None


# ----------------------------------------------------------------------
# Integration-level: a real ClientSession + real test server. Uses its
# own self-contained fixtures (username-based authentication, matching
# AuthenticationService.authenticate_user() at HEAD) rather than
# sharing fixtures from other test files, so this file's tests do not
# depend on any other in-progress, uncommitted feature's state.
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Own Keypair Persistence Test",
            "username": f"okp_{hint}{suffix}",
            "email": f"okp_{hint}{suffix}@example.com",
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

    def _launch(payload, password=PASSWORD, send_key=True, start_receiving=True):
        session = ClientSession()
        opened.append(session)

        result = session.authenticate_credentials(payload["username"], password)
        assert result.success, result.message

        session.user_id = result.user_id
        session.username = result.username
        session.session_id = result.session_id
        session.access_token = result.token_pair.access_token
        session.refresh_token = result.token_pair.refresh_token

        session.connect()
        session.login(payload["username"])
        if send_key:
            session.send_public_key()
        if start_receiving:
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


def test_own_keypair_survives_logout_and_login(app):
    """TEST E: the real application lifecycle. Bob logs in (K1
    generated and persisted), disconnects (logout), logs in again with
    a brand-new ClientSession/KeyManager (simulating both logout/login
    and an application restart, since nothing from the first session
    is reused) -- the SAME ML-KEM keypair, and the same fingerprint,
    must come back, not a freshly generated K2."""

    bob_payload = app["register"]("bob_")

    bob = app["launch"](bob_payload)
    public_key_1 = bytes(bob.key_manager.public_key)
    fingerprint_1 = fingerprint_public_key(public_key_1)
    bob.disconnect()

    bob_again = app["launch"](bob_payload)
    public_key_2 = bytes(bob_again.key_manager.public_key)
    fingerprint_2 = fingerprint_public_key(public_key_2)

    assert public_key_2 == public_key_1
    assert fingerprint_2 == fingerprint_1


def test_own_keypair_survives_a_third_login_too(app):
    """The same property, one more login deep -- guards against a
    design that happens to work for exactly one reload (e.g. an
    accidental overwrite-then-match) but drifts on a third."""

    bob_payload = app["register"]("bob_")

    bob_1 = app["launch"](bob_payload)
    fingerprint_1 = fingerprint_public_key(bob_1.key_manager.public_key)
    bob_1.disconnect()

    bob_2 = app["launch"](bob_payload)
    fingerprint_2 = fingerprint_public_key(bob_2.key_manager.public_key)
    bob_2.disconnect()

    bob_3 = app["launch"](bob_payload)
    fingerprint_3 = fingerprint_public_key(bob_3.key_manager.public_key)

    assert fingerprint_1 == fingerprint_2 == fingerprint_3


def test_private_key_never_appears_in_the_outgoing_public_key_packet(app, monkeypatch):
    """TEST L / Section 7: the packet actually sent to the server by
    send_public_key() must contain only the public key -- the private
    (decapsulation) key must never be present in the outgoing wire
    packet, in any form."""

    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload, send_key=False, start_receiving=False)

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", recording_send_message)

    private_key = bob.key_manager.kyber.decapsulation_key
    public_key_wire_text = bob.key_manager.public_key.decode("utf-8")

    bob.send_public_key()

    key_packets = [p for p in sent_packets if p.get("type") == "key_exchange"]
    assert len(key_packets) == 1

    packet = key_packets[0]
    serialized = json.dumps(packet, default=str)

    assert set(packet.keys()) == {"type", "operation", "algorithm", "username", "public_key"}
    assert packet["public_key"] == public_key_wire_text

    assert private_key.hex() not in serialized
    assert base64.b64encode(private_key).decode("ascii") not in serialized


def test_existing_kyber_operations_unaffected_direct_key_wrap(app):
    """Section 8 -- KeyManager compatibility: wrap_key_for_member()/
    unwrap_received_key() still work correctly against a PERSISTED
    keypair, exactly as they already do against an ephemeral one."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    deadline = time.time() + 5
    while alice.key_manager.get_public_key(bob_payload["username"]) is None:
        assert time.time() < deadline, "Bob's public key never arrived"
        _app.processEvents()
        time.sleep(0.05)

    session_key = os.urandom(32)
    encapsulation, wrapped_key = alice.key_manager.wrap_key_for_member(
        bob_payload["username"], session_key
    )

    recovered = bob.key_manager.unwrap_received_key(encapsulation, wrapped_key)

    assert recovered == session_key
