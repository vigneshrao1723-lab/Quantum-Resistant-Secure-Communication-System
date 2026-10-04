"""
ML-DSA identity/key-persistence foundation phase -- persistent local
ML-DSA-65 signing keypair.

Mirrors tests/test_own_kyber_keypair_persistence.py's structure and
reasoning exactly, for the new signing keypair rather than the KEM
keypair: KeyManager.__init__() generates an ephemeral ML-DSA keypair
every time (crypto/key_manager.py::KeyManager.__init__()), and without
persistence this local user's signing identity would silently change
on every login -- exactly the failure Stage 2.5 already prevents for
the Kyber keypair. This phase makes the SAME property hold for the
signing keypair, through the same encrypted, password-derived
SecureKeyStore file, alongside (not instead of) the Kyber keypair.

Unlike Kyber's load_or_create_kyber_keypair(), load_or_create_signing_
keypair() is unconditional (not gated on the active KEM algorithm) and
additionally re-derives the public key from a loaded private seed and
compares it against the separately-persisted public key, failing
closed with ValueError on a mismatch -- covered here directly.

This phase does not implement packet signing, network protocol
changes, or peer-identity trust-state wiring -- see
tests/test_combined_identity_fingerprint.py and
tests/test_peer_identity_state_transitions.py for those.

Run with:
    pytest tests/test_own_signing_keypair_persistence.py -v
"""

import base64
import json
import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

import client.session as client_session_module
import crypto.key_manager as key_manager_module
import crypto.ml_dsa as ml_dsa_module
from auth.authentication_service import AuthenticationService
from auth.schemas import RegisterRequest
from client.session import ClientSession
from crypto.key_manager import KeyManager
from crypto.ml_dsa import (
    ML_DSA_65_PRIVATE_SEED_BYTES,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    MLDSASigner,
)
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from storage.secure_key_store import KeyStoreError, KeyStoreLocked, SecureKeyStore
from tests.tls_test_support import start_test_server

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


# --- 1. First-startup creation ---


def test_first_creation_generates_and_persists_a_keypair(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    assert store.get_own_signing_keypair() is None

    manager = KeyManager()
    manager.load_or_create_signing_keypair(store)

    persisted = store.get_own_signing_keypair()

    assert persisted is not None
    assert persisted == (
        manager.ml_dsa.export_public_key(),
        manager.ml_dsa.export_private_key(),
    )

    # Also durable across a fresh unlock of the same file, not just
    # visible on the same in-memory store object.
    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)
    assert reopened.get_own_signing_keypair() == persisted


# --- 2/3/4. Restart loads the same keypair; public/private byte-identical ---


def test_reload_yields_an_identical_keypair(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    first = KeyManager()
    first.load_or_create_signing_keypair(store)

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    second = KeyManager()
    second.load_or_create_signing_keypair(reopened)

    assert second.ml_dsa.export_public_key() == first.ml_dsa.export_public_key()
    assert second.ml_dsa.export_private_key() == first.ml_dsa.export_private_key()


def test_load_does_not_regenerate_when_a_keypair_is_already_persisted(
    store_dir, monkeypatch
):
    """Scoped precisely to the LOAD step, exactly like the equivalent
    Kyber test: __init__() always generates a keypair once,
    unconditionally, before any store is available. What this test
    proves is that load_or_create_signing_keypair() itself never
    triggers a SECOND generation once persisted material already
    exists."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    first = KeyManager()
    first.load_or_create_signing_keypair(store)  # persists D1

    second = KeyManager()  # __init__ always generates once

    calls = []
    original_generate_keys = ml_dsa_module.MLDSASigner.generate_keys

    def counting_generate_keys(self):
        calls.append(1)
        return original_generate_keys(self)

    monkeypatch.setattr(
        ml_dsa_module.MLDSASigner, "generate_keys", counting_generate_keys
    )

    second.load_or_create_signing_keypair(store)  # must only ever LOAD here

    assert calls == []
    assert second.ml_dsa.export_public_key() == first.ml_dsa.export_public_key()
    assert second.ml_dsa.export_private_key() == first.ml_dsa.export_private_key()


# --- 5. Derived public key matches the persisted public key ---


def test_derived_public_key_matches_persisted_public_key_on_reload(store_dir):
    """The public key re-derived from the reloaded private seed must
    match the separately-persisted public key -- the exact property
    load_or_create_signing_keypair()'s own integrity check enforces."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    KeyManager().load_or_create_signing_keypair(store)
    persisted_public_key, persisted_private_seed = store.get_own_signing_keypair()

    rederived = MLDSASigner()
    rederived.import_private_key(persisted_private_seed)

    assert rederived.export_public_key() == persisted_public_key


def test_integrity_check_raises_when_persisted_halves_do_not_match(store_dir):
    """A persisted public key that does NOT match the persisted private
    seed (e.g. from file corruption or manual tampering) must be
    rejected with ValueError, not silently accepted -- see
    load_or_create_signing_keypair()'s docstring. Bypasses save_own_
    signing_keypair()'s own validation by writing directly into the
    store's in-memory state before persisting, since save_own_
    signing_keypair() itself only ever receives an honest, self-
    consistent pair from KeyManager."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    mismatched_public_key = MLDSASigner()
    mismatched_public_key.generate_keys()

    unrelated_seed = MLDSASigner()
    unrelated_seed.generate_keys()

    store._own_signing_keypair = (
        mismatched_public_key.export_public_key(),
        unrelated_seed.export_private_key(),
    )
    store._write(store._last_keys_snapshot)

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    manager = KeyManager()
    with pytest.raises(ValueError):
        manager.load_or_create_signing_keypair(reopened)


# --- 6. Malformed base64 rejected ---


def test_malformed_base64_in_signing_section_fails_closed(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    KeyManager().load_or_create_signing_keypair(store)

    document = json.loads(store.path.read_text())
    # Corrupt the AUTHENTICATED payload's ciphertext so the GCM tag no
    # longer matches -- the only way to change what a signing_keypair
    # section decodes to without unlock() detecting tampering first,
    # exactly mirroring the equivalent Kyber corruption test.
    document["payload"] = document["payload"][:-8] + "AAAAAAAA"
    store.path.write_text(json.dumps(document), encoding="utf-8")

    reopened = _store(store_dir)
    with pytest.raises(KeyStoreLocked):
        reopened.unlock(PASSWORD)


def test_decode_rejects_malformed_base64_directly():
    """Unit-level, below unlock()'s GCM authentication: _decode_own_
    signing_keypair() itself must reject a value that is not valid
    base64, rather than raising an uncaught, unclassified error."""

    with pytest.raises(Exception):
        SecureKeyStore._decode_own_signing_keypair(
            {"public_key": "not valid base64!!", "private_seed": "also not valid!!"}
        )


# --- 7. Wrong-length private seed rejected ---


def test_wrong_length_private_seed_rejected():
    valid_public_key = base64.b64encode(b"P" * ML_DSA_65_PUBLIC_KEY_BYTES).decode("ascii")
    too_short_seed = base64.b64encode(b"S" * 10).decode("ascii")

    with pytest.raises(ValueError):
        SecureKeyStore._decode_own_signing_keypair(
            {"public_key": valid_public_key, "private_seed": too_short_seed}
        )


# --- 8. Malformed (wrong-length) public key rejected ---


def test_wrong_length_public_key_rejected():
    too_short_public_key = base64.b64encode(b"P" * 10).decode("ascii")
    valid_seed = base64.b64encode(b"S" * ML_DSA_65_PRIVATE_SEED_BYTES).decode("ascii")

    with pytest.raises(ValueError):
        SecureKeyStore._decode_own_signing_keypair(
            {"public_key": too_short_public_key, "private_seed": valid_seed}
        )


# --- 9. Corrupted material fails closed (not silent regeneration) ---


def test_corrupted_own_signing_keypair_section_fails_closed_not_silent_regeneration(
    store_dir,
):
    """Same reasoning as the equivalent Kyber test: a corrupted
    persisted signing keypair must never silently produce a
    replacement D2 -- it must fail closed, refusing the whole store
    rather than minting a new signing identity underneath whatever
    peers have already VERIFIED this user's current combined
    fingerprint."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    KeyManager().load_or_create_signing_keypair(store)

    document = json.loads(store.path.read_text())
    document["payload"] = document["payload"][:-8] + "BBBBBBBB"
    store.path.write_text(json.dumps(document), encoding="utf-8")

    reopened = _store(store_dir)
    with pytest.raises(KeyStoreLocked):
        reopened.unlock(PASSWORD)


def test_save_own_signing_keypair_refuses_to_overwrite_an_existing_one(store_dir):
    """Defense in depth: even called directly (bypassing KeyManager
    entirely), SecureKeyStore itself must never silently replace an
    already-persisted own signing keypair."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    store.save_own_signing_keypair(
        b"P" * ML_DSA_65_PUBLIC_KEY_BYTES, b"S" * ML_DSA_65_PRIVATE_SEED_BYTES
    )

    with pytest.raises(KeyStoreError):
        store.save_own_signing_keypair(
            b"X" * ML_DSA_65_PUBLIC_KEY_BYTES, b"Y" * ML_DSA_65_PRIVATE_SEED_BYTES
        )

    assert store.get_own_signing_keypair() == (
        b"P" * ML_DSA_65_PUBLIC_KEY_BYTES,
        b"S" * ML_DSA_65_PRIVATE_SEED_BYTES,
    )


# --- 10. Private signing material never serialized into a network/public packet ---


def test_private_signing_key_is_never_stored_in_plaintext(store_dir):
    """The on-disk file never contains the raw private-seed bytes, in
    raw or base64 form -- only through the same encrypted,
    authenticated payload already protecting the Kyber keypair and
    conversation keys. This phase implements no network packet for the
    signing key at all yet (Phase 11's explicit scope boundary), so
    there is no wire path to test here -- persistence is the only
    surface that exists."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    manager = KeyManager()
    manager.load_or_create_signing_keypair(store)

    raw_file = store.path.read_bytes()
    private_seed = manager.ml_dsa.export_private_key()
    public_key = manager.ml_dsa.export_public_key()

    assert private_seed not in raw_file
    assert base64.b64encode(private_seed) not in raw_file
    assert public_key not in raw_file
    assert base64.b64encode(public_key) not in raw_file

    document = json.loads(raw_file.decode("utf-8"))
    assert "own_signing_keypair" not in document
    assert "private_seed" not in json.dumps(document)


# --- Backward compatibility / regression: existing Kyber persistence unaffected ---


def test_a_store_written_before_this_phase_existed_still_unlocks(store_dir):
    """A store with "keys", "peers", and "own_kyber_keypair" sections
    but no "own_signing_keypair" section at all (as every store written
    before this phase existed looks) must unlock exactly as it always
    did, with get_own_signing_keypair() reporting None rather than
    treating the absence as corruption -- and the existing Kyber
    keypair and peer verification state must remain completely
    unaffected."""

    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.record_observed_peer_fingerprint("bob", "AAAA BBBB")
    store.save_own_kyber_keypair(b"E" * 1184, b"D" * 2400)
    store.save({"conv-a": {1: b"K" * 32}})

    reopened = _store(store_dir)
    restored_keys = reopened.unlock(PASSWORD)

    assert reopened.get_own_signing_keypair() is None
    assert reopened.get_own_kyber_keypair() == (b"E" * 1184, b"D" * 2400)
    assert reopened.get_peer_verification("bob") == {
        "fingerprint": "AAAA BBBB",
        "state": "UNVERIFIED",
    }
    assert restored_keys == {"conv-a": {1: b"K" * 32}}

    manager = KeyManager()
    manager.load_or_create_signing_keypair(reopened)
    assert reopened.get_own_signing_keypair() is not None

    # And existing Kyber/peer state remains completely untouched by that.
    assert reopened.get_own_kyber_keypair() == (b"E" * 1184, b"D" * 2400)
    assert reopened.get_peer_verification("bob") == {
        "fingerprint": "AAAA BBBB",
        "state": "UNVERIFIED",
    }


def test_sign_verify_round_trip_correctly_after_reload(store_dir):
    """After reload, a signature made with the RELOADED private key
    must verify under the RELOADED public key, using the real ML-DSA-65
    implementation -- not a mock."""

    store = _store(store_dir)
    store.unlock(PASSWORD)

    original = KeyManager()
    original.load_or_create_signing_keypair(store)

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    loaded = KeyManager()
    loaded.load_or_create_signing_keypair(reopened)

    message = b"round trip after reload"
    signature = loaded.ml_dsa.sign(message)

    assert MLDSASigner.verify(message, signature, loaded.ml_dsa.export_public_key()) is True


# ----------------------------------------------------------------------
# Integration-level: a real ClientSession + real test server.
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Own Signing Keypair Persistence Test",
            "username": f"osk_{hint}{suffix}",
            "email": f"osk_{hint}{suffix}@example.com",
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

        result = session.authenticate_credentials(payload["phone_number"], password)
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


def test_own_signing_keypair_survives_logout_and_login(app):
    """The real application lifecycle, mirroring test_own_keypair_
    survives_logout_and_login for Kyber: Bob logs in (D1 generated and
    persisted via _unlock_key_store()), disconnects, logs in again with
    a brand-new ClientSession/KeyManager -- the SAME ML-DSA signing
    keypair must come back, not a freshly generated D2."""

    bob_payload = app["register"]("bob_")

    bob = app["launch"](bob_payload)
    public_key_1 = bytes(bob.key_manager.ml_dsa.export_public_key())
    bob.disconnect()

    bob_again = app["launch"](bob_payload)
    public_key_2 = bytes(bob_again.key_manager.ml_dsa.export_public_key())

    assert public_key_2 == public_key_1


def test_unlock_key_store_failure_is_not_fatal_to_login(app, monkeypatch):
    """Mirrors the Kyber keypair's "never fatal" posture: if load_or_
    create_signing_keypair() fails for any reason, login must still
    succeed, and the session keeps its ephemeral, __init__()-time
    signing keypair rather than crashing or blocking login."""

    def raising_load_or_create_signing_keypair(self, key_store):
        raise ValueError("simulated corruption")

    monkeypatch.setattr(
        key_manager_module.KeyManager,
        "load_or_create_signing_keypair",
        raising_load_or_create_signing_keypair,
    )

    bob_payload = app["register"]("bob_")
    bob = app["launch"](bob_payload)  # must not raise

    assert bob.key_manager.ml_dsa.public_key is not None
