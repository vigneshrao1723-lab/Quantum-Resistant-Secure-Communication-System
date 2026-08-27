"""
BUG 1 -- chat history survives closing and reopening the application.

Server-side history was never the problem: the rows, ciphertext, blobs
and metadata all came back after a restart. What could not come back
was the ability to READ them. Conversation AES keys lived only in
KeyManager's in-memory dict, every launch built a fresh KeyManager, the
server is deliberately blind to those keys, and peer recovery can only
relay what another running client still holds. Once every participant
had closed the application, the keys were gone from the entire system
and history was permanently undecryptable.

storage/secure_key_store.py persists exactly those keys, encrypted
under an Argon2id key derived from the user's own password.

The decisive test here is
test_history_decrypts_after_both_participants_restart: both sides close
and reopen with brand-new sessions and brand-new KeyManagers, with no
peer left holding anything, and the old messages must still decrypt. A
unit test that calls store_key() by hand would prove nothing about
that, so nothing in the end-to-end section does.

Run with:
    pytest tests/test_key_store_persistence.py -v
"""

import base64
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time
import uuid
from pathlib import Path

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession, _UNDECRYPTABLE_PLACEHOLDER
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.models.message import Message
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.payload_type import PayloadType
from storage import encrypted_blob_store
from storage.secure_key_store import (
    KeyStoreError,
    KeyStoreLocked,
    SecureKeyStore,
)
from tests.tls_test_support import start_test_server

PASSWORD = "Str0ng!Passw0rd"


# ----------------------------------------------------------------------
# Key-store unit behaviour
# ----------------------------------------------------------------------


@pytest.fixture()
def store_dir(tmp_path):
    return tmp_path / "keystore"


def _store(store_dir, user_id="user-1"):
    return SecureKeyStore(user_id, storage_dir=store_dir)


def test_missing_store_is_a_fresh_install_not_an_error(store_dir):
    store = _store(store_dir)

    assert store.exists() is False
    assert store.unlock(PASSWORD) == {}
    assert store.is_unlocked


def test_keys_round_trip_through_the_file(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})

    reopened = _store(store_dir)
    restored = reopened.unlock(PASSWORD)

    assert restored == {"conv-a": {1: b"K" * 32}}


def test_multiple_epochs_round_trip(store_dir):
    keys = {
        "conv-a": {1: b"1" * 32, 2: b"2" * 32, 3: b"3" * 32},
        "conv-b": {7: b"7" * 32},
    }

    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save(keys)

    assert _store(store_dir).unlock(PASSWORD) == keys


def test_file_is_encrypted_and_contains_no_plaintext_key(store_dir):
    secret = b"S" * 32

    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: secret}})

    raw = store.path.read_bytes()

    assert secret not in raw
    assert base64.b64encode(secret) not in raw
    assert PASSWORD.encode() not in raw

    document = json.loads(raw.decode("utf-8"))
    assert document["kdf"] == "argon2id"
    assert "conv-a" not in document["payload"]


def test_salt_is_unique_per_store(store_dir, tmp_path):
    first = _store(store_dir, "user-1")
    first.unlock(PASSWORD)
    first.save({})

    second = SecureKeyStore("user-2", storage_dir=tmp_path / "other")
    second.unlock(PASSWORD)
    second.save({})

    salt_one = json.loads(first.path.read_text())["salt"]
    salt_two = json.loads(second.path.read_text())["salt"]

    assert salt_one != salt_two


def test_nonce_differs_between_two_saves_of_the_same_data(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    store.save({"conv-a": {1: b"K" * 32}})
    first_payload = json.loads(store.path.read_text())["payload"]

    store.save({"conv-a": {1: b"K" * 32}})
    second_payload = json.loads(store.path.read_text())["payload"]

    assert first_payload != second_payload


def test_wrong_password_fails_closed_and_leaves_the_file_intact(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})
    before = store.path.read_bytes()

    with pytest.raises(KeyStoreLocked):
        _store(store_dir).unlock("the-wrong-password")

    assert store.path.read_bytes() == before
    assert _store(store_dir).unlock(PASSWORD) == {"conv-a": {1: b"K" * 32}}


def test_corrupted_store_fails_authentication(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})

    document = json.loads(store.path.read_text())
    document["payload"] = document["payload"][:-8] + "AAAAAAAA"
    store.path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(KeyStoreLocked):
        _store(store_dir).unlock(PASSWORD)


def test_saving_without_unlocking_is_refused(store_dir):
    with pytest.raises(KeyStoreError):
        _store(store_dir).save({"conv-a": {1: b"K" * 32}})


def test_lock_drops_the_derived_key_but_keeps_the_file(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})

    store.lock()

    assert store.is_unlocked is False
    assert store.exists() is True


# ----------------------------------------------------------------------
# Peer public-key verification state (Server-Untrusted Identity
# Verification, Stage 1)
# ----------------------------------------------------------------------


def test_unverified_peer_state_can_be_stored_and_retrieved(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    store.record_observed_peer_fingerprint("bob", "AAAA BBBB")

    entry = store.get_peer_verification("bob")

    assert entry == {"fingerprint": "AAAA BBBB", "state": "UNVERIFIED"}
    assert store.has_verified_fingerprint("bob") is False


def test_verified_fingerprint_can_be_stored_and_retrieved(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    store.verify_peer_fingerprint("bob", "AAAA BBBB")

    entry = store.get_peer_verification("bob")

    assert entry == {"fingerprint": "AAAA BBBB", "state": "VERIFIED"}
    assert store.has_verified_fingerprint("bob") is True


def test_unknown_peer_has_no_verification_entry(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    assert store.get_peer_verification("nobody-ever-seen") is None
    assert store.has_verified_fingerprint("nobody-ever-seen") is False


def test_verified_fingerprint_survives_key_store_reload(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.verify_peer_fingerprint("bob", "AAAA BBBB CCCC")

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    assert reopened.get_peer_verification("bob") == {
        "fingerprint": "AAAA BBBB CCCC",
        "state": "VERIFIED",
    }
    assert reopened.has_verified_fingerprint("bob") is True


def test_unverified_fingerprint_also_survives_reload(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.record_observed_peer_fingerprint("bob", "1111 2222")

    reopened = _store(store_dir)
    reopened.unlock(PASSWORD)

    assert reopened.get_peer_verification("bob") == {
        "fingerprint": "1111 2222",
        "state": "UNVERIFIED",
    }


def test_newly_observed_key_does_not_automatically_become_verified(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    store.record_observed_peer_fingerprint("bob", "AAAA BBBB")

    assert store.has_verified_fingerprint("bob") is False
    assert store.get_peer_verification("bob")["state"] == "UNVERIFIED"


def test_matching_fingerprint_is_detected_correctly(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.verify_peer_fingerprint("bob", "AAAA BBBB")

    assert store.fingerprint_matches_verified("bob", "AAAA BBBB") is True


def test_changed_fingerprint_is_detected_correctly(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.verify_peer_fingerprint("bob", "AAAA BBBB")

    assert store.fingerprint_matches_verified("bob", "ZZZZ YYYY") is False


def test_fingerprint_match_check_against_an_unverified_peer_is_false(store_dir):
    """Not a match, and not treated as one: matching is only ever
    meaningful against an entry this user has actually verified."""
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.record_observed_peer_fingerprint("bob", "AAAA BBBB")

    assert store.fingerprint_matches_verified("bob", "AAAA BBBB") is False


def test_verified_fingerprint_cannot_be_silently_overwritten_by_observation(store_dir):
    """The central protection: once verified, a newly OBSERVED
    (unverified-by-definition) key must never silently replace it --
    only verify_peer_fingerprint() itself may ever do that."""
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.verify_peer_fingerprint("bob", "AAAA BBBB")

    # A different key arrives -- e.g. a malicious server substituting
    # one -- and is merely observed, not explicitly re-verified.
    store.record_observed_peer_fingerprint("bob", "EVIL EVIL")

    entry = store.get_peer_verification("bob")

    assert entry == {"fingerprint": "AAAA BBBB", "state": "VERIFIED"}, (
        "an observed key silently overwrote a verified one"
    )


def test_verify_peer_fingerprint_can_explicitly_replace_a_verified_entry(store_dir):
    """The one and only path that MAY change a VERIFIED entry: an
    explicit call to verify_peer_fingerprint() itself (the future
    user-driven re-verification action)."""
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.verify_peer_fingerprint("bob", "AAAA BBBB")

    store.verify_peer_fingerprint("bob", "NEW1 NEW2")

    assert store.get_peer_verification("bob") == {
        "fingerprint": "NEW1 NEW2",
        "state": "VERIFIED",
    }


def test_verification_state_stays_associated_with_the_correct_peer(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)

    store.verify_peer_fingerprint("alice", "ALIC E000")
    store.record_observed_peer_fingerprint("bob", "BOB0 0000")
    store.verify_peer_fingerprint("carol", "CARO L000")

    assert store.get_peer_verification("alice") == {
        "fingerprint": "ALIC E000", "state": "VERIFIED",
    }
    assert store.get_peer_verification("bob") == {
        "fingerprint": "BOB0 0000", "state": "UNVERIFIED",
    }
    assert store.get_peer_verification("carol") == {
        "fingerprint": "CARO L000", "state": "VERIFIED",
    }
    assert store.has_verified_fingerprint("alice") is True
    assert store.has_verified_fingerprint("bob") is False
    assert store.has_verified_fingerprint("carol") is True


def test_peer_verification_coexists_with_conversation_keys_on_reload(store_dir):
    """Both kinds of persisted state -- conversation keys and peer
    verification -- live in the same encrypted file; a reload must
    recover both correctly, neither clobbering the other."""
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})
    store.verify_peer_fingerprint("bob", "AAAA BBBB")

    reopened = _store(store_dir)
    restored_keys = reopened.unlock(PASSWORD)

    assert restored_keys == {"conv-a": {1: b"K" * 32}}
    assert reopened.get_peer_verification("bob") == {
        "fingerprint": "AAAA BBBB", "state": "VERIFIED",
    }


def test_recording_a_peer_fingerprint_does_not_erase_conversation_keys(store_dir):
    """record_observed_peer_fingerprint()/verify_peer_fingerprint() has
    no conversation-key snapshot of its own -- it must write back
    whatever was last known, never an empty keys section."""
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})

    store.record_observed_peer_fingerprint("bob", "AAAA BBBB")

    reopened = _store(store_dir)
    restored_keys = reopened.unlock(PASSWORD)

    assert restored_keys == {"conv-a": {1: b"K" * 32}}


def test_peer_verification_file_contains_no_plaintext_fingerprint(store_dir):
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.verify_peer_fingerprint("bob", "AAAA BBBB CCCC")

    raw = store.path.read_bytes()

    assert b"AAAA BBBB CCCC" not in raw
    assert b"bob" not in raw


def test_a_store_written_before_peer_verification_existed_still_unlocks(store_dir):
    """Backward compatibility: a file with no "peers" section at all
    (every store written before this feature existed) must still
    unlock cleanly, with an empty, honest peer-verification state --
    not an error."""
    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})  # writes with no peer calls at all

    reopened = _store(store_dir)
    restored_keys = reopened.unlock(PASSWORD)

    assert restored_keys == {"conv-a": {1: b"K" * 32}}
    assert reopened.get_peer_verification("anyone") is None


def test_record_observed_peer_fingerprint_requires_unlocking_first(store_dir):
    store = _store(store_dir)

    with pytest.raises(KeyStoreError):
        store.record_observed_peer_fingerprint("bob", "AAAA BBBB")


def test_verify_peer_fingerprint_requires_unlocking_first(store_dir):
    store = _store(store_dir)

    with pytest.raises(KeyStoreError):
        store.verify_peer_fingerprint("bob", "AAAA BBBB")


# ----------------------------------------------------------------------
# KeyManager restore semantics
# ----------------------------------------------------------------------


def test_restore_never_overwrites_an_existing_epoch():
    manager = KeyManager()
    manager.store_key("conv-a", b"live" + b"-" * 27, epoch=1)

    manager.import_conversation_keys({"conv-a": {1: b"stale" + b"-" * 26}})

    assert manager.get_key("conv-a", epoch=1) == b"live" + b"-" * 27


def test_restore_adds_only_missing_epochs():
    manager = KeyManager()
    manager.store_key("conv-a", b"1" * 32, epoch=1)

    restored = manager.import_conversation_keys(
        {"conv-a": {1: b"x" * 32, 2: b"2" * 32, 3: b"3" * 32}}
    )

    assert restored == 2
    assert manager.get_key("conv-a", epoch=1) == b"1" * 32
    assert manager.get_key("conv-a", epoch=2) == b"2" * 32
    assert manager.current_epoch("conv-a") == 3


def test_on_change_fires_only_for_a_genuinely_new_epoch():
    manager = KeyManager()
    calls = []
    manager.on_change = lambda: calls.append(1)

    manager.store_key("conv-a", b"1" * 32, epoch=1)
    manager.store_key("conv-a", b"1" * 32, epoch=1)
    manager.store_key("conv-a", b"2" * 32, epoch=2)

    assert len(calls) == 2


# ----------------------------------------------------------------------
# End to end: the real restart scenario
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Key Store Test",
            "username": f"ks_{hint}{suffix}",
            "email": f"ks_{hint}{suffix}@example.com",
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


def _wait_for(predicate, attempts=200, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


@pytest.fixture()
def app(running_server, monkeypatch, tmp_path):
    """Launch real application sessions against an isolated key-store
    directory, so tests never touch a developer's real store."""

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)
    monkeypatch.setattr(
        "storage.secure_key_store.KEY_STORE_DIR", tmp_path / "keystore"
    )

    opened = []
    created = []
    blobs = []

    def _launch(payload, password=PASSWORD):
        """A full application start: brand-new ClientSession, brand-new
        KeyManager, authenticate (which unlocks the key store), then
        connect."""

        # Mirrors gui/main_window.py exactly: authenticate_credentials()
        # manages its own connection and closes it, then
        # start_chat_session() connects again and logs in.
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
        session.send_public_key()
        session.start_receiver()
        return session

    def _register_user(hint):
        payload = _register(hint)
        created.append(payload)
        return payload

    yield {
        "launch": _launch,
        "register": _register_user,
        "blobs": blobs,
        "store_dir": tmp_path / "keystore",
    }

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001 -- teardown must not mask a failure
            pass

    for reference in blobs:
        try:
            encrypted_blob_store.delete_blob(reference)
        except Exception:  # noqa: BLE001
            pass

    for payload in created:
        _delete(payload["username"])


def _open_direct(session, partner):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=partner,
            is_online=True,
            latest_message=None,
        )
    )


def _history(session, partner):
    _open_direct(session, partner)
    return session.load_conversation_history(partner, is_group=False)


def _texts(history):
    return [row["text"] for row in history if row.get("payload_type") == PayloadType.TEXT]


def test_history_decrypts_after_both_participants_restart(app):
    """The BUG 1 scenario, exactly as reported.

    Alice and Bob exchange messages, BOTH applications close, BOTH
    reopen and log in, and the old messages must still be readable --
    with no peer left holding a key in memory to recover from.
    """

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )
    assert _wait_for(
        lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None
    )

    _open_direct(alice, bob_payload["username"])
    _open_direct(bob, alice_payload["username"])

    alice.send_chat_message("alice before the restart")
    assert _wait_for(
        lambda: any(
            s.latest_message and s.latest_message.text == "alice before the restart"
            for s in bob.conversation_store.get_all()
        )
    )
    bob.send_chat_message("bob before the restart")
    time.sleep(0.4)

    # --- both applications close ---
    alice.disconnect()
    bob.disconnect()
    time.sleep(0.6)

    # --- both reopen and log in ---
    alice_again = app["launch"](alice_payload)
    bob_again = app["launch"](bob_payload)

    assert alice_again.key_manager is not alice.key_manager
    assert bob_again.key_manager is not bob.key_manager

    alice_texts = _texts(_history(alice_again, bob_payload["username"]))
    bob_texts = _texts(_history(bob_again, alice_payload["username"]))

    assert "alice before the restart" in alice_texts
    assert "bob before the restart" in alice_texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in alice_texts

    assert "alice before the restart" in bob_texts
    assert "bob before the restart" in bob_texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in bob_texts


def test_older_epochs_remain_decryptable_after_restart(app):
    """A conversation accumulates a new epoch each time a client
    establishes a key with an empty KeyManager. Every epoch the history
    references must survive, not just the newest."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    _open_direct(alice, bob_payload["username"])
    _open_direct(bob, alice_payload["username"])
    alice.send_chat_message("first epoch message")
    assert _wait_for(
        lambda: any(
            s.latest_message and s.latest_message.text == "first epoch message"
            for s in bob.conversation_store.get_all()
        )
    )

    conversation_id = alice.current_conversation_id
    first_epoch = alice.key_manager.current_epoch(conversation_id)

    # Alice restarts and sends again -- a second epoch for the same
    # conversation.
    alice.disconnect()
    time.sleep(0.5)
    alice_second = app["launch"](alice_payload)
    _open_direct(alice_second, bob_payload["username"])
    alice_second.send_chat_message("second epoch message")
    time.sleep(0.5)

    db = SessionLocal()
    try:
        epochs = {
            row.epoch
            for row in db.query(Message)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .all()
        }
    finally:
        db.close()

    assert len(epochs) >= 1

    # Everyone closes; Alice reopens alone.
    alice_second.disconnect()
    bob.disconnect()
    time.sleep(0.6)

    alice_third = app["launch"](alice_payload)
    texts = _texts(_history(alice_third, bob_payload["username"]))

    assert "first epoch message" in texts
    assert "second epoch message" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts
    assert alice_third.key_manager.get_key(conversation_id, epoch=first_epoch)


def test_attachment_from_a_previous_session_still_decrypts(app, tmp_path):
    from PySide6.QtGui import QColor, QImage

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    image_path = tmp_path / "shared.png"
    image = QImage(40, 30, QImage.Format_RGB32)
    image.fill(QColor(12, 34, 56))
    assert image.save(str(image_path), "PNG")
    original = image_path.read_bytes()

    _open_direct(alice, bob_payload["username"])
    _open_direct(bob, alice_payload["username"])
    alice.send_attachment(str(image_path))
    time.sleep(0.8)

    conversation_id = alice.current_conversation_id
    db = SessionLocal()
    try:
        row = (
            db.query(Message)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .order_by(Message.timestamp.desc())
            .first()
        )
        if row is not None and row.blob_ref:
            app["blobs"].append(row.blob_ref)
    finally:
        db.close()

    alice.disconnect()
    bob.disconnect()
    time.sleep(0.6)

    bob_again = app["launch"](bob_payload)
    history = _history(bob_again, alice_payload["username"])

    images = [r for r in history if r.get("payload_type") == PayloadType.IMAGE]
    assert images, "the attachment was not in the reloaded history"
    assert images[0]["content"] == original


def test_logout_then_login_preserves_history(app):
    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )

    _open_direct(alice, bob_payload["username"])
    _open_direct(bob, alice_payload["username"])
    alice.send_chat_message("message before logout")
    assert _wait_for(
        lambda: any(
            s.latest_message and s.latest_message.text == "message before logout"
            for s in bob.conversation_store.get_all()
        )
    )

    store_path = bob.key_store.path
    assert store_path.exists()

    bob.logout()

    # Logout clears RAM but must not delete the encrypted file.
    assert store_path.exists()
    assert bob.key_store is None
    assert bob.key_manager.keys == {}

    bob.disconnect()
    alice.disconnect()
    time.sleep(0.5)

    bob_again = app["launch"](bob_payload)
    texts = _texts(_history(bob_again, alice_payload["username"]))

    assert "message before logout" in texts
    assert _UNDECRYPTABLE_PLACEHOLDER not in texts


def test_wrong_password_does_not_break_login_or_destroy_the_store(app):
    """A store that cannot be unlocked is reported, not fatal, and
    never replaced with fabricated keys."""

    alice_payload = app["register"]("alice_")
    bob_payload = app["register"]("bob_")

    alice = app["launch"](alice_payload)
    bob = app["launch"](bob_payload)
    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )
    _open_direct(alice, bob_payload["username"])
    alice.send_chat_message("stored under the real password")
    time.sleep(0.5)

    store_path = alice.key_store.path
    before = store_path.read_bytes()
    alice.disconnect()
    bob.disconnect()
    time.sleep(0.5)

    # Corrupt the file, then log in normally: login must still succeed.
    document = json.loads(store_path.read_text())
    document["payload"] = document["payload"][:-8] + "AAAAAAAA"
    store_path.write_text(json.dumps(document), encoding="utf-8")

    alice_again = app["launch"](alice_payload)

    assert alice_again.key_store is None
    assert alice_again.key_store_error
    assert alice_again.key_manager.keys == {}

    # The damaged file was neither deleted nor overwritten.
    assert store_path.exists()
    assert store_path.read_bytes() != before  # our corruption, not a rewrite
    assert json.loads(store_path.read_text())["payload"].endswith("AAAAAAAA")


# ----------------------------------------------------------------------
# Concurrency: a stale snapshot must never overwrite newer keys
# ----------------------------------------------------------------------


def test_concurrent_key_additions_all_survive_a_reopen(store_dir):
    """Several threads add epochs at once, each triggering a save.

    Before the fix, export() and save() were two separate steps: a
    thread could snapshot {1}, be overtaken by a thread that stored and
    saved {1,2}, then write its stale {1} back -- silently dropping
    epoch 2 from the file and losing that history at the next restart.
    Reopening the store must show every epoch that was stored.
    """

    import threading

    store = SecureKeyStore("racer", storage_dir=store_dir)
    store.unlock(PASSWORD)

    manager = KeyManager()
    # Exactly what ClientSession does: snapshot and write from inside
    # store_key()'s lock, which is what makes the pair atomic.
    manager.on_change = lambda: store.save(manager.export_conversation_keys())

    epochs = list(range(1, 41))
    barrier = threading.Barrier(8)
    errors = []

    def _worker(slice_of_epochs):
        try:
            barrier.wait(timeout=10)
            for epoch in slice_of_epochs:
                manager.store_key("conv-race", bytes([epoch % 256]) * 32, epoch=epoch)
        except Exception as error:  # noqa: BLE001 -- surfaced below
            errors.append(error)

    threads = [
        threading.Thread(target=_worker, args=(epochs[index::8],))
        for index in range(8)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert all(not thread.is_alive() for thread in threads)

    reopened = SecureKeyStore("racer", storage_dir=store_dir).unlock(PASSWORD)

    assert sorted(reopened["conv-race"]) == epochs, (
        "epochs were lost from the file -- a stale snapshot overwrote newer keys"
    )
    for epoch in epochs:
        assert reopened["conv-race"][epoch] == bytes([epoch % 256]) * 32


def test_header_tampering_is_rejected(store_dir):
    """The plaintext header is bound into the authenticated payload, so
    editing it (e.g. weakening the KDF cost) fails closed."""

    store = _store(store_dir)
    store.unlock(PASSWORD)
    store.save({"conv-a": {1: b"K" * 32}})

    document = json.loads(store.path.read_text())
    document["time_cost"] = 1
    store.path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(KeyStoreLocked):
        _store(store_dir).unlock(PASSWORD)


def test_key_store_default_location_is_outside_the_repository():
    """Runtime user secrets must not live in the source tree."""

    import config

    default = config._default_key_store_dir()
    repository_root = Path(config.ROOT_DIR).resolve()

    assert repository_root not in Path(default).resolve().parents
    assert Path(default).name == "keystore"


def test_on_change_runs_while_the_key_manager_lock_is_held():
    """The atomicity guarantee rests on this.

    Snapshot-and-write is only atomic because store_key() invokes
    on_change() while still holding KeyManager's lock, so no other
    thread can add an epoch in between. If that callback is ever moved
    outside the lock, the persistence race returns silently -- this
    test is what would catch it.

    Checked from ANOTHER thread, because the lock is reentrant and the
    owning thread could always re-acquire it.
    """

    import threading

    manager = KeyManager()
    observed = {}

    def _probe():
        acquired = manager._lock.acquire(blocking=False)
        observed["held_by_someone_else"] = not acquired
        if acquired:
            manager._lock.release()

    def _on_change():
        thread = threading.Thread(target=_probe)
        thread.start()
        thread.join(timeout=5)

    manager.on_change = _on_change
    manager.store_key("conv-a", b"K" * 32, epoch=1)

    assert observed.get("held_by_someone_else") is True, (
        "on_change ran without KeyManager's lock held -- snapshot and write "
        "are no longer atomic"
    )


def test_store_save_does_not_need_the_key_manager_lock(store_dir):
    """The lock-order graph must stay acyclic.

    KeyManager.store_key() takes KM's lock and then reaches the store
    (KM -> STORE). If any store path took STORE and then needed KM, the
    reverse edge would close a cycle and two threads could deadlock.

    Proven behaviourally: another thread holds KeyManager's lock for
    the whole duration, and save() must still complete. If the store
    needed that lock it would block until released, and the wait below
    would time out.
    """

    import threading

    manager = KeyManager()
    store = SecureKeyStore("leaf", storage_dir=store_dir)
    store.unlock(PASSWORD)

    holding = threading.Event()
    release = threading.Event()

    def _hold_key_manager_lock():
        with manager._lock:
            holding.set()
            release.wait(timeout=10)

    holder = threading.Thread(target=_hold_key_manager_lock)
    holder.start()

    try:
        assert holding.wait(timeout=5), "helper never acquired KeyManager's lock"

        finished = threading.Event()

        def _save():
            store.save({"conv-a": {1: b"K" * 32}})
            finished.set()

        saver = threading.Thread(target=_save)
        saver.start()

        assert finished.wait(timeout=5), (
            "save() blocked while KeyManager's lock was held elsewhere -- the "
            "store is not a leaf lock and the lock graph has a cycle"
        )
        saver.join(timeout=5)
    finally:
        release.set()
        holder.join(timeout=5)


def test_mixed_concurrent_access_does_not_deadlock(store_dir):
    """Hammer both entry points at once and require completion.

    Threads persisting through store_key() take KM then STORE; threads
    calling save() directly take STORE alone. With a watchdog join, a
    lock-order inversion would surface as a hang rather than a pass.
    """

    import threading

    store = SecureKeyStore("mixed", storage_dir=store_dir)
    store.unlock(PASSWORD)

    manager = KeyManager()
    manager.on_change = lambda: store.save(manager.export_conversation_keys())

    errors = []
    barrier = threading.Barrier(6)

    def _through_key_manager(start):
        try:
            barrier.wait(timeout=10)
            for epoch in range(start, start + 12):
                manager.store_key("conv-mixed", bytes([epoch % 256]) * 32, epoch=epoch)
        except Exception as error:  # noqa: BLE001
            errors.append(error)

    def _direct_save():
        try:
            barrier.wait(timeout=10)
            for _ in range(12):
                store.save({"conv-direct": {1: b"D" * 32}})
        except Exception as error:  # noqa: BLE001
            errors.append(error)

    threads = [
        threading.Thread(target=_through_key_manager, args=(1 + index * 100,))
        for index in range(3)
    ] + [threading.Thread(target=_direct_save) for _ in range(3)]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    alive = [thread for thread in threads if thread.is_alive()]

    assert not alive, f"{len(alive)} thread(s) hung -- probable deadlock"
    assert not errors, errors
