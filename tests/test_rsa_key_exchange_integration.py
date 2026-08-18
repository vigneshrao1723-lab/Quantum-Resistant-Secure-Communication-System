"""
End-to-end verification of the RSA key-exchange path.

config.py offers two key-exchange algorithms -- "KYBER" (ML-KEM-768,
the default and the project's post-quantum path) and "RSA" (classical
RSA-2048, kept for the classical-vs-post-quantum comparison). Every
other test in this suite runs under the default, so two production
branches had never actually executed:

    ClientSession.establish_session_key()  the else: branch, which
                                           generates a 32-byte AES key
                                           and wraps it with RSA-OAEP
    ClientSession.handle_session_key()     the else: branch, which
                                           base64-decodes and unwraps
                                           it with the recipient's RSA
                                           private key

RSA existed and its primitives were unit-tested, but the complete
flow -- key exchange, server relay, encrypted message, plaintext
recovery -- was unproven. Since RSA exists precisely to be compared
against Kyber, a comparison path that has never been run end to end is
not a sound basis for that comparison.

These tests run the real thing: real TLS sockets against the real
server accept loop, real ClientSession objects, real authentication,
real epoch reservation over the request/response protocol, and real
RSA-OAEP wrapping. Nothing is mocked, stubbed, or bypassed.

Activating RSA
--------------
crypto/key_manager.py binds the algorithm at MODULE level::

    from config import KEY_EXCHANGE_ALGORITHM
    ...
    self.algorithm = KEY_EXCHANGE_ALGORITHM.upper()

so patching ``config.KEY_EXCHANGE_ALGORITHM`` after import would be
silently ineffective -- the name crypto.key_manager already holds is
the one that matters. These tests therefore patch
``crypto.key_manager.KEY_EXCHANGE_ALGORITHM``, and must do so BEFORE
any ClientSession is constructed, because ClientSession.__init__
builds its KeyManager immediately.

monkeypatch reverts it at teardown, so the default (KYBER) cannot leak
into any other test; test_kyber_remains_the_default_algorithm asserts
that explicitly.

Run with:
    pytest tests/test_rsa_key_exchange_integration.py -v
"""

import base64
import time
import uuid

import pytest

import client.session as client_session_module
import crypto.key_manager as key_manager_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import KeyManager
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from tests.tls_test_support import start_test_server

# RSA-2048 produces a fixed 256-byte OAEP ciphertext block. ML-KEM-768
# encapsulations are 1088 bytes, so this length alone distinguishes the
# two paths on the wire.
RSA_2048_CIPHERTEXT_BYTES = 256


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "RSA Exchange Test",
            "username": f"rsax_{suffix_hint}{suffix}",
            "email": f"rsax_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = auth_service.register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete_user(username):
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


def _login_and_get_token(payload):
    db = SessionLocal()
    try:
        auth_service = AuthenticationService(db)
        result = auth_service.authenticate_user(
            LoginRequest(identifier=payload["username"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _wait_for(predicate, attempts=100, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _make_connected_session(payload):
    """A real, fully connected ClientSession -- connect() -> login() ->
    send_public_key() -> start_receiver(), the same sequence
    gui/main_window.py::start_chat_session() performs."""

    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _open_direct_chat(session, partner_username):
    """Mirrors ChatWindow.open_conversation() enough to mark a direct
    conversation current, which resolves its conversation_id
    server-side."""

    session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=partner_username,
            is_online=True,
            latest_message=None,
        )
    )


def _last_received_text(session, from_username):
    summary = session.conversation_store.get(from_username)
    if summary is None or summary.latest_message is None:
        return None
    return summary.latest_message.text


@pytest.fixture()
def rsa_alice_and_bob(running_server, monkeypatch):
    """
    Two real, fully connected ClientSessions running in RSA mode.

    Order matters: KEY_EXCHANGE_ALGORITHM is patched BEFORE any
    ClientSession is constructed, because ClientSession.__init__ builds
    its KeyManager -- and therefore reads the algorithm -- immediately.

    ``sent_packets`` records every packet the clients put on the wire,
    by wrapping (not replacing) client.session.send_message. It calls
    straight through, so nothing about the real send path changes; the
    recording only lets a test inspect what the RSA path actually
    transmitted.
    """

    _state, port = running_server

    # Must precede any ClientSession() construction.
    monkeypatch.setattr(key_manager_module, "KEY_EXCHANGE_ALGORITHM", "RSA")

    # ClientSession.connect() dials the module-level SERVER_PORT.
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    sent_packets = []
    real_send_message = client_session_module.send_message

    def recording_send_message(sock, packet):
        sent_packets.append(packet)
        return real_send_message(sock, packet)

    monkeypatch.setattr(client_session_module, "send_message", recording_send_message)

    alice_payload = _register_user("alice_")
    bob_payload = _register_user("bob_")

    alice = _make_connected_session(alice_payload)
    bob = _make_connected_session(bob_payload)

    # Both sides must have learned the other's RSA public key before a
    # session key can be wrapped for them.
    assert _wait_for(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait_for(lambda: bob.key_manager.get_public_key(alice.username) is not None)

    _open_direct_chat(alice, bob.username)
    _open_direct_chat(bob, alice.username)

    conversation_id = alice.current_conversation_id
    assert conversation_id == bob.current_conversation_id

    yield {
        "alice": alice,
        "bob": bob,
        "conversation_id": conversation_id,
        "sent_packets": sent_packets,
    }

    for session in (alice, bob):
        try:
            session.disconnect()
        except OSError:
            pass

    _delete_user(alice_payload["username"])
    _delete_user(bob_payload["username"])


# ----------------------------------------------------------------------
# 1. RSA is genuinely the active algorithm
# ----------------------------------------------------------------------

def test_rsa_is_the_active_algorithm_when_configured(monkeypatch):
    """
    The patch must actually take effect on the object the application
    uses -- not merely on config.

    The exported public key is the proof that matters: in RSA mode it
    is a PEM SubjectPublicKeyInfo block, whereas Kyber exports base64
    encapsulation-key bytes. If the patch were applied to the wrong
    name, this key would still be a Kyber one.
    """

    monkeypatch.setattr(key_manager_module, "KEY_EXCHANGE_ALGORITHM", "RSA")

    key_manager = KeyManager()

    assert key_manager.algorithm == "RSA"
    assert key_manager.public_key.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_rsa_clients_exchange_rsa_public_keys(rsa_alice_and_bob):
    """Both connected clients are in RSA mode and have cached each
    other's RSA public key -- a `cryptography` RSAPublicKey object, not
    raw Kyber bytes."""

    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_backend

    alice = rsa_alice_and_bob["alice"]
    bob = rsa_alice_and_bob["bob"]

    assert alice.key_manager.algorithm == "RSA"
    assert bob.key_manager.algorithm == "RSA"

    assert isinstance(
        alice.key_manager.get_public_key(bob.username), rsa_backend.RSAPublicKey
    )
    assert isinstance(
        bob.key_manager.get_public_key(alice.username), rsa_backend.RSAPublicKey
    )


# ----------------------------------------------------------------------
# 2-4. The complete RSA path, end to end
# ----------------------------------------------------------------------

def test_rsa_direct_session_key_exchange_and_message_round_trip(rsa_alice_and_bob):
    """
    The core test: Client A -> RSA session-key establishment -> server
    relay -> Client B -> AES-encrypted message -> plaintext recovery.

    send_chat_message() establishes the session key on demand
    (_send_encrypted_payload -> establish_session_key), which in RSA
    mode generates a 32-byte AES key, wraps it with RSA-OAEP under
    Bob's public key, reserves an epoch through the real
    request/response protocol, and relays it via the real server. Bob's
    receiver thread runs handle_session_key(), unwraps with his RSA
    private key, and stores it -- after which the AES-GCM message
    decrypts.
    """

    alice = rsa_alice_and_bob["alice"]
    bob = rsa_alice_and_bob["bob"]
    conversation_id = rsa_alice_and_bob["conversation_id"]

    # Neither side has a session key yet.
    assert alice.key_manager.get_key(conversation_id) is None
    assert bob.key_manager.get_key(conversation_id) is None

    alice.send_chat_message("hello bob, over RSA")

    # The message arrives and decrypts to the exact plaintext.
    assert _wait_for(
        lambda: _last_received_text(bob, alice.username) == "hello bob, over RSA"
    ), "Bob never decrypted the RSA-keyed message"

    # Both sides converged on the same AES session key, under the same
    # epoch -- the key really travelled via RSA, it was not derived
    # independently.
    assert _wait_for(lambda: bob.key_manager.get_key(conversation_id) is not None)

    alice_key = alice.key_manager.get_key(conversation_id)
    bob_key = bob.key_manager.get_key(conversation_id)

    assert alice_key is not None
    assert alice_key == bob_key
    assert len(alice_key) == 32
    assert alice.key_manager.current_epoch(
        conversation_id
    ) == bob.key_manager.current_epoch(conversation_id)


def test_rsa_reply_also_round_trips(rsa_alice_and_bob):
    """The reverse direction, over the key established by the first
    exchange -- proving the RSA-delivered key works for both parties,
    not just the originator."""

    alice = rsa_alice_and_bob["alice"]
    bob = rsa_alice_and_bob["bob"]

    alice.send_chat_message("first, from alice")
    assert _wait_for(
        lambda: _last_received_text(bob, alice.username) == "first, from alice"
    )

    bob.send_chat_message("reply, from bob")
    assert _wait_for(
        lambda: _last_received_text(alice, bob.username) == "reply, from bob"
    )


def test_rsa_session_key_packet_declares_rsa(rsa_alice_and_bob):
    """
    The packet on the wire must declare algorithm="RSA" and carry a
    payload that is genuinely an RSA-OAEP block.

    Length is the discriminator: RSA-2048 OAEP output is exactly 256
    bytes, while an ML-KEM-768 encapsulation is 1088. A Kyber packet
    could therefore never satisfy this assertion.
    """

    alice = rsa_alice_and_bob["alice"]
    bob = rsa_alice_and_bob["bob"]
    sent_packets = rsa_alice_and_bob["sent_packets"]

    alice.send_chat_message("triggering the key exchange")
    assert _wait_for(
        lambda: _last_received_text(bob, alice.username) == "triggering the key exchange"
    )

    session_key_packets = [
        p
        for p in sent_packets
        if p.get("type") == "key_exchange" and p.get("operation") == "session_key"
    ]

    assert session_key_packets, "no session_key packet was ever sent"

    packet = session_key_packets[-1]

    assert packet["algorithm"] == "RSA"
    assert packet["algorithm"] != "KYBER"

    wrapped = base64.b64decode(packet["encrypted_key"])

    assert len(wrapped) == RSA_2048_CIPHERTEXT_BYTES, (
        f"expected a {RSA_2048_CIPHERTEXT_BYTES}-byte RSA-2048 OAEP block, "
        f"got {len(wrapped)} bytes"
    )


def test_rsa_wrapped_session_key_is_recoverable_only_with_the_private_key(
    rsa_alice_and_bob,
):
    """
    The wrapped payload is valid for the RSA path: Bob's own private
    key recovers exactly the AES key Alice stored, and an unrelated
    keypair cannot.
    """

    alice = rsa_alice_and_bob["alice"]
    bob = rsa_alice_and_bob["bob"]
    conversation_id = rsa_alice_and_bob["conversation_id"]
    sent_packets = rsa_alice_and_bob["sent_packets"]

    alice.send_chat_message("wrap check")
    assert _wait_for(lambda: _last_received_text(bob, alice.username) == "wrap check")

    packet = [
        p
        for p in sent_packets
        if p.get("type") == "key_exchange" and p.get("operation") == "session_key"
    ][-1]

    wrapped = base64.b64decode(packet["encrypted_key"])

    recovered = bob.key_manager.decrypt_session_key(wrapped)

    assert recovered == alice.key_manager.get_key(conversation_id)

    # A different keypair must not recover it.
    stranger = KeyManager()

    with pytest.raises(ValueError):
        stranger.decrypt_session_key(wrapped)


# ----------------------------------------------------------------------
# 5-6. The default path is untouched and restored
# ----------------------------------------------------------------------

def test_kyber_remains_the_default_algorithm():
    """
    Outside the RSA patch the project default must still be Kyber.

    Placed after the RSA tests deliberately: monkeypatch reverts its
    changes at teardown, so this also proves the RSA activation cannot
    leak into the rest of the suite. Every other test in this
    repository relies on that.
    """

    assert key_manager_module.KEY_EXCHANGE_ALGORITHM == "KYBER"

    key_manager = KeyManager()

    assert key_manager.algorithm == "KYBER"

    # Kyber exports base64 encapsulation-key bytes, never a PEM block.
    assert not key_manager.public_key.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert len(base64.b64decode(key_manager.public_key)) == 1184
