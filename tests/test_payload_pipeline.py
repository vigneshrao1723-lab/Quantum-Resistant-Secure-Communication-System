"""
Tests for the universal payload pipeline:

    Payload -> Serialization -> Encryption -> Packet -> Network

Covers:
  - domain/payload.py, domain/payload_serializer.py (round trip)
  - crypto/payload_cipher.py (generic, base64-based strategy)
  - payload/text_adapter.py (compatibility strategy) -- including the
    core compatibility claim: ciphertext produced by the adapter and
    ciphertext produced by raw AESCipher are interchangeable, in both
    directions, byte-for-byte.
  - utils/protocol.py's create_payload_packet()/create_chat_packet()

Run with:
    pytest tests/test_payload_pipeline.py -v
"""

from crypto.aes import AESCipher
from crypto.payload_cipher import decrypt_payload, encrypt_payload
from domain.payload import Payload
from domain.payload_envelope import PayloadEnvelope
from domain.payload_serializer import deserialize_payload, serialize_payload
from domain.payload_type import PayloadType
from payload.text_adapter import TextPayloadAdapter
from utils.protocol import (
    create_chat_packet,
    create_group_create_packet,
    create_group_create_result_packet,
    create_group_key_distribution_packet,
    create_payload_packet,
)

VALID_KEY = b"K" * 32


# =====================================================
# domain/payload_serializer.py
# =====================================================

def test_serialize_deserialize_text_round_trip():
    payload = Payload(payload_type=PayloadType.TEXT, content="hello quantum world")

    data = serialize_payload(payload)

    assert isinstance(data, bytes)
    assert deserialize_payload(PayloadType.TEXT, data) == "hello quantum world"


def test_serialize_handles_unicode():
    payload = Payload(payload_type=PayloadType.TEXT, content="héllo wörld 你好 🔐")

    data = serialize_payload(payload)

    assert deserialize_payload(PayloadType.TEXT, data) == "héllo wörld 你好 🔐"


def test_serialize_rejects_unknown_payload_type():
    """"image"/"voice"/"video" are real, implemented PayloadTypes since
    Phase 6/Phase 19.24 (see tests/test_file_payload_pipeline.py) --
    this guards the branch for a payload_type that is genuinely
    unimplemented, e.g. some future type before its own serializer
    branch exists. "holographic" is deliberately not a real
    PayloadType member at all, so this can never accidentally start
    passing again just because a future phase implements it."""
    payload = Payload(payload_type="holographic", content=b"not implemented yet")

    try:
        serialize_payload(payload)
        assert False, "expected ValueError"
    except ValueError:
        pass


# =====================================================
# crypto/payload_cipher.py (generic, base64-based strategy)
# =====================================================

def test_generic_encrypt_decrypt_round_trip():
    aes = AESCipher(VALID_KEY)
    payload = Payload(payload_type=PayloadType.TEXT, content="generic pipeline message")

    envelope = encrypt_payload(payload, aes)

    assert isinstance(envelope, PayloadEnvelope)
    assert envelope.payload_type == PayloadType.TEXT

    recovered = decrypt_payload(envelope, aes)

    assert recovered == "generic pipeline message"


def test_generic_pipeline_ciphertext_is_not_directly_aes_decryptable():
    """The generic strategy base64-wraps before encrypting -- decrypting
    its ciphertext with plain AESCipher (no base64-unwrap) must NOT
    yield the original text, proving it is a genuinely different wire
    format from the compatibility adapter's."""
    aes = AESCipher(VALID_KEY)
    payload = Payload(payload_type=PayloadType.TEXT, content="generic pipeline message")

    envelope = encrypt_payload(payload, aes)

    assert AESCipher(VALID_KEY).decrypt(envelope.ciphertext) != "generic pipeline message"


# =====================================================
# payload/text_adapter.py -- the compatibility layer
# =====================================================

def test_text_adapter_encrypt_decrypt_round_trip():
    aes = AESCipher(VALID_KEY)
    adapter = TextPayloadAdapter()

    envelope = adapter.encrypt("a real chat message", aes)

    assert envelope.payload_type == PayloadType.TEXT

    recovered = adapter.decrypt(envelope, AESCipher(VALID_KEY))

    assert recovered == "a real chat message"


def test_text_adapter_output_decrypts_with_raw_aescipher():
    """New messages sent through the adapter must be decryptable by
    the exact same operation the pre-existing code path always used
    -- proving no wire-format change for text."""
    aes = AESCipher(VALID_KEY)
    adapter = TextPayloadAdapter()

    envelope = adapter.encrypt("byte-identical compatibility check", aes)

    assert AESCipher(VALID_KEY).decrypt(envelope.ciphertext) == (
        "byte-identical compatibility check"
    )


def test_text_adapter_decrypts_legacy_raw_aescipher_ciphertext():
    """Historical ciphertext -- encrypted before this pipeline existed,
    via a direct AESCipher.encrypt() call with no adapter involved --
    must still decrypt correctly through the adapter, with no
    migration."""
    legacy_ciphertext = AESCipher(VALID_KEY).encrypt("a message from before Phase 3")

    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT, ciphertext=legacy_ciphertext, content_metadata={}
    )

    adapter = TextPayloadAdapter()

    assert adapter.decrypt(envelope, AESCipher(VALID_KEY)) == (
        "a message from before Phase 3"
    )


def test_text_adapter_round_trip_handles_unicode():
    aes = AESCipher(VALID_KEY)
    adapter = TextPayloadAdapter()

    envelope = adapter.encrypt("héllo wörld 你好 🔐", aes)

    assert adapter.decrypt(envelope, AESCipher(VALID_KEY)) == "héllo wörld 你好 🔐"


# =====================================================
# utils/protocol.py -- Packet stage
# =====================================================

def test_create_payload_packet_shape():
    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT, ciphertext="opaque-ciphertext", content_metadata={}
    )

    packet = create_payload_packet(
        sender="alice", receiver="bob", envelope=envelope, timestamp="2026-01-01T00:00:00+00:00"
    )

    assert packet == {
        "type": "chat",
        "sender": "alice",
        "receiver": "bob",
        "conversation_id": None,
        "message": "opaque-ciphertext",
        "payload_type": PayloadType.TEXT,
        "content_metadata": None,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "epoch": None,
    }


def test_create_chat_packet_is_backward_compatible_wrapper():
    """Every pre-Phase-3 call site (19 in tests, plus the old
    ClientSession.send_chat_message() shape) keeps working unmodified:
    same positional/keyword signature, same required output fields."""
    packet = create_chat_packet(
        sender="alice", receiver="bob", message="ciphertext-blob", timestamp="ts"
    )

    assert packet["type"] == "chat"
    assert packet["sender"] == "alice"
    assert packet["receiver"] == "bob"
    assert packet["message"] == "ciphertext-blob"
    assert packet["timestamp"] == "ts"

    # New, additive fields -- present but defaulted, never required by
    # an existing caller.
    assert packet["payload_type"] == PayloadType.TEXT
    assert packet["content_metadata"] is None


def test_create_chat_packet_output_decrypts_exactly_like_before():
    """The wrapper must not alter the actual ciphertext it carries --
    it repackages an already-encrypted string, it does not re-encrypt
    it."""
    ciphertext = AESCipher(VALID_KEY).encrypt("wrapped through create_chat_packet")

    packet = create_chat_packet(sender="alice", receiver="bob", message=ciphertext)

    assert AESCipher(VALID_KEY).decrypt(packet["message"]) == (
        "wrapped through create_chat_packet"
    )


# =====================================================
# Phase 4 (Secure Group Messaging Foundation) -- addressing
# =====================================================

def test_create_payload_packet_supports_conversation_id_addressing():
    """A group message reuses the exact same packet shape and "chat"
    type -- only which of receiver/conversation_id is populated
    differs. No duplicate packet type."""
    envelope = PayloadEnvelope(
        payload_type=PayloadType.TEXT, ciphertext="group-ciphertext", content_metadata={}
    )

    packet = create_payload_packet(
        sender="alice", envelope=envelope, conversation_id="conv-123"
    )

    assert packet["type"] == "chat"
    assert packet["receiver"] is None
    assert packet["conversation_id"] == "conv-123"
    assert packet["message"] == "group-ciphertext"


def test_create_group_create_packet_shape():
    packet = create_group_create_packet(
        sender="alice", name="Trio", member_usernames=["bob", "carol"]
    )

    assert packet == {
        "type": "group_create",
        "sender": "alice",
        "name": "Trio",
        "members": ["bob", "carol"],
    }


def test_create_group_create_result_packet_shape():
    packet = create_group_create_result_packet(
        conversation_id="conv-123", name="Trio", creator="alice", members=["alice", "bob"]
    )

    assert packet == {
        "type": "group_create_result",
        "conversation_id": "conv-123",
        "name": "Trio",
        "creator": "alice",
        "members": ["alice", "bob"],
    }


def test_create_group_key_distribution_packet_shape():
    packet = create_group_key_distribution_packet(
        sender="alice",
        conversation_id="conv-123",
        recipient="bob",
        encapsulation="kyber-ct",
        wrapped_key="wrapped-b64",
    )

    assert packet == {
        "type": "group_key_distribution",
        "sender": "alice",
        "conversation_id": "conv-123",
        "recipient": "bob",
        "encapsulation": "kyber-ct",
        "wrapped_key": "wrapped-b64",
        "epoch": 1,
    }
