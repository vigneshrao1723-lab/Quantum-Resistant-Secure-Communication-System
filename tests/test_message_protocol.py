"""
Message-level ML-DSA origin authentication -- crypto/message_protocol.py.

Pure crypto/canonicalization-level tests, mirroring tests/
test_identity_protocol.py's structure for the message-signing
counterpart: no ClientSession, no network, no server. Proves
canonical_message_payload()'s field binding is unambiguous, and that
sign_message_payload()/verify_message_payload() correctly detect every
required forgery scenario (Phase 12B forgery tests 1-11, the crypto-
level subset; end-to-end wire-level forgery against a real
ClientSession is covered in tests/test_message_authentication.py).

Run with:
    pytest tests/test_message_protocol.py -v
"""

import pytest

from crypto.message_protocol import (
    MESSAGE_PAYLOAD_PURPOSE,
    canonical_message_payload,
    sign_message_payload,
    verify_message_payload,
)
from crypto.ml_dsa import ML_DSA_65_SIGNATURE_BYTES, MLDSASigner
from domain.payload_type import PayloadType


def _signer():
    signer = MLDSASigner()
    signer.generate_keys()
    return signer


def _message(**overrides):
    fields = {
        "sender": "alice",
        "receiver": "bob",
        "conversation_id": None,
        "payload_type": PayloadType.TEXT,
        "ciphertext": "ZW5jcnlwdGVkLWNpcGhlcnRleHQ=",
        "content_metadata": None,
        "epoch": 1,
    }
    fields.update(overrides)
    return fields


# ========================================================================
# Canonicalization
# ========================================================================


def test_fixed_test_vector_matches_the_documented_construction():
    fields = _message()
    expected = (
        MESSAGE_PAYLOAD_PURPOSE
        + len(b"alice").to_bytes(4, "big") + b"alice"
        + len(b"bob").to_bytes(4, "big") + b"bob"
        + len(b"").to_bytes(4, "big") + b""
        + len(b"text").to_bytes(4, "big") + b"text"
        + len(fields["ciphertext"].encode()).to_bytes(4, "big") + fields["ciphertext"].encode()
        + len(b"{}").to_bytes(4, "big") + b"{}"
        + (1).to_bytes(4, "big")
    )

    assert canonical_message_payload(**fields) == expected


def test_direct_and_group_addressing_cannot_collide():
    """A direct message to receiver="X" must not canonicalize the same
    as a group message to conversation_id="X" -- the two fields are
    bound separately, never collapsed into one "recipient" slot."""

    direct = canonical_message_payload(**_message(receiver="X", conversation_id=None))
    group = canonical_message_payload(**_message(receiver=None, conversation_id="X"))

    assert direct != group


def test_content_metadata_none_and_empty_dict_canonicalize_identically():
    """create_payload_packet() puts None on the wire for an empty
    metadata dict; PayloadEnvelope defaults to {} on receipt -- both
    representations of "no metadata" must canonicalize identically, or
    a genuine text message would fail verification purely from this
    representational difference between sender and receiver."""

    with_none = canonical_message_payload(**_message(content_metadata=None))
    with_empty = canonical_message_payload(**_message(content_metadata={}))

    assert with_none == with_empty


def test_content_metadata_is_canonicalized_deterministically_regardless_of_key_order():
    a = canonical_message_payload(
        **_message(content_metadata={"filename": "x.png", "mime_type": "image/png", "size_bytes": 10})
    )
    b = canonical_message_payload(
        **_message(content_metadata={"size_bytes": 10, "filename": "x.png", "mime_type": "image/png"})
    )

    assert a == b


def test_epoch_none_and_epoch_1_canonicalize_identically():
    """Matches handle_chat()'s own "epoch = packet.get('epoch') or 1"
    convention and create_payload_packet()'s "epoch: None" default for
    an omitted epoch -- both sides must agree these mean the same
    thing."""

    assert canonical_message_payload(**_message(epoch=None)) == canonical_message_payload(
        **_message(epoch=1)
    )


def test_different_epoch_produces_a_different_payload():
    assert canonical_message_payload(**_message(epoch=1)) != canonical_message_payload(
        **_message(epoch=2)
    )


def test_different_purpose_produces_a_different_payload():
    """Domain separation from crypto/identity_protocol.py's identity-
    announcement purpose (and any other future signed-payload type) --
    a signature produced for THAT purpose must never be mistakable for
    one produced for this one."""

    real = canonical_message_payload(**_message())
    other = canonical_message_payload(**_message(), purpose=b"qrscs-public-identity-v1")

    assert real != other


# ========================================================================
# Sign / verify round trip
# ========================================================================


def test_sign_then_verify_round_trip_succeeds():
    signer = _signer()
    fields = _message()
    signature = sign_message_payload(signer, **fields)

    assert isinstance(signature, bytes)
    assert len(signature) == ML_DSA_65_SIGNATURE_BYTES
    assert verify_message_payload(
        **fields, signature=signature, signing_public_key=signer.export_public_key()
    ) is True


def test_group_message_round_trip_succeeds():
    signer = _signer()
    fields = _message(receiver=None, conversation_id="conv-123")
    signature = sign_message_payload(signer, **fields)

    assert verify_message_payload(
        **fields, signature=signature, signing_public_key=signer.export_public_key()
    ) is True


def test_attachment_message_round_trip_succeeds():
    signer = _signer()
    fields = _message(
        payload_type=PayloadType.IMAGE,
        content_metadata={"filename": "cat.png", "mime_type": "image/png", "size_bytes": 4096},
    )
    signature = sign_message_payload(signer, **fields)

    assert verify_message_payload(
        **fields, signature=signature, signing_public_key=signer.export_public_key()
    ) is True


# ========================================================================
# Forgery tests (Phase 12B, crypto-level subset)
# ========================================================================


def test_forgery_2_modified_ciphertext_fails():
    signer = _signer()
    fields = _message()
    signature = sign_message_payload(signer, **fields)

    tampered = dict(fields, ciphertext=fields["ciphertext"][:-1] + "X")
    assert verify_message_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_3_modified_sender_fails():
    signer = _signer()
    fields = _message()
    signature = sign_message_payload(signer, **fields)

    tampered = dict(fields, sender="mallory")
    assert verify_message_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_4_modified_recipient_fails():
    signer = _signer()
    fields = _message()
    signature = sign_message_payload(signer, **fields)

    tampered = dict(fields, receiver="charlie")
    assert verify_message_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_4b_modified_conversation_id_fails():
    signer = _signer()
    fields = _message(receiver=None, conversation_id="conv-123")
    signature = sign_message_payload(signer, **fields)

    tampered = dict(fields, conversation_id="conv-456")
    assert verify_message_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_6_modified_encryption_metadata_fails():
    signer = _signer()
    fields = _message(
        payload_type=PayloadType.FILE,
        content_metadata={"filename": "a.txt", "mime_type": "text/plain", "size_bytes": 5},
    )
    signature = sign_message_payload(signer, **fields)

    tampered = dict(
        fields,
        content_metadata={"filename": "a.txt", "mime_type": "text/plain", "size_bytes": 999999},
    )
    assert verify_message_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_6b_modified_payload_type_fails():
    """Type confusion: an attacker must not be able to take a genuine
    TEXT message's ciphertext+signature and relabel it as a FILE (or
    vice versa)."""

    signer = _signer()
    fields = _message(payload_type=PayloadType.TEXT)
    signature = sign_message_payload(signer, **fields)

    tampered = dict(fields, payload_type=PayloadType.FILE)
    assert verify_message_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_6c_modified_epoch_fails():
    signer = _signer()
    fields = _message(epoch=1)
    signature = sign_message_payload(signer, **fields)

    tampered = dict(fields, epoch=2)
    assert verify_message_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_7_signature_replaced_with_random_bytes_fails():
    fields = _message()
    signer = _signer()
    garbage = b"\x00" * ML_DSA_65_SIGNATURE_BYTES

    assert verify_message_payload(
        **fields, signature=garbage, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_8_truncated_signature_raises():
    signer = _signer()
    fields = _message()
    signature = sign_message_payload(signer, **fields)

    with pytest.raises(ValueError):
        verify_message_payload(
            **fields, signature=signature[:-4], signing_public_key=signer.export_public_key()
        )


def test_forgery_9_signature_from_another_peer_fails():
    fields = _message()
    real_signer = _signer()
    other_peer_signer = _signer()

    signature_by_other_peer = sign_message_payload(other_peer_signer, **fields)

    assert verify_message_payload(
        **fields, signature=signature_by_other_peer, signing_public_key=real_signer.export_public_key()
    ) is False


def test_forgery_10_valid_signature_but_ciphertext_replaced_fails():
    """A signature that is genuinely valid for the sender's OWN
    message must not also validate a completely different message
    (attacker-substituted ciphertext) just because both happen to be
    signed by the same real key -- the signature is bound to THIS
    exact ciphertext, not merely "came from a key that signs things"."""

    signer = _signer()
    fields = _message()
    signature = sign_message_payload(signer, **fields)

    attacker_ciphertext_fields = dict(fields, ciphertext="YXR0YWNrZXItY2hvc2VuLWNpcGhlcnRleHQ=")
    assert verify_message_payload(
        **attacker_ciphertext_fields, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_11_attacker_own_key_cannot_authenticate_as_the_real_peer():
    """The core CRITICAL TRUST RULE proof at the crypto layer: an
    attacker with their own perfectly valid ML-DSA keypair can sign a
    message consistently under THEIR OWN key -- but verify_message_
    payload() only ever answers "does this verify under the key I was
    given", and a caller resolving the verification key from the
    receiver's OWN peer-identity state (never from the packet) would
    never pass the attacker's key in for a peer whose real, trusted key
    is different. Proven here at the primitive level: the attacker's
    self-consistent signature does not verify under the REAL peer's
    key."""

    real_peer_signer = _signer()
    attacker_signer = _signer()
    fields = _message()

    attacker_signature = sign_message_payload(attacker_signer, **fields)

    assert verify_message_payload(
        **fields, signature=attacker_signature, signing_public_key=real_peer_signer.export_public_key()
    ) is False
