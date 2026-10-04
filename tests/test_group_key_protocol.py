"""
Group-key-distribution ML-DSA origin authentication --
crypto/group_key_protocol.py.

Pure crypto/canonicalization-level tests, mirroring tests/
test_identity_protocol.py's and tests/test_message_protocol.py's
structure for the group-key-signing counterpart: no ClientSession, no
network, no server. Proves canonical_group_key_payload()'s field
binding is unambiguous, that domain separation holds against the OTHER
TWO signed-payload purposes (identity announcements, messages), and
that every required forgery scenario (Phase 13 fail-closed tests 1-14,
the crypto-level subset) is independently detected.

End-to-end wire-level attacks (a real ClientSession/server relay) are
covered separately in tests/test_group_key_authentication.py.

Run with:
    pytest tests/test_group_key_protocol.py -v
"""

import pytest

from crypto.group_key_protocol import (
    GROUP_KEY_PAYLOAD_PURPOSE,
    canonical_group_key_payload,
    sign_group_key_payload,
    verify_group_key_payload,
)
from crypto.identity_protocol import (
    IDENTITY_PAYLOAD_PURPOSE,
    sign_identity_payload,
    verify_identity_payload,
)
from crypto.message_protocol import (
    MESSAGE_PAYLOAD_PURPOSE,
    sign_message_payload,
    verify_message_payload,
)
from crypto.ml_dsa import ML_DSA_65_SIGNATURE_BYTES, MLDSASigner


def _signer():
    signer = MLDSASigner()
    signer.generate_keys()
    return signer


def _delivery(**overrides):
    fields = {
        "sender": "alice",
        "conversation_id": "conv-123",
        "recipient": "bob",
        "encapsulation": "a2VtLWVuY2Fwc3VsYXRpb24=",
        "wrapped_key": "d3JhcHBlZC1rZXktY2lwaGVydGV4dA==",
        "epoch": 1,
    }
    fields.update(overrides)
    return fields


# ========================================================================
# Canonicalization
# ========================================================================


def test_fixed_test_vector_matches_the_documented_construction():
    fields = _delivery()
    expected = (
        GROUP_KEY_PAYLOAD_PURPOSE
        + len(b"alice").to_bytes(4, "big") + b"alice"
        + len(b"conv-123").to_bytes(4, "big") + b"conv-123"
        + len(b"bob").to_bytes(4, "big") + b"bob"
        + len(fields["encapsulation"].encode()).to_bytes(4, "big") + fields["encapsulation"].encode()
        + len(fields["wrapped_key"].encode()).to_bytes(4, "big") + fields["wrapped_key"].encode()
        + (1).to_bytes(4, "big")
    )

    assert canonical_group_key_payload(**fields) == expected


def test_rsa_mode_none_encapsulation_canonicalizes_as_empty():
    """crypto/key_manager.py::wrap_key_for_member() returns
    encapsulation=None in RSA mode -- must canonicalize identically to
    an explicit empty string, so a sender (which has None) and a
    receiver (which also reads None off the packet) always agree."""

    with_none = canonical_group_key_payload(**_delivery(encapsulation=None))
    with_empty = canonical_group_key_payload(**_delivery(encapsulation=""))

    assert with_none == with_empty


def test_epoch_none_and_epoch_1_canonicalize_identically():
    assert canonical_group_key_payload(**_delivery(epoch=None)) == (
        canonical_group_key_payload(**_delivery(epoch=1))
    )


def test_different_epoch_produces_a_different_payload():
    assert canonical_group_key_payload(**_delivery(epoch=1)) != (
        canonical_group_key_payload(**_delivery(epoch=2))
    )


def test_different_recipient_produces_a_different_payload():
    """The packet is inherently per-recipient -- re-addressing a
    genuinely-signed delivery to a different member must change the
    canonical payload."""

    assert canonical_group_key_payload(**_delivery(recipient="bob")) != (
        canonical_group_key_payload(**_delivery(recipient="charlie"))
    )


def test_reordering_fields_cannot_collide():
    """sender/conversation_id/recipient are all plain strings -- a
    swap between any two of them must not canonicalize identically."""

    a = canonical_group_key_payload(**_delivery(sender="X", conversation_id="Y", recipient="Z"))
    b = canonical_group_key_payload(**_delivery(sender="Y", conversation_id="Z", recipient="X"))

    assert a != b


# ========================================================================
# Domain separation from the OTHER TWO signed-payload purposes
# ========================================================================


def test_domain_separation_from_identity_purpose():
    assert GROUP_KEY_PAYLOAD_PURPOSE != IDENTITY_PAYLOAD_PURPOSE


def test_domain_separation_from_message_purpose():
    assert GROUP_KEY_PAYLOAD_PURPOSE != MESSAGE_PAYLOAD_PURPOSE


def test_a_valid_message_signature_does_not_verify_as_a_group_key_signature():
    """A signature genuinely produced for an ordinary chat message
    must not authenticate a group-key-distribution packet, even when
    an attacker tries to line up as many fields as coincidentally
    overlap between the two payload shapes."""

    signer = _signer()

    message_signature = sign_message_payload(
        signer, "alice", "bob", None, "text", "d3JhcHBlZC1rZXktY2lwaGVydGV4dA==", None, 1
    )

    assert verify_group_key_payload(
        **_delivery(sender="alice", recipient="bob", epoch=1),
        signature=message_signature,
        signing_public_key=signer.export_public_key(),
    ) is False


def test_a_valid_identity_signature_does_not_verify_as_a_group_key_signature():
    """A signature genuinely produced for a public identity
    announcement must not authenticate a group-key-distribution
    packet."""

    signer = _signer()

    identity_signature = sign_identity_payload(
        signer, "alice", "a2VtLWVuY2Fwc3VsYXRpb24=", signer.export_public_key()
    )

    assert verify_group_key_payload(
        **_delivery(sender="alice"),
        signature=identity_signature,
        signing_public_key=signer.export_public_key(),
    ) is False


def test_a_valid_group_key_signature_does_not_verify_as_a_message_signature():
    """And the reverse direction -- proves the separation is mutual,
    not accidentally one-directional."""

    signer = _signer()
    fields = _delivery()

    group_key_signature = sign_group_key_payload(signer, **fields)

    assert verify_message_payload(
        fields["sender"], fields["recipient"], None, "text", fields["wrapped_key"], None,
        fields["epoch"], group_key_signature, signer.export_public_key(),
    ) is False


def test_a_valid_group_key_signature_does_not_verify_as_an_identity_signature():
    signer = _signer()
    fields = _delivery()

    group_key_signature = sign_group_key_payload(signer, **fields)

    assert verify_identity_payload(
        fields["sender"], fields["wrapped_key"], signer.export_public_key(),
        group_key_signature,
    ) is False


# ========================================================================
# Sign / verify round trip
# ========================================================================


def test_sign_then_verify_round_trip_succeeds():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)

    assert isinstance(signature, bytes)
    assert len(signature) == ML_DSA_65_SIGNATURE_BYTES
    assert verify_group_key_payload(
        **fields, signature=signature, signing_public_key=signer.export_public_key()
    ) is True


def test_rsa_mode_round_trip_succeeds():
    signer = _signer()
    fields = _delivery(encapsulation=None)
    signature = sign_group_key_payload(signer, **fields)

    assert verify_group_key_payload(
        **fields, signature=signature, signing_public_key=signer.export_public_key()
    ) is True


# ========================================================================
# Fail-closed forgery tests (Phase 13, crypto-level subset)
# ========================================================================


def test_forgery_2_modified_encrypted_group_key_fails():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)

    tampered = dict(fields, wrapped_key=fields["wrapped_key"][:-1] + "X")
    assert verify_group_key_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_3_modified_sender_fails():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)

    tampered = dict(fields, sender="mallory")
    assert verify_group_key_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_4_modified_group_identity_fails():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)

    tampered = dict(fields, conversation_id="a-different-conversation")
    assert verify_group_key_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_5_modified_recipient_identity_fails():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)

    tampered = dict(fields, recipient="charlie")
    assert verify_group_key_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_6_modified_epoch_fails():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)

    tampered = dict(fields, epoch=2)
    assert verify_group_key_payload(
        **tampered, signature=signature, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_7_random_signature_fails():
    fields = _delivery()
    signer = _signer()
    garbage = b"\x00" * ML_DSA_65_SIGNATURE_BYTES

    assert verify_group_key_payload(
        **fields, signature=garbage, signing_public_key=signer.export_public_key()
    ) is False


def test_forgery_8_truncated_signature_raises():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)

    with pytest.raises(ValueError):
        verify_group_key_payload(
            **fields, signature=signature[:-4], signing_public_key=signer.export_public_key()
        )


def test_forgery_9_extra_signature_bytes_raises():
    signer = _signer()
    fields = _delivery()
    signature = sign_group_key_payload(signer, **fields)
    padded = signature + b"\x00" * 16

    with pytest.raises(ValueError):
        verify_group_key_payload(
            **fields, signature=padded, signing_public_key=signer.export_public_key()
        )


def test_forgery_10_signature_from_another_peer_fails():
    fields = _delivery()
    real_signer = _signer()
    other_peer_signer = _signer()

    signature_by_other_peer = sign_group_key_payload(other_peer_signer, **fields)

    assert verify_group_key_payload(
        **fields, signature=signature_by_other_peer,
        signing_public_key=real_signer.export_public_key(),
    ) is False


def test_forgery_11_attacker_own_key_and_signature_cannot_authenticate_as_the_real_peer():
    """The core CRITICAL TRUST RULE proof at the crypto layer: an
    attacker with their own perfectly valid ML-DSA keypair can sign a
    group-key delivery consistently under THEIR OWN key -- but a
    caller resolving the verification key from the receiver's OWN,
    already-VERIFIED peer-identity state (never from the packet) would
    never pass the attacker's key in for a peer whose real, trusted key
    is different."""

    real_peer_signer = _signer()
    attacker_signer = _signer()
    fields = _delivery()

    attacker_signature = sign_group_key_payload(attacker_signer, **fields)

    assert verify_group_key_payload(
        **fields, signature=attacker_signature,
        signing_public_key=real_peer_signer.export_public_key(),
    ) is False


def test_malformed_signing_public_key_raises():
    fields = _delivery()
    signer = _signer()
    signature = sign_group_key_payload(signer, **fields)

    with pytest.raises(ValueError):
        verify_group_key_payload(**fields, signature=signature, signing_public_key=b"not a key")


def test_non_bytes_signature_raises_typeerror():
    fields = _delivery()
    signer = _signer()

    with pytest.raises(TypeError):
        verify_group_key_payload(
            **fields, signature="not bytes", signing_public_key=signer.export_public_key()
        )
