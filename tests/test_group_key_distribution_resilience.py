"""
Regression tests for group key distribution robustness (D6).

ClientSession._distribute_group_key() wraps the group key once per
recipient. Before this fix, an unusable public key raised straight out
of the loop, so a single bad recipient silently truncated distribution:
every member after them in the list never received that epoch's key,
while the rotation was still reported complete via
group_key_rotation_complete. The result was a group permanently split
across key epochs, with no signal that anything had gone wrong.

Why an unusable key can still reach distribution, even after D6.5:
D6.5 -- Public-Key Input Validation made KyberKEM.import_public_key()
reject non-Base64 and wrong-length key material at handle_public_key()
time, so obviously-garbage keys are no longer cached at all. Length
validation is not completeness validation, though. A key of exactly
ML_KEM_768_PUBLIC_KEY_BYTES whose contents are not a well-formed
encapsulation key passes import and is only rejected later, by
ML-KEM's own modulus check, during encapsulation:

    malformed encapsulation key contents -> ValueError
    non-bytes key material               -> TypeError

Those two are exactly what _distribute_group_key() catches, per
recipient, around the wrapping call alone. Anything else stays
uncaught: a programming error must not be disguised as a bad peer key.

The two layers are complementary, and both are tested: D6.5 rejects
early where the format is knowable (tests/test_public_key_validation.py),
and this module proves the failure is contained per-recipient where it
is not.

These tests drive _distribute_group_key() directly with a stub key
manager, so they assert the loop's control flow precisely -- which
recipients were wrapped, which were skipped, and exactly what went out
on the wire -- without needing a live server, real Kyber keys, or a
GUI. The end-to-end group flows (creation, add-member, leave/rotation)
are covered by the existing integration suites and by
tests/test_group_key_distribution_authorization.py.

Run with:
    pytest tests/test_group_key_distribution_resilience.py -v
"""

import base64

import pytest

from client.session import ClientSession
from crypto.key_manager import fingerprint_public_key
from storage.secure_key_store import SecureKeyStore


class _StubKeyManager:
    """
    Minimal stand-in for crypto/key_manager.py::KeyManager, exposing
    only what _distribute_group_key() actually uses.

    ``behaviors`` maps a member name to what wrap_key_for_member()
    should do for them:
        "ok"          -> return a deterministic (encapsulation, wrapped)
        "missing"     -> get_public_key() returns None (never wrapped)
        ValueError    -> raise that exception class from wrapping
        TypeError     -> raise that exception class from wrapping

    Every wrap attempt is recorded so a test can assert that a skipped
    recipient really was skipped rather than merely failing quietly.
    """

    def __init__(self, behaviors):
        self.behaviors = behaviors
        self.wrap_attempts = []

    def get_public_key(self, username):
        if self.behaviors.get(username) == "missing":
            return None
        return b"stub-public-key"

    def wrap_key_for_member(self, username, key_bytes):
        self.wrap_attempts.append(username)

        behavior = self.behaviors.get(username, "ok")

        if isinstance(behavior, type) and issubclass(behavior, Exception):
            raise behavior(f"simulated unusable key for {username}")

        return f"encapsulation-for-{username}", f"wrapped-for-{username}"


@pytest.fixture()
def session_and_sent(monkeypatch, tmp_path):
    """
    A bare ClientSession with the network stubbed out. Returns the
    session plus the list every outgoing packet lands in, so tests
    assert on real create_group_key_distribution_packet() output
    rather than on a mock's call args.

    Server-Untrusted Identity Verification, Stage 3: _distribute_group_key()
    now skips any recipient who is not explicitly VERIFIED in
    session.key_store, before it ever reaches wrap_key_for_member() --
    on top of, not instead of, the pre-existing missing-key/unusable-key
    handling this module exists to test. A bare ClientSession() never
    unlocks a key store (that normally happens inside
    authenticate_credentials()), so a real, isolated, on-disk
    SecureKeyStore is unlocked here; individual tests verify whichever
    recipients they need to actually reach the wrapping call.
    """

    session = ClientSession()
    session.username = "distributor"
    session.client_socket = object()  # never touched; send is stubbed
    session.key_store = SecureKeyStore(
        "distribution-resilience-test-user", storage_dir=tmp_path / "keystore"
    )
    session.key_store.unlock("Str0ng!Passw0rd")

    sent = []

    monkeypatch.setattr(
        "client.session.send_message",
        lambda _socket, packet: sent.append(packet),
    )

    return session, sent


def _verify_stub_recipients(session, *usernames):
    """Marks each of ``usernames`` VERIFIED, using the fingerprint of
    _StubKeyManager.get_public_key()'s fixed b"stub-public-key" --
    the same raw value every non-"missing" stub recipient's key
    resolves to, so this matches what a real handle_public_key() ->
    verify_peer_fingerprint() flow would have recorded."""

    fingerprint = fingerprint_public_key(b"stub-public-key")
    for username in usernames:
        session.key_store.verify_peer_fingerprint(username, fingerprint)


def _recipients_of(sent):
    return [packet["recipient"] for packet in sent]


# ----------------------------------------------------------------------
# 5. All valid keys -- existing behavior must be untouched
# ----------------------------------------------------------------------

def test_all_valid_recipients_receive_the_key(session_and_sent):
    session, sent = session_and_sent
    session.key_manager = _StubKeyManager({})
    _verify_stub_recipients(session, "alice", "bob", "carol")

    session._distribute_group_key("conv-1", b"group-key", 1, ["alice", "bob", "carol"])

    assert _recipients_of(sent) == ["alice", "bob", "carol"]

    for packet in sent:
        member = packet["recipient"]
        assert packet["type"] == "group_key_distribution"
        assert packet["conversation_id"] == "conv-1"
        assert packet["sender"] == "distributor"
        assert packet["epoch"] == 1
        assert packet["encapsulation"] == f"encapsulation-for-{member}"
        assert packet["wrapped_key"] == f"wrapped-for-{member}"


# ----------------------------------------------------------------------
# 1-3. A malformed key must not stop the recipients after it
# ----------------------------------------------------------------------

@pytest.mark.parametrize("bad_error", [ValueError, TypeError])
@pytest.mark.parametrize(
    ("recipients", "bad_member", "expected_delivered"),
    [
        (["bad", "good1", "good2"], "bad", ["good1", "good2"]),
        (["good1", "bad", "good2"], "bad", ["good1", "good2"]),
        (["good1", "good2", "bad"], "bad", ["good1", "good2"]),
    ],
    ids=["first", "middle", "last"],
)
def test_unusable_key_is_skipped_and_others_still_receive(
    session_and_sent, recipients, bad_member, expected_delivered, bad_error
):
    """1 + 2 + 3. Position-independent: whichever recipient carries the
    unusable key, every other recipient is still served."""

    session, sent = session_and_sent
    session.key_manager = _StubKeyManager({bad_member: bad_error})
    _verify_stub_recipients(session, *recipients)

    session._distribute_group_key("conv-1", b"group-key", 4, recipients)

    assert _recipients_of(sent) == expected_delivered
    assert bad_member not in _recipients_of(sent)

    # The bad member really was attempted (not skipped by the
    # missing-key branch), and every recipient was attempted exactly
    # once -- proving the loop ran to completion.
    assert session.key_manager.wrap_attempts == recipients

    for packet in sent:
        assert packet["epoch"] == 4
        assert packet["wrapped_key"] == f"wrapped-for-{packet['recipient']}"


def test_every_recipient_unusable_sends_nothing_but_does_not_raise(session_and_sent):
    session, sent = session_and_sent
    session.key_manager = _StubKeyManager(
        {"a": ValueError, "b": TypeError, "c": ValueError}
    )
    _verify_stub_recipients(session, "a", "b", "c")

    session._distribute_group_key("conv-1", b"group-key", 2, ["a", "b", "c"])

    assert sent == []
    assert session.key_manager.wrap_attempts == ["a", "b", "c"]


# ----------------------------------------------------------------------
# 4. Missing public key -- pre-existing skip behavior unchanged
# ----------------------------------------------------------------------

def test_missing_public_key_is_still_skipped_without_wrapping(session_and_sent):
    session, sent = session_and_sent
    session.key_manager = _StubKeyManager({"offline": "missing"})
    _verify_stub_recipients(session, "alice", "bob")

    session._distribute_group_key(
        "conv-1", b"group-key", 1, ["alice", "offline", "bob"]
    )

    assert _recipients_of(sent) == ["alice", "bob"]

    # The missing-key branch must short-circuit BEFORE wrapping --
    # this is the behavior that already existed and must not regress.
    assert session.key_manager.wrap_attempts == ["alice", "bob"]


def test_missing_and_unusable_keys_mix_correctly(session_and_sent):
    session, sent = session_and_sent
    session.key_manager = _StubKeyManager(
        {"offline": "missing", "corrupt": ValueError}
    )
    _verify_stub_recipients(session, "alice", "corrupt", "bob")

    session._distribute_group_key(
        "conv-1", b"group-key", 3, ["offline", "alice", "corrupt", "bob"]
    )

    assert _recipients_of(sent) == ["alice", "bob"]
    assert session.key_manager.wrap_attempts == ["alice", "corrupt", "bob"]


# ----------------------------------------------------------------------
# Unexpected programming errors must NOT be swallowed
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "unexpected", [AttributeError, KeyError, RuntimeError, ZeroDivisionError]
)
def test_unexpected_errors_still_propagate(session_and_sent, unexpected):
    """The handler is deliberately narrow. A bug inside the crypto layer
    must surface loudly rather than be reported as a bad peer key --
    otherwise this fix would convert every future defect into a silent,
    per-member distribution failure."""

    session, _sent = session_and_sent
    session.key_manager = _StubKeyManager({"boom": unexpected})
    _verify_stub_recipients(session, "boom")

    with pytest.raises(unexpected):
        session._distribute_group_key("conv-1", b"group-key", 1, ["boom", "alice"])


# ----------------------------------------------------------------------
# The failure is reported, not silently dropped
# ----------------------------------------------------------------------

def test_unusable_key_is_logged_as_a_warning(session_and_sent, caplog):
    session, _sent = session_and_sent
    session.key_manager = _StubKeyManager({"corrupt": ValueError})
    _verify_stub_recipients(session, "corrupt")

    with caplog.at_level("WARNING"):
        session._distribute_group_key("conv-1", b"group-key", 7, ["corrupt", "alice"])

    warnings = " ".join(
        record.getMessage()
        for record in caplog.records
        if record.levelname == "WARNING"
    )

    assert "corrupt" in warnings
    assert "conv-1" in warnings
    assert "7" in warnings


# ----------------------------------------------------------------------
# Real key material, no stub: the reachable production failure
# ----------------------------------------------------------------------

def test_right_length_but_invalid_kyber_key_does_not_stop_distribution(
    session_and_sent,
):
    """
    The production scenario that survives D6.5, using the REAL
    KeyManager and real ML-KEM.

    D6.5 validates Base64 and length at import, so obviously-garbage
    keys never reach distribution any more. Length is not completeness,
    though: a key of exactly ML_KEM_768_PUBLIC_KEY_BYTES whose contents
    are not a well-formed encapsulation key passes import and is only
    rejected by ML-KEM's own modulus check during encapsulation. That
    is precisely the case this guard still has to contain -- and it
    proves the D6.4 per-recipient handling is load-bearing rather than
    redundant after D6.5.
    """

    import os

    from crypto.key_manager import KeyManager
    from crypto.kyber import ML_KEM_768_PUBLIC_KEY_BYTES, KyberKEM

    session, sent = session_and_sent

    key_manager = KeyManager()

    if key_manager.algorithm != "KYBER":
        pytest.skip("configured key exchange algorithm is not KYBER")

    # A genuine peer key, produced exactly as a real client would.
    good_peer = KyberKEM()
    good_peer.generate_keys()
    key_manager.add_public_key("goodpeer", good_peer.export_public_key())

    # Correct length, valid Base64 -- passes D6.5 -- but not a real
    # encapsulation key, so ML-KEM rejects it at encapsulation time.
    plausible_but_invalid = base64.b64encode(
        os.urandom(ML_KEM_768_PUBLIC_KEY_BYTES)
    ).decode("ascii")

    key_manager.add_public_key("badpeer", plausible_but_invalid)

    assert key_manager.get_public_key("badpeer") is not None, (
        "a right-length key still passes D6.5 validation -- which is "
        "why the per-recipient guard is still required"
    )

    session.key_store.verify_peer_fingerprint(
        "goodpeer", fingerprint_public_key(good_peer.export_public_key())
    )
    session.key_store.verify_peer_fingerprint(
        "badpeer", fingerprint_public_key(plausible_but_invalid)
    )

    session.key_manager = key_manager

    session._distribute_group_key("conv-1", b"x" * 32, 1, ["badpeer", "goodpeer"])

    assert _recipients_of(sent) == ["goodpeer"]

    delivered = sent[0]
    assert delivered["encapsulation"]
    assert delivered["wrapped_key"]
    assert delivered["epoch"] == 1
