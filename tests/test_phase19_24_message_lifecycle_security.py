"""
Phase 19.24 -- Message Lifecycle Events (Reply/Edit/Delete/Forward/
Copy/Reactions/Retry): server-side security and behavior tests.

Drives REAL ClientSession objects against a REAL test server (the
exact same `connect`/`accounts`/`_send_and_receive` harness tests/
test_read_receipts_realtime.py already established) -- no internal
dict manipulation, no mocked crypto. Security-negative cases are the
priority here (per this phase's own mandate): every handler in
server/client_handler.py that mutates a message re-derives
authorization from the authenticated socket and the stored row, never
from anything the packet claims, and these tests prove that by
attempting exactly the forgeries a malicious client would.
"""

import time
import uuid

from crypto.aes import AESCipher
from crypto.key_manager import fingerprint_public_key
from crypto.message_protocol import (
    EDIT_PAYLOAD_PURPOSE,
    MESSAGE_PAYLOAD_PURPOSE,
    REACTION_PAYLOAD_PURPOSE,
    sign_message_payload,
    verify_message_payload,
)
from database.connection import SessionLocal
from database.models.message import Message
from database.models.message_reaction import MessageReaction
from database.models.message_hidden_for_user import MessageHiddenForUser
from tests.test_read_receipts_realtime import (  # noqa: F401
    _open_direct,
    _send_and_receive,
    _wait_for,
    accounts,
    connect,
    running_server,
)


def _get_message_row(message_id):
    db = SessionLocal()
    try:
        return db.get(Message, uuid.UUID(str(message_id)))
    finally:
        db.close()


def _reaction_row(message_id, user_id):
    db = SessionLocal()
    try:
        return (
            db.query(MessageReaction)
            .filter(
                MessageReaction.message_id == uuid.UUID(str(message_id)),
                MessageReaction.user_id == user_id,
            )
            .first()
        )
    finally:
        db.close()


def _hidden_row(message_id, user_id):
    db = SessionLocal()
    try:
        return (
            db.query(MessageHiddenForUser)
            .filter(
                MessageHiddenForUser.message_id == uuid.UUID(str(message_id)),
                MessageHiddenForUser.user_id == user_id,
            )
            .first()
        )
    finally:
        db.close()


# ======================================================================
# EDIT
# ======================================================================


def test_edit_happy_path_recipient_sees_new_text(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "original text",
    )

    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    edited_events = []
    bob.message_edited_received.connect(
        lambda cid, mid, text, editor, edited_at, version: edited_events.append(
            (cid, mid, text, editor, version)
        )
    )

    alice.edit_message(alice.current_conversation_id, message_id, "edited text", expected_edit_version=0)

    assert _wait_for(lambda: len(edited_events) == 1)
    assert edited_events[0][1] == message_id
    assert edited_events[0][2] == "edited text"
    assert edited_events[0][3] == alice_payload["username"]
    assert edited_events[0][4] == 1

    row = _get_message_row(message_id)
    assert row.edit_version == 1
    assert row.edited_at is not None


def test_non_sender_cannot_edit_someone_elses_message(connect, accounts):
    """Security-negative: the actor is re-derived from the
    authenticated socket, never trusted from the packet -- Bob
    attempting to edit Alice's message must be rejected server-side,
    not merely hidden by the absence of a UI button."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "alice's original message",
    )

    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))
    original_ciphertext = _get_message_row(message_id).ciphertext

    _open_direct(bob, alice_payload["username"])
    bob.current_conversation_id = alice.current_conversation_id

    # Bob directly forges a message_edit packet naming Alice's message
    # -- bypassing edit_message()'s own sender-derived flow entirely,
    # exactly like a malicious client would.
    from utils.protocol import create_message_edit_packet
    from utils.network import send_message
    from payload.text_adapter import TextPayloadAdapter

    session_key = bob.key_manager.get_key(bob.current_conversation_id)
    aes = AESCipher(session_key)
    forged_envelope = TextPayloadAdapter().encrypt("bob's forged edit", aes, content_metadata=None)

    send_message(
        bob.client_socket,
        create_message_edit_packet(
            message_id=message_id, envelope=forged_envelope, epoch=1,
            message_signature="forged", expected_edit_version=0,
        ),
    )

    time.sleep(0.3)  # give the server a moment to (not) apply it

    row = _get_message_row(message_id)
    assert row.ciphertext == original_ciphertext, "an unauthorized edit was applied!"
    assert row.edit_version == 0


def test_stale_edit_version_is_rejected(connect, accounts):
    """Security-negative: a duplicate/replayed/out-of-order edit
    naming an edit_version the row has already moved past must be
    rejected, never silently re-applied."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "v0",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    alice.edit_message(alice.current_conversation_id, message_id, "v1", expected_edit_version=0)
    assert _wait_for(lambda: _get_message_row(message_id).edit_version == 1)

    # Replays the SAME (now-stale) expected_edit_version=0 again.
    alice.edit_message(alice.current_conversation_id, message_id, "v2-stale-replay", expected_edit_version=0)
    time.sleep(0.3)

    row = _get_message_row(message_id)
    assert row.edit_version == 1, "a stale edit_version was incorrectly applied"


def test_edit_rejected_after_delete_for_everyone(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "will be deleted",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    alice.delete_message_for_everyone(message_id)
    assert _wait_for(lambda: _get_message_row(message_id).deleted_at is not None)

    alice.edit_message(alice.current_conversation_id, message_id, "too late", expected_edit_version=0)
    time.sleep(0.3)

    row = _get_message_row(message_id)
    assert row.ciphertext is None, "editing a deleted message resurrected its content"


# ======================================================================
# DELETE FOR EVERYONE
# ======================================================================


def test_delete_for_everyone_actually_wipes_content_server_side(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "secret content",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    deleted_events = []
    bob.message_deleted_received.connect(
        lambda cid, mid, deleted_by, deleted_at: deleted_events.append((cid, mid, deleted_by))
    )

    alice.delete_message_for_everyone(message_id)

    assert _wait_for(lambda: len(deleted_events) == 1)
    assert deleted_events[0][1] == message_id
    assert deleted_events[0][2] == alice_payload["username"]

    row = _get_message_row(message_id)
    assert row.ciphertext is None
    assert row.content_metadata is None
    assert row.message_signature is None
    assert row.deleted_at is not None
    assert str(row.deleted_by) == str(alice.user_id)


def test_non_sender_cannot_delete_for_everyone(connect, accounts):
    """Security-negative: only the original sender may delete for
    everyone -- re-derived server-side from the stored row."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "alice's message",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    bob.current_conversation_id = alice.current_conversation_id
    bob.delete_message_for_everyone(message_id)

    time.sleep(0.3)

    row = _get_message_row(message_id)
    assert row.deleted_at is None, "a non-sender successfully deleted someone else's message!"
    assert row.ciphertext is not None


def test_delete_for_everyone_is_idempotent(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "delete me twice",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    alice.delete_message_for_everyone(message_id)
    assert _wait_for(lambda: _get_message_row(message_id).deleted_at is not None)
    first_deleted_at = _get_message_row(message_id).deleted_at

    alice.delete_message_for_everyone(message_id)
    time.sleep(0.3)

    assert _get_message_row(message_id).deleted_at == first_deleted_at


# ======================================================================
# DELETE FOR ME
# ======================================================================


def test_delete_for_me_affects_only_the_requester(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "hide this from bob only",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    bob.current_conversation_id = alice.current_conversation_id
    bob.delete_message_for_me(message_id)

    assert _wait_for(lambda: _hidden_row(message_id, bob.user_id) is not None)

    # Alice's own copy is completely untouched -- no hidden row for her.
    assert _hidden_row(message_id, alice.user_id) is None
    row = _get_message_row(message_id)
    assert row.ciphertext is not None
    assert row.deleted_at is None


def test_non_member_cannot_hide_a_message_they_cannot_see(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    carol = connect(carol_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "not carol's business",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    carol.delete_message_for_me(message_id)
    time.sleep(0.3)

    assert _hidden_row(message_id, carol.user_id) is None


# ======================================================================
# REACTIONS
# ======================================================================


def test_reaction_add_remove_round_trip(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "react to this",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    reaction_events = []
    alice.reaction_updated_received.connect(
        lambda cid, mid, actor, action, reaction: reaction_events.append((mid, actor, action, reaction))
    )

    bob.current_conversation_id = alice.current_conversation_id
    bob.add_reaction(bob.current_conversation_id, message_id, "👍")

    assert _wait_for(lambda: len(reaction_events) == 1)
    assert reaction_events[0] == (message_id, bob_payload["username"], "add", "👍")

    row = _reaction_row(message_id, bob.user_id)
    assert row is not None
    # The server must never be able to read the reaction -- its stored
    # ciphertext must not literally contain the plaintext emoji.
    assert "👍" not in row.ciphertext

    bob.remove_reaction(message_id)
    assert _wait_for(lambda: len(reaction_events) == 2)
    assert reaction_events[1][2] == "remove"
    assert _reaction_row(message_id, bob.user_id) is None


def test_adding_a_second_reaction_replaces_the_first(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "react twice",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    bob.current_conversation_id = alice.current_conversation_id
    bob.add_reaction(bob.current_conversation_id, message_id, "👍")
    assert _wait_for(lambda: _reaction_row(message_id, bob.user_id) is not None)

    bob.add_reaction(bob.current_conversation_id, message_id, "❤️")
    time.sleep(0.3)

    db = SessionLocal()
    try:
        count = (
            db.query(MessageReaction)
            .filter(
                MessageReaction.message_id == uuid.UUID(message_id),
                MessageReaction.user_id == bob.user_id,
            )
            .count()
        )
    finally:
        db.close()
    assert count == 1, "a second reaction stacked instead of replacing the first"


def test_non_member_cannot_react(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    carol = connect(carol_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "no carol allowed",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    try:
        carol.add_reaction(alice.current_conversation_id, message_id, "👍")
    except Exception:  # noqa: BLE001 -- carol has no key for this conversation either
        pass

    time.sleep(0.3)
    assert _reaction_row(message_id, carol.user_id) is None


# ======================================================================
# RETRY IDEMPOTENCY
# ======================================================================


def test_retry_with_same_client_message_id_does_not_duplicate(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    assert _wait_for(lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None)
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"], fingerprint_public_key(bob.key_manager.public_key),
    )

    _open_direct(alice, bob_payload["username"])

    client_message_id = str(uuid.uuid4())
    alice.send_chat_message("retry me", client_message_id=client_message_id)
    alice.send_chat_message("retry me", client_message_id=client_message_id)

    time.sleep(0.5)

    db = SessionLocal()
    try:
        count = (
            db.query(Message)
            .filter(Message.client_message_id == client_message_id)
            .count()
        )
    finally:
        db.close()

    assert count == 1, "a retried send with the same client_message_id created a duplicate message"


# ======================================================================
# REPLY
# ======================================================================


def test_reply_reference_persists_and_is_returned_by_history(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "original",
    )
    original_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    alice.send_chat_message("a reply", reply_to_message_id=original_id)
    time.sleep(0.5)

    db = SessionLocal()
    try:
        reply = (
            db.query(Message)
            .filter(Message.conversation_id == alice.current_conversation_id)
            .order_by(Message.created_at.desc())
            .first()
        )
        assert str(reply.reply_to_message_id) == original_id
    finally:
        db.close()


# ======================================================================
# RECEIVER-SIDE SIGNATURE VERIFICATION (continued Phase 19.24)
# ======================================================================


def test_edit_purpose_signature_cannot_be_replayed_as_an_ordinary_message():
    """Domain-separation proof, no server needed: an edit's signature
    must not verify under the ordinary MESSAGE_PAYLOAD_PURPOSE (or vice
    versa) -- otherwise a genuinely-signed edit could be replayed as if
    it were a fresh chat message with matching fields, or an ordinary
    message replayed as a fake edit."""

    from crypto.ml_dsa import MLDSASigner

    signer = MLDSASigner()
    signer.generate_keys()

    signature = sign_message_payload(
        signer, "alice", None, "conv-1", "text", "ciphertext-blob", None, 1,
        purpose=EDIT_PAYLOAD_PURPOSE,
    )

    # Verifies correctly under its OWN purpose.
    assert verify_message_payload(
        "alice", None, "conv-1", "text", "ciphertext-blob", None, 1,
        signature, signer.export_public_key(), purpose=EDIT_PAYLOAD_PURPOSE,
    ) is True

    # Must NOT verify under the ordinary chat-message purpose, or the
    # reaction purpose, even though every other field matches exactly.
    assert verify_message_payload(
        "alice", None, "conv-1", "text", "ciphertext-blob", None, 1,
        signature, signer.export_public_key(), purpose=MESSAGE_PAYLOAD_PURPOSE,
    ) is False
    assert verify_message_payload(
        "alice", None, "conv-1", "text", "ciphertext-blob", None, 1,
        signature, signer.export_public_key(), purpose=REACTION_PAYLOAD_PURPOSE,
    ) is False


def test_recipient_rejects_edit_with_wrong_signing_key(connect, accounts):
    """Security-negative: the RECEIVING client independently verifies
    the edit's ML-DSA signature against the editor's own trusted
    signing key -- it does not merely trust the server's 'editor'
    field. Simulated here by having alice (the legitimate original
    sender/editor, whose edit the server DID correctly authorize) sign
    with a throwaway key that does not match what bob has on file for
    her -- bob's client must silently drop the edit rather than trust
    it. This proves the client's OWN verification step actually runs
    and actually matters, independent of server-side authorization."""

    from crypto.ml_dsa import MLDSASigner

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "original",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    edited_events = []
    bob.message_edited_received.connect(
        lambda cid, mid, text, editor, edited_at, version: edited_events.append(mid)
    )

    # A throwaway signer standing in for "not alice's real key" --
    # simulates receiving a message_edited notification whose
    # signature does not match what this client has on file for the
    # claimed editor (e.g. a compromised/spoofing server, or a stale
    # cached key).
    rogue_signer = MLDSASigner()
    rogue_signer.generate_keys()

    session_key = alice.key_manager.get_key(alice.current_conversation_id)
    aes = AESCipher(session_key)
    from payload.text_adapter import TextPayloadAdapter
    envelope = TextPayloadAdapter().encrypt("forged edit", aes, content_metadata=None)

    forged_signature = sign_message_payload(
        rogue_signer, alice_payload["username"], None, str(alice.current_conversation_id),
        envelope.payload_type, envelope.ciphertext, envelope.content_metadata, 1,
        purpose=EDIT_PAYLOAD_PURPOSE,
    )

    import base64

    from utils.protocol import create_message_edited_notification_packet

    forged_packet = create_message_edited_notification_packet(
        message_id=message_id,
        conversation_id=str(alice.current_conversation_id),
        ciphertext=envelope.ciphertext,
        content_metadata=envelope.content_metadata,
        epoch=1,
        message_signature=base64.b64encode(forged_signature).decode("ascii"),
        editor=alice_payload["username"],
        edited_at="2026-01-01T00:00:00",
        edit_version=1,
    )

    # Fed DIRECTLY into bob's own packet handler -- exactly what would
    # happen if this arrived over the wire -- bypassing the server
    # entirely (which would never actually produce this, since its own
    # authorization check is unrelated to this test; this isolates the
    # CLIENT's independent verification step).
    bob.handle_message_edited(forged_packet)

    assert edited_events == [], "an edit with a forged/mismatched signature was accepted!"


def test_recipient_rejects_reaction_with_no_signature(connect, accounts):
    """Security-negative: a reaction_updated notification with no
    message_signature at all must be rejected, not treated as
    'unsigned but otherwise fine'."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "react to this",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    reaction_events = []
    alice.reaction_updated_received.connect(
        lambda cid, mid, actor, action, reaction: reaction_events.append(mid)
    )

    from utils.protocol import create_reaction_updated_notification_packet

    unsigned_packet = create_reaction_updated_notification_packet(
        message_id=message_id,
        conversation_id=str(alice.current_conversation_id),
        actor=bob_payload["username"],
        action="add",
        ciphertext="ZmFrZQ==",
        epoch=1,
        message_signature=None,
    )

    alice.handle_reaction_updated(unsigned_packet)

    assert reaction_events == [], "an unsigned reaction was accepted!"


# ======================================================================
# PINNED MESSAGES
# ======================================================================


def test_pin_happy_path_any_member_may_pin_broadcasts_to_both_sides(connect, accounts):
    """Deliberately the RECEIVER (bob), not the sender, pins -- proves
    handle_message_pin()'s "any active member" authorization actually
    differs from edit/delete's sender-only rule, not merely untested."""

    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "pin me",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    pinned_events = []
    alice.message_pinned_received.connect(
        lambda cid, mid, pinned_by, pinned_at: pinned_events.append((mid, pinned_by))
    )
    bob_pinned_events = []
    bob.message_pinned_received.connect(
        lambda cid, mid, pinned_by, pinned_at: bob_pinned_events.append((mid, pinned_by))
    )

    bob.current_conversation_id = alice.current_conversation_id
    bob.pin_message(message_id)

    assert _wait_for(lambda: len(pinned_events) == 1)
    assert pinned_events[0] == (message_id, bob_payload["username"])
    assert _wait_for(lambda: len(bob_pinned_events) == 1)

    row = _get_message_row(message_id)
    assert row.pinned_at is not None
    assert str(row.pinned_by) == str(bob.user_id)


def test_unpin_happy_path_broadcasts_and_clears_state(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "pin then unpin",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    alice.pin_message(message_id)
    assert _wait_for(lambda: _get_message_row(message_id).pinned_at is not None)

    unpinned_events = []
    bob.message_unpinned_received.connect(
        lambda cid, mid, unpinned_by: unpinned_events.append((mid, unpinned_by))
    )

    bob.current_conversation_id = alice.current_conversation_id
    bob.unpin_message(message_id)

    assert _wait_for(lambda: len(unpinned_events) == 1)
    assert unpinned_events[0] == (message_id, bob_payload["username"])
    assert _get_message_row(message_id).pinned_at is None
    assert _get_message_row(message_id).pinned_by is None


def test_repinning_updates_pinned_by_to_the_latest_actor(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "re-pin me",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    alice.pin_message(message_id)
    assert _wait_for(lambda: _get_message_row(message_id).pinned_at is not None)
    assert str(_get_message_row(message_id).pinned_by) == str(alice.user_id)

    bob.current_conversation_id = alice.current_conversation_id
    bob.pin_message(message_id)
    assert _wait_for(
        lambda: str((_get_message_row(message_id).pinned_by)) == str(bob.user_id)
    )


def test_non_member_cannot_pin(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    carol_payload = accounts("carol_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)
    carol = connect(carol_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "no carol allowed",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    carol.current_conversation_id = alice.current_conversation_id
    carol.pin_message(message_id)

    time.sleep(0.3)
    assert _get_message_row(message_id).pinned_at is None


def test_cannot_pin_a_deleted_message(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "delete then try to pin",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    alice.delete_message_for_everyone(message_id)
    assert _wait_for(lambda: _get_message_row(message_id).deleted_at is not None)

    bob.current_conversation_id = alice.current_conversation_id
    bob.pin_message(message_id)

    time.sleep(0.3)
    assert _get_message_row(message_id).pinned_at is None


def test_unpinning_an_unpinned_message_is_a_silent_noop(connect, accounts):
    alice_payload = accounts("alice_")
    bob_payload = accounts("bob_")
    alice = connect(alice_payload)
    bob = connect(bob_payload)

    _send_and_receive(
        alice, bob, alice_payload["username"], bob_payload["username"], "never pinned",
    )
    message_id = str(_latest_message_id(alice.current_conversation_id, alice.user_id))

    unpinned_events = []
    alice.message_unpinned_received.connect(
        lambda cid, mid, unpinned_by: unpinned_events.append((mid, unpinned_by))
    )

    alice.unpin_message(message_id)

    time.sleep(0.3)
    assert unpinned_events == []
    assert _get_message_row(message_id).pinned_at is None


# ======================================================================
# Helpers
# ======================================================================


def _latest_message_id(conversation_id, sender_id):
    db = SessionLocal()
    try:
        row = (
            db.query(Message)
            .filter(Message.conversation_id == conversation_id, Message.sender_id == sender_id)
            .order_by(Message.created_at.desc())
            .first()
        )
        return row.id
    finally:
        db.close()
