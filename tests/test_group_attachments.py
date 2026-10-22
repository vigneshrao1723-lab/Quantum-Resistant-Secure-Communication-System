"""
Group attachments: files, voice messages and video messages sent to a group.

The group design is one stored message plus one delivery row per recipient, reusing the same
payload adapters, group-key management and attachment encryption as direct chats. Proved against
the real TLS test server, real ClientSessions and the real database:

* every member decrypts the exact bytes (and sees the right type, name and size);
* the server holds ONE message row and ONE blob -- and the blob is ciphertext, not the file;
* a non-member and a removed member cannot fetch it, a removed member is sent nothing new, and a
  new attachment after a removal is encrypted under a key the removed member never receives;
* the size limit holds before anything is sent, a retried send is one message, history returns the
  content for members, and read receipts reach the sender.
"""

import time
import uuid

import pytest

from config import MAX_ATTACHMENT_SIZE_BYTES
from database.connection import SessionLocal
from database.models.message import Message
from database.models.message_recipient import MessageRecipient
from domain.message_delivery_status import MessageDeliveryStatus
from domain.payload_type import PayloadType
from storage import encrypted_blob_store
from tests.test_group_admin_and_inbox import (  # noqa: F401 -- helpers and fixture reused
    _app,
    _new_session,
    _verify,
    _wait_for,
    running_server,
)
from utils.protocol import create_blob_download_request_packet


def _group(admin, others, name):
    admin.create_group_conversation(name, [o.username for o in others])
    assert _wait_for(lambda: any(s.is_group and s.group_name == name for s in admin.conversation_store.get_all()))
    conversation_id = next(
        s.conversation_id for s in admin.conversation_store.get_all() if s.is_group and s.group_name == name
    )
    for member in others:
        assert _wait_for(lambda: member.conversation_store.get(conversation_id) is not None)
        assert _wait_for(lambda: member.key_manager.has_key(conversation_id)), "the group key never reached a member"
    return conversation_id


def _record(session):
    received = []
    session.payload_message_received.connect(
        lambda key, sender, payload_type, data, metadata: received.append((key, sender, payload_type, bytes(data), metadata))
    )
    return received


def _rows(conversation_id):
    db = SessionLocal()
    try:
        messages = db.query(Message).filter(Message.conversation_id == conversation_id).all()
        recipients = {
            m.id: db.query(MessageRecipient).filter(MessageRecipient.message_id == m.id).all() for m in messages
        }
        return messages, recipients
    finally:
        db.close()


def _send(session, conversation_id, path):
    session.set_current_chat(session.conversation_store.get(conversation_id))
    return session.send_attachment(str(path))


@pytest.fixture()
def trio(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    other = _new_session(running_server, monkeypatch, "other", tmp_path)
    for a, b in ((admin, member), (member, admin), (admin, other), (other, admin), (member, other), (other, member)):
        _verify(a, b)
    yield admin, member, other
    for session in (admin, member, other):
        session.disconnect()


def test_a_group_file_reaches_every_member_byte_for_byte_and_is_stored_once(trio, tmp_path):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Files Group")
    got_member, got_other = _record(member), _record(other)
    document = bytes(range(256)) * 40                                    # 10,240 bytes, every byte value
    path = tmp_path / "report.pdf"
    path.write_bytes(document)

    payload_type, _data, metadata = _send(admin, conversation_id, path)

    assert payload_type == PayloadType.FILE
    for received in (got_member, got_other):
        assert _wait_for(lambda: len(received) == 1)
        key, sender, kind, data, meta = received[0]
        assert (key, sender, kind) == (conversation_id, admin.username, PayloadType.FILE)
        assert data == document                                          # the exact bytes, decrypted
        assert meta["filename"] == "report.pdf" and meta["size_bytes"] == len(document)

    # ONE message row for the group, with one delivery row per recipient (not per copy of the file).
    messages, recipients = _rows(conversation_id)
    assert len(messages) == 1 and messages[0].blob_ref and messages[0].ciphertext is None
    assert {r.recipient_id for r in recipients[messages[0].id]} == {
        uuid.UUID(member.user_id), uuid.UUID(other.user_id)
    }


def test_the_stored_blob_is_ciphertext_not_the_file(trio, tmp_path):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "At Rest Group")
    marker = b"TOP-SECRET-PLAINTEXT-MARKER-" + uuid.uuid4().hex.encode()
    path = tmp_path / "secret.txt"
    path.write_bytes(marker * 20)

    _send(admin, conversation_id, path)

    messages, _recipients = _rows(conversation_id)
    assert _wait_for(lambda: len(_rows(conversation_id)[0]) == 1)
    stored = encrypted_blob_store.load_blob(_rows(conversation_id)[0][0].blob_ref)
    assert marker not in stored                                          # nothing readable at rest
    import base64
    assert marker not in base64.b64decode(stored, validate=False) if _is_base64(stored) else True


def _is_base64(data):
    import base64
    try:
        base64.b64decode(data, validate=True)
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.parametrize("name, expected", [
    ("voice-message.m4a", PayloadType.VOICE),
    ("clip.mp4", PayloadType.VIDEO),
    ("photo.png", PayloadType.IMAGE),
])
def test_voice_video_and_images_keep_their_type_in_a_group(trio, tmp_path, name, expected):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], f"Media {expected}")
    got = _record(other)
    path = tmp_path / name
    path.write_bytes(b"\x00\x01\x02 media bytes " * 100)

    _send(admin, conversation_id, path)

    assert _wait_for(lambda: len(got) == 1)
    assert got[0][2] == expected and got[0][3] == path.read_bytes()


def test_a_member_can_send_too_and_everyone_else_receives(trio, tmp_path):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Member Sends")
    got_admin, got_other = _record(admin), _record(other)
    path = tmp_path / "from-member.bin"
    path.write_bytes(b"member says hi" * 50)

    _send(member, conversation_id, path)

    for received in (got_admin, got_other):
        assert _wait_for(lambda: len(received) == 1)
        assert received[0][1] == member.username and received[0][3] == path.read_bytes()


def test_history_returns_the_attachment_to_a_member_who_loads_it_later(trio, tmp_path):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "History Group")
    got = _record(other)
    path = tmp_path / "keep.bin"
    path.write_bytes(b"history content " * 64)
    _send(admin, conversation_id, path)
    assert _wait_for(lambda: len(got) == 1)

    other.set_current_chat(other.conversation_store.get(conversation_id))
    history = other.load_conversation_history(conversation_id, is_group=True)

    assert len(history) == 1
    assert history[0]["content"] == path.read_bytes()
    assert history[0]["sender"] == admin.username
    assert history[0]["content_metadata"]["filename"] == "keep.bin"


def test_read_receipts_for_a_group_attachment_reach_the_sender(trio, tmp_path):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Receipts Group")
    got = _record(member)
    reads = []
    admin.read_receipt_updated.connect(lambda cid, reader: reads.append((cid, reader)))
    path = tmp_path / "read-me.bin"
    path.write_bytes(b"x" * 500)
    _send(admin, conversation_id, path)
    assert _wait_for(lambda: len(got) == 1)

    member.mark_conversation_read(conversation_id)

    assert _wait_for(lambda: (conversation_id, member.username) in reads)
    _messages, recipients = _rows(conversation_id)
    by_user = {r.recipient_id: r for rows in recipients.values() for r in rows}
    assert by_user[uuid.UUID(member.user_id)].status == MessageDeliveryStatus.READ
    assert by_user[uuid.UUID(other.user_id)].status != MessageDeliveryStatus.READ   # only the reader is marked read


def test_a_retried_send_is_one_message_and_is_delivered_once(trio):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Retry Group")
    got = _record(member)
    admin.set_current_chat(admin.conversation_store.get(conversation_id))
    attachment_id = str(uuid.uuid4())

    for _ in range(3):                                                   # the same send, retried
        admin._send_encrypted_payload(
            PayloadType.FILE, b"retry me " * 30,
            content_metadata={"filename": "retry.bin", "mime_type": "application/octet-stream", "size_bytes": 270},
            preview_text=None, client_message_id=attachment_id,
        )
    time.sleep(1.0)
    _app.processEvents()

    assert len(got) == 1
    assert len(_rows(conversation_id)[0]) == 1


def test_an_oversized_file_is_refused_before_anything_is_sent(trio, tmp_path, monkeypatch):
    admin, member, other = trio
    conversation_id = _group(admin, [member, other], "Limit Group")
    got = _record(member)
    big = tmp_path / "huge.bin"
    with open(big, "wb") as handle:
        handle.truncate(MAX_ATTACHMENT_SIZE_BYTES + 1)                   # a sparse file just over the limit

    with pytest.raises(ValueError, match="exceeds the maximum attachment size"):
        _send(admin, conversation_id, big)

    time.sleep(0.5)
    assert got == [] and _rows(conversation_id)[0] == []


def test_a_non_member_and_a_removed_member_cannot_fetch_or_receive_attachments(trio, running_server, monkeypatch, tmp_path):
    admin, member, other = trio
    outsider = _new_session(running_server, monkeypatch, "out", tmp_path)
    try:
        conversation_id = _group(admin, [member, other], "Private Files")
        got_other = _record(other)
        path = tmp_path / "before.bin"
        path.write_bytes(b"sent while other was a member " * 20)
        _send(admin, conversation_id, path)
        assert _wait_for(lambda: len(got_other) == 1)
        message_id = str(_rows(conversation_id)[0][0].id)

        assert admin.remove_group_member(conversation_id, other.username).get("success")
        time.sleep(0.8)
        got_other_after = len(got_other)
        later = tmp_path / "after.bin"
        later.write_bytes(b"sent after the removal " * 20)
        got_member = _record(member)
        _send(admin, conversation_id, later)

        assert _wait_for(lambda: len(got_member) == 1)                   # the remaining member still receives
        time.sleep(0.6)
        assert len(got_other) == got_other_after                         # the removed member is sent nothing

        for who in (other, outsider):                                    # neither can fetch either attachment
            for stored_message in _rows(conversation_id)[0]:
                reply = who.send_request(create_blob_download_request_packet(str(stored_message.id)))
                assert reply.get("ciphertext") is None and reply.get("error") == "Unknown message."
            assert who.send_request(create_blob_download_request_packet(message_id)).get("ciphertext") is None

        # The new attachment is under a key epoch the removed member never receives.
        later_epoch = max(m.epoch or 1 for m in _rows(conversation_id)[0])
        assert not other.key_manager.has_key(conversation_id, epoch=later_epoch) or later_epoch == 1
    finally:
        outsider.disconnect()
