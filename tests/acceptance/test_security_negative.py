"""Authorization boundaries, tried with protocol clients against the live acceptance stack.

These are backend/integration checks (the task allows protocol clients for these): real TLS, real
authentication, real server. Accounts are synthetic and created through the server's own
registration request.
"""

import time
import uuid

import pytest

import client.session as client_session_module
import storage.secure_key_store as key_store_module
from client.session import ClientSession
from domain.conversation_summary import ConversationSummary
from tests.acceptance.conftest import new_identity
from tests.acceptance.stack import SERVER_PORT
from utils.protocol import create_message_history_request_packet


@pytest.fixture()
def protocol_clients(stack, monkeypatch, tmp_path):
    monkeypatch.setattr(client_session_module, "SERVER_PORT", SERVER_PORT)
    monkeypatch.setattr(key_store_module, "KEY_STORE_DIR", tmp_path / "keystore")
    opened = []

    def make(prefix):
        ident = new_identity(prefix)
        registrar = ClientSession()
        result = registrar.register(ident["username"], ident["username"], f"{ident['username']}@example.test",
                                    ident["phone"], ident["password"], ident["password"])
        assert result.success, result.errors

        session = ClientSession()
        opened.append(session)
        auth = session.authenticate_credentials(ident["phone"], ident["password"])
        assert auth.success, auth.message
        session.user_id, session.username = auth.user_id, auth.username
        session.session_id, session.access_token = auth.session_id, auth.token_pair.access_token
        session.refresh_token = auth.token_pair.refresh_token
        session.connect()
        session.login(ident["username"])
        session.send_public_key()
        session.start_receiver()
        return session

    yield make

    for session in opened:
        try:
            session.disconnect()
        except Exception:
            pass


def _wait(predicate, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


def _group_id(session, name):
    for summary in session.conversation_store.get_all():
        if summary.is_group and summary.group_name == name:
            return summary.conversation_id
    return None


def test_a_non_member_cannot_read_a_groups_history(protocol_clients):
    owner, member, outsider = (protocol_clients(p) for p in ("neg_owner", "neg_mem", "neg_out"))
    name = f"private-{uuid.uuid4().hex[:6]}"
    owner.create_group_conversation(name, [member.username])
    assert _wait(lambda: _group_id(owner, name) is not None)
    group_id = _group_id(owner, name)

    reply = outsider.send_request(create_message_history_request_packet(group_id, True))

    assert not reply.get("messages"), "a non-member received group history"
    assert reply.get("error") or reply.get("success") is False or reply.get("messages") == []


def test_a_non_member_cannot_post_into_a_group(stack, protocol_clients):
    from database.connection import SessionLocal  # noqa: F401 -- imported lazily; uses the app role
    import acceptance_db
    from sqlalchemy import create_engine, text

    owner, member, outsider = (protocol_clients(p) for p in ("post_owner", "post_mem", "post_out"))
    name = f"locked-{uuid.uuid4().hex[:6]}"
    owner.create_group_conversation(name, [member.username])
    assert _wait(lambda: _group_id(owner, name) is not None)
    group_id = _group_id(owner, name)

    forged = {
        "type": "chat", "sender": outsider.username, "receiver": None, "conversation_id": group_id,
        "message": "bm90LWEtcmVhbC1jaXBoZXJ0ZXh0", "epoch": 1, "payload_type": "text",
        "message_signature": "AAAA", "client_message_id": str(uuid.uuid4()),
    }
    from utils.network import send_message
    send_message(outsider.client_socket, forged)
    time.sleep(2)

    engine = create_engine(acceptance_db.urls()[0], future=True)
    with engine.connect() as connection:
        stored = connection.execute(
            text("SELECT count(*) FROM messages WHERE conversation_id = :c"), {"c": group_id}
        ).scalar()
    engine.dispose()

    assert stored == 0, "a non-member's message was stored in the group"


def test_an_unauthenticated_connection_cannot_send_chat(stack):
    import socket

    from security.tls import build_client_context
    from utils.network import receive_message, send_message

    context = build_client_context()
    raw = socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=5)
    tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
    tls.settimeout(5)
    try:
        send_message(tls, {"type": "chat", "sender": "nobody", "receiver": "someone", "message": "x"})
        try:
            reply = receive_message(tls)
        except OSError:
            reply = None
        assert reply is None or reply.get("type") in ("error", "auth_result") and not reply.get("success", False), reply
    finally:
        tls.close()


def test_a_replayed_message_is_stored_once(stack, protocol_clients):
    import acceptance_db
    from sqlalchemy import create_engine, text

    alice, bob = protocol_clients("rp_a"), protocol_clients("rp_b")
    assert _wait(lambda: alice.key_manager.get_public_key(bob.username) is not None)
    assert _wait(lambda: bob.key_manager.get_public_key(alice.username) is not None)
    for one, other in ((alice, bob), (bob, alice)):
        fingerprint = one.get_peer_fingerprint_for_verification(other.username)
        one.confirm_peer_verification(other.username, fingerprint)
    alice.set_current_chat(ConversationSummary(conversation_id=None, username=bob.username, is_online=True,
                                               latest_message=None))
    from PySide6.QtCore import QCoreApplication

    app = QCoreApplication.instance() or QCoreApplication([])
    received = []
    bob.message_received.connect(lambda key, sender, body: received.append(body))

    message_id = str(uuid.uuid4())
    alice.send_chat_message("sent twice on purpose", client_message_id=message_id)
    alice.send_chat_message("sent twice on purpose", client_message_id=message_id)
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.05)

    engine = create_engine(acceptance_db.urls()[0], future=True)
    with engine.connect() as connection:
        stored = connection.execute(
            text("SELECT count(*) FROM messages WHERE client_message_id = :c"), {"c": message_id}
        ).scalar()
    engine.dispose()

    assert stored == 1, f"a replayed client_message_id was stored {stored} times"
    assert received.count("sent twice on purpose") == 1, (
        f"the recipient was shown the replayed message {received.count('sent twice on purpose')} times"
    )
