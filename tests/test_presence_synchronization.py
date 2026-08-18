"""
BUG 8 -- online-user / presence synchronization.

Presence reached clients asymmetrically: whoever connected FIRST saw
everyone who arrived later, but a client that connected later did not
see the users already online. The late joiner only "discovered" them
once some unrelated event triggered another broadcast.

The server was never at fault. broadcast_user_list() sends a
personalised list to every connected client on both connect and
disconnect, so the correct data always reached the wire.

The defect was on the client, in the startup ordering:

    ClientSession.handle_user_list()   ->  conversation_store
                                           .update_online_status()
                                           adds a placeholder entry for
                                           every online user
    ClientSession.load_conversations() ->  conversation_store
                                           .set_initial() REPLACES the
                                           whole store

load_conversations() builds its summaries purely from the server's
conversation list, and uses ``online_users`` only to set ``is_online``
on partners it already has a conversation with -- it never adds a peer
you have simply never messaged. So when the user_list packet arrived
during startup (receiver thread) BEFORE ChatWindow finished calling
load_conversations() (main thread), set_initial() discarded the
presence entries that had just been recorded, and nothing re-applied
them. The list stayed stale until the next broadcast, which only
happens when someone else connects or disconnects.

That is exactly the reported asymmetry: the first client is already
past its own startup when the second connects, so it renders the
broadcast normally; the second client is still starting up, so its copy
is thrown away.

These tests drive real ClientSession objects over the real TLS server,
and assert against ConversationStore -- the store the sidebar actually
renders from -- not merely ``session.online_users``, because the bug
lost the store entry while leaving the raw list intact.

Run with:
    pytest tests/test_presence_synchronization.py -v
"""

import time
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from database.connection import SessionLocal
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from tests.tls_test_support import start_test_server


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
            "full_name": "Presence Test",
            "username": f"pres_{suffix_hint}{suffix}",
            "email": f"pres_{suffix_hint}{suffix}@example.com",
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


def _connect(payload):
    """connect() -> login() -> send_public_key() -> start_receiver(),
    the sequence gui/main_window.py::start_chat_session() performs
    before it constructs ChatWindow."""

    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    return session


def _start_chat_window(session):
    """The part of ChatWindow startup that matters for presence:
    register_callbacks() ends by calling load_conversations(), which is
    where set_initial() used to discard the presence state."""

    session.load_conversations()


def _sidebar_usernames(session):
    """What the sidebar would actually render -- ConversationStore is
    its only source (see ChatWindow.render_conversations())."""

    return {summary.key for summary in session.conversation_store.get_all()}


def _sees(session, username):
    return username in _sidebar_usernames(session)


@pytest.fixture()
def presence_env(running_server, monkeypatch):
    """Server plus registered accounts; sessions are created per test so
    connection ORDER is under the test's control."""

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    payloads = {
        name: _register_user(f"{name}_") for name in ("alice", "bob", "carol")
    }
    sessions = []

    def connect(name):
        session = _connect(payloads[name])
        sessions.append(session)
        return session

    yield {"connect": connect, "payloads": payloads, "sessions": sessions}

    for session in sessions:
        try:
            session.disconnect()
        except OSError:
            pass

    for payload in payloads.values():
        _delete_user(payload["username"])


# ----------------------------------------------------------------------
# The reported asymmetry
# ----------------------------------------------------------------------

def test_late_joining_client_sees_the_user_who_was_already_online(presence_env):
    """
    THE regression test for BUG 8.

    Bob connects first, Alice second. Alice must see Bob in her sidebar
    the moment her chat window finishes starting up -- with no message
    sent, no conversation opened, and no second broadcast.

    load_conversations() is called AFTER Alice has demonstrably received
    the user_list, which is the exact interleaving that used to lose the
    presence state: the receiver thread recorded Bob, then set_initial()
    replaced the store and discarded him.
    """

    connect = presence_env["connect"]
    bob_name = presence_env["payloads"]["bob"]["username"]

    connect("bob")
    alice = connect("alice")

    # Alice's receiver has processed the user_list...
    assert _wait_for(lambda: bob_name in alice.get_online_users()), (
        "Alice never received the online-user list"
    )

    # ...and now her chat window starts up.
    _start_chat_window(alice)

    assert _sees(alice, bob_name), (
        "Alice cannot see Bob after startup -- the presence state was "
        "discarded by load_conversations()"
    )


def test_presence_is_symmetric_for_both_connection_orders(presence_env):
    """Neither client's view depends on who connected first."""

    connect = presence_env["connect"]
    alice_name = presence_env["payloads"]["alice"]["username"]
    bob_name = presence_env["payloads"]["bob"]["username"]

    bob = connect("bob")
    alice = connect("alice")

    _start_chat_window(bob)
    _start_chat_window(alice)

    assert _wait_for(lambda: _sees(alice, bob_name)), "Alice cannot see Bob"
    assert _wait_for(lambda: _sees(bob, alice_name)), "Bob cannot see Alice"


def test_three_clients_all_see_each_other(presence_env):
    """C joins last and must see A and B; A and B must see C."""

    connect = presence_env["connect"]
    names = {k: v["username"] for k, v in presence_env["payloads"].items()}

    alice = connect("alice")
    _start_chat_window(alice)

    bob = connect("bob")
    _start_chat_window(bob)

    carol = connect("carol")
    _start_chat_window(carol)

    assert _wait_for(
        lambda: _sees(alice, names["bob"]) and _sees(alice, names["carol"])
    ), f"Alice sees {_sidebar_usernames(alice)}"

    assert _wait_for(
        lambda: _sees(bob, names["alice"]) and _sees(bob, names["carol"])
    ), f"Bob sees {_sidebar_usernames(bob)}"

    # The last joiner is the case that used to fail.
    assert _wait_for(
        lambda: _sees(carol, names["alice"]) and _sees(carol, names["bob"])
    ), f"Carol sees {_sidebar_usernames(carol)}"


# ----------------------------------------------------------------------
# Disconnect / reconnect
# ----------------------------------------------------------------------

def test_disconnect_marks_user_offline_for_everyone_else(presence_env):
    """
    When B disconnects, A and C must stop showing B as online.

    ConversationStore keeps a departed peer as an OFFLINE entry rather
    than deleting the row -- that is existing, deliberate behaviour
    (update_online_status flips is_online and never removes), so the
    assertion is on presence state, not on the row disappearing.
    """

    connect = presence_env["connect"]
    names = {k: v["username"] for k, v in presence_env["payloads"].items()}

    alice = connect("alice")
    bob = connect("bob")
    carol = connect("carol")

    for session in (alice, bob, carol):
        _start_chat_window(session)

    assert _wait_for(lambda: _sees(alice, names["bob"]))
    assert _wait_for(lambda: _sees(carol, names["bob"]))

    bob.disconnect()

    def bob_is_offline_for(session):
        summary = session.conversation_store.get(names["bob"])
        return names["bob"] not in session.get_online_users() and (
            summary is None or summary.is_online is False
        )

    assert _wait_for(lambda: bob_is_offline_for(alice)), (
        f"Alice still shows Bob online: {alice.get_online_users()}"
    )
    assert _wait_for(lambda: bob_is_offline_for(carol)), (
        f"Carol still shows Bob online: {carol.get_online_users()}"
    )


def test_reconnecting_user_is_visible_again_to_everyone(presence_env):
    """After B reconnects, every view converges again -- including B's
    own view of the peers who stayed connected."""

    connect = presence_env["connect"]
    names = {k: v["username"] for k, v in presence_env["payloads"].items()}

    alice = connect("alice")
    bob = connect("bob")

    _start_chat_window(alice)
    _start_chat_window(bob)

    assert _wait_for(lambda: _sees(alice, names["bob"]))

    bob.disconnect()

    assert _wait_for(lambda: names["bob"] not in alice.get_online_users())

    new_bob = connect("bob")
    _start_chat_window(new_bob)

    assert _wait_for(lambda: _sees(alice, names["bob"])), (
        "Alice did not see Bob again after his reconnect"
    )
    assert _wait_for(lambda: _sees(new_bob, names["alice"])), (
        "Reconnected Bob cannot see Alice"
    )
