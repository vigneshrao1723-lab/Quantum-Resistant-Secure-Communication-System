"""
BUG 6 -- group membership and key state after a member is re-added.

The reported symptom was that a member who left a group and was then
added back could not send to it until they opened another conversation
and returned, which looked like stale client-side membership or key
state.

It was neither. The cause was BUG 3: the Qt double-toggle in
AddMembersDialog meant a checkbox click produced an EMPTY selection, so
handle_group_add_members() hit its ``if not member_usernames: return``
guard and silently did nothing. Nobody was re-added. The re-adder saw
the dialog close without error and believed otherwise, while the
would-be member's send was correctly refused by the server's
membership check -- presenting exactly as "cannot send to the group".
Retrying and happening to click the row TEXT rather than the checkbox
produced a correct list, which is why it sometimes "started working".

Fixed in 42f98b0; verified non-reproducing at session level, at strict
session level, and against real ChatWindow widgets.

No test covered leave -> re-add -> immediate send, which is precisely
why the BUG 3 -> BUG 6 chain went unnoticed: add-member and leave were
each covered alone. This module closes that gap and pins the whole
journey, including the security properties that must hold throughout.

The re-added member deliberately does NOTHING between being re-added
and sending -- no refresh, no logout/login, no reconnect, no opening
another conversation, and no reopening the group. ``set_current_chat``
is called once, BEFORE she leaves (mirroring a user who had the group
open), and never again, so the test cannot accidentally pass by
re-establishing the state it is meant to check.

Run with:
    pytest tests/test_group_re_add_membership.py -v
"""

import time
import uuid

import pytest

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_public_key
from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


def _register_user(suffix_hint=""):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Group Re-Add Test",
            "username": f"readd_{suffix_hint}{suffix}",
            "email": f"readd_{suffix_hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
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
        result = AuthenticationService(db).authenticate_user(
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _connect(payload, key_store_dir):
    """connect() -> login() -> send_public_key() -> start_receiver(),
    the sequence gui/main_window.py::start_chat_session() performs.

    Also unlocks a real, isolated, on-disk SecureKeyStore -- this
    lighter connect()-only pattern normally never does that (it skips
    authenticate_credentials(), the only place that happens), but
    Server-Untrusted Identity Verification, Stage 3 needs one to exist
    so the fixture below can explicitly verify these peers with
    key_store.verify_peer_fingerprint(), exactly as a real login would
    have unlocked one for the same purpose."""

    session = ClientSession()
    session.user_id = payload["user_id"]
    session.access_token = _login_and_get_token(payload)
    session.connect()
    session.login(payload["username"])
    session.send_public_key()
    session.start_receiver()
    session.key_store = SecureKeyStore(
        payload["user_id"], storage_dir=key_store_dir / payload["username"]
    )
    session.key_store.unlock(payload["password"])
    return session


def _wait_for(predicate, attempts=120, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _members_in_db(conversation_id):
    db = SessionLocal()
    try:
        member_ids = ConversationRepository(db).get_member_user_ids(
            uuid.UUID(conversation_id)
        )
        user_repo = UserRepository(db)
        return sorted(
            user_repo.get_by_id(member_id).username
            for member_id in member_ids
            if user_repo.get_by_id(member_id) is not None
        )
    finally:
        db.close()


def _epoch_state(conversation_id):
    db = SessionLocal()
    try:
        return ConversationRepository(db).get_epoch_state(uuid.UUID(conversation_id))
    finally:
        db.close()


def _open_group(session, conversation_id, name, participants):
    """What ChatWindow.open_conversation() does for a group."""

    session.set_current_chat(
        ConversationSummary(
            conversation_id=conversation_id,
            username=None,
            is_online=False,
            latest_message=None,
            is_group=True,
            group_name=name,
            participants=participants,
        )
    )


def _received(session, text):
    return any(
        summary.latest_message is not None
        and summary.latest_message.text == text
        for summary in session.conversation_store.get_all()
    )


@pytest.fixture()
def group_of_three(running_server, monkeypatch, tmp_path):
    """
    Alice, Bob and Ramya in one group, plus an ``outsider`` who is
    connected and authenticated but was never a member.

    Ramya has the group OPEN before anything else happens -- the state
    a real user is in when they leave -- and no test reopens it
    afterwards.
    """

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    key_store_dir = tmp_path / "keystores"

    payloads = {
        name: _register_user(f"{name}_")
        for name in ("alice", "bob", "ramya", "outsider")
    }
    sessions = {
        name: _connect(payload, key_store_dir) for name, payload in payloads.items()
    }

    alice, bob, ramya = sessions["alice"], sessions["bob"], sessions["ramya"]
    names = {name: payload["username"] for name, payload in payloads.items()}

    # Everyone must know everyone's public key before group keys can be
    # wrapped for them.
    for holder, others in (
        (alice, (names["bob"], names["ramya"])),
        (bob, (names["alice"], names["ramya"])),
        (ramya, (names["alice"], names["bob"])),
    ):
        for other in others:
            assert _wait_for(
                lambda other=other, holder=holder: (
                    holder.key_manager.get_public_key(other) is not None
                )
            ), f"public key for {other} never arrived"

    # Server-Untrusted Identity Verification, Stage 3:
    # _distribute_group_key() silently skips any recipient who is not
    # explicitly VERIFIED -- and the server picks an arbitrary
    # currently-connected active member to (re)distribute the key on
    # every creation/leave/re-add rotation (see server/client_handler.py
    # ::_select_connected_active_member() -- "any valid connected
    # member is acceptable... no election"), so whichever of
    # alice/bob/ramya ends up distributing must already have the other
    # two verified. All three verify each other here, before the group
    # is even created, so the fixture's own baseline (three members,
    # one shared key) does not depend on which one the server happens
    # to pick.
    for verifier, peers in (
        (alice, (("bob", bob), ("ramya", ramya))),
        (bob, (("alice", alice), ("ramya", ramya))),
        (ramya, (("alice", alice), ("bob", bob))),
    ):
        for peer_name, peer_session in peers:
            verifier.key_store.verify_peer_fingerprint(
                names[peer_name],
                fingerprint_public_key(peer_session.key_manager.public_key),
            )

    alice.create_group_conversation("Re-Add Group", [names["bob"], names["ramya"]])

    assert _wait_for(
        lambda: any(s.is_group for s in ramya.conversation_store.get_all())
    ), "Ramya never received the group"

    conversation_id = next(
        s.key for s in ramya.conversation_store.get_all() if s.is_group
    )

    for name in ("alice", "bob", "ramya"):
        assert _wait_for(
            lambda name=name: (
                sessions[name].key_manager.get_key(conversation_id) is not None
            )
        ), f"{name} never received the initial group key"

    # Ramya opens the group ONCE, here. Nothing reopens it later.
    _open_group(
        ramya, conversation_id, "Re-Add Group", [names["alice"], names["bob"]]
    )
    _open_group(
        alice, conversation_id, "Re-Add Group", [names["bob"], names["ramya"]]
    )

    yield {
        "sessions": sessions,
        "names": names,
        "conversation_id": conversation_id,
    }

    for session in sessions.values():
        try:
            session.disconnect()
        except OSError:
            pass

    for payload in payloads.values():
        _delete_user(payload["username"])


def _leave(env):
    """Ramya leaves, confirmed against the database."""

    ramya = env["sessions"]["ramya"]
    conversation_id = env["conversation_id"]

    ramya.leave_group_conversation(conversation_id)

    assert _wait_for(
        lambda: env["names"]["ramya"] not in _members_in_db(conversation_id)
    ), "the leave was never recorded"

    # Let the leave-triggered rotation settle.
    time.sleep(1.5)


def _re_add(env):
    """Alice adds Ramya back, confirmed against the database."""

    alice = env["sessions"]["alice"]
    conversation_id = env["conversation_id"]

    alice.add_group_members(conversation_id, [env["names"]["ramya"]])

    assert _wait_for(
        lambda: env["names"]["ramya"] in _members_in_db(conversation_id)
    ), "the re-add was never recorded"

    # Let the re-add-triggered rotation distribute the new epoch key.
    time.sleep(2.0)


# ----------------------------------------------------------------------
# 1-2. Baseline
# ----------------------------------------------------------------------

def test_all_three_members_share_the_group_and_its_key(group_of_three):
    """1: the starting state -- three members, one conversation, one key."""

    env = group_of_three
    conversation_id = env["conversation_id"]

    assert _members_in_db(conversation_id) == sorted(
        [env["names"]["alice"], env["names"]["bob"], env["names"]["ramya"]]
    )

    keys = {
        name: env["sessions"][name].key_manager.get_key(conversation_id)
        for name in ("alice", "bob", "ramya")
    }

    assert all(key is not None for key in keys.values())
    assert keys["alice"] == keys["bob"] == keys["ramya"]


def test_leaving_removes_the_member_from_the_database(group_of_three):
    """2: the leave itself is recorded server-side."""

    env = group_of_three

    _leave(env)

    assert _members_in_db(env["conversation_id"]) == sorted(
        [env["names"]["alice"], env["names"]["bob"]]
    )


# ----------------------------------------------------------------------
# 3 + 14. A removed member cannot send, and stale state cannot help
# ----------------------------------------------------------------------

def test_removed_member_cannot_send_to_the_group(group_of_three):
    """
    3 + 14: after leaving, Ramya's client still holds her old key and
    still has the group as its current chat -- nothing local stops her
    attempting a send. The server's membership check is what refuses
    it, so stale client state cannot authorise anything.
    """

    env = group_of_three
    ramya = env["sessions"]["ramya"]
    alice = env["sessions"]["alice"]
    bob = env["sessions"]["bob"]
    conversation_id = env["conversation_id"]

    _leave(env)

    # Precisely the stale state the report suspected: still "in" the
    # conversation locally, still holding a key.
    assert ramya.get_current_chat() == conversation_id
    assert ramya.key_manager.get_key(conversation_id) is not None

    try:
        ramya.send_chat_message("i left but am still trying")
    except (RuntimeError, ValueError):
        # Refusing locally is also acceptable; what matters is that it
        # never reaches the group.
        pass

    assert not _wait_for(
        lambda: _received(alice, "i left but am still trying"), attempts=12
    ), "a removed member's message reached Alice"

    assert not _wait_for(
        lambda: _received(bob, "i left but am still trying"), attempts=12
    ), "a removed member's message reached Bob"


def test_stale_epoch_key_does_not_authorize_after_removal(group_of_three):
    """14: the epoch Ramya still holds is strictly behind the server's
    after her departure triggers a rotation -- her key is stale by
    construction, not merely unused."""

    env = group_of_three
    ramya = env["sessions"]["ramya"]
    conversation_id = env["conversation_id"]

    epoch_before = ramya.key_manager.current_epoch(conversation_id)

    _leave(env)

    server_epoch, _confirmed = _epoch_state(conversation_id)

    assert epoch_before is not None
    assert server_epoch > epoch_before, (
        "leaving must reserve a new epoch the departed member does not hold"
    )
    assert ramya.key_manager.get_key(conversation_id, epoch=server_epoch) is None


# ----------------------------------------------------------------------
# 4-13. Re-add, then send immediately with no other action
# ----------------------------------------------------------------------

def test_re_added_member_can_send_immediately(group_of_three):
    """
    THE regression test (4-11).

    Between being re-added and sending, Ramya does NOT refresh, log out
    and back in, reconnect, open another conversation, or reopen the
    group. Her current chat was set once in the fixture, before she
    left, and is never touched again -- so this test cannot pass by
    re-establishing the very state it is checking.
    """

    env = group_of_three
    ramya = env["sessions"]["ramya"]
    alice = env["sessions"]["alice"]
    bob = env["sessions"]["bob"]
    conversation_id = env["conversation_id"]

    _leave(env)
    _re_add(env)

    # No reconnect, no re-login, no new socket.
    assert ramya.is_connected() is True

    # Still pointing at the group from before the leave -- untouched.
    assert ramya.get_current_chat() == conversation_id
    assert ramya.current_chat_is_group is True

    ramya.send_chat_message("ramya is back in the group")

    assert _wait_for(
        lambda: _received(alice, "ramya is back in the group")
    ), "Alice did not receive the re-added member's message"

    assert _wait_for(
        lambda: _received(bob, "ramya is back in the group")
    ), "Bob did not receive the re-added member's message"


def test_re_added_member_holds_the_current_group_key(group_of_three):
    """12: the re-added member has the CURRENT key, not a revived old
    one -- and it is the same key the existing members hold."""

    env = group_of_three
    conversation_id = env["conversation_id"]

    _leave(env)
    _re_add(env)

    keys = {
        name: env["sessions"][name].key_manager.get_key(conversation_id)
        for name in ("alice", "bob", "ramya")
    }

    assert keys["ramya"] is not None
    assert keys["ramya"] == keys["alice"] == keys["bob"], (
        "the re-added member must hold the same current key as the group"
    )


def test_client_and_server_epochs_agree_after_re_add(group_of_three):
    """13: epoch state converges -- client and server agree, and the
    epoch advanced for both the leave and the re-add."""

    env = group_of_three
    conversation_id = env["conversation_id"]

    epoch_at_start = env["sessions"]["ramya"].key_manager.current_epoch(
        conversation_id
    )

    _leave(env)
    _re_add(env)

    server_epoch, confirmed_epoch = _epoch_state(conversation_id)

    for name in ("alice", "bob", "ramya"):
        client_epoch = env["sessions"][name].key_manager.current_epoch(
            conversation_id
        )
        assert client_epoch == server_epoch, (
            f"{name} is on epoch {client_epoch}, server is on {server_epoch}"
        )

    assert server_epoch > epoch_at_start
    assert confirmed_epoch == server_epoch, "the rotation never completed"

    # The re-added member can still read messages sent under the key she
    # legitimately held before leaving -- rotation adds epochs, it never
    # destroys old ones.
    assert (
        env["sessions"]["ramya"].key_manager.get_key(
            conversation_id, epoch=epoch_at_start
        )
        is not None
    )


def test_re_added_member_receives_messages_from_existing_members(group_of_three):
    """The reverse direction: the group can reach the re-added member,
    not only the other way round."""

    env = group_of_three
    ramya = env["sessions"]["ramya"]
    alice = env["sessions"]["alice"]

    _leave(env)
    _re_add(env)

    alice.send_chat_message("welcome back ramya")

    assert _wait_for(lambda: _received(ramya, "welcome back ramya")), (
        "the re-added member did not receive the group's message"
    )


def test_existing_members_still_communicate_after_the_re_add(group_of_three):
    """9 of the brief's checklist: ordinary group messaging is not
    disturbed by the leave/re-add cycle."""

    env = group_of_three
    alice = env["sessions"]["alice"]
    bob = env["sessions"]["bob"]

    _leave(env)
    _re_add(env)

    alice.send_chat_message("alice to bob, still working")

    assert _wait_for(lambda: _received(bob, "alice to bob, still working"))


# ----------------------------------------------------------------------
# 15. Non-members
# ----------------------------------------------------------------------

def test_non_member_cannot_send_to_the_group(group_of_three):
    """15: a connected, authenticated user who was never a member
    cannot send to the group, before or after the re-add."""

    env = group_of_three
    outsider = env["sessions"]["outsider"]
    alice = env["sessions"]["alice"]
    conversation_id = env["conversation_id"]

    _leave(env)
    _re_add(env)

    # The outsider fabricates the group as their current chat and
    # supplies a key of their own -- the server must still refuse.
    _open_group(
        outsider, conversation_id, "Re-Add Group", [env["names"]["alice"]]
    )
    outsider.key_manager.store_key(conversation_id, b"\x00" * 32, epoch=1)

    try:
        outsider.send_chat_message("outsider trying to join in")
    except (RuntimeError, ValueError):
        pass

    assert not _wait_for(
        lambda: _received(alice, "outsider trying to join in"), attempts=12
    ), "a non-member's message reached the group"
