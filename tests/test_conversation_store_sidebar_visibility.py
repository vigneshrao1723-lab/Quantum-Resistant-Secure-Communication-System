"""
Tests for ConversationStore's sidebar-visibility rules (UI Finalization
Decision 1): a direct conversation must not appear merely because its
identity was resolved (opening a chat) or because its owner is online
-- only real message activity, or a group's own eager creation, may
add an entry.

Pure unit tests against ConversationStore directly -- no server, no
ClientSession, no Qt event loop required: QObject/Signal construction
and direct method calls work without a running QApplication as long as
nothing here depends on a real event loop delivering a queued signal,
which none of these assertions do (they inspect state, not signal
delivery).

Run with:
    pytest tests/test_conversation_store_sidebar_visibility.py -v
"""

from domain.conversation_summary import MessagePreview
from domain.payload_type import PayloadType
from client.conversation_store import ConversationStore


def _preview(text="hello"):
    return MessagePreview(payload_type=PayloadType.TEXT, text=text)


def test_update_online_status_does_not_add_an_entry_for_an_unrepresented_user():
    """The primary regression this decision fixes: being online, on
    its own, must never make someone show up in Chats."""
    store = ConversationStore()

    store.update_online_status(["alice", "bob"])

    assert store.get("alice") is None
    assert store.get("bob") is None
    assert store.get_all() == []


def test_update_online_status_still_updates_presence_on_existing_entries():
    """Presence tracking for conversations that DO already exist must
    keep working -- only the "add a new one" half of the old behavior
    was removed."""
    store = ConversationStore()

    store.record_message("alice", _preview(), is_own=False, is_online=False)
    assert store.get("alice").is_online is False

    store.update_online_status(["alice"])
    assert store.get("alice").is_online is True

    store.update_online_status([])
    assert store.get("alice").is_online is False


def test_record_message_creates_a_new_entry_with_the_given_conversation_id():
    """The fix for the gap record_message()'s new conversation_id
    parameter closes: the sender's own first-send path is often the
    first time this store ever hears about a conversation (opening it
    deliberately does not cache anything -- see
    ClientSession._resolve_direct_conversation_id()), so the id it
    already resolved must not be lost."""
    store = ConversationStore()

    store.record_message(
        "alice",
        _preview("first message"),
        is_own=True,
        is_online=True,
        conversation_id="real-conversation-id-123",
    )

    summary = store.get("alice")

    assert summary is not None
    assert summary.conversation_id == "real-conversation-id-123"
    assert summary.latest_message.text == "first message"


def test_record_message_without_a_conversation_id_still_works_for_the_receive_path():
    """The receive path already caches the real id via
    record_direct_conversation_id()/handle_session_key() before
    record_message() ever runs, so passing no conversation_id here
    must not clobber it."""
    store = ConversationStore()

    store.record_direct_conversation_id("alice", "already-known-id")

    store.record_message(
        "alice",
        _preview("a reply"),
        is_own=False,
        is_online=True,
    )

    summary = store.get("alice")

    assert summary is not None
    assert summary.conversation_id == "already-known-id"


def test_record_message_preserves_existing_conversation_id_over_a_new_argument():
    """A second record_message() call for an already-known
    conversation must never let a (redundant, or stale) passed-in id
    override the one already cached."""
    store = ConversationStore()

    store.record_message(
        "alice", _preview("one"), is_own=True, is_online=True,
        conversation_id="original-id",
    )

    store.record_message(
        "alice", _preview("two"), is_own=True, is_online=True,
        conversation_id="a-different-id-that-must-be-ignored",
    )

    assert store.get("alice").conversation_id == "original-id"
    assert store.get("alice").latest_message.text == "two"


def test_group_conversation_is_visible_immediately_with_no_message():
    """The exclusion is scoped to direct conversations -- a group is
    always eagerly created with real membership and must appear right
    away, unlike a lazily-opened direct conversation."""
    store = ConversationStore()

    store.add_or_update_group("group-1", "Trio", ["bob", "carol"])

    summary = store.get("group-1")

    assert summary is not None
    assert summary.is_group is True
    assert summary.latest_message is None
    assert [s.key for s in store.get_all()] == ["group-1"]


def test_online_placeholder_removal_does_not_affect_group_entries():
    """update_online_status() must not remove or otherwise disturb a
    group entry -- it only ever touches is_online, and only for
    entries that already exist."""
    store = ConversationStore()

    store.add_or_update_group("group-1", "Trio", ["bob", "carol"])

    store.update_online_status(["bob"])

    assert store.get("group-1") is not None
    assert [s.key for s in store.get_all()] == ["group-1"]
