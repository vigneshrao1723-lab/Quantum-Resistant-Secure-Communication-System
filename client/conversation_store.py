"""
Conversation Store

The single source of truth for conversation state on the client
(Architecture Blueprint v2, S11/S15; Phase 2's approved requirement
that exactly one component may mutate conversation state). No GUI
component may mutate conversation state directly -- every change,
today and in every future phase (files, images, voice, group
messages, reactions, read receipts, edits, deletes), flows through
the methods below, which always end by emitting
``conversations_changed``. The GUI only ever reacts to that signal;
it never computes or caches conversation state of its own.

Phase 5 (Secure Group Key Distribution) adds a second responsibility:
this is also the authoritative cache of conversation *identity*. It
no longer resolves or creates anything itself -- as of D4.3 (Message/
History Operations Migration), every direct conversation's real
conversation_id is resolved server-side (ClientSession.
_resolve_direct_conversation_id() for a genuine "create", the
server's response to a message_history_request/chat/session_key
packet for a "get") and simply cached here via
record_direct_conversation_id(), a pure in-memory operation with no
database access at all. A group conversation never needs this either
-- its conversation_id is already known synchronously at creation
(see add_or_update_group()).

Sidebar visibility tracks real activity, not mere existence. A direct
conversation's identity can be (and is) resolved before any message
is ever sent -- ClientSession.set_current_chat() needs a
conversation_id for key-manager/epoch setup the instant a chat is
opened, whether or not anything gets typed. That resolution
deliberately does NOT, by itself, create an entry in this store: only
record_message() (real, attributable activity -- a message actually
sent or received) or add_or_update_group()/a group notification (a
group's membership is real the moment it's created, unlike a lazily-
resolved direct conversation) make an entry appear here, and therefore
in the sidebar. update_online_status() only ever updates existing
entries' presence, never adds one for its own sake.
"""

from datetime import datetime

from PySide6.QtCore import QObject, Signal

from domain.conversation_summary import ConversationSummary

# Every MessagePreview.timestamp in this codebase is a naive UTC
# datetime (the same convention _utc_now() establishes for every DB
# model), so the "no activity yet" sort fallback must be naive too --
# comparing it against an aware datetime would raise TypeError.
_NEVER = datetime.min  # noqa: DTZ901


class ConversationStore(QObject):
    """Owns the authoritative in-memory list of conversation summaries."""

    conversations_changed = Signal()

    def __init__(self):
        super().__init__()

        self._summaries = {}  # ConversationSummary.key -> ConversationSummary

    def set_initial(self, summaries):
        """
        Replace the entire store -- called once, by
        ClientSession.load_conversations() at chat startup. From then
        on the store is updated incrementally by record_message(),
        add_or_update_group(), and update_online_status(), never by
        another full reload.
        """

        self._summaries = {summary.key: summary for summary in summaries}

        self.conversations_changed.emit()

    def record_message(self, key, preview, is_own, is_online, conversation_id=None):
        """
        Record the latest message for a conversation -- the point a
        direct conversation becomes eligible for sidebar display (see
        this module's docstring: sidebar visibility tracks real
        activity, not mere DB/key-manager existence). Creates a new
        entry if this is the first activity with this partner this
        session. ``key`` is a username for a direct conversation or a
        conversation_id for a group one (Phase 4 -- Secure Group
        Messaging Foundation) -- see ConversationSummary.key.

        ``conversation_id`` (optional): the real, already-resolved
        conversation_id for a brand-new entry. A direct conversation's
        id is resolved server-side when the chat is opened (see
        ClientSession.set_current_chat()), before any message exists,
        but is deliberately NOT cached into this store at that point
        (that would make an empty conversation sidebar-visible) -- the
        sender's own send path is therefore the first time this store
        ever learns of it, and must pass the id it already has rather
        than leaving it None. The receive path doesn't need this: an
        incoming message's conversation_id is always cached first via
        record_direct_conversation_id()/handle_session_key(), so
        ``existing`` is already populated with the real id by the time
        this runs. Ignored when updating an existing entry, which
        always keeps its own conversation_id.

        Used identically for outgoing and incoming text messages
        today. A future file, image, voice, or reaction update calls
        this exact same method -- only the MessagePreview passed in
        changes, never this method's shape.

        Preserves an existing entry's group identity (is_group,
        group_name, participants) when updating it -- group entries
        always exist beforehand, created by add_or_update_group(), so
        this never has to guess whether ``key`` names a group.
        """

        existing = self._summaries.get(key)

        resolved_conversation_id = (
            existing.conversation_id if existing else conversation_id
        )
        is_group = existing.is_group if existing else False
        group_name = existing.group_name if existing else None
        participants = existing.participants if existing else None
        username = existing.username if existing else key

        self._summaries[key] = ConversationSummary(
            conversation_id=resolved_conversation_id,
            username=username,
            is_online=is_online,
            latest_message=preview,
            is_group=is_group,
            group_name=group_name,
            participants=participants,
        )

        self.conversations_changed.emit()

    def add_or_update_group(self, conversation_id, group_name, participant_usernames, admin=None):
        """
        Ensure a group conversation entry exists (or refresh its name/
        participants) -- called once when a group is created or when
        this client first learns about an existing one. Never touches
        latest_message; record_message() is still the only place that
        updates it, for groups exactly as for direct conversations.

        ``admin`` (Phase 19.18 -- Desktop Group Info/Remove Member
        parity): the group's admin username, when the caller has it
        (group_create_result's own "creator" field, or the
        conversation-list preview's "admin_username"). group_members_
        added carries neither -- that packet's own docstring already
        establishes the "preserve what wasn't sent" precedent this
        follows for latest_message/is_online, so a member-added update
        with no admin argument keeps whatever admin was already on
        file rather than wiping it back to unknown.
        """

        existing = self._summaries.get(conversation_id)

        latest_message = existing.latest_message if existing else None
        is_online = existing.is_online if existing else False
        resolved_admin = admin if admin is not None else (existing.admin if existing else None)

        self._summaries[conversation_id] = ConversationSummary(
            conversation_id=conversation_id,
            username=None,
            is_online=is_online,
            latest_message=latest_message,
            is_group=True,
            group_name=group_name,
            participants=list(participant_usernames),
            admin=resolved_admin,
        )

        self.conversations_changed.emit()

    def update_group_participants(self, conversation_id, participant_usernames):
        """
        Refresh a group's participant list in place (Phase 7 -- Group
        Membership Management: called after a member other than this
        client leaves) -- mirrors add_or_update_group()'s shape but
        only touches participants, preserving latest_message/
        is_online/group_name. A no-op if this client doesn't have the
        conversation (shouldn't happen: a member-left notification only
        ever reaches members who were in the group).
        """

        existing = self._summaries.get(conversation_id)

        if existing is None:
            return

        self._summaries[conversation_id] = ConversationSummary(
            conversation_id=conversation_id,
            username=None,
            is_online=existing.is_online,
            latest_message=existing.latest_message,
            is_group=True,
            group_name=existing.group_name,
            participants=list(participant_usernames),
            admin=existing.admin,
        )

        self.conversations_changed.emit()

    def remove_conversation(self, key):
        """
        Remove a conversation entirely from the store (Phase 7 --
        Group Membership Management: used when this client itself
        leaves a group). A no-op if the key isn't present.
        """

        if key in self._summaries:

            del self._summaries[key]

            self.conversations_changed.emit()

    def record_direct_conversation_id(self, username, conversation_id):
        """
        Cache an already-resolved direct conversation id -- no
        database access at all (D3.2 -- Conversation Operations
        Migration; the last database-touching caller, ClientSession.
        load_conversation_history(), was migrated in D4.3, so this is
        now the ONLY way anything in this class ever learns a direct
        conversation's id). Callers always already have the id from
        elsewhere -- a server-supplied packet field (ClientSession.
        handle_chat()/handle_session_key()) or a server request/
        response result (ClientSession._resolve_direct_conversation_id()
        for a genuine "create") -- so this never needs to touch the
        database itself, and in particular never needs to from the
        receiver thread, where a database call is not just wasteful
        but the deadlock risk D3.2 exists to remove.

        Creates a fresh, online placeholder summary if none exists yet
        for ``username``, otherwise updates the existing one's
        conversation_id in place; every other field of an existing
        summary (latest_message, is_online, group fields) is left
        untouched. Always emits conversations_changed: both branches
        represent a real, externally-observable change (a conversation
        either just became known to this client, or just gained/
        confirmed its id).
        """

        existing = self._summaries.get(username)

        if existing is not None:
            existing.conversation_id = conversation_id
        else:
            self._summaries[username] = ConversationSummary(
                conversation_id=conversation_id,
                username=username,
                is_online=True,
                latest_message=None,
            )

        self.conversations_changed.emit()

    def update_online_status(self, usernames_online):
        """
        Refresh online/offline status for existing conversations only.

        Deliberately does NOT add an entry for an online user who
        isn't already represented (that was the "before Phase 2"
        behavior, and the other of the two mechanisms -- alongside
        record_direct_conversation_id() being called merely from
        opening a chat -- that made the sidebar double as an
        online-user picker regardless of whether any real conversation
        existed). Starting a chat with someone not yet in this store
        is Find User's job (gui/find_user_dialog.py); this store's
        sidebar-visible set is scoped to conversations with real
        activity, per this module's docstring.
        """

        online_set = set(usernames_online)

        for username, summary in self._summaries.items():
            summary.is_online = username in online_set

        self.conversations_changed.emit()

    def get(self, key):
        """
        Return the ConversationSummary for one key, or None if not
        present (Issue 2 fix -- Add Members After Group Creation:
        the GUI needs a group's current participant list to exclude
        already-active members from the "add" candidate list). A
        narrow, read-only accessor -- does not create or mutate
        anything, unlike every method above it.
        """

        return self._summaries.get(key)

    def get_all(self):
        """
        Return every conversation, sorted by latest activity (most
        recent message first; conversations with no message yet sort
        last).
        """

        return sorted(
            self._summaries.values(),
            key=lambda summary: (
                summary.latest_message.timestamp
                if summary.latest_message and summary.latest_message.timestamp
                else _NEVER
            ),
            reverse=True,
        )
