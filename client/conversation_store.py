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
this is also the authoritative source of conversation *identity* --
including resolving/creating a direct conversation's real
conversation_id, via ensure_direct_conversation_id() -- so that
ClientSession never performs a database lookup or keeps a second
cache of its own. See that method's docstring for the scope of this
responsibility and where it should move if it grows.
"""

import uuid
from datetime import datetime

from PySide6.QtCore import QObject, Signal

from database.connection import SessionLocal
from database.repositories.conversation_repository import ConversationRepository
from database.repositories.user_repository import UserRepository
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

    def record_message(self, key, preview, is_own, is_online):
        """
        Record the latest message for a conversation, creating a new
        (placeholder, conversation_id-less) direct entry if this is
        the first activity with this partner this session. ``key`` is
        a username for a direct conversation or a conversation_id for
        a group one (Phase 4 -- Secure Group Messaging Foundation) --
        see ConversationSummary.key.

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

        conversation_id = existing.conversation_id if existing else None
        is_group = existing.is_group if existing else False
        group_name = existing.group_name if existing else None
        participants = existing.participants if existing else None
        username = existing.username if existing else key

        self._summaries[key] = ConversationSummary(
            conversation_id=conversation_id,
            username=username,
            is_online=is_online,
            latest_message=preview,
            is_group=is_group,
            group_name=group_name,
            participants=participants,
        )

        self.conversations_changed.emit()

    def add_or_update_group(self, conversation_id, group_name, participant_usernames):
        """
        Ensure a group conversation entry exists (or refresh its name/
        participants) -- called once when a group is created or when
        this client first learns about an existing one. Never touches
        latest_message; record_message() is still the only place that
        updates it, for groups exactly as for direct conversations.
        """

        existing = self._summaries.get(conversation_id)

        latest_message = existing.latest_message if existing else None
        is_online = existing.is_online if existing else False

        self._summaries[conversation_id] = ConversationSummary(
            conversation_id=conversation_id,
            username=None,
            is_online=is_online,
            latest_message=latest_message,
            is_group=True,
            group_name=group_name,
            participants=list(participant_usernames),
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

    def ensure_direct_conversation_id(self, own_user_id, username):
        """
        Resolve the real conversation_id for a direct conversation
        with ``username``, creating it if it doesn't exist yet, and
        cache it on the stored summary so every later call is a plain
        dictionary lookup, not a database round trip. Caching itself
        is delegated to record_direct_conversation_id() below.

        This is intentionally the ONE place in the client that ever
        resolves or creates a direct conversation's identity via the
        database -- ConversationRepository owns persistence, this
        method is the sole caller of it for this purpose. Its only
        remaining caller is ClientSession.load_conversation_history()
        -- always a "get" there (only reached once messages already
        exist, meaning the conversation was necessarily already
        created), left as direct database access until that method's
        own migration. Every other former caller now avoids the
        database here entirely: ClientSession's receiver-thread packet
        handlers (D3.2: handle_chat()/handle_session_key()) use
        record_direct_conversation_id() directly with a server-
        supplied id, and ClientSession.set_current_chat() (D3.3: the
        one former caller here that was a genuine "create") now asks
        the server via a direct_conversation_request instead (see
        ClientSession._resolve_direct_conversation_id()). A group
        conversation never needs either method -- its conversation_id
        is already known synchronously at creation (see
        add_or_update_group()).

        Design note for future growth: if conversation lifecycle
        responsibilities expand significantly (group administration,
        member management, archive, pin, delete, ...), this
        responsibility should be extracted into a dedicated
        ConversationResolver (or equivalent) service *without*
        changing ConversationStore's public interface -- this method
        would simply delegate to it. Not done now because a single
        method does not yet justify a new abstraction.
        """

        existing = self._summaries.get(username)

        if existing is not None and existing.conversation_id is not None:
            return existing.conversation_id

        db = SessionLocal()

        try:
            user_repo = UserRepository(db)
            conversation_repo = ConversationRepository(db)

            partner = user_repo.get_by_username(username)

            if partner is None:
                raise ValueError(f"Unknown user: {username}")

            conversation = conversation_repo.get_or_create_direct_conversation(
                uuid.UUID(own_user_id), partner.id
            )

            conversation_repo.commit()

            conversation_id = str(conversation.id)
        finally:
            db.close()

        self.record_direct_conversation_id(username, conversation_id)

        return conversation_id

    def record_direct_conversation_id(self, username, conversation_id):
        """
        Cache an already-resolved direct conversation id -- no database
        access (D3.2 -- Conversation Operations Migration: the DB-free
        half of ensure_direct_conversation_id() above, extracted so a
        caller that already has the id -- a server-supplied packet
        field, see ClientSession.handle_chat()/handle_session_key() --
        never needs the DB-touching half at all, and in particular
        never needs it from the receiver thread, where a database call
        is not just wasteful but the deadlock risk this migration
        exists to remove). ensure_direct_conversation_id() itself calls
        this for its own caching step -- this is the same behavior it
        always had, just named and shared rather than duplicated.

        Creates a fresh, online placeholder summary if none exists yet
        for ``username``, otherwise updates the existing one's
        conversation_id in place -- exactly matching
        ensure_direct_conversation_id()'s prior inline behavior; every
        other field of an existing summary (latest_message, is_online,
        group fields) is left untouched. Always emits
        conversations_changed: both branches represent a real,
        externally-observable change (a conversation either just
        became known to this client, or just gained/confirmed its id).
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
        Refresh online/offline status for existing conversations, and
        add a placeholder entry (no conversation yet, no preview) for
        any online user who isn't already represented -- preserving
        the ability to start a new chat with anyone online, exactly
        as before Phase 2.
        """

        online_set = set(usernames_online)

        for username, summary in self._summaries.items():
            summary.is_online = username in online_set

        for username in online_set:
            if username not in self._summaries:
                self._summaries[username] = ConversationSummary(
                    conversation_id=None,
                    username=username,
                    is_online=True,
                    latest_message=None,
                )

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
