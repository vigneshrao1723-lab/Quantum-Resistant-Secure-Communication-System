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

    def ensure_direct_conversation_id(self, own_user_id, username):
        """
        Resolve the real conversation_id for a direct conversation
        with ``username``, creating it if it doesn't exist yet, and
        cache it on the stored summary so every later call is a plain
        dictionary lookup, not a database round trip.

        This is intentionally the ONE place in the client that ever
        resolves or creates a direct conversation's identity --
        ConversationRepository owns persistence, this method is the
        sole caller of it for this purpose, and ClientSession (Phase 5
        -- Secure Group Key Distribution) never performs a database
        lookup or keeps a second cache; it only ever calls this and
        consumes the result. A group conversation never needs this --
        its conversation_id is already known synchronously at
        creation (see add_or_update_group()).

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

        return conversation_id

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
