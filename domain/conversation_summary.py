"""
Conversation summary domain model.

Framework-free: no Qt, no SQLAlchemy, no session/network dependency --
reusable by any future consumer, not just the current PySide6 client.
This is the payload-independent preview shape from Architecture
Blueprint v2 (S02 Payload Pipeline, S15 Communication Pipeline).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from domain.payload_type import PayloadType


@dataclass
class MessagePreview:
    """A short, renderable preview of one message.

    ``payload_type`` is the extension point every future content type
    hangs off of. ``content_metadata`` (Phase 8 -- File & Image
    Transfer) carries the non-secret descriptors (e.g. filename) a
    non-text preview needs to render -- it is never decrypted content
    itself, only what persist_message() already stored alongside the
    ciphertext/blob_ref.
    """

    payload_type: PayloadType
    text: str | None = None
    timestamp: datetime | None = None
    content_metadata: dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        """
        Return the display string for this preview -- the one place
        payload-type branches into text. Adding voice/video support
        later means adding a branch here, not touching any widget:
            "voice" -> "\U0001F3A4 Voice Message"
            "video" -> "\U0001F3A5 Video"
        """
        if self.payload_type == PayloadType.TEXT:
            return self.text or ""
        if self.payload_type == PayloadType.IMAGE:
            return "\U0001F4F7 Photo"
        if self.payload_type == PayloadType.FILE:
            filename = self.content_metadata.get("filename")
            return f"\U0001F4C4 {filename}" if filename else "\U0001F4C4 File"
        return "Unsupported message"


@dataclass
class ConversationSummary:
    """One sidebar row's worth of conversation state.

    ``username`` is populated for a direct conversation and ``None``
    for a group one; ``is_group``/``group_name``/``participants`` are
    the Phase 4 (Secure Group Messaging Foundation) extension of the
    single-partner field this class started with in Phase 2 -- every
    existing direct-conversation construction site is unaffected,
    since all four new/changed fields default away.
    """

    conversation_id: str | None
    username: str | None
    is_online: bool
    latest_message: MessagePreview | None
    is_group: bool = False
    group_name: str | None = None
    participants: list[str] | None = None
    admin: str | None = None

    @property
    def key(self) -> str:
        """
        The addressing identity used throughout ConversationStore and
        the GUI: ``conversation_id`` for a group conversation,
        ``username`` for a direct one (even before its conversation_id
        is known -- see ConversationStore's docstring).
        """
        return self.conversation_id if self.is_group else self.username
